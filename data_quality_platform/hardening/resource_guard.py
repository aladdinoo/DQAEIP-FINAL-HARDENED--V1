"""Layer H — Resource / Execution Guard.

Hard resource ceilings enforced around every hardened execution:

* input size (bytes)      — checked BEFORE execution starts
* input row count         — checked BEFORE execution starts
* wall-clock time         — enforced DURING execution by a monitor
                             thread that terminates the process on
                             breach
* peak RSS (VmRSS/VmHWM)  — sampled DURING execution from
                             ``/proc/<pid>/status``; breach terminates
                             the process
* output size (bytes)     — checked BEFORE commit is allowed

Fail-closed semantics: a guard trip yields ``GUARD_TRIPPED`` with the
exact reason and measurements; it is never converted into a pass. A
monitor that cannot start also fails closed
(``GUARD_MONITOR_ERROR``), because an unmonitored execution is not an
acceptable state for this layer.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional

LAYER_ID = "H"
LAYER_NAME = "Resource / Execution Guard"
LAYER_VERSION = "1.0.0"

VERDICT_PASS = "GUARD_PASS"
VERDICT_TRIPPED = "GUARD_TRIPPED"
VERDICT_MONITOR_ERROR = "GUARD_MONITOR_ERROR"

TRIP_INPUT_SIZE = "input_size_exceeded"
TRIP_ROW_COUNT = "row_count_exceeded"
TRIP_WALL_TIME = "wall_time_exceeded"
TRIP_PEAK_RSS = "peak_rss_exceeded"
TRIP_OUTPUT_SIZE = "output_size_exceeded"

_ROW_CHUNK = 1 << 20


@dataclass
class ResourceLimits:
    max_input_bytes: int = 2 * 1024 * 1024 * 1024
    max_rows: int = 4_000_000
    max_wall_seconds: float = 3600.0
    max_peak_rss_bytes: int = 4 * 1024 * 1024 * 1024
    max_output_bytes: int = 4 * 1024 * 1024 * 1024

    def as_dict(self) -> dict:
        return {
            "max_input_bytes": self.max_input_bytes,
            "max_rows": self.max_rows,
            "max_wall_seconds": self.max_wall_seconds,
            "max_peak_rss_bytes": self.max_peak_rss_bytes,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass
class GuardResult:
    layer_id: str = LAYER_ID
    layer_name: str = LAYER_NAME
    layer_version: str = LAYER_VERSION
    verdict: str = VERDICT_TRIPPED
    trip_reason: Optional[str] = None
    reasons: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def pass_(self) -> bool:
        return self.verdict == VERDICT_PASS

    def as_dict(self) -> dict:
        return {
            "layer_id": self.layer_id,
            "layer_name": self.layer_name,
            "layer_version": self.layer_version,
            "verdict": self.verdict,
            "trip_reason": self.trip_reason,
            "reasons": list(self.reasons),
            "details": dict(self.details),
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)


def count_rows(path: str) -> int:
    """Count data rows (excluding header) by streaming the file."""
    rows = 0
    with open(path, "rb") as f:
        f.readline()  # header
        tail = b""
        while True:
            chunk = f.read(_ROW_CHUNK)
            if not chunk:
                break
            tail += chunk
            rows += tail.count(b"\n")
            tail = tail[-1:]
    if tail and not tail.endswith(b"\n"):
        rows += 1  # final line without trailing newline
    return rows


def check_pre_execution(limits: ResourceLimits,
                        input_path: str) -> GuardResult:
    """Static pre-execution checks (input size + row count)."""
    result = GuardResult()
    add = result.reasons.append
    try:
        size = os.path.getsize(input_path)
        result.details["input_size_bytes"] = size
        if size > limits.max_input_bytes:
            result.trip_reason = TRIP_INPUT_SIZE
            add(f"input size {size} > limit {limits.max_input_bytes}")
            return result
        rows = count_rows(input_path)
        result.details["input_row_count"] = rows
        if rows > limits.max_rows:
            result.trip_reason = TRIP_ROW_COUNT
            add(f"input row count {rows} > limit {limits.max_rows}")
            return result
    except OSError as exc:
        add(f"pre-execution guard failed: {exc!r}")
        result.verdict = VERDICT_MONITOR_ERROR
        return result
    result.verdict = VERDICT_PASS
    return result


def check_post_execution(limits: ResourceLimits,
                         output_paths: List[str]) -> GuardResult:
    """Output size ceiling, checked before commit is allowed."""
    result = GuardResult()
    add = result.reasons.append
    total = 0
    try:
        sizes = {}
        for path in output_paths:
            size = os.path.getsize(path)
            sizes[path] = size
            total += size
        result.details["output_sizes"] = sizes
        result.details["output_total_bytes"] = total
        if total > limits.max_output_bytes:
            result.trip_reason = TRIP_OUTPUT_SIZE
            add(f"total output size {total} > limit "
                f"{limits.max_output_bytes}")
            return result
    except OSError as exc:
        add(f"post-execution guard failed: {exc!r}")
        result.verdict = VERDICT_MONITOR_ERROR
        return result
    result.verdict = VERDICT_PASS
    return result


def _read_proc_rss(pid: int) -> Optional[int]:
    """Current VmRSS in bytes for a pid, or None if unreadable."""
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    # e.g. "VmRSS:\t  2365700 kB"
                    parts = line.split()
                    return int(parts[1]) * 1024
    except (OSError, IndexError, ValueError):
        return None
    return None


class ExecutionMonitor:
    """Wall-time and peak-RSS monitor for a running subprocess.

    Usage:
        monitor = ExecutionMonitor(limits)
        monitor.start(proc)
        ... wait for the process ...
        report = monitor.finish(returncode)
    The monitor thread kills the process (SIGKILL) when a limit is
    breached; ``finish`` reports the trip with measurements.
    """

    def __init__(self, limits: ResourceLimits,
                 sample_interval: float = 0.25):
        self.limits = limits
        self.sample_interval = sample_interval
        self._trip_reason: Optional[str] = None
        self._trip_details: dict = {}
        self._peak_rss: int = 0
        self._samples: int = 0
        self._started_at: Optional[float] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def start(self, proc: subprocess.Popen) -> None:
        self._started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._run, args=(proc,), daemon=True,
            name="dqaeip-resource-guard")
        self._thread.start()

    def _run(self, proc: subprocess.Popen) -> None:
        pid = proc.pid
        while not self._stop.is_set():
            elapsed = time.monotonic() - (self._started_at or 0.0)
            if elapsed > self.limits.max_wall_seconds:
                with self._lock:
                    if self._trip_reason is None:
                        self._trip_reason = TRIP_WALL_TIME
                        self._trip_details = {
                            "elapsed_seconds": elapsed,
                            "limit_seconds": self.limits.max_wall_seconds,
                        }
                self._kill(proc)
                return
            rss = _read_proc_rss(pid)
            if rss is not None:
                with self._lock:
                    self._samples += 1
                    if rss > self._peak_rss:
                        self._peak_rss = rss
                    if rss > self.limits.max_peak_rss_bytes:
                        if self._trip_reason is None:
                            self._trip_reason = TRIP_PEAK_RSS
                            self._trip_details = {
                                "rss_bytes": rss,
                                "limit_bytes":
                                    self.limits.max_peak_rss_bytes,
                            }
                        self._kill(proc)
                        return
            self._stop.wait(self.sample_interval)

    def _kill(self, proc: subprocess.Popen) -> None:
        try:
            proc.kill()
        except OSError:
            pass

    def finish(self, returncode: int) -> GuardResult:
        """Stop sampling and produce the guard verdict."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        result = GuardResult()
        add = result.reasons.append
        result.details["wall_seconds"] = round(
            time.monotonic() - (self._started_at or time.monotonic()), 3)
        result.details["peak_rss_bytes"] = self._peak_rss
        result.details["rss_samples"] = self._samples
        with self._lock:
            trip = self._trip_reason
            trip_details = dict(self._trip_details)
        if trip is not None:
            result.trip_reason = trip
            result.details["trip"] = trip_details
            add(f"resource guard tripped: {trip} ({trip_details})")
            return result
        result.verdict = VERDICT_PASS
        result.details["monitored_returncode"] = returncode
        return result


def guard_result_from_error(exc: Exception) -> GuardResult:
    """Fail-closed conversion of monitor errors."""
    result = GuardResult()
    result.verdict = VERDICT_MONITOR_ERROR
    result.reasons.append(f"guard monitor error: {exc!r}")
    return result
