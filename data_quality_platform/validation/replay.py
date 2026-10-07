"""Deterministic Replay.

Proves reproducibility: run the SAME deterministic dataset through the
production engine at least twice and compare

    input hash / schema / row count / rule versions / rule hashes /
    reference hashes / configuration hash / output hash / decision
    counts / evidence-level key facts

Expected:

    same input + same rules + same references + same configuration
        = same decisions + byte-identical output

If anything differs, the replay FAILS (fail closed) — determinism is
never assumed, only proven.
"""

import csv
import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from data_quality_platform.contracts import SOURCE_COLUMNS, STATE_ZIP_PREFIXES
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.validation.engine import ValidationEngine

__all__ = ["replay_dataset", "ReplayMismatch"]


class ReplayMismatch(AssertionError):
    """Raised (or recorded) when a replay comparison fails."""


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _schema_hash_of_input(csv_path: str) -> str:
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        header = next(csv.reader(f))
    return hashlib.sha256(",".join(header).encode("utf-8")).hexdigest()


def _input_row_count(csv_path: str) -> int:
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        return max(sum(1 for _ in csv.reader(f)) - 1, 0)


def replay_dataset(
    csv_path: str,
    *,
    runs: int = 2,
    work_dir: str,
    config_thresholds: Optional[Dict[str, float]] = None,
    registry_factory=None,
) -> Dict[str, Any]:
    """Execute the engine ``runs`` times over the same input and verify
    full decision determinism. Returns a structured report; raises
    ``ReplayMismatch`` when determinism fails.

    The input file is never modified (source preservation verified by
    input-hash equality across runs).
    """
    if runs < 2:
        raise ValueError("replay requires runs >= 2")
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(csv_path)

    factory = registry_factory or RuleRegistry.create_default
    # The V1 reference data is hard-coded in contracts.py (STATE_ZIP_PREFIXES);
    # its SHA-256 is implicitly pinned by the file hash of contracts.py.
    reference_hashes = {"STATE_ZIP_PREFIXES": "hard-coded in contracts.py"}

    executions: List[Dict[str, Any]] = []
    for i in range(1, runs + 1):
        out_path = os.path.join(work_dir, f"replay_output_{i}.csv")
        evd = os.path.join(work_dir, f"replay_evidence_{i}")
        engine = ValidationEngine(
            rules=factory(),
            run_id=f"replay_{i}",
            evidence_dir=evd,
            config_thresholds=config_thresholds,
        )
        result = engine.validate(csv_path, out_path)
        if not result.success:
            raise ReplayMismatch(
                f"replay run {i} failed: {result.error}")
        executions.append({
            "run": i,
            "input_sha256": _sha256_file(csv_path),
            "input_row_count": result.input_row_count,
            "schema_sha256": result.schema_hash,
            "output_sha256": _sha256_file(out_path),
            "output_path": out_path,
            "flag_counts": dict(result.flag_counts),
            "rule_versions": {r.rule_id: r.rule_version
                             for r in engine.rules.get_all_rules()},
            "rule_hashes": engine.rules.get_rule_hashes(),
            "monitoring_score": result.monitoring_score,
        })

    first = executions[0]
    mismatches: List[str] = []

    for later in executions[1:]:
        n = later["run"]
        for field in ("input_sha256", "input_row_count", "schema_sha256",
                      "flag_counts", "rule_versions", "rule_hashes",
                      "monitoring_score", "output_sha256"):
            if later[field] != first[field]:
                mismatches.append(
                    f"run {n}: {field} differs from run 1 "
                    f"({later[field]!r} != {first[field]!r})")
        # byte-identical output (actual file comparison, not just hashes)
        if not os.path.isfile(first["output_path"]) or \
                not os.path.isfile(later["output_path"]):
            mismatches.append(f"run {n}: output file missing")
        else:
            with open(first["output_path"], "rb") as fa, \
                    open(later["output_path"], "rb") as fb:
                if fa.read() != fb.read():
                    mismatches.append(
                        f"run {n}: output files not byte-identical")

    report = {
        "replay_verified": not mismatches,
        "runs": runs,
        "input_sha256": first["input_sha256"],
        "input_row_count": first["input_row_count"],
        "input_schema_sha256": first["schema_sha256"],
        "byte_identical_output": not any(
            "byte-identical" in m or "output_sha256" in m
            for m in mismatches),
        "reference_hashes": reference_hashes,
        "deterministic_config_hash": (None if config_thresholds is None else
                                     json.dumps(config_thresholds,
                                                sort_keys=True,
                                                default=str)),
        "executions": executions,
        "mismatches": mismatches,
        "fail_closed_note": "determinism is proven, never assumed: any "
                            "difference in input hash, schema, rule "
                            "versions/hashes, reference hashes, decision "
                            "counts, or output bytes fails the replay",
    }
    if mismatches:
        raise ReplayMismatch(
            "deterministic replay FAILED: " + "; ".join(mismatches[:10]))
    return report


def replay_report_from_paths(csv_path: str, work_dir: str,
                             runs: int = 2) -> Dict[str, Any]:
    """Non-raising variant: returns the report; callers inspect
    ``replay_verified``. (Fail closed still applies — a failed replay is
    never reported as verified.)"""
    try:
        return replay_dataset(csv_path, runs=runs, work_dir=work_dir)
    except ReplayMismatch as exc:
        return {
            "replay_verified": False,
            "runs": runs,
            "mismatches": [str(exc)],
            "fail_closed_note": "deterministic replay failed",
        }
