"""Layer A — Input Contract Firewall.

Validates the input data file against an explicit, cryptographically pinned
contract BEFORE the file is allowed to enter execution. A rejected input
never reaches the engine.

Contract checks (all must pass):
* file exists and is a regular file
* size does not exceed ``max_input_bytes``
* full-content SHA-256 equals ``expected_sha256`` (identity pin)
* decodes as strict UTF-8 (no replacement-tolerant decoding)
* CSV header row equals the authorized column list, in exact order,
  with exact column count
* declared per-column CSV type contract is satisfied by sampled rows
  (integer / float / string / nullable)
* row count does not exceed ``max_rows``
* no NUL bytes anywhere in the file

Fail-closed: every exception or failed check yields
``INPUT_CONTRACT_REJECTED`` with structured reasons; the module never
returns PASS as a side effect of error handling.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

LAYER_ID = "A"
LAYER_NAME = "Input Contract Firewall"
LAYER_VERSION = "1.0.0"

VERDICT_PASS = "INPUT_CONTRACT_PASS"
VERDICT_REJECTED = "INPUT_CONTRACT_REJECTED"

_READ_CHUNK = 1 << 20

# CSV type contract vocabulary. Types are validated on a bounded sample of
# rows (sample_rows); a column failing its declared type on any sampled,
# non-empty value is a contract violation.
_ALLOWED_TYPES = ("string", "integer", "float", "nullable_string",
                  "nullable_integer", "nullable_float")


@dataclass
class InputContractResult:
    """Machine-readable verdict for the input contract firewall."""

    layer_id: str = LAYER_ID
    layer_name: str = LAYER_NAME
    layer_version: str = LAYER_VERSION
    verdict: str = VERDICT_REJECTED
    reasons: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.verdict == VERDICT_PASS

    def as_dict(self) -> dict:
        return {
            "layer_id": self.layer_id,
            "layer_name": self.layer_name,
            "layer_version": self.layer_version,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "details": dict(self.details),
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_type(value: str, declared: str) -> bool:
    base = declared
    nullable = declared.startswith("nullable_")
    if nullable:
        base = declared[len("nullable_"):]
    if value == "":
        return nullable
    if base == "string":
        return True
    try:
        if base == "integer":
            int(value)
        elif base == "float":
            float(value)
    except ValueError:
        return False
    return True


def validate_input_contract(
    input_path: str,
    expected_sha256: str,
    authorized_columns: Sequence[str],
    *,
    column_types: Optional[dict] = None,
    max_rows: int = 4_000_000,
    max_input_bytes: int = 2 * 1024 * 1024 * 1024,
    sample_rows: int = 200,
    encoding: str = "utf-8",
) -> InputContractResult:
    """Validate the input file against the pinned contract.

    Parameters
    ----------
    input_path:
        Path to the input CSV.
    expected_sha256:
        Authorized full-file SHA-256 (hex). The observed hash must equal
        this value exactly.
    authorized_columns:
        Exact authorized column list, in order.
    column_types:
        Optional mapping column-name -> declared CSV type (one of
        ``string``, ``integer``, ``float``, ``nullable_*`` variants).
        Columns without a declared type are not type-checked.
    max_rows / max_input_bytes:
        Hard caps enforced before execution is allowed.
    sample_rows:
        Bounded number of leading data rows used for type sampling.
    """
    result = InputContractResult()
    add = result.reasons.append

    # ── existence / regular-file / size ─────────────────────────────────
    try:
        st = os.stat(input_path)
        if not os.path.isfile(input_path):
            add(f"input is not a regular file: {input_path}")
            result.details["exists"] = False
            return result
        size = st.st_size
        result.details["size_bytes"] = size
        if size > max_input_bytes:
            add(
                f"input size {size} bytes exceeds max_input_bytes "
                f"{max_input_bytes}"
            )
    except OSError as exc:
        add(f"input file stat failed: {exc!r}")
        return result

    # ── full-content hash (identity pin) ───────────────────────────────
    try:
        observed_sha = _sha256_file(input_path)
        result.details["observed_sha256"] = observed_sha
        result.details["expected_sha256"] = expected_sha256
        if observed_sha.lower() != str(expected_sha256).lower():
            add("input SHA-256 does not match the authorized expected hash")
    except OSError as exc:
        add(f"input hashing failed: {exc!r}")
        return result

    # ── NUL-byte scan + strict decode ──────────────────────────────────
    try:
        nul_found = False
        utf8_ok = True
        decode_error = None
        with open(input_path, "rb") as f:
            for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
                if b"\x00" in chunk:
                    nul_found = True
                    break
        if nul_found:
            add("input contains NUL bytes")
        else:
            with open(input_path, "rb") as f:
                data = f.read()
            try:
                data.decode(encoding, errors="strict")
            except UnicodeDecodeError as exc:
                utf8_ok = False
                decode_error = str(exc)
        result.details["encoding"] = encoding
        result.details["decode_strict_ok"] = utf8_ok
        if not utf8_ok:
            add(f"input is not valid strict {encoding}: {decode_error}")
    except OSError as exc:
        add(f"input decode scan failed: {exc!r}")
        return result

    # ── header / schema / row cap / type sample ────────────────────────
    try:
        with open(input_path, "r", encoding=encoding, newline="") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                add("input file is empty (no header row)")
                return result
            result.details["observed_column_count"] = len(header)
            result.details["authorized_column_count"] = len(
                list(authorized_columns))
            if header != list(authorized_columns):
                if len(header) != len(authorized_columns):
                    add(
                        f"header column count {len(header)} != authorized "
                        f"{len(authorized_columns)}"
                    )
                else:
                    diffs = [
                        f"position {i}: authorized {a!r}, observed {o!r}"
                        for i, (a, o) in enumerate(
                            zip(authorized_columns, header))
                        if a != o
                    ]
                    add("header does not match the authorized column list: "
                        + "; ".join(diffs[:8]))
            row_count = 0
            type_violations = []
            if column_types:
                unknown = set(column_types) - set(authorized_columns)
                if unknown:
                    add("column_types declares unknown columns: "
                        + ", ".join(sorted(unknown)))
                bad_decl = [
                    f"{c}:{t}" for c, t in column_types.items()
                    if t not in _ALLOWED_TYPES
                ]
                if bad_decl:
                    add("column_types uses unsupported type declarations: "
                        + ", ".join(sorted(bad_decl)))
            sampled = 0
            for row in reader:
                row_count += 1
                if sampled < max(0, sample_rows):
                    sampled += 1
                    if column_types:
                        if len(row) == len(header):
                            for name, value in zip(header, row):
                                declared = column_types.get(name)
                                if declared and not _check_type(
                                        value, declared):
                                    type_violations.append(
                                        f"row {row_count} column {name!r}: "
                                        f"value {value!r} fails declared "
                                        f"type {declared!r}")
            result.details["row_count"] = row_count
            result.details["type_sample_rows"] = sampled
            if row_count > max_rows:
                add(
                    f"row count {row_count} exceeds max_rows {max_rows}"
                )
            if type_violations:
                add("column type contract violated: "
                    + "; ".join(type_violations[:8]))
    except (csv.Error, OSError, UnicodeDecodeError) as exc:
        add(f"input CSV parse failed: {exc!r}")
        return result
    except Exception as exc:  # defensive: fail-closed on anything
        add(f"input contract evaluation failed unexpectedly: {exc!r}")
        return result

    if result.reasons:
        result.verdict = VERDICT_REJECTED
    else:
        result.verdict = VERDICT_PASS
    return result


def iter_row_ids(path: str, encoding: str = "utf-8") -> Iterable[str]:
    """Stream the first column of every data row (id column reader)."""
    with open(path, "r", encoding=encoding, newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            yield row[0] if row else ""
