"""Input Contract / Preflight Firewall (DQAVP hardening, Section 11).

A fail-closed structural gate that runs BEFORE the existing validation
engine executes. Its purpose is to refuse malformed input early, with
actionable diagnostics, instead of letting the streaming engine produce
silently degraded output (e.g., ragged CSV rows that ``csv.DictReader``
would pad with blanks).

Scope contract (deliberate, to preserve frozen V1 semantics):
- The firewall validates STRUCTURE ONLY: file readability, encoding, CSV
  shape, header contract (expected columns), row-level structural
  constraints, identifier sanity (bounded scan), and configuration
  compatibility.
- It does NOT evaluate data QUALITY. Malformed e-mails, weird names, or
  mismatched ZIPs are exactly what the frozen V1 rules are supposed to
  flag; the firewall must never reject a row that the engine would
  legitimately process and flag.
- It does NOT modify the input file (source preservation).
- The engine's business logic is untouched: the gate is wired into the
  production CLI (``runner.cli validate``) ahead of engine construction.

Fail-closed behavior:
- VALID INPUT -> validation proceeds (engine executes).
- INVALID INPUT -> ``InputContractError`` raised (CLI blocks the run and
  writes a failure manifest; exit code 2).
- Any unexpected internal error during the scan itself is reported as an
  issue and BLOCKS the run (never a silent pass).

Identifier duplicate scanning is bounded by ``id_scan_rows`` for memory
safety on very large files; the covered fraction is reported honestly in
``details``. Full-population duplicate counting remains the responsibility
of the engine's monitoring layer (``unique_id_count`` vs row count).
"""

import csv
import hashlib
import io
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from data_quality_platform.contracts import SOURCE_COLUMNS

__all__ = [
    "InputContractIssue",
    "InputContractError",
    "InputContractResult",
    "validate_input_contract",
]

_BOM = b"\xef\xbb\xbf"
_ID_SAMPLE_DEFAULT = 500_000
_ENCODING_SAMPLE_BYTES = 1 << 16  # 64 KiB explicit encoding pre-check


class InputContractIssue:
    """One structural finding. ``code`` values are stable identifiers."""

    def __init__(self, code: str, message: str, row_number: Optional[int] = None,
                 column: Optional[str] = None):
        self.code = code
        self.message = message
        self.row_number = row_number
        self.column = column

    def to_dict(self) -> Dict[str, Any]:
        d = {"code": self.code, "message": self.message}
        if self.row_number is not None:
            d["row_number"] = self.row_number
        if self.column is not None:
            d["column"] = self.column
        return d

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        loc = f" (row {self.row_number})" if self.row_number else ""
        col = f" column={self.column!r}" if self.column else ""
        return f"[{self.code}]{loc}{col}: {self.message}"


class InputContractError(Exception):
    """Raised when the input contract is violated (fail closed)."""

    def __init__(self, issues: Sequence[InputContractIssue],
                 details: Optional[Dict[str, Any]] = None):
        self.issues = list(issues)
        self.details = dict(details or {})
        summary = "; ".join(repr(i) for i in self.issues[:10])
        more = "" if len(self.issues) <= 10 else f" (+{len(self.issues) - 10} more)"
        super().__init__(f"input contract violated: {summary}{more}")


@dataclass
class InputContractResult:
    """Outcome of the preflight scan."""

    valid: bool
    issues: List[InputContractIssue] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


def _sha256_header(header: Sequence[str]) -> str:
    return hashlib.sha256(",".join(header).encode("utf-8")).hexdigest()


def _validate_config_compat(config: Any,
                            issues: List[InputContractIssue]) -> None:
    """Configuration compatibility check (fail closed on invalid values)."""
    if config is None:
        return
    thresholds = getattr(config, "get_quality_thresholds", None)
    if callable(thresholds):
        try:
            th = config.get_quality_thresholds()
        except Exception as exc:  # malformed config object
            issues.append(InputContractIssue(
                "config_thresholds_unreadable",
                f"quality thresholds could not be read: {exc}"))
            return
        for key, value in sorted(th.items()):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                issues.append(InputContractIssue(
                    "config_threshold_not_numeric",
                    f"quality_thresholds.{key} is not numeric: {value!r}"))
            elif not (0.0 <= float(value) <= 1.0):
                issues.append(InputContractIssue(
                    "config_threshold_out_of_range",
                    f"quality_thresholds.{key}={value!r} outside [0, 1]"))


def validate_input_contract(
    csv_path: str,
    expected_columns: Optional[Sequence[str]] = None,
    config: Any = None,
    id_scan_rows: int = _ID_SAMPLE_DEFAULT,
    max_reported_issues: int = 50,
) -> InputContractResult:
    """Validate the input contract of a CSV file. Fail closed.

    Args:
        csv_path: path to the input CSV.
        expected_columns: expected header (default: the frozen 33-column
            V1 contract ``SOURCE_COLUMNS``).
        config: optional ``PlatformConfig`` for configuration compatibility
            checks.
        id_scan_rows: number of leading data rows scanned for blank /
            duplicate identifier checks (memory-bounded on huge files).
        max_reported_issues: per-category cap on stored issues (counting
            continues; totals are exact).

    Returns:
        ``InputContractResult`` with ``valid`` and structured issues.

    Raises:
        InputContractError: when any blocking issue is found.
    """
    issues: List[InputContractIssue] = []
    expected = list(expected_columns or SOURCE_COLUMNS)
    details: Dict[str, Any] = {
        "path_present": bool(csv_path),
        "expected_column_count": len(expected),
        "id_scan_rows_requested": int(id_scan_rows),
    }

    # ---- 1. File-level checks -------------------------------------------
    if not csv_path:
        raise InputContractError(
            [InputContractIssue("path_missing", "no input path provided")],
            details)
    if not os.path.exists(csv_path):
        raise InputContractError(
            [InputContractIssue("file_not_found",
                                f"input file does not exist: {csv_path}")],
            details)
    if not os.path.isfile(csv_path):
        raise InputContractError(
            [InputContractIssue("not_a_regular_file",
                                f"input path is not a regular file: {csv_path}")],
            details)
    try:
        size = os.path.getsize(csv_path)
    except OSError as exc:
        raise InputContractError(
            [InputContractIssue("stat_failed", f"cannot stat input: {exc}")],
            details) from exc
    details["size_bytes"] = size
    if size == 0:
        raise InputContractError(
            [InputContractIssue("empty_file", "input file is empty (0 bytes)")],
            details)

    # ---- 2. Encoding pre-check (BOM / binary garbage) --------------------
    with open(csv_path, "rb") as bf:
        head = bf.read(_ENCODING_SAMPLE_BYTES)
    if head.startswith(_BOM):
        issues.append(InputContractIssue(
            "utf8_bom_detected",
            "file starts with a UTF-8 BOM; the engine contract expects "
            "BOM-free UTF-8 (a BOM corrupts the first header column)"))
    try:
        head.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InputContractError(
            [InputContractIssue(
                "encoding_invalid",
                f"first {len(head)} bytes are not valid UTF-8: {exc}")],
            details) from exc

    # ---- 3. Header checks -------------------------------------------------
    try:
        with open(csv_path, "r", newline="", encoding="utf-8",
                  errors="strict") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                raise InputContractError(
                    [InputContractIssue("header_missing",
                                        "file has no header row")], details)
            except UnicodeDecodeError as exc:
                raise InputContractError(
                    [InputContractIssue(
                        "encoding_invalid",
                        f"header is not valid UTF-8: {exc}")], details)
    except UnicodeDecodeError as exc:  # pragma: no cover - defensive
        raise InputContractError(
            [InputContractIssue("encoding_invalid", str(exc))], details)

    details["header_column_count"] = len(header)
    details["schema_identity_sha256"] = _sha256_header(header)

    if len(header) != len(expected):
        issues.append(InputContractIssue(
            "column_count_mismatch",
            f"header has {len(header)} columns, expected {len(expected)}"))
    missing = [c for c in expected if c not in header]
    unexpected = [c for c in header if c not in expected]
    for c in missing[:max_reported_issues]:
        issues.append(InputContractIssue(
            "column_missing", f"expected column absent: {c!r}", column=c))
    for c in unexpected[:max_reported_issues]:
        issues.append(InputContractIssue(
            "column_unexpected", f"unexpected column present: {c!r}", column=c))
    if missing:
        details["missing_columns"] = missing
    if unexpected:
        details["unexpected_columns"] = unexpected
    if header != expected and not missing and not unexpected:
        issues.append(InputContractIssue(
            "column_order_mismatch",
            "columns match as a set but not in the frozen contract order"))
    dup_names = sorted({c for c in header if header.count(c) > 1})
    if dup_names:
        issues.append(InputContractIssue(
            "duplicate_header_names",
            f"duplicate header column names: {dup_names}"))
    if any(c.strip() == "" for c in header):
        issues.append(InputContractIssue(
            "blank_header_name", "header contains a blank column name"))

    # ---- 4. Structural + identifier scan ---------------------------------
    id_index = header.index("id") if "id" in header else None
    seen_id_hashes: set = set()
    total_rows = 0
    ragged_total = 0
    nul_total = 0
    blank_id_total = 0
    duplicate_id_total = 0
    id_rows_scanned = 0
    try:
        with open(csv_path, "r", newline="", encoding="utf-8",
                  errors="strict") as f:
            reader = csv.reader(f)
            next(reader, None)  # header (validated above)
            for row in reader:
                total_rows += 1
                if len(row) != len(expected):
                    ragged_total += 1
                    if ragged_total <= max_reported_issues:
                        issues.append(InputContractIssue(
                            "ragged_row",
                            f"row has {len(row)} fields, expected "
                            f"{len(expected)}",
                            row_number=total_rows + 1))
                scan_ids = (id_index is not None
                            and id_rows_scanned < id_scan_rows)
                if scan_ids:
                    id_rows_scanned += 1
                    rid = row[id_index] if id_index < len(row) else ""
                    if "\x00" in rid:
                        issues.append(InputContractIssue(
                            "nul_byte_in_id",
                            "identifier field contains a NUL byte",
                            row_number=total_rows + 1, column="id"))
                    elif rid == "" or rid.strip() == "":
                        blank_id_total += 1
                        if blank_id_total <= max_reported_issues:
                            issues.append(InputContractIssue(
                                "blank_identifier",
                                "identifier field is blank",
                                row_number=total_rows + 1, column="id"))
                    else:
                        h = int(hashlib.sha256(
                            rid.encode("utf-8")).hexdigest()[:15], 16)
                        if h in seen_id_hashes:
                            duplicate_id_total += 1
                            if duplicate_id_total <= max_reported_issues:
                                issues.append(InputContractIssue(
                                    "duplicate_identifier",
                                    f"duplicate id value: {rid!r}",
                                    row_number=total_rows + 1, column="id"))
                        else:
                            seen_id_hashes.add(h)
                if not scan_ids:
                    # Cheap NUL scan on remaining rows.
                    if any("\x00" in cell for cell in row):
                        nul_total += 1
                        if nul_total <= max_reported_issues:
                            issues.append(InputContractIssue(
                                "nul_byte_in_row",
                                "row contains a NUL byte",
                                row_number=total_rows + 1))
    except UnicodeDecodeError as exc:
        raise InputContractError(
            [InputContractIssue(
                "encoding_invalid",
                f"file is not valid UTF-8 (full scan at row ~{total_rows + 1}): "
                f"{exc}")],
            details) from exc
    except csv.Error as exc:
        raise InputContractError(
            [InputContractIssue(
                "csv_parse_error",
                f"CSV parse error at row ~{total_rows + 1}: {exc}")],
            details) from exc

    details["total_data_rows"] = total_rows
    details["ragged_rows_total"] = ragged_total
    details["id_rows_scanned"] = id_rows_scanned
    details["id_scan_complete"] = (
        id_index is None or id_rows_scanned >= total_rows)
    details["duplicate_ids_in_scanned_range"] = duplicate_id_total
    details["blank_ids_in_scanned_range"] = blank_id_total
    details["id_coverage_note"] = (
        "full population scanned"
        if details["id_scan_complete"]
        else f"first {id_rows_scanned} rows scanned (memory-bounded); "
             f"full-population duplicate counting remains the engine "
             f"monitoring layer's responsibility")

    # ---- 5. Configuration compatibility -----------------------------------
    _validate_config_compat(config, issues)

    details["issue_count"] = len(issues)
    result = InputContractResult(valid=not issues, issues=issues,
                                 details=details)
    if issues:
        raise InputContractError(issues, details)
    return result
