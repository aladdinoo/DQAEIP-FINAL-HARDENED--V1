"""Evidence consistency validator — smallest complete implementation.

Distinguishes:

1. TAMPER DETECTION — provided by ``evidence_root.py::verify_evidence_root``.
   Any modification to a covered artifact invalidates the root hash.

2. SEMANTIC CONSISTENCY VALIDATION — provided by THIS module.
   Verifies that the engine wrote internally-consistent evidence:
     - required artifacts exist
     - JSON is parseable
     - manifest has required schema fields
     - run_id is consistent across manifest/lineage/audit
     - row counts agree across manifest/audit/lineage
     - flag counts agree across manifest/audit
     - verdict is consistent (no success+failure contradiction)
     - lineage structure is valid (dicts, required fields, valid rule IDs)
     - referenced artifacts exist and their hashes match
     - output column count == 41

This is the smallest implementation that covers the meaningful checks.
It is NOT the historical 487-line validator — that had ~16 checks, many
of which were redundant (e.g., checking both ``manifest_type`` validity
AND ``manifest_not_success`` separately). This implementation consolidates
redundant checks and skips checks that are already enforced elsewhere
(e.g., schema validation is enforced by Layer A before the engine runs).

Fail-closed: ANY missing artifact, malformed JSON, schema violation,
cross-artifact disagreement, or hash mismatch makes the report invalid.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from data_quality_platform.contracts import (
    FLAG_COLUMNS, TOTAL_OUTPUT_COLUMNS,
)

__all__ = [
    "EvidenceIssue",
    "EvidenceConsistencyError",
    "validate_evidence_dir",
    "require_valid_evidence",
]

_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")
_REQUIRED_FIELDS = (
    "manifest_type", "run_id", "timestamp",
    "source_row_count", "output_row_count", "schema_hash",
    "rule_hashes", "sql_hashes", "flag_counts",
    "reconciliation", "safety_invariants", "generated_files",
)
_LINEAGE_ROW_FIELDS = (
    "run_id", "row_number", "rule_id", "rule_version",
    "flag_value", "row_hash", "timestamp",
)
_REPR_MARKERS = (
    "RowLineageRecord object at",
    "LineageRecord object at",
    "object at 0x",
)


class EvidenceIssue:
    """A single consistency issue found in an evidence directory."""

    def __init__(self, code: str, message: str, artifact: str = ""):
        self.code = code
        self.message = message
        self.artifact = artifact

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "artifact": self.artifact}

    def __repr__(self) -> str:
        art = f" [{self.artifact}]" if self.artifact else ""
        return f"[{self.code}]{art}: {self.message}"


class EvidenceConsistencyError(Exception):
    """Raised by strict callers when evidence is inconsistent."""

    def __init__(self, issues: List[EvidenceIssue], report: Dict[str, Any]):
        self.issues = issues
        self.report = report
        super().__init__(
            "inconsistent evidence: " + "; ".join(repr(i) for i in issues[:5]))


def _load_json(path: str, issues: List[EvidenceIssue]) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        issues.append(EvidenceIssue("json_invalid", f"not valid JSON: {exc}",
                                     os.path.basename(path)))
    except OSError as exc:
        issues.append(EvidenceIssue("file_unreadable", f"cannot read: {exc}",
                                     os.path.basename(path)))
    except UnicodeDecodeError as exc:
        issues.append(EvidenceIssue("encoding_invalid", f"not valid UTF-8: {exc}",
                                     os.path.basename(path)))
    return None


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def validate_evidence_dir(
    evidence_dir: str,
    *,
    expected_rule_ids: Optional[List[str]] = None,
    expect_success: bool = True,
) -> Dict[str, Any]:
    """Validate an engine evidence directory. Read-only, fail closed.

    Returns a report dict:
        {"valid": bool, "issues": [...], "checks_performed": [...],
         "run_id": str|None, "details": {...}}

    ``valid`` is True if and only if zero issues were found AND the
    directory contained the required complete evidence set.
    """
    issues: List[EvidenceIssue] = []
    checks: List[str] = []
    details: Dict[str, Any] = {"evidence_dir_present": False}
    rule_ids = list(expected_rule_ids or FLAG_COLUMNS)

    report: Dict[str, Any] = {
        "valid": False, "issues": [], "checks_performed": checks,
        "run_id": None, "details": details,
    }

    if not evidence_dir or not os.path.isdir(evidence_dir):
        issues.append(EvidenceIssue(
            "evidence_dir_missing",
            f"evidence directory does not exist: {evidence_dir!r}"))
        report["issues"] = [i.to_dict() for i in issues]
        return report
    details["evidence_dir_present"] = True

    # ---- required artifacts ---------------------------------------------
    required = ["manifest.json", "lineage.json", "audit.json"]
    for name in required:
        if not os.path.isfile(os.path.join(evidence_dir, name)):
            issues.append(EvidenceIssue(
                "required_file_missing",
                f"required evidence file absent: {name}", name))
    checks.append("required_files_exist")

    manifest = _load_json(os.path.join(evidence_dir, "manifest.json"), issues)
    lineage = _load_json(os.path.join(evidence_dir, "lineage.json"), issues)
    audit = _load_json(os.path.join(evidence_dir, "audit.json"), issues)
    monitoring = _load_json(os.path.join(evidence_dir, "monitoring.json"), issues)
    alerts = _load_json(os.path.join(evidence_dir, "alerts.json"), issues)
    checks.append("json_parseable")

    # ---- manifest schema ------------------------------------------------
    if manifest is not None:
        checks.append("manifest_schema")
        for field in _REQUIRED_FIELDS:
            if field not in manifest:
                issues.append(EvidenceIssue(
                    "manifest_field_missing",
                    f"manifest missing required field: {field}", "manifest.json"))
        if manifest.get("manifest_type") not in ("success", "failure"):
            issues.append(EvidenceIssue(
                "manifest_type_invalid",
                f"manifest_type must be 'success' or 'failure', got "
                f"{manifest.get('manifest_type')!r}", "manifest.json"))
        elif expect_success and manifest.get("manifest_type") != "success":
            issues.append(EvidenceIssue(
                "manifest_not_success",
                f"expected success, got {manifest.get('manifest_type')!r}",
                "manifest.json"))
        if isinstance(manifest.get("schema_hash"), str) and not _HEX64_RE.match(manifest["schema_hash"]):
            issues.append(EvidenceIssue(
                "hash_format_invalid",
                "schema_hash is not 64-char lowercase hex", "manifest.json"))
        rh = manifest.get("rule_hashes")
        if not isinstance(rh, dict) or sorted(rh) != sorted(rule_ids):
            issues.append(EvidenceIssue(
                "rule_hashes_incomplete",
                f"rule_hashes keys != required {sorted(rule_ids)}", "manifest.json"))
        elif not all(_HEX64_RE.match(v) for v in rh.values() if isinstance(v, str)):
            issues.append(EvidenceIssue(
                "hash_format_invalid",
                "rule_hashes value not 64-char hex", "manifest.json"))
        fc = manifest.get("flag_counts")
        if not isinstance(fc, dict) or sorted(fc) != sorted(rule_ids):
            issues.append(EvidenceIssue(
                "flag_counts_incomplete",
                "flag_counts keys != required rule ids", "manifest.json"))
        elif not all(_is_int(v) and v >= 0 for v in fc.values()):
            issues.append(EvidenceIssue(
                "flag_counts_invalid",
                "flag_counts values must be non-negative integers", "manifest.json"))
        for cf in ("source_row_count", "output_row_count"):
            if not _is_int(manifest.get(cf)) or manifest[cf] < 0:
                issues.append(EvidenceIssue(
                    "row_count_invalid",
                    f"{cf} must be a non-negative integer", "manifest.json"))
        if not isinstance(manifest.get("reconciliation"), dict) or \
                "passed" not in manifest["reconciliation"]:
            issues.append(EvidenceIssue(
                "reconciliation_missing",
                "reconciliation.passed must be recorded", "manifest.json"))
        if not isinstance(manifest.get("safety_invariants"), list) or \
                not manifest["safety_invariants"]:
            issues.append(EvidenceIssue(
                "safety_invariants_missing",
                "safety_invariants must be a non-empty list", "manifest.json"))

    # ---- run_id consistency ---------------------------------------------
    if manifest is not None:
        checks.append("run_id_consistency")
        run_id = manifest.get("run_id")
        report["run_id"] = run_id
        if not isinstance(run_id, str) or not run_id:
            issues.append(EvidenceIssue(
                "run_id_invalid", "manifest.run_id missing/empty", "manifest.json"))
        else:
            if lineage is not None and lineage.get("run_id") != run_id:
                issues.append(EvidenceIssue(
                    "run_id_mismatch",
                    f"lineage.run_id != manifest.run_id", "lineage.json"))
            if audit is not None and audit.get("run_id") != run_id:
                issues.append(EvidenceIssue(
                    "run_id_mismatch",
                    f"audit.run_id != manifest.run_id", "audit.json"))

    # ---- row count agreement --------------------------------------------
    if manifest is not None:
        checks.append("row_count_agreement")
        src = manifest.get("source_row_count")
        out = manifest.get("output_row_count")
        if _is_int(src) and _is_int(out) and src != out:
            issues.append(EvidenceIssue(
                "row_count_mismatch",
                f"source_row_count {src} != output_row_count {out}",
                "manifest.json"))
        if audit is not None:
            completed = [e for e in audit.get("events", [])
                         if isinstance(e, dict) and e.get("event_type") == "validation_completed"]
            if not completed:
                issues.append(EvidenceIssue(
                    "audit_event_missing",
                    "audit has no validation_completed event", "audit.json"))
            else:
                det = completed[-1].get("details") or {}
                for key, val in (("input_rows", src), ("output_rows", out)):
                    a = det.get(key)
                    if _is_int(val) and _is_int(a) and a != val:
                        issues.append(EvidenceIssue(
                            "row_count_mismatch",
                            f"audit {key}={a} != manifest {val}", "audit.json"))
        if lineage is not None:
            run_records = lineage.get("run_records") or []
            if run_records:
                last = run_records[-1]
                lr = last.get("row_count") if isinstance(last, dict) else None
                if _is_int(src) and _is_int(lr) and lr != src:
                    issues.append(EvidenceIssue(
                        "row_count_mismatch",
                        f"lineage final row_count {lr} != manifest {src}",
                        "lineage.json"))

    # ---- flag count agreement -------------------------------------------
    if manifest is not None and audit is not None:
        checks.append("flag_count_agreement")
        completed = [e for e in audit.get("events", [])
                     if isinstance(e, dict) and e.get("event_type") == "validation_completed"]
        if completed:
            a_fc = (completed[-1].get("details") or {}).get("flag_counts") or {}
            m_fc = manifest.get("flag_counts") or {}
            if sorted(a_fc) != sorted(m_fc) or any(a_fc.get(k) != m_fc.get(k) for k in m_fc):
                issues.append(EvidenceIssue(
                    "flag_count_mismatch",
                    "audit flag_counts != manifest flag_counts", "audit.json"))
        src = manifest.get("source_row_count")
        m_fc = manifest.get("flag_counts") or {}
        if _is_int(src) and m_fc:
            total = sum(v for v in m_fc.values() if isinstance(v, int))
            if total > src * len(rule_ids):
                issues.append(EvidenceIssue(
                    "flag_count_impossible",
                    f"total flags {total} > rows×rules ({src}×{len(rule_ids)})",
                    "manifest.json"))

    # ---- verdict agreement ----------------------------------------------
    if manifest is not None:
        checks.append("verdict_agreement")
        if audit is not None:
            failed = [e for e in audit.get("events", [])
                      if isinstance(e, dict) and e.get("event_type") == "run_failed"]
            if manifest.get("manifest_type") == "success" and failed:
                issues.append(EvidenceIssue(
                    "contradictory_status",
                    "success manifest coexists with run_failed event", "audit.json"))
        if alerts is not None:
            alert_list = alerts if isinstance(alerts, list) else (
                alerts.get("alerts") if isinstance(alerts, dict) else [])
            rec_fail = [a for a in (alert_list if isinstance(alert_list, list) else [])
                        if isinstance(a, dict) and "reconciliation" in str(a.get("type", ""))]
            rec = manifest.get("reconciliation") or {}
            if rec.get("passed") is True and rec_fail:
                issues.append(EvidenceIssue(
                    "contradictory_status",
                    "reconciliation passed but failure alert recorded", "alerts.json"))

    # ---- lineage serialization ------------------------------------------
    if lineage is not None:
        checks.append("lineage_serialization")
        raw = ""
        try:
            with open(os.path.join(evidence_dir, "lineage.json"), "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError:
            pass
        for marker in _REPR_MARKERS:
            if marker in raw:
                issues.append(EvidenceIssue(
                    "lineage_repr_leak",
                    f"lineage contains Python repr: {marker!r}", "lineage.json"))
        rr = lineage.get("run_records")
        if not isinstance(rr, list) or not rr:
            issues.append(EvidenceIssue(
                "lineage_run_records_missing",
                "lineage has no run_records", "lineage.json"))
        row_records = lineage.get("row_records")
        if not isinstance(row_records, list):
            issues.append(EvidenceIssue(
                "lineage_row_records_missing",
                "row_records must be a list", "lineage.json"))
        else:
            for r in row_records:
                if not isinstance(r, dict):
                    issues.append(EvidenceIssue(
                        "lineage_record_not_dict",
                        "row_records entry not a dict", "lineage.json"))
                    break
                missing = [f for f in _LINEAGE_ROW_FIELDS if f not in r]
                if missing:
                    issues.append(EvidenceIssue(
                        "lineage_field_missing",
                        f"row record missing: {missing}", "lineage.json"))
                    break
                if r.get("rule_id") not in rule_ids:
                    issues.append(EvidenceIssue(
                        "lineage_unknown_rule",
                        f"unknown rule_id {r.get('rule_id')!r}", "lineage.json"))
                    break

    # ---- referenced artifacts + hash recomputation ----------------------
    if manifest is not None:
        checks.append("referenced_artifacts")
        gf = manifest.get("generated_files") or {}
        if not isinstance(gf, dict) or not gf:
            issues.append(EvidenceIssue(
                "generated_files_missing",
                "generated_files must be non-empty mapping", "manifest.json"))
        for name, path in gf.items():
            if not path or not os.path.isfile(str(path)):
                issues.append(EvidenceIssue(
                    "referenced_artifact_missing",
                    f"generated_files.{name} absent: {path!r}", "manifest.json"))
                continue
            fh = (manifest.get("file_hashes") or {}).get(name)
            if fh is None:
                issues.append(EvidenceIssue(
                    "file_hash_missing",
                    f"no hash for {name!r}", "manifest.json"))
            else:
                actual = hashlib.sha256(open(str(path), "rb").read()).hexdigest()
                if actual != fh:
                    issues.append(EvidenceIssue(
                        "file_hash_mismatch",
                        f"{name}: recorded {fh[:12]}... != actual {actual[:12]}...",
                        "manifest.json"))
        # Output column count contract (33 → 41)
        out_path = gf.get("output")
        if out_path and os.path.isfile(str(out_path)):
            try:
                with open(str(out_path), "r", newline="", encoding="utf-8") as f:
                    header = f.readline().rstrip("\r\n").split(",")
                if len(header) != TOTAL_OUTPUT_COLUMNS:
                    issues.append(EvidenceIssue(
                        "output_column_count_invalid",
                        f"output has {len(header)} cols, expected {TOTAL_OUTPUT_COLUMNS}",
                        "manifest.json"))
            except OSError:
                pass

    details["issue_count"] = len(issues)
    report["issues"] = [i.to_dict() for i in issues]
    report["checks_performed"] = checks
    report["valid"] = not issues
    return report


def require_valid_evidence(evidence_dir: str, **kwargs) -> Dict[str, Any]:
    """Strict wrapper: raises ``EvidenceConsistencyError`` when invalid."""
    report = validate_evidence_dir(evidence_dir, **kwargs)
    if not report["valid"]:
        raise EvidenceConsistencyError(
            [EvidenceIssue(i["code"], i["message"], i["artifact"])
             for i in report["issues"]], report)
    return report
