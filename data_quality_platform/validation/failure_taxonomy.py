"""Structured Failure Taxonomy (DQAVP enterprise hardening, Section 18).

Every failed release gate / validation stage must identify:

    failure_class / severity / gate / reason / evidence / remediation

This module defines the closed taxonomy of failure classes and builds
structured, machine-readable failure records. It is ADDITIVE: existing
exceptions and error paths are unchanged — they are CLASSIFIED here.

Severity levels:

    BLOCKER  — release cannot proceed
    MAJOR    — gate failed; release blocked until remediated
    MINOR    — recorded warning; does not alone block release
               (e.g. performance within WARN threshold)

Class mapping is explicit and test-enforced: a class with no
programmatic anchor is documented as REVIEW_REQUIRED rather than
guessed.
"""

import json
import time
from typing import Any, Dict, Optional

__all__ = [
    "FailureClass",
    "Severity",
    "FAILURE_CLASSES",
    "SEVERITIES",
    "CLASS_DESCRIPTIONS",
    "build_failure_record",
    "classify_exception",
    "format_failure_record",
]

FailureClass = str
Severity = str

FAILURE_CLASSES = (
    "DATA_ERROR",
    "CONTRACT_ERROR",
    "CONFIG_ERROR",
    "RULE_ERROR",
    "REFERENCE_ERROR",
    "EVIDENCE_ERROR",
    "NON_DETERMINISM",
    "SECURITY_ERROR",
    "PERFORMANCE_ERROR",
    "ENVIRONMENT_ERROR",
    "INFRASTRUCTURE_ERROR",
    "AUTHORIZATION_ERROR",
    "REVIEW_REQUIRED",
)

SEVERITIES = ("BLOCKER", "MAJOR", "MINOR")

CLASS_DESCRIPTIONS = {
    "DATA_ERROR":
        "input data violates structural expectations (encoding, ragged "
        "rows, NUL bytes, unreadable file)",
    "CONTRACT_ERROR":
        "input/output contract violation (columns, order, duplicates, "
        "schema version, identifier sanity)",
    "CONFIG_ERROR":
        "configuration malformed, incompatible, or missing required "
        "keys/threshold ranges",
    "RULE_ERROR":
        "rule registry or rule execution defect (missing rule, wrong "
        "version, unexpected exception)",
    "REFERENCE_ERROR":
        "reference data missing, invalid, hash-mismatched, or "
        "unverifiable for a decision that requires it",
    "EVIDENCE_ERROR":
        "evidence artifact missing, malformed, internally inconsistent, "
        "or tamper-detected",
    "NON_DETERMINISM":
        "deterministic replay produced different results (hashes, "
        "counts, or bytes)",
    "SECURITY_ERROR":
        "security boundary violation (PII in evidence, secrets, "
        "unauthorized activation/mutation attempt)",
    "PERFORMANCE_ERROR":
        "performance regression beyond the configured FAIL threshold",
    "ENVIRONMENT_ERROR":
        "execution environment unsuitable or unverifiable (python "
        "version, missing dependency, resource limits)",
    "INFRASTRUCTURE_ERROR":
        "external infrastructure unavailable or not exercised "
        "(ClickHouse, Airflow runtime, network)",
    "AUTHORIZATION_ERROR":
        "an operation requires explicit authorization that is not "
        "present (e.g. activation of an experimental component outside "
        "its authorized scope, or production mutation)",
    "REVIEW_REQUIRED":
        "behavior is ambiguous or disputed; business-rule adjudication "
        "by the contract owner is required before any change",
}

# Exception type -> failure class (programmatic anchors; fail-safe
# default is REVIEW_REQUIRED — never a silent pass).
_EXCEPTION_CLASS_MAP = {
    # CONTRACT_ERROR anchors
    "InputContractError": "CONTRACT_ERROR",
    # EVIDENCE_ERROR anchors
    "EvidenceValidationError": "EVIDENCE_ERROR",
    # NON_DETERMINISM anchors
    "ReplayMismatch": "NON_DETERMINISM",
    # RULE_ERROR anchors
    "RuleRegistryError": "RULE_ERROR",
    # REFERENCE_ERROR anchors
    "ReferenceUnavailableError": "REFERENCE_ERROR",
    # AUTHORIZATION anchors
    "AuthorizationError": "AUTHORIZATION_ERROR",
    # CONFIG anchors
    "ConfigError": "CONFIG_ERROR",
    "PlatformConfigError": "CONFIG_ERROR",
    # DATA anchors
    "UnicodeDecodeError": "DATA_ERROR",
    "csv.Error": "DATA_ERROR",
    # SECURITY anchors
    "PIIScanViolation": "SECURITY_ERROR",
}


def classify_exception(exc: BaseException) -> FailureClass:
    """Map an exception to a failure class. Unknown types classify as
    REVIEW_REQUIRED (never silently pass as a lesser class)."""
    for name in (type(exc).__name__, *(
            t.__name__ for t in type(exc).__mro__[1:-1])):
        if name in _EXCEPTION_CLASS_MAP:
            return _EXCEPTION_CLASS_MAP[name]
    return "REVIEW_REQUIRED"


def build_failure_record(
    failure_class: FailureClass,
    *,
    severity: Severity,
    gate: str,
    reason: str,
    evidence: Optional[Dict[str, Any]] = None,
    remediation: Optional[str] = None,
    exception: Optional[BaseException] = None,
) -> Dict[str, Any]:
    """Build one structured failure record (fully JSON-serializable)."""
    if failure_class not in FAILURE_CLASSES:
        raise ValueError(
            f"unknown failure_class {failure_class!r}; "
            f"known: {FAILURE_CLASSES}")
    if severity not in SEVERITIES:
        raise ValueError(
            f"unknown severity {severity!r}; known: {SEVERITIES}")

    record: Dict[str, Any] = {
        "failure_class": failure_class,
        "class_description": CLASS_DESCRIPTIONS[failure_class],
        "severity": severity,
        "gate": gate,
        "reason": reason,
        "evidence": evidence or {},
        "remediation": remediation or "not specified",
        "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime()),
    }
    if exception is not None:
        record["exception"] = {
            "type": type(exception).__name__,
            "message": str(exception)[:500],
            "classified_as": classify_exception(exception),
        }
    return record


def format_failure_record(record: Dict[str, Any]) -> str:
    """Human-readable one-block rendering of a failure record."""
    return (
        f"[{record['failure_class']}/{record['severity']}] "
        f"gate={record['gate']}\n"
        f"  reason:      {record['reason']}\n"
        f"  remediation: {record['remediation']}"
    )


def taxonomy_definition() -> Dict[str, Any]:
    """The full taxonomy definition (for evidence embedding)."""
    return {
        "taxonomy_version": "1.0.0",
        "failure_classes": list(FAILURE_CLASSES),
        "severities": list(SEVERITIES),
        "class_descriptions": dict(CLASS_DESCRIPTIONS),
        "default_for_unknown_exception": "REVIEW_REQUIRED",
        "record_schema": ["failure_class", "severity", "gate", "reason",
                          "evidence", "remediation",
                          "recorded_utc", "exception (optional)"],
    }


def to_json(record: Dict[str, Any]) -> str:
    return json.dumps(record, indent=2, ensure_ascii=False)
