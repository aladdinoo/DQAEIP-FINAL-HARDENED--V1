"""Failure Taxonomy tests (DQAVP enterprise hardening, Section 18)."""

import json

import pytest

from data_quality_platform.validation.failure_taxonomy import (
    CLASS_DESCRIPTIONS, FAILURE_CLASSES, SEVERITIES,
    build_failure_record, classify_exception, format_failure_record,
    taxonomy_definition, to_json,
)


def test_taxonomy_is_closed_and_complete():
    assert len(FAILURE_CLASSES) == 13
    assert set(CLASS_DESCRIPTIONS) == set(FAILURE_CLASSES)
    assert SEVERITIES == ("BLOCKER", "MAJOR", "MINOR")


def test_record_contains_required_fields():
    rec = build_failure_record(
        "EVIDENCE_ERROR", severity="MAJOR", gate="evidence_validation",
        reason="manifest row count disagrees with lineage",
        evidence={"file": "manifest.json"},
        remediation="re-run validation with evidence validator",
    )
    for field in ("failure_class", "severity", "gate", "reason",
                  "evidence", "remediation", "recorded_utc"):
        assert field in rec
    assert rec["failure_class"] == "EVIDENCE_ERROR"
    assert rec["severity"] == "MAJOR"
    assert rec["evidence"] == {"file": "manifest.json"}


def test_record_rejects_unknown_class_and_severity():
    with pytest.raises(ValueError):
        build_failure_record("NOT_A_CLASS", severity="MAJOR",
                             gate="g", reason="r")
    with pytest.raises(ValueError):
        build_failure_record("DATA_ERROR", severity="SUPER_BAD",
                             gate="g", reason="r")


def test_record_is_json_serializable():
    rec = build_failure_record(
        "NON_DETERMINISM", severity="BLOCKER", gate="replay",
        reason="output hash differs between runs",
        evidence={"run1": "aa", "run2": "bb"})
    parsed = json.loads(to_json(rec))
    assert parsed["failure_class"] == "NON_DETERMINISM"


def test_format_renders_class_and_gate():
    rec = build_failure_record(
        "SECURITY_ERROR", severity="BLOCKER", gate="pii_evidence_scan",
        reason="non-synthetic email domain in evidence")
    text = format_failure_record(rec)
    assert "[SECURITY_ERROR/BLOCKER]" in text
    assert "gate=pii_evidence_scan" in text
    assert "remediation" in text


class _FakeInputContractError(Exception):
    pass


class _FakeEvidenceValidationError(Exception):
    pass


class _FakeReplayMismatch(AssertionError):
    pass


def test_classify_exception_anchors():
    from data_quality_platform.validation.input_contract import (
        InputContractError)
    from data_quality_platform.validation.replay import ReplayMismatch
    from data_quality_platform.rules.registry import RuleRegistryError

    assert classify_exception(
        InputContractError("bad")) == "CONTRACT_ERROR"
    assert classify_exception(
        ReplayMismatch("bad")) == "NON_DETERMINISM"
    assert classify_exception(
        RuleRegistryError("bad")) == "RULE_ERROR"
    assert classify_exception(UnicodeDecodeError(
        "utf-8", b"\xff", 0, 1, "invalid")) == "DATA_ERROR"


def test_classify_exception_unknown_fails_to_review_required():
    class NovelProblem(Exception):
        pass

    assert classify_exception(NovelProblem("?")) == "REVIEW_REQUIRED"


def test_exception_attached_and_classified():
    from data_quality_platform.validation.replay import ReplayMismatch
    rec = build_failure_record(
        "NON_DETERMINISM", severity="BLOCKER", gate="replay",
        reason="deterministic replay produced different output hashes",
        exception=ReplayMismatch("run 2: output_sha256 differs"))
    assert rec["exception"]["type"] == "ReplayMismatch"
    assert rec["exception"]["classified_as"] == "NON_DETERMINISM"


def test_taxonomy_definition_schema():
    definition = taxonomy_definition()
    assert definition["taxonomy_version"] == "1.0.0"
    assert len(definition["failure_classes"]) == 13
    assert definition["default_for_unknown_exception"] == "REVIEW_REQUIRED"
