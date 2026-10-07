"""Failure-path coverage for ValidationEngine.

GAP-CLOSURE TESTS (PHASE 20 audit): the engine's error branch
(schema failure -> failure manifest + run_failed audit event +
failure alert) previously had zero test coverage. These tests
exercise ONLY the documented failure behavior; they change no
business rule and assert no new behavior.

Read-only with respect to the repository: all artifacts are
written to pytest tmp_path.
"""

import json
import os

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.validation.engine import ValidationEngine


def _make_engine(tmp_path) -> ValidationEngine:
    return ValidationEngine(
        rules=RuleRegistry.create_default(),
        run_id="test_failure_path",
        evidence_dir=str(tmp_path / "evidence"),
    )


def _write_truncated_header_csv(path) -> None:
    """CSV whose header is missing most of the 33 required columns."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(",".join(SOURCE_COLUMNS[:3]) + "\n")
        f.write("1,a,b\n")


class TestEngineFailurePath:
    def test_schema_failure_returns_success_false(self, tmp_path):
        engine = _make_engine(tmp_path)
        src = tmp_path / "bad.csv"
        out = tmp_path / "out.csv"
        _write_truncated_header_csv(str(src))
        result = engine.validate(csv_path=str(src), output_path=str(out))
        assert result.success is False
        assert result.error  # non-empty error message
        # Schema gate fires before the output file is opened.
        assert not out.exists()

    def test_schema_failure_writes_failure_manifest(self, tmp_path):
        engine = _make_engine(tmp_path)
        src = tmp_path / "bad.csv"
        out = tmp_path / "out.csv"
        _write_truncated_header_csv(str(src))
        result = engine.validate(csv_path=str(src), output_path=str(out))
        assert result.success is False
        manifest_path = os.path.join(str(tmp_path / "evidence"), "manifest.json")
        assert os.path.exists(manifest_path)
        with open(manifest_path) as f:
            manifest = json.load(f)
        assert manifest["manifest_type"] == "failure"
        assert manifest["error_type"] == "SchemaValidationError"
        assert manifest["run_id"] == "test_failure_path"

    def test_schema_failure_records_run_failed_audit_event(self, tmp_path):
        engine = _make_engine(tmp_path)
        src = tmp_path / "bad.csv"
        out = tmp_path / "out.csv"
        _write_truncated_header_csv(str(src))
        engine.validate(csv_path=str(src), output_path=str(out))
        audit_path = os.path.join(str(tmp_path / "evidence"), "audit.json")
        assert os.path.exists(audit_path)
        with open(audit_path) as f:
            audit = json.load(f)
        event_types = [e["event_type"] for e in audit["events"]]
        assert "run_started" in event_types
        assert "run_failed" in event_types
        failed = [e for e in audit["events"] if e["event_type"] == "run_failed"][0]
        assert failed["details"]["error_type"] == "SchemaValidationError"

    def test_schema_failure_does_not_write_output_or_success_evidence(self, tmp_path):
        engine = _make_engine(tmp_path)
        src = tmp_path / "bad.csv"
        out = tmp_path / "out.csv"
        _write_truncated_header_csv(str(src))
        result = engine.validate(csv_path=str(src), output_path=str(out))
        assert result.success is False
        assert not out.exists()
        evidence_dir = str(tmp_path / "evidence")
        # monitoring.json / lineage.json belong to the success path only;
        # the failure branch persists manifest.json, audit.json and alerts.json.
        assert not os.path.exists(os.path.join(evidence_dir, "monitoring.json"))
        assert not os.path.exists(os.path.join(evidence_dir, "lineage.json"))
        assert os.path.exists(os.path.join(evidence_dir, "alerts.json"))
