"""Evidence consistency validator tests.

Tests the ``validate_evidence_dir`` function in
``data_quality_platform/validation/evidence_consistency.py`` against:

  - valid evidence (passes)
  - missing artifacts (fails)
  - corrupt JSON (fails)
  - row-count tamper (fails)
  - output hash mismatch (fails)
  - referenced artifact deleted (fails)
  - run_id mismatch (fails)
  - rule hash format invalid (fails)
  - failure manifest rejected when success expected (fails)
  - contradictory run_failed event (fails)
  - lineage repr leak (fails)
  - lineage row record missing field (fails)
  - lineage unknown rule reference (fails)
  - flag count exceeds rows×rules (fails)
"""

import json
import os

import pytest

from data_quality_platform.validation.engine import ValidationEngine
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.generation.synthetic import SyntheticDataGenerator
from data_quality_platform.validation.evidence_consistency import (
    validate_evidence_dir, require_valid_evidence, EvidenceConsistencyError,
)


@pytest.fixture
def good_run(tmp_path):
    """A clean engine run that produces valid evidence."""
    csv_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    ev_dir = str(tmp_path / "ev")
    SyntheticDataGenerator(seed=42).generate(50, str(csv_path))
    engine = ValidationEngine(
        rules=RuleRegistry.create_default(),
        run_id="good", evidence_dir=ev_dir)
    result = engine.validate(csv_path=str(csv_path), output_path=str(out_path))
    assert result.success, f"setup run failed: {result.error}"
    return ev_dir, str(out_path)


class TestValidEvidencePasses:
    def test_real_engine_run_is_valid(self, good_run):
        ev_dir, _ = good_run
        report = validate_evidence_dir(ev_dir)
        assert report["valid"], \
            f"valid evidence rejected: {report['issues']}"

    def test_strict_wrapper_accepts_valid(self, good_run):
        ev_dir, _ = good_run
        report = require_valid_evidence(ev_dir)
        assert report["valid"]


class TestFailClosed:
    def test_missing_evidence_dir(self, tmp_path):
        report = validate_evidence_dir(str(tmp_path / "nonexistent"))
        assert not report["valid"]

    def test_missing_manifest(self, good_run, tmp_path):
        ev_dir, _ = good_run
        os.remove(os.path.join(ev_dir, "manifest.json"))
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "required_file_missing" for i in report["issues"])

    def test_corrupt_json(self, good_run):
        ev_dir, _ = good_run
        with open(os.path.join(ev_dir, "manifest.json"), "w") as f:
            f.write("{not valid json")
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "json_invalid" for i in report["issues"])

    def test_row_count_tamper(self, good_run):
        ev_dir, _ = good_run
        manifest_path = os.path.join(ev_dir, "manifest.json")
        doc = json.load(open(manifest_path))
        doc["source_row_count"] = doc["source_row_count"] + 1
        with open(manifest_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "row_count_mismatch" for i in report["issues"])

    def test_output_file_tamper_hash_mismatch(self, good_run):
        ev_dir, out_path = good_run
        with open(out_path, "a") as f:
            f.write("tamper,appendix,row\n")
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "file_hash_mismatch" for i in report["issues"])

    def test_referenced_artifact_deleted(self, good_run):
        ev_dir, out_path = good_run
        os.remove(out_path)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "referenced_artifact_missing" for i in report["issues"])

    def test_run_id_mismatch(self, good_run):
        ev_dir, _ = good_run
        lineage_path = os.path.join(ev_dir, "lineage.json")
        doc = json.load(open(lineage_path))
        doc["run_id"] = "WRONG"
        with open(lineage_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "run_id_mismatch" for i in report["issues"])

    def test_rule_hash_format_invalid(self, good_run):
        ev_dir, _ = good_run
        manifest_path = os.path.join(ev_dir, "manifest.json")
        doc = json.load(open(manifest_path))
        doc["rule_hashes"]["email_blank"] = "not-a-hash"
        with open(manifest_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "hash_format_invalid" for i in report["issues"])

    def test_failure_manifest_rejected_when_success_expected(self, good_run):
        ev_dir, _ = good_run
        manifest_path = os.path.join(ev_dir, "manifest.json")
        doc = json.load(open(manifest_path))
        doc["manifest_type"] = "failure"
        with open(manifest_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "manifest_not_success" for i in report["issues"])

    def test_contradictory_run_failed_event(self, good_run):
        ev_dir, _ = good_run
        audit_path = os.path.join(ev_dir, "audit.json")
        doc = json.load(open(audit_path))
        doc["events"].append({
            "event_type": "run_failed",
            "error_type": "InjectedError",
            "error_message": "contradictory",
        })
        with open(audit_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "contradictory_status" for i in report["issues"])

    def test_lineage_repr_leak_detected(self, good_run):
        ev_dir, _ = good_run
        lineage_path = os.path.join(ev_dir, "lineage.json")
        raw = open(lineage_path).read()
        # Inject a Python repr artifact.
        raw = raw.replace('"row_hash"', '"RowLineageRecord object at 0x7f1234567890"', 1)
        with open(lineage_path, "w") as f:
            f.write(raw)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "lineage_repr_leak" for i in report["issues"])

    def test_lineage_row_record_missing_field(self, good_run):
        ev_dir, _ = good_run
        lineage_path = os.path.join(ev_dir, "lineage.json")
        doc = json.load(open(lineage_path))
        if doc.get("row_records"):
            del doc["row_records"][0]["rule_id"]
        with open(lineage_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "lineage_field_missing" for i in report["issues"])

    def test_lineage_unknown_rule_reference(self, good_run):
        ev_dir, _ = good_run
        lineage_path = os.path.join(ev_dir, "lineage.json")
        doc = json.load(open(lineage_path))
        if doc.get("row_records"):
            doc["row_records"][0]["rule_id"] = "totally_unknown_rule"
        with open(lineage_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "lineage_unknown_rule" for i in report["issues"])

    def test_flag_count_impossible_exceeds_rows_x_rules(self, good_run):
        ev_dir, _ = good_run
        manifest_path = os.path.join(ev_dir, "manifest.json")
        doc = json.load(open(manifest_path))
        # Set flag_counts to an impossibly high value.
        for k in doc["flag_counts"]:
            doc["flag_counts"][k] = 999999
        with open(manifest_path, "w") as f:
            json.dump(doc, f)
        report = validate_evidence_dir(ev_dir)
        assert not report["valid"]
        assert any(i["code"] == "flag_count_impossible" for i in report["issues"])

    def test_strict_wrapper_raises(self, good_run):
        ev_dir, _ = good_run
        os.remove(os.path.join(ev_dir, "manifest.json"))
        with pytest.raises(EvidenceConsistencyError):
            require_valid_evidence(ev_dir)
