import json
from data_quality_platform.evidence.manifests import ManifestWriter, ManifestReader, compute_file_sha256


class TestManifestWriter:
    def test_write_success_manifest(self, tmp_path):
        mw = ManifestWriter()
        # Create dummy files
        out_file = tmp_path / "output.csv"
        out_file.write_text("test")
        lineage_file = tmp_path / "lineage.json"
        lineage_file.write_text("{}")
        audit_file = tmp_path / "audit.json"
        audit_file.write_text("{}")
        mon_file = tmp_path / "monitoring.json"
        mon_file.write_text("{}")
        alerts_file = tmp_path / "alerts.json"
        alerts_file.write_text("{}")

        manifest = mw.write_success_manifest(
            evidence_dir=str(tmp_path),
            run_id="test_run",
            source_row_count=100,
            output_row_count=100,
            schema_hash="schema_hash_123",
            rule_hashes={"r1": "h1"},
            sql_hashes={"r1": "sh1"},
            flag_counts={"email_blank": 5},
            reconciliation={"passed": True, "errors": []},
            safety_invariants=["row_count_match"],
            lineage_reference=str(lineage_file),
            monitoring_score=0.95,
            monitoring_scores={"completeness": 0.95},
            sla_results={"completeness": True},
            generated_files={
                "output": str(out_file),
                "lineage": str(lineage_file),
                "audit": str(audit_file),
                "monitoring": str(mon_file),
                "alerts": str(alerts_file),
            },
        )
        assert manifest["manifest_type"] == "success"
        assert manifest["run_id"] == "test_run"
        assert manifest["source_row_count"] == 100
        assert "file_hashes" in manifest
        assert "manifest_hash" in manifest

    def test_write_failure_manifest(self, tmp_path):
        mw = ManifestWriter()
        manifest = mw.write_failure_manifest(
            evidence_dir=str(tmp_path),
            run_id="fail_run",
            error_type="SchemaValidationError",
            error_message="Missing columns",
            failed_step="schema_validation",
        )
        assert manifest["manifest_type"] == "failure"
        assert manifest["error_type"] == "SchemaValidationError"


class TestManifestReader:
    def test_read_success(self, tmp_path):
        mw = ManifestWriter()
        mw.write_success_manifest(
            evidence_dir=str(tmp_path), run_id="r1",
            source_row_count=10, output_row_count=10,
            schema_hash="sh", rule_hashes={}, sql_hashes={},
            flag_counts={}, reconciliation={"passed": True, "errors": []},
            safety_invariants=[], lineage_reference="",
            monitoring_score=0.9, monitoring_scores={}, sla_results={},
            generated_files={},
        )
        manifest = ManifestReader.read(str(tmp_path))
        assert manifest is not None
        assert ManifestReader.is_success(manifest)

    def test_read_missing(self, tmp_path):
        assert ManifestReader.read(str(tmp_path / "nonexistent")) is None

    def test_compute_file_sha256(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = compute_file_sha256(str(f))
        assert len(h) == 64
        h2 = compute_file_sha256(str(f))
        assert h == h2  # deterministic
