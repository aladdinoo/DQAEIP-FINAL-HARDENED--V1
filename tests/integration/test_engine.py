import csv
import json
import os
from data_quality_platform.validation.engine import ValidationEngine
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.generation.synthetic import SyntheticDataGenerator
from data_quality_platform.contracts import (
    SOURCE_COLUMNS, FLAG_COLUMNS, TOTAL_OUTPUT_COLUMNS, OUTPUT_COLUMNS,
)
from data_quality_platform.evidence.manifests import ManifestReader


class TestValidationEngineIntegration:
    """Integration tests: full pipeline from CSV to Flag Preview."""

    def test_100_rows_end_to_end(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(100, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_100",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)

        assert result.success
        assert result.input_row_count == 100
        assert result.output_row_count == 100
        assert os.path.exists(out_path)
        assert os.path.exists(ev_dir)

    def test_41_column_output(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(50, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_41col",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)
        assert result.success

        with open(out_path, "r") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            assert len(header) == TOTAL_OUTPUT_COLUMNS
            assert header == OUTPUT_COLUMNS
            for row in reader:
                for fc in FLAG_COLUMNS:
                    assert row[fc] in ("0", "1"), f"{fc}={row[fc]}"

    def test_source_columns_unchanged(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(20, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_passthrough",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)
        assert result.success

        # Read input and output, compare source columns
        with open(csv_path, "r") as f:
            input_rows = list(csv.DictReader(f))
        with open(out_path, "r") as f:
            output_rows = list(csv.DictReader(f))

        for i, (in_row, out_row) in enumerate(zip(input_rows, output_rows)):
            for col in SOURCE_COLUMNS:
                assert in_row[col] == out_row[col], f"Row {i+1}, col {col} changed"

    def test_manifest_success(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(30, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_manifest",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)
        assert result.success

        manifest = ManifestReader.read(ev_dir)
        assert manifest is not None
        assert manifest["manifest_type"] == "success"
        assert manifest["source_row_count"] == 30
        assert manifest["reconciliation"]["passed"]
        assert "file_hashes" in manifest
        assert "schema_hash" in manifest

    def test_lineage_persisted(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(50, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_lineage",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)
        assert result.success

        lineage_path = os.path.join(ev_dir, "lineage.json")
        assert os.path.exists(lineage_path)
        with open(lineage_path) as f:
            lineage = json.load(f)
        assert lineage["run_id"] == "test_lineage"
        assert lineage["total_row_records"] > 0

    def test_audit_persisted(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(30, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_audit",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)
        assert result.success

        audit_path = os.path.join(ev_dir, "audit.json")
        assert os.path.exists(audit_path)
        with open(audit_path) as f:
            audit = json.load(f)
        events = [e["event_type"] for e in audit["events"]]
        assert "run_started" in events
        assert "schema_validated" in events
        assert "rules_loaded" in events
        assert "validation_completed" in events

    def test_monitoring_persisted(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(50, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_monitoring",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)
        assert result.success

        mon_path = os.path.join(ev_dir, "monitoring.json")
        assert os.path.exists(mon_path)
        with open(mon_path) as f:
            mon = json.load(f)
        assert len(mon["scores"]) == 8
        assert "overall_score" in mon

    def test_schema_mismatch_fails(self, tmp_path):
        # Create CSV with wrong columns
        csv_path = str(tmp_path / "bad.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["col1", "col2"])
            writer.writerow(["1", "2"])

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_schema_fail",
            evidence_dir=str(tmp_path / "ev"),
        )
        result = engine.validate(csv_path, str(tmp_path / "out.csv"))
        assert not result.success
        assert "Schema" in result.error

    def test_flag_counts_populated(self, tmp_path):
        gen = SyntheticDataGenerator(seed=42)
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        gen.generate(100, csv_path)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="test_flags",
            evidence_dir=ev_dir,
        )
        result = engine.validate(csv_path, out_path)
        assert result.success
        assert len(result.flag_counts) == 8
        # With 100 rows and our defect injection, some flags should be non-zero
        assert result.flag_counts["email_blank"] > 0
        assert result.flag_counts["proposed_email_export_eligible"] > 0

    def test_deterministic_output(self, tmp_path):
        gen1 = SyntheticDataGenerator(seed=999)
        gen2 = SyntheticDataGenerator(seed=999)
        csv1 = str(tmp_path / "d1.csv")
        csv2 = str(tmp_path / "d2.csv")
        out1 = str(tmp_path / "o1.csv")
        out2 = str(tmp_path / "o2.csv")
        gen1.generate(50, csv1)
        gen2.generate(50, csv2)

        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="det1",
            evidence_dir=str(tmp_path / "ev1"),
        )
        engine.validate(csv1, out1)

        engine2 = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="det2",
            evidence_dir=str(tmp_path / "ev2"),
        )
        engine2.validate(csv2, out2)

        with open(out1) as f1, open(out2) as f2:
            assert f1.read() == f2.read()
