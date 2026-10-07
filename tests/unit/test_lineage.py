import json
import os
from data_quality_platform.lineage.recorder import (
    LineageRecorder, compute_row_identity_hash,
)


class TestLineageRecorder:
    def test_record_run(self, tmp_path):
        lr = LineageRecorder("test_run", str(tmp_path))
        lr.record_run(source="test.csv", row_count=100, schema_hash="abc")
        assert len(lr.records) == 1
        assert lr.records[0].source == "test.csv"

    def test_record_row_flag(self, tmp_path):
        lr = LineageRecorder("test_run", str(tmp_path))
        lr.record_row_flag(1, "email_blank", "1.0.0", 1)
        assert len(lr.row_records) == 1
        assert lr.row_records[0].flag_value == 1

    def test_persist_creates_file(self, tmp_path):
        lr = LineageRecorder("test_run", str(tmp_path))
        lr.record_run(source="test.csv", row_count=100)
        lr.record_row_flag(1, "email_blank", "1.0.0", 1)
        path = lr.persist()
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["run_id"] == "test_run"
        assert data["total_row_records"] == 1

    def test_row_identity_hash_no_pii(self, tmp_path):
        row = {
            "id": "123", "email_address": "secret@example.com",
            "first_name": "Secret", "last_name": "Person",
            "zip": "10001", "state": "NY", "country": "US", "source": "web",
        }
        h = compute_row_identity_hash(row)
        assert len(h) == 16
        # Hash should NOT depend on PII
        row2 = dict(row)
        row2["email_address"] = "different@example.com"
        row2["first_name"] = "Different"
        h2 = compute_row_identity_hash(row2)
        assert h == h2  # Same identity fields = same hash

    def test_get_summary(self, tmp_path):
        lr = LineageRecorder("test_run", str(tmp_path))
        lr.record_run(source="test.csv")
        lr.record_row_flag(1, "email_blank", "1.0.0", 1)
        summary = lr.get_summary()
        assert summary["run_records_count"] == 1
        assert summary["row_records_count"] == 1
