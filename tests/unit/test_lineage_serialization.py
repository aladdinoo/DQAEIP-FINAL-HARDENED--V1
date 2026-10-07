"""Regression tests for lineage JSON serialization (DQAVP hardening, Section 3).

Historical defect (fixed 2026-09-15): ``LineageRecorder.persist()`` wrote
``row_records`` as raw ``RowLineageRecord`` objects through
``json.dump(..., default=str)``, producing Python repr strings such as
``<data_quality_platform.lineage.recorder.RowLineageRecord object at 0x...>``
instead of structured JSON dictionaries.

The fix serializes each record with ``to_dict()`` and REMOVES the
``default=str`` fallback so that any future non-JSON-serializable object in
the evidence layer fails closed (TypeError) instead of silently persisting
an opaque repr string.

These tests pin the fixed behavior:
- persisted row_records are JSON dictionaries
- required lineage fields exist
- no Python object repr strings exist anywhere in the file
- the file can be parsed independently by a fresh json.load
- truncated metadata remains correct
- total_row_records remains correct
"""

import json
import os

import pytest

from data_quality_platform.lineage.recorder import (
    LineageRecorder,
    RowLineageRecord,
)

REQUIRED_ROW_FIELDS = (
    "run_id",
    "row_number",
    "rule_id",
    "rule_version",
    "flag_value",
    "row_hash",
    "timestamp",
)


def _record_many(lr, n, rule_id="email_blank", version="1.0.0"):
    for i in range(1, n + 1):
        lr.record_row_flag(
            i, rule_id, version, 1,
            row={"id": str(i), "zip": "10001", "state": "NY",
                 "source": "web", "country": "US"},
        )


class TestLineageSerializationContract:
    def test_row_records_are_json_dictionaries(self, tmp_path):
        lr = LineageRecorder("run_ser_1", str(tmp_path))
        _record_many(lr, 3)
        path = lr.persist()
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        data = json.loads(raw)
        assert isinstance(data["row_records"], list)
        assert len(data["row_records"]) == 3
        for rec in data["row_records"]:
            assert isinstance(rec, dict), (
                "persisted row_records must be JSON objects, got "
                f"{type(rec).__name__}"
            )

    def test_required_lineage_fields_exist(self, tmp_path):
        lr = LineageRecorder("run_ser_2", str(tmp_path))
        _record_many(lr, 2)
        path = lr.persist()
        data = json.load(open(path, encoding="utf-8"))
        for rec in data["row_records"]:
            for field in REQUIRED_ROW_FIELDS:
                assert field in rec, f"missing lineage field: {field}"
            assert rec["run_id"] == "run_ser_2"
            assert rec["rule_id"] == "email_blank"
            assert rec["rule_version"] == "1.0.0"
            assert rec["flag_value"] == 1
            assert isinstance(rec["row_number"], int)
            assert isinstance(rec["flag_value"], int)
            assert isinstance(rec["row_hash"], str) and rec["row_hash"] != ""

    def test_no_python_repr_strings_in_file(self, tmp_path):
        lr = LineageRecorder("run_ser_3", str(tmp_path))
        _record_many(lr, 5)
        path = lr.persist()
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        for banned in (
            "RowLineageRecord object at",
            "LineageRecord object at",
            "object at 0x",
            "<data_quality_platform",
        ):
            assert banned not in raw, f"repr artifact leaked: {banned!r}"

    def test_json_parses_independently(self, tmp_path):
        """A fresh interpreter-independent parse must succeed with no
        Python-specific tolerance (no default=, no eval)."""
        lr = LineageRecorder("run_ser_4", str(tmp_path))
        _record_many(lr, 2)
        lr.record_run(source="input.csv", row_count=2, schema_hash="s" * 64)
        path = lr.persist()
        # Strict re-parse of the exact persisted bytes.
        with open(path, "rb") as f:
            payload = f.read()
        data = json.loads(payload.decode("utf-8"))
        assert data["run_id"] == "run_ser_4"
        assert len(data["run_records"]) == 1
        assert data["run_records"][0]["source"] == "input.csv"
        assert len(data["row_records"]) == 2

    def test_truncation_metadata_correct(self, tmp_path):
        lr = LineageRecorder("run_ser_5", str(tmp_path))
        _record_many(lr, 1500)  # above the 1000 cap
        path = lr.persist()
        data = json.load(open(path, encoding="utf-8"))
        assert len(data["row_records"]) == 1000
        assert data["total_row_records"] == 1500
        assert data["truncated"] is True
        # First 1000 records are rows 1..1000 in order.
        assert data["row_records"][0]["row_number"] == 1
        assert data["row_records"][999]["row_number"] == 1000

    def test_total_row_records_exact_without_truncation(self, tmp_path):
        lr = LineageRecorder("run_ser_6", str(tmp_path))
        _record_many(lr, 7)
        path = lr.persist()
        data = json.load(open(path, encoding="utf-8"))
        assert data["total_row_records"] == 7
        assert data["truncated"] is False
        assert len(data["row_records"]) == 7

    def test_fail_closed_on_non_serializable_object(self, tmp_path):
        """The removed default=str fallback must now fail closed: injecting
        a non-JSON object into row_records raises on persist (AttributeError
        for objects without to_dict, TypeError for to_dict results that are
        not JSON-serializable). Under the old code this silently wrote a
        repr string and returned exit code 0."""
        lr = LineageRecorder("run_ser_7", str(tmp_path))
        _record_many(lr, 1)
        # Simulate a future regression that appends a raw object.
        lr.row_records.append(object())
        with pytest.raises((TypeError, AttributeError)):
            lr.persist()

    def test_fail_closed_on_non_serializable_to_dict_result(self, tmp_path):
        """Even a to_dict()-like result that is not JSON-serializable must
        raise TypeError from json.dump (no default=str rescue)."""

        class FakeRecord(RowLineageRecord):
            def to_dict(self):
                return {"bad": object()}

        lr = LineageRecorder("run_ser_7b", str(tmp_path))
        _record_many(lr, 1)
        lr.row_records.append(FakeRecord("run", 2, "r", "1.0.0", 1))
        with pytest.raises(TypeError):
            lr.persist()

    def test_row_hash_uses_identity_fields_not_pii(self, tmp_path):
        lr = LineageRecorder("run_ser_8", str(tmp_path))
        lr.record_row_flag(1, "email_blank", "1.0.0", 1,
                           row={"id": "1", "zip": "10001", "state": "NY",
                                "source": "web", "email_address": "a@b.co",
                                "first_name": "Alice", "last_name": "Doe"})
        path = lr.persist()
        data = json.load(open(path, encoding="utf-8"))
        rec = data["row_records"][0]
        assert rec["row_hash"] != ""
        assert "a@b.co" not in json.dumps(rec)  # no PII in persisted record

    def test_engine_end_to_end_lineage_is_structured(self, tmp_path):
        """Integration: the production engine's persisted lineage.json must
        contain structured row_records after the fix."""
        import csv

        from data_quality_platform.validation.engine import ValidationEngine

        src = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        evd = tmp_path / "evidence"
        cols = ["id", "first_name", "last_name", "email_address", "zip",
                "state", "source", "country"]
        # Build a minimal 33-column header using empty extras.
        import data_quality_platform.contracts as C
        header = C.SOURCE_COLUMNS
        with open(src, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            row = {c: "" for c in header}
            row.update({"id": "1", "email_address": "", "zip": "10001",
                        "state": "NY", "first_name": "Test",
                        "last_name": "User", "source": "web", "country": "US"})
            w.writerow([row[c] for c in header])
        engine = ValidationEngine(run_id="run_e2e_ser", evidence_dir=str(evd))
        result = engine.validate(str(src), str(out))
        assert result.success, result.error
        lineage = json.load(open(result.lineage_path, encoding="utf-8"))
        assert len(lineage["row_records"]) >= 1
        for rec in lineage["row_records"]:
            assert isinstance(rec, dict)
            for field in REQUIRED_ROW_FIELDS:
                assert field in rec
        raw = open(result.lineage_path, encoding="utf-8").read()
        assert "object at 0x" not in raw
