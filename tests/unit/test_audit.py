import json
import os
from data_quality_platform.audit.trail import AuditTrail, AuditEventType


class TestAuditTrail:
    def test_record_run_started(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_run_started("test.csv")
        assert at.has_event(AuditEventType.RUN_STARTED)

    def test_record_schema_validated(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_schema_validated("hash123")
        assert at.has_event(AuditEventType.SCHEMA_VALIDATED)

    def test_record_rules_loaded(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_rules_loaded(8, "rh")
        assert at.has_event(AuditEventType.RULES_LOADED)

    def test_record_validation_completed(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_validation_completed(100, 100, {"a": 5}, 1.5)
        assert at.has_event(AuditEventType.VALIDATION_COMPLETED)

    def test_record_run_failed(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_run_failed("SchemaError", "bad schema", "schema_validation")
        assert at.has_event(AuditEventType.RUN_FAILED)

    def test_persist_creates_file(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_run_started("test.csv")
        at.record_schema_validated()
        path = at.persist()
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["run_id"] == "run1"
        assert len(data["events"]) == 2

    def test_get_events_by_type(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_run_started("a")
        at.record_run_started("b")
        events = at.get_events_by_type(AuditEventType.RUN_STARTED)
        assert len(events) == 2

    def test_record_access(self, tmp_path):
        at = AuditTrail("run1", str(tmp_path))
        at.record_access(user="admin", action="read", resource="evidence")
        assert at.has_event(AuditEventType.ACCESS_LOGGED)
