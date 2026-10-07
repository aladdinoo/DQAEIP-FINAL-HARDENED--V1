import json
import os
from data_quality_platform.alerting.alerts import AlertManager


class TestAlertManager:
    def test_alert_creation(self, tmp_path):
        am = AlertManager(str(tmp_path))
        alert = am.alert("warning", "test_alert", "test message")
        assert alert.alert_type == "test_alert"
        assert alert.severity == "warning"

    def test_validation_failure_alert(self, tmp_path):
        am = AlertManager(str(tmp_path))
        am.alert_validation_failure("run1", "schema error")
        assert am.has_alert_type("validation_failure")
        assert am.has_critical()

    def test_sla_breach_alert(self, tmp_path):
        am = AlertManager(str(tmp_path))
        am.alert_sla_breach("run1", "completeness", 0.8, 0.95)
        assert am.has_alert_type("sla_breach")
        assert not am.has_critical()

    def test_reconciliation_failure_alert(self, tmp_path):
        am = AlertManager(str(tmp_path))
        am.alert_reconciliation_failure("run1", {"error": "mismatch"})
        assert am.has_alert_type("reconciliation_failure")

    def test_persist(self, tmp_path):
        am = AlertManager(str(tmp_path))
        am.alert("info", "test", "msg")
        path = am.persist()
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert len(data) == 1

    def test_no_critical_by_default(self, tmp_path):
        am = AlertManager(str(tmp_path))
        assert not am.has_critical()
