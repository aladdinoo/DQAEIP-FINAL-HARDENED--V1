import json
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Alert:
    """Single alert event."""

    def __init__(
        self,
        severity: str,
        alert_type: str,
        message: str,
        run_id: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        self.severity = severity
        self.alert_type = alert_type
        self.message = message
        self.run_id = run_id
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "alert_type": self.alert_type,
            "message": self.message,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class AlertManager:
    """Alert abstraction supporting console, email, and Slack.

    Console alerts always work.
    Email and Slack require configuration.
    External credentials are optional.
    """

    def __init__(self, evidence_dir: str = ""):
        self.alerts: List[Alert] = []
        self.evidence_dir = evidence_dir

    def alert(
        self,
        severity: str,
        alert_type: str,
        message: str,
        run_id: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Create and dispatch an alert."""
        alert_obj = Alert(
            severity=severity,
            alert_type=alert_type,
            message=message,
            run_id=run_id,
            details=details,
        )
        self.alerts.append(alert_obj)
        self._dispatch_console(alert_obj)
        return alert_obj

    def alert_validation_failure(self, run_id: str, error: str) -> Alert:
        return self.alert(
            severity=AlertSeverity.CRITICAL,
            alert_type="validation_failure",
            message=f"Validation failed for run {run_id}: {error}",
            run_id=run_id,
            details={"error": error},
        )

    def alert_sla_breach(self, run_id: str, dimension: str, score: float, threshold: float) -> Alert:
        return self.alert(
            severity=AlertSeverity.WARNING,
            alert_type="sla_breach",
            message=f"SLA breach for {dimension}: score={score}, threshold={threshold}",
            run_id=run_id,
            details={"dimension": dimension, "score": score, "threshold": threshold},
        )

    def alert_reconciliation_failure(self, run_id: str, details: Dict) -> Alert:
        return self.alert(
            severity=AlertSeverity.CRITICAL,
            alert_type="reconciliation_failure",
            message=f"Reconciliation failed for run {run_id}",
            run_id=run_id,
            details=details,
        )

    def _dispatch_console(self, alert: Alert) -> None:
        """Print alert to console."""
        print(f"[ALERT {alert.severity.upper()}] {alert.alert_type}: {alert.message}")

    def _dispatch_email(self, alert: Alert) -> None:
        """Email abstraction - V1 placeholder.

        Requires SMTP configuration via environment variables.
        """
        smtp_host = os.environ.get("DQ_SMTP_HOST")
        if not smtp_host:
            return  # Email not configured, skip silently
        # In production, this would send via SMTP
        # V1: no-op when not configured

    def _dispatch_slack(self, alert: Alert) -> None:
        """Slack abstraction - V1 placeholder.

        Requires webhook URL via environment variable.
        """
        webhook_url = os.environ.get("DQ_SLACK_WEBHOOK_URL")
        if not webhook_url:
            return  # Slack not configured, skip silently
        # In production, this would POST to webhook
        # V1: no-op when not configured

    def persist(self) -> str:
        """Write alerts to evidence directory."""
        if not self.evidence_dir:
            return ""
        os.makedirs(self.evidence_dir, exist_ok=True)
        path = os.path.join(self.evidence_dir, "alerts.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)
        return path

    def has_critical(self) -> bool:
        return any(a.severity == AlertSeverity.CRITICAL for a in self.alerts)

    def has_alert_type(self, alert_type: str) -> bool:
        return any(a.alert_type == alert_type for a in self.alerts)
