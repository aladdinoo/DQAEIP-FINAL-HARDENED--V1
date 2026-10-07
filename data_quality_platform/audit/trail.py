import json
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AuditEventType(str, Enum):
    RUN_STARTED = "run_started"
    SCHEMA_VALIDATED = "schema_validated"
    RULES_LOADED = "rules_loaded"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_COMPLETED = "validation_completed"
    OUTPUT_WRITTEN = "output_written"
    MANIFEST_WRITTEN = "manifest_written"
    RUN_FAILED = "run_failed"
    RECONCILIATION_COMPLETED = "reconciliation_completed"
    MONITORING_COMPLETED = "monitoring_completed"
    LINEAGE_RECORDED = "lineage_recorded"
    ACCESS_LOGGED = "access_logged"


class AuditEvent:
    """Single audit event."""

    def __init__(
        self,
        event_type: str,
        run_id: str,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ):
        self.event_type = event_type
        self.run_id = run_id
        self.details = details or {}
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class AuditTrail:
    """Records audit events for validation runs.

    This class is actively called by ValidationEngine.
    """

    def __init__(self, run_id: str, evidence_dir: str):
        self.run_id = run_id
        self.evidence_dir = evidence_dir
        self.events: List[AuditEvent] = []

    def record(
        self,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Record an audit event."""
        event = AuditEvent(
            event_type=event_type,
            run_id=self.run_id,
            details=details,
        )
        self.events.append(event)
        return event

    def record_run_started(self, source: str = "") -> None:
        self.record(AuditEventType.RUN_STARTED, {"source": source})

    def record_schema_validated(self, schema_hash: str = "", errors: List[str] = None) -> None:
        self.record(AuditEventType.SCHEMA_VALIDATED, {
            "schema_hash": schema_hash,
            "errors": errors or [],
        })

    def record_rules_loaded(self, rule_count: int = 0, registry_hash: str = "") -> None:
        self.record(AuditEventType.RULES_LOADED, {
            "rule_count": rule_count,
            "registry_hash": registry_hash,
        })

    def record_validation_started(self, row_count: int = 0) -> None:
        self.record(AuditEventType.VALIDATION_STARTED, {"row_count": row_count})

    def record_validation_completed(
        self,
        input_rows: int = 0,
        output_rows: int = 0,
        flag_counts: Optional[Dict[str, int]] = None,
        duration_seconds: float = 0.0,
    ) -> None:
        self.record(AuditEventType.VALIDATION_COMPLETED, {
            "input_rows": input_rows,
            "output_rows": output_rows,
            "flag_counts": flag_counts or {},
            "duration_seconds": duration_seconds,
        })

    def record_output_written(self, path: str = "", rows: int = 0) -> None:
        self.record(AuditEventType.OUTPUT_WRITTEN, {
            "path": path,
            "rows": rows,
        })

    def record_manifest_written(self, path: str = "") -> None:
        self.record(AuditEventType.MANIFEST_WRITTEN, {"path": path})

    def record_run_failed(self, error_type: str = "", error_message: str = "", failed_step: str = "") -> None:
        self.record(AuditEventType.RUN_FAILED, {
            "error_type": error_type,
            "error_message": error_message,
            "failed_step": failed_step,
        })

    def record_reconciliation(self, passed: bool = True, details: Optional[Dict] = None) -> None:
        self.record(AuditEventType.RECONCILIATION_COMPLETED, {
            "passed": passed,
            "details": details or {},
        })

    def record_monitoring(self, score: float = 0.0, sla_passed: bool = True) -> None:
        self.record(AuditEventType.MONITORING_COMPLETED, {
            "overall_score": score,
            "sla_passed": sla_passed,
        })

    def record_lineage(self, lineage_path: str = "") -> None:
        self.record(AuditEventType.LINEAGE_RECORDED, {"path": lineage_path})

    def record_access(self, user: str = "", action: str = "", resource: str = "") -> None:
        self.record(AuditEventType.ACCESS_LOGGED, {
            "user": user,
            "action": action,
            "resource": resource,
        })

    def persist(self) -> str:
        """Write audit trail to evidence directory.

        Returns the path to the written file.
        """
        os.makedirs(self.evidence_dir, exist_ok=True)
        audit_path = os.path.join(self.evidence_dir, "audit.json")
        data = {
            "run_id": self.run_id,
            "events": [e.to_dict() for e in self.events],
        }
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return audit_path

    def get_event_types(self) -> List[str]:
        return [e.event_type for e in self.events]

    def get_events_by_type(self, event_type: str) -> List[AuditEvent]:
        return [e for e in self.events if e.event_type == event_type]

    def has_event(self, event_type: str) -> bool:
        return any(e.event_type == event_type for e in self.events)
