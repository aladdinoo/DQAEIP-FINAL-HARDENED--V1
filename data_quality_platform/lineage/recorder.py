import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class LineageRecord:
    """Single lineage record."""

    def __init__(
        self,
        run_id: str,
        source: str = "",
        database: str = "",
        table: str = "",
        rule_id: str = "",
        rule_version: str = "",
        row_count: int = 0,
        schema_hash: str = "",
        ddl_hash: str = "",
        sql_hash: str = "",
        output_identity: str = "",
        timestamp: Optional[str] = None,
    ):
        self.run_id = run_id
        self.source = source
        self.database = database
        self.table = table
        self.rule_id = rule_id
        self.rule_version = rule_version
        self.row_count = row_count
        self.schema_hash = schema_hash
        self.ddl_hash = ddl_hash
        self.sql_hash = sql_hash
        self.output_identity = output_identity
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "source": self.source,
            "database": self.database,
            "table": self.table,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "row_count": self.row_count,
            "schema_hash": self.schema_hash,
            "ddl_hash": self.ddl_hash,
            "sql_hash": self.sql_hash,
            "output_identity": self.output_identity,
            "timestamp": self.timestamp,
        }


class RowLineageRecord:
    """Row-level lineage: traceability without storing raw PII."""

    def __init__(
        self,
        run_id: str,
        row_number: int,
        rule_id: str,
        rule_version: str,
        flag_value: int,
        row_hash: str = "",
        timestamp: Optional[str] = None,
    ):
        self.run_id = run_id
        self.row_number = row_number
        self.rule_id = rule_id
        self.rule_version = rule_version
        self.flag_value = flag_value
        self.row_hash = row_hash
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "row_number": self.row_number,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "flag_value": self.flag_value,
            "row_hash": self.row_hash,
            "timestamp": self.timestamp,
        }


def compute_row_identity_hash(row: Dict[str, Any]) -> str:
    """Compute a stable identity hash for a row WITHOUT storing PII.

    Uses id, zip, state, source for identity (not PII fields).
    """
    identity_fields = ["id", "zip", "state", "source", "country"]
    values = [str(row.get(f, "")) for f in identity_fields]
    content = "|".join(values)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


class LineageRecorder:
    """Records lineage information for validation runs.

    This class is actively used by ValidationEngine.
    """

    def __init__(self, run_id: str, evidence_dir: str):
        self.run_id = run_id
        self.evidence_dir = evidence_dir
        self.records: List[LineageRecord] = []
        self.row_records: List[RowLineageRecord] = []
        self._run_start_time = datetime.now(timezone.utc).isoformat()

    def record_run(
        self,
        source: str,
        database: str = "",
        table: str = "",
        row_count: int = 0,
        schema_hash: str = "",
        ddl_hash: str = "",
        sql_hash: str = "",
        output_identity: str = "",
    ) -> None:
        """Record a run-level lineage entry."""
        record = LineageRecord(
            run_id=self.run_id,
            source=source,
            database=database,
            table=table,
            row_count=row_count,
            schema_hash=schema_hash,
            ddl_hash=ddl_hash,
            sql_hash=sql_hash,
            output_identity=output_identity,
        )
        self.records.append(record)

    def record_row_flag(
        self,
        row_number: int,
        rule_id: str,
        rule_version: str,
        flag_value: int,
        row: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record row-level lineage for a flagged row.

        Does NOT store raw PII. Uses row identity hash instead.
        """
        row_hash = ""
        if row is not None:
            row_hash = compute_row_identity_hash(row)
        record = RowLineageRecord(
            run_id=self.run_id,
            row_number=row_number,
            rule_id=rule_id,
            rule_version=rule_version,
            flag_value=flag_value,
            row_hash=row_hash,
        )
        self.row_records.append(record)

    def persist(self) -> str:
        """Write lineage data to evidence directory.

        Returns the path to the written file.
        """
        os.makedirs(self.evidence_dir, exist_ok=True)
        lineage_path = os.path.join(self.evidence_dir, "lineage.json")
        data = {
            "run_id": self.run_id,
            "run_start_time": self._run_start_time,
            "run_records": [r.to_dict() for r in self.records],
            # Serialize row records to structured JSON dictionaries (not
            # Python objects). json.dump() below deliberately has NO
            # default=str fallback: a non-JSON-serializable object in the
            # evidence layer must raise TypeError (fail closed) instead of
            # silently persisting an opaque repr string.
            "row_records": [r.to_dict() for r in self.row_records[:1000]],
            "total_row_records": len(self.row_records),
            "truncated": len(self.row_records) > 1000,
        }
        with open(lineage_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return lineage_path

    def get_summary(self) -> Dict[str, Any]:
        """Return summary of recorded lineage."""
        return {
            "run_id": self.run_id,
            "run_records_count": len(self.records),
            "row_records_count": len(self.row_records),
        }
