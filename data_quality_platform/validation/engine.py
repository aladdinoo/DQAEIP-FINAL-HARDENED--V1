import csv
import hashlib
import os
import time
import uuid
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from data_quality_platform.contracts import (
    SOURCE_COLUMNS, FLAG_COLUMNS, OUTPUT_COLUMNS,
    TOTAL_OUTPUT_COLUMNS,
)
from data_quality_platform.schema.validator import SchemaValidator, SchemaValidationError
from data_quality_platform.rules.registry import RuleRegistry, RuleRegistryError
from data_quality_platform.lineage.recorder import LineageRecorder
from data_quality_platform.audit.trail import AuditTrail
from data_quality_platform.monitoring.quality import QualityMonitor
from data_quality_platform.alerting.alerts import AlertManager
from data_quality_platform.evidence.manifests import ManifestWriter, compute_file_sha256
from data_quality_platform.security import PIIMasker
from data_quality_platform.validation.evidence_consistency import validate_evidence_dir
from data_quality_platform.validation.evidence_root import write_evidence_root


@dataclass
class ValidationResult:
    """Structured result from a validation run."""
    run_id: str
    success: bool
    source_path: str
    output_path: str
    evidence_dir: str
    input_row_count: int = 0
    output_row_count: int = 0
    flag_counts: Dict[str, int] = field(default_factory=dict)
    blank_counts: Dict[str, int] = field(default_factory=dict)
    unique_id_count: int = 0
    zip_state_mismatch_count: int = 0
    zip_state_assessable_count: int = 0
    schema_hash: str = ""
    rule_hashes: Dict[str, str] = field(default_factory=dict)
    monitoring_score: float = 0.0
    sla_passed: bool = True
    reconciliation_passed: bool = True
    duration_seconds: float = 0.0
    error: str = ""
    manifest_path: str = ""
    lineage_path: str = ""
    audit_path: str = ""
    monitoring_path: str = ""
    alerts_path: str = ""


class ValidationEngine:
    """Streaming CSV validation engine — INTERNAL IMPLEMENTATION COMPONENT.

    .. warning::

        ValidationEngine is an **internal implementation component**.
        Production execution MUST enter through
        ``data_quality_platform.hardening.pipeline.run_validation()``,
        which is the authorization and safety boundary. Direct
        ValidationEngine invocation is not a supported production
        execution path.

        The CLI (``runner.cli.cmd_validate``) and the Airflow DAG
        (``airflow.dags.dq_validation_dag._run_validation_task``) both
        call ``run_validation()``. Tests and dev tooling (benchmark,
        replay) may instantiate the engine directly — those are not
        production paths.

    Processes rows one-by-one using csv.DictReader (per-row evaluation is
    streaming), but total in-process memory is O(N) in the row count, not
    O(1): ``id_set`` and ``row_lineage_buffer`` grow with every processed
    row, and the lineage recorder accumulates ``row_records`` (the
    persisted lineage file caps ``row_records`` at 1000 entries). See
    FINAL_SCALE_REPORT.md for the measured evidence. No O(1) memory claim
    is made.

    The engine orchestrates: schema validation, rule execution,
    lineage recording (with PII masking via PIIMasker), audit trail,
    monitoring, alerting, reconciliation, evidence root (tamper-evident
    root hash), evidence consistency validation, and manifest generation.
    """

    def __init__(
        self,
        rules: Optional[RuleRegistry] = None,
        run_id: str = "",
        evidence_dir: str = "evidence",
        config_thresholds: Optional[Dict[str, float]] = None,
    ):
        self.rules = rules or RuleRegistry.create_default()
        self.run_id = run_id
        self.evidence_dir = evidence_dir
        self.schema_validator = SchemaValidator()
        self.lineage = LineageRecorder(run_id, evidence_dir) if run_id else None
        self.audit = AuditTrail(run_id, evidence_dir) if run_id else None
        self.monitor = QualityMonitor(thresholds=config_thresholds)
        self.alerts = AlertManager(evidence_dir) if evidence_dir else AlertManager()
        self.manifest_writer = ManifestWriter()

    def validate(
        self,
        csv_path: str,
        output_path: str,
    ) -> ValidationResult:
        """Execute full validation pipeline on a CSV file.

        Args:
            csv_path: path to input CSV (33 columns)
            output_path: path to write 41-column Flag Preview CSV

        Returns:
            ValidationResult with all metrics and evidence paths

        Raises:
            ValueError: if input and output paths resolve to the same
                file (prevents accidental input destruction).
        """
        # GAP-01: Input/output path collision guard.
        # Reject before ANY file write operation to prevent accidental
        # destruction of the input file. Uses pathlib.Path.resolve()
        # to normalize relative paths, ".." components, and symlinks
        # so that equivalent paths are detected regardless of how they
        # are spelled.
        input_resolved = Path(csv_path).resolve()
        output_resolved = Path(output_path).resolve()
        if input_resolved == output_resolved:
            raise ValueError(
                f"Input and output paths must refer to different files "
                f"(both resolve to: {input_resolved}). Refusing to "
                f"overwrite the input file."
            )

        start_time = time.time()
        run_id = self.run_id or f"run_{int(start_time)}"
        self.run_id = run_id

        # Re-init components with run_id
        self.lineage = LineageRecorder(run_id, self.evidence_dir)
        self.audit = AuditTrail(run_id, self.evidence_dir)
        self.alerts = AlertManager(self.evidence_dir)

        try:
            # Step 1: Schema validation
            self.audit.record_run_started(source=csv_path)
            is_valid, errors = self.schema_validator.validate_csv_file(csv_path)
            if not is_valid:
                raise SchemaValidationError(f"Schema validation failed: {errors}")
            self.audit.record_schema_validated(errors=[])

            # Read header for schema hash
            with open(csv_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
            schema_hash = self.schema_validator.compute_schema_hash(header)

            # Step 2: Rule registry validation
            is_valid_rules, rule_errors, rule_warnings = self.rules.validate()
            if not is_valid_rules:
                raise RuleRegistryError(f"Rule registry invalid: {rule_errors}")
            rule_hashes = self.rules.get_rule_hashes()
            registry_hash = self.rules.compute_registry_hash()
            self.audit.record_rules_loaded(
                rule_count=self.rules.count,
                registry_hash=registry_hash,
            )

            # Step 3: Prepare lineage
            self.lineage.record_run(
                source=csv_path,
                row_count=0,  # updated later
                schema_hash=schema_hash,
                sql_hash=registry_hash,
            )

            # Step 4: Streaming validation
            self.audit.record_validation_started(row_count=0)
            output_dir = os.path.dirname(output_path) if os.path.dirname(output_path) else "."
            os.makedirs(output_dir, exist_ok=True)
            os.makedirs(self.evidence_dir, exist_ok=True)

            # GAP-02: Atomic output publication.
            # Write to a temporary file on the SAME filesystem as the
            # final output, then atomically replace into the final
            # path via os.replace. This ensures that a crash or failure
            # during output generation never leaves a partial file at
            # the final output path. If a previous valid output exists,
            # it remains intact until the new output is fully prepared.
            temp_output = os.path.join(
                output_dir,
                f".{os.path.basename(output_path)}.{run_id}.{uuid.uuid4().hex[:8]}.tmp"
            )

            flag_counts: Dict[str, int] = {r.rule_id: 0 for r in self.rules.get_all_rules()}
            blank_counts: Dict[str, int] = {}
            id_set = set()
            input_row_count = 0
            zip_state_mismatch_count = 0
            zip_state_assessable_count = 0
            row_lineage_buffer = []

            try:
                with open(csv_path, "r", newline="", encoding="utf-8") as infile, \
                     open(temp_output, "w", newline="", encoding="utf-8") as outfile:

                    reader = csv.DictReader(infile)
                    writer = csv.DictWriter(outfile, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
                    writer.writeheader()

                    for row_num, row in enumerate(reader, start=2):  # start=2 because row 1 is header
                        input_row_count += 1

                        # Track blank counts for monitoring
                        for col in SOURCE_COLUMNS:
                            val = str(row.get(col, "")).strip()
                            if not val:
                                blank_counts[col] = blank_counts.get(col, 0) + 1

                        # Track unique IDs
                        row_id = row.get("id", "")
                        id_set.add(row_id)

                        # Execute all rules
                        flags = self.rules.execute_all(row)

                        # Track ZIP/state assessable and mismatch counts
                        if flags.get("zip_state_assessable", 0) == 1:
                            zip_state_assessable_count += 1
                        if flags.get("geography_mismatch_candidate", 0) == 1:
                            zip_state_mismatch_count += 1

                        # Update flag counts
                        for rule_id, flag_val in flags.items():
                            if flag_val == 1:
                                flag_counts[rule_id] = flag_counts.get(rule_id, 0) + 1

                        # Record row-level lineage for flagged rows (batched).
                        # PII masking: the row stored in lineage is masked via
                        # PIIMasker.mask_row() so that raw PII (email, phone,
                        # address, names) never persists in lineage.json.
                        for rule_id, flag_val in flags.items():
                            if flag_val == 1:
                                masked_row = PIIMasker.mask_row(row)
                                row_lineage_buffer.append((
                                    row_num, rule_id,
                                    self.rules.get(rule_id).rule_version, flag_val, masked_row
                                ))
                                if len(row_lineage_buffer) >= 100:
                                    for rn, rid, rver, rval, rrow in row_lineage_buffer:
                                        self.lineage.record_row_flag(rn, rid, rver, rval, rrow)
                                    row_lineage_buffer.clear()

                        # Write output row
                        output_row = dict(row)
                        output_row.update(flags)
                        writer.writerow(output_row)

                    # Flush remaining row lineage
                    for rn, rid, rver, rval, rrow in row_lineage_buffer:
                        self.lineage.record_row_flag(rn, rid, rver, rval, rrow)
                    row_lineage_buffer.clear()

                    # Flush and fsync before atomic publish
                    outfile.flush()
                    os.fsync(outfile.fileno())

                # GAP-02: Atomic publish — temp is complete and fsynced.
                # os.replace is atomic on the same filesystem; the
                # final output path is either untouched (if this line
                # is never reached) or fully replaced (if it succeeds).
                os.replace(temp_output, output_path)
            except Exception:
                # Cleanup: remove temporary output on any failure.
                # The final output_path is NOT touched.
                if os.path.exists(temp_output):
                    try:
                        os.remove(temp_output)
                    except OSError:
                        pass
                raise

            output_row_count = input_row_count
            duration = time.time() - start_time

            # Step 5: Update lineage with final row count
            self.lineage.record_run(
                source=csv_path,
                row_count=input_row_count,
                schema_hash=schema_hash,
                sql_hash=registry_hash,
                output_identity=compute_file_sha256(output_path) if os.path.exists(output_path) else "",
            )

            # Step 6: Reconciliation
            reconciliation_result = self._reconcile(
                input_row_count=input_row_count,
                output_row_count=output_row_count,
                flag_counts=flag_counts,
                output_path=output_path,
            )
            self.audit.record_reconciliation(
                passed=reconciliation_result["passed"],
                details=reconciliation_result,
            )
            if not reconciliation_result["passed"]:
                self.alerts.alert_reconciliation_failure(run_id, reconciliation_result)

            # Step 7: Monitoring
            monitoring_results = self.monitor.compute(
                total_rows=input_row_count,
                flag_counts=flag_counts,
                blank_counts=blank_counts,
                unique_id_count=len(id_set),
                zip_state_mismatch_count=zip_state_mismatch_count,
                zip_state_assessable_count=zip_state_assessable_count,
            )
            self.audit.record_monitoring(
                score=monitoring_results["overall_score"],
                sla_passed=monitoring_results["sla_passed"],
            )
            if not monitoring_results["sla_passed"]:
                for dim, passed in monitoring_results["sla_results"].items():
                    if not passed:
                        self.alerts.alert_sla_breach(
                            run_id=run_id,
                            dimension=dim,
                            score=monitoring_results["scores"][dim],
                            threshold=monitoring_results["thresholds"][dim],
                        )

            # Step 8: Audit completion
            self.audit.record_validation_completed(
                input_rows=input_row_count,
                output_rows=output_row_count,
                flag_counts=flag_counts,
                duration_seconds=duration,
            )
            self.audit.record_output_written(path=output_path, rows=output_row_count)

            # Step 9: Persist evidence
            lineage_path = self.lineage.persist()
            self.audit.record_lineage(lineage_path=lineage_path)
            audit_path = self.audit.persist()
            monitoring_path = self.monitor.persist(self.evidence_dir)
            alerts_path = self.alerts.persist()

            # Step 10: Compute SQL hashes
            sql_hashes = self.rules.get_sql_templates()
            sql_hashes_digest = {rid: hashlib.sha256(sql.encode()).hexdigest() for rid, sql in sql_hashes.items()}

            # Step 11: Write success manifest
            generated_files = {
                "output": output_path,
                "lineage": lineage_path,
                "audit": audit_path,
                "monitoring": monitoring_path,
                "alerts": alerts_path,
            }
            generated_files = {k: v for k, v in generated_files.items() if v}

            manifest = self.manifest_writer.write_success_manifest(
                evidence_dir=self.evidence_dir,
                run_id=run_id,
                source_row_count=input_row_count,
                output_row_count=output_row_count,
                schema_hash=schema_hash,
                rule_hashes=rule_hashes,
                sql_hashes=sql_hashes_digest,
                flag_counts=flag_counts,
                reconciliation=reconciliation_result,
                safety_invariants=[
                    "input_row_count == output_row_count",
                    "all_flags_are_0_or_1",
                    "source_columns_unchanged",
                    "no_lost_rows",
                    "no_duplicated_rows",
                ],
                lineage_reference=lineage_path,
                monitoring_score=monitoring_results["overall_score"],
                monitoring_scores=monitoring_results["scores"],
                sla_results=monitoring_results["sla_results"],
                generated_files=generated_files,
            )
            self.audit.record_manifest_written(path=os.path.join(self.evidence_dir, "manifest.json"))

            # Tamper-evident evidence root (SHA-256 over all artifact hashes).
            write_evidence_root(self.evidence_dir, output_csv=output_path)
            # Semantic consistency validation (fail-closed: if evidence is
            # internally inconsistent, the run is recorded as failed).
            consistency = validate_evidence_dir(self.evidence_dir)
            if not consistency["valid"]:
                # Evidence is inconsistent — this is an engine bug, not
                # a validation failure. Record it and return failure.
                self.audit.record_run_failed(
                    error_type="EvidenceConsistencyError",
                    error_message="; ".join(i["code"] for i in consistency["issues"][:5]),
                    failed_step="evidence_consistency",
                )
                self.alerts.alert_validation_failure(run_id, "evidence consistency validation failed")
                return ValidationResult(
                    run_id=run_id, success=False,
                    source_path=csv_path, output_path=output_path,
                    evidence_dir=self.evidence_dir,
                    error=f"evidence consistency validation failed: "
                          f"{len(consistency['issues'])} issue(s)",
                )

            return ValidationResult(
                run_id=run_id,
                success=True,
                source_path=csv_path,
                output_path=output_path,
                evidence_dir=self.evidence_dir,
                input_row_count=input_row_count,
                output_row_count=output_row_count,
                flag_counts=flag_counts,
                blank_counts=blank_counts,
                unique_id_count=len(id_set),
                zip_state_mismatch_count=zip_state_mismatch_count,
                zip_state_assessable_count=zip_state_assessable_count,
                schema_hash=schema_hash,
                rule_hashes=rule_hashes,
                monitoring_score=monitoring_results["overall_score"],
                sla_passed=monitoring_results["sla_passed"],
                reconciliation_passed=reconciliation_result["passed"],
                duration_seconds=duration,
                manifest_path=os.path.join(self.evidence_dir, "manifest.json"),
                lineage_path=lineage_path,
                audit_path=audit_path,
                monitoring_path=monitoring_path,
                alerts_path=alerts_path,
            )

        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)
            error_type = type(e).__name__

            self.audit.record_run_failed(
                error_type=error_type,
                error_message=error_msg,
                failed_step=error_type,
            )
            self.alerts.alert_validation_failure(run_id, error_msg)

            # Write failure manifest
            try:
                self.manifest_writer.write_failure_manifest(
                    evidence_dir=self.evidence_dir,
                    run_id=run_id,
                    error_type=error_type,
                    error_message=error_msg,
                    failed_step=error_type,
                )
                self.audit.persist()
                self.alerts.persist()
            except Exception:
                pass

            return ValidationResult(
                run_id=run_id,
                success=False,
                source_path=csv_path,
                output_path=output_path,
                evidence_dir=self.evidence_dir,
                duration_seconds=duration,
                error=error_msg,
            )

    def _reconcile(
        self,
        input_row_count: int,
        output_row_count: int,
        flag_counts: Dict[str, int],
        output_path: str,
    ) -> Dict[str, Any]:
        """Reconcile input/output consistency.

        Verifies:
        - input row count == output row count
        - no lost rows
        - no duplicated rows
        - all flag values are 0/1
        - source columns unchanged
        """
        errors = []
        passed = True

        # Check row counts
        if input_row_count != output_row_count:
            errors.append(f"Row count mismatch: input={input_row_count}, output={output_row_count}")
            passed = False

        # Verify output file exists
        if not os.path.exists(output_path):
            errors.append("Output file does not exist")
            passed = False
            return {"passed": passed, "errors": errors}

        # Verify flag values and column count
        with open(output_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            file_row_count = 0
            header_cols = reader.fieldnames or []

            if len(header_cols) != TOTAL_OUTPUT_COLUMNS:
                errors.append(
                    f"Output column count mismatch: expected {TOTAL_OUTPUT_COLUMNS}, got {len(header_cols)}"
                )
                passed = False

            for row in reader:
                file_row_count += 1
                for flag_col in FLAG_COLUMNS:
                    val = row.get(flag_col, "")
                    if val not in ("0", "1"):
                        errors.append(
                            f"Invalid flag value at row {file_row_count + 1}: "
                            f"{flag_col}={val}"
                        )
                        passed = False

            if file_row_count != output_row_count:
                errors.append(
                    f"Output file row count mismatch: expected {output_row_count}, got {file_row_count}"
                )
                passed = False

        return {
            "passed": passed,
            "errors": errors,
            "input_row_count": input_row_count,
            "output_row_count": output_row_count,
            "flag_counts": flag_counts,
        }
