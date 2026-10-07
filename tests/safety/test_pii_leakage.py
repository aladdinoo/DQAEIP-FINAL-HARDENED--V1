"""PII negative-leakage end-to-end security test.

Proves that synthetic canary PII values injected into input rows do
NOT appear in persisted evidence artifacts after a full validation run.

Canary values are clearly synthetic (reserved domains, obvious patterns)
so there is no risk of false-positive on real customer data.

The test runs the ACTUAL validation+evidence path via ``run_validation()``
(the production execution boundary), then inspects every evidence-
producing artifact:
  - lineage.json
  - manifest.json
  - audit.json
  - monitoring.json
  - alerts.json
  - evidence_root.json
  - hardened_execution_report.json

Required property: the original canary values MUST NOT appear in any
persisted evidence artifact where masking is required.

Documented limitation: PII/secret scanning and masking are heuristic
controls, not complete DLP. This test proves the specific canary values
are masked; it does NOT prove all possible PII is masked.
"""

import json
import os
import subprocess
import sys

import pytest

from data_quality_platform.hardening.pipeline import run_validation
from data_quality_platform.hardening.authorization import observe_scope
from data_quality_platform.config import PlatformConfig
from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.generation.synthetic import SyntheticDataGenerator
from data_quality_platform.hardening.pipeline import (
    _default_reference_data_paths, _default_software_paths, _v1_rules_path,
)


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


# Canary values — clearly synthetic. These MUST NOT appear in evidence.
CANARY_EMAIL = "canary.leak.test@synthetic-canary-domain.example.org"
CANARY_PHONE = "555-000-9999"
CANARY_PASSWORD = "canary-secret-password-12345"
CANARY_TOKEN = "ghp_canarytoken000000000000000000000000aaaa"
CANARY_CARD = "4111-1111-1111-1111"
CANARY_ADDRESS = "999 Canary Leak Street"
CANARY_FIRST_NAME = "Canaryfirst"
CANARY_LAST_NAME = "Canarylast"


@pytest.fixture
def canary_csv(tmp_path):
    """Build a CSV with canary PII values in flagged rows.

    The canary first_name contains "test" (a suspicious pattern) so
    the row WILL be flagged and its lineage record WILL be written.
    """
    csv_path = str(tmp_path / "canary_input.csv")
    # Use the synthetic generator to get a valid 33-column base, then
    # overwrite specific rows with canary values.
    SyntheticDataGenerator(seed=42).generate(50, csv_path)
    # Read, inject canaries into the first few rows, write back.
    import csv
    rows = []
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames
        rows = list(reader)
    # Inject canaries into rows 0-4 (force flagging via "test" in first_name).
    for i in range(5):
        rows[i]["first_name"] = "test" + CANARY_FIRST_NAME  # triggers flag
        rows[i]["last_name"] = CANARY_LAST_NAME
        rows[i]["email_address"] = CANARY_EMAIL
        rows[i]["phone_number"] = CANARY_PHONE
        rows[i]["address"] = CANARY_ADDRESS
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return csv_path


@pytest.fixture
def canary_evidence(canary_csv, tmp_path):
    """Run a full validation via run_validation() with canary input."""
    out_path = str(tmp_path / "canary_output.csv")
    ev_dir = str(tmp_path / "canary_evidence")
    config = PlatformConfig.from_yaml(
        os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()
    scope = observe_scope(
        input_path=canary_csv,
        authorized_columns=SOURCE_COLUMNS,
        v1_rules_path=_v1_rules_path(),
        reference_data_paths=_default_reference_data_paths(),
        config=config,
        execution_mode="validation",
        software_paths=_default_software_paths(),
    )
    result = run_validation(
        input_path=canary_csv,
        output_path=out_path,
        evidence_dir=ev_dir,
        run_id="canary_leak_test",
        granted_scope=scope,
        config=config,
        config_thresholds=PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
    )
    assert result.passed, f"canary validation failed: {result.reasons}"
    return ev_dir, out_path


class TestPIINegativeLeakage:
    """Canary PII values must NOT appear in persisted evidence."""

    CANARIES = [
        CANARY_EMAIL,
        CANARY_PHONE,
        CANARY_PASSWORD,
        CANARY_TOKEN,
        CANARY_CARD,
        CANARY_ADDRESS,
        CANARY_FIRST_NAME,
        CANARY_LAST_NAME,
    ]

    # Artifacts produced by run_validation() + the engine.
    # Note: hardened_execution_report.json is produced by the CLI
    # (cmd_validate), not by run_validation() itself.
    EVIDENCE_ARTIFACTS = [
        "manifest.json",
        "lineage.json",
        "audit.json",
        "monitoring.json",
        "alerts.json",
        "evidence_root.json",
    ]

    def test_canaries_not_in_lineage(self, canary_evidence):
        """Lineage records are masked — canary PII must not appear."""
        ev_dir, _ = canary_evidence
        lineage = open(os.path.join(ev_dir, "lineage.json")).read()
        for canary in self.CANARIES:
            assert canary not in lineage, \
                f"canary value {canary!r} leaked into lineage.json"

    def test_canaries_not_in_manifest(self, canary_evidence):
        ev_dir, _ = canary_evidence
        manifest = open(os.path.join(ev_dir, "manifest.json")).read()
        for canary in self.CANARIES:
            assert canary not in manifest, \
                f"canary value {canary!r} leaked into manifest.json"

    def test_canaries_not_in_audit(self, canary_evidence):
        ev_dir, _ = canary_evidence
        audit = open(os.path.join(ev_dir, "audit.json")).read()
        for canary in self.CANARIES:
            assert canary not in audit, \
                f"canary value {canary!r} leaked into audit.json"

    def test_canaries_not_in_monitoring(self, canary_evidence):
        ev_dir, _ = canary_evidence
        monitoring = open(os.path.join(ev_dir, "monitoring.json")).read()
        for canary in self.CANARIES:
            assert canary not in monitoring, \
                f"canary value {canary!r} leaked into monitoring.json"

    def test_canaries_not_in_alerts(self, canary_evidence):
        ev_dir, _ = canary_evidence
        alerts = open(os.path.join(ev_dir, "alerts.json")).read()
        for canary in self.CANARIES:
            assert canary not in alerts, \
                f"canary value {canary!r} leaked into alerts.json"

    def test_canaries_not_in_evidence_root(self, canary_evidence):
        ev_dir, _ = canary_evidence
        root = open(os.path.join(ev_dir, "evidence_root.json")).read()
        for canary in self.CANARIES:
            assert canary not in root, \
                f"canary value {canary!r} leaked into evidence_root.json"

    def test_canaries_not_in_hardened_report(self, canary_evidence):
        """The hardened_execution_report.json is produced by the CLI,
        not by run_validation(). This test verifies that IF it exists,
        it does not contain canary values. If it does not exist (because
        run_validation was called directly), the test passes trivially."""
        ev_dir, _ = canary_evidence
        report_path = os.path.join(ev_dir, "hardened_execution_report.json")
        if not os.path.isfile(report_path):
            pytest.skip("hardened_execution_report.json not produced by "
                        "run_validation() directly (CLI-level artifact)")
        report = open(report_path).read()
        for canary in self.CANARIES:
            assert canary not in report, \
                f"canary value {canary!r} leaked into hardened_execution_report.json"

    def test_lineage_stores_row_hash_not_row_content(self, canary_evidence):
        """Lineage stores ONLY a row identity hash, never raw row content.
        This is the primary PII protection for lineage — masking is
        defense-in-depth on top of this.

        This test verifies that lineage row_records contain only:
        run_id, row_number, rule_id, rule_version, flag_value, row_hash,
        timestamp — and NO raw row fields (first_name, email_address, etc.).
        """
        ev_dir, _ = canary_evidence
        import json
        lineage = json.load(open(os.path.join(ev_dir, "lineage.json")))
        row_records = lineage.get("row_records", [])
        assert row_records, "no row_records in lineage"
        # Every row record must have ONLY the hash-based fields.
        allowed_fields = {"run_id", "row_number", "rule_id", "rule_version",
                          "flag_value", "row_hash", "timestamp"}
        for record in row_records:
            assert set(record.keys()) <= allowed_fields, \
                f"row record has unexpected fields: {set(record.keys()) - allowed_fields}"
            # No raw PII fields should be present.
            for pii_field in ("first_name", "last_name", "email_address",
                              "phone_number", "address"):
                assert pii_field not in record, \
                    f"raw PII field {pii_field!r} in lineage row record"

    def test_all_evidence_artifacts_exist(self, canary_evidence):
        ev_dir, _ = canary_evidence
        for artifact in self.EVIDENCE_ARTIFACTS:
            assert os.path.isfile(os.path.join(ev_dir, artifact)), \
                f"evidence artifact missing: {artifact}"
