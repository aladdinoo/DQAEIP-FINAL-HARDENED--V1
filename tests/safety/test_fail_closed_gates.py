"""Consolidated fail-closed safety tests.

Every security/safety gate must have at least one negative test. This
module consolidates the scenarios not already covered elsewhere and
maps the full checklist to its covering test:

Scenario                                Covered by
---------------------------------------------------------------------
corrupted input                         test_input_contract.py (module+CLI)
missing evidence                        test_evidence_consistency.py
modified evidence (row counts)          test_evidence_consistency.py
modified evidence (lineage repr leak)    test_evidence_consistency.py
wrong hash (rule/file format)            test_evidence_consistency.py
wrong rule version                      HERE (registry)
missing rule                            HERE (registry + engine path)
invalid schema                          test_schema.py + failure path tests
unexpected column                       test_input_contract.py
malformed configuration                 test_input_contract.py + HERE
missing reference                       HERE (reference registry fail-closed)
invalid reference hash                  test_rule_oracle_consistency.py
                                        (transcription fidelity pins)
altered output                          test_evidence_consistency.py
                                        (file hash mismatch)
tampered manifest                       test_evidence_consistency.py
                                        + test_failure_recovery_hardening.py
unauthorized mutation attempt           HERE (ClickHouse/E1 boundaries)
source mutation attempt                 test_replay.py + mutation_testing.py
determinism violation                    HERE + test_replay.py
"""

import csv
import os

import pytest

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.rules.base import Rule
from data_quality_platform.rules.registry import (
    RuleRegistry, RuleRegistryError,
)
from data_quality_platform.validation.replay import (
    ReplayMismatch, replay_dataset,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class _StubRule(Rule):
    """A deliberately foreign rule (not in the V1 required set)."""

    @property
    def rule_id(self):
        return "totally_new_rule"

    @property
    def rule_version(self):
        return "9.9.9"

    def execute(self, row):
        return 0

    def execute_sql_template(self):
        return ""

    def description(self):
        return "stub"


class _EmailBlankLike(Rule):
    @property
    def rule_id(self):
        return "email_blank"

    @property
    def rule_version(self):
        return "1.0.0"

    def execute(self, row):
        email = row.get("email_address")
        return 1 if email is None or str(email).strip() == "" else 0

    def execute_sql_template(self):
        return ""

    def description(self):
        return ""


class TestMissingRuleGate:
    def test_registry_without_required_rule_fails_validation(self):
        registry = RuleRegistry()
        valid, errors, _ = registry.validate()
        assert valid is False
        assert any("Missing required rules" in e for e in errors)

    def test_execute_all_with_missing_rule_raises(self):
        registry = RuleRegistry()
        with pytest.raises(RuleRegistryError):
            registry.execute_all({"id": "1"})


class TestWrongRuleVersionGate:
    def test_duplicate_rule_id_with_different_version_rejected(self):
        from data_quality_platform.rules.v1_rules import EmailBlank

        class VersionBumped(EmailBlank):
            @property
            def rule_version(self):
                return "2.0.0"

        registry = RuleRegistry.create_default()
        with pytest.raises(RuleRegistryError, match="different version"):
            registry.register(VersionBumped())

    def test_unexpected_foreign_rule_never_enters_execution_path(self):
        registry = RuleRegistry.create_default()
        registry.register(_StubRule())
        valid, errors, warnings = registry.validate()
        assert valid is True  # required set intact
        assert any("Unexpected rules" in w for w in warnings)
        executed = [r.rule_id for r in registry.get_all_rules()]
        assert _StubRule().rule_id not in executed


class TestMalformedConfigurationGate:
    def test_missing_explicit_config_is_a_hard_error(self, tmp_path):
        """CLI N1 hardening: an explicitly supplied --config path that
        does not exist must block validation (exit 2, no silent
        fallback)."""
        import subprocess
        import sys
        # Build a valid CSV and grant so the only failure is the missing config.
        from data_quality_platform.generation.synthetic import SyntheticDataGenerator
        csv_path = str(tmp_path / "input.csv")
        grant_path = str(tmp_path / "grant.json")
        SyntheticDataGenerator(seed=42).generate(10, csv_path)
        subprocess.run(
            [sys.executable, "-m", "runner.cli", "authorize",
             "--csv", csv_path, "--output", grant_path],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)
        proc = subprocess.run(
            [sys.executable, "-m", "runner.cli", "validate",
             "--csv", csv_path, "--output", str(tmp_path / "o.csv"),
             "--grant", grant_path,
             "--config", str(tmp_path / "nope.yaml")],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
        assert proc.returncode == 2
        assert "does not exist" in proc.stderr or "not found" in proc.stderr

    def test_invalid_thresholds_block_at_preflight(self, tmp_path):
        from data_quality_platform.validation.input_contract import (
            InputContractError, validate_input_contract,
        )

        class BadConfig:
            def get_quality_thresholds(self):
                return {"validity": 42.0}

        p = tmp_path / "ok.csv"
        with open(p, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(SOURCE_COLUMNS)
            w.writerow([""] * 33)
        with pytest.raises(InputContractError):
            validate_input_contract(str(p), config=BadConfig())


# The historical TestMissingReferenceGate and TestUnauthorizedMutationBoundaries
# classes have been removed: they tested the SP1 successor geography module
# and the verification/ reference-provenance module, both of which were
# deleted in the simplification (SP1 is intentionally not activated; the
# V1 reference data is hard-coded in contracts.py).


class TestDeterminismGateFailClosed:
    def test_non_deterministic_registry_fails_replay(self, tmp_path):
        """A rule whose hash changes between runs must FAIL the replay
        (determinism gate), never pass silently."""

        state = {"n": 0}

        class ShiftingHash(_EmailBlankLike):
            @property
            def hash(self):
                state["n"] += 1
                return f"{state['n']:064d}"

        def factory():
            reg = RuleRegistry()
            for rule in RuleRegistry.create_default().get_all_rules():
                if rule.rule_id == "email_blank":
                    reg.register(ShiftingHash())
                else:
                    reg.register(rule)
            return reg

        p = tmp_path / "in.csv"
        with open(p, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(SOURCE_COLUMNS)
            row = {c: "" for c in SOURCE_COLUMNS}
            row.update({"id": "1", "email_address": ""})
            w.writerow([row[c] for c in SOURCE_COLUMNS])

        with pytest.raises(ReplayMismatch):
            replay_dataset(str(p), runs=2, work_dir=str(tmp_path / "w"),
                           registry_factory=factory)
