import pytest


class TestCanonicalImports:
    """Regression: previous version had empty __init__.py causing ImportError."""

    def test_import_rule_registry(self):
        from data_quality_platform.rules import RuleRegistry
        assert RuleRegistry is not None

    def test_import_validation_engine(self):
        from data_quality_platform.validation.engine import ValidationEngine
        assert ValidationEngine is not None

    def test_import_cli_main(self):
        from runner.cli import main
        assert callable(main)

    def test_import_all_rules(self):
        from data_quality_platform.rules import (
            FirstNameCleaningCandidate, LastNameCleaningCandidate,
            NameCleaningCandidate, EmailBlank, EmailSyntaxFailure,
            ProposedEmailExportEligible, ZipStateAssessable, GeographyMismatchCandidate,
        )
        assert all([FirstNameCleaningCandidate, LastNameCleaningCandidate])

    def test_import_schema_validator(self):
        from data_quality_platform.schema.validator import SchemaValidator
        assert SchemaValidator is not None

    def test_import_lineage(self):
        from data_quality_platform.lineage import LineageRecorder
        assert LineageRecorder is not None

    def test_import_audit(self):
        from data_quality_platform.audit import AuditTrail
        assert AuditTrail is not None

    def test_import_monitoring(self):
        from data_quality_platform.monitoring import QualityMonitor
        assert QualityMonitor is not None

    def test_import_hardening_pipeline(self):
        from data_quality_platform.hardening.pipeline import run_validation
        assert callable(run_validation)

    def test_import_alerts(self):
        from data_quality_platform.alerting import AlertManager
        assert AlertManager is not None

    def test_import_evidence(self):
        from data_quality_platform.evidence import ManifestWriter, ManifestReader
        assert ManifestWriter is not None

    def test_import_generator(self):
        from data_quality_platform.generation import SyntheticDataGenerator
        assert SyntheticDataGenerator is not None

    def test_import_contracts(self):
        from data_quality_platform.contracts import SOURCE_COLUMNS, FLAG_COLUMNS
        assert len(SOURCE_COLUMNS) == 33
        assert len(FLAG_COLUMNS) == 8

    def test_import_config(self):
        from data_quality_platform.config import PlatformConfig
        assert PlatformConfig is not None


class TestEngineCanonicalPath:
    """Regression: previous version had engine in wrong module."""

    def test_engine_not_in_wrong_path(self):
        """Regression #2: engine must NOT be at top-level module."""
        with pytest.raises((ImportError, ModuleNotFoundError)):
            import data_quality_platform.engine as e


    def test_engine_in_correct_path(self):
        from data_quality_platform.validation.engine import ValidationEngine
        assert hasattr(ValidationEngine, 'validate')


class TestRuleRegistryAPI:
    """Regression: previous version had empty __init__.py for rules."""

    def test_registry_has_create_default(self):
        from data_quality_platform.rules import RuleRegistry
        assert hasattr(RuleRegistry, 'create_default')

    def test_registry_has_validate(self):
        from data_quality_platform.rules import RuleRegistry
        rr = RuleRegistry.create_default()
        assert hasattr(rr, 'validate')
        assert hasattr(rr, 'execute_all')
        assert hasattr(rr, 'get_rule_hashes')
