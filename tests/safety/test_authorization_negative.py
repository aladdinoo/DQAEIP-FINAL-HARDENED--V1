"""Authorization negative tests — Layer B fail-closed behavior.

Tests that the hardened execution boundary rejects:
  - tampered input SHA-256
  - tampered schema fingerprint
  - tampered V1 ruleset SHA-256
  - tampered reference data fingerprint
  - tampered config fingerprint
  - tampered software identity
  - tampered execution mode
  - missing grant (None)
  - missing observed scope (None)
  - wrong execution mode
"""

import json
import os

import pytest

from data_quality_platform.hardening.authorization import (
    AuthorizationScope, evaluate_authorization, observe_scope, load_grant,
)
from data_quality_platform.hardening.pipeline import (
    run_validation, _default_reference_data_paths, _default_software_paths, _v1_rules_path,
)
from data_quality_platform.config import PlatformConfig
from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.generation.synthetic import SyntheticDataGenerator


@pytest.fixture
def synthetic_csv(tmp_path):
    csv_path = str(tmp_path / "input.csv")
    SyntheticDataGenerator(seed=42).generate(50, csv_path)
    return csv_path


@pytest.fixture
def granted_scope(synthetic_csv):
    config = PlatformConfig.from_yaml("configs/quality.yaml").as_dict()
    return observe_scope(
        input_path=synthetic_csv,
        authorized_columns=SOURCE_COLUMNS,
        v1_rules_path=_v1_rules_path(),
        reference_data_paths=_default_reference_data_paths(),
        config=config,
        execution_mode="validation",
        software_paths=_default_software_paths(),
    )


def _run(synthetic_csv, tmp_path, granted_scope):
    return run_validation(
        input_path=synthetic_csv,
        output_path=str(tmp_path / "out.csv"),
        evidence_dir=str(tmp_path / "ev"),
        run_id="auth_test",
        granted_scope=granted_scope,
        config=PlatformConfig.from_yaml("configs/quality.yaml").as_dict(),
    )


class TestLayerBNegativeBattery:
    """Each scope field is tampered individually; the run must be rejected."""

    def test_01_correct_scope_authorizes(self, synthetic_csv, tmp_path, granted_scope):
        result = _run(synthetic_csv, tmp_path, granted_scope)
        assert result.passed, f"correct scope was rejected: {result.reasons}"

    def test_02_tampered_input_sha_rejected(self, synthetic_csv, tmp_path, granted_scope):
        tampered = AuthorizationScope(
            input_sha256="0" * 64,
            schema_fingerprint=granted_scope.schema_fingerprint,
            v1_ruleset_sha256=granted_scope.v1_ruleset_sha256,
            reference_data_fingerprint=granted_scope.reference_data_fingerprint,
            config_fingerprint=granted_scope.config_fingerprint,
            execution_mode=granted_scope.execution_mode,
            software_identity=granted_scope.software_identity,
        )
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed
        assert any("Layer A rejected" in r or "Layer B refused" in r
                   or "SHA-256 does not match" in r for r in result.reasons)

    def test_03_tampered_schema_fingerprint_rejected(self, synthetic_csv, tmp_path, granted_scope):
        tampered = AuthorizationScope(
            input_sha256=granted_scope.input_sha256,
            schema_fingerprint="0" * 64,
            v1_ruleset_sha256=granted_scope.v1_ruleset_sha256,
            reference_data_fingerprint=granted_scope.reference_data_fingerprint,
            config_fingerprint=granted_scope.config_fingerprint,
            execution_mode=granted_scope.execution_mode,
            software_identity=granted_scope.software_identity,
        )
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed

    def test_04_tampered_v1_ruleset_sha_rejected(self, synthetic_csv, tmp_path, granted_scope):
        tampered = AuthorizationScope(
            input_sha256=granted_scope.input_sha256,
            schema_fingerprint=granted_scope.schema_fingerprint,
            v1_ruleset_sha256="0" * 64,
            reference_data_fingerprint=granted_scope.reference_data_fingerprint,
            config_fingerprint=granted_scope.config_fingerprint,
            execution_mode=granted_scope.execution_mode,
            software_identity=granted_scope.software_identity,
        )
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed

    def test_05_tampered_reference_data_fingerprint_rejected(self, synthetic_csv, tmp_path, granted_scope):
        tampered = AuthorizationScope(
            input_sha256=granted_scope.input_sha256,
            schema_fingerprint=granted_scope.schema_fingerprint,
            v1_ruleset_sha256=granted_scope.v1_ruleset_sha256,
            reference_data_fingerprint="0" * 64,
            config_fingerprint=granted_scope.config_fingerprint,
            execution_mode=granted_scope.execution_mode,
            software_identity=granted_scope.software_identity,
        )
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed

    def test_06_tampered_config_fingerprint_rejected(self, synthetic_csv, tmp_path, granted_scope):
        tampered = AuthorizationScope(
            input_sha256=granted_scope.input_sha256,
            schema_fingerprint=granted_scope.schema_fingerprint,
            v1_ruleset_sha256=granted_scope.v1_ruleset_sha256,
            reference_data_fingerprint=granted_scope.reference_data_fingerprint,
            config_fingerprint="0" * 64,
            execution_mode=granted_scope.execution_mode,
            software_identity=granted_scope.software_identity,
        )
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed

    def test_07_tampered_software_identity_rejected(self, synthetic_csv, tmp_path, granted_scope):
        tampered_identity = dict(granted_scope.software_identity)
        tampered_identity["validation.engine"] = "0" * 64
        tampered = AuthorizationScope(
            input_sha256=granted_scope.input_sha256,
            schema_fingerprint=granted_scope.schema_fingerprint,
            v1_ruleset_sha256=granted_scope.v1_ruleset_sha256,
            reference_data_fingerprint=granted_scope.reference_data_fingerprint,
            config_fingerprint=granted_scope.config_fingerprint,
            execution_mode=granted_scope.execution_mode,
            software_identity=tampered_identity,
        )
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed

    def test_08_wrong_execution_mode_rejected(self, synthetic_csv, tmp_path, granted_scope):
        tampered = AuthorizationScope(
            input_sha256=granted_scope.input_sha256,
            schema_fingerprint=granted_scope.schema_fingerprint,
            v1_ruleset_sha256=granted_scope.v1_ruleset_sha256,
            reference_data_fingerprint=granted_scope.reference_data_fingerprint,
            config_fingerprint=granted_scope.config_fingerprint,
            execution_mode="export",  # wrong mode
            software_identity=granted_scope.software_identity,
        )
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed

    def test_09_missing_grant_rejected(self, synthetic_csv, tmp_path):
        result = _run(synthetic_csv, tmp_path, None)
        assert not result.passed

    def test_10_engine_never_runs_on_rejected_scope(self, synthetic_csv, tmp_path, granted_scope):
        """When authorization is rejected, the engine must NOT have run.
        The output file must not exist."""
        tampered = AuthorizationScope(
            input_sha256="0" * 64,
            schema_fingerprint=granted_scope.schema_fingerprint,
            v1_ruleset_sha256=granted_scope.v1_ruleset_sha256,
            reference_data_fingerprint=granted_scope.reference_data_fingerprint,
            config_fingerprint=granted_scope.config_fingerprint,
            execution_mode=granted_scope.execution_mode,
            software_identity=granted_scope.software_identity,
        )
        out_path = str(tmp_path / "out.csv")
        result = _run(synthetic_csv, tmp_path, tampered)
        assert not result.passed
        # The engine must not have produced output.
        assert not os.path.exists(out_path), \
            "engine ran despite authorization rejection"


class TestEvaluateAuthorizationUnit:
    """Direct unit tests of evaluate_authorization()."""

    def test_none_grant_rejected(self, granted_scope):
        result = evaluate_authorization(None, granted_scope)
        assert not result.authorized
        assert "no authorization grant supplied" in result.reasons

    def test_none_observed_rejected(self, granted_scope):
        result = evaluate_authorization(granted_scope, None)
        assert not result.authorized
        assert any("observed scope could not be computed" in r for r in result.reasons)

    def test_both_none_rejected(self):
        result = evaluate_authorization(None, None)
        assert not result.authorized
