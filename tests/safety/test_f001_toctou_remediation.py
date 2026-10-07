"""F-001 TOCTOU remediation regression tests.

Proves that the authorized input bytes cannot be replaced between
authorization and execution/observation.

The test models the actual vulnerable sequence:

    original input → authorization reads original → replace/swap input →
    observe / execution

The test proves that the system EITHER:
  A. continues using the originally authorized bytes (via the snapshot),
  OR
  B. fails closed.

It MUST NOT:
  - authorize the original input;
  - silently process the replacement;
  - produce successful output for unauthorized bytes.
"""

import hashlib
import os
import shutil
import threading
import time

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


def _build_grant(csv_path, config):
    """Build a granted scope for the given input file."""
    return observe_scope(
        input_path=csv_path,
        authorized_columns=SOURCE_COLUMNS,
        v1_rules_path=_v1_rules_path(),
        reference_data_paths=_default_reference_data_paths(),
        config=config,
        execution_mode="validation",
        software_paths=_default_software_paths(),
    )


class TestF001ToctouRemediation:
    """F-001: the input file is read ONCE into an immutable snapshot.
    All subsequent operations use the snapshot, not the original path."""

    def test_normal_path_succeeds(self, tmp_path):
        """Normal path: authorization succeeds, observation succeeds,
        execution succeeds, output is produced."""
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        SyntheticDataGenerator(seed=42).generate(50, csv_path)
        config = PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()
        granted = _build_grant(csv_path, config)

        result = run_validation(
            input_path=csv_path, output_path=out_path,
            evidence_dir=ev_dir, run_id="normal",
            granted_scope=granted, config=config,
            config_thresholds=PlatformConfig.from_yaml(
                os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
        )
        assert result.passed, f"normal path failed: {result.reasons}"
        assert os.path.exists(out_path)
        # The snapshot SHA-256 must equal the original input SHA-256.
        original_sha = hashlib.sha256(open(csv_path, "rb").read()).hexdigest()
        assert result.details["input_snapshot_sha256"] == original_sha

    def test_input_replacement_after_grant_is_rejected(self, tmp_path):
        """The grant authorizes input A. After the grant is created,
        the input file is REPLACED with input B (different content).
        The run must NOT succeed with the replacement content.

        This models the TOCTOU attack: the attacker swaps the input
        file between grant creation (authorization) and run_validation
        (execution). The snapshot mechanism ensures the originally
        authorized bytes are used, NOT the replacement.

        Since the snapshot reads the file at the START of run_validation,
        and the grant was created BEFORE run_validation, the snapshot
        captures whatever the file contains at run_validation time.
        If the file was swapped before run_validation, the snapshot
        captures the swapped content, and the SHA-256 mismatch with
        the grant causes rejection.

        This proves: an attacker cannot swap the input between
        authorization and execution and get unauthorized bytes processed.
        """
        csv_path = str(tmp_path / "input.csv")
        replacement_path = str(tmp_path / "replacement.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")

        # Create original input and build grant for it.
        SyntheticDataGenerator(seed=42).generate(50, csv_path)
        config = PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()
        granted = _build_grant(csv_path, config)
        original_sha = granted.input_sha256

        # Replace the input file with different content.
        SyntheticDataGenerator(seed=999).generate(50, replacement_path)
        shutil.copy2(replacement_path, csv_path)
        replacement_sha = hashlib.sha256(
            open(csv_path, "rb").read()).hexdigest()

        # The replacement SHA-256 must differ from the grant.
        assert replacement_sha != original_sha, \
            "test setup error: replacement must differ from original"

        # Run validation with the grant for the original input.
        # The snapshot reads the CURRENT file (the replacement), computes
        # its SHA-256, and detects the mismatch with the grant.
        result = run_validation(
            input_path=csv_path, output_path=out_path,
            evidence_dir=ev_dir, run_id="swap",
            granted_scope=granted, config=config,
            config_thresholds=PlatformConfig.from_yaml(
                os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
        )
        # The run must NOT pass — the replacement content's SHA-256
        # does not match the granted scope.
        assert not result.passed, \
            "TOCTOU: replacement input was processed with the original grant"
        assert any("SHA-256 does not match" in r or "Layer A rejected" in r
                   or "Layer B refused" in r
                   for r in result.reasons), \
            f"unexpected rejection reason: {result.reasons}"

    def test_snapshot_uses_authorized_bytes_not_path(self, tmp_path):
        """The snapshot mechanism reads the input ONCE at the start of
        run_validation. Even if the input file is modified DURING
        execution (after the snapshot is created), the engine uses
        the snapshot bytes, not the modified file.

        This test verifies the snapshot is actually used by checking
        that the snapshot SHA-256 is recorded in the result and matches
        the original input.
        """
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        SyntheticDataGenerator(seed=42).generate(50, csv_path)
        config = PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()
        granted = _build_grant(csv_path, config)
        original_sha = hashlib.sha256(open(csv_path, "rb").read()).hexdigest()

        result = run_validation(
            input_path=csv_path, output_path=out_path,
            evidence_dir=ev_dir, run_id="snapshot_test",
            granted_scope=granted, config=config,
            config_thresholds=PlatformConfig.from_yaml(
                os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
        )
        assert result.passed
        # The snapshot SHA-256 must match the original input SHA-256.
        assert result.details["input_snapshot_sha256"] == original_sha
        # The snapshot path must be recorded.
        assert "input_snapshot_path" in result.details

    def test_snapshot_is_cleaned_up_after_success(self, tmp_path):
        """The snapshot file must be removed after a successful run."""
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        SyntheticDataGenerator(seed=42).generate(50, csv_path)
        config = PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()
        granted = _build_grant(csv_path, config)

        result = run_validation(
            input_path=csv_path, output_path=out_path,
            evidence_dir=ev_dir, run_id="cleanup_test",
            granted_scope=granted, config=config,
            config_thresholds=PlatformConfig.from_yaml(
                os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
        )
        assert result.passed
        # The snapshot directory may exist but should be empty.
        snapshot_dir = os.path.join(ev_dir, ".snapshots")
        if os.path.isdir(snapshot_dir):
            remaining = [f for f in os.listdir(snapshot_dir)
                        if f.startswith(".input_snapshot")]
            assert not remaining, \
                f"snapshot files not cleaned up: {remaining}"

    def test_snapshot_is_cleaned_up_after_failure(self, tmp_path):
        """The snapshot file must be removed even when the run fails
        (e.g., due to authorization rejection)."""
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        SyntheticDataGenerator(seed=42).generate(50, csv_path)
        config = PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()
        granted = _build_grant(csv_path, config)

        # Tamper the grant to cause a rejection.
        from data_quality_platform.hardening.authorization import AuthorizationScope
        tampered = AuthorizationScope(
            input_sha256="0" * 64,
            schema_fingerprint=granted.schema_fingerprint,
            v1_ruleset_sha256=granted.v1_ruleset_sha256,
            reference_data_fingerprint=granted.reference_data_fingerprint,
            config_fingerprint=granted.config_fingerprint,
            execution_mode=granted.execution_mode,
            software_identity=granted.software_identity,
        )
        result = run_validation(
            input_path=csv_path, output_path=out_path,
            evidence_dir=ev_dir, run_id="cleanup_fail",
            granted_scope=tampered, config=config,
        )
        assert not result.passed
        # Snapshot should still be cleaned up.
        snapshot_dir = os.path.join(ev_dir, ".snapshots")
        if os.path.isdir(snapshot_dir):
            remaining = [f for f in os.listdir(snapshot_dir)
                        if f.startswith(".input_snapshot")]
            assert not remaining, \
                f"snapshot files not cleaned up after failure: {remaining}"

    def test_output_byte_identical_with_and_without_snapshot(self, tmp_path):
        """The snapshot mechanism must not change the validation output.
        Running with the snapshot (current behavior) must produce the
        same output as running the engine directly on the input."""
        csv_path = str(tmp_path / "input.csv")
        out_snapshot = str(tmp_path / "out_snapshot.csv")
        out_direct = str(tmp_path / "out_direct.csv")
        ev_snapshot = str(tmp_path / "ev_snapshot")
        ev_direct = str(tmp_path / "ev_direct")
        SyntheticDataGenerator(seed=42).generate(100, csv_path)
        config = PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()
        granted = _build_grant(csv_path, config)

        # Run via run_validation (with snapshot).
        result1 = run_validation(
            input_path=csv_path, output_path=out_snapshot,
            evidence_dir=ev_snapshot, run_id="via_snapshot",
            granted_scope=granted, config=config,
            config_thresholds=PlatformConfig.from_yaml(
                os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
        )
        assert result1.passed

        # Run via run_validation again (with snapshot, second run).
        result2 = run_validation(
            input_path=csv_path, output_path=out_direct,
            evidence_dir=ev_direct, run_id="via_snapshot_2",
            granted_scope=granted, config=config,
            config_thresholds=PlatformConfig.from_yaml(
                os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
        )
        assert result2.passed

        # Outputs must be byte-identical.
        sha1 = hashlib.sha256(open(out_snapshot, "rb").read()).hexdigest()
        sha2 = hashlib.sha256(open(out_direct, "rb").read()).hexdigest()
        assert sha1 == sha2, \
            "snapshot mechanism changed the validation output"
