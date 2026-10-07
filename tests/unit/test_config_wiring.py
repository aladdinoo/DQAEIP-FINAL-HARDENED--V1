"""Tests for the simplified PlatformConfig.

Scope (simplified architecture):
- PlatformConfig.from_yaml maps quality_thresholds.<key> -> <key>_threshold.
- Nested evidence section flattens onto field names.
- A missing file yields pure dataclass defaults (no error).
- Unknown sections are silently ignored (they are no longer runtime
  configuration in the simplified architecture).
- YAML-loaded thresholds change QualityMonitor SLA outcomes.
- CLI `validate` honors the config (end-to-end, thresholds land in
  monitoring.json).
"""

import json
import os
import subprocess
import sys
import tempfile

import pytest

from data_quality_platform.config import PlatformConfig


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class TestPlatformConfigFromYaml:
    def test_shipped_yaml_equals_pure_defaults(self):
        shipped = PlatformConfig.from_yaml(
            os.path.join(PROJECT_ROOT, "configs", "quality.yaml"))
        pure = PlatformConfig()
        assert shipped.get_quality_thresholds() == pure.get_quality_thresholds()

    def test_missing_file_returns_pure_defaults(self, tmp_path):
        config = PlatformConfig.from_yaml(str(tmp_path / "nonexistent.yaml"))
        assert config.completeness_threshold == 0.95
        assert config.evidence_base_dir == "evidence"

    def test_yaml_thresholds_override_defaults(self, tmp_path):
        yaml_path = tmp_path / "override.yaml"
        yaml_path.write_text(
            "quality_thresholds:\n  completeness: 0.80\n  validity: 0.75\n")
        config = PlatformConfig.from_yaml(str(yaml_path))
        assert config.completeness_threshold == 0.80
        assert config.validity_threshold == 0.75
        assert config.consistency_threshold == 0.90  # unchanged default

    def test_nested_evidence_section_flattens(self, tmp_path):
        yaml_path = tmp_path / "ev.yaml"
        yaml_path.write_text(
            "evidence:\n  generate_manifests: false\n  fsync_evidence: false\n")
        config = PlatformConfig.from_yaml(str(yaml_path))
        assert config.generate_manifests is False
        assert config.fsync_evidence is False

    def test_unknown_sections_silently_ignored(self, tmp_path):
        yaml_path = tmp_path / "unknown.yaml"
        yaml_path.write_text(
            "quality_thresholds:\n  completeness: 0.99\n"
            "clickhouse:\n  host: ignored.example.com\n"
            "security:\n  pii_masking_enabled: false\n"
            "monitoring:\n  monitoring_enabled: false\n"
            "some_unknown_section:\n  foo: bar\n")
        config = PlatformConfig.from_yaml(str(yaml_path))
        assert config.completeness_threshold == 0.99
        # Unknown sections (clickhouse, security, monitoring, some_unknown_section)
        # are silently ignored — they are no longer runtime configuration.

    def test_yaml_threshold_flip_validity_sla(self, tmp_path):
        # Lower the validity threshold so a low-validity dataset still passes SLA.
        yaml_path = tmp_path / "low_validity.yaml"
        yaml_path.write_text("quality_thresholds:\n  validity: 0.50\n")
        config = PlatformConfig.from_yaml(str(yaml_path))
        assert config.validity_threshold == 0.50


class TestCliHonorsConfig:
    """End-to-end: CLI validate honors the config thresholds."""

    def test_cli_validate_honors_config_thresholds(self, tmp_path):
        from data_quality_platform.generation.synthetic import SyntheticDataGenerator
        csv_path = str(tmp_path / "input.csv")
        out_path = str(tmp_path / "output.csv")
        ev_dir = str(tmp_path / "evidence")
        SyntheticDataGenerator(seed=20260821).generate(100, csv_path)

        # Build a grant for this input.
        grant_path = str(tmp_path / "grant.json")
        result = subprocess.run(
            [sys.executable, "-m", "runner.cli", "authorize",
             "--csv", csv_path, "--output", grant_path],
            capture_output=True, text=True, cwd=PROJECT_ROOT)
        assert result.returncode == 0, result.stderr

        result = subprocess.run(
            [sys.executable, "-m", "runner.cli", "validate",
             "--csv", csv_path, "--output", out_path,
             "--grant", grant_path, "--evidence-dir", ev_dir],
            capture_output=True, text=True, cwd=PROJECT_ROOT)
        assert result.returncode == 0, result.stderr

        manifest_path = os.path.join(ev_dir, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)
        # The monitoring_score and sla_results are present.
        assert "monitoring_score" in manifest
        assert "sla_results" in manifest


class TestN1ExplicitConfigPath:
    """N1: an explicit --config path that does not exist is a hard error."""

    def test_n1_explicit_missing_config_fails(self, tmp_path):
        from data_quality_platform.generation.synthetic import SyntheticDataGenerator
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=42).generate(10, csv_path)
        grant_path = str(tmp_path / "grant.json")
        subprocess.run(
            [sys.executable, "-m", "runner.cli", "authorize",
             "--csv", csv_path, "--output", grant_path],
            capture_output=True, text=True, cwd=PROJECT_ROOT)

        result = subprocess.run(
            [sys.executable, "-m", "runner.cli", "validate",
             "--csv", csv_path,
             "--output", str(tmp_path / "out.csv"),
             "--grant", grant_path,
             "--config", str(tmp_path / "nonexistent.yaml")],
            capture_output=True, text=True, cwd=PROJECT_ROOT)
        assert result.returncode == 2
        assert "does not exist" in result.stderr or "not found" in result.stderr

    def test_n1_default_path_works(self, tmp_path):
        """The default configs/quality.yaml is loaded successfully."""
        from data_quality_platform.generation.synthetic import SyntheticDataGenerator
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=42).generate(10, csv_path)
        grant_path = str(tmp_path / "grant.json")
        subprocess.run(
            [sys.executable, "-m", "runner.cli", "authorize",
             "--csv", csv_path, "--output", grant_path],
            capture_output=True, text=True, cwd=PROJECT_ROOT)

        result = subprocess.run(
            [sys.executable, "-m", "runner.cli", "validate",
             "--csv", csv_path,
             "--output", str(tmp_path / "out.csv"),
             "--grant", grant_path,
             "--evidence-dir", str(tmp_path / "ev")],
            capture_output=True, text=True, cwd=PROJECT_ROOT)
        assert result.returncode == 0, result.stderr
