import csv
import os
import subprocess
import sys
from data_quality_platform.generation.synthetic import SyntheticDataGenerator


class TestCLISubprocess:
    """Subprocess integration tests: run actual CLI commands."""

    def _run_cli(self, args, cwd):
        env = os.environ.copy()
        env["PYTHONPATH"] = cwd
        result = subprocess.run(
            [sys.executable, "-m", "runner.cli"] + args,
            capture_output=True, text=True, cwd=cwd,
            timeout=60,
            env=env,
        )
        return result

    def test_cli_help(self):
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        result = self._run_cli(["--help"], project_root)
        assert result.returncode == 0
        assert "validate" in result.stdout
        assert "generate" in result.stdout
        assert "verify" in result.stdout

    def test_cli_generate(self, tmp_path):
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        out = os.path.join(str(tmp_path), "gen.csv")
        result = self._run_cli(["generate", "--rows", "50", "--seed", "42", "--output", out], project_root)
        assert result.returncode == 0
        assert os.path.exists(out)
        with open(out) as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 50

    def _build_grant(self, csv_path, grant_path, cwd):
        """Authorize the input CSV so the hardened execution boundary accepts it."""
        return self._run_cli(
            ["authorize", "--csv", csv_path, "--output", grant_path], cwd)

    def test_cli_validate(self, tmp_path):
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_dir = os.path.join(str(tmp_path), "data")
        os.makedirs(data_dir)
        csv_path = os.path.join(data_dir, "input.csv")
        out_path = os.path.join(data_dir, "output.csv")
        ev_dir = os.path.join(str(tmp_path), "evidence")
        grant_path = os.path.join(str(tmp_path), "grant.json")

        gen = SyntheticDataGenerator(seed=42)
        gen.generate(50, csv_path)

        # Authorization is required: build a grant first.
        auth = self._build_grant(csv_path, grant_path, project_root)
        assert auth.returncode == 0, f"authorize failed: {auth.stderr}"

        result = self._run_cli([
            "validate",
            "--csv", csv_path,
            "--output", out_path,
            "--grant", grant_path,
            "--run-id", "cli_test",
            "--evidence-dir", ev_dir,
        ], project_root)

        if result.returncode != 0:
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")

        assert result.returncode == 0, f"CLI validate failed: {result.stderr}"
        assert os.path.exists(out_path)
        assert os.path.exists(ev_dir)

        # Verify 41 columns
        with open(out_path) as f:
            reader = csv.DictReader(f)
            assert len(reader.fieldnames) == 41

    def test_cli_validate_exact_command(self, tmp_path):
        """Regression: test the exact PowerShell command from requirements."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_dir = os.path.join(str(tmp_path), "data", "generated")
        os.makedirs(data_dir)
        csv_path = os.path.join(data_dir, "synthetic_1k.csv")
        out_path = os.path.join(data_dir, "flag_preview_1k.csv")
        ev_dir = os.path.join(str(tmp_path), "evidence", "demo_1k")
        grant_path = os.path.join(str(tmp_path), "grant.json")

        gen = SyntheticDataGenerator(seed=20260821)
        gen.generate(1000, csv_path)

        auth = self._build_grant(csv_path, grant_path, project_root)
        assert auth.returncode == 0, f"authorize failed: {auth.stderr}"

        result = self._run_cli([
            "validate",
            "--csv", csv_path,
            "--output", out_path,
            "--grant", grant_path,
            "--run-id", "demo_1k",
            "--evidence-dir", ev_dir,
        ], project_root)

        assert result.returncode == 0, f"CLI failed: {result.stderr}"


class TestRegressionCLIFailures:
    """Regression tests for the 9 specific failures from previous version."""

    def test_rules_init_not_empty(self):
        """Regression #1: rules/__init__.py must export RuleRegistry."""
        from data_quality_platform.rules import RuleRegistry
        rr = RuleRegistry.create_default()
        assert rr.count == 8

    def test_engine_canonical_path(self):
        """Regression #2: engine must be at validation/engine.py."""
        from data_quality_platform.validation.engine import ValidationEngine
        assert hasattr(ValidationEngine, 'validate')

    def test_cli_engine_signature_compatible(self):
        """Regression #3: CLI must pass correct args to ValidationEngine."""
        from data_quality_platform.validation.engine import ValidationEngine
        import inspect
        sig = inspect.signature(ValidationEngine.__init__)
        params = list(sig.parameters.keys())
        assert 'rules' in params
        assert 'run_id' in params
        assert 'evidence_dir' in params

    def test_lineage_actually_called(self):
        """Regression #5: LineageRecorder must be called by engine."""
        import json
        from data_quality_platform.validation.engine import ValidationEngine
        from data_quality_platform.rules.registry import RuleRegistry
        from data_quality_platform.generation.synthetic import SyntheticDataGenerator
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "in.csv")
            out_path = os.path.join(td, "out.csv")
            ev_dir = os.path.join(td, "ev")
            gen = SyntheticDataGenerator(seed=42)
            gen.generate(20, csv_path)
            engine = ValidationEngine(rules=RuleRegistry.create_default(), run_id="reg5", evidence_dir=ev_dir)
            result = engine.validate(csv_path, out_path)
            assert result.success
            lineage_path = os.path.join(ev_dir, "lineage.json")
            assert os.path.exists(lineage_path), "Lineage not persisted by engine"

    def test_monitoring_actually_called(self):
        """Regression #6: QualityMonitor must be called by engine."""
        import json
        from data_quality_platform.validation.engine import ValidationEngine
        from data_quality_platform.rules.registry import RuleRegistry
        from data_quality_platform.generation.synthetic import SyntheticDataGenerator
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "in.csv")
            out_path = os.path.join(td, "out.csv")
            ev_dir = os.path.join(td, "ev")
            gen = SyntheticDataGenerator(seed=42)
            gen.generate(20, csv_path)
            engine = ValidationEngine(rules=RuleRegistry.create_default(), run_id="reg6", evidence_dir=ev_dir)
            result = engine.validate(csv_path, out_path)
            assert result.success
            mon_path = os.path.join(ev_dir, "monitoring.json")
            assert os.path.exists(mon_path), "Monitoring not persisted by engine"
            with open(mon_path) as f:
                mon = json.load(f)
            assert "overall_score" in mon

    def test_manifest_has_runtime_values(self):
        """Regression #9: manifest must contain actual runtime values."""
        import json
        from data_quality_platform.validation.engine import ValidationEngine
        from data_quality_platform.rules.registry import RuleRegistry
        from data_quality_platform.generation.synthetic import SyntheticDataGenerator
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "in.csv")
            out_path = os.path.join(td, "out.csv")
            ev_dir = os.path.join(td, "ev")
            gen = SyntheticDataGenerator(seed=42)
            gen.generate(30, csv_path)
            engine = ValidationEngine(rules=RuleRegistry.create_default(), run_id="reg9", evidence_dir=ev_dir)
            result = engine.validate(csv_path, out_path)
            assert result.success
            manifest_path = os.path.join(ev_dir, "manifest.json")
            with open(manifest_path) as f:
                manifest = json.load(f)
            assert manifest["source_row_count"] == 30
            assert manifest["output_row_count"] == 30
            assert isinstance(manifest.get("flag_counts"), dict)
            assert isinstance(manifest.get("file_hashes"), dict)
