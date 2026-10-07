import csv
import json
import os
import shutil
import subprocess
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRuntimeVerification:
    """Runtime verification: real execution, real files, real evidence."""

    def test_imports_at_runtime(self):
        """Verify all canonical imports work at runtime."""
        code = """
from data_quality_platform.rules import RuleRegistry
from data_quality_platform.validation.engine import ValidationEngine
from runner.cli import main
print("OK")
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
        )
        assert result.returncode == 0, f"Import failed: {result.stderr}"
        assert "OK" in result.stdout

    def test_generate_1k(self):
        """Generate 1K rows and verify file."""
        out = os.path.join(PROJECT_ROOT, "data", "generated", "rt_1k.csv")
        result = subprocess.run(
            [sys.executable, "-m", "runner.cli", "generate",
             "--rows", "1000", "--seed", "20260821", "--output", out],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
        )
        assert result.returncode == 0, result.stderr
        assert os.path.exists(out)
        with open(out) as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1000

    def test_validate_1k(self):
        """Validate 1K rows end-to-end via the hardened execution boundary."""
        csv_path = os.path.join(PROJECT_ROOT, "data", "generated", "rt_1k.csv")
        out_path = os.path.join(PROJECT_ROOT, "data", "generated", "rt_1k_out.csv")
        ev_dir = os.path.join(PROJECT_ROOT, "evidence", "rt_1k")
        grant_path = os.path.join(PROJECT_ROOT, "data", "generated", "rt_1k.grant.json")

        if not os.path.exists(csv_path):
            pytest.skip("rt_1k.csv not generated")

        # Concurrent-run collision prevention: run_validation() atomically
        # claims evidence_dir; clean up any leftover dir from a prior run.
        if os.path.isdir(ev_dir):
            shutil.rmtree(ev_dir, ignore_errors=True)

        # Authorization is required.
        auth = subprocess.run(
            [sys.executable, "-m", "runner.cli", "authorize",
             "--csv", csv_path, "--output", grant_path],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
        )
        assert auth.returncode == 0, f"authorize failed: {auth.stderr}"

        result = subprocess.run(
            [sys.executable, "-m", "runner.cli", "validate",
             "--csv", csv_path, "--output", out_path,
             "--grant", grant_path,
             "--run-id", "rt_1k", "--evidence-dir", ev_dir],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
        )
        assert result.returncode == 0, f"Validate failed: {result.stderr}"

        # Verify output
        with open(out_path) as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            assert len(header) == 41
            rows = list(reader)
        assert len(rows) == 1000

        # Verify evidence
        assert os.path.exists(os.path.join(ev_dir, "lineage.json"))
        assert os.path.exists(os.path.join(ev_dir, "audit.json"))
        assert os.path.exists(os.path.join(ev_dir, "monitoring.json"))
        assert os.path.exists(os.path.join(ev_dir, "manifest.json"))
        # The hardened-execution report is also written.
        assert os.path.exists(os.path.join(ev_dir, "hardened_execution_report.json"))

    def test_verify_command(self, tmp_path):
        """Run the verify command.

        The evidence dir is isolated to tmp_path so the test never rewrites
        the tracked historical evidence under evidence/verification/.
        """
        result = subprocess.run(
            [sys.executable, "-m", "runner.cli", "verify",
             "--evidence-dir", str(tmp_path)],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
            timeout=120,
            env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
        )
        # verify returns 0 if no FAIL statuses
        assert "Verification:" in result.stdout or "Verification:" in result.stderr
        # Report landed in the isolated dir, not in tracked evidence/
        assert os.path.exists(os.path.join(str(tmp_path), "verification_report.json"))


# The historical TestClickHouseIntegration class has been removed.
# ClickHouse was never connected at runtime (the production client was
# intentionally absent). The SQL schemas and docker-compose.yml were
# removed in the simplification. ClickHouse runtime is out of scope.


class TestAirflowDAG:
    """Airflow DAG tests - import and structure validation."""

    def test_dag_file_exists(self):
        assert os.path.exists(os.path.join(PROJECT_ROOT, "airflow", "dags", "dq_validation_dag.py"))

    def test_dag_importable(self):
        """Test that the DAG file can be imported."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dq_validation_dag",
            os.path.join(PROJECT_ROOT, "airflow", "dags", "dq_validation_dag.py"),
        )
        # The import may fail if airflow is not installed, that's OK
        try:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            assert hasattr(mod, 'dag')
        except ImportError:
            pytest.skip("Airflow not installed - DESIGNED_BUT_NOT_RUNTIME_VERIFIED")

    def test_dag_has_tasks(self):
        """Verify DAG structure has the single hardened-validation task."""
        dag_path = os.path.join(PROJECT_ROOT, "airflow", "dags", "dq_validation_dag.py")
        with open(dag_path) as f:
            content = f.read()
        # The simplified DAG has ONE task that calls run_validation.
        assert "run_validation" in content, "DAG must call run_validation"
        assert "PythonOperator" in content
