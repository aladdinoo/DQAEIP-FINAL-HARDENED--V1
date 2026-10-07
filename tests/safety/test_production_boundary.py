"""Production execution boundary regression test.

Proves that every SUPPORTED production entry point enters through
``run_validation()`` — the authorization and safety boundary — and does
NOT instantiate ``ValidationEngine`` directly to perform validation.

This test does NOT verify:
  - test-only code (tests may instantiate ValidationEngine directly
    for unit/integration testing — that is acceptable)
  - dev tooling (benchmark.py, mutation_testing.py, replay.py may use
    the engine directly — they are not production entry points)
  - import-only references (cmd_verify, gate_core_imports verify the
    import succeeds but never call validate())

What this test DOES verify:
  1. ``runner.cli.cmd_validate`` calls ``run_validation()``, not
     ``ValidationEngine.validate()``.
  2. ``airflow.dags.dq_validation_dag._run_validation_task`` calls
     ``run_validation()``, not ``ValidationEngine.validate()``.
  3. ``run_validation()`` is the only function in the production path
     that instantiates ``ValidationEngine``.
  4. The CLI ``validate`` command requires a ``--grant`` argument
     (authorization cannot be bypassed by omitting the grant).
"""

import inspect
import os
import re
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class TestProductionExecutionBoundary:
    """The production execution boundary is run_validation()."""

    def test_cli_cmd_validate_uses_run_validation(self):
        """``runner.cli.cmd_validate`` must call ``run_validation()``,
        not ``ValidationEngine.validate()``."""
        import runner.cli
        src = inspect.getsource(runner.cli.cmd_validate)
        assert "run_validation(" in src, \
            "cmd_validate must call run_validation()"
        # cmd_validate must NOT instantiate ValidationEngine to perform
        # validation. (An import-only reference in cmd_verify is acceptable.)
        assert "ValidationEngine(" not in src, \
            "cmd_validate must not instantiate ValidationEngine directly"

    def test_cli_validate_requires_grant(self):
        """The CLI ``validate`` subparser must require ``--grant``."""
        import runner.cli
        src = inspect.getsource(runner.cli)
        # The --grant argument must be required (required=True).
        assert re.search(r'--grant["\'].*required\s*=\s*True', src) or \
               re.search(r'add_argument\(["\']--grant["\']\s*,\s*required\s*=\s*True', src), \
            "validate subparser must require --grant"

    def test_airflow_task_uses_run_validation(self):
        """``_run_validation_task`` must call ``run_validation()``,
        not ``ValidationEngine.validate()``."""
        dag_path = os.path.join(PROJECT_ROOT, "airflow", "dags",
                                "dq_validation_dag.py")
        src = open(dag_path).read()
        assert "run_validation(" in src, \
            "Airflow DAG must call run_validation()"
        assert "ValidationEngine(" not in src, \
            "Airflow DAG must not instantiate ValidationEngine directly"

    def test_run_validation_is_the_only_production_engine_caller(self):
        """In the production code (data_quality_platform/, runner/,
        airflow/), ``ValidationEngine(...)`` instantiation must appear
        ONLY in:
          - ``hardening/pipeline.py`` (which IS run_validation — the
            production boundary)
          - ``validation/replay.py`` (dev tooling for deterministic
            replay verification — NOT a production entry point; used
          only by tests)

        No other production file may instantiate ValidationEngine."""
        scan_dirs = [
            os.path.join(PROJECT_ROOT, "data_quality_platform"),
            os.path.join(PROJECT_ROOT, "runner"),
            os.path.join(PROJECT_ROOT, "airflow"),
        ]
        callers = []
        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            for dirpath, _, files in os.walk(scan_dir):
                if "__pycache__" in dirpath:
                    continue
                for fname in files:
                    if not fname.endswith(".py"):
                        continue
                    fpath = os.path.join(dirpath, fname)
                    try:
                        content = open(fpath).read()
                    except OSError:
                        continue
                    # Look for ValidationEngine instantiation (not import).
                    if re.search(r'\bValidationEngine\s*\(', content):
                        rel = os.path.relpath(fpath, PROJECT_ROOT)
                        callers.append(rel)
        # The ONLY production files that instantiate ValidationEngine:
        #   - pipeline.py (the boundary itself)
        #   - replay.py (dev/test tooling, not a production entry point)
        expected = {
            "data_quality_platform/hardening/pipeline.py",
            "data_quality_platform/validation/replay.py",
        }
        callers_norm = {c.replace("\\", "/") for c in callers}
        unexpected = callers_norm - expected
        assert not unexpected, \
            f"ValidationEngine instantiated in unexpected production files: " \
            f"{unexpected}"

    def test_pipeline_run_validation_invokes_engine(self):
        """``run_validation()`` in pipeline.py must instantiate
        ValidationEngine (this is the correct path)."""
        import data_quality_platform.hardening.pipeline as pipeline
        src = inspect.getsource(pipeline.run_validation)
        assert "ValidationEngine(" in src, \
            "run_validation must instantiate ValidationEngine"

    def test_engine_docstring_documents_internal_status(self):
        """ValidationEngine's docstring must document that it is an
        internal implementation component and that production execution
        MUST enter through run_validation()."""
        from data_quality_platform.validation.engine import ValidationEngine
        doc = ValidationEngine.__doc__ or ""
        assert "internal" in doc.lower(), \
            "ValidationEngine docstring must say it is internal"
        assert "run_validation" in doc, \
            "ValidationEngine docstring must reference run_validation()"
