"""Airflow DAG for DQAEIP validation.

This is a THIN orchestration layer. It calls the SAME hardened
execution boundary used by the CLI: ``run_validation()``. The DAG does
NOT instantiate ``ValidationEngine`` directly and does NOT implement
validation logic.

The DAG is structurally importable and structurally tested. Airflow
runtime deployment is the operator's responsibility — the DAG is not
deployed as part of this repository.
"""

from datetime import datetime, timedelta
import os
import sys

DAGS_FOLDER = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(DAGS_FOLDER))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _run_validation_task(**context):
    """Single task that invokes the hardened execution boundary."""
    from data_quality_platform.hardening.pipeline import run_validation
    from data_quality_platform.hardening.authorization import load_grant
    from data_quality_platform.config import PlatformConfig

    params = context["params"]
    config_path = os.path.join(PROJECT_ROOT, "configs", "quality.yaml")
    platform_config = PlatformConfig.from_yaml(config_path)
    granted = load_grant(params["grant_path"])

    result = run_validation(
        input_path=params["csv_path"],
        output_path=params["output_path"],
        evidence_dir=params["evidence_dir"],
        run_id=context["run_id"],
        granted_scope=granted,
        config=platform_config.as_dict(),
        execution_mode="validation",
        config_thresholds=platform_config.get_quality_thresholds(),
    )
    if not result.passed:
        raise RuntimeError(
            f"Hardened execution failed: {result.reasons}")
    v = result.validation
    return {
        "row_count": v.input_row_count,
        "score": v.monitoring_score,
        "evidence_dir": params["evidence_dir"],
    }


try:
    from airflow import DAG
    from airflow.operators.python import PythonOperator

    default_args = {
        "owner": "data-quality",
        "depends_on_past": False,
        "email_on_failure": True,
        "email_on_retry": False,
        "retries": 0,  # hardened execution is deterministic; retries are pointless
        "retry_delay": timedelta(minutes=2),
        "execution_timeout": timedelta(minutes=60),
    }

    dag = DAG(
        "dq_validation",
        default_args=default_args,
        description="DQAEIP Hardened Validation Pipeline",
        schedule=None,
        start_date=datetime(2026, 1, 1),
        catchup=False,
        tags=["data-quality", "validation"],
    )

    validation_task = PythonOperator(
        task_id="run_hardened_validation",
        python_callable=_run_validation_task,
        dag=dag,
    )

except ImportError:
    # Airflow is not installed in this environment. The DAG is
    # structurally defined above; the import error is expected when
    # the test environment does not have Airflow.
    dag = None
    validation_task = None
