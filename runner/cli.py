"""Canonical CLI: python -m runner.cli

The CLI is a thin shell. The ONLY production validation entry point is
``data_quality_platform.hardening.pipeline.run_validation()``. The CLI
does NOT instantiate ``ValidationEngine`` directly — authorization is
enforced by the hardened execution boundary.

Commands: validate, generate, profile, test, verify, benchmark, authorize
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone


def _ensure_path() -> None:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)


_ensure_path()


from data_quality_platform.generation.synthetic import SyntheticDataGenerator
from data_quality_platform.config import PlatformConfig
from data_quality_platform.contracts import SOURCE_COLUMNS, FLAG_COLUMNS, TOTAL_OUTPUT_COLUMNS
from data_quality_platform.hardening.authorization import (
    AuthorizationScope,
    load_grant,
    observe_scope,
    sha256_file,
    schema_fingerprint,
    config_fingerprint,
)
from data_quality_platform.hardening.pipeline import run_validation


def cmd_generate(args) -> int:
    """Generate synthetic data."""
    gen = SyntheticDataGenerator(seed=args.seed)
    gen.generate(args.rows, args.output)
    print(f"Generated {args.rows} rows -> {args.output}")
    return 0


def cmd_authorize(args) -> int:
    """Build a granted AuthorizationScope JSON for an input file.

    The operator runs this once to produce a grant file, then passes the
    grant file to ``validate --grant <path>`` for every validation run
    against that input. The grant pins: input SHA-256, schema fingerprint,
    V1 ruleset SHA-256, reference-data fingerprint, config fingerprint,
    execution mode, and software identity.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = args.config or os.path.join(project_root, "configs", "quality.yaml")
    if not os.path.isfile(config_path):
        print(f"ERROR: config not found: {config_path}", file=sys.stderr)
        return 2
    config = PlatformConfig.from_yaml(config_path).as_dict()

    # Compute the observed scope for the current files — this becomes the
    # granted scope. The operator inspects it and commits it as the grant.
    from data_quality_platform.hardening.pipeline import _default_reference_data_paths, _default_software_paths, _v1_rules_path
    observed = observe_scope(
        input_path=args.csv,
        authorized_columns=SOURCE_COLUMNS,
        v1_rules_path=_v1_rules_path(),
        reference_data_paths=_default_reference_data_paths(),
        config=config,
        execution_mode=args.execution_mode,
        software_paths=_default_software_paths(),
    )
    grant = {
        "schema": "dqaeip.authorization.grant/1.0",
        "scope": observed.as_dict(),
        "identity_sha256": observed.identity_sha256(),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(grant, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"Grant written: {args.output}")
    print(f"  input_sha256:        {observed.input_sha256}")
    print(f"  v1_ruleset_sha256:   {observed.v1_ruleset_sha256}")
    print(f"  identity_sha256:     {observed.identity_sha256()}")
    return 0


def cmd_validate(args) -> int:
    """Run the hardened validation pipeline.

    Requires a grant file produced by ``runner.cli authorize``. The
    observed scope is recomputed at run time and compared against the
    granted scope via ``hmac.compare_digest``; any divergence yields
    AUTHORIZATION_REJECTED and the engine is never invoked.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    run_id = args.run_id or f"run_{int(time.time())}"
    evidence_dir = args.evidence_dir or os.path.join("evidence", run_id)

    config_path = args.config or os.path.join(project_root, "configs", "quality.yaml")
    if args.config and not os.path.isfile(config_path):
        print(f"ERROR: explicit --config path does not exist: {config_path}",
              file=sys.stderr)
        return 2
    config = PlatformConfig.from_yaml(config_path).as_dict() if os.path.isfile(config_path) else {}

    if not args.grant:
        print("ERROR: --grant <path> is required. Produce one with "
              "`python -m runner.cli authorize --csv <input>`.",
              file=sys.stderr)
        return 2
    if not os.path.isfile(args.grant):
        print(f"ERROR: grant file not found: {args.grant}", file=sys.stderr)
        return 2
    granted = load_grant(args.grant)

    result = run_validation(
        input_path=args.csv,
        output_path=args.output,
        evidence_dir=evidence_dir,
        run_id=run_id,
        granted_scope=granted,
        config=config,
        execution_mode="validation",
        config_thresholds=PlatformConfig.from_yaml(config_path).get_quality_thresholds()
            if os.path.isfile(config_path) else None,
    )

    # Always emit the machine-readable hardened-execution report.
    os.makedirs(evidence_dir, exist_ok=True)
    report_path = os.path.join(evidence_dir, "hardened_execution_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(result.to_json())
        f.write("\n")

    if result.passed:
        v = result.validation
        print(f"Validation PASSED: {v.input_row_count} rows in, "
              f"{v.output_row_count} rows out")
        print(f"  Run ID: {v.run_id}")
        print(f"  Duration: {v.duration_seconds:.2f}s")
        print(f"  Monitoring score: {v.monitoring_score:.4f}")
        print(f"  SLA passed: {v.sla_passed}")
        print(f"  Reconciliation passed: {v.reconciliation_passed}")
        print(f"  Evidence: {v.evidence_dir}")
        for rule_id, count in v.flag_counts.items():
            print(f"    {rule_id}: {count}")
        return 0
    else:
        print("Hardened execution FAILED:", file=sys.stderr)
        for r in result.reasons:
            print(f"  {r}", file=sys.stderr)
        if result.validation and not result.validation.success:
            print(f"  engine error: {result.validation.error}",
                  file=sys.stderr)
        print(f"  report: {report_path}", file=sys.stderr)
        return 1


def cmd_profile(args) -> int:
    """Profile a CSV file (basic stats)."""
    if not os.path.exists(args.csv):
        print(f"File not found: {args.csv}", file=sys.stderr)
        return 1
    with open(args.csv, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        row_count = 0
        blank_counts: dict = {}
        for row in reader:
            row_count += 1
            for col in header:
                if not str(row.get(col, "")).strip():
                    blank_counts[col] = blank_counts.get(col, 0) + 1
    print(f"File: {args.csv}")
    print(f"Columns: {len(header)}")
    print(f"Rows: {row_count}")
    print(f"\nBlank counts:")
    for col, count in sorted(blank_counts.items(), key=lambda x: -x[1]):
        if count > 0:
            pct = count / row_count * 100 if row_count > 0 else 0
            print(f"  {col}: {count} ({pct:.1f}%)")
    return 0


def cmd_test(args) -> int:
    """Run pytest."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = [sys.executable, "-m", "pytest", "-q"]
    if args.verbose:
        cmd.remove("-q")
        cmd.append("-v")
    result = subprocess.run(cmd, cwd=project_root)
    return result.returncode


def cmd_verify(args) -> int:
    """Run a quick self-check of the engine, rules, and contracts."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    evidence_dir = args.evidence_dir or os.path.join(project_root, "evidence", "verification")
    os.makedirs(evidence_dir, exist_ok=True)

    from data_quality_platform.schema.validator import SchemaValidator
    from data_quality_platform.rules import RuleRegistry

    results: list = []

    def check(name: str, fn):
        try:
            status, evidence = fn()
        except Exception as e:
            status, evidence = "FAIL", repr(e)
        results.append({"check": name, "status": status, "evidence": evidence})

    def q_imports():
        from data_quality_platform.rules import RuleRegistry  # noqa
        from data_quality_platform.validation.engine import ValidationEngine  # noqa
        from data_quality_platform.hardening.pipeline import run_validation  # noqa
        from runner.cli import main  # noqa
        return "PASS", "imports OK"

    def q_rules():
        rr = RuleRegistry.create_default()
        valid, errors, warnings = rr.validate()
        if valid and rr.count == 8:
            return "PASS", f"{rr.count} rules, valid"
        return "FAIL", f"errors={errors} warnings={warnings}"

    def q_schema():
        sv = SchemaValidator()
        valid, errors = sv.validate_header(list(SOURCE_COLUMNS))
        if valid:
            return "PASS", "schema validator accepts 33 columns"
        return "FAIL", f"errors={errors}"

    def q_contracts():
        if (len(SOURCE_COLUMNS) == 33 and len(FLAG_COLUMNS) == 8
                and TOTAL_OUTPUT_COLUMNS == 41):
            return "PASS", "33 source + 8 flag = 41 output"
        return "FAIL", "column count mismatch"

    check("imports", q_imports)
    check("rules", q_rules)
    check("schema", q_schema)
    check("contracts", q_contracts)

    report_path = os.path.join(evidence_dir, "verification_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({"timestamp": datetime.now(timezone.utc).isoformat(),
                   "results": results}, f, indent=2)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    print(f"Verification: {passed} PASS, {failed} FAIL")
    print(f"Report: {report_path}")
    return 0 if failed == 0 else 1


def cmd_benchmark(args) -> int:
    """Run scalability benchmark."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = os.path.join(project_root, "scripts", "benchmark.py")
    if not os.path.exists(script):
        print(f"Benchmark script not found: {script}", file=sys.stderr)
        return 1
    result = subprocess.run([sys.executable, script], cwd=project_root)
    return result.returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m runner.cli",
        description="DQAEIP Data Quality CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_gen = subparsers.add_parser("generate", help="Generate synthetic data")
    p_gen.add_argument("--rows", type=int, required=True)
    p_gen.add_argument("--seed", type=int, default=20260821)
    p_gen.add_argument("--output", required=True)
    p_gen.set_defaults(func=cmd_generate)

    p_auth = subparsers.add_parser("authorize",
        help="Build an authorization grant for an input CSV")
    p_auth.add_argument("--csv", required=True, help="Input CSV path")
    p_auth.add_argument("--output", required=True, help="Grant JSON output path")
    p_auth.add_argument("--config", default="", help="Optional config YAML")
    p_auth.add_argument("--execution-mode", default="validation",
        choices=("validation", "export", "mutation_testing", "benchmark"))
    p_auth.set_defaults(func=cmd_authorize)

    p_val = subparsers.add_parser("validate",
        help="Run the hardened validation pipeline")
    p_val.add_argument("--csv", required=True, help="Input CSV path")
    p_val.add_argument("--output", required=True, help="Output Flag Preview path")
    p_val.add_argument("--grant", required=True,
        help="Authorization grant JSON (from `runner.cli authorize`)")
    p_val.add_argument("--run-id", default="")
    p_val.add_argument("--evidence-dir", default="")
    p_val.add_argument("--config", default="")
    p_val.set_defaults(func=cmd_validate)

    p_prof = subparsers.add_parser("profile", help="Profile a CSV file")
    p_prof.add_argument("--csv", required=True)
    p_prof.set_defaults(func=cmd_profile)

    p_test = subparsers.add_parser("test", help="Run pytest")
    p_test.add_argument("-v", "--verbose", action="store_true")
    p_test.set_defaults(func=cmd_test)

    p_ver = subparsers.add_parser("verify", help="Run quick self-check")
    p_ver.add_argument("--evidence-dir", default="")
    p_ver.set_defaults(func=cmd_verify)

    p_bench = subparsers.add_parser("benchmark", help="Run scalability benchmark")
    p_bench.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
