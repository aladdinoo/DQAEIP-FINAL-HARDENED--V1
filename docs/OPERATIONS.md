# DQAEIP Operations

## 1. CLI commands

The CLI is `python -m runner.cli`. It is a thin shell; the only
production validation entry point is `run_validation()`.

### `generate` — generate synthetic test data

```bash
python3 -m runner.cli generate \
    --rows 1000 \
    --seed 20260821 \
    --output data/generated/input.csv
```

### `authorize` — build an authorization grant

```bash
python3 -m runner.cli authorize \
    --csv data/generated/input.csv \
    --output data/generated/input.grant.json
```

The grant pins: input SHA-256, schema fingerprint, V1 ruleset SHA-256,
reference data fingerprint, config fingerprint, execution mode, and
software identity. Commit the grant file to your config repo and
reuse it for every validation of that input.

### `validate` — run the hardened validation pipeline

```bash
python3 -m runner.cli validate \
    --csv data/generated/input.csv \
    --output data/generated/output.csv \
    --grant data/generated/input.grant.json \
    --run-id my_run \
    --evidence-dir evidence/my_run
```

Exit codes: 0 (success), 1 (validation failure), 2 (input contract
failure or explicit `--config` missing).

### `profile` — profile a CSV (basic stats)

```bash
python3 -m runner.cli profile --csv data/generated/input.csv
```

### `verify` — quick self-check

```bash
python3 -m runner.cli verify --evidence-dir evidence/verification
```

### `test` — run pytest

```bash
python3 -m runner.cli test -v
```

### `benchmark` — run scalability benchmark

```bash
python3 -m runner.cli benchmark
```

## 2. Airflow integration

The DAG at `airflow/dags/dq_validation_dag.py` defines ONE task that
calls `run_validation()`. It is a thin orchestration layer; it does
NOT implement validation logic.

To deploy:

1. Install Airflow in your environment.
2. Place `airflow/dags/dq_validation_dag.py` in your Airflow
   `dags_folder`.
3. Trigger the DAG with `params`:
   - `csv_path` — input CSV path
   - `output_path` — output CSV path
   - `evidence_dir` — evidence directory
   - `grant_path` — grant JSON path (from `runner.cli authorize`)

The DAG is NOT deployed as part of this repository. Airflow runtime
is the operator's responsibility.

## 3. Release gate

The release gate is `scripts/release_gate.py`. It is a 16-gate
deterministic gate that does NOT depend on Git or GPG.

```bash
python3 scripts/release_gate.py
```

Output: `evidence/release_gate/final_release_gate.json` (atomic-published).
Exit: 0 (all gates PASS) or 1 (any gate FAIL).

The gate verifies:

1. Repository structure (required files present)
2. Core imports (production imports succeed; 8 rules valid)
3. Frozen V1 integrity (`v1_rules.py` SHA-256 matches pinned constant)
4. Unit tests
5. Contract tests
6. Integration tests
7. Golden tests
8. Property tests
9. Safety tests
10. Hardening tests
11. Differential validation (engine vs oracle)
12. Deterministic replay (two runs byte-identical)
13. Evidence validation (root hash verifies)
14. PII evidence scan (no PII patterns in evidence)
15. Negative battery (tampered scope rejected)
16. No GPG/Git dependency in production code

## 4. Evidence locations

| Artifact | Path |
|----------|------|
| Per-run evidence | `evidence/<run_id>/` (manifest, lineage, audit, monitoring, alerts, evidence_root, hardened_execution_report) |
| Release gate output | `evidence/release_gate/final_release_gate.json` |
| Final results | `FINAL_RESULTS.json` (root — single authoritative current result) |

## 5. Reproduction

```bash
# Generate a deterministic input
python3 -m runner.cli generate --rows 1000 --seed 20260821 \
    --output data/generated/input.csv

# Authorize
python3 -m runner.cli authorize --csv data/generated/input.csv \
    --output data/generated/input.grant.json

# Validate (run 1)
python3 -m runner.cli validate \
    --csv data/generated/input.csv \
    --output data/generated/output_run1.csv \
    --grant data/generated/input.grant.json \
    --run-id run1 \
    --evidence-dir evidence/run1

# Validate (run 2)
python3 -m runner.cli validate \
    --csv data/generated/input.csv \
    --output data/generated/output_run2.csv \
    --grant data/generated/input.grant.json \
    --run-id run2 \
    --evidence-dir evidence/run2

# Verify byte-identical output
sha256sum data/generated/output_run1.csv data/generated/output_run2.csv
# Expected: identical SHA-256
```

## 6. Limitations

| ID | Title | Status | Mitigation |
|----|-------|--------|------------|
| LIM-001 | O(N) memory profile | OPEN | Engine materializes the full dataset. Bounded-memory design is future work. |
| LIM-002 | Airflow runtime not validated | OPEN | DAG is structurally correct; deploy at your own responsibility. |
| LIM-003 | No customer data processed | NOT_PROVEN | All validations used synthetic data. |
| LIM-004 | DL001-DL015 geography table unavailable | 7 golden tests skipped | The authoritative geography acceptance table was not supplied. |

## 7. Dependencies

Runtime: `pyyaml>=6.0` (the only third-party runtime dependency).
Dev: `pytest>=7.0`, `pytest-cov>=4.0`.

There are NO cryptographic library dependencies. There is no `gpg`,
`gnupg`, `cryptography`, or `pyca/cryptography` dependency. SHA-256
is provided by the Python stdlib `hashlib` module.

There is no ClickHouse client dependency. There is no Airflow
dependency declared in `pyproject.toml` (the DAG file imports Airflow
lazily inside a try/except, so it does not fail at import time when
Airflow is not installed).
