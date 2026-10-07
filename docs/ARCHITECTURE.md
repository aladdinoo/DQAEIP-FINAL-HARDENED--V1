# DQAEIP Architecture

## 1. Overview

DQAEIP is a deterministic, flag-only consumer data-quality validation
platform. The architecture is intentionally simple: there is ONE
production execution path, and every production caller (CLI, Airflow,
application) must use it.

```
CLI ────────┐
Airflow ────┼──> run_validation()  (hardening/pipeline.py)
Application ┘            |
                         v
               Layer A: Input Contract Firewall
                         |
               Layer F: Schema Evolution Guard
                         |
               Layer G: Reference Data Versioning
                         |
               Layer B: Execution Authorization Gate
                         |
               Layer H: Pre-execution Resource Guard
                         |
               ValidationEngine.validate()  (in-process)
                         |
               Layer H: Post-execution Resource Guard
                         |
               Evidence (manifest, lineage, audit, monitoring, alerts, root)
```

## 2. Single execution boundary

`data_quality_platform/hardening/pipeline.py::run_validation()` is the
ONLY production entry point that runs a validation. It:

1. **Layer A** — Validates the input file against a cryptographically
   pinned contract (size, UTF-8, NUL-byte scan, header equality,
   column count, SHA-256 identity pin).
2. **Layer F** — Classifies the schema as compatible or incompatible
   with the authorized column set.
3. **Layer G** — Pins the reference data fingerprint (the V1 reference
   data is hard-coded in `contracts.py`).
4. **Layer B** — Compares the observed execution scope against the
   granted scope via `hmac.compare_digest` on 6 fields. Any divergence
   yields `AUTHORIZATION_REJECTED` and the engine is never invoked.
5. **Layer H (pre)** — Checks input size and row count against
   resource limits.
6. **Engine** — Calls `ValidationEngine.validate()` in-process. The
   engine internally implements Layer D (atomic output commit via
   temp + fsync + os.replace).
7. **Layer H (post)** — Checks output size against resource limits.

A `HardenedExecutionResult` is returned with `passed=True` only if
every layer accepted and the engine returned `success=True`.

## 3. Component map

| Component | Path | Purpose |
|-----------|------|---------|
| CLI | `runner/cli.py` | Thin shell: `validate`, `authorize`, `generate`, `profile`, `test`, `verify`, `benchmark` |
| Hardened execution boundary | `data_quality_platform/hardening/pipeline.py` | Single entry point; wires Layers A→F→G→B→H→engine→H |
| Layer A — Input Contract | `data_quality_platform/hardening/input_contract.py` | Structural input validation |
| Layer B — Authorization | `data_quality_platform/hardening/authorization.py` | SHA-256 scope comparison via `hmac.compare_digest` |
| Layer F — Schema Guard | `data_quality_platform/hardening/schema_guard.py` | Schema evolution classification |
| Layer G — Reference Data | `data_quality_platform/hardening/reference_data.py` | Reference data fingerprinting |
| Layer H — Resource Guard | `data_quality_platform/hardening/resource_guard.py` | Resource ceilings (size, rows, time, RSS) |
| Validation engine | `data_quality_platform/validation/engine.py` | Streaming CSV validation with GAP-01/GAP-02 |
| Rule registry | `data_quality_platform/rules/registry.py` | 8 frozen V1 rules, hash-pinned |
| V1 rules | `data_quality_platform/rules/v1_rules.py` | The 8 rule implementations (SHA-256 pinned) |
| Contracts | `data_quality_platform/contracts.py` | 33 source + 8 flag + 41 output columns; `STATE_ZIP_PREFIXES` |
| Schema validator | `data_quality_platform/schema/validator.py` | 33-column schema validation |
| Evidence manifests | `data_quality_platform/evidence/manifests.py` | `manifest.json` with file hashes |
| Lineage recorder | `data_quality_platform/lineage/recorder.py` | Row-level lineage (capped at 1000) |
| Audit trail | `data_quality_platform/audit/trail.py` | Audit events |
| Quality monitor | `data_quality_platform/monitoring/quality.py` | 8-dimension SLA scoring |
| Alert manager | `data_quality_platform/alerting/alerts.py` | SLA-breach / reconciliation alerts |
| Evidence root | `data_quality_platform/validation/evidence_root.py` | Tamper-evident root hash |
| Input contract (Layer A helper) | `data_quality_platform/validation/input_contract.py` | Used by `engine.validate()` for type-contract checks |
| Failure taxonomy | `data_quality_platform/validation/failure_taxonomy.py` | Failure classification |
| Replay | `data_quality_platform/validation/replay.py` | Deterministic replay verification |
| Synthetic generator | `data_quality_platform/generation/synthetic.py` | Test data generation |
| Config | `data_quality_platform/config/settings.py` | `PlatformConfig.from_yaml()` |
| Release gate | `scripts/release_gate.py` | 16 deterministic gates (no Git/GPG) |
| Mutation testing | `scripts/mutation_testing.py` | Proves tests catch rule mutations |
| Airflow DAG | `airflow/dags/dq_validation_dag.py` | Thin task calling `run_validation()` |

## 4. Data flow

```
Input CSV (33 columns)
    ↓  Layer A — structural checks (size, UTF-8, NUL, header, columns, SHA-256 pin)
    ↓  Layer F — schema compatibility
    ↓  Layer G — reference data fingerprint
    ↓  Layer B — authorization scope comparison (hmac.compare_digest)
    ↓  Layer H — pre-execution resource guard
Engine: streaming row loop
    ↓  csv.DictReader → 8 rules per row → output row (33 source + 8 flags)
    ↓  temp file + fsync + os.replace (GAP-02 atomic publish)
    ↓  reconciliation (row count, columns, flag values)
    ↓  monitoring (8-dimension SLA)
    ↓  evidence write (manifest, lineage, audit, monitoring, alerts, evidence_root)
    ↓  Layer H — post-execution resource guard
HardenedExecutionResult
```

## 5. The 8 frozen V1 rules

The rules are defined in `data_quality_platform/rules/v1_rules.py`
(SHA-256: `daef1ded54c7d3c79898a1ba253be2acd5b6120e18b16b09009fdd7be9fc2276`).
Each rule returns 0 or 1. No rule can suppress another rule's flag.

| Rule ID | Purpose |
|---------|---------|
| `first_name_cleaning_candidate` | Flag suspicious first names (substring match against `SUSPICIOUS_NAME_PATTERNS`, non-alpha chars, repeated chars). |
| `last_name_cleaning_candidate` | Same as above, for last names. |
| `name_cleaning_candidate` | Flag rows where first == last (case-insensitive) or both are single chars. |
| `email_blank` | Flag rows where `email_address` is blank or null. |
| `email_syntax_failure` | Flag rows where `email_address` is non-empty but fails the regex. |
| `proposed_email_export_eligible` | Positive flag: email is non-empty and syntactically valid. |
| `zip_state_assessable` | Flag rows where both `zip` and `state` are present and `state` is a valid US state. |
| `geography_mismatch_candidate` | Flag rows where ZIP prefix does not match the state. Conditional on `zip_state_assessable == 1`. |

### Frozen V1 semantics

The name rules use **case-insensitive substring matching**. The
pattern `"na"` matches ordinary names like `"Anna"`, `"Hannah"`,
`"Donna"`, `"Jonathan"`. This is the **frozen V1 contract** — not an
engine defect. Changing it requires a new rule version and a re-issued
release identity.

### Geography assessability

`geography_mismatch_candidate` is conditional on
`zip_state_assessable == 1`. Non-assessable records (invalid US state,
blank zip/state) return 0 for both flags — these records are **NOT
clean**, they are **NOT ASSESSABLE / NOT EVALUATED**.

## 6. Evidence architecture

Each validation run writes to `--evidence-dir`:

| File | Producer | Content |
|------|----------|---------|
| `manifest.json` | `ManifestWriter` | success/failure type, file_hashes (SHA-256), run_id, row counts, schema_hash, rule_hashes, flag_counts, reconciliation, monitoring_score, sla_results, safety_invariants |
| `lineage.json` | `LineageRecorder` | run metadata + row-level lineage for flagged rows (capped at 1000) |
| `audit.json` | `AuditTrail` | events: run_started, schema_validated, rules_loaded, validation_started, validation_completed/failed, reconciliation, monitoring, output_written, lineage, manifest_written |
| `monitoring.json` | `QualityMonitor` | 8-dimension SLA scores + overall_score |
| `alerts.json` | `AlertManager` | SLA-breach / reconciliation-failure / validation-failure alerts |
| `evidence_root.json` | `evidence_root.py` | Tamper-evident root hash over all artifact hashes |
| `hardened_execution_report.json` | `pipeline.py` | The `HardenedExecutionResult` (layer verdicts, identity SHA-256) |

Tamper detection: `evidence_root.json` contains a root SHA-256 over
all artifact hashes. Any modification to any artifact invalidates the
root hash. Verified by release gate gate 13 (`evidence_validation`).

## 7. Authorization model

Authorization uses the smallest model that correctly protects the
execution boundary:

- **Actor**: the operator invoking the CLI / Airflow / application.
- **Operation**: `validation`, `export`, `mutation_testing`, or
  `benchmark` (the `execution_mode` field).
- **Input scope**: the input file SHA-256.
- **Output scope**: the output file path (enforced by GAP-01 path
  collision guard).
- **Evidence scope**: the evidence directory.

The granted `AuthorizationScope` pins 6 fields:

1. `input_sha256` — SHA-256 of the input file
2. `schema_fingerprint` — SHA-256 of the authorized column-list JSON
3. `v1_ruleset_sha256` — SHA-256 of `v1_rules.py` (pinned constant)
4. `reference_data_fingerprint` — SHA-256 of the reference data bundle
5. `config_fingerprint` — SHA-256 of the canonical configuration JSON
6. `software_identity` — map of module-label → SHA-256 for the 5
   production modules (hardening.input_contract,
   hardening.authorization, hardening.resource_guard, validation.engine,
   rules.v1_rules)

The observed scope is recomputed at run time from the actual files
and compared via `hmac.compare_digest` on each hex digest. Any
divergence yields `AUTHORIZATION_REJECTED` with the list of divergent
fields. The gate is fail-closed: missing files, unreadable artifacts,
or any exception yield rejection; the gate never defaults to
authorized.

There is no RBAC system. There are no roles. There is no permissions
enum. The authorization model is "the operator supplies a grant that
cryptographically pins the execution scope; the runtime verifies it."

## 8. Release gate

`scripts/release_gate.py` is a 16-gate deterministic release gate.
It does NOT depend on Git or GPG. It verifies:

| # | Gate | Purpose |
|---|------|---------|
| 1 | `repository_structure` | Required files present |
| 2 | `core_imports` | All production imports succeed; 8 rules valid |
| 3 | `frozen_v1_integrity` | `v1_rules.py` SHA-256 matches pinned constant |
| 4 | `unit_tests` | All unit tests pass |
| 5 | `contract_tests` | All contract tests pass |
| 6 | `integration_tests` | All integration tests pass |
| 7 | `golden_tests` | All golden tests pass |
| 8 | `property_tests` | All property tests pass |
| 9 | `safety_tests` | All safety tests pass |
| 10 | `hardening_tests` | All hardening tests pass |
| 11 | `differential_validation` | Engine vs oracle consistency |
| 12 | `deterministic_replay` | Two runs byte-identical |
| 13 | `evidence_validation` | Evidence root hash verifies |
| 14 | `pii_evidence_scan` | No PII patterns in evidence |
| 15 | `negative_battery` | Tampered scope rejected (fail-closed) |
| 16 | `no_gpg_git_dependency` | No GPG/Git trust-anchor patterns in production code |

Output: `evidence/release_gate/final_release_gate.json` (atomic-published
via tmp → fsync → os.replace). Exit 0 only when all 16 gates PASS.

## 9. Airflow integration

`airflow/dags/dq_validation_dag.py` is a thin orchestration layer. It
defines ONE task that calls `run_validation()` — the same hardened
execution boundary used by the CLI. The DAG does NOT instantiate
`ValidationEngine` directly and does NOT implement validation logic.

The DAG is structurally importable and structurally tested. Airflow
runtime deployment is the operator's responsibility — the DAG is not
deployed as part of this repository.

## 10. Limitations

| ID | Title | Status |
|----|-------|--------|
| LIM-001 | O(N) memory profile | OPEN — engine materializes the full dataset in memory. `id_set` and `row_lineage_buffer` grow with row count. Bounded-memory design documented as future work. |
| LIM-002 | Airflow runtime not validated | OPEN — DAG is structurally correct; not deployed to an Airflow instance. |
| LIM-003 | No customer data processed | NOT_PROVEN — all validations used synthetic data. |
| LIM-004 | DL001-DL015 geography table unavailable | 7 golden tests skipped; the authoritative geography acceptance table was not supplied. |
