# DQAEIP Security

## 1. Threat model

DQAEIP is a flag-only validation platform. It does not modify source
data, does not connect to external services at runtime, and does not
execute arbitrary code. The threat model:

| Threat | Control | Detection | Failure behavior | Test |
|--------|---------|-----------|-------------------|------|
| Unauthorized validation | Layer B authorization gate (SHA-256 scope comparison via `hmac.compare_digest`) | Tampered scope → `AUTHORIZATION_REJECTED` | Engine never invoked; exit 1 | `test_authorization_negative.py` (10 tests) |
| Tampered input | Layer A SHA-256 pin (input SHA must match granted scope) | Hash mismatch → `INPUT_CONTRACT_REJECTED` | Exit 1, no engine run | `test_input_contract.py`, `gate_negative_battery` |
| Tampered rules | `FROZEN_V1_SHA256` constant + release gate gate 3 | SHA-256 mismatch → gate FAIL | Release gate exit 1 | `gate_frozen_v1_integrity` |
| Tampered evidence | `evidence_root.json` root hash + consistency validator | Root hash mismatch / inconsistency → fail | `ValidationResult(success=False)` | `test_f5/f5b`, `test_evidence_consistency.py` (14 tests) |
| PII in evidence | `PIIMasker.mask_row()` at lineage write time + `scan_for_prohibited_content` at release | PII pattern detected → gate FAIL | Release gate exit 1 | `test_pii_security.py` (26 tests) |
| Secrets in evidence | `scan_for_prohibited_content` (PEM, AWS, GitHub, password) | Secret pattern detected → gate FAIL | Release gate exit 1 | `test_pii_security.py` |
| Path collision (input overwrite) | GAP-01 `Path.resolve()` equality | ValueError raised | Engine aborts | `test_gap01_path_collision.py` (8 tests) |
| Partial output on crash | GAP-02 temp + fsync + os.replace | Temp file removed on exception | Final output untouched | `test_gap02_atomic_output.py` (7 tests) |
| Resource exhaustion | Layer H resource guard | Pre-execution: input-size + row-count limit tripped; Post-execution: output-size limit tripped. Application-level wall-time and RSS limits are declared but NOT enforced; deployment-level OS/container resource controls are required. | `GUARD_TRIPPED` (pre/post only) | `gate_negative_battery` |
| Evidence inconsistency | 9-check consistency validator | Cross-artifact disagreement → `EvidenceConsistencyError` | `ValidationResult(success=False)` | `test_evidence_consistency.py` |
| Rule mutation | Independent oracle + mutation testing | Oracle divergence / mutant survival → test FAIL | Release gate gate 17 FAIL | `test_rule_oracle_consistency.py`, `gate_mutation_testing` |

## 2. Authorization (Layer B)

Authorization is enforced at the execution boundary. Every validation
requires a granted `AuthorizationScope` whose SHA-256 identity matches
the observed scope.

**Current authorization is operator-asserted authorization, NOT
cryptographically independent authorization.** The grant file is a JSON
document; anyone with read access can validate the input. There is no
GPG, no signing key, no trust anchor. The grant pins 6 scope fields
compared via `hmac.compare_digest`:

1. `input_sha256` — SHA-256 of the input file
2. `schema_fingerprint` — SHA-256 of the authorized column-list JSON
3. `v1_ruleset_sha256` — SHA-256 of `v1_rules.py` (pinned constant)
4. `reference_data_fingerprint` — SHA-256 of the reference data bundle
5. `config_fingerprint` — SHA-256 of the canonical configuration JSON
6. `software_identity` — map of module-label → SHA-256 for 5 production modules

Fail-closed: missing grant, missing observed scope, or any divergence →
`AUTHORIZATION_REJECTED`. The engine is never invoked.

### Negative tests (10 scenarios)

`tests/safety/test_authorization_negative.py` covers:
- Correct scope authorizes (baseline)
- Tampered input SHA-256 rejected
- Tampered schema fingerprint rejected
- Tampered V1 ruleset SHA rejected
- Tampered reference data fingerprint rejected
- Tampered config fingerprint rejected
- Tampered software identity rejected
- Wrong execution mode rejected
- Missing grant (None) rejected
- Engine never runs on rejected scope (output file does not exist)

## 3. PII protection

PII protection is a FIRST-CLASS security requirement. Two capabilities:

### PII masking at write time

`PIIMasker.mask_row(row)` masks PII fields before they are written to
`lineage.json`. The engine calls `mask_row` on every flagged row before
passing it to `LineageRecorder.record_row_flag()`. Masked fields:
- `email_address` → `j***@example.com`
- `phone_number` → `***-***-1234`
- `address` → `123 Main...`
- `first_name`, `last_name` → `J***`, `S***`

Non-PII fields (id, city, state, zip, etc.) are preserved verbatim.
The original row is NOT mutated.

**What is NOT masked**: the output CSV (`--output`) contains raw source
columns per the V1 33→41 contract. This is by design — the output IS
the validated data. PII in the output is the customer's responsibility.

### Prohibited-content scanner

`scan_for_prohibited_content(evidence_dir)` scans evidence files for:
- **PII**: email addresses (non-synthetic domains), phone numbers, credit-card-like numbers (with separators)
- **Secrets**: PEM private keys, AWS AKIA access keys, GitHub `gh[p]_` tokens, password/secret/token credential assignments

The scanner is a heuristic, not a complete DLP solution. Documented
limitations (`SCAN_LIMITATIONS`):
- Detects common patterns, not obfuscated PII
- Does not scan binary files or archives
- A clean scan does NOT guarantee evidence is PII-free

Used by release gate gate 14 (`pii_evidence_scan`).

## 4. Evidence integrity (tamper detection + consistency validation)

Two distinct layers:

### Tamper detection (`evidence_root.py`)

`write_evidence_root()` computes a SHA-256 root hash over all artifact
hashes (manifest, output, lineage, audit, monitoring, alerts). Any
modification to any artifact invalidates the root. Verified by
`verify_evidence_root()` and release gate gate 13.

### Externally anchored evidence verification (F-003 hardening)

`verify_evidence_root_with_external_anchor(evidence_dir, expected_root,
output_csv=None)` is the protected-mode variant. It treats the evidence
directory as attacker-controlled and requires the caller to supply a
64-char hex `expected_root` from an out-of-band source (operator
clipboard, separate trust channel, prior committed run record, etc.).

Fail-closed behavior:
- `expected_root` missing / not a 64-char hex string → fail closed
  (the protected mode REQUIRES the anchor)
- Recomputed root ≠ `expected_root` → fail
- Recorded root (inside the evidence dir) ≠ `expected_root` → fail
- Any tamper-detection signal from `verify_evidence_root` → fail

**Distinction:**

- **TAMPER-EVIDENT** (`verify_evidence_root`): detects modification of
  any covered artifact within the evidence directory by comparing the
  recomputed root hash against the root hash recorded inside the
  directory itself. An attacker with write access to the entire
  evidence directory can forge a self-consistent evidence set.
- **EXTERNALLY ANCHORED** (`verify_evidence_root_with_external_anchor`):
  compares the recomputed root hash against an anchor supplied from
  OUTSIDE the writable evidence directory. An attacker who controls
  only the evidence directory cannot forge evidence that matches the
  external anchor.

The external-anchor mode is OPT-IN. Existing callers that do not supply
an `expected_root` continue to use the tamper-evident mode unchanged.

Test coverage: `tests/unit/test_external_evidence_root.py` (13 tests,
covering all 7 verification points required by the hardening spec).

### Semantic consistency validation (`evidence_consistency.py`)

`validate_evidence_dir()` performs 9 cross-artifact consistency checks:

1. Required artifacts exist (manifest, lineage, audit)
2. JSON parseable
3. Manifest schema (12 required fields, manifest_type, hash formats, flag counts, row counts, reconciliation, safety_invariants)
4. Run ID consistency (manifest = lineage = audit)
5. Row count agreement (manifest = audit = lineage)
6. Flag count agreement (manifest = audit; total ≤ rows × rules)
7. Verdict agreement (no success+failure contradiction)
8. Lineage serialization (no repr leaks, valid structure, known rule IDs)
9. Referenced artifacts (generated_files exist, hashes match, output has 41 columns)

Fail-closed: ANY issue → `valid: False`. The engine calls
`validate_evidence_dir()` after writing evidence; if inconsistent, the
run is recorded as failed.

## 5. What was removed (no GPG, no Git, no keys)

- **GPG trust anchor** — `TRUSTED_SIGNING_KEY_FINGERPRINT`, `.sig` files, public signing key. All removed.
- **Commit signature verification** — old gates 2 and 3. Removed.
- **Dormant RBAC** — `RBACManager`/`AuthContext`/`Permission` were instantiated by the engine but never called. Removed. Authorization is now Layer B (different model, actually enforced).
- **Git runtime deps** — `git status`, `git rev-parse HEAD`, commit signature. All removed.

## 6. Residual risks

- **Operator bypasses authorization**: if an operator calls `ValidationEngine.validate()` directly via `python -c`, authorization is not enforced. Mitigation: CLI and Airflow both use `run_validation()`; release gate verifies no direct engine import from production entry points.
- **Grant file leakage**: the grant is a JSON file; anyone with read access can validate. Mitigation: filesystem ACLs (operator responsibility).
- **Scanner limitations**: the PII/secret scanner is heuristic; sophisticated obfuscated PII may evade detection. Documented in `SCAN_LIMITATIONS`.
- **Evidence forgery (F-003)**: evidence hashes are stored inside the same writable evidence directory. Under the operator-controlled-evidence-directory threat model, an attacker with write access to the entire evidence directory can forge a self-consistent evidence set that passes the TAMPER-EVIDENT verification. The EXTERNALLY ANCHORED verification (`verify_evidence_root_with_external_anchor`) closes this gap when the operator supplies a 64-char hex `expected_root` from an out-of-band trust source; this is the protected mode and is OPT-IN.
- **CSV formula injection**: the raw validation output CSV preserves source values verbatim per the frozen V1 contract. It is intended for machine-to-machine consumption. It should not be opened directly in spreadsheet software when the input may contain attacker-controlled formula-like values (e.g., `=`, `+`, `-`, `@` prefixes); an approved safe-export/sanitization process should be used for spreadsheet consumption.
- **Wall-time and RSS not enforced**: `max_wall_seconds` and `max_peak_rss_bytes` are declared in `ResourceLimits` but are NOT enforced at the application level. The `ExecutionMonitor` class exists but is not connected to the in-process execution path. Input-size, row-count, and output-size limits ARE enforced (pre/post-execution). Deployment-level OS/container resource controls (ulimit, cgroups, container limits) are required for wall-time and memory containment.

## 7. Concurrent-run collision prevention

`run_validation()` atomically claims `evidence_dir` via
`os.makedirs(evidence_dir, exist_ok=False)`. Two simultaneous runs that
share the same `evidence_dir` cannot both succeed: the first claim wins;
the second fails closed at `stopped_at=evidence-dir-collision`.

Properties:
- First run succeeds (creates the directory atomically).
- Second simultaneous run cannot silently reuse the same directory.
- No last-writer-wins behavior (the first run's artifacts are preserved).
- No evidence mixing (the second run writes nothing to the shared dir).
- Existing single-run behavior is unchanged: a fresh evidence_dir is
  claimed exactly as before.

Callers that legitimately re-use a fixed evidence_dir path (e.g. the
release gate's `evidence/release_gate/replay_1`) MUST clean it up
before invoking `run_validation()`. The release gate does this via the
`_reset_evidence_dir(path)` helper.

Test coverage: `tests/safety/test_concurrent_run_collision.py` (6 tests).

## 8. Dependency reproducibility

Production dependencies are pinned in `pyproject.toml`:

| Package | Pin | Purpose |
|---------|-----|---------|
| `pyyaml` | `>=6.0.3,<7.0` | `configs/quality.yaml` parsing |
| `setuptools` | `>=68.0,<76.0` | build backend |

Dev dependencies are pinned in `pyproject.toml` `[project.optional-dependencies.dev]`:

| Package | Pin |
|---------|-----|
| `pytest` | `>=7.0,<10.0` |
| `pytest-cov` | `>=4.0,<8.0` |

`requires-python = ">=3.9,<3.13"` — verified on Python 3.12.14.

For exact-reproducibility installs, use the pinned files:

```bash
pip install -r requirements.txt          # production only
pip install -r requirements-dev.txt     # production + dev
```

The `requirements*.txt` files pin exact versions (`==`) of the verified
production toolchain; `pyproject.toml` uses compatible-release (`~=`
semantics: lower-bound with major-version upper-bound) so patch and
minor updates within the verified major line are allowed.

**Compatibility note:** `pyproject.toml` `version` is `3.1.0` (PEP 440
strict). The internal informational label `3.1.0-hardened` is used in
`LAYER_BUNDLE_VERSION`, `HARDENING_LAYER_VERSION`, and `GATE_VERSION`
constants; this label is NOT a PEP 440 version and is not exposed to
packaging tooling — it is a release-line identifier only.
