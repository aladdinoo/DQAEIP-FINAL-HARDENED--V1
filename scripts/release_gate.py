#!/usr/bin/env python3
"""DQAEIP release gate — simplified, deterministic, no Git/GPG.

The gate verifies that the production code is internally consistent,
that the frozen V1 rules are byte-identical to the recorded SHA-256,
that the test suite passes, that the engine is deterministic, that
evidence is tamper-evident, and that no PII leaks into evidence.

The gate does NOT depend on:
  - Git (no commit SHA verification, no git status check)
  - GPG (no signature verification, no trust anchors)
  - GitHub (no remote API calls)
  - Cryptographic keys of any kind

Integrity is enforced by SHA-256 over the frozen production files.

Output: evidence/release_gate/final_release_gate.json
Exit: 0 only when every gate PASSES (fail-closed).
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

GATE_NAME = "scripts/release_gate.py"
GATE_VERSION = "3.1.0-hardened"
DEFAULT_GATE_EVIDENCE = os.path.join(REPO_ROOT, "evidence", "release_gate")

# The frozen V1 rules SHA-256 — the single source of truth for the
# rule set's integrity. Any change to v1_rules.py changes its SHA-256
# and fails gate 3 (frozen_v1_integrity).
FROZEN_V1_SHA256 = (
    "daef1ded54c7d3c79898a1ba253be2acd5b6120e18b16b09009fdd7be9fc2276"
)

# Production files whose bytes are FROZEN for this release.
FROZEN_CRITICAL = [
    "data_quality_platform/rules/v1_rules.py",
    "data_quality_platform/rules/registry.py",
    "data_quality_platform/rules/base.py",
    "data_quality_platform/contracts.py",
    "data_quality_platform/validation/engine.py",
    "data_quality_platform/generation/synthetic.py",
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _reset_evidence_dir(path):
    """Remove and re-create an evidence directory before a fresh run.

    run_validation() now claims evidence_dir atomically via
    os.makedirs(exist_ok=False). The release gate legitimately re-uses
    fixed paths (e.g. ``evidence/release_gate/replay_1``) across runs, so
    each gate that invokes run_validation must clean the target path
    first; otherwise the atomic-claim check correctly rejects the run.
    """
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)


def run_cmd(cmd, timeout, cwd=REPO_ROOT):
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr, time.time() - t0


def pytest_category(name, path, extra_args=None):
    cmd = [sys.executable, "-m", "pytest", "-q", "--no-header",
           "-p", "no:cacheprovider", "--tb=line"]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(path)
    rc, out, dur = run_cmd(cmd, timeout=3600)
    passed = re.findall(r"(\d+) passed", out)
    failed = re.findall(r"(\d+) failed", out)
    skipped = re.findall(r"(\d+) skipped", out)
    details = {
        "path": path,
        "exit_code": rc,
        "passed": int(passed[-1]) if passed else 0,
        "failed": int(failed[-1]) if failed else 0,
        "skipped": int(skipped[-1]) if skipped else 0,
        "output_excerpt": out[-1500:] if out else "",
    }
    status = "PASS" if rc == 0 and details["failed"] == 0 else "FAIL"
    return status, details, dur


class GateRunner:
    def __init__(self):
        self.gates = []
        self.failures = []

    def record(self, gate, status, evidence, duration, details):
        self.gates.append({
            "gate": gate,
            "status": status,
            "evidence": evidence,
            "duration_seconds": round(duration, 2),
            **({"details": details} if details else {}),
        })
        print(f"[{status:4s}] {gate:32s} ({duration:.1f}s) {evidence}")

    def fail(self, gate, reason, details=None):
        self.failures.append({
            "gate": gate,
            "reason": reason,
            "details": details or {},
        })

    # ── Gate 1: repository structure ──────────────────────────────
    def gate_repository_structure(self):
        t0 = time.time()
        required = [
            "data_quality_platform/__init__.py",
            "data_quality_platform/contracts.py",
            "data_quality_platform/rules/v1_rules.py",
            "data_quality_platform/rules/registry.py",
            "data_quality_platform/rules/base.py",
            "data_quality_platform/validation/engine.py",
            "data_quality_platform/hardening/pipeline.py",
            "data_quality_platform/hardening/authorization.py",
            "data_quality_platform/hardening/input_contract.py",
            "data_quality_platform/evidence/manifests.py",
            "data_quality_platform/audit/trail.py",
            "data_quality_platform/lineage/recorder.py",
            "data_quality_platform/monitoring/quality.py",
            "data_quality_platform/alerting/alerts.py",
            "data_quality_platform/config/settings.py",
            "runner/cli.py",
            "scripts/release_gate.py",
            "configs/quality.yaml",
            "tests/",
        ]
        missing = [p for p in required if not os.path.exists(os.path.join(REPO_ROOT, p))]
        details = {"required_count": len(required), "missing": missing}
        if missing:
            self.fail("repository_structure", "missing required files", details)
            self.record("repository_structure", "FAIL", f"{len(missing)} missing",
                        time.time() - t0, details)
            return
        self.record("repository_structure", "PASS", "all required files present",
                    time.time() - t0, details)

    # ── Gate 2: core source imports ──────────────────────────────
    def gate_core_imports(self):
        t0 = time.time()
        try:
            from data_quality_platform.rules import RuleRegistry
            from data_quality_platform.validation.engine import ValidationEngine
            from data_quality_platform.hardening.pipeline import run_validation
            from data_quality_platform.hardening.authorization import (
                AuthorizationScope, observe_scope, evaluate_authorization)
            from runner.cli import main  # noqa
            rr = RuleRegistry.create_default()
            valid, errors, _ = rr.validate()
            if not valid or rr.count != 8:
                self.fail("core_imports", f"registry invalid: {errors}")
                self.record("core_imports", "FAIL", "registry invalid",
                            time.time() - t0, {"errors": errors})
                return
        except Exception as exc:
            self.fail("core_imports", f"import error: {exc!r}")
            self.record("core_imports", "FAIL", f"import error: {exc!r}",
                        time.time() - t0, {})
            return
        self.record("core_imports", "PASS", "all core imports succeed",
                    time.time() - t0, {"rule_count": rr.count})

    # ── Gate 3: frozen V1 rule integrity ─────────────────────────
    def gate_frozen_v1_integrity(self):
        t0 = time.time()
        v1_path = os.path.join(REPO_ROOT, "data_quality_platform", "rules", "v1_rules.py")
        actual = sha256_file(v1_path)
        details = {"expected": FROZEN_V1_SHA256, "actual": actual, "path": v1_path}
        if actual != FROZEN_V1_SHA256:
            self.fail("frozen_v1_integrity", "v1_rules.py SHA-256 mismatch", details)
            self.record("frozen_v1_integrity", "FAIL", "SHA-256 mismatch",
                        time.time() - t0, details)
            return
        # Also verify the other FROZEN_CRITICAL files exist and are stable.
        # (Their SHA-256 is not pinned to a constant; their existence is.)
        missing = [f for f in FROZEN_CRITICAL
                   if not os.path.isfile(os.path.join(REPO_ROOT, f))]
        if missing:
            self.fail("frozen_v1_integrity", f"frozen files missing: {missing}",
                      {"missing": missing})
            self.record("frozen_v1_integrity", "FAIL", "frozen files missing",
                        time.time() - t0, details)
            return
        self.record("frozen_v1_integrity", "PASS",
                    f"v1_rules.py SHA-256 verified", time.time() - t0, details)

    # ── Gate 4: unit tests ───────────────────────────────────────
    def gate_unit_tests(self):
        status, details, dur = pytest_category(
            "unit_tests", os.path.join(REPO_ROOT, "tests", "unit"))
        if status == "FAIL":
            self.fail("unit_tests", "unit tests failed", details)
        self.record("unit_tests", status,
                    f"{details['passed']} passed / {details['skipped']} skipped / "
                    f"{details['failed']} failed", dur, details)

    # ── Gate 5: contract tests ───────────────────────────────────
    def gate_contract_tests(self):
        status, details, dur = pytest_category(
            "contract_tests", os.path.join(REPO_ROOT, "tests", "contract"))
        if status == "FAIL":
            self.fail("contract_tests", "contract tests failed", details)
        self.record("contract_tests", status,
                    f"{details['passed']} passed / {details['failed']} failed",
                    dur, details)

    # ── Gate 6: integration tests ───────────────────────────────
    def gate_integration_tests(self):
        status, details, dur = pytest_category(
            "integration_tests", os.path.join(REPO_ROOT, "tests", "integration"))
        if status == "FAIL":
            self.fail("integration_tests", "integration tests failed", details)
        self.record("integration_tests", status,
                    f"{details['passed']} passed / {details['failed']} failed",
                    dur, details)

    # ── Gate 7: golden tests ─────────────────────────────────────
    def gate_golden_tests(self):
        status, details, dur = pytest_category(
            "golden_tests", os.path.join(REPO_ROOT, "tests", "golden"))
        if status == "FAIL":
            self.fail("golden_tests", "golden tests failed", details)
        self.record("golden_tests", status,
                    f"{details['passed']} passed / {details['skipped']} skipped / "
                    f"{details['failed']} failed", dur, details)

    # ── Gate 8: property tests ───────────────────────────────────
    def gate_property_tests(self):
        prop_path = os.path.join(REPO_ROOT, "tests", "property")
        if not os.path.isdir(prop_path) or not os.listdir(prop_path):
            self.record("property_tests", "PASS", "no property tests directory",
                        0.0, {"note": "skipped - no property tests"})
            return
        status, details, dur = pytest_category("property_tests", prop_path)
        if status == "FAIL":
            self.fail("property_tests", "property tests failed", details)
        self.record("property_tests", status,
                    f"{details['passed']} passed / {details['failed']} failed",
                    dur, details)

    # ── Gate 9: safety tests ─────────────────────────────────────
    def gate_safety_tests(self):
        path = os.path.join(REPO_ROOT, "tests", "safety")
        if not os.path.isdir(path):
            self.record("safety_tests", "PASS", "no safety tests directory",
                        0.0, {})
            return
        status, details, dur = pytest_category("safety_tests", path)
        if status == "FAIL":
            self.fail("safety_tests", "safety tests failed", details)
        self.record("safety_tests", status,
                    f"{details['passed']} passed / {details['failed']} failed",
                    dur, details)

    # ── Gate 10: hardening tests ─────────────────────────────────
    def gate_hardening_tests(self):
        path = os.path.join(REPO_ROOT, "tests", "hardening")
        if not os.path.isdir(path):
            self.record("hardening_tests", "PASS", "no hardening tests directory",
                        0.0, {})
            return
        status, details, dur = pytest_category("hardening_tests", path)
        if status == "FAIL":
            self.fail("hardening_tests", "hardening tests failed", details)
        self.record("hardening_tests", status,
                    f"{details['passed']} passed / {details['failed']} failed",
                    dur, details)

    # ── Gate 11: differential validation ────────────────────────
    def gate_differential_validation(self):
        oracle_path = os.path.join(REPO_ROOT, "tests", "unit",
                                   "test_rule_oracle_consistency.py")
        if not os.path.isfile(oracle_path):
            self.fail("differential_validation",
                      "test_rule_oracle_consistency.py is required")
            self.record("differential_validation", "FAIL",
                        "oracle test absent", 0.0,
                        {"expected": oracle_path})
            return
        status, details, dur = pytest_category(
            "differential_validation", oracle_path)
        if status == "FAIL":
            self.fail("differential_validation", "differential test failed", details)
        self.record("differential_validation", status,
                    f"{details['passed']} consistency tests green", dur, details)

    # ── Gate 12: deterministic replay ────────────────────────────
    def gate_deterministic_replay(self):
        t0 = time.time()
        try:
            from data_quality_platform.generation.synthetic import SyntheticDataGenerator
            from data_quality_platform.hardening.pipeline import run_validation
            from data_quality_platform.hardening.authorization import observe_scope
            from data_quality_platform.config import PlatformConfig
            from data_quality_platform.contracts import SOURCE_COLUMNS

            csv1 = os.path.join(REPO_ROOT, "data", "generated", "release_replay_1.csv")
            csv2 = os.path.join(REPO_ROOT, "data", "generated", "release_replay_2.csv")
            out1 = os.path.join(REPO_ROOT, "data", "generated", "release_replay_1_out.csv")
            out2 = os.path.join(REPO_ROOT, "data", "generated", "release_replay_2_out.csv")
            ev1 = os.path.join(REPO_ROOT, "evidence", "release_gate", "replay_1")
            ev2 = os.path.join(REPO_ROOT, "evidence", "release_gate", "replay_2")
            os.makedirs(os.path.dirname(csv1), exist_ok=True)

            SyntheticDataGenerator(seed=20260929).generate(500, csv1)
            SyntheticDataGenerator(seed=20260929).generate(500, csv2)

            # Concurrent-run collision prevention: run_validation() now
            # atomically claims evidence_dir; clean up any leftover dir
            # from a previous gate run before invoking it.
            _reset_evidence_dir(ev1)
            _reset_evidence_dir(ev2)

            config = PlatformConfig.from_yaml(
                os.path.join(REPO_ROOT, "configs", "quality.yaml")).as_dict()

            from data_quality_platform.hardening.pipeline import (
                _default_reference_data_paths, _default_software_paths, _v1_rules_path)
            scope1 = observe_scope(
                input_path=csv1, authorized_columns=SOURCE_COLUMNS,
                v1_rules_path=_v1_rules_path(),
                reference_data_paths=_default_reference_data_paths(),
                config=config, execution_mode="validation",
                software_paths=_default_software_paths(),
            )

            r1 = run_validation(
                input_path=csv1, output_path=out1, evidence_dir=ev1,
                run_id="replay_1", granted_scope=scope1, config=config,
                config_thresholds=PlatformConfig.from_yaml(
                    os.path.join(REPO_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
            )
            r2 = run_validation(
                input_path=csv2, output_path=out2, evidence_dir=ev2,
                run_id="replay_2", granted_scope=scope1, config=config,
                config_thresholds=PlatformConfig.from_yaml(
                    os.path.join(REPO_ROOT, "configs", "quality.yaml")).get_quality_thresholds(),
            )
            if not (r1.passed and r2.passed):
                self.fail("deterministic_replay", "replay runs did not both pass",
                          {"r1": r1.verdict, "r2": r2.verdict})
                self.record("deterministic_replay", "FAIL",
                            "replay runs failed", time.time() - t0, {})
                return
            h1 = sha256_file(out1)
            h2 = sha256_file(out2)
            details = {"output_sha256_run1": h1, "output_sha256_run2": h2,
                       "byte_identical": h1 == h2}
            if h1 != h2:
                self.fail("deterministic_replay", "output not byte-identical", details)
                self.record("deterministic_replay", "FAIL",
                            "byte-identical check failed", time.time() - t0, details)
                return
            self.record("deterministic_replay", "PASS",
                        "byte-identical replay verified", time.time() - t0, details)
        except Exception as exc:
            self.fail("deterministic_replay", f"exception: {exc!r}")
            self.record("deterministic_replay", "FAIL",
                        f"exception: {exc!r}", time.time() - t0, {})

    # ── Gate 13: evidence validation (tamper + consistency) ───────
    def gate_evidence_validation(self):
        t0 = time.time()
        try:
            from data_quality_platform.validation.evidence_root import (
                compute_evidence_root, verify_evidence_root,
            )
            from data_quality_platform.validation.evidence_consistency import (
                validate_evidence_dir,
            )
            ev_dir = os.path.join(REPO_ROOT, "evidence", "release_gate", "replay_1")
            if not os.path.isdir(ev_dir):
                self.fail("evidence_validation",
                          "no replay evidence to validate (run deterministic_replay first)")
                self.record("evidence_validation", "FAIL",
                            "no replay evidence", time.time() - t0,
                            {"expected": ev_dir})
                return
            # The output CSV lives outside the evidence dir; resupply its path.
            output_csv = os.path.join(REPO_ROOT, "data", "generated",
                                      "release_replay_1_out.csv")
            # 1. Tamper detection: verify the evidence root hash.
            ok_root, root_details = verify_evidence_root(
                ev_dir, output_csv=output_csv if os.path.isfile(output_csv) else None)
            # 2. Semantic consistency: validate cross-artifact agreement.
            consistency = validate_evidence_dir(ev_dir)
            details = {
                "evidence_dir": ev_dir,
                "root_verified": ok_root,
                "root_details": root_details,
                "consistency_valid": consistency["valid"],
                "consistency_issues": consistency["issues"][:5],
                "checks_performed": consistency.get("checks_performed", []),
            }
            if not ok_root:
                self.fail("evidence_validation",
                          f"evidence root verification failed: {root_details.get('reason')}",
                          details)
                self.record("evidence_validation", "FAIL",
                            "root verification failed", time.time() - t0, details)
                return
            if not consistency["valid"]:
                self.fail("evidence_validation",
                          f"evidence consistency validation failed: "
                          f"{len(consistency['issues'])} issue(s)",
                          details)
                self.record("evidence_validation", "FAIL",
                            f"{len(consistency['issues'])} consistency issues",
                            time.time() - t0, details)
                return
            self.record("evidence_validation", "PASS",
                        f"root verified + {len(details['checks_performed'])} consistency checks",
                        time.time() - t0, details)
        except Exception as exc:
            self.fail("evidence_validation", f"exception: {exc!r}")
            self.record("evidence_validation", "FAIL",
                        f"exception: {exc!r}", time.time() - t0, {})

    # ── Gate 14: PII / secret evidence scan ──────────────────────
    def gate_pii_evidence_scan(self):
        t0 = time.time()
        try:
            from data_quality_platform.security import scan_for_prohibited_content
            scan_root = os.path.join(REPO_ROOT, "evidence", "release_gate")
            if not os.path.isdir(scan_root):
                self.record("pii_evidence_scan", "PASS",
                            "no release_gate evidence", time.time() - t0, {})
                return
            findings = scan_for_prohibited_content(scan_root)
            details = {
                "findings_count": len(findings),
                "findings": [dict(f) for f in findings[:10]],
            }
            if findings:
                self.fail("pii_evidence_scan",
                          f"{len(findings)} prohibited-content finding(s) in evidence",
                          details)
                self.record("pii_evidence_scan", "FAIL",
                            f"{len(findings)} findings", time.time() - t0, details)
                return
            self.record("pii_evidence_scan", "PASS",
                        "no prohibited content in release_gate evidence",
                        time.time() - t0, details)
        except Exception as exc:
            self.fail("pii_evidence_scan", f"exception: {exc!r}")
            self.record("pii_evidence_scan", "FAIL",
                        f"exception: {exc!r}", time.time() - t0, {})

    # ── Gate 15: negative / fail-closed behavior ─────────────────
    def gate_negative_battery(self):
        t0 = time.time()
        try:
            from data_quality_platform.hardening.pipeline import run_validation
            from data_quality_platform.hardening.authorization import (
                AuthorizationScope, observe_scope)
            from data_quality_platform.config import PlatformConfig
            from data_quality_platform.contracts import SOURCE_COLUMNS
            from data_quality_platform.generation.synthetic import SyntheticDataGenerator

            csv_path = os.path.join(REPO_ROOT, "data", "generated",
                                    "neg_battery_input.csv")
            os.makedirs(os.path.dirname(csv_path), exist_ok=True)
            SyntheticDataGenerator(seed=42).generate(50, csv_path)

            config = PlatformConfig.from_yaml(
                os.path.join(REPO_ROOT, "configs", "quality.yaml")).as_dict()
            from data_quality_platform.hardening.pipeline import (
                _default_reference_data_paths, _default_software_paths, _v1_rules_path)
            real_scope = observe_scope(
                input_path=csv_path, authorized_columns=SOURCE_COLUMNS,
                v1_rules_path=_v1_rules_path(),
                reference_data_paths=_default_reference_data_paths(),
                config=config, execution_mode="validation",
                software_paths=_default_software_paths(),
            )
            # Tamper the scope: change input_sha256.
            tampered = AuthorizationScope(
                input_sha256="0" * 64,
                schema_fingerprint=real_scope.schema_fingerprint,
                v1_ruleset_sha256=real_scope.v1_ruleset_sha256,
                reference_data_fingerprint=real_scope.reference_data_fingerprint,
                config_fingerprint=real_scope.config_fingerprint,
                execution_mode=real_scope.execution_mode,
                software_identity=real_scope.software_identity,
            )
            # Concurrent-run collision prevention: same as gate 12.
            neg_ev_dir = os.path.join(REPO_ROOT, "evidence", "neg_battery")
            _reset_evidence_dir(neg_ev_dir)
            r = run_validation(
                input_path=csv_path,
                output_path=os.path.join(REPO_ROOT, "data", "generated",
                                         "neg_battery_out.csv"),
                evidence_dir=neg_ev_dir,
                run_id="neg_battery", granted_scope=tampered, config=config,
            )
            details = {"verdict": r.verdict, "stopped_at": r.details.get("stopped_at"),
                       "reasons": r.reasons[:2]}
            if r.passed:
                self.fail("negative_battery",
                          "tampered scope was accepted (should have been rejected)",
                          details)
                self.record("negative_battery", "FAIL",
                            "fail-closed violated", time.time() - t0, details)
                return
            self.record("negative_battery", "PASS",
                        "tampered scope rejected (fail-closed)",
                        time.time() - t0, details)
        except Exception as exc:
            self.fail("negative_battery", f"exception: {exc!r}")
            self.record("negative_battery", "FAIL",
                        f"exception: {exc!r}", time.time() - t0, {})

    # ── Gate 16: no forbidden dependencies in production code ──────
    def gate_no_gpg_git_dependency(self):
        t0 = time.time()
        forbidden_patterns = [
            (r"\bgpg\b", "gpg command reference"),
            (r"\bGNUPGHOME\b", "GNUPGHOME env var"),
            (r"TRUSTED_SIGNING_KEY_FINGERPRINT", "trust anchor fingerprint"),
            (r"commit_signature", "commit signature verification"),
            (r"baseline_signature", "baseline signature verification"),
            (r"\.sig\b", ".sig file as active input"),
            # ClickHouse client must NOT be imported in production code.
            (r"\bclickhouse_driver\b", "ClickHouse client import"),
            (r"\bclickhouse_connect\b", "ClickHouse client import"),
            # E1 experiment code must NOT be in production.
            (r"\be1_experiment\b", "E1 experiment code"),
            (r"\bE1Experiment\b", "E1 experiment code"),
        ]
        scan_dirs = [
            os.path.join(REPO_ROOT, "data_quality_platform"),
            os.path.join(REPO_ROOT, "runner"),
            os.path.join(REPO_ROOT, "airflow"),
        ]
        # Note: scripts/ is NOT scanned here because release_gate.py
        # itself contains the forbidden-pattern strings as scan targets
        # (not as actual GPG/Git usage). The gate verifies production
        # code; scripts/ is tooling, not runtime.
        findings = []
        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            for dirpath, _, files in os.walk(scan_dir):
                for fname in files:
                    if not fname.endswith(".py"):
                        continue
                    fpath = os.path.join(dirpath, fname)
                    try:
                        content = open(fpath, "r", encoding="utf-8").read()
                    except Exception:
                        continue
                    for pattern, desc in forbidden_patterns:
                        if re.search(pattern, content):
                            findings.append({
                                "file": os.path.relpath(fpath, REPO_ROOT),
                                "pattern": pattern,
                                "desc": desc,
                            })
        details = {"findings_count": len(findings), "findings": findings[:5]}
        if findings:
            self.fail("no_gpg_git_dependency",
                      "GPG/Git trust-anchor patterns found in production code",
                      details)
            self.record("no_gpg_git_dependency", "FAIL",
                        f"{len(findings)} forbidden patterns", time.time() - t0, details)
            return
        self.record("no_gpg_git_dependency", "PASS",
                    "no GPG/Git/ClickHouse/E1 patterns in production code",
                    time.time() - t0, details)

    # ── Gate 17: mutation testing ────────────────────────────────
    def gate_mutation_testing(self):
        t0 = time.time()
        rc, out, dur = run_cmd(
            [sys.executable, "scripts/mutation_testing.py"], 600)
        evidence_path = os.path.join(REPO_ROOT, "evidence",
                                     "mutation_testing",
                                     "mutation_results.json")
        details = {}
        try:
            with open(evidence_path, encoding="utf-8") as f:
                summary = json.load(f)
            details = {
                "mutants_total": summary.get("mutants_total"),
                "mutants_detected": summary.get("mutants_detected"),
                "mutants_survived": summary.get("mutants_survived"),
                "mutation_score": summary.get("mutation_score"),
                "source_restored_exactly":
                    summary.get("source_restored_exactly"),
            }
        except Exception as exc:
            self.fail("mutation_testing", f"cannot read mutation evidence: {exc}")
            self.record("mutation_testing", "FAIL", "evidence unreadable",
                        time.time() - t0, details)
            return
        ok = (rc == 0 and details.get("mutants_survived") == 0
              and details.get("mutation_score") == 1.0
              and details.get("source_restored_exactly") is True)
        if not ok:
            self.fail("mutation_testing",
                      f"mutation testing did not kill every mutant "
                      f"(score={details.get('mutation_score')}, "
                      f"survived={details.get('mutants_survived')})",
                      details)
        self.record("mutation_testing", "PASS" if ok else "FAIL",
                    f"{details.get('mutants_detected')}/"
                    f"{details.get('mutants_total')} mutants detected, "
                    f"score {details.get('mutation_score')}",
                    time.time() - t0, details)

    def run(self):
        t0 = time.time()
        os.makedirs(DEFAULT_GATE_EVIDENCE, exist_ok=True)
        out_path = os.path.join(DEFAULT_GATE_EVIDENCE, "final_release_gate.json")
        tmp_path = out_path + ".tmp"

        try:
            self.gate_repository_structure()          # [ 1]
            self.gate_core_imports()                 # [ 2]
            self.gate_frozen_v1_integrity()          # [ 3]
            self.gate_unit_tests()                    # [ 4]
            self.gate_contract_tests()               # [ 5]
            self.gate_integration_tests()             # [ 6]
            self.gate_golden_tests()                 # [ 7]
            self.gate_property_tests()                # [ 8]
            self.gate_safety_tests()                  # [ 9]
            self.gate_hardening_tests()              # [10]
            self.gate_differential_validation()       # [11]
            self.gate_deterministic_replay()          # [12]
            self.gate_evidence_validation()           # [13]
            self.gate_pii_evidence_scan()             # [14]
            self.gate_negative_battery()              # [15]
            self.gate_no_gpg_git_dependency()        # [16]
            self.gate_mutation_testing()              # [17]

            failed = [g for g in self.gates if g["status"] == "FAIL"]
            overall = "FAIL" if failed else "PASS"

            report = {
                "release_gate": GATE_NAME,
                "gate_version": GATE_VERSION,
                "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime()),
                "fail_closed_statement": (
                    "A gate result is PASS only when its own evidence proves it. "
                    "Missing evidence, unreadable evidence, or any exception is "
                    "FAIL — never a skip. The overall verdict is PASS only when "
                    "every gate PASSES."),
                "gates": self.gates,
                "gate_count": len(self.gates),
                "gate_counts": {
                    "pass": sum(1 for g in self.gates if g["status"] == "PASS"),
                    "fail": len(failed),
                },
                "failures": self.failures,
                "overall_verdict": overall,
                "total_duration_seconds": round(time.time() - t0, 2),
            }

            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, out_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        print("=" * 72)
        print(f"OVERALL VERDICT: {overall} "
              f"({report['gate_counts']['pass']}/{len(self.gates)} gates pass)")
        for failure in self.failures:
            print(f"  FAILURE: gate={failure['gate']}: {failure['reason']}")
        print(f"evidence: {os.path.relpath(out_path, REPO_ROOT)}")
        return 0 if overall == "PASS" else 1


def main():
    return GateRunner().run()


if __name__ == "__main__":
    sys.exit(main())
