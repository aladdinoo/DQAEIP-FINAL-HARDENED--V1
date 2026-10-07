#!/usr/bin/env python3
"""SAFE MUTATION TESTING LAYER (DQAVP hardening, Section 6).

Proves that the existing test suite can detect broken V1 rules by
introducing CONTROLLED TEMPORARY MUTATIONS into the production rule
source, running the relevant test suite, and restoring the original
bytes immediately and verifiably.

Safety rails (all fail-closed):
- The original source bytes are captured before any mutation and
  restored in a ``finally`` block after EVERY mutant.
- Restoration is verified by SHA-256 against the pre-run hash; any
  mismatch aborts the whole run with a nonzero exit code.
- A final integrity check re-verifies the production file hash at the
  end of the run and refuses to declare success otherwise.
- Mutant application is exact-count guarded: every textual replacement
  must occur EXACTLY ONCE in the source, otherwise the mutant is an
  infrastructure error (never a silent no-op).

Detection contract:
- A mutant is DETECTED when the relevant test suite FAILS while the
  mutant is active (at least one failing test).
- A mutant that SURVIVES (suite green with the mutant active) is a
  TESTING GAP and is recorded as such — never hidden.

Evidence: evidence/mutation_testing/mutation_results.json

Usage:
    python scripts/mutation_testing.py [--quick]
"""

import hashlib
import json
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_PATH = os.path.join(REPO_ROOT, "data_quality_platform/rules/v1_rules.py")
EVIDENCE_DIR = os.path.join(REPO_ROOT, "evidence", "mutation_testing")

# The relevant test suite for V1 rule semantics.
TEST_TARGETS = [
    "tests/golden/test_golden_cases.py",
    "tests/golden/test_golden_fixture_integrity.py",
    "tests/unit/test_rules.py",
    "tests/unit/test_rule_oracle_consistency.py",
    "tests/integration/test_engine.py",
]

# Each mutation: (mutation_id, rule_id, description, technique, old, new)
# `old` must occur EXACTLY ONCE in v1_rules.py (verified at runtime).
MUTATIONS = [
    ("M01", "first_name_cleaning_candidate",
     "inverted final boolean result (suspicious names pass)",
     "inverted_boolean",
     "        if _has_non_alpha(first):\n            return 1\n        if _is_repeated_char(first):\n            return 1\n        return 0",
     "        if _has_non_alpha(first):\n            return 1\n        if _is_repeated_char(first):\n            return 1\n        return 1"),
    ("M02", "first_name_cleaning_candidate",
     "removed repeated-character condition",
     "removed_condition",
     "        if _is_repeated_char(first):\n            return 1\n        return 0",
     "        return 0"),
    ("M03", "first_name_cleaning_candidate",
     "changed normalization: leading/trailing whitespace no longer stripped",
     "changed_normalization",
     "        first = str(row.get(\"first_name\", \"\")).strip()\n        if not first:\n            return 0\n        first_lower = first.lower()",
     "        first = str(row.get(\"first_name\", \"\"))\n        if not first:\n            return 0\n        first_lower = first.lower()"),
    ("M04", "last_name_cleaning_candidate",
     "inverted final boolean result",
     "inverted_boolean",
     "        if _has_non_alpha(last):\n            return 1\n        if _is_repeated_char(last):\n            return 1\n        return 0",
     "        if _has_non_alpha(last):\n            return 1\n        if _is_repeated_char(last):\n            return 1\n        return 1"),
    ("M05", "last_name_cleaning_candidate",
     "removed non-alpha character condition",
     "removed_condition",
     "        if _has_non_alpha(last):\n            return 1\n        if _is_repeated_char(last):\n            return 1\n        return 0",
     "        if _is_repeated_char(last):\n            return 1\n        return 0"),
    ("M06", "name_cleaning_candidate",
     "inverted equality comparison (equal names no longer flagged)",
     "inverted_comparison",
     "        if first and last and first.lower() == last.lower():\n            return 1",
     "        if first and last and first.lower() != last.lower():\n            return 1"),
    ("M07", "name_cleaning_candidate",
     "removed single-character-name condition",
     "removed_condition",
     "        if first and last and len(first) <= 1 and len(last) <= 1:\n            return 1\n        return 0",
     "        return 0"),
    ("M08", "email_blank",
     "inverted blank comparison",
     "inverted_comparison",
     "        if email is None or str(email).strip() == \"\":\n            return 1\n        return 0",
     "        if email is None or str(email).strip() == \"\":\n            return 0\n        return 1"),
    ("M09", "email_blank",
     "altered blank handling: whitespace-only emails no longer blank",
     "altered_blank_handling",
     "        if email is None or str(email).strip() == \"\":",
     "        if email is None or str(email) == \"\":"),
    ("M10", "email_syntax_failure",
     "inverted regex match verdict",
     "inverted_boolean",
     "        if not self.EMAIL_PATTERN.match(email):\n            return 1\n        return 0",
     "        if not self.EMAIL_PATTERN.match(email):\n            return 0\n        return 1"),
    ("M11", "email_syntax_failure",
     "altered threshold: TLD suffix minimum {2,} -> {1,}",
     "altered_threshold",
     "        r\"^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$\"\n    )\n\n    @property\n    def rule_id(self) -> str:\n        return \"email_syntax_failure\"",
     "        r\"^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{1,}$\"\n    )\n\n    @property\n    def rule_id(self) -> str:\n        return \"email_syntax_failure\""),
    ("M12", "proposed_email_export_eligible",
     "inverted eligibility verdict",
     "inverted_boolean",
     "        if self.EMAIL_PATTERN.match(email):\n            return 1\n        return 0",
     "        if self.EMAIL_PATTERN.match(email):\n            return 0\n        return 1"),
    ("M13", "zip_state_assessable",
     "inverted state-membership check",
     "inverted_comparison",
     "        if zip_val and state and state.upper() in STATE_ZIP_PREFIXES:\n            return 1\n        return 0",
     "        if zip_val and state and state.upper() in STATE_ZIP_PREFIXES:\n            return 0\n        return 1"),
    ("M14", "zip_state_assessable",
     "changed normalization: state case no longer normalized",
     "changed_normalization",
     "        if zip_val and state and state.upper() in STATE_ZIP_PREFIXES:\n            return 1\n        return 0",
     "        if zip_val and state and state in STATE_ZIP_PREFIXES:\n            return 1\n        return 0"),
    ("M15", "geography_mismatch_candidate",
     "inverted prefix-match verdict (matching prefixes flagged as mismatch)",
     "inverted_boolean",
     "        for prefix in zip_prefixes:\n            if zip_val.startswith(prefix):\n                return 0\n        return 1",
     "        for prefix in zip_prefixes:\n            if zip_val.startswith(prefix):\n                return 1\n        return 0"),
    ("M16", "geography_mismatch_candidate",
     "incorrect geography condition: unknown states flagged as mismatch",
     "incorrect_condition",
     "        state_upper = state.upper()\n        if state_upper not in STATE_ZIP_PREFIXES:\n            return 0",
     "        state_upper = state.upper()\n        if state_upper not in STATE_ZIP_PREFIXES:\n            return 1"),
    ("M17", "geography_mismatch_candidate",
     "altered blank handling: blank ZIP no longer exempts a row",
     "altered_blank_handling",
     "        if not zip_val or not state:\n            return 0",
     "        if not state:\n            return 0"),
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_test_suite():
    """Run the relevant test suite; return (exit_code, failed_test_ids)."""
    cmd = [sys.executable, "-m", "pytest", "-x", "-q",
           "--no-header", "-p", "no:cacheprovider"] + TEST_TARGETS
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True,
                          text=True, timeout=900)
    failed = []
    for line in (proc.stdout + proc.stderr).splitlines():
        line = line.strip()
        if line.startswith("FAILED ") or line.startswith("ERROR "):
            failed.append(line.split()[1])
    return proc.returncode, failed, (proc.stdout + proc.stderr)[-3000:]


def main():
    quick = "--quick" in sys.argv
    mutations = MUTATIONS[:6] if quick else MUTATIONS

    original_bytes = open(RULES_PATH, "rb").read()
    original_hash = hashlib.sha256(original_bytes).hexdigest()
    print(f"production rule source: {RULES_PATH}")
    print(f"pre-run SHA-256:        {original_hash}")
    print(f"mutants planned:        {len(mutations)}")
    print("=" * 72)

    results = []
    restore_ok = True
    try:
        for (mid, rule_id, desc, technique, old, new) in mutations:
            src = original_bytes.decode("utf-8")
            count = src.count(old)
            if count != 1:
                results.append({
                    "mutation_id": mid, "rule_id": rule_id,
                    "mutation_description": desc, "technique": technique,
                    "detected": False,
                    "infrastructure_error": (
                        f"mutation anchor occurs {count} times (need exactly 1); "
                        f"mutant NOT applied"),
                    "tests_that_detected_it": [],
                })
                print(f"[{mid}] INFRA ERROR: anchor count={count} — skipped")
                continue
            mutated_src = src.replace(old, new, 1)
            t0 = time.time()
            try:
                with open(RULES_PATH, "w", encoding="utf-8") as f:
                    f.write(mutated_src)
                # SANITY: mutated file hash must differ from original.
                mutated_hash = sha256_file(RULES_PATH)
                assert mutated_hash != original_hash, "mutant is a no-op"
                rc, failed, _tail = run_test_suite()
                detected = rc != 0 and bool(failed)
                results.append({
                    "mutation_id": mid, "rule_id": rule_id,
                    "mutation_description": desc, "technique": technique,
                    "detected": detected,
                    "tests_that_detected_it": failed[:25],
                    "failed_test_count": len(failed),
                    "suite_exit_code": rc,
                    "duration_seconds": round(time.time() - t0, 2),
                })
                status = "DETECTED" if detected else "SURVIVED (TESTING GAP)"
                print(f"[{mid}] {rule_id:35s} {technique:24s} {status} "
                      f"({len(failed)} failing tests, "
                      f"{time.time() - t0:.1f}s)")
            finally:
                with open(RULES_PATH, "wb") as f:
                    f.write(original_bytes)
                restored = sha256_file(RULES_PATH)
                if restored != original_hash:
                    restore_ok = False
                    print(f"[{mid}] FATAL: restoration hash mismatch — "
                          f"ABORTING ALL FURTHER MUTATIONS")
                    break
    finally:
        # Absolute final safety net: bytes-exact restore regardless.
        with open(RULES_PATH, "wb") as f:
            f.write(original_bytes)
        final_hash = sha256_file(RULES_PATH)
    print("=" * 72)
    print(f"post-run SHA-256:       {final_hash}")
    print(f"restore verified:      {final_hash == original_hash and restore_ok}")

    detected = [r for r in results if r.get("detected")]
    survived = [r for r in results
                if not r.get("detected") and "infrastructure_error" not in r]
    summary = {
        "tool": "scripts/mutation_testing.py",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "production_source": "data_quality_platform/rules/v1_rules.py",
        "source_sha256_before": original_hash,
        "source_sha256_after": final_hash,
        "source_restored_exactly": final_hash == original_hash and restore_ok,
        "test_targets": TEST_TARGETS,
        "mutants_total": len(results),
        "mutants_detected": len(detected),
        "mutants_survived": len(survived),
        "mutation_score": (round(len(detected) / len(results), 4)
                           if results else None),
        "testing_gaps": [
            {"mutation_id": r["mutation_id"], "rule_id": r["rule_id"],
             "mutation_description": r["mutation_description"]}
            for r in survived],
        "results": results,
    }
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    out = os.path.join(EVIDENCE_DIR, "mutation_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"evidence written:       {out}")
    print(f"mutation score:         {summary['mutation_score']} "
          f"({len(detected)}/{len(results)})")
    ok = (final_hash == original_hash and restore_ok and not survived)
    print(f"VERDICT: {'ALL MUTANTS DETECTED — test suite mutation-robust' if ok else 'TESTING GAPS PRESENT'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
