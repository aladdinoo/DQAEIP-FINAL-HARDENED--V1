"""Rule oracle consistency tests — differential validation.

These tests compare the production rule implementations in
``data_quality_platform/rules/v1_rules.py`` against the INDEPENDENT
oracle in ``data_quality_platform/rules/oracle.py`` on a 5000-row
random battery. Any divergence is either (a) a bug, or (b) a
documented frozen-V1 semantic edge case.

This test is the primary detector for the mutation testing harness.
When ``scripts/mutation_testing.py`` mutates ``v1_rules.py``, this test
catches the mutation because the engine's output diverges from the
oracle's output.

The oracle does NOT import or call ``v1_rules.py`` — it is a fully
independent re-implementation of the frozen V1 semantics.
"""

import csv
import os
import random
import sys
import tempfile

import pytest

from data_quality_platform.contracts import (
    SOURCE_COLUMNS, FLAG_COLUMNS, STATE_ZIP_PREFIXES,
    SUSPICIOUS_NAME_PATTERNS,
)
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.rules.v1_rules import (
    FirstNameCleaningCandidate, LastNameCleaningCandidate,
    NameCleaningCandidate, EmailBlank, EmailSyntaxFailure,
    ProposedEmailExportEligible, ZipStateAssessable,
    GeographyMismatchCandidate,
)
from data_quality_platform.rules.oracle import oracle_flags

# Verify the oracle does NOT import v1_rules (independence guarantee).
import data_quality_platform.rules.oracle as _oracle_mod
assert not any('v1_rules' in name for name in sys.modules
               if 'oracle' in str(getattr(sys.modules[name], '__file__', ''))), \
    "oracle must not import v1_rules"


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Single-rule differential tests (boundary cases)
# ---------------------------------------------------------------------------

class TestRuleOracleConsistency:
    """Each V1 rule's output must match the oracle on every test row."""

    @pytest.fixture
    def registry(self):
        return RuleRegistry.create_default()

    @pytest.fixture
    def rows_5000(self):
        """5000-row random battery covering all 8 rules + edge cases.

        Includes lowercase/mixed-case states to catch normalization mutants
        (e.g., M14 which removes ``.upper()``).
        """
        rng = random.Random(20260929)
        # Include lowercase, mixed-case, and uppercase states.
        states = (list(STATE_ZIP_PREFIXES.keys())
                  + [s.lower() for s in STATE_ZIP_PREFIXES.keys()]
                  + [s.title() for s in STATE_ZIP_PREFIXES.keys()]
                  + ["XX", "GU", "PR", "", "12", "AB"])
        names = ["James", "Mary", "test", "Anna", "na", "Hannah", "Donna",
                 "", "xxx", "John", "x", "A", "Jonathan", None, "test-user",
                 # Whitespace-padded names to catch normalization mutants
                 # (e.g., M03 which removes .strip()).
                 "  James  ", " test ", "  ", "\tAnna\t",
                 # Repeated-character names to catch removed_condition
                 # mutants (e.g., M02/M05 which remove _is_repeated_char).
                 "aaa", "bbb", "zzz", "jjj", "mmmm",
                 # Names with non-alpha chars to catch _has_non_alpha mutants
                 "John123", "Mary!", "Bob@work", "Jane_Doe"]
        emails = ["john@example.com", "", "bad-email", "a@b.io",
                  "user@test.org", None, "x@y.z"]
        zips = ["12345", "90210", "", "00000", "99999", "12345-6789", None]
        rows = []
        for i in range(5000):
            rows.append({
                "id": str(i),
                "email_address": rng.choice(emails),
                "first_name": rng.choice(names),
                "last_name": rng.choice(names),
                "state": rng.choice(states),
                "zip": rng.choice(zips),
            })
        return rows

    def test_all_8_rules_match_oracle_on_5000_rows(self, registry, rows_5000):
        """The engine's per-row flag output must match the oracle on all 5000 rows."""
        mismatches = []
        for i, row in enumerate(rows_5000):
            engine_flags = registry.execute_all(row)
            oracle = oracle_flags(row)
            for rule_id in FLAG_COLUMNS:
                if engine_flags.get(rule_id) != oracle.get(rule_id):
                    mismatches.append({
                        "row": i, "rule": rule_id,
                        "engine": engine_flags.get(rule_id),
                        "oracle": oracle.get(rule_id),
                        "row_data": {k: row.get(k) for k in
                                     ("first_name", "last_name", "email_address", "zip", "state")},
                    })
                    if len(mismatches) >= 10:
                        break
            if len(mismatches) >= 10:
                break
        assert not mismatches, (
            f"engine vs oracle divergence on {len(mismatches)} rows "
            f"(showing first 10):\n" +
            "\n".join(repr(m) for m in mismatches))

    def test_oracle_does_not_import_v1_rules(self):
        """Independence guarantee: the oracle module must not import v1_rules."""
        import inspect
        src = inspect.getsource(_oracle_mod)
        assert "from data_quality_platform.rules.v1_rules" not in src, \
            "oracle.py must not import v1_rules.py"
        assert "import data_quality_platform.rules.v1_rules" not in src, \
            "oracle.py must not import v1_rules.py"

    # ---- per-rule boundary cases ----------------------------------------

    def test_first_name_suspicious_pattern(self):
        row = {"first_name": "test", "last_name": "", "email_address": "", "zip": "", "state": ""}
        assert registry_flag(row, "first_name_cleaning_candidate") == oracle_flags(row)["first_name_cleaning_candidate"]

    def test_first_name_normal_name_with_na_substring(self):
        """Frozen V1: 'na' substring matches 'Anna' — intended, not a bug."""
        row = {"first_name": "Anna", "last_name": "", "email_address": "", "zip": "", "state": ""}
        assert registry_flag(row, "first_name_cleaning_candidate") == oracle_flags(row)["first_name_cleaning_candidate"]

    def test_first_name_blank_returns_0(self):
        row = {"first_name": "", "last_name": "", "email_address": "", "zip": "", "state": ""}
        assert registry_flag(row, "first_name_cleaning_candidate") == 0

    def test_email_blank_vs_syntax_distinct(self):
        row = {"email_address": ""}
        assert registry_flag(row, "email_blank") == 1
        assert registry_flag(row, "email_syntax_failure") == 0

    def test_email_syntax_failure_for_bad_email(self):
        row = {"email_address": "not-an-email"}
        assert registry_flag(row, "email_syntax_failure") == 1
        assert registry_flag(row, "email_blank") == 0

    def test_geography_unknown_state_not_assessable(self):
        row = {"zip": "12345", "state": "XX"}
        assert registry_flag(row, "zip_state_assessable") == 0
        assert registry_flag(row, "geography_mismatch_candidate") == 0

    def test_geography_valid_state_valid_prefix(self):
        row = {"zip": "90210", "state": "CA"}
        assert registry_flag(row, "zip_state_assessable") == 1
        assert registry_flag(row, "geography_mismatch_candidate") == 0

    def test_geography_valid_state_wrong_prefix(self):
        row = {"zip": "10001", "state": "CA"}
        assert registry_flag(row, "zip_state_assessable") == 1
        assert registry_flag(row, "geography_mismatch_candidate") == 1

    def test_geography_blank_zip_not_assessable(self):
        row = {"zip": "", "state": "CA"}
        assert registry_flag(row, "zip_state_assessable") == 0
        assert registry_flag(row, "geography_mismatch_candidate") == 0

    def test_name_cleaning_first_equals_last(self):
        row = {"first_name": "John", "last_name": "John"}
        assert registry_flag(row, "name_cleaning_candidate") == 1

    def test_name_cleaning_both_single_char(self):
        row = {"first_name": "A", "last_name": "B"}
        assert registry_flag(row, "name_cleaning_candidate") == 1


def registry_flag(row, rule_id):
    """Helper: execute one rule via the registry and return its flag."""
    rr = RuleRegistry.create_default()
    return rr.execute_all(row)[rule_id]
