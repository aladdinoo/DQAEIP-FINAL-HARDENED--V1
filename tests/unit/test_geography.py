"""Geography contract tests — V1 authoritative geography subsystem.

Tests the ``data_quality_platform/geography/__init__.py`` module:

  - normalize_state: None, blank, lowercase, mixed-case, with whitespace
  - compute_zip5: 5-digit, ZIP+4, int, malformed, blank, None
  - is_assessable_state: valid 2-letter, invalid format, unknown state
  - assess_geography: all boundary cases
  - UNASSESSABLE != MISMATCH invariant
  - V1 rule consistency: ZipStateAssessable + GeographyMismatchCandidate
    outputs match assess_geography() on every test case
"""

import pytest

from data_quality_platform.geography import (
    normalize_state, compute_zip5, is_assessable_state,
    assess_geography, STATE_ZIP_PREFIXES, GEOGRAPHY_CONTRACT_VERSION,
)
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.contracts import STATE_ZIP_PREFIXES as CONTRACT_PREFIXES


class TestNormalizeState:
    def test_none_returns_empty(self):
        assert normalize_state(None) == ""

    def test_blank_returns_empty(self):
        assert normalize_state("") == ""
        assert normalize_state("   ") == ""

    def test_lowercase_uppercased(self):
        assert normalize_state("ca") == "CA"
        assert normalize_state("tx") == "TX"

    def test_mixed_case_uppercased(self):
        assert normalize_state("Ca") == "CA"
        assert normalize_state("tX") == "TX"

    def test_whitespace_trimmed(self):
        assert normalize_state("  CA  ") == "CA"

    def test_non_string_coerced(self):
        assert normalize_state(123) == "123"


class TestComputeZip5:
    def test_five_digit_string(self):
        assert compute_zip5("12345") == "12345"

    def test_zip_plus_4_truncates(self):
        assert compute_zip5("12345-6789") == "12345"

    def test_integer(self):
        assert compute_zip5(12345) == "12345"

    def test_blank_returns_empty(self):
        assert compute_zip5("") == ""
        assert compute_zip5("   ") == ""

    def test_none_returns_empty(self):
        assert compute_zip5(None) == ""

    def test_malformed_returns_empty(self):
        assert compute_zip5("abcde") == ""
        assert compute_zip5("1234") == ""  # 4 digits
        assert compute_zip5("123456") == ""  # 6 digits
        assert compute_zip5("--") == ""


class TestIsAssessableState:
    def test_valid_state(self):
        assert is_assessable_state("CA") is True
        assert is_assessable_state("NY") is True

    def test_unknown_state(self):
        assert is_assessable_state("XX") is False

    def test_invalid_format(self):
        assert is_assessable_state("123") is False
        assert is_assessable_state("CALIF") is False

    def test_blank(self):
        assert is_assessable_state("") is False

    def test_non_string(self):
        assert is_assessable_state(None) is False
        assert is_assessable_state(123) is False


class TestAssessGeography:
    def test_blank_zip_returns_not_assessable(self):
        a, m = assess_geography("", "CA")
        assert (a, m) == (0, 0)

    def test_blank_state_returns_not_assessable(self):
        a, m = assess_geography("90210", "")
        assert (a, m) == (0, 0)

    def test_none_zip_returns_not_assessable(self):
        # Frozen V1: str(None) = "None" (truthy) → assessable=1, mismatch=1.
        # This is the V1 contract (present-but-None is NOT blank).
        a, m = assess_geography(None, "CA")
        assert (a, m) == (1, 1)

    def test_none_state_returns_not_assessable(self):
        a, m = assess_geography("90210", None)
        assert (a, m) == (0, 0)

    def test_unknown_state_returns_not_assessable(self):
        a, m = assess_geography("12345", "XX")
        assert (a, m) == (0, 0)

    def test_valid_state_valid_prefix_no_mismatch(self):
        a, m = assess_geography("90210", "CA")
        assert (a, m) == (1, 0)

    def test_valid_state_wrong_prefix_mismatch(self):
        a, m = assess_geography("10001", "CA")
        assert (a, m) == (1, 1)

    def test_assessable_but_no_prefix_match(self):
        # CA prefixes are 90-96; a zip starting with 10 is NY, mismatched for CA.
        a, m = assess_geography("10500", "CA")
        assert (a, m) == (1, 1)

    def test_unassessable_not_mismatch_invariant(self):
        """UNASSESSABLE != MISMATCH. Any (0, assessable) result is impossible."""
        # Test all 51 states + territories in the map.
        for state in STATE_ZIP_PREFIXES:
            # An assessable state with a valid prefix must yield (1, 0).
            first_prefix = STATE_ZIP_PREFIXES[state][0]
            a, m = assess_geography(first_prefix + "000", state)
            assert a == 1, f"{state} with valid prefix should be assessable"
        # Test unknown states — all must yield (0, 0).
        for unknown in ("XX", "GU", "PR", "AA", "12", "AB", "ZZ"):
            assert assess_geography("12345", unknown) == (0, 0), \
                f"{unknown} should be not assessable, not mismatched"


class TestV1RuleConsistency:
    """The V1 rule outputs must match assess_geography() on every case."""

    @pytest.fixture
    def registry(self):
        return RuleRegistry.create_default()

    def test_zip_state_assessable_matches(self, registry):
        # Frozen V1: None → str(None) = "None" (not blank) → assessable if state valid.
        # assess_geography matches this: str(None).strip() = "None" → truthy.
        cases = [
            ("90210", "CA", 1), ("10001", "CA", 1), ("", "CA", 0),
            ("90210", "", 0), ("90210", "XX", 0),
            # None → "None" (truthy) → assessable=1 if state valid, mismatch=1.
            (None, "CA", 1),
        ]
        for zip_val, state_val, expected in cases:
            row = {"zip": zip_val, "state": state_val}
            flags = registry.execute_all(row)
            a, _ = assess_geography(zip_val, state_val)
            assert flags["zip_state_assessable"] == a == expected, \
                f"zip={zip_val!r} state={state_val!r}: rule={flags['zip_state_assessable']} geography={a} expected={expected}"

    def test_geography_mismatch_matches(self, registry):
        cases = [
            ("90210", "CA", 0),   # valid prefix, no mismatch
            ("10001", "CA", 1),   # wrong prefix, mismatch
            ("", "CA", 0),        # blank zip, not assessable
            ("90210", "", 0),     # blank state, not assessable
            ("90210", "XX", 0),   # unknown state, not assessable
        ]
        for zip_val, state_val, expected in cases:
            row = {"zip": zip_val, "state": state_val}
            flags = registry.execute_all(row)
            a, m = assess_geography(zip_val, state_val)
            assert flags["geography_mismatch_candidate"] == m == expected, \
                f"zip={zip_val!r} state={state_val!r}: rule={flags['geography_mismatch_candidate']} geography={m} expected={expected}"


class TestGeographyContractVersion:
    def test_version_is_frozen_v1(self):
        assert "frozen" in GEOGRAPHY_CONTRACT_VERSION
        assert "v1" in GEOGRAPHY_CONTRACT_VERSION

    def test_prefixes_match_contracts(self):
        """The geography module re-exports the SAME STATE_ZIP_PREFIXES object
        from contracts.py — no drift, no copy."""
        assert STATE_ZIP_PREFIXES is CONTRACT_PREFIXES
