"""Independent rule oracle for V1 rule mutation testing.

This module implements the 8 frozen V1 rules INDEPENDENTLY of
``data_quality_platform/rules/v1_rules.py``. It is used by the
differential-validation tests to detect semantic drift between the
production rule implementations and an independent reference.

DESIGN CONTRACT
---------------
1. This module MUST NOT import from ``data_quality_platform.rules.v1_rules``
   or ``data_quality_platform.rules.registry``. The oracle is independent.
2. The oracle's reference data (``SUSPICIOUS_NAME_PATTERNS``,
   ``STATE_ZIP_PREFIXES``) is copied verbatim from the frozen V1 contract
   in ``contracts.py``. It is NOT re-derived or re-implemented — the V1
   contract IS the authoritative reference data.
3. The oracle's logic is a deliberate re-implementation of the V1 rule
   semantics. Any divergence between the oracle and ``v1_rules.py`` is
   either (a) a bug in one of them, or (b) a documented frozen-V1
   semantic edge case.
4. The oracle is pure and deterministic. It never raises on malformed
   input — it returns 0 (not flagged) for blank/unparseable values,
   matching the V1 contract.

MUTATION TESTING
---------------
The mutation testing harness (``scripts/mutation_testing.py``) mutates
``v1_rules.py`` one mutant at a time and runs the test suite. The
``test_rule_oracle_consistency.py`` tests compare the engine's output
against this oracle on a 5000-row random battery. A mutant that changes
a rule's output causes the oracle comparison to fail, detecting the
mutation.

Target: 17/17 mutants detected (mutation score 1.0).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping

# Reference data — copied verbatim from the frozen V1 contract.
# (Imported from contracts to avoid drift, but the LOGIC below is
# independently implemented — it does NOT call v1_rules.py.)
from data_quality_platform.contracts import (
    STATE_ZIP_PREFIXES,
    SUSPICIOUS_NAME_PATTERNS,
)

__all__ = ["oracle_flags", "ORACLE_VERSION"]

ORACLE_VERSION = "1.0.0-independent"

# Regex patterns — independently defined (not imported from v1_rules).
_ORACLE_NON_ALPHA_RE = re.compile(r"[^a-zA-Z\-']+")
_ORACLE_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _oracle_name_flag(name: Any) -> int:
    """first_name/last_name cleaning candidate predicate.

    Matches the frozen V1 rule semantics EXACTLY:
      ``str(row.get(field, "")).strip()`` — so a None value becomes the
      string "None", which contains "none" (a suspicious pattern) → flagged.
      An absent key becomes "" (the default) → not flagged.

    Returns 1 if the name contains a suspicious pattern, a non-alpha
    character (outside ``a-zA-Z-'``), or is a repeated single character.
    Returns 0 if the name is blank.
    """
    s = str(name).strip()
    if s == "":
        return 0
    low = s.lower()
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern in low:
            return 1
    for ch in s:
        if not (ch.isalpha() or ch == "-" or ch == "'"):
            return 1
    collapsed = low.replace("-", "").replace("'", "")
    if len(s) > 1 and collapsed != "" and len(set(collapsed)) == 1:
        return 1
    return 0


def _oracle_full_name_flag(first: Any, last: Any) -> int:
    """name_cleaning_candidate predicate.

    Matches frozen V1: ``str(row.get("first_name", "")).strip()`` for
    both fields. None → "None" (not blank).
    """
    f = str(first).strip()
    l = str(last).strip()
    if f == "" and l == "":
        return 0
    if f != "" and l != "":
        if f.lower() == l.lower():
            return 1
        if len(f) <= 1 and len(l) <= 1:
            return 1
    return 0


def _oracle_email_flags(email_no_default: Any, email_with_default: Any = None) -> tuple:
    """Returns (blank, syntax_failure, export_eligible).

    Matches frozen V1 EXACTLY (verified against the production engine):
      - EmailBlank: ``row.get("email_address")`` (no default), then
        ``email is None or str(email).strip() == ""``.
        None, "", and absent → blank=1.
      - EmailSyntaxFailure: ``str(row.get("email_address", "")).strip()``.
        absent → "" (default) → not syntax failure.
        None → "None" → regex fails → syntax failure=1.
        "" → "" → not syntax failure (empty short-circuits in V1).
      - ProposedEmailExportEligible: same as syntax failure but inverted.

    Net behavior (verified):
      None         → blank=1, syntax=1, eligible=0  (None→"None"→regex fail)
      ""           → blank=1, syntax=0, eligible=0
      absent       → blank=1, syntax=0, eligible=0  (no-default→None→blank; with-default→""→no syntax fail)
      "x@y.z"      → blank=0, syntax=0, eligible=1
      "bad-email"  → blank=0, syntax=1, eligible=0
    """
    # email_no_default: from row.get("email_address") — None if absent or present-None.
    # email_with_default: from row.get("email_address", "") — "" if absent, None if present-None.
    # EmailBlank: None or "" → blank=1.
    if email_no_default is None or str(email_no_default).strip() == "":
        blank = 1
    else:
        blank = 0
    # EmailSyntaxFailure / ExportEligible: str(value).strip(), then regex.
    e = str(email_with_default).strip()
    if e == "":
        # "" or absent → not a syntax failure, not eligible.
        syntax_fail = 0
        eligible = 0
    else:
        ok = _ORACLE_EMAIL_RE.fullmatch(e) is not None
        syntax_fail = 0 if ok else 1
        eligible = 1 if ok else 0
    # Special case: present-but-None. email_no_default is None (so blank=1),
    # but email_with_default is also None (so e="None" → regex fails → syntax=1).
    # This matches the verified V1 behavior: None → blank=1, syntax=1.
    return blank, syntax_fail, eligible


def _oracle_geography_flags(raw_zip: Any, raw_state: Any) -> tuple:
    """Returns (assessable, mismatch) under frozen V1 prefix-map semantics.

    Matches frozen V1: ``str(row.get("zip", "")).strip()`` and
    ``str(row.get("state", "")).strip()``. None → "None" (not blank).

    UNASSESSABLE != MISMATCH. A row with an unknown state returns (0, 0).
    """
    z = str(raw_zip).strip()
    s = str(raw_state).strip()
    if z == "" or s == "":
        return 0, 0
    su = s.upper()
    if su not in STATE_ZIP_PREFIXES:
        return 0, 0
    for prefix in STATE_ZIP_PREFIXES[su]:
        if z.startswith(prefix):
            return 1, 0
    return 1, 1


def oracle_flags(row: Mapping[str, Any]) -> Dict[str, int]:
    """Compute all 8 V1 flags for one row dict. Independent code path.

    This function does NOT call or import ``v1_rules.py``. It is a
    deliberate independent re-implementation of the frozen V1 semantics.

    Each field is read via the SAME ``row.get`` pattern as the V1 rules:
      - EmailBlank: ``row.get("email_address")`` (no default) — absent → None.
      - EmailSyntaxFailure / ProposedEmailExportEligible:
        ``row.get("email_address", "")`` (with default) — absent → "".
      - Name rules: ``row.get("first_name", "")`` (with default).
      - Geography rules: ``row.get("zip", "")`` and ``row.get("state", "")``.

    This means absent and present-but-None behave DIFFERENTLY for the
    email syntax rule (absent → "", None → "None"). The oracle matches
    this frozen V1 quirk exactly.
    """
    # EmailBlank uses row.get("email_address") (no default).
    email_no_default = row.get("email_address")
    # EmailSyntaxFailure / ExportEligible use row.get("email_address", "").
    email_with_default = row.get("email_address", "")
    blank, syntax_fail, eligible = _oracle_email_flags(email_no_default, email_with_default)
    assessable, mismatch = _oracle_geography_flags(
        row.get("zip", ""), row.get("state", ""))
    return {
        "first_name_cleaning_candidate": _oracle_name_flag(row.get("first_name", "")),
        "last_name_cleaning_candidate": _oracle_name_flag(row.get("last_name", "")),
        "name_cleaning_candidate": _oracle_full_name_flag(
            row.get("first_name", ""), row.get("last_name", "")),
        "email_blank": blank,
        "email_syntax_failure": syntax_fail,
        "proposed_email_export_eligible": eligible,
        "zip_state_assessable": assessable,
        "geography_mismatch_candidate": mismatch,
    }
