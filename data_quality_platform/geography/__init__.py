"""Geography contract — V1 authoritative geography subsystem.

This is the SINGLE authoritative geography implementation for DQAEIP.
It is consumed by ``rules/v1_rules.py::ZipStateAssessable`` and
``GeographyMismatchCandidate`` via the ``STATE_ZIP_PREFIXES`` constant
re-exported here from ``contracts.py``.

Design decisions
----------------
1. ONE geography implementation. No competing SP1 successor module.
2. V1 semantics are FROZEN. The rule outputs (assessable, mismatch)
   match the certified 3.3M validation exactly (0 false negatives).
3. ``UNASSESSABLE != MISMATCH`` — a row whose state is not in the
   prefix map returns (0, 0), meaning "not assessable", NOT "clean".
4. Fail-closed on malformed inputs: a non-string zip/state, a
   non-UTF-8 state, or a None value normalizes to "" and returns
   (0, 0) — never raises, never produces a spurious mismatch flag.
5. The reference data (``STATE_ZIP_PREFIXES``) is hard-coded in
   ``contracts.py`` and hash-pinned implicitly by the file hash of
   ``contracts.py`` (which is in ``FROZEN_CRITICAL`` in the release
   gate). There is no external reference file to corrupt or lose.

Normalization contract
-----------------------
- ``normalize_state(value)``: ``str(value).strip().upper()``. None → "".
- ``compute_zip5(value)``: ``str(value).strip()`` if it matches
  ``^[0-9]{5}$``, otherwise "". A 9-digit ZIP+4 (``12345-6789``)
  truncates to the first 5 digits.
- ``is_assessable_state(state_code)``: True iff the normalized
  state is a 2-letter code present in ``STATE_ZIP_PREFIXES``.

This module does NOT implement SP1 successor semantics (canonical
two-reference resolution, SP1 eligibility, etc.). SP1 was a future
design that was intentionally never activated. It is NOT restored.
"""

from __future__ import annotations

import re
from typing import Tuple

from data_quality_platform.contracts import STATE_ZIP_PREFIXES

__all__ = [
    "STATE_ZIP_PREFIXES",
    "normalize_state",
    "compute_zip5",
    "is_assessable_state",
    "assess_geography",
    "GEOGRAPHY_CONTRACT_VERSION",
]

GEOGRAPHY_CONTRACT_VERSION = "1.0.0-frozen-v1"

_ZIP5_RE = re.compile(r"^[0-9]{5}$")
_ZIP_PLUS_4_RE = re.compile(r"^([0-9]{5})-[0-9]{4}$")
_TWO_LETTER_RE = re.compile(r"^[A-Za-z]{2}$")


def normalize_state(value) -> str:
    """Normalize a state value to upper-cased trimmed text. None → ''."""
    if value is None:
        return ""
    return str(value).strip().upper()


def compute_zip5(value) -> str:
    """Extract a 5-digit ZIP from a raw value.

    Accepts:
      - 5-digit string ('12345')
      - 9-digit ZIP+4 ('12345-6789' → '12345')
      - int (12345 → '12345')

    Returns '' for anything else (blank, malformed, non-numeric).
    """
    if value is None:
        return ""
    text = str(value).strip()
    m = _ZIP_PLUS_4_RE.match(text)
    if m:
        return m.group(1)
    if _ZIP5_RE.match(text):
        return text
    # Accept a bare 5-digit integer.
    if text.isdigit() and len(text) == 5:
        return text
    return ""


def is_assessable_state(state_code: str) -> bool:
    """True iff the normalized state is a 2-letter code in the prefix map."""
    if not isinstance(state_code, str):
        return False
    return bool(_TWO_LETTER_RE.match(state_code)) and state_code in STATE_ZIP_PREFIXES


def assess_geography(raw_zip, raw_state) -> Tuple[int, int]:
    """Assess one (zip, state) pair under the frozen V1 contract.

    Returns ``(assessable, mismatch)`` where each value is 0 or 1.

    Matches the frozen V1 rule semantics EXACTLY:
      ``str(row.get("zip", "")).strip()`` and
      ``str(row.get("state", "")).strip()``.

    This means a present-but-None value becomes the string "None"
    (not blank), which is then evaluated against the prefix map.
    An absent key becomes "" (the default) → not assessable.

    Semantics (frozen V1):
      - If zip is "" (absent) OR state is "" (absent) → (0, 0) — NOT ASSESSABLE.
      - If zip is "None" (present None) → "None" is truthy and non-blank →
        proceeds to state check.
      - If state is "None" (present None) → "None".upper() not in map → (0, 0).
      - If state is in the map but zip doesn't match any prefix → (1, 1) mismatch.
      - If zip starts with one of the state's prefixes → (1, 0).

    This function is pure and deterministic. It never raises.
    """
    zip_val = str(raw_zip).strip()
    state = str(raw_state).strip().upper()
    if not zip_val or not state:
        return (0, 0)
    if state not in STATE_ZIP_PREFIXES:
        return (0, 0)
    for prefix in STATE_ZIP_PREFIXES[state]:
        if zip_val.startswith(prefix):
            return (1, 0)
    return (1, 1)
