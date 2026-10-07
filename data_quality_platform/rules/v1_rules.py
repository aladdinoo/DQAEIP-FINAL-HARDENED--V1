"""V1 quality rules - all 8 required rules with deterministic behavior.

Each rule:
- Returns 0 or 1
- Has a version
- Has SQL template
- Has SHA-256 hash (computed from source)
- Is deterministic for same input
"""

import re
from typing import Any, Dict
from data_quality_platform.rules.base import Rule
from data_quality_platform.contracts import STATE_ZIP_PREFIXES, SUSPICIOUS_NAME_PATTERNS

# Regex to detect non-alpha chars in names (allowing hyphen and apostrophe)
_NON_ALPHA_RE = re.compile(r"[^a-zA-Z\-'\x22]+")


def _has_non_alpha(name: str) -> bool:
    """Check if name has non-alpha chars excluding hyphen and apostrophe."""
    for ch in name:
        if not ch.isalpha() and ch not in ("-", "'"):
            return True
    return False


def _is_repeated_char(name: str) -> bool:
    """Check if name consists of repeated single character."""
    cleaned = name.lower().replace("-", "").replace("'", "")
    return len(name) > 1 and len(cleaned) > 0 and len(set(cleaned)) == 1


class FirstNameCleaningCandidate(Rule):
    """Flag rows where first_name looks suspicious or needs cleaning."""

    @property
    def rule_id(self) -> str:
        return "first_name_cleaning_candidate"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        first = str(row.get("first_name", "")).strip()
        if not first:
            return 0
        first_lower = first.lower()
        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if pattern in first_lower:
                return 1
        if _has_non_alpha(first):
            return 1
        if _is_repeated_char(first):
            return 1
        return 0

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, first_name, 1 AS first_name_cleaning_candidate "
            "FROM source "
            "WHERE lower(first_name) IN ('test','fake','dummy','xxx','zzz','aaa','bbb',"
            "'admin','null','none','na','n/a','unknown','example','sample','asdf','qwerty','abc','xyz') "
            r"OR first_name !~ '^[a-zA-Z\-\'\s]+$' "
            r"OR length(first_name) > 1 AND length(regexp_replace(lower(first_name), '[-\']', '')) = 1"
        )

    def description(self) -> str:
        return "Flags rows where first_name contains suspicious patterns, non-alpha characters, or repeated characters."


class LastNameCleaningCandidate(Rule):
    """Flag rows where last_name looks suspicious or needs cleaning."""

    @property
    def rule_id(self) -> str:
        return "last_name_cleaning_candidate"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        last = str(row.get("last_name", "")).strip()
        if not last:
            return 0
        last_lower = last.lower()
        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if pattern in last_lower:
                return 1
        if _has_non_alpha(last):
            return 1
        if _is_repeated_char(last):
            return 1
        return 0

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, last_name, 1 AS last_name_cleaning_candidate "
            "FROM source "
            "WHERE lower(last_name) IN ('test','fake','dummy','xxx','zzz','aaa','bbb',"
            "'admin','null','none','na','n/a','unknown','example','sample','asdf','qwerty','abc','xyz') "
            r"OR last_name !~ '^[a-zA-Z\-\'\s]+$' "
            r"OR length(last_name) > 1 AND length(regexp_replace(lower(last_name), '[-\']', '')) = 1"
        )

    def description(self) -> str:
        return "Flags rows where last_name contains suspicious patterns, non-alpha characters, or repeated characters."


class NameCleaningCandidate(Rule):
    """Flag rows where the full name combination is suspicious."""

    @property
    def rule_id(self) -> str:
        return "name_cleaning_candidate"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        first = str(row.get("first_name", "")).strip()
        last = str(row.get("last_name", "")).strip()
        if not first and not last:
            return 0
        if first and last and first.lower() == last.lower():
            return 1
        if first and last and len(first) <= 1 and len(last) <= 1:
            return 1
        return 0

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, first_name, last_name, 1 AS name_cleaning_candidate "
            "FROM source "
            "WHERE lower(first_name) = lower(last_name) AND first_name != \' \'"
            "OR length(first_name) <= 1 AND length(last_name) <= 1 AND first_name != \' \' AND last_name != \' \'"
        )

    def description(self) -> str:
        return "Flags rows where first_name equals last_name, or both are suspiciously short single characters."


class EmailBlank(Rule):
    """Flag rows where email_address is blank or empty."""

    @property
    def rule_id(self) -> str:
        return "email_blank"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        email = row.get("email_address")
        if email is None or str(email).strip() == "":
            return 1
        return 0

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, email_address, 1 AS email_blank "
            "FROM source "
            "WHERE email_address IS NULL OR trim(email_address) = \'\'"
        )

    def description(self) -> str:
        return "Flags rows where email_address is blank, empty, or null."


class EmailSyntaxFailure(Rule):
    """Flag rows where email_address has invalid syntax."""

    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    )

    @property
    def rule_id(self) -> str:
        return "email_syntax_failure"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        email = str(row.get("email_address", "")).strip()
        if not email:
            return 0
        if not self.EMAIL_PATTERN.match(email):
            return 1
        return 0

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, email_address, 1 AS email_syntax_failure "
            "FROM source "
            "WHERE email_address != \'\' AND email_address IS NOT NULL "
            "AND NOT match(email_address, \'^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$\')"
        )

    def description(self) -> str:
        return "Flags rows where email_address is non-empty but has invalid syntax."


class ProposedEmailExportEligible(Rule):
    """Flag rows where the email is eligible for export."""

    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    )

    @property
    def rule_id(self) -> str:
        return "proposed_email_export_eligible"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        email = str(row.get("email_address", "")).strip()
        if not email:
            return 0
        if self.EMAIL_PATTERN.match(email):
            return 1
        return 0

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, email_address, 1 AS proposed_email_export_eligible "
            "FROM source "
            "WHERE email_address IS NOT NULL AND trim(email_address) != \'\' "
            "AND match(email_address, \'^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$\')"
        )

    def description(self) -> str:
        return "Flags rows where email is non-blank and syntactically valid, making it export-eligible."


class ZipStateAssessable(Rule):
    """Flag rows where ZIP code and state can be assessed."""

    @property
    def rule_id(self) -> str:
        return "zip_state_assessable"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        zip_val = str(row.get("zip", "")).strip()
        state = str(row.get("state", "")).strip()
        if zip_val and state and state.upper() in STATE_ZIP_PREFIXES:
            return 1
        return 0

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, zip, state, 1 AS zip_state_assessable "
            "FROM source "
            "WHERE zip != \'\' AND state != \'\' AND state IN ({states})"
        )

    def description(self) -> str:
        return "Flags rows where both ZIP code and state are present, allowing geography assessment."


class GeographyMismatchCandidate(Rule):
    """Flag rows where ZIP code prefix does not match the state."""

    @property
    def rule_id(self) -> str:
        return "geography_mismatch_candidate"

    @property
    def rule_version(self) -> str:
        return "1.0.0"

    def execute(self, row: Dict[str, Any]) -> int:
        zip_val = str(row.get("zip", "")).strip()
        state = str(row.get("state", "")).strip()
        if not zip_val or not state:
            return 0
        state_upper = state.upper()
        if state_upper not in STATE_ZIP_PREFIXES:
            return 0
        zip_prefixes = STATE_ZIP_PREFIXES[state_upper]
        for prefix in zip_prefixes:
            if zip_val.startswith(prefix):
                return 0
        return 1

    def execute_sql_template(self) -> str:
        return (
            "SELECT id, zip, state, 1 AS geography_mismatch_candidate "
            "FROM source "
            "WHERE zip != \'\' AND state != \'\' "
            "AND NOT ({zip_state_conditions})"
        )

    def description(self) -> str:
        return "Flags rows where the ZIP code prefix does not match the expected prefixes for the given state."
