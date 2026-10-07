"""Rule registry: manages rule loading, validation, and lookup."""

import hashlib
from typing import Dict, List, Tuple
from data_quality_platform.rules.base import Rule
from data_quality_platform.contracts import REQUIRED_RULE_IDS
from data_quality_platform.rules.v1_rules import (
    FirstNameCleaningCandidate,
    LastNameCleaningCandidate,
    NameCleaningCandidate,
    EmailBlank,
    EmailSyntaxFailure,
    ProposedEmailExportEligible,
    ZipStateAssessable,
    GeographyMismatchCandidate,
)


class RuleRegistryError(Exception):
    """Raised when the rule registry is invalid."""
    pass


class RuleRegistry:
    """Manages quality rules: loading, validation, and execution.

    The registry enforces:
    - All REQUIRED_RULE_IDS are present
    - No duplicate rule IDs
    - No unexpected rules (warnings, not errors)
    - Version tracking
    - Hash verification
    """

    def __init__(self):
        self._rules: Dict[str, Rule] = {}

    @classmethod
    def create_default(cls) -> "RuleRegistry":
        """Create a registry pre-loaded with all V1 rules."""
        registry = cls()
        v1_rules = [
            FirstNameCleaningCandidate(),
            LastNameCleaningCandidate(),
            NameCleaningCandidate(),
            EmailBlank(),
            EmailSyntaxFailure(),
            ProposedEmailExportEligible(),
            ZipStateAssessable(),
            GeographyMismatchCandidate(),
        ]
        for rule in v1_rules:
            registry.register(rule)
        return registry

    def register(self, rule: Rule) -> None:
        """Register a rule. Raises on duplicate ID."""
        if rule.rule_id in self._rules:
            existing_version = self._rules[rule.rule_id].rule_version
            if existing_version != rule.rule_version:
                raise RuleRegistryError(
                    f"Duplicate rule_id '{rule.rule_id}' with different version: "
                    f"existing={existing_version}, new={rule.rule_version}"
                )
            # Same ID and version: allow idempotent re-registration
            return
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Rule:
        """Get a rule by ID. Raises KeyError if not found."""
        if rule_id not in self._rules:
            raise KeyError(f"Rule '{rule_id}' not found in registry")
        return self._rules[rule_id]

    def validate(self) -> Tuple[bool, List[str], List[str]]:
        """Validate the registry against required rules.

        Returns:
            (is_valid, errors, warnings)
        """
        errors = []
        warnings = []

        # Check for missing required rules
        registered_ids = set(self._rules.keys())
        required_set = set(REQUIRED_RULE_IDS)
        missing = required_set - registered_ids
        if missing:
            errors.append(f"Missing required rules: {sorted(missing)}")

        # Check for unexpected rules
        unexpected = registered_ids - required_set
        if unexpected:
            warnings.append(f"Unexpected rules (not in V1 spec): {sorted(unexpected)}")

        # Check for duplicate rule IDs (shouldn't happen due to register() guard)
        # But verify hash uniqueness as a sanity check
        seen_hashes = {}
        for rule_id, rule in self._rules.items():
            if rule.hash in seen_hashes:
                warnings.append(
                    f"Rules '{seen_hashes[rule.hash]}' and '{rule_id}' have identical hashes"
                )
            seen_hashes[rule.hash] = rule_id

        return (len(errors) == 0, errors, warnings)

    def get_all_rules(self) -> List[Rule]:
        """Return all registered rules in required order."""
        ordered = []
        for rule_id in REQUIRED_RULE_IDS:
            if rule_id in self._rules:
                ordered.append(self._rules[rule_id])
        return ordered

    def get_rule_hashes(self) -> Dict[str, str]:
        """Return mapping of rule_id -> SHA-256 hash."""
        return {rule_id: rule.hash for rule_id, rule in self._rules.items()}

    def get_rule_versions(self) -> Dict[str, str]:
        """Return mapping of rule_id -> version."""
        return {rule_id: rule.rule_version for rule_id, rule in self._rules.items()}

    @property
    def count(self) -> int:
        return len(self._rules)

    def execute_all(self, row: dict) -> Dict[str, int]:
        """Execute all registered rules against a single row.

        Returns dict of rule_id -> flag value (0 or 1).
        """
        results = {}
        for rule_id in REQUIRED_RULE_IDS:
            if rule_id in self._rules:
                try:
                    results[rule_id] = self._rules[rule_id].execute(row)
                except Exception as e:
                    raise RuleRegistryError(
                        f"Rule '{rule_id}' failed on row: {e}"
                    )
            else:
                raise RuleRegistryError(f"Rule '{rule_id}' not found in registry")
        return results

    def get_sql_templates(self) -> Dict[str, str]:
        """Return mapping of rule_id -> SQL template."""
        return {
            rule_id: rule.execute_sql_template()
            for rule_id, rule in self._rules.items()
        }

    def compute_registry_hash(self) -> str:
        """Compute SHA-256 hash of the entire registry state."""
        import json
        state = {
            rule_id: {
                "version": rule.rule_version,
                "hash": rule.hash,
            }
            for rule_id, rule in sorted(self._rules.items())
        }
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode("utf-8")).hexdigest()
