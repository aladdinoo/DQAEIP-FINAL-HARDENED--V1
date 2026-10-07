import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict


class Rule(ABC):
    """Abstract base class for all quality rules.

    Every rule must have:
    - rule_id: unique identifier
    - rule_version: semantic version string
    - execute(row): returns 0 or 1
    - execute_sql_template(): returns SQL template string
    - description(): human-readable description
    - hash: SHA-256 hash of the rule implementation
    """

    def __init__(self):
        self._hash = self._compute_hash()

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier."""
        ...

    @property
    @abstractmethod
    def rule_version(self) -> str:
        """Rule version string."""
        ...

    @abstractmethod
    def execute(self, row: Dict[str, Any]) -> int:
        """Execute rule against a single row.

        Returns:
            1 if the rule flags the row, 0 otherwise.
        """
        ...

    @abstractmethod
    def execute_sql_template(self) -> str:
        """Return a SQL template that implements this rule.

        The template should use {column} placeholders where appropriate.
        """
        ...

    @abstractmethod
    def description(self) -> str:
        """Human-readable description of this rule."""
        ...

    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of the rule's source code."""
        import inspect
        source = inspect.getsource(type(self))
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    @property
    def hash(self) -> str:
        """SHA-256 hash of this rule's implementation."""
        return self._hash

    def __repr__(self) -> str:
        return f"Rule({self.rule_id}@{self.rule_version})"


class RuleExecutionError(Exception):
    """Raised when a rule fails during execution."""
    pass
