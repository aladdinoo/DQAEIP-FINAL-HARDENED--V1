"""Schema validation and drift detection."""

import csv
import hashlib
from typing import List, Optional, Tuple
from data_quality_platform.contracts import SOURCE_COLUMNS, EXPECTED_COLUMN_COUNT


class SchemaValidationError(Exception):
    """Raised when schema validation fails."""
    pass


class SchemaDriftError(Exception):
    """Raised when schema drift is detected."""
    pass


class SchemaValidator:
    """Validates CSV schema against the 33-column source contract."""

    def __init__(self):
        self.expected_columns = list(SOURCE_COLUMNS)
        self.expected_count = EXPECTED_COLUMN_COUNT
        self._schema_hash: Optional[str] = None

    def validate_header(self, header: List[str]) -> Tuple[bool, List[str]]:
        """Validate that header matches the expected schema exactly.

        Checks for: missing columns, extra columns, reordered columns,
        duplicate columns, and invalid header entries.

        Returns:
            (is_valid, list of error messages)
        """
        errors = []

        # Check column count
        if len(header) != self.expected_count:
            errors.append(
                f"Column count mismatch: expected {self.expected_count}, got {len(header)}"
            )

        # Check for duplicates
        seen = set()
        duplicates = []
        for col in header:
            if col in seen:
                duplicates.append(col)
            seen.add(col)
        if duplicates:
            errors.append(f"Duplicate columns found: {duplicates}")

        # Check for missing columns
        header_set = set(header)
        missing = [c for c in self.expected_columns if c not in header_set]
        if missing:
            errors.append(f"Missing columns: {missing}")

        # Check for extra columns
        extra = [c for c in header if c not in set(self.expected_columns)]
        if extra:
            errors.append(f"Extra columns found: {extra}")

        # Check column order
        if len(header) == self.expected_count and not duplicates and not missing and not extra:
            if header != self.expected_columns:
                errors.append("Columns are reordered")

        return (len(errors) == 0, errors)

    def validate_csv_file(self, filepath: str) -> Tuple[bool, List[str]]:
        """Validate the header of a CSV file."""
        with open(filepath, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header is None:
                return (False, ["CSV file is empty or has no header"])
            return self.validate_header(header)

    def compute_schema_hash(self, header: List[str]) -> str:
        """Compute SHA-256 hash of the schema (column names and order)."""
        content = ",".join(header)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def detect_drift(self, header_a: List[str], header_b: List[str]) -> Tuple[bool, List[str]]:
        """Detect schema drift between two headers."""
        drift = []
        set_a = set(header_a)
        set_b = set(header_b)

        added = set_b - set_a
        if added:
            drift.append(f"Columns added: {sorted(added)}")

        removed = set_a - set_b
        if removed:
            drift.append(f"Columns removed: {sorted(removed)}")

        if header_a != header_b and not added and not removed:
            drift.append("Column order changed")

        return (len(drift) == 0, drift)

    def get_schema_hash(self, header: List[str]) -> str:
        """Get or compute schema hash."""
        self._schema_hash = self.compute_schema_hash(header)
        return self._schema_hash
