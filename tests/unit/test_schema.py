from data_quality_platform.schema.validator import SchemaValidator
from data_quality_platform.contracts import SOURCE_COLUMNS


class TestSchemaValidator:
    def setup_method(self):
        self.sv = SchemaValidator()

    def test_valid_schema(self):
        valid, errors = self.sv.validate_header(list(SOURCE_COLUMNS))
        assert valid
        assert errors == []

    def test_missing_column(self):
        header = SOURCE_COLUMNS[:32]  # missing last column
        valid, errors = self.sv.validate_header(header)
        assert not valid
        assert any("Missing" in e for e in errors)

    def test_extra_column(self):
        header = list(SOURCE_COLUMNS) + ["extra_col"]
        valid, errors = self.sv.validate_header(header)
        assert not valid
        assert any("Extra" in e for e in errors)

    def test_reordered_columns(self):
        header = list(SOURCE_COLUMNS)
        header[0], header[1] = header[1], header[0]  # swap first two
        valid, errors = self.sv.validate_header(header)
        assert not valid
        assert any("reordered" in e.lower() for e in errors)

    def test_duplicate_columns(self):
        header = list(SOURCE_COLUMNS)
        header[0] = header[1]  # duplicate
        valid, errors = self.sv.validate_header(header)
        assert not valid
        assert any("Duplicate" in e for e in errors)

    def test_schema_hash_deterministic(self):
        h1 = self.sv.compute_schema_hash(list(SOURCE_COLUMNS))
        h2 = self.sv.compute_schema_hash(list(SOURCE_COLUMNS))
        assert h1 == h2
        assert len(h1) == 64

    def test_schema_hash_different_for_different_schemas(self):
        h1 = self.sv.compute_schema_hash(list(SOURCE_COLUMNS))
        h2 = self.sv.compute_schema_hash(list(SOURCE_COLUMNS)[:32])
        assert h1 != h2

    def test_detect_drift_no_drift(self):
        ok, drift = self.sv.detect_drift(list(SOURCE_COLUMNS), list(SOURCE_COLUMNS))
        assert ok
        assert drift == []

    def test_detect_drift_column_added(self):
        ok, drift = self.sv.detect_drift(list(SOURCE_COLUMNS), list(SOURCE_COLUMNS) + ["new_col"])
        assert not ok
        assert any("added" in d.lower() for d in drift)

    def test_detect_drift_column_removed(self):
        ok, drift = self.sv.detect_drift(list(SOURCE_COLUMNS), list(SOURCE_COLUMNS)[:32])
        assert not ok
        assert any("removed" in d.lower() for d in drift)
