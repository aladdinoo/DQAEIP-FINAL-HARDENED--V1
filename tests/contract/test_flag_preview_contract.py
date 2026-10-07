from data_quality_platform.contracts import (
    SOURCE_COLUMNS, FLAG_COLUMNS, OUTPUT_COLUMNS,
    TOTAL_OUTPUT_COLUMNS, REQUIRED_RULE_IDS,
)


class TestFlagPreviewContract:
    def test_output_column_count(self):
        assert TOTAL_OUTPUT_COLUMNS == 41

    def test_source_then_flags_order(self):
        assert OUTPUT_COLUMNS[:33] == SOURCE_COLUMNS
        assert OUTPUT_COLUMNS[33:] == FLAG_COLUMNS

    def test_flag_columns_match_rule_ids(self):
        assert list(REQUIRED_RULE_IDS) == FLAG_COLUMNS

    def test_no_duplicate_output_columns(self):
        assert len(OUTPUT_COLUMNS) == len(set(OUTPUT_COLUMNS))
