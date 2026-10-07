from data_quality_platform.contracts import (
    SOURCE_COLUMNS, FLAG_COLUMNS, OUTPUT_COLUMNS,
    TOTAL_OUTPUT_COLUMNS,
    REQUIRED_RULE_IDS, STATE_ZIP_PREFIXES,
    VERIFIED, PARTIALLY_VERIFIED, DESIGNED_BUT_NOT_RUNTIME_VERIFIED, NOT_IMPLEMENTED,
)


class TestContracts:
    def test_source_columns_count(self):
        assert len(SOURCE_COLUMNS) == 33

    def test_source_columns_first_is_id(self):
        assert SOURCE_COLUMNS[0] == "id"

    def test_source_columns_last_is_zip_norm(self):
        assert SOURCE_COLUMNS[-1] == "zip_norm"

    def test_source_columns_unique(self):
        assert len(set(SOURCE_COLUMNS)) == 33

    def test_flag_columns_count(self):
        assert len(FLAG_COLUMNS) == 8

    def test_total_output_columns(self):
        assert TOTAL_OUTPUT_COLUMNS == 41

    def test_output_columns_order(self):
        assert OUTPUT_COLUMNS[:33] == SOURCE_COLUMNS
        assert OUTPUT_COLUMNS[33:] == FLAG_COLUMNS

    def test_required_rule_ids_count(self):
        assert len(REQUIRED_RULE_IDS) == 8

    def test_required_rule_ids_match_flag_columns(self):
        assert REQUIRED_RULE_IDS == FLAG_COLUMNS

    def test_state_zip_prefixes_has_us_states(self):
        assert "CA" in STATE_ZIP_PREFIXES
        assert "NY" in STATE_ZIP_PREFIXES
        assert "TX" in STATE_ZIP_PREFIXES

    def test_status_constants(self):
        assert VERIFIED == "VERIFIED"
        assert PARTIALLY_VERIFIED == "PARTIALLY_VERIFIED"
        assert DESIGNED_BUT_NOT_RUNTIME_VERIFIED == "DESIGNED_BUT_NOT_RUNTIME_VERIFIED"
        assert NOT_IMPLEMENTED == "NOT_IMPLEMENTED"

    def test_source_columns_include_pii(self):
        assert "email_address" in SOURCE_COLUMNS
        assert "phone_number" in SOURCE_COLUMNS
        assert "first_name" in SOURCE_COLUMNS
        assert "last_name" in SOURCE_COLUMNS
        assert "address" in SOURCE_COLUMNS

    def test_flag_columns_include_all_8(self):
        expected_flags = [
            "first_name_cleaning_candidate",
            "last_name_cleaning_candidate",
            "name_cleaning_candidate",
            "email_blank",
            "email_syntax_failure",
            "proposed_email_export_eligible",
            "zip_state_assessable",
            "geography_mismatch_candidate",
        ]
        for f in expected_flags:
            assert f in FLAG_COLUMNS
