import pytest
from data_quality_platform.rules import RuleRegistry, Rule
from data_quality_platform.rules.base import Rule
from data_quality_platform.rules.v1_rules import (
    FirstNameCleaningCandidate, LastNameCleaningCandidate, NameCleaningCandidate,
    EmailBlank, EmailSyntaxFailure, ProposedEmailExportEligible,
    ZipStateAssessable, GeographyMismatchCandidate,
)


def _make_row(**overrides) -> dict:
    row = {
        "id": "1", "email_address": "john.smith@example.com",
        "first_name": "John", "last_name": "Smith",
        "address": "123 Main St", "city": "New York", "county_name": "NYC",
        "state": "NY", "zip": "10001", "website_source": "example.com",
        "phone_number": "212-555-1234", "gender": "M", "dob": "1985-01-01",
        "registration_date": "2023-01-01", "valid": "1", "extra": "",
        "email_id": "e1", "ethnicity": "White", "ownrent": "Own",
        "domain": "example.com", "main_interest": "tech", "sub_interest": "mobile",
        "latitude": "40.7128", "longitude": "-74.0060", "uploaded": "2023-01-01",
        "country": "US", "websource_id": "1", "interest_ids": "1,2",
        "DNC": "0", "source": "web", "first_name_norm": "john",
        "last_name_norm": "smith", "zip_norm": "10001",
    }
    row.update(overrides)
    return row


class TestFirstNameCleaningCandidate:
    def setup_method(self):
        self.rule = FirstNameCleaningCandidate()

    def test_valid_name(self):
        assert self.rule.execute(_make_row()) == 0

    def test_suspicious_test(self):
        assert self.rule.execute(_make_row(first_name="test")) == 1

    def test_suspicious_fake(self):
        assert self.rule.execute(_make_row(first_name="fake")) == 1

    def test_suspicious_xxx(self):
        assert self.rule.execute(_make_row(first_name="xxx")) == 1

    def test_suspicious_admin(self):
        assert self.rule.execute(_make_row(first_name="admin")) == 1

    def test_suspicious_null(self):
        assert self.rule.execute(_make_row(first_name="null")) == 1

    def test_suspicious_asdf(self):
        assert self.rule.execute(_make_row(first_name="asdf")) == 1

    def test_empty_name(self):
        assert self.rule.execute(_make_row(first_name="")) == 0

    def test_rule_id(self):
        assert self.rule.rule_id == "first_name_cleaning_candidate"

    def test_rule_version(self):
        assert self.rule.rule_version == "1.0.0"

    def test_has_hash(self):
        assert len(self.rule.hash) == 64

    def test_has_sql_template(self):
        sql = self.rule.execute_sql_template()
        assert "SELECT" in sql
        assert "first_name_cleaning_candidate" in sql

    def test_has_description(self):
        assert len(self.rule.description()) > 10


class TestLastNameCleaningCandidate:
    def setup_method(self):
        self.rule = LastNameCleaningCandidate()

    def test_valid_name(self):
        assert self.rule.execute(_make_row()) == 0

    def test_suspicious_dummy(self):
        assert self.rule.execute(_make_row(last_name="dummy")) == 1

    def test_suspicious_zzz(self):
        assert self.rule.execute(_make_row(last_name="zzz")) == 1

    def test_suspicious_test(self):
        assert self.rule.execute(_make_row(last_name="test")) == 1

    def test_empty_name(self):
        assert self.rule.execute(_make_row(last_name="")) == 0

    def test_rule_id(self):
        assert self.rule.rule_id == "last_name_cleaning_candidate"


class TestNameCleaningCandidate:
    def setup_method(self):
        self.rule = NameCleaningCandidate()

    def test_different_names(self):
        assert self.rule.execute(_make_row()) == 0

    def test_same_first_last(self):
        assert self.rule.execute(_make_row(first_name="John", last_name="John")) == 1

    def test_both_empty(self):
        assert self.rule.execute(_make_row(first_name="", last_name="")) == 0

    def test_both_single_char(self):
        assert self.rule.execute(_make_row(first_name="A", last_name="B")) == 1


class TestEmailBlank:
    def setup_method(self):
        self.rule = EmailBlank()

    def test_valid_email(self):
        assert self.rule.execute(_make_row()) == 0

    def test_blank_email(self):
        assert self.rule.execute(_make_row(email_address="")) == 1

    def test_whitespace_email(self):
        assert self.rule.execute(_make_row(email_address="   ")) == 1

    def test_none_email(self):
        assert self.rule.execute(_make_row(email_address=None)) == 1


class TestEmailSyntaxFailure:
    def setup_method(self):
        self.rule = EmailSyntaxFailure()

    def test_valid_email(self):
        assert self.rule.execute(_make_row()) == 0

    def test_no_at(self):
        assert self.rule.execute(_make_row(email_address="not-an-email")) == 1

    def test_missing_local(self):
        assert self.rule.execute(_make_row(email_address="@example.com")) == 1

    def test_blank_email_not_flagged(self):
        assert self.rule.execute(_make_row(email_address="")) == 0

    def test_double_at(self):
        assert self.rule.execute(_make_row(email_address="a@@b.com")) == 1

    def test_no_tld(self):
        assert self.rule.execute(_make_row(email_address="user@nodomain")) == 1


class TestProposedEmailExportEligible:
    def setup_method(self):
        self.rule = ProposedEmailExportEligible()

    def test_valid_email_eligible(self):
        assert self.rule.execute(_make_row()) == 1

    def test_blank_email_not_eligible(self):
        assert self.rule.execute(_make_row(email_address="")) == 0

    def test_malformed_not_eligible(self):
        assert self.rule.execute(_make_row(email_address="not-valid")) == 0


class TestZipStateAssessable:
    def setup_method(self):
        self.rule = ZipStateAssessable()

    def test_ny_10001_assessable(self):
        assert self.rule.execute(_make_row()) == 1

    def test_empty_zip_not_assessable(self):
        assert self.rule.execute(_make_row(zip="")) == 0

    def test_empty_state_not_assessable(self):
        assert self.rule.execute(_make_row(state="")) == 0

    def test_unknown_state_not_assessable(self):
        assert self.rule.execute(_make_row(state="XX")) == 0


class TestGeographyMismatchCandidate:
    def setup_method(self):
        self.rule = GeographyMismatchCandidate()

    def test_ny_10001_no_mismatch(self):
        assert self.rule.execute(_make_row()) == 0

    def test_ca_with_fl_zip_mismatch(self):
        assert self.rule.execute(_make_row(state="CA", zip="32001")) == 1

    def test_ny_with_ca_zip_mismatch(self):
        assert self.rule.execute(_make_row(state="NY", zip="90210")) == 1

    def test_empty_zip_no_mismatch(self):
        assert self.rule.execute(_make_row(zip="")) == 0

    def test_empty_state_no_mismatch(self):
        assert self.rule.execute(_make_row(state="")) == 0


class TestRuleRegistry:
    def setup_method(self):
        self.rr = RuleRegistry.create_default()

    def test_create_default_has_8_rules(self):
        assert self.rr.count == 8

    def test_validate_passes(self):
        valid, errors, warnings = self.rr.validate()
        assert valid
        assert errors == []

    def test_get_all_rules_returns_8(self):
        assert len(self.rr.get_all_rules()) == 8

    def test_get_rule_hashes(self):
        hashes = self.rr.get_rule_hashes()
        assert len(hashes) == 8
        for h in hashes.values():
            assert len(h) == 64

    def test_get_sql_templates(self):
        templates = self.rr.get_sql_templates()
        assert len(templates) == 8

    def test_compute_registry_hash(self):
        h = self.rr.compute_registry_hash()
        assert len(h) == 64

    def test_execute_all_returns_8_flags(self):
        row = _make_row()
        flags = self.rr.execute_all(row)
        assert len(flags) == 8
        for v in flags.values():
            assert v in (0, 1)

    def test_duplicate_rule_id_different_version_raises(self):
        from data_quality_platform.rules.registry import RuleRegistryError
        rr = RuleRegistry()
        r1 = FirstNameCleaningCandidate()
        class FakeV2Rule(FirstNameCleaningCandidate):
            @property
            def rule_version(self): return "2.0.0"
        r2 = FakeV2Rule()
        rr.register(r1)
        with pytest.raises(RuleRegistryError):
            rr.register(r2)

    def test_idempotent_reregistration(self):
        rr = RuleRegistry()
        r1 = FirstNameCleaningCandidate()
        r2 = FirstNameCleaningCandidate()
        rr.register(r1)
        rr.register(r2)  # same id and version, should not raise
        assert rr.count == 1
