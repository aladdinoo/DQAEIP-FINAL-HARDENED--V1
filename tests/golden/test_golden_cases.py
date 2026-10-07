import csv
import pytest
import os
from data_quality_platform.rules import RuleRegistry
from data_quality_platform.contracts import SOURCE_COLUMNS


def _load_golden_cases():
    """Load golden test cases from CSV."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(project_root, "tests", "golden", "golden_cases.csv")
    rows = []
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def _load_expected_results():
    """Load expected results from CSV."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(project_root, "tests", "golden", "expected_results.csv")
    results = {}
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            results[row["case_id"]] = row
    return results


class TestGoldenCases:
    """Golden tests: verify every V1 rule against 50 pre-defined cases."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.cases = _load_golden_cases()
        self.expected = _load_expected_results()
        self.rr = RuleRegistry.create_default()

    def test_has_50_cases(self):
        assert len(self.cases) >= 45, f"Expected 45+ cases, got {len(self.cases)}"

    def test_gc001_valid_row(self):
        row = {col: self.cases[0].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        exp = self.expected["GC001"]
        assert flags["first_name_cleaning_candidate"] == int(exp["expected_first_name_cleaning_candidate"])
        assert flags["email_blank"] == int(exp["expected_email_blank"])
        assert flags["proposed_email_export_eligible"] == int(exp["expected_proposed_email_export_eligible"])

    def test_gc002_blank_email(self):
        row = {col: self.cases[1].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        assert flags["email_blank"] == 1
        assert flags["proposed_email_export_eligible"] == 0

    def test_gc003_malformed_email(self):
        row = {col: self.cases[2].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        assert flags["email_syntax_failure"] == 1
        assert flags["proposed_email_export_eligible"] == 0

    def test_gc005_suspicious_first_name(self):
        row = {col: self.cases[4].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        assert flags["first_name_cleaning_candidate"] == 1

    def test_gc008_suspicious_last_name(self):
        row = {col: self.cases[7].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        assert flags["last_name_cleaning_candidate"] == 1

    def test_gc011_same_name(self):
        row = {col: self.cases[10].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        assert flags["name_cleaning_candidate"] == 1

    def test_gc019_zip_state_mismatch(self):
        row = {col: self.cases[18].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        assert flags["geography_mismatch_candidate"] == 1

    def test_gc013_email_export_eligible(self):
        row = {col: self.cases[12].get(col, "") for col in SOURCE_COLUMNS}
        flags = self.rr.execute_all(row)
        assert flags["proposed_email_export_eligible"] == 1

    def test_all_50_cases_all_rules(self):
        """Comprehensive: run all 50 cases through all 8 rules and compare with expected."""
        failures = []
        for case in self.cases:
            case_id = case["case_id"]
            if case_id not in self.expected:
                failures.append(f"{case_id}: no expected results")
                continue
            row = {col: case.get(col, "") for col in SOURCE_COLUMNS}
            flags = self.rr.execute_all(row)
            exp = self.expected[case_id]
            for rule_id, val in flags.items():
                exp_key = f"expected_{rule_id}"
                if exp_key in exp:
                    expected_val = int(exp[exp_key])
                    if val != expected_val:
                        failures.append(f"{case_id}/{rule_id}: got {val}, expected {expected_val}")
        if failures:
            pytest.fail(f"{len(failures)} golden case failures:\n" + "\n".join(failures[:10]))