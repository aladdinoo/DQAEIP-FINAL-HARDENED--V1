"""Golden fixture integrity tests (Phase 3 remediation).

These tests pin the STRUCTURAL and ORACLE integrity of the golden fixtures:

    tests/golden/golden_cases.csv      (input rows + inline expected annotations)
    tests/golden/expected_results.csv  (authoritative expected flag values)
    tests/golden/geography_edge_cases.csv (geography edge fixture)

They exist because the historical suite tolerated two structurally corrupted
rows (GC022: 46 fields, GC050: 45 fields) whose shifted DictReader views were
silently codified into expected_results.csv. Structural integrity is now a
tested contract, not an assumption.

These tests consume the production rule registry directly (no duplicated
implementation) — the same oracle the golden case tests use.

Known carried conflict (NOT a failure, pinned deliberately):
    geography_mismatch_candidate for GC011/GC037/GC050 (TX 733xx ZIPs):
    expected_results.csv = 1 (legacy 2-digit prefix map assigns 73 -> OK),
    golden_cases.csv inline annotations = 0 (real-world Austin TX intent).
    Resolution belongs to the canonical geography remediation (Phase 6).
"""

import csv
import os

import pytest

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.rules import RuleRegistry

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
GOLDEN_DIR = os.path.join(PROJECT_ROOT, "tests", "golden")
GOLDEN_CASES = os.path.join(GOLDEN_DIR, "golden_cases.csv")
EXPECTED_RESULTS = os.path.join(GOLDEN_DIR, "expected_results.csv")
GEOGRAPHY_EDGES = os.path.join(GOLDEN_DIR, "geography_edge_cases.csv")

EXPECTED_HEADER = [
    "case_id", "description", "id", "email_address", "first_name", "last_name",
    "address", "city", "county_name", "state", "zip", "website_source",
    "phone_number", "gender", "dob", "registration_date", "valid", "extra",
    "email_id", "ethnicity", "ownrent", "domain", "main_interest",
    "sub_interest", "latitude", "longitude", "uploaded", "country",
    "websource_id", "interest_ids", "DNC", "source", "first_name_norm",
    "last_name_norm", "zip_norm",
    "expected_first_name_cleaning_candidate",
    "expected_last_name_cleaning_candidate",
    "expected_name_cleaning_candidate",
    "expected_email_blank",
    "expected_email_syntax_failure",
    "expected_proposed_email_export_eligible",
    "expected_zip_state_assessable",
    "expected_geography_mismatch_candidate",
]

GOLDEN_CASE_COUNT = 50
GOLDEN_HEADER_WIDTH = 43

RULE_SEQUENCE = [
    "first_name_cleaning_candidate", "last_name_cleaning_candidate",
    "name_cleaning_candidate", "email_blank", "email_syntax_failure",
    "proposed_email_export_eligible", "zip_state_assessable",
    "geography_mismatch_candidate",
]

# Deliberately carried inline-vs-file conflict pending canonical geography:
# {case_id: (rule_id, inline_value, file_value)}
CARRIED_GEOGRAPHY_CONFLICTS = {
    "GC011": ("geography_mismatch_candidate", "0", "1"),
    "GC037": ("geography_mismatch_candidate", "0", "1"),
    "GC050": ("geography_mismatch_candidate", "0", "1"),
}


# ---------------------------------------------------------------------------
# Strict loaders (no silent None/overflow tolerance)
# ---------------------------------------------------------------------------


def _load_raw_rows(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.reader(f))
    return rows[0], rows[1:]


def _load_strict_dictrows(path):
    """DictReader load that FAILS on restval (short rows) or restkey (long rows)."""
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    for index, row in enumerate(rows, start=2):
        assert None not in row.values(), (
            f"{os.path.basename(path)} line {index} ({row.get('case_id')}): row is "
            f"missing fields (restval None) — structurally malformed"
        )
        assert row.get(None) is None, (
            f"{os.path.basename(path)} line {index} ({row.get('case_id')}): row has "
            f"extra fields (restkey overflow {row.get(None)!r}) — structurally malformed"
        )
    return rows


@pytest.fixture(scope="module")
def golden_raw():
    return _load_raw_rows(GOLDEN_CASES)


@pytest.fixture(scope="module")
def golden_rows(golden_raw):
    return golden_raw[1]


@pytest.fixture(scope="module")
def expected_rows():
    return _load_strict_dictrows(EXPECTED_RESULTS)


@pytest.fixture(scope="module")
def registry():
    return RuleRegistry.create_default()


# ---------------------------------------------------------------------------
# 1. Exactly 50 cases
# ---------------------------------------------------------------------------


def test_golden_cases_exactly_50(golden_rows):
    assert len(golden_rows) == GOLDEN_CASE_COUNT


# ---------------------------------------------------------------------------
# 2 + 6. Every row structurally valid — no malformed rows remain
# ---------------------------------------------------------------------------


def test_header_contract(golden_raw):
    header, _ = golden_raw
    assert header == EXPECTED_HEADER
    assert len(header) == GOLDEN_HEADER_WIDTH
    # the 33 rule-input columns must be exactly the production SOURCE_COLUMNS
    assert header[2:35] == list(SOURCE_COLUMNS)


def test_every_row_has_correct_field_count(golden_raw):
    header, rows = golden_raw
    malformed = [
        {"line": index + 1, "case_id": row[0] if row else "<empty>",
         "fields": len(row)}
        for index, row in enumerate(rows) if len(row) != len(header)
    ]
    assert malformed == [], f"malformed rows remain: {malformed}"


def test_no_row_loads_with_silent_none_or_overflow():
    """The exact historical failure mode: DictReader silently mapped the
    shifted GC022/GC050 rows and the suite stayed green. Must never regress."""
    _load_strict_dictrows(GOLDEN_CASES)  # raises on any None restval / restkey


# ---------------------------------------------------------------------------
# 3. Unique case IDs + canonical order (pins positional test access)
# ---------------------------------------------------------------------------


def test_case_ids_unique_and_sequential(golden_rows):
    ids = [row[0] for row in golden_rows]
    assert len(ids) == len(set(ids)), "duplicate case IDs present"
    assert ids == [f"GC{n:03d}" for n in range(1, GOLDEN_CASE_COUNT + 1)], (
        "case IDs are not the canonical GC001..GC050 sequence — positional "
        "indexing in test_golden_cases.py would silently test wrong rows"
    )


# ---------------------------------------------------------------------------
# 4 + 5. expected_results matches 1:1
# ---------------------------------------------------------------------------


def test_expected_results_match_golden_case_ids(golden_rows, expected_rows):
    golden_ids = [row[0] for row in golden_rows]
    expected_ids = [row["case_id"] for row in expected_rows]
    assert len(expected_ids) == len(set(expected_ids)), "duplicate expected IDs"
    assert set(golden_ids) == set(expected_ids)
    assert len(golden_ids) == len(expected_ids)


def test_every_golden_case_has_exactly_one_expected_result(golden_rows,
                                                           expected_rows):
    expected_by_id = {}
    for row in expected_rows:
        cid = row["case_id"]
        assert cid not in expected_by_id, f"{cid} has duplicate expected result"
        expected_by_id[cid] = row
    for cid in (row[0] for row in golden_rows):
        assert cid in expected_by_id, f"{cid} has no expected result"


# ---------------------------------------------------------------------------
# 7. Expected values conform to the authoritative rule contract
# ---------------------------------------------------------------------------


def test_expected_values_conform_to_rule_contract(golden_raw, expected_rows,
                                                  registry):
    """Run the real implementation on every (repaired) golden row and compare
    every expected flag. The only permitted deviations are the pinned carried
    geography conflicts (see module docstring)."""
    header, rows = golden_raw
    expected_by_id = {row["case_id"]: row for row in expected_rows}
    deviations = []
    for row in rows:
        cid = row[0]
        case_input = {col: row[2 + idx] for idx, col in enumerate(header[2:35])}
        flags = registry.execute_all(case_input)
        exp = expected_by_id[cid]
        for position, rule_id in enumerate(RULE_SEQUENCE):
            file_value = exp[f"expected_{rule_id}"]
            impl_value = str(flags[rule_id])
            if file_value != impl_value:
                carried = CARRIED_GEOGRAPHY_CONFLICTS.get(cid)
                if carried and carried[0] == rule_id:
                    assert carried[1] == row[35 + position], (
                        f"{cid}: inline annotation changed unexpectedly — "
                        f"update CARRIED_GEOGRAPHY_CONFLICTS deliberately"
                    )
                    continue
                deviations.append(f"{cid}/{rule_id}: file={file_value} impl={impl_value}")
    assert deviations == [], (
        f"expected_results.csv deviates from the rule contract: {deviations}"
    )


def test_inline_annotations_consistent_except_carried_conflicts(golden_raw,
                                                                expected_rows):
    header, rows = golden_raw
    expected_by_id = {row["case_id"]: row for row in expected_rows}
    contradictions = []
    for row in rows:
        cid = row[0]
        exp = expected_by_id[cid]
        for position, rule_id in enumerate(RULE_SEQUENCE):
            inline_value = row[35 + position]
            file_value = exp[f"expected_{rule_id}"]
            if inline_value != file_value:
                carried = CARRIED_GEOGRAPHY_CONFLICTS.get(cid)
                if carried and carried[0] == rule_id:
                    continue
                contradictions.append(
                    f"{cid}/{rule_id}: inline={inline_value} file={file_value}"
                )
    assert contradictions == [], (
        f"unexpected inline-vs-file contradictions: {contradictions}"
    )


# ---------------------------------------------------------------------------
# 8. Golden tests genuinely consume golden_cases.csv
# ---------------------------------------------------------------------------


def test_golden_test_loader_targets_this_fixture():
    """Pin the loader paths used by test_golden_cases.py so the oracle chain
    (golden_cases.csv -> rule execution -> expected_results.csv) cannot be
    silently repointed."""
    source = open(
        os.path.join(GOLDEN_DIR, "test_golden_cases.py"), encoding="utf-8"
    ).read()
    assert '"golden_cases.csv"' in source or "'golden_cases.csv'" in source
    assert '"expected_results.csv"' in source or "'expected_results.csv'" in source


def test_positional_access_alignment(golden_rows, registry, expected_rows):
    """test_golden_cases.py accesses rows positionally (cases[0] -> GC001 etc.).
    Pin that each position maps to the intended case and passes its spot-check
    assertions, so reordering can never silently change what is tested."""
    positions = {0: "GC001", 1: "GC002", 2: "GC003", 4: "GC005", 7: "GC008",
                 10: "GC011", 12: "GC013", 18: "GC019"}
    expected_by_id = {row["case_id"]: row for row in expected_rows}
    for index, cid in positions.items():
        assert golden_rows[index][0] == cid
        flags = registry.execute_all(
            {col: golden_rows[index][2 + i] for i, col in enumerate(SOURCE_COLUMNS)}
        )
        exp = expected_by_id[cid]
        for rule_id in RULE_SEQUENCE:
            # the individual spot-check tests only assert the flags below
            asserted = {
                "GC001": ["first_name_cleaning_candidate", "email_blank",
                          "proposed_email_export_eligible"],
                "GC002": ["email_blank", "proposed_email_export_eligible"],
                "GC003": ["email_syntax_failure", "proposed_email_export_eligible"],
                "GC005": ["first_name_cleaning_candidate"],
                "GC008": ["last_name_cleaning_candidate"],
                "GC011": ["name_cleaning_candidate"],
                "GC019": ["geography_mismatch_candidate"],
                "GC013": ["proposed_email_export_eligible"],
            }[cid]
            if rule_id in asserted:
                assert flags[rule_id] == int(exp[f"expected_{rule_id}"]), (
                    f"positional case {cid} (cases[{index}]) fails its "
                    f"spot-check on {rule_id}"
                )


# ---------------------------------------------------------------------------
# 9. expected_results cannot silently substitute for malformed input
#    (covered by test_no_row_loads_with_silent_none_or_overflow +
#     test_every_row_has_correct_field_count; this test pins the strict
#     loader contract itself on a deliberately malformed probe)
# ---------------------------------------------------------------------------


def test_strict_loader_rejects_malformed_probe(tmp_path):
    """Prove the strict loader contract actually detects corruption — i.e. it
    would have caught the historical GC022/GC050 defect."""
    probe = tmp_path / "probe.csv"
    with open(GOLDEN_CASES, encoding="utf-8") as src, \
            open(probe, "w", encoding="utf-8", newline="") as dst:
        lines = src.read().splitlines()
        # recreate the historical GC022 corruption: drop the empty last_name
        fields = lines[22].split(",")
        assert fields[0] == "GC022"
        del fields[5]  # remove last_name -> shifts everything left
        lines[22] = ",".join(fields)
        dst.write("\n".join(lines) + "\n")
    with pytest.raises(AssertionError, match="GC022.*missing fields"):
        _load_strict_dictrows(str(probe))


# ---------------------------------------------------------------------------
# 10. Deterministic rerun
# ---------------------------------------------------------------------------


def test_golden_evaluation_deterministic(golden_raw, expected_rows, registry):
    header, rows = golden_raw
    expected_by_id = {row["case_id"]: row for row in expected_rows}

    def evaluate():
        return [
            (row[0], tuple(
                str(registry.execute_all(
                    {col: row[2 + idx] for idx, col in enumerate(header[2:35])
                     })[rule_id])
                for rule_id in RULE_SEQUENCE))
            for row in rows
        ]

    first = evaluate()
    second = evaluate()
    assert first == second
    # and every result matches the expected file (modulo carried conflicts)
    for cid, values in first:
        exp = expected_by_id[cid]
        for rule_id, value in zip(RULE_SEQUENCE, values):
            if cid in CARRIED_GEOGRAPHY_CONFLICTS and \
                    CARRIED_GEOGRAPHY_CONFLICTS[cid][0] == rule_id:
                continue
            assert value == exp[f"expected_{rule_id}"]


# ---------------------------------------------------------------------------
# Geography edge cases fixture (Phase 3 STEP 7)
# ---------------------------------------------------------------------------


def test_geography_edge_cases_structurally_valid():
    header, rows = _load_raw_rows(GEOGRAPHY_EDGES)
    assert header == ["case_id", "description", "id", "email_address",
                      "first_name", "last_name", "state", "zip",
                      "expected_zip_state_assessable",
                      "expected_geography_mismatch_candidate"]
    assert len(rows) == 20
    ids = [r[0] for r in rows]
    assert ids == [f"GEO{n:03d}" for n in range(1, 21)]
    assert all(len(r) == len(header) for r in rows)
    _load_strict_dictrows(GEOGRAPHY_EDGES)  # no None restval / restkey overflow


def test_geography_edge_cases_expectations_conform_to_implementation(registry):
    """First automated consumption of geography_edge_cases.csv (historically it
    was only presence-checked, never executed against the rules)."""
    header, rows = _load_raw_rows(GEOGRAPHY_EDGES)
    col = {name: index for index, name in enumerate(header)}
    for row in rows:
        flags = registry.execute_all(
            {"state": row[col["state"]], "zip": row[col["zip"]]}
        )
        assert flags["zip_state_assessable"] == int(row[col["expected_zip_state_assessable"]]), \
            f"{row[0]}: zip_state_assessable"
        assert flags["geography_mismatch_candidate"] == int(row[col["expected_geography_mismatch_candidate"]]), \
            f"{row[0]}: geography_mismatch_candidate"
