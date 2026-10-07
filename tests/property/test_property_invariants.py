"""Property-Based Invariant Tests (DQAVP enterprise hardening, Section 8).

Deterministic seeded property battery over the FROZEN V1 rule contract.
Every property below is derived from the EXISTING implementation
semantics (data_quality_platform/rules/v1_rules.py) — none of these
tests invent new business behavior:

P1  flag domain            every rule returns exactly 0 or 1 for any row
P2  assessability guard    zip_state_assessable=0 implies
                           geography_mismatch_candidate=0
P3  mismatch implication    geography_mismatch_candidate=1 implies
                           zip_state_assessable=1
P4  email pair             blank email implies syntax_failure=0 and
                           export_eligible=0; non-blank email implies
                           exactly one of them is 1 (they partition on
                           the same regex)
P5  column independence    perturbing columns outside a rule's input
                           set never changes that rule's decision
P6  determinism            identical rows evaluated by fresh registry
                           instances produce identical flags
P7  registry shape         execute_all returns exactly the 8 required
                           rule ids, each an int
P8  malformed safety       adversarial values (None, wrong types, huge
                           strings, unicode, control chars) never raise
                           and still produce {0,1}
P9  engine determinism     the full engine produces byte-identical
                           output files for two independent executions
                           over the same deterministic input

The row battery is generated from a FIXED seed — the suite is itself
deterministic (a property-testing style without external fuzzing
dependencies; divergence from expected behavior always reproduces).
"""

import csv
import random

import pytest

from data_quality_platform.contracts import (
    REQUIRED_RULE_IDS, SOURCE_COLUMNS, STATE_ZIP_PREFIXES,
    SUSPICIOUS_NAME_PATTERNS,
)
from data_quality_platform.rules.registry import RuleRegistry

SEED = 20260915
N_ROWS = 2500

NAME_RULES = {
    "first_name_cleaning_candidate": ("first_name",),
    "last_name_cleaning_candidate": ("last_name",),
    "name_cleaning_candidate": ("first_name", "last_name"),
}
EMAIL_RULES = {
    "email_blank": ("email_address",),
    "email_syntax_failure": ("email_address",),
    "proposed_email_export_eligible": ("email_address",),
}
GEO_RULES = {
    "zip_state_assessable": ("zip", "state"),
    "geography_mismatch_candidate": ("zip", "state"),
}

VALID_STATES = sorted(STATE_ZIP_PREFIXES)


def build_row_pool(rng):
    """Adversarial-but-deterministic value pools per logical column."""
    normal_names = ["Alice", "Bob", "Charlie", "Dana", "Eve", "Frank",
                    "Grace", "Heidi", "Ivan", "Judy"]
    weird_names = (
        ["", "   ", "\t", "Test", "FAKE", "dummy", "xXx", "null", "N/A",
         "unknown", "example", "sample", "asdf", "qwerty"]
        + [p for p in SUSPICIOUS_NAME_PATTERNS if isinstance(p, str)]
        + ["Jean-Luc", "O'Brien", "Anna-Marie", "A", "B", "aa", "zzzz",
           "J0hn", "Mary@Ann", "Ünal", "日本太郎", "x" * 300,
           "name\nwith\nnewlines", "  padded  ", "lead ", " trail"]
    )
    valid_emails = [
        "alice@example.com", "bob@test.org", "carol@mail.com",
        "dave@web.net", "erin@company.co", "frank@business.io",
        "UPPER@EXAMPLE.COM", "first.last+tag@sub.example.org",
        "a1b2c3@x-y-z.example.com",
    ]
    invalid_emails = [
        "", "   ", "not-an-email", "@missing-local.com", "no-at-sign",
        "spaces in@email.com", "double@@at.com", "trailing@dot.",
        ".leading.dot@x.com", "a@b..co", "a b@c.com", "user@",
        "@", "a@b", "a@b.c", "ünïcode@exämple.com", "a@" + "x" * 300,
    ]
    # zip/state combos: matching, mismatching, unknown, malformed
    zip_state_pairs = []
    for _ in range(120):
        state = rng.choice(VALID_STATES)
        prefixes = STATE_ZIP_PREFIXES[state]
        matching = rng.choice(prefixes) + f"{rng.randint(0, 999):03d}"
        zip_state_pairs.append((matching, state))
        other = rng.choice(VALID_STATES)
        zip_state_pairs.append(
            (rng.choice(STATE_ZIP_PREFIXES[other]) + "001", state))
    zip_state_pairs += [
        ("90210", "CA"), ("73301", "TX"), ("10001", "NY"),
        ("", "CA"), ("   ", "TX"), ("12345", ""), ("12345", "  "),
        ("12345", "ZZ"), ("12345", "zz"), ("12345", "Puerto Rico"),
        ("1234", "NY"), ("123456", "NY"), ("abcde", "NY"),
        ("12 45", "NY"), (" 12345", "CA"), (None, "CA"), ("12345", None),
        ("0" * 12, "CA"), ("99999-9999", "CA"), ("  ", "  "),
    ]
    fillers = ["", "   ", "value", "123", None, "1234567890",
               "x" * 200, "line1\nline2"]

    def pick_name():
        return rng.choice(normal_names + weird_names)

    def pick_email():
        return rng.choice(valid_emails + invalid_emails)

    def pick_pair():
        return rng.choice(zip_state_pairs)

    rows = []
    for i in range(N_ROWS):
        z, s = pick_pair()
        rows.append({
            "id": f"row-{i}",
            "email_address": pick_email(),
            "first_name": pick_name(),
            "last_name": pick_name(),
            "zip": z,
            "state": s,
            "phone_number": rng.choice(
                ["555-0100", "555-0101", "5550102", "(555) 010-3103",
                 "", "   ", "not-a-phone"]),
            "address": rng.choice(fillers),
            "city": rng.choice(["Springfield", "", "NYC", None]),
            "country": rng.choice(["US", "", "CA", None]),
            "some_extra": rng.choice(fillers),
        })
    # hard edge cases that must always be present
    rows.append({"id": "edge-1", "email_address": None,
                 "first_name": None, "last_name": None,
                 "zip": None, "state": None})
    rows.append({"id": "edge-2", "email_address": 12345,
                 "first_name": 99, "last_name": [],
                 "zip": {"z": 1}, "state": ("TX",)})
    rows.append({"id": "edge-3", "email_address": "\x00ctrl",
                 "first_name": "rtl", "last_name": "zwsp",
                 "zip": "00000", "state": "MA"})
    return rows


@pytest.fixture(scope="module")
def row_pool():
    return build_row_pool(random.Random(SEED))


@pytest.fixture(scope="module")
def registry():
    return RuleRegistry.create_default()


def flags_of(registry, row):
    return registry.execute_all(row)


# ---------------------------------------------------------------- P1
def test_p1_flag_domain(row_pool, registry):
    """Every rule emits exactly {0,1} for every row in the battery."""
    for row in row_pool:
        flags = flags_of(registry, row)
        for rule_id, value in flags.items():
            assert value in (0, 1), (
                f"rule {rule_id} emitted {value!r} for row "
                f"{row.get('id')!r}")


# ---------------------------------------------------------------- P2
def test_p2_assessable_zero_implies_mismatch_zero(row_pool, registry):
    """zip_state_assessable=0 => geography_mismatch_candidate=0."""
    for row in row_pool:
        flags = flags_of(registry, row)
        if flags["zip_state_assessable"] == 0:
            assert flags["geography_mismatch_candidate"] == 0, (
                f"mismatch without assessability on row "
                f"{row.get('id')!r}: {row.get('zip')!r} / "
                f"{row.get('state')!r}")


# ---------------------------------------------------------------- P3
def test_p3_mismatch_one_implies_assessable_one(row_pool, registry):
    """geography_mismatch_candidate=1 => zip_state_assessable=1."""
    seen = 0
    for row in row_pool:
        flags = flags_of(registry, row)
        if flags["geography_mismatch_candidate"] == 1:
            seen += 1
            assert flags["zip_state_assessable"] == 1, (
                f"mismatch flagged on non-assessable row "
                f"{row.get('id')!r}")
    assert seen > 0, "battery failed to exercise any mismatch=1 case"


# ---------------------------------------------------------------- P4
def test_p4_email_rule_pair_partition(row_pool, registry):
    """Frozen V1 email semantics, verified as two properties:

    (a) CSV-domain rows (email_address is a str): blank email implies
        email_blank=1 and syntax_failure=0 and export_eligible=0; a
        non-blank email implies email_blank=0 and EXACTLY ONE of
        syntax_failure / export_eligible is 1 (both rules evaluate the
        same frozen regex with opposite polarity).

    (b) FROZEN coercion characteristic (pinned, NOT changed): an
        explicit None email — which CANNOT occur in CSV input, where
        values are always strings — is counted blank by email_blank
        (None check) while email_syntax_failure coerces str(None) to
        the non-empty string "None" and flags it (regex mismatch).
        This asymmetry is existing V1 behavior and is preserved
        as-is; documenting it here prevents accidental "fixes".
    """
    non_blank = 0
    for row in row_pool:
        flags = flags_of(registry, row)
        email = row.get("email_address")
        if not isinstance(email, str):
            # out-of-CSV-domain: pin the frozen None coercion exactly
            if email is None:
                assert flags["email_blank"] == 1
                assert flags["email_syntax_failure"] == 1
                assert flags["proposed_email_export_eligible"] == 0
            continue
        blank = email.strip() == ""
        if blank:
            assert flags["email_blank"] == 1
            assert flags["email_syntax_failure"] == 0
            assert flags["proposed_email_export_eligible"] == 0
        else:
            non_blank += 1
            assert flags["email_blank"] == 0
            assert (flags["email_syntax_failure"]
                    + flags["proposed_email_export_eligible"]) == 1
    assert non_blank > 0


# ---------------------------------------------------------------- P5
def test_p5_column_independence(row_pool, registry):
    """Perturbing columns outside a rule's input set never changes
    that rule's decision (verified for all 8 rules)."""
    rng = random.Random(SEED + 1)
    inputs = {}
    inputs.update(NAME_RULES)
    inputs.update(EMAIL_RULES)
    inputs.update(GEO_RULES)

    perturbation_values = {
        "first_name": ["Zack", "Yara", "  ", "Ünal", "Q"],
        "last_name": ["Quinn", "Perez", "", "O'Hara", "W"],
        "email_address": ["zack@example.com", "", "bad@@x.com",
                          "yara@test.org", "   "],
        "zip": ["99999", "10001", "", "00000", "73301"],
        "state": ["AK", "tx", "", "ZZ", "NY"],
    }

    checked = 0
    for row in row_pool:
        base = flags_of(registry, row)
        for col, values in perturbation_values.items():
            if col not in row:
                continue
            for new_value in values:
                perturbed = dict(row)
                perturbed[col] = new_value
                new_flags = flags_of(registry, perturbed)
                for rule_id, cols in inputs.items():
                    if col not in cols:
                        checked += 1
                        assert new_flags[rule_id] == base[rule_id], (
                            f"rule {rule_id} changed when unrelated "
                            f"column {col!r} changed on row "
                            f"{row.get('id')!r}")
    assert checked > 1000, f"only {checked} independence checks ran"


# ---------------------------------------------------------------- P6
def test_p6_determinism_fresh_registries(row_pool):
    """Identical rows through FRESH registry instances -> identical
    flags (rule evaluation is a pure function of the row)."""
    rng = random.Random(SEED + 2)
    sample = rng.sample(row_pool, min(300, len(row_pool)))
    for row in sample:
        a = flags_of(RuleRegistry.create_default(), row)
        b = flags_of(RuleRegistry.create_default(), row)
        assert a == b


# ---------------------------------------------------------------- P7
def test_p7_registry_output_shape(row_pool, registry):
    """execute_all returns exactly the 8 required rule ids, ints."""
    for row in row_pool:
        flags = flags_of(registry, row)
        assert set(flags) == set(REQUIRED_RULE_IDS)
        assert all(isinstance(v, int) for v in flags.values())


# ---------------------------------------------------------------- P8
def test_p8_malformed_values_fail_safely(row_pool, registry):
    """Adversarial values never raise; every flag stays in {0,1}."""
    adversarial = [
        {"id": "a1", "email_address": 3.14, "first_name": True,
         "last_name": {"k": "v"}, "zip": [1, 2], "state": 77},
        {"id": "a2", "email_address": "bytes@x.com",
         "first_name": " " * 1000, "last_name": "\x01\x02\x03",
         "zip": "\n\n", "state": "\t"},
        {"id": "a3", "email_address": "a" * 500 + "@x.com",
         "first_name": "Élan", "last_name": "Ω",
         "zip": "1" * 50, "state": "T" * 50},
        {"id": "a4", "email_address": "ok@example.com",
         "first_name": "Anne", "last_name": "Anne",
         "zip": "73301", "state": "TX"},
    ]
    for row in adversarial + row_pool[:200]:
        flags = flags_of(registry, row)  # must not raise
        for v in flags.values():
            assert v in (0, 1)


# ---------------------------------------------------------------- P9
def test_p9_engine_determinism(tmp_path):
    """Full engine over the same deterministic CSV twice -> byte
    identical outputs and identical flag counts."""
    from data_quality_platform.validation.engine import ValidationEngine

    rng = random.Random(SEED + 3)
    pool = build_row_pool(rng)[:400]
    csv_path = tmp_path / "property_input.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(SOURCE_COLUMNS)
        for row in pool:
            writer.writerow([
                str(row.get(col, "")) if row.get(col) is not None else ""
                for col in SOURCE_COLUMNS])

    outs, counts = [], []
    for run in (1, 2):
        out_path = tmp_path / f"property_output_{run}.csv"
        evd = tmp_path / f"property_evidence_{run}"
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id=f"property_{run}",
            evidence_dir=str(evd),
        )
        result = engine.validate(str(csv_path), str(out_path))
        assert result.success, f"engine run {run} failed: {result.error}"
        outs.append(out_path.read_bytes())
        counts.append(dict(result.flag_counts))

    assert outs[0] == outs[1], "engine output not byte-identical"
    assert counts[0] == counts[1]
