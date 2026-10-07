"""DL001-DL015 canonical geography acceptance tests.

ACCEPTANCE EVIDENCE PROVENANCE (authoritative, do not edit the semantics):
The case table lives in tests/golden/dl_geography_cases.csv and MUST be
supplied verbatim by the repo owner as external acceptance evidence. It is
NEVER reconstructed from GEO001-GEO020, golden_cases.csv, or any other
fixture. Until that file exists, every test in this module skips with an
explicit reason.

Test groups
-----------
A. Structural acceptance (runs as soon as the authoritative CSV exists):
   15 cases DL001-DL015, required canonical_* columns, boolean values, the
   canonical invariant mismatch == assessable AND state != resolved, and the
   DL013 non-defect control guard.

B. Canonical behavior (gated on the canonical geography implementation being
   explicitly authorized and merged): asserts the canonical_* expectations of
   every DL case against data_quality_platform.rules.geography_canonical.

C. Current-vs-canonical divergence evidence (runs as soon as the CSV exists):
   executes the CURRENT v1 prefix-map classes (ZipStateAssessable /
   GeographyMismatchCandidate) directly -- deliberately not the registry, so
   this evidence stays pinned to the legacy implementation even after a
   canonical swap -- and reports the exact disagreement list. Per the
   acceptance brief, exactly 8 of the 15 cases must disagree.

Scope guard: this module touches GEOGRAPHY acceptance only. It must not be
used to change name rules (R1-R3), experiment E1, or proposal SP1.
"""

import csv
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

DL_COLUMNS_REQUIRED = [
    "case_id",
    "state",
    "zip",
    "canonical_zip_state_assessable",
    "canonical_geography_mismatch_candidate",
]
EXPECTED_CASE_IDS = [f"DL{i:03d}" for i in range(1, 16)]
EXPECTED_DISAGREEMENT_COUNT = 8  # per the authoritative acceptance brief


def _dl_csv_path():
    override = os.environ.get("DL_CASES_PATH")
    if override:
        return override
    return os.path.join(REPO_ROOT, "tests", "golden", "dl_geography_cases.csv")


def _load_dl_rows():
    path = _dl_csv_path()
    if not os.path.exists(path):
        pytest.skip(
            "Authoritative DL001-DL015 acceptance table not present at "
            f"{path}. It is external evidence to be supplied verbatim by the "
            "repo owner; it is never reconstructed from existing fixtures."
        )
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return path, rows


def _v1_geography_flags(state, zip_val):
    """Run the CURRENT (legacy) geography implementation, independent of the
    registry, so divergence evidence remains pinned to v1 even after any
    future canonical swap."""
    from data_quality_platform.rules.v1_rules import (
        GeographyMismatchCandidate,
        ZipStateAssessable,
    )

    row = {"zip": zip_val, "state": state}
    return {
        "zip_state_assessable": ZipStateAssessable().execute(row),
        "geography_mismatch_candidate": GeographyMismatchCandidate().execute(row),
    }


# ---------------------------------------------------------------------------
# Group A: structural acceptance of the authoritative table itself
# ---------------------------------------------------------------------------


class TestDLTableStructure:
    def test_table_present_with_15_cases(self):
        path, rows = _load_dl_rows()
        assert len(rows) == 15, (
            f"{path}: expected exactly 15 authoritative cases, got {len(rows)}"
        )
        ids = [r.get("case_id", "") for r in rows]
        assert ids == EXPECTED_CASE_IDS, f"case_id sequence mismatch: {ids}"

    def test_required_canonical_columns(self):
        _path, rows = _load_dl_rows()
        missing = [c for c in DL_COLUMNS_REQUIRED if c not in rows[0]]
        assert not missing, f"DL table missing required canonical columns: {missing}"

    def test_canonical_values_are_boolean(self):
        _path, rows = _load_dl_rows()
        for r in rows:
            for col in (
                "canonical_zip_state_assessable",
                "canonical_geography_mismatch_candidate",
            ):
                assert r[col] in ("0", "1"), (
                    f"{r['case_id']}.{col} must be 0 or 1, got {r[col]!r}"
                )

    def test_canonical_invariant_mismatch_implies_assessable(self):
        _path, rows = _load_dl_rows()
        for r in rows:
            a = int(r["canonical_zip_state_assessable"])
            m = int(r["canonical_geography_mismatch_candidate"])
            assert not (m == 1 and a == 0), (
                f"{r['case_id']}: canonical mismatch=1 requires assessable=1 "
                "(mismatch = assessable AND row state != canonical resolved state)"
            )

    def test_dl013_is_non_defect_control(self):
        _path, rows = _load_dl_rows()
        dl013 = [r for r in rows if r["case_id"] == "DL013"]
        assert len(dl013) == 1, "DL013 must exist exactly once"
        assert int(dl013[0]["canonical_geography_mismatch_candidate"]) == 0, (
            "DL013 must remain a non-defect control case "
            "(canonical geography_mismatch_candidate == 0)"
        )


# ---------------------------------------------------------------------------
# Group B: canonical behavior of every DL case (gated on implementation)
# ---------------------------------------------------------------------------


class TestDLCanonicalBehavior:
    def test_all_15_cases_match_canonical(self):
        _load_dl_rows()  # enforce the skip contract even when module is absent
        geo = pytest.importorskip(
            "data_quality_platform.rules.geography_canonical",
            reason=(
                "Canonical geography implementation not merged yet. It may only "
                "be implemented after explicit authorization per the successor "
                "geography contract (SP1 stays unimplemented until then)."
            ),
        )
        _path, rows = _load_dl_rows()
        failures = []
        for r in rows:
            got = geo.evaluate_geography(row={"state": r["state"], "zip": r["zip"]})
            for col, flag_key in (
                ("canonical_zip_state_assessable", "zip_state_assessable"),
                ("canonical_geography_mismatch_candidate", "geography_mismatch_candidate"),
            ):
                want = int(r[col])
                have = int(got[flag_key])
                if have != want:
                    failures.append(
                        f"{r['case_id']}/{flag_key}: got {have}, canonical expects {want}"
                    )
        assert not failures, "Canonical acceptance failures:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# Group C: current-vs-canonical divergence evidence (legacy implementation)
# ---------------------------------------------------------------------------


class TestDLCurrentVsCanonicalDivergence:
    def test_exact_disagreements_against_v1_prefix_map(self):
        path, rows = _load_dl_rows()
        divergences = []
        for r in rows:
            cur = _v1_geography_flags(r["state"], r["zip"])
            can = {
                "zip_state_assessable": int(r["canonical_zip_state_assessable"]),
                "geography_mismatch_candidate": int(
                    r["canonical_geography_mismatch_candidate"]
                ),
            }
            fields = [
                k
                for k in can
                if cur[k] != can[k]
            ]
            if fields:
                divergences.append(
                    {
                        "case_id": r["case_id"],
                        "state": r["state"],
                        "zip": r["zip"],
                        "current": cur,
                        "canonical": can,
                        "disagreed_fields": fields,
                    }
                )

        out = os.environ.get("DL_DIVERGENCE_OUT")
        if out:
            import json

            with open(out, "w", encoding="utf-8") as fh:
                json.dump({"dl_table": path, "divergences": divergences}, fh, indent=2)

        assert len(divergences) == EXPECTED_DISAGREEMENT_COUNT, (
            "Acceptance brief asserts exactly "
            f"{EXPECTED_DISAGREEMENT_COUNT} current-vs-canonical disagreements, "
            f"but the authoritative table yields {len(divergences)}: "
            + ", ".join(d["case_id"] for d in divergences)
            + ". Reconcile the table against the brief (or the brief against "
            "the table) before proceeding."
        )
