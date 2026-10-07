"""External evidence-root anchor tests (F-003 hardening).

These tests prove that ``verify_evidence_root_with_external_anchor`` and
the underlying ``verify_evidence_root(expected_root=...)`` mechanism
implement EXTERNALLY ANCHORED evidence authentication (in contrast to
the directory's own self-recorded root hash, which is only
TAMPER-EVIDENT under an attacker-controlled evidence directory).

The seven verification points required by the hardening spec:

1.  Valid evidence + correct external expected_root → PASS
2.  Modified evidence + unchanged expected_root → FAIL
3.  Replaced evidence directory + unchanged expected_root → FAIL
4.  Wrong expected_root → FAIL
5.  Missing expected_root → fail closed (protected mode)
6.  Existing legitimate evidence continues to pass
7.  Existing tests remain valid (covered by test_evidence_root.py)
"""

import json
import os
import shutil

import pytest

from data_quality_platform.validation.evidence_root import (
    CORE_ARTIFACTS,
    EVIDENCE_ROOT_FILENAME,
    compute_evidence_root,
    verify_evidence_root,
    verify_evidence_root_with_external_anchor,
    write_evidence_root,
)


@pytest.fixture
def evidence_dir(tmp_path):
    d = tmp_path / "evd"
    d.mkdir()
    payloads = {
        "manifest.json": {"run_id": "r1", "kind": "engine_run_manifest",
                          "rows": 10},
        "output.csv": "id,email\n1,a@example.com\n",
        "lineage.json": {"run_id": "r1", "row_records": [],
                         "total_row_records": 0, "truncated": False},
        "audit.json": {"events": ["e1", "e2"]},
        "monitoring.json": {"score": 0.98},
        "alerts.json": {"alerts": []},
    }
    for name, payload in payloads.items():
        with open(d / name, "w", encoding="utf-8") as f:
            if name.endswith(".json"):
                json.dump(payload, f)
            else:
                f.write(payload)
    return d


# ── Point 1: valid evidence + correct external expected_root → PASS ──

def test_external_anchor_correct_root_passes(evidence_dir):
    record = write_evidence_root(str(evidence_dir))
    external_root = record["root_sha256"]
    ok, details = verify_evidence_root_with_external_anchor(
        str(evidence_dir), external_root)
    assert ok, details
    assert details["expected_root"] == external_root
    assert details["current_root"] == external_root
    assert details["anchor_state"] == "verified"


# ── Point 2: modified evidence + unchanged expected_root → FAIL ──────

def test_external_anchor_modified_evidence_fails(evidence_dir):
    record = write_evidence_root(str(evidence_dir))
    external_root = record["root_sha256"]
    # Tamper with an artifact.
    original = (evidence_dir / "audit.json").read_text(encoding="utf-8")
    (evidence_dir / "audit.json").write_text(
        original + "TAMPERED", encoding="utf-8")
    ok, details = verify_evidence_root_with_external_anchor(
        str(evidence_dir), external_root)
    assert not ok
    assert details["expected_root"] == external_root
    assert details["current_root"] != external_root


# ── Point 3: replaced evidence directory + unchanged expected_root ──

def test_external_anchor_replaced_directory_fails(evidence_dir, tmp_path):
    record = write_evidence_root(str(evidence_dir))
    external_root = record["root_sha256"]
    # Replace the directory entirely with a different (legitimate but
    # distinct) evidence set, then re-write its root. The external
    # anchor must still detect the replacement.
    new_dir = tmp_path / "replaced"
    new_dir.mkdir()
    payloads = {
        "manifest.json": {"run_id": "r2", "kind": "engine_run_manifest",
                          "rows": 999},
        "output.csv": "id,email\n9,z@other.com\n",
        "lineage.json": {"run_id": "r2", "row_records": [],
                         "total_row_records": 0, "truncated": False},
        "audit.json": {"events": ["x"]},
        "monitoring.json": {"score": 0.5},
        "alerts.json": {"alerts": ["hi"]},
    }
    for name, payload in payloads.items():
        with open(new_dir / name, "w", encoding="utf-8") as f:
            if name.endswith(".json"):
                json.dump(payload, f)
            else:
                f.write(payload)
    # write a fresh root for the replacement directory — but the external
    # anchor is the OLD root, so verification must fail.
    write_evidence_root(str(new_dir))
    ok, details = verify_evidence_root_with_external_anchor(
        str(new_dir), external_root)
    assert not ok
    assert details["expected_root"] == external_root
    assert details["current_root"] != external_root


# ── Point 4: wrong expected_root → FAIL ─────────────────────────────

def test_external_anchor_wrong_root_fails(evidence_dir):
    write_evidence_root(str(evidence_dir))
    wrong = "0" * 64
    ok, details = verify_evidence_root_with_external_anchor(
        str(evidence_dir), wrong)
    assert not ok
    assert "root hash mismatch" in (details.get("inner_reason") or "")
    assert details["expected_root"] == wrong


# ── Point 5: missing expected_root → fail closed ────────────────────

@pytest.mark.parametrize("bad", [None, "", "abc", "g" * 64, 64, [], {}])
def test_external_anchor_missing_or_malformed_fails_closed(evidence_dir, bad):
    write_evidence_root(str(evidence_dir))
    ok, details = verify_evidence_root_with_external_anchor(
        str(evidence_dir), bad)
    assert not ok
    assert details["anchor_state"] in ("missing_or_malformed", "non_hex")


# ── Point 6: existing legitimate evidence continues to pass ──────────

def test_legacy_verify_evidence_root_still_passes_without_anchor(evidence_dir):
    """Existing callers that don't supply an expected_root must continue
    to work — the protected-mode helper is OPT-IN."""
    record = write_evidence_root(str(evidence_dir))
    # The legacy function call (no expected_root) still works.
    ok, _ = verify_evidence_root(str(evidence_dir))
    assert ok
    # And explicitly None does NOT break the legacy function.
    ok, _ = verify_evidence_root(str(evidence_dir), expected_root=None)
    assert ok
    # The recorded root hash equals the externally computable one.
    assert record["root_sha256"] == compute_evidence_root(
        str(evidence_dir))["root_sha256"]


# ── Point 7: existing tests remain valid ─────────────────────────────
# (Covered by tests/unit/test_evidence_root.py — no duplication here.)


# ── Additional: missing root file with external anchor → fail closed

def test_external_anchor_missing_root_file_fails(evidence_dir):
    # No write_evidence_root call — root file is absent.
    external_root = "a" * 64
    ok, details = verify_evidence_root_with_external_anchor(
        str(evidence_dir), external_root)
    assert not ok
    assert "missing evidence_root.json" in (details.get("inner_reason") or "")
