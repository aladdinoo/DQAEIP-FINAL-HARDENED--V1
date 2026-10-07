"""Failure / recovery fail-closed battery (FINAL HARDENING, Section 14).

Controlled failure injection on ISOLATED SYNTHETIC FIXTURES ONLY
(never real data). Required behavior for every scenario: FAIL CLOSED —
no partial success may ever be represented as PASS.

Covered scenarios (complementing the existing schema-failure and
input-contract tests):

    F1  output write failure       (output parent is a regular file)
    F2  evidence persistence fail  (read-only evidence directory)
    F3  mid-stream engine failure  (injected per-row exception ->
                                    failure manifest, no success manifest)
    F4  interrupted execution      (KeyboardInterrupt mid-stream ->
                                    propagates, no success manifest)
    F5  corrupted evidence         (tampered manifest rejected by the
                                    strict evidence validator)
"""

import csv
import json
import os

import stat
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.validation.engine import ValidationEngine


def _make_csv(path, n=40):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SOURCE_COLUMNS)
        for i in range(1, n + 1):
            row = {c: "" for c in SOURCE_COLUMNS}
            row.update({
                "id": str(2000 + i),
                "first_name": "Alice", "last_name": f"L{i}",
                "email_address": "" if i % 5 == 0 else f"u{i}@x.co",
                "zip": "10001", "state": "NY",
                "source": "web", "country": "US",
            })
            w.writerow([row[c] for c in SOURCE_COLUMNS])
    return str(path)


class _ExplodingRegistry:
    """Wraps the frozen V1 registry; raises from execute_all at a chosen
    data-row index. Used ONLY inside tests to simulate a mid-stream
    engine failure — the V1 rule code itself is untouched."""

    def __init__(self, inner, fail_at_row):
        self._inner = inner
        self._fail_at_row = fail_at_row
        self._seen = 0

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def execute_all(self, row):
        self._seen += 1
        if self._seen == self._fail_at_row:
            raise RuntimeError(
                f"INJECTED mid-stream failure at data row "
                f"{self._fail_at_row}")
        return self._inner.execute_all(row)


def _manifest_type(ev_dir):
    p = os.path.join(ev_dir, "manifest.json")
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f).get("manifest_type")


class TestWriteFailuresFailClosed:
    def test_f1_output_write_failure_blocks_run(self, tmp_path):
        """Output parent path is a regular file: the engine must fail
        closed — success=False, no success manifest."""
        src = _make_csv(tmp_path / "in.csv")
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        ev = str(tmp_path / "ev")
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="f1", evidence_dir=ev)
        result = engine.validate(
            csv_path=src, output_path=str(blocker / "out.csv"))
        assert result.success is False
        assert result.error
        assert _manifest_type(ev) in (None, "failure")
        assert _manifest_type(ev) != "success"

    def test_f2_readonly_evidence_dir_blocks_success(self, tmp_path):
        """Evidence persistence failure (read-only evidence directory)
        must downgrade the run: success=False; a success manifest must
        never appear."""
        src = _make_csv(tmp_path / "in.csv")
        ev = tmp_path / "ev_ro"
        ev.mkdir()
        os.chmod(ev, stat.S_IRUSR | stat.S_IXUSR)
        try:
            engine = ValidationEngine(
                rules=RuleRegistry.create_default(),
                run_id="f2", evidence_dir=str(ev))
            result = engine.validate(
                csv_path=src, output_path=str(tmp_path / "out.csv"))
            assert result.success is False
            assert _manifest_type(str(ev)) != "success"
        finally:
            os.chmod(ev, stat.S_IRWXU)  # restore for tmp cleanup


class TestMidStreamFailuresFailClosed:
    def test_f3_midstream_failure_writes_failure_manifest(self, tmp_path):
        src = _make_csv(tmp_path / "in.csv")
        ev = str(tmp_path / "ev_f3")
        registry = _ExplodingRegistry(RuleRegistry.create_default(),
                                      fail_at_row=15)
        engine = ValidationEngine(rules=registry, run_id="f3",
                                  evidence_dir=ev)
        result = engine.validate(csv_path=src,
                                 output_path=str(tmp_path / "o3.csv"))
        assert result.success is False
        assert "INJECTED" in (result.error or "")
        # GAP-02: atomic output publication means NO partial output
        # file appears at the final path on failure. The temp file is
        # cleaned up and the final output_path is never touched.
        out = tmp_path / "o3.csv"
        assert not out.exists()
        # The failure is still recorded in evidence:
        assert _manifest_type(ev) == "failure"
        audit = json.load(open(os.path.join(ev, "audit.json"),
                               encoding="utf-8"))
        events = audit.get("events", [])
        assert any(e.get("event_type") == "run_failed"
                   for e in events), events

    def test_f4_keyboard_interrupt_propagates_no_success_manifest(
            self, tmp_path):
        """An interrupted execution (KeyboardInterrupt is a
        BaseException, deliberately NOT swallowed by the engine) must
        propagate and leave NO success manifest behind."""
        src = _make_csv(tmp_path / "in.csv")
        ev = str(tmp_path / "ev_f4")
        registry = _ExplodingRegistry(RuleRegistry.create_default(),
                                      fail_at_row=10)

        def raise_interrupt(row):
            raise KeyboardInterrupt("simulated operator interrupt")

        registry.execute_all = raise_interrupt
        engine = ValidationEngine(rules=registry, run_id="f4",
                                  evidence_dir=ev)
        with pytest.raises(KeyboardInterrupt):
            engine.validate(csv_path=src,
                            output_path=str(tmp_path / "o4.csv"))
        assert _manifest_type(ev) != "success"

    def test_f5_corrupted_success_manifest_rejected(self, tmp_path):
        """A tampered (corrupted) success manifest must invalidate the
        tamper-evident evidence root — fail closed."""
        from data_quality_platform.validation.evidence_root import (
            write_evidence_root, verify_evidence_root,
        )
        src = _make_csv(tmp_path / "in.csv")
        ev = str(tmp_path / "ev_f5")
        out = str(tmp_path / "o5.csv")
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="f5", evidence_dir=ev)
        result = engine.validate(csv_path=src, output_path=out)
        assert result.success is True
        # Stamp the evidence root AFTER the engine writes the manifest.
        write_evidence_root(ev, output_csv=out)
        ok, _ = verify_evidence_root(ev, output_csv=out)
        assert ok is True

        # Corrupt the manifest after the root was written.
        manifest_path = os.path.join(ev, "manifest.json")
        doc = json.load(open(manifest_path, encoding="utf-8"))
        doc["source_row_count"] = doc["source_row_count"] + 1
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        ok, details = verify_evidence_root(ev, output_csv=out)
        assert ok is False, "tampered manifest must be detected"
        assert "root hash mismatch" in details.get("reason", "") \
            or "artifact hash changed" in details.get("reason", "")

    def test_f5b_tampered_output_hash_rejected(self, tmp_path):
        """Modified output bytes (hash mismatch vs root) must be
        rejected by the tamper-evident evidence root."""
        from data_quality_platform.validation.evidence_root import (
            write_evidence_root, verify_evidence_root,
        )
        src = _make_csv(tmp_path / "in.csv")
        ev = str(tmp_path / "ev_f5b")
        out = str(tmp_path / "o5b.csv")
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="f5b", evidence_dir=ev)
        result = engine.validate(csv_path=src, output_path=out)
        assert result.success is True
        write_evidence_root(ev, output_csv=out)
        ok, _ = verify_evidence_root(ev, output_csv=out)
        assert ok is True
        # Tamper the output by appending bytes.
        with open(out, "a", encoding="utf-8") as f:
            f.write("tamper,appendix,row\n")
        ok, details = verify_evidence_root(ev, output_csv=out)
        assert ok is False, "tampered output must be detected"
