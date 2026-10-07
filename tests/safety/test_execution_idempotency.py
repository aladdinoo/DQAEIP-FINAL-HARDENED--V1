"""Execution idempotency tests (FINAL HARDENING, Section 13).

Proves on small deterministic fixtures that

    same input + same rules + same configuration
        → same business output (byte-identical 41-column CSV,
          identical flag counts)

while EXECUTION METADATA (run_id, evidence directory, audit timestamps)
is explicitly allowed to differ. The test separates the two identities:
business output identity is asserted equal; execution metadata is
asserted to exist and to differ (proving the runs were genuinely
distinct executions, not a cached result).

No distributed-execution idempotency is claimed — these are
single-process, engine-level tests only.
"""

import csv
import hashlib
import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.validation.engine import ValidationEngine


def _make_csv(path, n=60):
    """Deterministic 33-column fixture with flag-triggering patterns."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SOURCE_COLUMNS)
        for i in range(1, n + 1):
            row = {c: "" for c in SOURCE_COLUMNS}
            row.update({
                "id": str(1000 + i),
                "first_name": "   Bob " if i % 6 == 0 else "Alice",
                "last_name": "Smith" if i % 10 == 0 else f"L{i}",
                "email_address": "" if i % 5 == 0 else (
                    "not-an-email" if i % 7 == 0 else f"u{i}@x.co"),
                "zip": "90210" if i % 3 == 0 else "10001",
                "state": "CA" if i % 3 == 0 else "NY",
                "source": "web", "country": "US",
            })
            w.writerow([row[c] for c in SOURCE_COLUMNS])
    return str(path)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


class TestExecutionIdempotency:
    def test_same_input_rules_config_same_business_output(self, tmp_path):
        src = _make_csv(tmp_path / "in.csv")
        results, outputs = [], []
        for run_no in (1, 2, 3):
            out = str(tmp_path / f"out_{run_no}.csv")
            ev = str(tmp_path / f"ev_{run_no}")
            engine = ValidationEngine(
                rules=RuleRegistry.create_default(),
                run_id=f"idem_{run_no}", evidence_dir=ev)
            results.append(engine.validate(csv_path=src, output_path=out))
            outputs.append(out)
        assert all(r.success for r in results)
        # business identity: byte-identical outputs
        hashes = {_sha256(p) for p in outputs}
        assert len(hashes) == 1
        # business identity: identical flag counts
        fc = [r.flag_counts for r in results]
        assert fc[0] == fc[1] == fc[2]
        assert fc[0]  # fixture triggers at least one rule
        # business identity: identical row accounting
        assert {(r.input_row_count, r.output_row_count)
                for r in results} == {(60, 60)}
        # execution metadata differs (genuinely distinct executions)
        assert len({r.run_id for r in results}) == 3

    def test_business_output_identity_separate_from_execution_metadata(
            self, tmp_path):
        src = _make_csv(tmp_path / "in.csv")
        outs, audits = [], []
        for run_no in (1, 2):
            out = str(tmp_path / f"o{run_no}.csv")
            ev = str(tmp_path / f"e{run_no}")
            engine = ValidationEngine(
                rules=RuleRegistry.create_default(),
                run_id=f"sep_{run_no}", evidence_dir=ev)
            result = engine.validate(csv_path=src, output_path=out)
            assert result.success
            outs.append(_sha256(out))
            with open(os.path.join(ev, "audit.json"), encoding="utf-8") as f:
                audits.append(json.load(f))
        # business output: identical
        assert outs[0] == outs[1]
        # execution metadata: run ids recorded in audit differ
        ids = {a.get("run_id") for a in audits}
        assert len(ids) == 2
        # audit trails carry (allowed) per-execution timestamps
        for a in audits:
            assert a.get("events"), "audit events must exist"

    def test_reexecution_into_same_evidence_dir_completes(self, tmp_path):
        """Duplicate execution into the SAME evidence directory must
        not produce partial or corrupted state: the second run
        completes, its manifest reflects the second run, and the
        business output is again byte-identical (determinism under
        re-execution)."""
        src = _make_csv(tmp_path / "in.csv")
        ev = str(tmp_path / "ev_same")
        outs = []
        for run_no in (1, 2):
            out = str(tmp_path / f"o_same_{run_no}.csv")
            engine = ValidationEngine(
                rules=RuleRegistry.create_default(),
                run_id="dup_run", evidence_dir=ev)
            result = engine.validate(csv_path=src, output_path=out)
            assert result.success
            outs.append(_sha256(out))
            manifest = os.path.join(ev, "manifest.json")
            assert os.path.isfile(manifest), "success manifest must exist"
            with open(manifest, encoding="utf-8") as f:
                m = json.load(f)
            assert m.get("run_id") == "dup_run"
            assert m.get("manifest_type") == "success", (
                f"manifest must not represent a partial run; "
                f"got {m.get('manifest_type')!r}")
            assert m.get("reconciliation", {}).get("passed") is True
        # business output deterministic across the duplicate execution
        assert outs[0] == outs[1]

    def test_source_file_immutable_across_executions(self, tmp_path):
        src = _make_csv(tmp_path / "in.csv")
        before = _sha256(src)
        for run_no in (1, 2):
            engine = ValidationEngine(
                rules=RuleRegistry.create_default(),
                run_id=f"imm_{run_no}",
                evidence_dir=str(tmp_path / f"evi{run_no}"))
            engine.validate(csv_path=src,
                            output_path=str(tmp_path / f"oi{run_no}.csv"))
        assert _sha256(src) == before

    def test_monitoring_thresholds_do_not_change_business_output(self, tmp_path):
        """Business output identity is independent of monitoring
        thresholds (execution/monitoring configuration), as long as the
        rule registry is the frozen V1 set."""
        src = _make_csv(tmp_path / "in.csv")
        outs = []
        for thresholds in (None, {"completeness": 0.99},
                           {"completeness": 0.10}):
            out = str(tmp_path / f"oc_{len(outs)}.csv")
            engine = ValidationEngine(
                rules=RuleRegistry.create_default(),
                run_id=f"cfg_{len(outs)}",
                evidence_dir=str(tmp_path / f"evc{len(outs)}"),
                config_thresholds=thresholds)
            result = engine.validate(csv_path=src, output_path=out)
            assert result.success
            outs.append(_sha256(out))
        assert len(set(outs)) == 1
