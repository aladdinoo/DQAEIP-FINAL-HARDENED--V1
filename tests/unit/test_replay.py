"""Deterministic replay tests (DQAVP hardening, Section 8)."""

import csv

import pytest

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.validation.replay import (
    ReplayMismatch, replay_dataset, replay_report_from_paths,
)


def _make_csv(path, n=40):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SOURCE_COLUMNS)
        for i in range(1, n + 1):
            row = {c: "" for c in SOURCE_COLUMNS}
            row.update({
                "id": str(i),
                "first_name": "Test" if i % 7 == 0 else "Alice",
                "last_name": "User" if i % 7 == 0 else f"Last{i}",
                "email_address": "" if i % 5 == 0 else f"u{i}@x.co",
                "zip": "90210" if i % 3 == 0 else "10001",
                "state": "CA" if i % 3 == 0 else "NY",
                "source": "web", "country": "US",
            })
            w.writerow([row[c] for c in SOURCE_COLUMNS])
    return str(path)


class TestDeterministicReplay:
    def test_two_runs_are_fully_deterministic(self, tmp_path):
        src = _make_csv(tmp_path / "in.csv")
        report = replay_dataset(src, runs=2, work_dir=str(tmp_path))
        assert report["replay_verified"] is True
        assert report["byte_identical_output"] is True
        assert report["runs"] == 2
        assert report["input_row_count"] == 40
        assert len(report["executions"]) == 2
        e1, e2 = report["executions"]
        assert e1["output_sha256"] == e2["output_sha256"]
        assert e1["rule_versions"] == e2["rule_versions"]
        assert e1["rule_hashes"] == e2["rule_hashes"]
        assert e1["flag_counts"] == e2["flag_counts"]

    def test_source_preserved_across_replays(self, tmp_path):
        import hashlib
        src = _make_csv(tmp_path / "in.csv")
        before = hashlib.sha256(open(src, "rb").read()).hexdigest()
        replay_dataset(src, runs=3, work_dir=str(tmp_path))
        after = hashlib.sha256(open(src, "rb").read()).hexdigest()
        assert before == after

    def test_replay_fails_closed_on_non_determinism(self, tmp_path):
        """A registry factory returning a different rule HASH on the
        second run must fail the replay (rule_hashes differ)."""
        from data_quality_platform.rules.registry import RuleRegistry

        calls = {"n": 0}

        class FakeRule:
            rule_id = "email_blank"
            rule_version = "1.0.0"

            def __init__(self):
                calls["n"] += 1
                self._hash = f"{'0' * 63}{calls['n']}"

            @property
            def hash(self):
                return self._hash

            def execute(self, row):
                return 0

            def execute_sql_template(self):
                return ""

            def description(self):
                return ""

        def factory():
            r = RuleRegistry.create_default()
            r._rules["email_blank"] = FakeRule()
            return r

        src = _make_csv(tmp_path / "in.csv")
        with pytest.raises(ReplayMismatch):
            replay_dataset(src, runs=2, work_dir=str(tmp_path),
                           registry_factory=factory)

    def test_non_raising_report_variant(self, tmp_path):
        src = _make_csv(tmp_path / "in.csv")
        report = replay_report_from_paths(src, str(tmp_path), runs=2)
        assert report["replay_verified"] is True

    def test_replay_requires_two_runs(self, tmp_path):
        src = _make_csv(tmp_path / "in.csv")
        with pytest.raises(ValueError):
            replay_dataset(src, runs=1, work_dir=str(tmp_path))
