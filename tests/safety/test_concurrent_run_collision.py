"""Concurrent-run collision prevention tests (CHANGE 2).

Proves that the hardened execution boundary's atomic evidence-directory
claim prevents two simultaneous runs from silently re-using the same
run directory.

Required verification points:

1.  First run succeeds (atomic claim creates the directory).
2.  Second simultaneous run cannot silently reuse the same run directory.
3.  No last-writer-wins behavior.
4.  No evidence mixing (first run's artifacts are NOT overwritten).
5.  Existing legitimate single-run behavior remains unchanged.
"""

import os
import shutil
import threading

import pytest

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.config import PlatformConfig
from data_quality_platform.generation.synthetic import SyntheticDataGenerator
from data_quality_platform.hardening.authorization import observe_scope
from data_quality_platform.hardening.pipeline import (
    _default_reference_data_paths,
    _default_software_paths,
    _v1_rules_path,
    run_validation,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def _build_grant(csv_path, config):
    return observe_scope(
        input_path=csv_path,
        authorized_columns=SOURCE_COLUMNS,
        v1_rules_path=_v1_rules_path(),
        reference_data_paths=_default_reference_data_paths(),
        config=config,
        execution_mode="validation",
        software_paths=_default_software_paths(),
    )


def _config():
    return PlatformConfig.from_yaml(
        os.path.join(PROJECT_ROOT, "configs", "quality.yaml")).as_dict()


class TestConcurrentRunCollisionPrevention:

    def test_first_run_succeeds(self, tmp_path):
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=1).generate(50, csv_path)
        ev = str(tmp_path / "ev")
        out = str(tmp_path / "out.csv")
        granted = _build_grant(csv_path, _config())
        result = run_validation(
            input_path=csv_path, output_path=out, evidence_dir=ev,
            run_id="first", granted_scope=granted, config=_config())
        assert result.passed, result.reasons
        assert os.path.isdir(ev)
        # Evidence artifacts landed in the claimed directory.
        assert os.path.isfile(os.path.join(ev, "manifest.json"))
        assert os.path.isfile(os.path.join(ev, "evidence_root.json"))

    def test_second_run_collides_and_fails_closed(self, tmp_path):
        """A second run against the same evidence_dir fails closed."""
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=1).generate(50, csv_path)
        ev = str(tmp_path / "ev")
        out = str(tmp_path / "out.csv")
        granted = _build_grant(csv_path, _config())
        r1 = run_validation(
            input_path=csv_path, output_path=out, evidence_dir=ev,
            run_id="first", granted_scope=granted, config=_config())
        assert r1.passed

        # Second run: same evidence_dir, different output path.
        out2 = str(tmp_path / "out2.csv")
        r2 = run_validation(
            input_path=csv_path, output_path=out2, evidence_dir=ev,
            run_id="second", granted_scope=granted, config=_config())
        assert not r2.passed, "second run must fail closed"
        assert r2.details.get("stopped_at") == "evidence-dir-collision"
        assert any("already exists" in r for r in r2.reasons), r2.reasons

    def test_no_last_writer_wins(self, tmp_path):
        """The first run's manifest must NOT be overwritten by run 2."""
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=1).generate(50, csv_path)
        ev = str(tmp_path / "ev")
        out = str(tmp_path / "out.csv")
        granted = _build_grant(csv_path, _config())
        r1 = run_validation(
            input_path=csv_path, output_path=out, evidence_dir=ev,
            run_id="first", granted_scope=granted, config=_config())
        assert r1.passed

        manifest_path = os.path.join(ev, "manifest.json")
        with open(manifest_path, "r", encoding="utf-8") as f:
            first_manifest = f.read()

        # Attempted second run — must fail closed.
        out2 = str(tmp_path / "out2.csv")
        run_validation(
            input_path=csv_path, output_path=out2, evidence_dir=ev,
            run_id="second", granted_scope=granted, config=_config())

        # Verify the first manifest is unchanged.
        with open(manifest_path, "r", encoding="utf-8") as f:
            second_manifest = f.read()
        assert first_manifest == second_manifest, (
            "second run overwrote the first run's manifest "
            "(last-writer-wins bug)")

    def test_no_evidence_mixing(self, tmp_path):
        """A second run cannot write any artifact into the first run's dir."""
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=1).generate(50, csv_path)
        ev = str(tmp_path / "ev")
        out = str(tmp_path / "out.csv")
        granted = _build_grant(csv_path, _config())
        run_validation(
            input_path=csv_path, output_path=out, evidence_dir=ev,
            run_id="first", granted_scope=granted, config=_config())

        # Snapshot the file set after run 1.
        files_after_run1 = set(os.listdir(ev))

        # Attempt run 2 — must fail closed before writing anything.
        out2 = str(tmp_path / "out2.csv")
        run_validation(
            input_path=csv_path, output_path=out2, evidence_dir=ev,
            run_id="second", granted_scope=granted, config=_config())

        # The snapshot directory (.snapshots) is created during run 2's
        # attempt but is cleaned up in the finally block; the file set
        # should be identical.
        files_after_run2 = set(os.listdir(ev))
        # Allow the hardened_execution_report.json to be updated (it is
        # written by the CLI wrapper, not by run_validation itself; but
        # if invoked directly, no report is written here).
        # Inside run_validation, NO artifacts from run 2 should be present.
        assert files_after_run1 == files_after_run2, (
            f"run 2 modified the evidence dir: "
            f"added={files_after_run2 - files_after_run1}, "
            f"removed={files_after_run1 - files_after_run2}")

    def test_existing_single_run_behavior_unchanged(self, tmp_path):
        """A fresh evidence_dir is claimed exactly as before — no regression."""
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=2).generate(30, csv_path)
        ev = str(tmp_path / "fresh")
        out = str(tmp_path / "out.csv")
        granted = _build_grant(csv_path, _config())
        result = run_validation(
            input_path=csv_path, output_path=out, evidence_dir=ev,
            run_id="fresh", granted_scope=granted, config=_config())
        assert result.passed
        assert os.path.isdir(ev)
        # The directory must NOT have been pre-existing — it was created
        # by the atomic makedirs call.
        # (Implicit: if it had pre-existed, run_validation would have
        # failed closed, which we already verified.)

    def test_concurrent_threads_one_wins_one_fails(self, tmp_path):
        """Two concurrent threads sharing the same evidence_dir: exactly one
        wins the atomic claim; the other fails closed. No evidence mixing."""
        csv_path = str(tmp_path / "input.csv")
        SyntheticDataGenerator(seed=3).generate(50, csv_path)
        ev = str(tmp_path / "ev")
        granted = _build_grant(csv_path, _config())
        config = _config()

        results = {}
        errors = []

        def _run(label, out_name):
            try:
                results[label] = run_validation(
                    input_path=csv_path,
                    output_path=str(tmp_path / out_name),
                    evidence_dir=ev,
                    run_id=f"thread_{label}",
                    granted_scope=granted,
                    config=config,
                )
            except Exception as exc:
                errors.append((label, repr(exc)))

        t1 = threading.Thread(target=_run, args=("A", "outA.csv"))
        t2 = threading.Thread(target=_run, args=("B", "outB.csv"))
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert not errors, errors
        # Exactly one must pass, the other must fail with collision.
        passed = [k for k, r in results.items() if r.passed]
        failed = [k for k, r in results.items() if not r.passed]
        assert len(passed) == 1, f"expected exactly 1 pass, got {passed}"
        assert len(failed) == 1, f"expected exactly 1 fail, got {failed}"
        loser = results[failed[0]]
        assert loser.details.get("stopped_at") == "evidence-dir-collision", (
            loser.details)
