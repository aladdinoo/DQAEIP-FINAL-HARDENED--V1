"""GAP-01 path-collision guard tests.

The engine's ``validate()`` method raises ``ValueError`` if the input
and output paths resolve to the same file. This prevents accidental
destruction of the input file.

Test cases (8):
  1. Same exact path
  2. Relative vs absolute (same file)
  3. Normalized path (with '..' components)
  4. Different paths (no error)
  5. Existing different output (no error, output overwritten)
  6. Direct engine invocation (guard works without CLI)
  7. Input SHA preservation (input not modified by failed run)
  8. Symlink alias (symlink to input as output → collision detected)
"""

import os
import subprocess
import sys
import tempfile

import pytest

from data_quality_platform.validation.engine import ValidationEngine
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.generation.synthetic import SyntheticDataGenerator

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def _make_csv(path, rows=10):
    SyntheticDataGenerator(seed=42).generate(rows, str(path))


class TestGap01PathCollision:
    def test_1_same_exact_path(self, tmp_path):
        p = tmp_path / "same.csv"
        _make_csv(p)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t1", evidence_dir=str(tmp_path / "ev"))
        with pytest.raises(ValueError, match="Input and output paths must refer"):
            engine.validate(csv_path=str(p), output_path=str(p))

    def test_2_relative_vs_absolute(self, tmp_path):
        p = tmp_path / "rel.csv"
        _make_csv(p)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t2", evidence_dir=str(tmp_path / "ev"))
        # Same file, one relative, one absolute.
        cwd = os.getcwd()
        try:
            os.chdir(str(tmp_path))
            with pytest.raises(ValueError):
                engine.validate(csv_path="rel.csv", output_path=str(p.resolve()))
        finally:
            os.chdir(cwd)

    def test_3_normalized_path(self, tmp_path):
        p = tmp_path / "norm.csv"
        _make_csv(p)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t3", evidence_dir=str(tmp_path / "ev"))
        # Path with redundant '..' components resolving to the same file.
        parent = os.path.dirname(str(p))
        name = os.path.basename(str(p))
        weird = os.path.join(parent, "..", os.path.basename(parent), name)
        with pytest.raises(ValueError):
            engine.validate(csv_path=str(p), output_path=weird)

    def test_4_different_paths_no_error(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _make_csv(inp)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t4", evidence_dir=str(tmp_path / "ev"))
        result = engine.validate(csv_path=str(inp), output_path=str(out))
        assert result.success

    def test_5_existing_different_output_overwritten(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        out.write_text("old content")
        _make_csv(inp)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t5", evidence_dir=str(tmp_path / "ev"))
        result = engine.validate(csv_path=str(inp), output_path=str(out))
        assert result.success
        # Output was overwritten with the new content.
        with open(out) as f:
            assert "old content" not in f.read()

    def test_6_direct_engine_invocation_guard_works(self, tmp_path):
        """The guard works even when the engine is called directly
        (not via the CLI). This is the last line of defense."""
        p = tmp_path / "direct.csv"
        _make_csv(p)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t6", evidence_dir=str(tmp_path / "ev"))
        with pytest.raises(ValueError):
            engine.validate(csv_path=str(p), output_path=str(p))

    def test_7_input_sha_preservation_on_collision(self, tmp_path):
        """When a collision is detected, the input file is NOT modified."""
        p = tmp_path / "preserve.csv"
        _make_csv(p)
        import hashlib
        sha_before = hashlib.sha256(open(p, "rb").read()).hexdigest()
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t7", evidence_dir=str(tmp_path / "ev"))
        with pytest.raises(ValueError):
            engine.validate(csv_path=str(p), output_path=str(p))
        sha_after = hashlib.sha256(open(p, "rb").read()).hexdigest()
        assert sha_before == sha_after, "input file was modified during collision"

    def test_8_symlink_alias(self, tmp_path):
        """A symlink pointing to the input file, used as the output path,
        must be detected as a collision."""
        p = tmp_path / "real.csv"
        _make_csv(p)
        link = tmp_path / "link.csv"
        try:
            os.symlink(str(p), str(link))
        except OSError:
            pytest.skip("cannot create symlink on this platform")
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="t8", evidence_dir=str(tmp_path / "ev"))
        with pytest.raises(ValueError):
            engine.validate(csv_path=str(p), output_path=str(link))
