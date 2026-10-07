"""GAP-02 atomic output publication tests.

The engine writes the output to a temp file, fsyncs it, then atomically
publishes via ``os.replace(temp, output)``. A crash or failure during
writing leaves the previous output (if any) intact and removes the temp
file. No partial output ever appears at the final output path.

Test cases (7):
  1. Successful publication (output appears)
  2. Existing output preserved after mid-stream failure
  3. Controlled write failure (monkeypatch os.replace to raise)
  4. No partial final output on failure
  5. Temp file cleaned up on failure
  6. Output SHA correctness (published output matches computed hash)
  7. GAP-01 collision guard intact (regression)
"""

import hashlib
import os
import pytest
from unittest.mock import patch

from data_quality_platform.validation.engine import ValidationEngine
from data_quality_platform.rules.registry import RuleRegistry, RuleRegistryError
from data_quality_platform.generation.synthetic import SyntheticDataGenerator
from data_quality_platform.rules.base import Rule


def _make_csv(path, rows=20):
    SyntheticDataGenerator(seed=42).generate(rows, str(path))


class _ExplodingRegistry:
    """Wraps a real registry but injects an exception at a specific row."""
    def __init__(self, real_registry, fail_at_row=10):
        self._real = real_registry
        self._fail_at = fail_at_row
        self._count = 0
        # Proxy attributes the engine needs.
        self.count = real_registry.count

    def __getattr__(self, name):
        return getattr(self._real, name)

    def execute_all(self, row):
        self._count += 1
        if self._count == self._fail_at:
            raise RuntimeError("INJECTED_FAILURE_AT_ROW_%d" % self._fail_at)
        return self._real.execute_all(row)

    def validate(self):
        return self._real.validate()

    def get_all_rules(self):
        return self._real.get_all_rules()

    def get_rule_hashes(self):
        return self._real.get_rule_hashes()

    def get_sql_templates(self):
        return self._real.get_sql_templates()

    def compute_registry_hash(self):
        return self._real.compute_registry_hash()


class TestGap02AtomicOutput:
    def test_1_successful_publication(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _make_csv(inp)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="g2_1", evidence_dir=str(tmp_path / "ev"))
        result = engine.validate(csv_path=str(inp), output_path=str(out))
        assert result.success
        assert out.exists()
        # No leftover temp files.
        temps = [f for f in os.listdir(str(tmp_path)) if f.startswith(".out.csv.") and f.endswith(".tmp")]
        assert not temps, f"leftover temp files: {temps}"

    def test_2_existing_output_preserved_after_failure(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        out.write_text("ORIGINAL_CONTENT_PRESERVED")
        _make_csv(inp)
        registry = _ExplodingRegistry(RuleRegistry.create_default(), fail_at_row=10)
        engine = ValidationEngine(
            rules=registry, run_id="g2_2",
            evidence_dir=str(tmp_path / "ev"))
        result = engine.validate(csv_path=str(inp), output_path=str(out))
        assert not result.success
        # The original output is preserved (not overwritten by partial output).
        assert "ORIGINAL_CONTENT_PRESERVED" in out.read_text()

    def test_3_controlled_write_failure(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _make_csv(inp)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="g2_3", evidence_dir=str(tmp_path / "ev"))
        # Monkeypatch os.replace to raise.
        with patch("os.replace", side_effect=OSError("INJECTED_REPLACE_FAILURE")):
            result = engine.validate(csv_path=str(inp), output_path=str(out))
        assert not result.success

    def test_4_no_partial_final_output_on_failure(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _make_csv(inp)
        registry = _ExplodingRegistry(RuleRegistry.create_default(), fail_at_row=5)
        engine = ValidationEngine(
            rules=registry, run_id="g2_4",
            evidence_dir=str(tmp_path / "ev"))
        result = engine.validate(csv_path=str(inp), output_path=str(out))
        assert not result.success
        # The final output file must NOT exist (no partial output).
        assert not out.exists(), "partial output appeared at the final path"

    def test_5_temp_cleanup_on_failure(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _make_csv(inp)
        registry = _ExplodingRegistry(RuleRegistry.create_default(), fail_at_row=5)
        engine = ValidationEngine(
            rules=registry, run_id="g2_5",
            evidence_dir=str(tmp_path / "ev"))
        engine.validate(csv_path=str(inp), output_path=str(out))
        # No leftover temp files in the output directory.
        temps = [f for f in os.listdir(str(tmp_path)) if f.startswith(".out.csv.") and f.endswith(".tmp")]
        assert not temps, f"leftover temp files: {temps}"

    def test_6_output_sha_correctness(self, tmp_path):
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _make_csv(inp)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="g2_6", evidence_dir=str(tmp_path / "ev"))
        result = engine.validate(csv_path=str(inp), output_path=str(out))
        assert result.success
        # The output SHA computed by the engine (in the manifest) must
        # match the actual file SHA.
        import json
        manifest = json.load(open(str(tmp_path / "ev" / "manifest.json")))
        actual_sha = hashlib.sha256(open(str(out), "rb").read()).hexdigest()
        recorded_sha = manifest.get("file_hashes", {}).get("output")
        assert recorded_sha == actual_sha, \
            f"manifest output hash {recorded_sha} != actual {actual_sha}"

    def test_7_gap01_collision_guard_intact(self, tmp_path):
        """Regression: the GAP-01 path-collision guard is still present
        and raises ValueError before any write occurs."""
        p = tmp_path / "same.csv"
        _make_csv(p)
        engine = ValidationEngine(
            rules=RuleRegistry.create_default(),
            run_id="g2_7", evidence_dir=str(tmp_path / "ev"))
        with pytest.raises(ValueError, match="Input and output paths"):
            engine.validate(csv_path=str(p), output_path=str(p))
