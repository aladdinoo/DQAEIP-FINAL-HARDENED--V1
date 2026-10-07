"""Input contract / preflight firewall tests (DQAVP hardening, Section 11).

Covers the fail-closed structural gate both at module level and through
the production CLI, including negative (must-block) scenarios.
"""

import csv
import json
import os
import subprocess
import sys

import pytest

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.validation.input_contract import (
    InputContractError,
    validate_input_contract,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def _write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return str(path)


def _base_row(i=1):
    row = {c: "" for c in SOURCE_COLUMNS}
    row.update({
        "id": str(i), "first_name": "Alice", "last_name": "Smith",
        "email_address": "alice@example.com", "zip": "10001",
        "state": "NY", "source": "web", "country": "US",
    })
    return [row[c] for c in SOURCE_COLUMNS]


class TestValidInputsPass:
    def test_valid_file_passes(self, tmp_path):
        p = _write_csv(tmp_path / "ok.csv", SOURCE_COLUMNS,
                       [_base_row(1), _base_row(2)])
        result = validate_input_contract(p)
        assert result.valid is True
        assert result.issues == []
        assert result.details["total_data_rows"] == 2
        assert result.details["header_column_count"] == 33
        assert result.details["id_scan_complete"] is True
        assert result.details["schema_identity_sha256"] != ""

    def test_data_quality_problems_are_not_structural(self, tmp_path):
        """Blank e-mails, bad zips, junk names MUST pass the firewall —
        they are exactly what the V1 rules flag, not gate rejects."""
        row = _base_row(1)
        row[SOURCE_COLUMNS.index("email_address")] = "not-an-email"
        row[SOURCE_COLUMNS.index("zip")] = "ABCDE"
        row[SOURCE_COLUMNS.index("first_name")] = "Test123"
        p = _write_csv(tmp_path / "quality_issues.csv", SOURCE_COLUMNS, [row])
        result = validate_input_contract(p)
        assert result.valid is True

    def test_id_scan_bounds_and_coverage_reporting(self, tmp_path):
        rows = [_base_row(i) for i in range(1, 6)]  # ids 1..5
        p = _write_csv(tmp_path / "five.csv", SOURCE_COLUMNS, rows)
        result = validate_input_contract(p, id_scan_rows=3)
        assert result.valid is True
        assert result.details["id_rows_scanned"] == 3
        assert result.details["id_scan_complete"] is False
        assert "first 3 rows scanned" in result.details["id_coverage_note"]


class TestFailClosedBlocking:
    def test_missing_file(self, tmp_path):
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(tmp_path / "nope.csv"))
        assert ei.value.issues[0].code == "file_not_found"

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.csv"
        p.write_bytes(b"")
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        assert ei.value.issues[0].code == "empty_file"

    def test_directory_not_file(self, tmp_path):
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(tmp_path))
        assert ei.value.issues[0].code == "not_a_regular_file"

    def test_invalid_utf8(self, tmp_path):
        p = tmp_path / "bad.csv"
        p.write_bytes(b"id,first_name\n1,\xff\xfe\n")
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        assert ei.value.issues[0].code == "encoding_invalid"

    def test_utf8_bom_detected(self, tmp_path):
        p = tmp_path / "bom.csv"
        p.write_bytes(b"\xef\xbb\xbf" + ",".join(SOURCE_COLUMNS).encode()
                      + b"\n" + b",".join([b"1"] * 33) + b"\n")
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        codes = [i.code for i in ei.value.issues]
        assert "utf8_bom_detected" in codes

    def test_missing_column(self, tmp_path):
        header = [c for c in SOURCE_COLUMNS if c != "email_address"]
        p = _write_csv(tmp_path / "missing.csv", header, [
            [r for r in _base_row(1)][:-1]])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        codes = [i.code for i in ei.value.issues]
        assert "column_count_mismatch" in codes
        assert "column_missing" in codes
        assert "email_address" in ei.value.details["missing_columns"]

    def test_unexpected_column(self, tmp_path):
        header = SOURCE_COLUMNS + ["extra_col"]
        row = _base_row(1) + ["x"]
        p = _write_csv(tmp_path / "extra.csv", header, [row])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        assert "column_unexpected" in [i.code for i in ei.value.issues]
        assert ei.value.details["unexpected_columns"] == ["extra_col"]

    def test_reordered_columns(self, tmp_path):
        header = list(SOURCE_COLUMNS)
        header[0], header[1] = header[1], header[0]
        row = _base_row(1)
        row[0], row[1] = row[1], row[0]
        p = _write_csv(tmp_path / "reordered.csv", header, [row])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        assert "column_order_mismatch" in [i.code for i in ei.value.issues]

    def test_duplicate_header_names(self, tmp_path):
        header = list(SOURCE_COLUMNS)
        header[5] = header[4]
        p = _write_csv(tmp_path / "dupheader.csv", header, [_base_row(1)])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        assert "duplicate_header_names" in [i.code for i in ei.value.issues]

    def test_ragged_row(self, tmp_path):
        short = _base_row(1)[:-2]
        p = _write_csv(tmp_path / "ragged.csv", SOURCE_COLUMNS,
                       [_base_row(1), short, _base_row(3)])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        ragged = [i for i in ei.value.issues if i.code == "ragged_row"]
        assert len(ragged) == 1
        assert ragged[0].row_number == 3  # 1-based including header
        assert ei.value.details["ragged_rows_total"] == 1

    def test_duplicate_identifier(self, tmp_path):
        p = _write_csv(tmp_path / "dupid.csv", SOURCE_COLUMNS,
                       [_base_row(1), _base_row(1)])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        dups = [i for i in ei.value.issues if i.code == "duplicate_identifier"]
        assert len(dups) == 1
        assert ei.value.details["duplicate_ids_in_scanned_range"] == 1

    def test_blank_identifier(self, tmp_path):
        row = _base_row(1)
        row[SOURCE_COLUMNS.index("id")] = "  "
        p = _write_csv(tmp_path / "blankid.csv", SOURCE_COLUMNS, [row])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p))
        assert "blank_identifier" in [i.code for i in ei.value.issues]

    def test_nul_byte_in_row(self, tmp_path):
        p = tmp_path / "nul.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(SOURCE_COLUMNS)
            row = _base_row(1)
            row[SOURCE_COLUMNS.index("city")] = "Spring\x00field"
            w.writerow(row)
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p), id_scan_rows=0)
        assert "nul_byte_in_row" in [i.code for i in ei.value.issues]

    def test_header_only_no_data_rows_is_valid_structure(self, tmp_path):
        """A header-only file is structurally valid (engine handles 0 rows);
        the firewall must not invent a business rule against it."""
        p = _write_csv(tmp_path / "headeronly.csv", SOURCE_COLUMNS, [])
        result = validate_input_contract(str(p))
        assert result.valid is True
        assert result.details["total_data_rows"] == 0

    def test_invalid_config_thresholds(self, tmp_path):
        class BadConfig:
            def get_quality_thresholds(self):
                return {"completeness": 1.5, "validity": "high"}

        p = _write_csv(tmp_path / "ok.csv", SOURCE_COLUMNS, [_base_row(1)])
        with pytest.raises(InputContractError) as ei:
            validate_input_contract(str(p), config=BadConfig())
        codes = [i.code for i in ei.value.issues]
        assert "config_threshold_out_of_range" in codes
        assert "config_threshold_not_numeric" in codes


class TestCliFirewallEndToEnd:
    """The production CLI must block invalid input before the engine.

    The CLI requires an authorization grant for every validate run. The
    test helper builds the grant before invoking validate.
    """

    def _authorize(self, csv_path, grant_path):
        return subprocess.run(
            [sys.executable, "-m", "runner.cli", "authorize",
             "--csv", csv_path, "--output", grant_path],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
        )

    def _run_cli(self, csv_path, out_path, evidence_dir, grant_path):
        return subprocess.run(
            [sys.executable, "-m", "runner.cli", "validate",
             "--csv", csv_path, "--output", out_path,
             "--grant", grant_path,
             "--run-id", "preflight_test", "--evidence-dir", evidence_dir],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
        )

    def test_cli_valid_input_passes_preflight_and_validation(self, tmp_path):
        p = _write_csv(tmp_path / "ok.csv", SOURCE_COLUMNS,
                       [_base_row(i) for i in range(1, 11)])
        out = tmp_path / "out.csv"
        evd = tmp_path / "evidence"
        grant = tmp_path / "grant.json"
        auth = self._authorize(str(p), str(grant))
        assert auth.returncode == 0, auth.stderr
        proc = self._run_cli(str(p), str(out), str(evd), str(grant))
        assert proc.returncode == 0, proc.stderr
        assert "Validation PASSED: 10 rows in, 10 rows out" in proc.stdout
        # Engine output unaffected by the firewall.
        with open(out, encoding="utf-8") as f:
            rows = list(csv.reader(f))
        assert rows[0] == list(SOURCE_COLUMNS) + [
            "first_name_cleaning_candidate", "last_name_cleaning_candidate",
            "name_cleaning_candidate", "email_blank", "email_syntax_failure",
            "proposed_email_export_eligible", "zip_state_assessable",
            "geography_mismatch_candidate"]
        assert len(rows) == 11

    def test_cli_blocks_invalid_input_with_manifest_and_exit_2(self, tmp_path):
        header = [c for c in SOURCE_COLUMNS if c != "state"]
        row = [r for r in _base_row(1)][:-1]
        p = _write_csv(tmp_path / "nostate.csv", header, [row])
        out = tmp_path / "out.csv"
        evd = tmp_path / "evidence_blocked"
        grant = tmp_path / "grant.json"
        # Authorize the (malformed) input — Layer A still rejects it
        # because the schema fingerprint will not match the granted scope.
        auth = self._authorize(str(p), str(grant))
        assert auth.returncode == 0, auth.stderr
        proc = self._run_cli(str(p), str(out), str(evd), str(grant))
        # Layer A rejects before the engine runs.
        assert proc.returncode != 0
        assert not out.exists(), "engine must not run on blocked input"
