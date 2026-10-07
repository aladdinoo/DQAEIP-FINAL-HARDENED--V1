"""PII masking and prohibited-content scanner tests.

Tests:
  1. PIIMasker.mask_email / mask_phone / mask_address / mask_name
  2. PIIMasker.mask_row masks all PII fields, leaves others verbatim
  3. scan_for_prohibited_content detects: PEM keys, AWS keys, GitHub tokens,
     password assignments, real emails, phone numbers, credit-card-like
  4. scan_for_prohibited_content ignores: placeholder values, synthetic-domain
     emails (example.com etc.), hash-like sequences
"""

import json
import os
import tempfile

import pytest

from data_quality_platform.security import (
    PIIMasker, scan_for_prohibited_content, SCAN_LIMITATIONS,
)


class TestPIIMasker:
    def test_mask_email_standard(self):
        assert PIIMasker.mask_email("john.smith@example.com") == "j***@example.com"

    def test_mask_email_single_char_local(self):
        assert PIIMasker.mask_email("a@example.com") == "***@example.com"

    def test_mask_email_blank(self):
        assert PIIMasker.mask_email("") == ""

    def test_mask_email_no_at(self):
        assert PIIMasker.mask_email("notanemail") == "notanemail"

    def test_mask_phone_standard(self):
        masked = PIIMasker.mask_phone("212-555-1234")
        assert "212" not in masked
        assert "1234" in masked

    def test_mask_phone_blank(self):
        assert PIIMasker.mask_phone("") == ""

    def test_mask_phone_short(self):
        # Less than 4 digits → "***"
        assert PIIMasker.mask_phone("12") == "***"

    def test_mask_address_standard(self):
        masked = PIIMasker.mask_address("123 Main Street")
        assert masked.startswith("123 Main")
        assert masked.endswith("...")

    def test_mask_address_short(self):
        assert PIIMasker.mask_address("Hi") == "***"

    def test_mask_address_blank(self):
        assert PIIMasker.mask_address("") == ""

    def test_mask_name_standard(self):
        masked = PIIMasker.mask_name("John")
        assert masked.startswith("J")
        assert "***" in masked

    def test_mask_name_blank(self):
        assert PIIMasker.mask_name("") == ""

    def test_mask_name_no_alpha(self):
        assert PIIMasker.mask_name("---") == "***"

    def test_mask_row_masks_all_pii_fields(self):
        row = {
            "id": "1",
            "email_address": "john.smith@example.com",
            "first_name": "John",
            "last_name": "Smith",
            "address": "123 Main St",
            "phone_number": "212-555-1234",
            "city": "Anytown",  # NOT masked
            "state": "CA",     # NOT masked
        }
        masked = PIIMasker.mask_row(row)
        assert "john.smith@" not in masked["email_address"]
        assert "John" not in masked["first_name"]
        assert "Smith" not in masked["last_name"]
        assert "123 Main St" not in masked["address"]
        assert "212-555" not in masked["phone_number"]
        # Non-PII fields are preserved verbatim.
        assert masked["city"] == "Anytown"
        assert masked["state"] == "CA"
        assert masked["id"] == "1"

    def test_mask_row_does_not_mutate_original(self):
        row = {"email_address": "john@example.com", "first_name": "John"}
        original = dict(row)
        PIIMasker.mask_row(row)
        assert row == original, "mask_row mutated the input"

    def test_mask_row_handles_non_dict(self):
        assert PIIMasker.mask_row(None) is None
        assert PIIMasker.mask_row("string") == "string"


class TestProhibitedContentScanner:
    @pytest.fixture
    def ev_dir(self, tmp_path):
        d = tmp_path / "ev"
        d.mkdir()
        return str(d)

    def test_detects_pem_private_key(self, ev_dir):
        with open(os.path.join(ev_dir, "evidence.json"), "w") as f:
            f.write('{"key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIE"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert any(f["category"] == "secret_pem_key" for f in findings)

    def test_detects_aws_access_key(self, ev_dir):
        with open(os.path.join(ev_dir, "manifest.json"), "w") as f:
            f.write('{"config": "AKIAIOSFODNN7EXAMPLE"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert any(f["category"] == "secret_aws_key" for f in findings)

    def test_detects_github_token(self, ev_dir):
        with open(os.path.join(ev_dir, "note.md"), "w") as f:
            f.write("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        findings = scan_for_prohibited_content(ev_dir)
        assert any(f["category"] == "secret_github_token" for f in findings)

    def test_detects_password_assignment(self, ev_dir):
        with open(os.path.join(ev_dir, "config.json"), "w") as f:
            f.write('{"password": "supersecretpassword123"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert any(f["category"] == "secret_credential_assignment" for f in findings)

    def test_ignores_placeholder_password(self, ev_dir):
        with open(os.path.join(ev_dir, "config.json"), "w") as f:
            f.write('{"password": "changeme"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert not any(f["category"] == "secret_credential_assignment" for f in findings)

    def test_detects_real_email(self, ev_dir):
        with open(os.path.join(ev_dir, "audit.json"), "w") as f:
            f.write('{"user": "john.doe@somecompany.com"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert any(f["category"] == "pii_email" for f in findings)

    def test_ignores_synthetic_domain_email(self, ev_dir):
        with open(os.path.join(ev_dir, "audit.json"), "w") as f:
            f.write('{"user": "john@example.com"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert not any(f["category"] == "pii_email" for f in findings)

    def test_detects_phone_number(self, ev_dir):
        with open(os.path.join(ev_dir, "log.txt"), "w") as f:
            f.write("call 212-555-1234 for support")
        findings = scan_for_prohibited_content(ev_dir)
        assert any(f["category"] == "pii_phone" for f in findings)

    def test_detects_credit_card_like(self, ev_dir):
        with open(os.path.join(ev_dir, "data.json"), "w") as f:
            f.write('{"card": "4111-1111-1111-1111"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert any(f["category"] == "pii_credit_card" for f in findings)

    def test_ignores_hex_hash_sequences(self, ev_dir):
        # A 64-char hex hash should not be flagged as an email.
        with open(os.path.join(ev_dir, "manifest.json"), "w") as f:
            f.write('{"sha": "daef1ded54c7d3c79898a1ba253be2acd5b6120e18b16b09009fdd7be9fc2276"}')
        findings = scan_for_prohibited_content(ev_dir)
        assert not any(f["category"] == "pii_email" for f in findings)

    def test_empty_directory_returns_empty(self, ev_dir):
        findings = scan_for_prohibited_content(ev_dir)
        assert findings == []

    def test_nonexistent_directory_returns_empty(self, tmp_path):
        findings = scan_for_prohibited_content(str(tmp_path / "nonexistent"))
        assert findings == []

    def test_scanner_has_documented_limitations(self):
        assert len(SCAN_LIMITATIONS) >= 5
        assert any("DLP" in lim or "guarantee" in lim for lim in SCAN_LIMITATIONS)
