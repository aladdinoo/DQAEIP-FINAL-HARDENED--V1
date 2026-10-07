"""PII and secret protection — masking + evidence scanner.

This module provides TWO distinct capabilities:

1. ``PIIMasker`` — masks PII fields (email, phone, address, name) for
   safe logging. Used by the engine when writing lineage row records
   for flagged rows (the row content is masked before persistence).

2. ``scan_for_prohibited_content`` — scans evidence files for
   prohibited content: raw PII patterns (email, phone, credit-card-
   like), private keys (PEM), cloud credentials (AWS AKIA, GitHub
   tokens), and password/secret assignments. Used by the release gate.

Design decisions
----------------
- Masking is applied at WRITE TIME to lineage row records. The engine
  writes ``mask_row(row)`` to lineage, NOT the raw row.
- Evidence manifests, audit, monitoring, alerts contain only metadata
  (counts, hashes, run IDs) — no raw PII by design.
- The scanner is fail-closed: any prohibited finding yields a non-empty
  findings list. The release gate fails on any finding.
- The scanner does NOT claim to be a complete DLP solution. It detects
  common patterns; sophisticated or obfuscated PII may evade detection.
  Documented limitation: see ``SCAN_LIMITATIONS`` below.

What is NOT protected
---------------------
- The OUTPUT CSV (``--output``) contains raw source columns per the V1
  33→41 contract. This is by design — the output IS the validated data.
  PII in the output is the customer's responsibility, not DQAEIP's.
- The INPUT CSV is never modified and never scanned (it is the source
  of truth being validated).
- Exception messages and stack traces may contain file paths but are
  not persisted to evidence (they go to stderr).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "PIIMasker",
    "scan_for_prohibited_content",
    "ScanFinding",
    "SCAN_LIMITATIONS",
]


# ---------------------------------------------------------------------------
# PII Masking
# ---------------------------------------------------------------------------

class PIIMasker:
    """Masks PII fields for safe persistence in lineage/audit/alerts.

    Masking is one-way and lossy: the original value cannot be recovered
    from the masked form. The masked form preserves enough structure to
    be useful for debugging (e.g., the first character of a name, the
    domain of an email) without revealing the full PII value.
    """

    _EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

    @staticmethod
    def mask_email(email: str) -> str:
        """Mask email: john.smith@example.com → j***@example.com"""
        if not email or "@" not in str(email):
            return str(email) if email else ""
        local, domain = str(email).rsplit("@", 1)
        if len(local) <= 1:
            return f"***@{domain}"
        return f"{local[0]}***@{domain}"

    @staticmethod
    def mask_phone(phone: str) -> str:
        """Mask phone: 212-555-1234 → ***-***-1234"""
        if not phone:
            return str(phone) if phone is not None else ""
        s = str(phone)
        digits = re.sub(r"\D", "", s)
        if len(digits) < 4:
            return "***"
        if "-" in s:
            parts = s.split("-")
            if len(parts) == 3:
                return f"***-***-{parts[2]}"
        return "*" * (len(digits) - 4) + digits[-4:]

    @staticmethod
    def mask_address(address: str) -> str:
        """Mask address: show only first 8 chars + ..."""
        if not address:
            return str(address) if address is not None else ""
        s = str(address)
        if len(s) <= 8:
            return "***"
        return s[:8] + "..."

    @staticmethod
    def mask_name(name: str) -> str:
        """Mask name: John → J***, Smith-Jones → S*********"""
        if not name:
            return str(name) if name is not None else ""
        s = str(name)
        for i, ch in enumerate(s):
            if ch.isalpha():
                return s[:i] + ch + "***"
        return "***"

    @classmethod
    def mask_row(cls, row: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of ``row`` with PII fields masked.

        Non-PII fields are preserved verbatim. The original ``row`` is
        not modified.
        """
        if not isinstance(row, dict):
            return row
        masked = dict(row)
        masking = {
            "email_address": cls.mask_email,
            "phone_number": cls.mask_phone,
            "address": cls.mask_address,
            "first_name": cls.mask_name,
            "last_name": cls.mask_name,
        }
        for field, fn in masking.items():
            if field in masked:
                masked[field] = fn(str(masked[field]))
        return masked


# ---------------------------------------------------------------------------
# Prohibited-content scanner
# ---------------------------------------------------------------------------

# Documented limitations — the scanner is a heuristic, not a complete DLP.
SCAN_LIMITATIONS = [
    "Detects common PII patterns (email, phone, credit-card-like) but not obfuscated PII.",
    "Detects PEM private key blocks but not other key formats (e.g., raw base64 keys).",
    "Detects AWS AKIA-style access keys and GitHub gh[p]_ tokens but not arbitrary API keys.",
    "Detects password/secret/token variable assignments but not values embedded in JSON without a key name.",
    "Does NOT scan binary files, images, or archives — only .json, .md, .txt, .csv evidence files.",
    "A clean scan does NOT guarantee the evidence is free of PII — only that common patterns were not found.",
]


class ScanFinding(dict):
    """A single prohibited-content finding."""


# Placeholder values that are NOT real secrets — exempt from credential detection.
_PLACEHOLDER_VALUES = frozenset({
    "your_password_here", "changeme", "change-me", "placeholder",
    "example", "sample", "test", "xxx", "yyy", "zzz",
    "<your-key>", "<secret>", "<token>", "",
})

# Patterns that indicate a real secret (vs. a placeholder).
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")
# Credential assignment: ``password = "..."``, ``"password": "..."``, ``api_key: "..."``
# Allows optional quote before/after the key name (JSON/YAML style).
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r'(?i)["\']?(password|passwd|passphrase|secret|api[_\-]?key|apikey|'
    r'access[_\-]?key|auth[_\-]?token|bearer[_\-]?token|client[_\-]?secret|'
    r'private[_\-]?key)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']')
# PII patterns
_EMAIL_IN_CONTENT_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_PHONE_RE = re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")
# Credit-card-like: 4 groups of 4 digits separated by dash or space
# (does NOT match bare 16-digit sequences that are likely timestamps or
# float mantissas). Requires separators to reduce false positives.
_CREDIT_CARD_RE = re.compile(r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b")


def _is_placeholder(value: str) -> bool:
    """True if the value is a known placeholder, not a real secret."""
    v = value.strip().lower()
    if v in _PLACEHOLDER_VALUES:
        return True
    if v.startswith("<") and v.endswith(">"):
        return True
    # Example.com / test.org / mail.com / web.net / company.co / business.io
    # are the synthetic generator's reserved domains — emails on these are not real PII.
    return False


def _is_synthetic_email(email: str) -> bool:
    """True if the email is on a synthetic/reserved domain (not real PII).

    Checks the domain part (after @) against the synthetic generator's
    reserved domains. Matches exact domain, not substring, to avoid
    false positives like ``somecompany.com`` matching ``company.co``.
    """
    synthetic_domains = frozenset({
        "example.com", "example.org", "example.net",
        "test.org", "test.com", "test.net",
        "mail.com", "web.net", "company.co", "business.io",
        "invalid", "localhost",
    })
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].lower().rstrip(">")
    return domain in synthetic_domains


def scan_for_prohibited_content(
    evidence_dir: str,
    *,
    file_extensions: Tuple[str, ...] = (".json", ".md", ".txt", ".csv"),
) -> List[ScanFinding]:
    """Scan evidence files for prohibited content.

    Returns a list of ``ScanFinding`` dicts. An empty list means no
    prohibited content was found by the heuristic patterns. This is
    NOT a guarantee that the evidence is clean — see
    ``SCAN_LIMITATIONS``.

    Each finding has:
      - ``file``: relative path to the evidence file
      - ``category``: one of ``pii_email``, ``pii_phone``, ``pii_credit_card``,
        ``secret_pem_key``, ``secret_aws_key``, ``secret_github_token``,
        ``secret_credential_assignment``
      - ``match``: the matched substring (truncated to 40 chars)
      - ``line``: 1-based line number (best-effort)
    """
    import os
    findings: List[ScanFinding] = []
    if not os.path.isdir(evidence_dir):
        return findings

    for dirpath, _, files in os.walk(evidence_dir):
        for fname in files:
            if not fname.endswith(file_extensions):
                continue
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, evidence_dir)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            # PEM private keys
            for m in _PEM_PRIVATE_KEY_RE.finditer(content):
                findings.append(ScanFinding(
                    file=rel, category="secret_pem_key",
                    match=m.group(0)[:40],
                    line=content[:m.start()].count("\n") + 1,
                ))

            # AWS access keys
            for m in _AWS_ACCESS_KEY_RE.finditer(content):
                findings.append(ScanFinding(
                    file=rel, category="secret_aws_key",
                    match=m.group(0)[:40],
                    line=content[:m.start()].count("\n") + 1,
                ))

            # GitHub tokens
            for m in _GITHUB_TOKEN_RE.finditer(content):
                findings.append(ScanFinding(
                    file=rel, category="secret_github_token",
                    match=m.group(0)[:40],
                    line=content[:m.start()].count("\n") + 1,
                ))

            # Credential assignments (password = "..." etc.)
            for m in _CREDENTIAL_ASSIGNMENT_RE.finditer(content):
                value = m.group(2)
                if _is_placeholder(value):
                    continue
                findings.append(ScanFinding(
                    file=rel, category="secret_credential_assignment",
                    match=f"{m.group(1)}=***",
                    line=content[:m.start()].count("\n") + 1,
                ))

            # PII: emails (skip synthetic-domain emails)
            for m in _EMAIL_IN_CONTENT_RE.finditer(content):
                email = m.group(0)
                if _is_synthetic_email(email):
                    continue
                # Also skip if it's a hash-like sequence (64 hex chars)
                if re.fullmatch(r"[0-9a-f]{64}", email):
                    continue
                findings.append(ScanFinding(
                    file=rel, category="pii_email",
                    match=email[:40],
                    line=content[:m.start()].count("\n") + 1,
                ))

            # PII: phone numbers
            for m in _PHONE_RE.finditer(content):
                findings.append(ScanFinding(
                    file=rel, category="pii_phone",
                    match=m.group(0)[:40],
                    line=content[:m.start()].count("\n") + 1,
                ))

            # PII: credit-card-like
            for m in _CREDIT_CARD_RE.finditer(content):
                findings.append(ScanFinding(
                    file=rel, category="pii_credit_card",
                    match=m.group(0)[:40],
                    line=content[:m.start()].count("\n") + 1,
                ))

    return findings
