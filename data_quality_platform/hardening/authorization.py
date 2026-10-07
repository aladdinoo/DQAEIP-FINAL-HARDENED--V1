"""Layer B — Execution Authorization Gate.

Binds an execution authorization to a cryptographically complete identity:

* input file SHA-256
* schema fingerprint (SHA-256 of the authorized column list)
* Frozen V1 rule-set source SHA-256
* reference-data fingerprint
* configuration fingerprint (SHA-256 of the canonical configuration JSON)
* execution mode
* software identity (SHA-256 of each hardening layer module + the engine
  entry module)

The gate compares the OBSERVED execution scope (computed at run time from
the actual files) against the GRANTED scope. Any divergence — a single
field — fails closed with the list of divergent fields. Comparison uses
``hmac.compare_digest`` on hex digests.

Fail-closed: missing files, unreadable artifacts, or any exception yield
``AUTHORIZATION_REJECTED``; the gate never defaults to authorized.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

LAYER_ID = "B"
LAYER_NAME = "Execution Authorization Gate"
LAYER_VERSION = "1.0.0"

VERDICT_AUTHORIZED = "AUTHORIZED"
VERDICT_REJECTED = "AUTHORIZATION_REJECTED"

EXECUTION_MODES = ("validation", "export", "mutation_testing", "benchmark")

FROZEN_V1_SHA256 = (
    "daef1ded54c7d3c79898a1ba253be2acd5b6120e18b16b09009fdd7be9fc2276"
)

_READ_CHUNK = 1 << 20


@dataclass
class AuthorizationScope:
    """The full identity an authorization is bound to."""

    input_sha256: str
    schema_fingerprint: str
    v1_ruleset_sha256: str
    reference_data_fingerprint: str
    config_fingerprint: str
    execution_mode: str
    software_identity: Dict[str, str] = field(default_factory=dict)

    def identity_sha256(self) -> str:
        """Deterministic SHA-256 over the canonical scope JSON."""
        payload = json.dumps(self.as_dict(), sort_keys=True,
                             separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict:
        return {
            "input_sha256": self.input_sha256,
            "schema_fingerprint": self.schema_fingerprint,
            "v1_ruleset_sha256": self.v1_ruleset_sha256,
            "reference_data_fingerprint": self.reference_data_fingerprint,
            "config_fingerprint": self.config_fingerprint,
            "execution_mode": self.execution_mode,
            "software_identity": dict(sorted(
                self.software_identity.items())),
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)


@dataclass
class AuthorizationResult:
    layer_id: str = LAYER_ID
    layer_name: str = LAYER_NAME
    layer_version: str = LAYER_VERSION
    verdict: str = VERDICT_REJECTED
    reasons: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def authorized(self) -> bool:
        return self.verdict == VERDICT_AUTHORIZED

    def as_dict(self) -> dict:
        return {
            "layer_id": self.layer_id,
            "layer_name": self.layer_name,
            "layer_version": self.layer_version,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "details": dict(self.details),
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def schema_fingerprint(columns) -> str:
    """SHA-256 of the canonical authorized-column JSON."""
    payload = json.dumps(list(columns), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def config_fingerprint(config: dict) -> str:
    """SHA-256 of the canonical configuration JSON."""
    payload = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def software_identity(paths: Dict[str, str]) -> Dict[str, str]:
    """Map of module label -> SHA-256 for every pinned software artifact."""
    identity = {}
    for label, path in sorted(paths.items()):
        identity[label] = sha256_file(path)
    return identity


def observe_scope(
    input_path: str,
    authorized_columns,
    v1_rules_path: str,
    reference_data_paths: Dict[str, str],
    config: dict,
    execution_mode: str,
    software_paths: Dict[str, str],
) -> AuthorizationScope:
    """Compute the OBSERVED scope from actual files at run time.

    Raises on any unreadable artifact — callers convert that into a
    fail-closed rejection.
    """
    input_sha = sha256_file(input_path)
    if execution_mode not in EXECUTION_MODES:
        raise ValueError(f"unknown execution mode: {execution_mode!r}")
    v1_sha = sha256_file(v1_rules_path)
    ref_parts = []
    for label, path in sorted(reference_data_paths.items()):
        ref_parts.append(f"{label}={sha256_file(path)}")
    ref_fp = hashlib.sha256(
        ";".join(ref_parts).encode("utf-8")).hexdigest()
    return AuthorizationScope(
        input_sha256=input_sha,
        schema_fingerprint=schema_fingerprint(authorized_columns),
        v1_ruleset_sha256=v1_sha,
        reference_data_fingerprint=ref_fp,
        config_fingerprint=config_fingerprint(config),
        execution_mode=execution_mode,
        software_identity=software_identity(software_paths),
    )


def evaluate_authorization(
    granted: Optional[AuthorizationScope],
    observed: Optional[AuthorizationScope],
) -> AuthorizationResult:
    """Compare observed scope against granted scope, fail-closed."""
    result = AuthorizationResult()
    add = result.reasons.append

    if granted is None:
        add("no authorization grant supplied")
    if observed is None:
        add("observed scope could not be computed (unreadable artifact)")
    if granted is None or observed is None:
        result.details["gate"] = "scope-incomplete"
        return result

    if observed.execution_mode not in EXECUTION_MODES:
        add(f"observed execution mode is not a known mode: "
            f"{observed.execution_mode!r}")

    divergent = []
    if not hmac.compare_digest(granted.input_sha256.lower(),
                               observed.input_sha256.lower()):
        divergent.append("input_sha256")
    if not hmac.compare_digest(granted.schema_fingerprint.lower(),
                               observed.schema_fingerprint.lower()):
        divergent.append("schema_fingerprint")
    if not hmac.compare_digest(granted.v1_ruleset_sha256.lower(),
                               observed.v1_ruleset_sha256.lower()):
        divergent.append("v1_ruleset_sha256")
    if not hmac.compare_digest(granted.reference_data_fingerprint.lower(),
                               observed.reference_data_fingerprint.lower()):
        divergent.append("reference_data_fingerprint")
    if not hmac.compare_digest(granted.config_fingerprint.lower(),
                               observed.config_fingerprint.lower()):
        divergent.append("config_fingerprint")
    if granted.execution_mode != observed.execution_mode:
        divergent.append("execution_mode")
    if sorted(granted.software_identity) != sorted(
            observed.software_identity):
        divergent.append("software_identity_module_set")
    else:
        for label in sorted(granted.software_identity):
            if not hmac.compare_digest(
                    granted.software_identity[label].lower(),
                    observed.software_identity[label].lower()):
                divergent.append(f"software_identity[{label}]")

    result.details["granted_identity_sha256"] = granted.identity_sha256()
    result.details["observed_identity_sha256"] = observed.identity_sha256()
    result.details["divergent_fields"] = divergent

    if divergent:
        add("observed execution identity diverges from the authorization "
            "grant: " + ", ".join(divergent))
        return result

    result.verdict = VERDICT_AUTHORIZED
    return result


def load_grant(path: str) -> AuthorizationScope:
    """Load a granted scope from a JSON authorization file."""
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    scope = payload.get("scope", payload)
    return AuthorizationScope(
        input_sha256=scope["input_sha256"],
        schema_fingerprint=scope["schema_fingerprint"],
        v1_ruleset_sha256=scope["v1_ruleset_sha256"],
        reference_data_fingerprint=scope["reference_data_fingerprint"],
        config_fingerprint=scope["config_fingerprint"],
        execution_mode=scope["execution_mode"],
        software_identity=dict(scope.get("software_identity", {})),
    )
