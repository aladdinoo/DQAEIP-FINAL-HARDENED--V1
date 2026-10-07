"""Layer G — Reference-Data Versioning.

Binds every reference-data artifact consumed by the frozen V1 engine to
a content-addressed version (SHA-256) and aggregates them into a single
reference-data fingerprint used by the Layer B authorization scope.

Scope for this release
----------------------
The reference data of the frozen V1 core is INTERNAL to the repository
(the STATE_ZIP_PREFIXES contract table in
``data_quality_platform/contracts.py`` plus the frozen rule source).
There is no authoritative external source available for these values;
therefore:

* version == content hash (content-addressed versioning), and
* provenance beyond content (external authority) is explicitly NOT
  claimed — this is a documented limitation of the release, faithfully
  carried over from the certified 2026-09-18 baseline (no fabrication
  of an external authority that does not exist).

Fail-closed: a missing or unreadable reference artifact yields
``REFERENCE_DATA_INCOMPLETE`` (never a fingerprint of a partial set).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict

LAYER_ID = "G"
LAYER_NAME = "Reference-Data Versioning"
LAYER_VERSION = "1.0.0"

VERDICT_PINNED = "REFERENCE_DATA_PINNED"
VERDICT_INCOMPLETE = "REFERENCE_DATA_INCOMPLETE"

_READ_CHUNK = 1 << 20


@dataclass
class ReferenceDataResult:
    layer_id: str = LAYER_ID
    layer_name: str = LAYER_NAME
    layer_version: str = LAYER_VERSION
    verdict: str = VERDICT_INCOMPLETE
    reasons: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def pinned(self) -> bool:
        return self.verdict == VERDICT_PINNED

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


def reference_data_versions(paths: Dict[str, str]) -> Dict[str, str]:
    """Map label -> content SHA-256 for every reference artifact.

    Raises on missing/unreadable artifacts (callers convert to a
    fail-closed verdict).
    """
    versions: Dict[str, str] = {}
    for label, path in sorted(paths.items()):
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"reference artifact {label!r} missing at {path}")
        versions[label] = sha256_file(path)
    return versions


def aggregate_fingerprint(versions: Dict[str, str]) -> str:
    parts = [f"{k}={versions[k]}" for k in sorted(versions)]
    payload = ";".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_reference_data(paths: Dict[str, str]) -> ReferenceDataResult:
    """Pin every reference artifact version and aggregate a fingerprint."""
    result = ReferenceDataResult()
    add = result.reasons.append
    try:
        versions = reference_data_versions(paths)
    except (OSError, FileNotFoundError) as exc:
        add(str(exc))
        return result
    if not versions:
        add("no reference artifacts supplied; refusing to fingerprint "
            "an empty reference set")
        return result
    fingerprint = aggregate_fingerprint(versions)
    result.details["versions"] = versions
    result.details["reference_data_fingerprint"] = fingerprint
    result.details["versioning_model"] = "content-addressed (SHA-256)"
    result.details["provenance_note"] = (
        "reference data is internal to the repository; no external "
        "authoritative source is claimed (documented limitation, "
        "inherited verbatim from the certified 2026-09-18 baseline)")
    result.verdict = VERDICT_PINNED
    return result
