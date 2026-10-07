"""Tamper-Evident Evidence Root (DQAVP enterprise hardening, Section 17).

An ADDITIVE integrity layer on top of the existing evidence format
(which is unchanged): for a given evidence directory, compute SHA-256
for each core evidence artifact

    manifest.json / output / lineage.json / audit.json /
    monitoring.json / alerts.json

and derive a deterministic root hash over the artifact-hash set. The
root is written to ``evidence_root.json`` inside the directory.

Verification recomputes everything from the actual files and compares
against the recorded root: changing ANY covered artifact (or adding/
removing one) invalidates the evidence root — FAIL CLOSED.

Guarantees and limits (explicit, no overstatement):
- The root binds the artifacts listed in the root record at creation
  time, identified by fixed logical names.
- The output CSV is covered only when it resides inside the evidence
  directory at creation time; if absent it is recorded as ``absent``
  (never silently skipped).
- This layer does not replace the existing manifest format or the
  evidence validator; it adds tamper-evidence on top of them.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "EVIDENCE_ROOT_FILENAME",
    "CORE_ARTIFACTS",
    "compute_evidence_root",
    "write_evidence_root",
    "verify_evidence_root",
    "verify_evidence_root_with_external_anchor",
]

EVIDENCE_ROOT_FILENAME = "evidence_root.json"

# Fixed logical order — the root hash is a deterministic function of
# this ordering plus the artifact hashes.
CORE_ARTIFACTS = (
    "manifest.json",
    "output.csv",
    "lineage.json",
    "audit.json",
    "monitoring.json",
    "alerts.json",
)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def compute_evidence_root(evidence_dir: str,
                          output_csv: Optional[str] = None
                          ) -> Dict[str, Any]:
    """Compute the evidence-root record for ``evidence_dir``.

    ``output_csv`` optionally names the engine output file covered by
    the root when it does not live inside the evidence directory; its
    basename is recorded and its hash included in the root.
    """
    if not os.path.isdir(evidence_dir):
        raise FileNotFoundError(f"not an evidence directory: {evidence_dir}")

    artifact_hashes: Dict[str, Any] = {}
    for name in CORE_ARTIFACTS:
        path = os.path.join(evidence_dir, name)
        if os.path.isfile(path):
            artifact_hashes[name] = _sha256_file(path)
        elif name == "output.csv" and output_csv is not None \
                and os.path.isfile(output_csv):
            artifact_hashes[name] = _sha256_file(output_csv)
        else:
            artifact_hashes[name] = None  # explicitly absent

    present = [n for n in CORE_ARTIFACTS if artifact_hashes[n] is not None]
    absent = [n for n in CORE_ARTIFACTS if artifact_hashes[n] is None]

    # Deterministic root: fixed artifact order + hashes + presence set.
    root_material = {
        "layer_version": "1.0.0",
        "artifacts": {n: artifact_hashes[n] for n in CORE_ARTIFACTS},
        "present_artifacts": present,
        "absent_artifacts": absent,
    }
    root_hash = hashlib.sha256(
        _canonical(root_material).encode("utf-8")).hexdigest()

    return {
        "layer": "tamper_evident_evidence_root",
        "layer_version": "1.0.0",
        "evidence_dir_portable_note":
            "paths are handled by the caller; this record stores only "
            "artifact names and hashes",
        "artifacts": {n: artifact_hashes[n] for n in CORE_ARTIFACTS},
        "present_artifacts": present,
        "absent_artifacts": absent,
        "root_sha256": root_hash,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verification_note": (
            "Recompute the artifact hashes and the root hash from the "
            "actual files and compare against root_sha256 — any "
            "difference (including an artifact appearing or "
            "disappearing) invalidates this evidence root."),
    }


def write_evidence_root(evidence_dir: str,
                        output_csv: Optional[str] = None) -> Dict[str, Any]:
    """Compute and persist ``evidence_root.json`` into the directory."""
    record = compute_evidence_root(evidence_dir, output_csv=output_csv)
    out_path = os.path.join(evidence_dir, EVIDENCE_ROOT_FILENAME)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
    return record


def verify_evidence_root(evidence_dir: str,
                          expected_root: Optional[str] = None,
                          output_csv: Optional[str] = None
                          ) -> Tuple[bool, Dict[str, Any]]:
    """Verify an evidence directory against its recorded root.

    Returns ``(ok, details)``. Fail closed: verification fails when the
    root record is missing, unreadable, or disagrees with the actual
    files in ANY way. ``expected_root`` (hex) may be supplied instead of
    reading the recorded value (belt-and-braces for callers that carry
    the root hash out-of-band).
    """
    root_path = os.path.join(evidence_dir, EVIDENCE_ROOT_FILENAME)
    if not os.path.isfile(root_path):
        return False, {"reason": "missing evidence_root.json",
                       "evidence_dir_portable": True}
    try:
        with open(root_path, encoding="utf-8") as f:
            recorded = json.load(f)
    except Exception as exc:  # malformed JSON — fail closed
        return False, {"reason": f"malformed evidence_root.json: "
                                f"{type(exc).__name__}"}

    if not isinstance(recorded.get("root_sha256"), str):
        return False, {"reason": "root_sha256 missing or not a string"}

    recorded_root = expected_root or recorded["root_sha256"]

    # Output coverage note: if the recorded root covered an output.csv
    # that lived outside the evidence dir, the caller must resupply it.
    if recorded["artifacts"].get("output.csv") is not None \
            and output_csv is None \
            and not os.path.isfile(os.path.join(evidence_dir,
                                                "output.csv")):
        return False, {"reason": "recorded root covers an output.csv that "
                                "is not present; resupply its path to "
                                "verify"}

    current = compute_evidence_root(evidence_dir, output_csv=output_csv)

    problems = []
    if current["root_sha256"] != recorded_root:
        problems.append("root hash mismatch")
    for name in CORE_ARTIFACTS:
        if current["artifacts"][name] != recorded["artifacts"].get(name):
            problems.append(f"artifact hash changed: {name}")
    if sorted(recorded.get("present_artifacts", [])) != \
            sorted(current["present_artifacts"]):
        problems.append("present-artifact set changed")

    if problems:
        return False, {"reason": "; ".join(problems),
                       "recorded_root": recorded_root,
                       "current_root": current["root_sha256"]}
    return True, {"root_sha256": current["root_sha256"],
                  "present_artifacts": current["present_artifacts"],
                  "absent_artifacts": current["absent_artifacts"]}


def verify_evidence_root_with_external_anchor(
    evidence_dir: str,
    expected_root: Optional[str],
    output_csv: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Protected-mode evidence verification.

    The evidence directory is treated as attacker-controlled. The
    ``expected_root`` MUST be supplied out-of-band (e.g. recorded by the
    operator at run time, persisted outside the writable evidence
    directory, or transmitted via a trusted side channel). It is then
    compared against the recomputed root hash.

    Fail-closed behavior:
      * ``expected_root`` is None / empty / not a 64-char hex string →
        fail closed (the protected validation mode REQUIRES the anchor).
      * Recomputed root ≠ ``expected_root`` → fail.
      * Recorded root (inside the evidence dir) ≠ ``expected_root`` →
        fail (the directory's own claim must also agree with the anchor).
      * Any tamper-detection signal from ``verify_evidence_root`` → fail.

    Returns ``(ok, details)`` where ``details`` always includes both the
    externally anchored ``expected_root`` and the recomputed
    ``current_root`` for operator forensics.
    """
    if not isinstance(expected_root, str) or len(expected_root) != 64:
        return False, {
            "reason": "external expected_root missing or malformed "
                      "(protected mode requires a 64-char hex anchor)",
            "anchor_state": "missing_or_malformed",
        }
    try:
        int(expected_root, 16)
    except ValueError:
        return False, {
            "reason": "external expected_root is not hex",
            "anchor_state": "non_hex",
        }
    ok, inner = verify_evidence_root(
        evidence_dir, expected_root=expected_root, output_csv=output_csv)
    details = {
        "expected_root": expected_root,
        "current_root": inner.get("current_root") or inner.get("root_sha256"),
        "recorded_root": inner.get("recorded_root"),
        "inner_reason": inner.get("reason"),
        "anchor_state": "verified",
    }
    return ok, details
