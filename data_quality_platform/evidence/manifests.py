"""Evidence manifests: success and failure."""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA-256 of a file. Call AFTER file is closed."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def fsync_path(filepath: str) -> None:
    """Flush and fsync a file."""
    fd = os.open(filepath, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class ManifestWriter:
    """Writes success and failure manifests."""

    def write_success_manifest(
        self,
        evidence_dir: str,
        run_id: str,
        source_row_count: int,
        output_row_count: int,
        schema_hash: str,
        rule_hashes: Dict[str, str],
        sql_hashes: Dict[str, str],
        flag_counts: Dict[str, int],
        reconciliation: Dict[str, Any],
        safety_invariants: List[str],
        lineage_reference: str,
        monitoring_score: float,
        monitoring_scores: Dict[str, float],
        sla_results: Dict[str, Any],
        generated_files: Dict[str, str],
    ) -> Dict[str, Any]:
        """Write success manifest AFTER all files are closed.

        Computes SHA-256 hashes after file close.
        """
        os.makedirs(evidence_dir, exist_ok=True)

        # Compute file hashes after files are closed
        file_hashes = {}
        for name, path in generated_files.items():
            if path and os.path.exists(path):
                file_hashes[name] = compute_file_sha256(path)

        manifest = {
            "manifest_type": "success",
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_row_count": source_row_count,
            "output_row_count": output_row_count,
            "schema_hash": schema_hash,
            "rule_hashes": rule_hashes,
            "sql_hashes": sql_hashes,
            "flag_counts": flag_counts,
            "reconciliation": reconciliation,
            "safety_invariants": safety_invariants,
            "lineage_reference": lineage_reference,
            "monitoring_score": monitoring_score,
            "monitoring_scores": monitoring_scores,
            "sla_results": sla_results,
            "generated_files": generated_files,
            "file_hashes": file_hashes,
        }

        manifest_path = os.path.join(evidence_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, default=str)
        # fsync after write
        try:
            fsync_path(manifest_path)
        except Exception:
            pass  # fsync not critical on all platforms

        manifest["manifest_hash"] = compute_file_sha256(manifest_path)
        return manifest

    def write_failure_manifest(
        self,
        evidence_dir: str,
        run_id: str,
        error_type: str,
        error_message: str,
        failed_step: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write failure manifest with hashes captured so far."""
        os.makedirs(evidence_dir, exist_ok=True)

        manifest = {
            "manifest_type": "failure",
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_type": error_type,
            "error_message": error_message,
            "failed_step": failed_step,
            "context": context or {},
        }

        manifest_path = os.path.join(evidence_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, default=str)

        manifest["manifest_hash"] = compute_file_sha256(manifest_path)
        return manifest


class ManifestReader:
    """Reads and parses manifests."""

    @staticmethod
    def read(evidence_dir: str) -> Optional[Dict[str, Any]]:
        manifest_path = os.path.join(evidence_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            return None
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def is_success(manifest: Dict[str, Any]) -> bool:
        return manifest.get("manifest_type") == "success"

    @staticmethod
    def is_failure(manifest: Dict[str, Any]) -> bool:
        return manifest.get("manifest_type") == "failure"
