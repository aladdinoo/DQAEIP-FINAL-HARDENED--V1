"""Single hardened execution boundary for DQAEIP.

This module is the ONLY production entry point that runs a validation.
The CLI, Airflow, and any application code MUST call ``run_validation()``
rather than instantiating ``ValidationEngine`` directly.

Execution order (every step is fail-closed; the first blocking verdict
stops the run and no engine work is performed):

1. Layer A  Input Contract Firewall      (REJECTED -> stop)
2. Layer B  Execution Authorization Gate (REJECTED -> stop)
3. Layer H  Pre-execution Resource Guard  (TRIPPED  -> stop)
4. ValidationEngine.validate()  (in-process; internal Layer D atomic commit)
5. Layer H  Post-execution Resource Guard (TRIPPED  -> clean failure)
6. Layer D  Atomic evidence commit (already inside the engine; the
   post-execution guard wraps the result)

Authorization is enforced: callers MUST supply a granted
``AuthorizationScope`` whose SHA-256 identity matches the observed
scope. A missing or mismatched grant yields ``AUTHORIZATION_REJECTED``
and the engine is never invoked.

Layer C (idempotency ledger) and Layer E (checkpoint contract) are not
required in the simplified architecture — the engine is deterministic,
and a fresh full re-run is the safe equivalent of any interrupted run
(this is the explicit Layer E decision, preserved).
"""

from __future__ import annotations

import json
import os
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from data_quality_platform.contracts import SOURCE_COLUMNS
from data_quality_platform.hardening.input_contract import (
    validate_input_contract,
)
from data_quality_platform.hardening.authorization import (
    AuthorizationScope,
    evaluate_authorization,
    observe_scope,
)
from data_quality_platform.hardening.resource_guard import (
    ResourceLimits,
    check_pre_execution,
    check_post_execution,
)
from data_quality_platform.hardening.schema_guard import assess_schema_evolution
from data_quality_platform.hardening.reference_data import (
    fingerprint_reference_data,
)
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.validation.engine import (
    ValidationEngine,
    ValidationResult,
)


# ── F-001 TOCTOU remediation ────────────────────────────────────
# The input file MUST be read exactly once into an immutable snapshot.
# All subsequent operations (Layer A verification, Layer F header check,
# Layer B observe_scope, and ValidationEngine.validate) operate on the
# snapshot path, NOT the original input_path. This closes the TOCTOU
# window where the input file could be swapped between authorization
# and execution.
#
# Security invariant: authorized_bytes == observed_bytes == executed_bytes.
# The snapshot is created by reading the original file once, computing
# its SHA-256, and writing the bytes to a temp file with a unique name
# in the same directory as the output (for filesystem atomicity). The
# temp file is cleaned up in a finally block.

def _create_input_snapshot(input_path: str, work_dir: str) -> tuple:
    """Read the input file ONCE and create an immutable snapshot.

    Returns (snapshot_path, input_sha256, input_bytes) or raises OSError.

    The snapshot is a temp file containing the exact bytes read from
    input_path at this single point in time. All subsequent operations
    use snapshot_path instead of input_path, eliminating the TOCTOU
    window between authorization and execution.
    """
    _READ_CHUNK = 1 << 20  # 1 MB
    os.makedirs(work_dir, exist_ok=True)
    h = hashlib.sha256()
    snapshot_path = os.path.join(
        work_dir,
        f".input_snapshot.{uuid.uuid4().hex}.csv")
    try:
        with open(input_path, "rb") as src, \
             open(snapshot_path, "wb") as dst:
            for chunk in iter(lambda: src.read(_READ_CHUNK), b""):
                h.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        return snapshot_path, h.hexdigest(), None
    except Exception:
        # Clean up partial snapshot on failure.
        if os.path.exists(snapshot_path):
            try:
                os.remove(snapshot_path)
            except OSError:
                pass
        raise


def _cleanup_snapshot(snapshot_path: str) -> None:
    """Remove the input snapshot file if it exists."""
    if snapshot_path and os.path.exists(snapshot_path):
        try:
            os.remove(snapshot_path)
        except OSError:
            pass


LAYER_BUNDLE_VERSION = "3.1.0-hardened"

VERDICT_PASS = "HARDENED_EXECUTION_PASS"
VERDICT_FAIL = "HARDENED_EXECUTION_FAIL"


@dataclass
class HardenedExecutionResult:
    """Structured outcome of a hardened validation run."""

    verdict: str = VERDICT_FAIL
    reasons: List[str] = field(default_factory=list)
    layers: List[dict] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    validation: Optional[ValidationResult] = None

    @property
    def passed(self) -> bool:
        return self.verdict == VERDICT_PASS

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "layers": list(self.layers),
            "details": dict(self.details),
            "validation_success": self.validation.success if self.validation else False,
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)


def _default_reference_data_paths() -> Dict[str, str]:
    """The V1 reference data is hard-coded in contracts.py; there are no
    external reference files in the simplified architecture. Layer G is
    therefore a constant fingerprint that the authorization scope pins."""
    contracts_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "contracts.py"))
    return {"contracts.py": contracts_path}


def _default_software_paths() -> Dict[str, str]:
    """The set of production modules whose SHA-256 forms the software
    identity checked by Layer B."""
    import data_quality_platform.hardening.input_contract as _a
    import data_quality_platform.hardening.authorization as _b
    import data_quality_platform.hardening.resource_guard as _h
    import data_quality_platform.validation.engine as _eng
    import data_quality_platform.rules.v1_rules as _rules
    return {
        "hardening.input_contract": os.path.abspath(_a.__file__),
        "hardening.authorization": os.path.abspath(_b.__file__),
        "hardening.resource_guard": os.path.abspath(_h.__file__),
        "validation.engine": os.path.abspath(_eng.__file__),
        "rules.v1_rules": os.path.abspath(_rules.__file__),
    }


def _v1_rules_path() -> str:
    import data_quality_platform.rules.v1_rules as _r
    return os.path.abspath(_r.__file__)


def run_validation(
    *,
    input_path: str,
    output_path: str,
    evidence_dir: str,
    run_id: str,
    granted_scope: AuthorizationScope,
    config: Optional[dict] = None,
    execution_mode: str = "validation",
    limits: Optional[ResourceLimits] = None,
    config_thresholds: Optional[Dict[str, float]] = None,
) -> HardenedExecutionResult:
    """The single hardened validation entry point.

    Parameters
    ----------
    input_path, output_path, evidence_dir, run_id
        Filesystem locations and run identifier.
    granted_scope
        REQUIRED. The cryptographically complete authorization scope.
        The observed scope is computed from the actual files at run time
        and compared via ``hmac.compare_digest``; any divergence rejects.
    config
        Optional configuration dict consumed by Layer B's config
        fingerprint. If None, an empty dict is used.
    execution_mode
        One of ``validation``, ``export``, ``mutation_testing``,
        ``benchmark``. Defaults to ``validation``.
    limits
        Optional ``ResourceLimits`` override (Layer H). If None, the
        defaults are used.
    config_thresholds
        Optional SLA thresholds forwarded to ``QualityMonitor`` inside
        the engine.

    Returns
    -------
    HardenedExecutionResult
        ``passed=True`` only if every layer accepted and the engine
        returned ``success=True``.
    """
    result = HardenedExecutionResult()
    add_reason = result.reasons.append
    limits = limits or ResourceLimits()
    config = config if config is not None else {}
    v1_rules_path = _v1_rules_path()
    reference_paths = _default_reference_data_paths()
    software_paths = _default_software_paths()

    # Fail-closed: a missing granted scope is an immediate rejection.
    # The engine is never invoked.
    if granted_scope is None:
        add_reason("no authorization grant supplied (granted_scope is None)")
        result.details["stopped_at"] = "B-no-grant"
        result.layers.append({
            "layer_id": "B", "layer_name": "Execution Authorization Gate",
            "verdict": "AUTHORIZATION_REJECTED",
            "reasons": ["no authorization grant supplied"],
        })
        return result

    # ── Concurrent-run collision prevention ──────────────────────
    # Atomically claim the evidence directory. If two simultaneous runs
    # share the same evidence_dir (e.g., two Airflow tasks with the same
    # run_id, or two CLI invocations colliding on the same timestamped
    # default), the FIRST os.makedirs with exist_ok=False succeeds and
    # the SECOND fails closed — no last-writer-wins, no evidence mixing.
    # Existing single-run behavior is unchanged: a fresh evidence_dir is
    # claimed exactly as before. Callers that legitimately need to re-use
    # a fixed evidence_dir path (e.g., the release gate's replay_1/) MUST
    # clean it up first.
    try:
        os.makedirs(evidence_dir, exist_ok=False)
    except FileExistsError as exc:
        add_reason(f"evidence_dir already exists "
                   f"(concurrent-run collision prevented): {exc!r}")
        result.details["stopped_at"] = "evidence-dir-collision"
        result.details["evidence_dir"] = evidence_dir
        return result

    # ── F-001 TOCTOU remediation: read input ONCE into immutable snapshot ──
    # The input file is read exactly once here. All subsequent operations
    # (Layer A, Layer F, Layer B, Layer H, engine.validate) use the
    # snapshot_path, NOT the original input_path. This closes the TOCTOU
    # window where the input file could be swapped between authorization
    # and execution.
    #
    # The snapshot is created in a work directory derived from evidence_dir
    # (which is unique per run). The snapshot is cleaned up in finally.
    snapshot_work_dir = os.path.join(evidence_dir, ".snapshots")
    snapshot_path = None
    try:
        try:
            snapshot_path, snapshot_sha, _ = _create_input_snapshot(
                input_path, snapshot_work_dir)
        except Exception as exc:
            add_reason(f"failed to create input snapshot: {exc!r}")
            result.details["stopped_at"] = "snapshot"
            return result
        result.details["input_snapshot_sha256"] = snapshot_sha
        result.details["input_snapshot_path"] = snapshot_path

        # Verify the snapshot SHA-256 matches the granted scope BEFORE
        # any other operation uses it. This is the authorization binding.
        if snapshot_sha.lower() != granted_scope.input_sha256.lower():
            add_reason("input snapshot SHA-256 does not match the granted "
                       "scope; authorization rejected")
            result.details["stopped_at"] = "snapshot-hash-mismatch"
            return result

        # ── Layer A: Input Contract Firewall (uses snapshot, not original) ──
        layer_a = validate_input_contract(
            snapshot_path,
            granted_scope.input_sha256,
            SOURCE_COLUMNS,
            max_rows=limits.max_rows,
            max_input_bytes=limits.max_input_bytes,
        )
        result.layers.append(layer_a.as_dict())
        if not layer_a.accepted:
            add_reason("Layer A rejected the input; execution never started")
            result.details["stopped_at"] = "A"
            return result

        # ── Layer F: Schema Evolution Guard (uses snapshot) ──────────
        with open(snapshot_path, "r", encoding="utf-8", newline="") as f:
            import csv as _csv
            header = next(_csv.reader(f), [])
        layer_f = assess_schema_evolution(header, SOURCE_COLUMNS)
        result.layers.append(layer_f.as_dict())
        if getattr(layer_f, "blocked", False):
            add_reason("Layer F classified the schema as INCOMPATIBLE")
            result.details["stopped_at"] = "F"
            return result

        # ── Layer G: Reference Data Versioning ───────────────────────
        layer_g = fingerprint_reference_data(reference_paths)
        result.layers.append(layer_g.as_dict())
        if not getattr(layer_g, "pinned", True):
            add_reason("Layer G could not pin reference data")
            result.details["stopped_at"] = "G"
            return result

        # ── Layer B: Execution Authorization Gate (uses snapshot) ────
        try:
            observed_scope = observe_scope(
                input_path=snapshot_path,
                authorized_columns=SOURCE_COLUMNS,
                v1_rules_path=v1_rules_path,
                reference_data_paths=reference_paths,
                config=config,
                execution_mode=execution_mode,
                software_paths=software_paths,
            )
        except Exception as exc:
            observed_scope = None
            result.details["scope_observation_error"] = repr(exc)
        layer_b = evaluate_authorization(granted_scope, observed_scope)
        result.layers.append(layer_b.as_dict())
        if not layer_b.authorized:
            add_reason("Layer B refused authorization; execution never started")
            result.details["stopped_at"] = "B"
            return result
        identity_sha = observed_scope.identity_sha256()
        result.details["execution_identity_sha256"] = identity_sha

        # ── Layer H: Pre-execution Resource Guard (uses snapshot) ─────
        pre = check_pre_execution(limits, snapshot_path)
        result.layers.append(pre.as_dict())
        if not getattr(pre, "pass_", True):
            add_reason(f"Layer H tripped before execution "
                       f"({getattr(pre, 'trip_reason', 'unknown')})")
            result.details["stopped_at"] = "H-pre"
            return result

        # ── Engine: in-process validation (uses snapshot, not original) ──
        rules = RuleRegistry.create_default()
        engine = ValidationEngine(
            rules=rules,
            run_id=run_id,
            evidence_dir=evidence_dir,
            config_thresholds=config_thresholds,
        )
        validation = engine.validate(csv_path=snapshot_path, output_path=output_path)
        result.validation = validation

        # ── Layer H: Post-execution Resource Guard ──────────────────
        produced = [output_path] if os.path.exists(output_path) else []
        post = check_post_execution(limits, produced)
        result.layers.append(post.as_dict())
        if not getattr(post, "pass_", True):
            add_reason(f"Layer H tripped after execution "
                       f"({getattr(post, 'trip_reason', 'unknown')})")
            result.details["stopped_at"] = "H-post"
            return result

        if not validation.success:
            add_reason(f"engine returned success=False: {validation.error}")
            result.details["stopped_at"] = "engine"
            return result

        result.verdict = VERDICT_PASS
        result.details["output_path"] = output_path
        result.details["evidence_dir"] = evidence_dir
        return result
    finally:
        # ── F-001: always clean up the snapshot ──────────────────────
        _cleanup_snapshot(snapshot_path)
