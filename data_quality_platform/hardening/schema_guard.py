"""Layer F — Schema Evolution Guard.

Classifies the relationship between an OBSERVED column schema and the
AUTHORIZED column schema:

* ``SCHEMA_COMPATIBLE``      — exact match (names, order, count, types,
  nullability).
* ``SCHEMA_INCOMPATIBLE``    — any deletion, reordering, rename,
  position change, type change, or nullability change (fail-closed:
  execution must NOT proceed; a re-authorization cannot rescue a
  reordered/retyped input under the frozen V1 engine).
* ``REQUIRES_AUTHORIZATION`` — strictly additive trailing columns only
  (the observed schema equals the authorized schema plus new columns
  appended at the END with declared types). This is not silently
  accepted: it requires a NEW authorization grant (Layer B) before
  execution.

Type/nullability comparison is positional: for each authorized column
index, the observed type must equal the authorized type exactly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional, Sequence

LAYER_ID = "F"
LAYER_NAME = "Schema Evolution Guard"
LAYER_VERSION = "1.0.0"

VERDICT_COMPATIBLE = "SCHEMA_COMPATIBLE"
VERDICT_INCOMPATIBLE = "SCHEMA_INCOMPATIBLE"
VERDICT_REQUIRES_AUTH = "REQUIRES_AUTHORIZATION"

_ALLOWED_TYPES = ("string", "integer", "float", "nullable_string",
                  "nullable_integer", "nullable_float")


@dataclass
class SchemaEvolutionResult:
    layer_id: str = LAYER_ID
    layer_name: str = LAYER_NAME
    layer_version: str = LAYER_VERSION
    verdict: str = VERDICT_INCOMPATIBLE
    reasons: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def compatible(self) -> bool:
        return self.verdict == VERDICT_COMPATIBLE

    @property
    def blocked(self) -> bool:
        return self.verdict == VERDICT_INCOMPATIBLE

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


def _validate_type_decl(decl, column: str, errors: list) -> None:
    if decl is None:
        return
    if decl not in _ALLOWED_TYPES:
        errors.append(
            f"column {column!r} declares unsupported type {decl!r}")


def assess_schema_evolution(
    observed_columns: Sequence[str],
    authorized_columns: Sequence[str],
    observed_types: Optional[dict] = None,
    authorized_types: Optional[dict] = None,
) -> SchemaEvolutionResult:
    """Classify observed-vs-authorized schema evolution, fail-closed."""
    result = SchemaEvolutionResult()
    add = result.reasons.append
    observed = list(observed_columns)
    authorized = list(authorized_columns)
    result.details["observed_columns"] = observed
    result.details["authorized_columns"] = authorized
    result.details["observed_count"] = len(observed)
    result.details["authorized_count"] = len(authorized)

    observed_types = dict(observed_types or {})
    authorized_types = dict(authorized_types or {})

    # ── declared-type vocabulary validation ────────────────────────────
    decl_errors: list = []
    for col, decl in sorted(authorized_types.items()):
        _validate_type_decl(decl, f"authorized:{col}", decl_errors)
    for col, decl in sorted(observed_types.items()):
        _validate_type_decl(decl, f"observed:{col}", decl_errors)
    if decl_errors:
        add("; ".join(decl_errors))
        return result

    unknown_auth = sorted(
        c for c in authorized_types if c not in authorized)
    unknown_obs = sorted(
        c for c in observed_types if c not in observed)
    if unknown_auth:
        add("authorized_types declares columns absent from the "
            "authorized schema: " + ", ".join(unknown_auth))
    if unknown_obs:
        add("observed_types declares columns absent from the observed "
            "schema: " + ", ".join(unknown_obs))
    if unknown_auth or unknown_obs:
        return result

    # ── exact match → COMPATIBLE ──────────────────────────────────────
    if observed == authorized:
        type_changes = []
        for col in authorized:
            a = authorized_types.get(col)
            o = observed_types.get(col)
            if a is not None and o is not None and a != o:
                type_changes.append(
                    f"column {col!r}: authorized type {a!r}, observed "
                    f"type {o!r}")
            elif (a is None) != (o is None):
                type_changes.append(
                    f"column {col!r}: type declaration presence differs "
                    f"(authorized={a!r}, observed={o!r})")
        if type_changes:
            add("; ".join(type_changes))
            return result
        result.verdict = VERDICT_COMPATIBLE
        return result

    # ── structural classification ─────────────────────────────────────
    common = min(len(observed), len(authorized))
    pos_diffs = [
        f"position {i}: authorized {authorized[i]!r}, observed "
        f"{observed[i]!r}"
        for i in range(common) if observed[i] != authorized[i]
    ]
    if pos_diffs:
        add("column mismatch at fixed positions — reordering or rename: "
            + "; ".join(pos_diffs[:8]))

    removed = [c for c in authorized if c not in observed]
    if removed:
        add("columns deleted: " + ", ".join(removed))

    added = [c for c in observed if c not in authorized]
    if pos_diffs or removed:
        result.details["added_columns"] = added
        result.details["removed_columns"] = removed
        return result  # INCOMPATIBLE (fail-closed)

    # only additions remain: trailing-only test
    if observed[:len(authorized)] == authorized:
        result.details["added_columns"] = added
        add("strictly additive trailing columns require a NEW "
            "authorization grant: " + ", ".join(added))
        result.verdict = VERDICT_REQUIRES_AUTH
        return result

    add("added columns are not strictly trailing — insertion changes "
        "column positions: " + ", ".join(added))
    return result


def schema_fingerprint(columns: Sequence[str]) -> str:
    import hashlib
    payload = json.dumps(list(columns), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
