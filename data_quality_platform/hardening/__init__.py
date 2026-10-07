"""Operational hardening envelope for the DQAEIP validation engine.

Layers (each is a fail-closed verdict object; no layer ever converts
an error into a PASS):

A. Input Contract Firewall      -> :mod:`data_quality_platform.hardening.input_contract`
B. Execution Authorization Gate -> :mod:`data_quality_platform.hardening.authorization`
D. Atomic Output Commit          -> internal to ``validation/engine.py``
   (temp file + fsync + os.replace inside ``ValidationEngine.validate()``)
F. Schema Evolution Guard       -> :mod:`data_quality_platform.hardening.schema_guard`
G. Reference-Data Versioning    -> :mod:`data_quality_platform.hardening.reference_data`
H. Resource / Execution Guard    -> :mod:`data_quality_platform.hardening.resource_guard`

Single execution boundary: :func:`data_quality_platform.hardening.pipeline.run_validation`.

Layers C (idempotency ledger) and E (checkpoint contract) are not
required in the simplified architecture; the engine is deterministic,
and a fresh full re-run is the safe equivalent of any interrupted run.
"""

HARDENING_PACKAGE = "data_quality_platform.hardening"
HARDENING_LAYER_VERSION = "3.1.0-hardened"

LAYERS = (
    ("A", "input_contract", "Input Contract Firewall"),
    ("B", "authorization", "Execution Authorization Gate"),
    ("F", "schema_guard", "Schema Evolution Guard"),
    ("G", "reference_data", "Reference-Data Versioning"),
    ("H", "resource_guard", "Resource / Execution Guard"),
)

FROZEN_V1_SHA256 = (
    "daef1ded54c7d3c79898a1ba253be2acd5b6120e18b16b09009fdd7be9fc2276"
)

__all__ = [
    "HARDENING_PACKAGE",
    "HARDENING_LAYER_VERSION",
    "LAYERS",
    "FROZEN_V1_SHA256",
]
