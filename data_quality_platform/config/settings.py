"""Platform configuration loaded from YAML and environment variables.

The simplified configuration surface covers only what the runtime
actually consumes: SLA thresholds forwarded to ``QualityMonitor``.
ClickHouse, Slack and SMTP are NOT wired into the runtime — the
production code has no ClickHouse client and no network calls — so
they are no longer declared as configuration fields.
"""

import os
import warnings
from dataclasses import dataclass, asdict
from typing import Any, Dict
import yaml


@dataclass
class PlatformConfig:
    """Central configuration for the DQAEIP runtime."""

    # SLA thresholds (consumed by QualityMonitor)
    completeness_threshold: float = 0.95
    validity_threshold: float = 0.95
    consistency_threshold: float = 0.90
    uniqueness_threshold: float = 0.95
    accuracy_threshold: float = 0.90
    freshness_threshold: float = 0.95
    geography_quality_threshold: float = 0.90
    email_quality_threshold: float = 0.95

    # Evidence settings (consumed by the engine + manifest writer)
    evidence_base_dir: str = "evidence"
    generate_manifests: bool = True
    compute_sha256: bool = True
    fsync_evidence: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> "PlatformConfig":
        """Load configuration from a YAML file.

        A missing file yields pure dataclass defaults — no error, no
        warning. An explicit ``--config`` path that does not exist is
        rejected by the CLI (N1 hardening) before this method is called.
        """
        if not os.path.exists(path):
            return cls()
        raw: Dict[str, Any] = yaml.safe_load(open(path, "r")) or {}
        config_dict: Dict[str, Any] = {}
        for section, values in raw.items():
            if not isinstance(values, dict):
                continue
            if section == "quality_thresholds":
                for key, val in values.items():
                    field_name = f"{key}_threshold" if not key.endswith("_threshold") else key
                    if field_name not in cls.__dataclass_fields__:
                        warnings.warn(f"unknown quality threshold {key!r} ignored")
                        continue
                    if val is not None:
                        config_dict[field_name] = float(val)
            elif section in ("evidence",):
                for key, val in values.items():
                    if key in cls.__dataclass_fields__ and val is not None:
                        config_dict[key] = val
            # Unknown sections (security, monitoring, clickhouse) are
            # silently ignored — they are no longer runtime configuration.
        return cls(**{k: v for k, v in config_dict.items() if k in cls.__dataclass_fields__})

    def get_quality_thresholds(self) -> Dict[str, float]:
        return {
            "completeness": self.completeness_threshold,
            "validity": self.validity_threshold,
            "consistency": self.consistency_threshold,
            "uniqueness": self.uniqueness_threshold,
            "accuracy": self.accuracy_threshold,
            "freshness": self.freshness_threshold,
            "geography_quality": self.geography_quality_threshold,
            "email_quality": self.email_quality_threshold,
        }

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)
