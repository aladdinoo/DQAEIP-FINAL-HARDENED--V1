import json
import os
from typing import Any, Dict, Optional, Tuple


class SLABreach(Exception):
    """Raised when SLA thresholds are breached."""
    pass


class QualityMonitor:
    """Computes 8 quality dimensions and evaluates SLA thresholds.

    This class is actively called by ValidationEngine.
    Dimensions:
    1. Completeness
    2. Validity
    3. Consistency
    4. Uniqueness
    5. Accuracy
    6. Freshness
    7. Geography Quality
    8. Email Quality
    """

    def __init__(self, thresholds: Optional[Dict[str, float]] = None):
        self.thresholds = thresholds or {
            "completeness": 0.95,
            "validity": 0.95,
            "consistency": 0.90,
            "uniqueness": 0.95,
            "accuracy": 0.90,
            "freshness": 0.95,
            "geography_quality": 0.90,
            "email_quality": 0.95,
        }
        self.scores: Dict[str, float] = {}
        self.sla_results: Dict[str, bool] = {}
        self.overall_score: float = 0.0
        self.sla_passed: bool = True

    def compute(
        self,
        total_rows: int,
        flag_counts: Dict[str, int],
        blank_counts: Dict[str, int],
        unique_id_count: int,
        zip_state_mismatch_count: int,
        zip_state_assessable_count: int,
    ) -> Dict[str, Any]:
        """Compute all quality dimensions.

        Args:
            total_rows: total number of rows processed
            flag_counts: dict of rule_id -> count of flagged rows
            blank_counts: dict of column_name -> count of blank values
            unique_id_count: number of unique id values
            zip_state_mismatch_count: rows with ZIP/state mismatch
            zip_state_assessable_count: rows where ZIP/state could be assessed
        """
        if total_rows == 0:
            for dim in self.thresholds:
                self.scores[dim] = 0.0
                self.sla_results[dim] = False
            self.overall_score = 0.0
            self.sla_passed = False
            return self.get_results()

        # 1. Completeness: fraction of rows with no blank critical fields
        critical_fields_blank = sum(blank_counts.get(f, 0) for f in ["id", "email_address", "first_name", "last_name", "state", "zip"])
        completeness = max(0.0, 1.0 - (critical_fields_blank / total_rows))
        self.scores["completeness"] = round(completeness, 4)

        # 2. Validity: fraction of rows with no email issues
        email_issues = flag_counts.get("email_blank", 0) + flag_counts.get("email_syntax_failure", 0)
        validity = max(0.0, 1.0 - (email_issues / total_rows))
        self.scores["validity"] = round(validity, 4)

        # 3. Consistency: fraction of assessable rows with no ZIP/state mismatch
        if zip_state_assessable_count > 0:
            consistency = max(0.0, 1.0 - (zip_state_mismatch_count / zip_state_assessable_count))
        else:
            consistency = 1.0  # Nothing to assess = no inconsistency detected
        self.scores["consistency"] = round(consistency, 4)

        # 4. Uniqueness: fraction of unique IDs
        uniqueness = unique_id_count / total_rows
        self.scores["uniqueness"] = round(uniqueness, 4)

        # 5. Accuracy: proxy via name quality (inverse of name cleaning candidates)
        name_flags = flag_counts.get("first_name_cleaning_candidate", 0) + flag_counts.get("last_name_cleaning_candidate", 0)
        accuracy = max(0.0, 1.0 - (name_flags / total_rows))
        self.scores["accuracy"] = round(accuracy, 4)

        # 6. Freshness: for V1, use registration_date presence as a proxy
        # If most rows have registration_date, freshness is high
        reg_blank = blank_counts.get("registration_date", 0)
        freshness = max(0.0, 1.0 - (reg_blank / total_rows))
        self.scores["freshness"] = round(freshness, 4)

        # 7. Geography Quality: inverse of geography mismatch among assessable
        if zip_state_assessable_count > 0:
            geo_quality = max(0.0, 1.0 - (zip_state_mismatch_count / zip_state_assessable_count))
        else:
            geo_quality = 1.0
        self.scores["geography_quality"] = round(geo_quality, 4)

        # 8. Email Quality: fraction of rows with valid, non-blank email
        export_eligible = flag_counts.get("proposed_email_export_eligible", 0)
        email_quality = export_eligible / total_rows
        self.scores["email_quality"] = round(email_quality, 4)

        # Check SLA
        self.sla_passed = True
        for dim, threshold in self.thresholds.items():
            score = self.scores.get(dim, 0.0)
            passed = score >= threshold
            self.sla_results[dim] = passed
            if not passed:
                self.sla_passed = False

        # Overall score: average of all dimensions
        self.overall_score = round(
            sum(self.scores.values()) / len(self.scores), 4
        ) if self.scores else 0.0

        return self.get_results()

    def compute_overall_score(self) -> float:
        """Return the overall quality score."""
        return self.overall_score

    def check_sla(self) -> Tuple[bool, Dict[str, bool]]:
        """Check SLA compliance. Returns (passed, per-dimension results)."""
        return self.sla_passed, dict(self.sla_results)

    def get_results(self) -> Dict[str, Any]:
        """Return all monitoring results as a dict."""
        return {
            "scores": dict(self.scores),
            "thresholds": dict(self.thresholds),
            "sla_results": dict(self.sla_results),
            "overall_score": self.overall_score,
            "sla_passed": self.sla_passed,
        }

    def persist(self, evidence_dir: str) -> str:
        """Write monitoring results to evidence directory."""
        os.makedirs(evidence_dir, exist_ok=True)
        path = os.path.join(evidence_dir, "monitoring.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.get_results(), f, indent=2)
        return path
