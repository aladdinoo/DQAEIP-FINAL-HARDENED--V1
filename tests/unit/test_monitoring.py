from data_quality_platform.monitoring.quality import QualityMonitor


class TestQualityMonitor:
    def setup_method(self):
        self.monitor = QualityMonitor()

    def test_compute_all_dimensions(self):
        self.monitor.compute(
            total_rows=1000,
            flag_counts={
                "email_blank": 50,
                "email_syntax_failure": 30,
                "first_name_cleaning_candidate": 20,
                "last_name_cleaning_candidate": 15,
                "name_cleaning_candidate": 10,
                "proposed_email_export_eligible": 900,
                "zip_state_assessable": 800,
                "geography_mismatch_candidate": 40,
            },
            blank_counts={"id": 0, "email_address": 50, "first_name": 10, "last_name": 5, "state": 2, "zip": 2, "registration_date": 20},
            unique_id_count=1000,
            zip_state_mismatch_count=40,
            zip_state_assessable_count=800,
        )
        assert len(self.monitor.scores) == 8
        assert "completeness" in self.monitor.scores
        assert "validity" in self.monitor.scores
        assert self.monitor.overall_score > 0

    def test_zero_rows(self):
        self.monitor.compute(
            total_rows=0,
            flag_counts={},
            blank_counts={},
            unique_id_count=0,
            zip_state_mismatch_count=0,
            zip_state_assessable_count=0,
        )
        assert self.monitor.overall_score == 0.0
        assert not self.monitor.sla_passed

    def test_perfect_data(self):
        self.monitor.compute(
            total_rows=100,
            flag_counts={
                "email_blank": 0, "email_syntax_failure": 0,
                "first_name_cleaning_candidate": 0, "last_name_cleaning_candidate": 0,
                "name_cleaning_candidate": 0, "proposed_email_export_eligible": 100,
                "zip_state_assessable": 100, "geography_mismatch_candidate": 0,
            },
            blank_counts={"id": 0, "email_address": 0, "first_name": 0, "last_name": 0, "state": 0, "zip": 0, "registration_date": 0},
            unique_id_count=100,
            zip_state_mismatch_count=0,
            zip_state_assessable_count=100,
        )
        assert self.monitor.overall_score == 1.0
        assert self.monitor.sla_passed

    def test_sla_breach(self):
        strict = QualityMonitor(thresholds={"completeness": 0.99})
        strict.compute(
            total_rows=1000,
            flag_counts={
                "email_blank": 100, "email_syntax_failure": 0,
                "first_name_cleaning_candidate": 0, "last_name_cleaning_candidate": 0,
                "name_cleaning_candidate": 0, "proposed_email_export_eligible": 900,
                "zip_state_assessable": 1000, "geography_mismatch_candidate": 0,
            },
            blank_counts={"id": 0, "email_address": 100, "first_name": 0, "last_name": 0, "state": 0, "zip": 0, "registration_date": 0},
            unique_id_count=1000,
            zip_state_mismatch_count=0,
            zip_state_assessable_count=1000,
        )
        # completeness = 1 - 100/1000 = 0.9, threshold 0.99
        assert not strict.sla_passed

    def test_check_sla(self):
        self.monitor.compute(
            total_rows=100,
            flag_counts={
                "email_blank": 0, "email_syntax_failure": 0,
                "first_name_cleaning_candidate": 0, "last_name_cleaning_candidate": 0,
                "name_cleaning_candidate": 0, "proposed_email_export_eligible": 100,
                "zip_state_assessable": 100, "geography_mismatch_candidate": 0,
            },
            blank_counts={"id": 0, "email_address": 0, "first_name": 0, "last_name": 0, "state": 0, "zip": 0, "registration_date": 0},
            unique_id_count=100,
            zip_state_mismatch_count=0,
            zip_state_assessable_count=100,
        )
        passed, results = self.monitor.check_sla()
        assert passed

    def test_get_results(self):
        self.monitor.compute(
            total_rows=100,
            flag_counts={
                "email_blank": 0, "email_syntax_failure": 0,
                "first_name_cleaning_candidate": 0, "last_name_cleaning_candidate": 0,
                "name_cleaning_candidate": 0, "proposed_email_export_eligible": 100,
                "zip_state_assessable": 100, "geography_mismatch_candidate": 0,
            },
            blank_counts={"id": 0, "email_address": 0, "first_name": 0, "last_name": 0, "state": 0, "zip": 0, "registration_date": 0},
            unique_id_count=100,
            zip_state_mismatch_count=0,
            zip_state_assessable_count=100,
        )
        results = self.monitor.get_results()
        assert "scores" in results
        assert "thresholds" in results
        assert "sla_results" in results
        assert "overall_score" in results
