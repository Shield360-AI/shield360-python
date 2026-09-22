"""Tests for disable_metrics in shield360.init()."""

import shield360
import shield360.otel.metrics as metrics_module


class TestDisableMetrics:
    """Regression tests for issue #1319."""

    def setup_method(self):
        """Reset meter state before each test."""
        metrics_module.METER_SET = False
        shield360.Shield360Config.reset_to_defaults()

    def test_disable_metrics_skips_meter_setup(self):
        """disable_metrics=True should not initialize the meter provider."""
        shield360.init(disable_metrics=True)
        assert shield360.Shield360Config.disable_metrics is True
        assert shield360.Shield360Config.metrics_dict is None
        assert metrics_module.METER_SET is False

    def test_disable_metrics_false_sets_up_meter(self):
        """disable_metrics=False should initialize metrics as usual."""
        shield360.init(disable_metrics=False)
        assert shield360.Shield360Config.disable_metrics is False
        assert shield360.Shield360Config.metrics_dict is not None
        assert metrics_module.METER_SET is True
