"""
Shield360 Auto-Initialization Bootstrap

This module automatically initializes Shield360 when Python starts
if SHIELD360_AUTO_INSTRUMENT environment variable is set.

This follows the same pattern as OpenTelemetry's auto-instrumentation.
"""

import os
import logging

# Import the centralized configuration
try:
    # First try absolute import
    from shield360.cli.config import build_config_from_environment
except ImportError:
    try:
        # Try relative import as fallback
        from ..config import build_config_from_environment
    except ImportError:
        # Final fallback - build config manually from environment
        def build_config_from_environment():
            """Build configuration from environment variables as fallback."""

            config = {}

            # Map environment variables to Shield360 parameters
            env_mappings = {
                "OTEL_SERVICE_NAME": "application_name",
                "OTEL_DEPLOYMENT_ENVIRONMENT": "environment",
                "OTEL_EXPORTER_OTLP_ENDPOINT": "otlp_endpoint",
                "OTEL_EXPORTER_OTLP_HEADERS": "otlp_headers",
                "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "capture_message_content",
                "SHIELD360_DISABLED_INSTRUMENTORS": "disabled_instrumentors",
                "SHIELD360_CONTROLLER_MODE": "controller_mode",
                "SHIELD360_DISABLE_BATCH": "disable_batch",
                "SHIELD360_DISABLE_METRICS": "disable_metrics",
                "SHIELD360_DISABLE_EVENTS": "disable_events",
                "SHIELD360_COLLECT_GPU_STATS": "collect_gpu_stats",
                "SHIELD360_PRICING_JSON": "pricing_json",
                "SHIELD360_CAPTURE_DB_PARAMETERS": "capture_db_parameters",
                "SHIELD360_MAX_CONTENT_LENGTH": "max_content_length",
                "SHIELD360_CUSTOM_SPAN_ATTRIBUTES": "custom_span_attributes",
            }

            for env_var, param_name in env_mappings.items():
                if env_value := os.environ.get(env_var):
                    # Handle boolean values
                    if env_var in [
                        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
                        "SHIELD360_DISABLE_BATCH",
                        "SHIELD360_DISABLE_METRICS",
                        "SHIELD360_DISABLE_EVENTS",
                        "SHIELD360_COLLECT_GPU_STATS",
                        "SHIELD360_CAPTURE_DB_PARAMETERS",
                    ]:
                        config[param_name] = env_value.lower() in ("true", "1", "yes")
                    # Handle CSV values
                    elif env_var == "SHIELD360_DISABLED_INSTRUMENTORS":
                        config[param_name] = [
                            item.strip()
                            for item in env_value.split(",")
                            if item.strip()
                        ]
                    # Handle JSON values
                    elif env_var in [
                        "OTEL_EXPORTER_OTLP_HEADERS",
                        "SHIELD360_CUSTOM_SPAN_ATTRIBUTES",
                    ]:
                        try:
                            import json

                            config[param_name] = json.loads(env_value)
                        except (json.JSONDecodeError, ImportError):
                            pass
                    # Handle integer values
                    elif env_var == "SHIELD360_MAX_CONTENT_LENGTH":
                        try:
                            config[param_name] = int(env_value)
                        except ValueError:
                            pass
                    else:
                        config[param_name] = env_value

            return config


# Set up logging for auto-instrumentation
logger = logging.getLogger(__name__)


def initialize(*, swallow_exceptions: bool = True) -> None:
    """
    Setup auto-instrumentation, called by the sitecustomize module

    :param swallow_exceptions: Whether or not to propagate instrumentation exceptions to the caller.
                              Exceptions are logged and swallowed by default.
    """
    # Prevents auto-instrumentation of subprocesses if code execs another python process
    if "PYTHONPATH" in os.environ:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        python_path = os.environ["PYTHONPATH"].split(os.pathsep)
        # Remove current directory from PYTHONPATH to prevent subprocess instrumentation
        python_path = [path for path in python_path if path != current_dir]
        os.environ["PYTHONPATH"] = os.pathsep.join(python_path)

    try:
        # Import Shield360 and initialize
        import shield360

        # Build configuration from environment variables
        config = build_config_from_environment()

        # Initialize Shield360 with environment variables
        shield360.init(**config)

    except ImportError as e:
        if not swallow_exceptions:
            raise
        logger.error("Shield360 not found. Please ensure shield360 is installed: %s", e)
    except Exception as e:
        if not swallow_exceptions:
            raise
        # Log error but don't break the application
        logger.error("Shield360 auto-instrumentation failed: %s", e)


# Auto-initialize when module is imported (like OpenTelemetry does)
initialize()
