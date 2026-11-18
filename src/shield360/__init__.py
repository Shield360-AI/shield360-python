# pylint: disable=broad-exception-caught
"""
The __init__.py module for the shield360 package.
This module sets up the shield360 configuration and instrumentation for various
large language models (LLMs).
"""

from typing import Any, Dict
import logging
import os
from importlib.util import find_spec
from functools import wraps
from contextlib import ContextDecorator, contextmanager
import requests

# Import internal modules for setting up tracing and fetching pricing info.
from opentelemetry import trace as t
from opentelemetry.trace import SpanKind, Status, StatusCode, Span
from opentelemetry.sdk.resources import SERVICE_NAME, DEPLOYMENT_ENVIRONMENT
from shield360.semcov import SemanticConvention
from shield360.otel.tracing import setup_tracing
from shield360.otel.metrics import setup_meter
from shield360.otel.events import setup_events
from shield360.otel.build_info import SERVICE_VERSION, resolve_build_attributes
from shield360._feedback import (  # noqa: F401 — public re-exports
    configure_feedback,
    feedback,
    get_current_span_id,
    get_current_trace_id,
)
# SHIELD: application logs, opt-in.
from shield360.otel import app_logs as _app_logs
from shield360.otel.app_logs import capture_logs, stop_capturing_logs  # noqa: F401 — public API
from shield360.__helpers import (
    fetch_pricing_info,
    get_env_variable,
    set_agent_name,
    reset_agent_name,
    set_agent_version,
    reset_agent_version,
    set_custom_attributes,
    reset_custom_attributes,
    record_agent_invocation,
    record_agent_tool_error,
)
from shield360._config import Shield360Config  # noqa: F401 — re-exported for public API
from shield360._destination import resolve_destination
from shield360._noise import apply_default_excluded_urls
from shield360._instrumentors import (
    MODULE_NAME_MAP,
    get_all_instrumentors,
    normalize_instrumentor_names,
)

# Import GPU instrumentor separately as it doesn't follow the standard pattern
from shield360.instrumentation.gpu import GPUInstrumentor

# Import guards and evals
import shield360.guard
# Budget check: shield360.budgets.check() and the automatic pre-call check.
import shield360.budgets
from shield360.budgets import BudgetExceededError  # noqa: F401 — public re-export
import shield360.flags  # noqa: F401 — feature flags: shield360.flags.get_flag / is_enabled
# Cost per end customer: set_customer(), with customer(...), get_customer().
# The SDK never hashes: Shield360 stores user ids only as a keyed hash, and
# tenant ids as given unless the organisation opts to hash them.
from shield360._customer import (  # noqa: F401 — public re-exports
    CustomerSpanProcessor,
    customer,
    get_customer,
    set_customer,
)
import shield360.evals

# Re-export guard classes at top level for clean API:
#   shield360.PII(action="redact")  instead of  shield360.guard.PII(action="redact")
# Shield Protect re-exports: enforcement APIs, apart from the tracing ones.
from shield360.protect import (  # noqa: F401 — public re-exports
    protect_tool,
    authorize_with_shield360,
    protect_readiness,
    ProtectError,
    ProtectDeniedError,
    ProtectReadinessError,
)
from shield360.guard import (  # noqa: F401 — public re-exports
    PII,
    PromptInjection,
    SensitiveTopic,
    TopicRestriction,
    Moderation,
    Schema,
    Custom,
    Pipeline,
    Guard,
    GuardAction,
    GuardPhase,
    GuardResult,
    PipelineResult,
    GuardError,
    GuardDeniedError,
    GuardTimeoutError,
    GuardConfigError,
)
# SHIELD: runtime protection (RASP), opt-in: init(rasp=...), the runtime switch and the block error.
from shield360.rasp import RaspBlockedError, disable_rasp, enable_rasp  # noqa: F401 — public re-exports

# Set up logging for error and information messages.
logger = logging.getLogger(__name__)

CONTROLLER_MANAGED_DISABLED_INSTRUMENTORS = [
    "openai",
    "anthropic",
    "cohere",
    "mistral",
    "bedrock",
    "oci",
    "vertexai",
    "groq",
    "ollama",
    "vllm",
    "google-ai-studio",
    "azure-ai-inference",
    "litellm",
    "together",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "aiohttp-client",
]


def module_exists(module_name):
    """Check if nested modules exist, addressing the dot notation issue."""
    parts = module_name.split(".")
    for i in range(1, len(parts) + 1):
        if find_spec(".".join(parts[:i])) is None:
            return False
    return True


def is_opentelemetry_instrumentor(instrumentor_name):
    """Check if the instrumentor is an official OpenTelemetry instrumentor."""
    opentelemetry_instrumentors = {
        "asgi",
        "django",
        "fastapi",
        "flask",
        "pyramid",
        "starlette",
        "falcon",
        "tornado",
        "aiohttp-client",
        "httpx",
        "requests",
        "urllib",
        "urllib3",
        "sqlalchemy",
        "asyncpg",
        "psycopg2",
        "pymysql",
        "mysqlclient",
        "pymongo",
        "redis",
        "celery",
        "grpc-client",
        "grpc-server",
        "botocore",
        "kafka-python",
        "confluent-kafka",
    }
    return instrumentor_name in opentelemetry_instrumentors


def instrument_if_available(
    instrumentor_name, instrumentor_instance, config, disabled_instrumentors
):
    """Instruments the specified instrumentor if its library is available."""
    if instrumentor_name in disabled_instrumentors:
        logger.info("Instrumentor %s is disabled", instrumentor_name)
        return

    module_name = MODULE_NAME_MAP.get(instrumentor_name)
    if not module_name:
        logger.error("No module mapping for %s", instrumentor_name)
        return

    try:
        if module_exists(module_name):
            if is_opentelemetry_instrumentor(instrumentor_name):
                # OpenTelemetry instrumentations use the standard instrument() method
                instrumentor_instance.instrument()
                logger.info("OpenTelemetry instrumentor %s enabled", instrumentor_name)
            else:
                # Shield360 custom instrumentations use extended parameters
                instrumentor_instance.instrument(
                    environment=config.environment,
                    application_name=config.application_name,
                    pricing_info=config.pricing_info,
                    capture_message_content=config.capture_message_content,
                    disable_metrics=config.disable_metrics,
                    disable_events=config.disable_events,
                    capture_db_parameters=config.capture_db_parameters,
                )
        else:
            logger.info(
                "Library for %s (%s) not found. Skipping instrumentation",
                instrumentor_name,
                module_name,
            )
    except Exception as e:
        logger.error("Failed to instrument %s: %s", instrumentor_name, e)


def apply_controller_mode_defaults(controller_mode, disabled_instrumentors):
    """Apply controller-managed defaults for Shield360 auto-instrumentation."""
    normalized_disabled = normalize_instrumentor_names(disabled_instrumentors)
    if controller_mode != "agent_observability":
        return normalized_disabled

    merged = list(
        dict.fromkeys(
            normalized_disabled
            + normalize_instrumentor_names(CONTROLLER_MANAGED_DISABLED_INSTRUMENTORS)
        )
    )
    logger.info(
        "Controller-managed agent observability mode enabled; default duplicate-prone instrumentors will be disabled"
    )
    return merged



def _installed_version() -> str:
    try:
        from importlib.metadata import version

        return version("shield360")
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


def init(  # pylint: disable=too-many-arguments  # SHIELD: capture_logs, log_level
    environment="default",
    application_name="default",
    service_name="default",
    otlp_endpoint=None,
    otlp_headers=None,
    disable_batch=False,
    capture_message_content=None,
    disabled_instrumentors=None,
    disable_metrics=False,
    disable_events=False,
    pricing_json=None,
    controller_mode=None,
    collect_gpu_stats=False,
    collect_system_metrics=False,
    capture_db_parameters=False,
    max_content_length=None,
    custom_span_attributes=None,
    custom_metrics_attributes=None,
    shield360_api_key=None,
    shield360_url=None,
    *,
    guards=None,
    guard_fail_open=True,
    guard_heartbeat=None,
    protect=None,
    service_version=None,
    capture_code_location=None,
    code_root=None,
    budget_check=None,
    capture_logs=None,  # pylint: disable=redefined-outer-name
    log_level=None,
    ai_security=None,
    rasp=None,  # SHIELD: runtime protection
    runtime_packages=None,  # SHIELD: runtime SCA
):
    """
    Initializes the shield360 configuration and setups tracing.

    This function sets up the shield360 environment with provided configurations
    and initializes instrumentors for tracing. Existing OTel providers
    (TracerProvider, MeterProvider, LoggerProvider) are auto-detected and
    reused when already configured.

    Args:
        environment (str): Deployment environment.
        application_name (str): Application name.
        otlp_endpoint (str): OTLP endpoint for exporter (Optional).
        otlp_headers (Dict[str, str]): OTLP headers for exporter (Optional).
        disable_batch (bool): Flag to disable batch span processing (Optional).
        capture_message_content (bool): Flag to trace prompt and completion
            content (Optional). Off unless set here, in the config file or
            environment, or with OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true.
        disabled_instrumentors (List[str]): Optional. List of instrumentor names to disable.
                                          Common aliases are resolved automatically (e.g. "aiohttp"
                                          maps to "aiohttp-client"). Note: "urllib3" must be disabled
                                          separately from "requests" since requests uses urllib3
                                          internally.
        disable_metrics (bool): Flag to disable metrics (Optional).
        disable_events (bool): Flag to disable OTel Logger event emission (Optional).
        pricing_json(str): File path or url to the pricing json (Optional).
        collect_gpu_stats (bool): Flag to enable or disable GPU metrics collection.
        capture_db_parameters (bool): Capture database query parameters in per-key OTel format
                                      (db.query.parameter.<key>). WARNING: may expose sensitive data.
        max_content_length (int): Maximum character length for captured content attributes (prompts,
                                 completions, tool output, etc.). None (default) means no truncation.
                                 Set to a positive integer to truncate content to that length.
        custom_span_attributes (dict): Custom key-value attributes applied to every auto-instrumented
                                       span. Values must be valid OTel attribute types (str, int,
                                       float, bool, or sequences thereof). Optional.
        custom_metrics_attributes (dict): Custom key-value attributes applied to every metric
                                          recording. Useful for grouping metrics by custom tags
                                          (e.g., client ID, team, project). Values must be valid
                                          OTel attribute types. Optional.
        shield360_api_key (str): API key for Shield360 server (used by shield360.eval() and
                               shield360.get_prompt()). Falls back to SHIELD360_API_KEY env var.
        shield360_url (str): URL of the Shield360 server (used by shield360.eval() and
                           shield360.get_prompt()). Falls back to SHIELD360_URL env var.
        guards (list): List of Guard instances (e.g. ``[shield360.PII(action="redact")]``)
                       that automatically run on every LLM call.  Optional.
        guard_fail_open (bool): If True (default), guard errors resolve to allow.
                                Set to False for strict environments.
        guard_heartbeat (bool): With guards and a Shield360 URL and key, the SDK
                                tells Shield360 every few minutes which guards run
                                and in which mode (no content). False turns it off,
                                as does SHIELD360_GUARD_HEARTBEAT=false.
        protect (dict): Shield Protect: ``{"mode": "observe" | "warn" | "enforced",
                        "required": ["openai", ...]}``. The environment can raise
                        the mode (SHIELD360_PROTECT_MODE), never lower it, and add
                        required providers (SHIELD360_PROTECT_REQUIRED). In
                        enforced mode a guard failure refuses the call, a
                        streamed completion postflight guards cannot inspect is
                        refused, and init() raises ProtectReadinessError instead
                        of starting with a required provider unguarded.
        service_version (str): Release version, set as the ``service.version``
                               resource attribute. Falls back to
                               SHIELD360_SERVICE_VERSION, then OTEL_SERVICE_VERSION.
        capture_code_location (bool): Record the application call site
                               (code.function.name, code.file.path,
                               code.line.number) on GenAI spans. On by default;
                               overrides SHIELD360_CAPTURE_CODE_LOCATION.
        code_root (str): Directory that code.file.path is made relative to.
                         Falls back to SHIELD360_CODE_ROOT, then the git root.
        budget_check (bool | dict): Check this app's Shield360 budgets before each
                         provider call (``True``, or ``{"fail_closed": True}``);
                         a call a budget blocks raises BudgetExceededError.
                         Cached per the decision's ttl and headroom; fails open
                         unless fail_closed. Falls back to SHIELD360_BUDGET_CHECK.
                         ``shield360.budgets.check()`` works either way.
        capture_logs (bool): Send the application's ``logging`` records to
                             Shield360 (a handler on the root logger, at
                             ``log_level`` and above). Off by default; falls
                             back to SHIELD360_CAPTURE_LOGS.
        log_level (int | str): Lowest level sent when capture_logs is on.
                               INFO by default; falls back to SHIELD360_LOG_LEVEL.
        ai_security (bool | dict): The AI security pack (OWASP Top 10 for LLM
                         apps), monitoring by default: ``True`` uses the
                         platform's policy; a dict may add ``policy`` (from
                         code), ``config_public_key`` (required for the platform
                         policy; or SHIELD360_CONFIG_PUBLIC_KEY),
                         ``allow_unpinned_config`` (development only),
                         ``config_cache_file``,
                         ``auto_instrument`` (default True) and
                         ``record_allowed``. Falls back to SHIELD360_AI_SECURITY.
                         See ``shield360.ai_security``.
        rasp (bool | dict): Runtime application self-protection, off unless
                         set: ``True``, or a dict of ``mode``, ``attacks``,
                         ``allow``, ``model_output``, ``remote``,
                         ``config_public_key`` (required for the signed config;
                         or SHIELD360_CONFIG_PUBLIC_KEY), ``allow_unpinned_config``
                         (development only), ``cache_dir`` and ``components``.
                         SHIELD360_RASP=monitor|block turns it on, =off always
                         wins. See ``shield360.rasp``.
        runtime_packages (bool): Report the names and versions of the
                         packages this process imports (never paths) so
                         Shield360 can match them against vulnerability data.
                         On by default with a Shield360 URL and API key;
                         ``False`` or SHIELD360_RUNTIME_PACKAGES=off turns it
                         off. See ``shield360.runtime_packages``.
    """
    # SHIELD: shield360-instrument already started Shield360 from the environment: a second init() is a no-op.
    from shield360 import _zero_code  # pylint: disable=import-outside-toplevel

    if _zero_code.started():
        _zero_code.note_skipped_init()
        return

    disabled_instrumentors = normalize_instrumentor_names(disabled_instrumentors)
    logger.info("Starting shield360 initialization...")

    # Handle service_name/application_name migration
    # service_name takes precedence over application_name if both are provided
    if service_name != "default":
        # service_name explicitly provided, use it
        final_service_name = service_name
    elif application_name != "default":
        # Only application_name provided, use it (silent for backward compatibility)
        final_service_name = application_name
    else:
        # Both are default, will be handled by environment variables below
        final_service_name = "default"

    # Apply environment variables for parameters not explicitly provided
    # Environment variables take precedence over default values but not over explicit parameters
    try:
        from shield360.cli.config import build_config_from_environment

        env_config = build_config_from_environment()

        # Apply env vars only if function parameters are at their default values
        if environment == "default" and "environment" in env_config:
            environment = env_config["environment"]

        # Handle service name from environment (both service_name and application_name map to same env var)
        if final_service_name == "default":
            final_service_name = env_config.get(
                "service_name",
                env_config.get(
                    "application_name", "default"
                ),  # Fallback for backward compatibility
            )
        # Skip otlp_endpoint and otlp_headers - let existing code handle them
        if disable_batch is False and "disable_batch" in env_config:
            disable_batch = env_config["disable_batch"]
        if capture_message_content is None and "capture_message_content" in env_config:
            capture_message_content = env_config["capture_message_content"]
        if not disabled_instrumentors and "disabled_instrumentors" in env_config:
            disabled_instrumentors = normalize_instrumentor_names(
                env_config["disabled_instrumentors"]
            )
        if controller_mode is None and "controller_mode" in env_config:
            controller_mode = env_config["controller_mode"]
        if disable_metrics is False and "disable_metrics" in env_config:
            disable_metrics = env_config["disable_metrics"]
        if disable_events is False and "disable_events" in env_config:
            disable_events = env_config["disable_events"]
        if pricing_json is None and "pricing_json" in env_config:
            pricing_json = env_config["pricing_json"]
        if collect_gpu_stats is False and "collect_gpu_stats" in env_config:
            collect_gpu_stats = env_config["collect_gpu_stats"]
        if collect_system_metrics is False and "collect_system_metrics" in env_config:
            collect_system_metrics = env_config["collect_system_metrics"]
        if capture_db_parameters is False and "capture_db_parameters" in env_config:
            capture_db_parameters = env_config["capture_db_parameters"]
        if max_content_length is None and "max_content_length" in env_config:
            max_content_length = env_config["max_content_length"]
        if custom_span_attributes is None and "custom_span_attributes" in env_config:
            custom_span_attributes = env_config["custom_span_attributes"]
        if shield360_api_key is None and "shield360_api_key" in env_config:
            shield360_api_key = env_config["shield360_api_key"]
        if shield360_url is None and "shield360_url" in env_config:
            shield360_url = env_config["shield360_url"]
        if capture_logs is None and "capture_logs" in env_config:
            capture_logs = env_config["capture_logs"]
        if log_level is None and "log_level" in env_config:
            log_level = env_config["log_level"]

    except ImportError:
        # Fallback if config module is not available - continue without env var support
        pass

    if shield360_api_key is None:
        shield360_api_key = os.getenv("SHIELD360_API_KEY")
    if shield360_url is None:
        shield360_url = os.getenv("SHIELD360_URL")

    # With no OTLP endpoint, a Shield360 URL and API key are the destination:
    # the platform's authenticated ingest route, with the key as bearer.
    otlp_endpoint, otlp_headers = resolve_destination(
        otlp_endpoint, otlp_headers, shield360_url, shield360_api_key
    )

    disabled_instrumentors = apply_controller_mode_defaults(
        controller_mode,
        disabled_instrumentors,
    )
    if controller_mode == "agent_observability":
        custom_span_attributes = custom_span_attributes or {}
        custom_span_attributes.setdefault(
            "shield360.controller.mode",
            "agent_observability",
        )

    # Validate disabled instrumentors
    invalid_instrumentors = [
        name for name in disabled_instrumentors if name not in MODULE_NAME_MAP
    ]
    for invalid_name in invalid_instrumentors:
        lower_name = invalid_name.lower()
        suggestions = [k for k in MODULE_NAME_MAP if lower_name in k or k in lower_name]
        if suggestions:
            logger.warning(
                "Invalid instrumentor name '%s'. Did you mean: %s?",
                invalid_name,
                ", ".join(suggestions),
            )
        else:
            logger.warning(
                "Invalid instrumentor name detected and ignored: '%s'",
                invalid_name,
            )

    try:
        # Retrieve or create the single configuration instance.
        config = Shield360Config()

        # Build and VCS attributes (service.version, vcs.*), resolved once.
        resource_attributes = resolve_build_attributes(service_version)
        # User feedback names the application and release it was given for.
        configure_feedback(
            app=final_service_name, release=resource_attributes.get(SERVICE_VERSION)
        )

        # Setup tracing based on the provided or default configuration.
        tracer = setup_tracing(
            application_name=final_service_name,
            environment=environment,
            tracer=None,
            otlp_endpoint=otlp_endpoint,
            otlp_headers=otlp_headers,
            disable_batch=disable_batch,
            resource_attributes=resource_attributes,
            capture_code_location=capture_code_location,
            code_root=code_root,
        )

        if not tracer:
            logger.error("Shield360 tracing setup failed. Tracing will not be available.")

        # Setup events based on the provided or default configuration.
        # SHIELD: the resolved destination is passed, not left to the
        # environment tracing happened to set, so logs go where traces go.
        event_provider = setup_events(
            application_name=final_service_name,
            environment=environment,
            event_logger=None,
            otlp_endpoint=otlp_endpoint,
            otlp_headers=otlp_headers,
            disable_batch=disable_batch,
            resource_attributes=resource_attributes,
        )

        if not event_provider:
            logger.error("Shield360 events setup failed. Events will not be available")

        # SHIELD: application logs, through the same LoggerProvider. Nothing
        # is sent unless asked for (data minimisation).
        if capture_logs:
            _app_logs.capture_logs(level=log_level)

        # Setup meter and receive metrics_dict instead of meter.
        metrics_dict = None
        err = None
        if not disable_metrics:
            metrics_dict, err = setup_meter(
                application_name=final_service_name,
                environment=environment,
                meter=None,
                otlp_endpoint=otlp_endpoint,
                otlp_headers=otlp_headers,
                resource_attributes=resource_attributes,
            )

        if err:
            logger.error(
                "Shield360 metrics setup failed. Metrics will not be available: %s", err
            )
            # Set metrics_dict to None and disable metrics instead of returning early
            metrics_dict = None
            disable_metrics = True

        # Prompt and completion text is captured only when asked for: the
        # argument, the config file / SHIELD360_* environment, or the
        # OpenTelemetry GenAI variable. The default is off (data minimisation:
        # a Shield360 organisation stores no content unless it opts in).
        otel_capture = os.getenv(
            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", ""
        ).lower()
        if otel_capture == "false":
            capture_message_content = False
        elif capture_message_content is None:
            capture_message_content = otel_capture == "true"
        capture_message_content = bool(capture_message_content)

        # Update global configuration with the provided settings.
        config.update_config(
            environment,
            final_service_name,
            otlp_endpoint,
            otlp_headers,
            disable_batch,
            capture_message_content,
            metrics_dict,
            disable_metrics,
            fetch_pricing_info(pricing_json),
            disable_events,
            capture_db_parameters,
            max_content_length,
            custom_span_attributes,
            custom_metrics_attributes,
            shield360_api_key=shield360_api_key,
            shield360_url=shield360_url,
        )

        # SHIELD: health probes and the SDK's own calls to Shield360 are not traced.
        apply_default_excluded_urls(shield360_url)

        # Create instrumentor instances dynamically
        instrumentor_instances = get_all_instrumentors()

        # Initialize and instrument only the enabled instrumentors
        for name, instrumentor in instrumentor_instances.items():
            instrument_if_available(name, instrumentor, config, disabled_instrumentors)

        # Shield Protect: the mode and the required providers, merged with the environment.
        from shield360.protect._mode import resolve_protect, set_protect_state

        resolved_protect = resolve_protect(protect)

        # Set up auto-guards if configured (second wrapt pass over provider methods)
        if guards:
            try:
                from shield360.guard._integration import setup_auto_guards

                setup_auto_guards(guards, fail_open=guard_fail_open, protect=resolved_protect)

                # With a Shield360 URL and API key, what the guards stop is
                # also recorded in Shield360's Data protection report.
                from shield360.guard import _report

                _report.configure(
                    shield360_url,
                    shield360_api_key,
                    application_name=final_service_name,
                    environment=environment,
                    sdk_version=_installed_version(),
                    guards=list(guards),
                    heartbeat=guard_heartbeat,
                )
            except ProtectReadinessError:
                # Shield Protect: a readiness failure in enforced mode stops startup; it is never logged and swallowed.
                raise
            except Exception as e:
                logger.error("Failed to set up auto-guards: %s", e)
        elif resolved_protect.mode == "enforced" and resolved_protect.required:
            set_protect_state(resolved_protect.mode, [], resolved_protect.required)
            raise ProtectReadinessError(
                resolved_protect.required, "Shield360 Protect: enforced mode requires guards; pass guards to init()."
            )
        else:
            set_protect_state(resolved_protect.mode, [], [])

        # Budget check: the process's client, and the automatic pre-call check when asked for.
        try:
            if budget_check is None:
                budget_check = (os.getenv("SHIELD360_BUDGET_CHECK") or "").strip().lower() in ("1", "true", "yes")
            budget_options = {"app": final_service_name}
            if isinstance(budget_check, dict) and budget_check.get("fail_closed") is not None:
                budget_options["fail_closed"] = bool(budget_check["fail_closed"])
            budget_client = shield360.budgets.configure(**budget_options)
            if budget_check:
                shield360.budgets.setup_auto_budget_check(budget_client)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to set up the budget check: %s", e)

        # AI security pack: on when asked for; monitors by default.
        try:
            if ai_security is None:
                ai_security = (os.getenv("SHIELD360_AI_SECURITY") or "").strip().lower() in ("1", "true", "yes")
            if ai_security:
                import shield360.ai_security as _ai_security  # pylint: disable=import-outside-toplevel
                options = ai_security if isinstance(ai_security, dict) else {}
                _ai_security.configure(
                    url=shield360_url,
                    api_key=shield360_api_key,
                    app=final_service_name,
                    environment=config.environment,
                    policy=options.get("policy"),
                    config_public_key=options.get("config_public_key"),
                    allow_unpinned_config=bool(options.get("allow_unpinned_config")),
                    config_cache_file=options.get("config_cache_file"),
                    record_allowed=bool(options.get("record_allowed")),
                )
                if options.get("auto_instrument", True):
                    _ai_security.setup_ai_security()
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to set up AI security: %s", e)

        # SHIELD: runtime SCA — names and versions of the packages imported, on unless
        # runtime_packages=False or SHIELD360_RUNTIME_PACKAGES=off. Started before RASP,
        # which then leaves its own components report to it. Never raises.
        try:
            from shield360.runtime_packages import start_runtime_packages  # pylint: disable=import-outside-toplevel

            start_runtime_packages(
                shield360_url,
                shield360_api_key,
                final_service_name,
                environment=environment,
                sdk_version=_installed_version(),
                option=runtime_packages,
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to start the runtime package report: %s", e)

        # SHIELD: runtime protection (RASP): off unless asked for; never raises.
        from shield360.rasp import init_rasp

        init_rasp(
            rasp,
            application_name=final_service_name,
            environment=environment,
            url=shield360_url,
            api_key=shield360_api_key,
            sdk_version=_installed_version(),
            otlp_endpoint=otlp_endpoint,
        )

        # Handle GPU instrumentation separately (only if GPU is found)
        if not disable_metrics and collect_gpu_stats:
            gpu_instrumentor = GPUInstrumentor()
            if gpu_instrumentor._get_gpu_type():  # Only instrument if GPU is detected
                gpu_instrumentor.instrument(
                    environment=config.environment,
                    application_name=config.application_name,
                )
            else:
                logger.info("No GPU detected, skipping GPU metrics collection")

        # Handle OpenTelemetry System Metrics instrumentation
        if not disable_metrics and collect_system_metrics:
            try:
                from opentelemetry.instrumentation.system_metrics import (
                    SystemMetricsInstrumentor,
                )

                SystemMetricsInstrumentor().instrument()

                # Auto-enable GPU metrics if GPU is detected (comprehensive system monitoring)
                gpu_instrumentor = GPUInstrumentor()
                if gpu_instrumentor._get_gpu_type():
                    gpu_instrumentor.instrument(
                        environment=config.environment,
                        application_name=config.application_name,
                    )

            except ImportError:
                logger.warning(
                    "OpenTelemetry system metrics not available. "
                    "Install with: pip install opentelemetry-instrumentation-system-metrics"
                )
            except Exception as e:
                logger.error("Failed to enable system metrics: %s", e)
    except Exception as e:
        logger.error("Error during shield360 initialization: %s", e)


def get_prompt(
    url=None,
    name=None,
    api_key=None,
    prompt_id=None,
    version=None,
    should_compile=None,
    variables=None,
    meta_properties=None,
):
    """
    Retrieve and returns the prompt from Shield360 Prompt Hub
    """

    # Validate and set the base URL
    url = get_env_variable(
        "SHIELD360_URL",
        url,
        "Missing Shield360 URL: Provide as arg or set SHIELD360_URL env var.",
    )

    # Validate and set the API key
    api_key = get_env_variable(
        "SHIELD360_API_KEY",
        api_key,
        "Missing API key: Provide as arg or set SHIELD360_API_KEY env var.",
    )

    # Construct the API endpoint
    endpoint = url + "/api/prompt/get-compiled"

    # Prepare the payload
    payload = {
        "name": name,
        "promptId": prompt_id,
        "version": version,
        "shouldCompile": should_compile,
        "variables": variables,
        "metaProperties": meta_properties,
        "source": "python-sdk",
    }

    # Remove None values from payload
    payload = {k: v for k, v in payload.items() if v is not None}

    # Prepare headers
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        # Make the POST request to the API with headers
        response = requests.post(endpoint, json=payload, headers=headers, timeout=120)

        # Check if the response is successful
        response.raise_for_status()

        # Return the JSON response
        return response.json()
    except requests.RequestException as error:
        logger.error("Error fetching prompt: '%s'", error)
        return None


def get_secrets(url=None, api_key=None, key=None, tags=None, should_set_env=None):
    """
    Retrieve & returns the secrets from Shield360 Vault & sets all to env is should_set_env is True
    """

    # Validate and set the base URL
    url = get_env_variable(
        "SHIELD360_URL",
        url,
        "Missing Shield360 URL: Provide as arg or set SHIELD360_URL env var.",
    )

    # Validate and set the API key
    api_key = get_env_variable(
        "SHIELD360_API_KEY",
        api_key,
        "Missing API key: Provide as arg or set SHIELD360_API_KEY env var.",
    )

    # Construct the API endpoint
    endpoint = url + "/api/vault/get-secrets"

    # Prepare the payload
    payload = {"key": key, "tags": tags, "source": "python-sdk"}

    # Remove None values from payload
    payload = {k: v for k, v in payload.items() if v is not None}

    # Prepare headers
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        # Make the POST request to the API with headers
        response = requests.post(endpoint, json=payload, headers=headers, timeout=120)

        # Check if the response is successful
        response.raise_for_status()

        # Return the JSON response
        vault_response = response.json()

        res = vault_response.get("res", [])

        if should_set_env is True:
            for token, value in res.items():
                os.environ[token] = str(value)
        return vault_response
    except requests.RequestException as error:
        logger.error("Error fetching secrets: '%s'", error)
        return None


def evaluate_rule(
    url=None,
    api_key=None,
    entity_type=None,
    fields=None,
    include_entity_data=False,
    entity_inputs=None,
):
    """
    Evaluate rules against the Shield360 Rule Engine and retrieve matching
    rules, entities, and optionally entity data (contexts, prompts, etc.).

    Args:
        url (str): Shield360 dashboard URL. Falls back to SHIELD360_URL env var.
        api_key (str): API key for authentication. Falls back to SHIELD360_API_KEY env var.
        entity_type (str): Type of entity to match — "context", "prompt", or "evaluation".
        fields (dict): Trace attributes to evaluate against rules.
            e.g. {"gen_ai.system": "openai", "gen_ai.request.model": "gpt-4"}
        include_entity_data (bool): If True, include full entity data in response.
        entity_inputs (dict): Optional inputs for entity resolution (e.g. prompt variables).

    Returns:
        dict: Server response with matchingRuleIds, entities, and optionally entity_data.
        None: If the request fails.
    """

    # Validate and set the base URL
    url = get_env_variable(
        "SHIELD360_URL",
        url,
        "Missing Shield360 URL: Provide as arg or set SHIELD360_URL env var.",
    )

    # Validate and set the API key
    api_key = get_env_variable(
        "SHIELD360_API_KEY",
        api_key,
        "Missing API key: Provide as arg or set SHIELD360_API_KEY env var.",
    )

    # Construct the API endpoint
    endpoint = url + "/api/rule-engine/evaluate"

    # Prepare the payload
    payload = {
        "entity_type": entity_type,
        "fields": fields,
        "include_entity_data": include_entity_data,
        "entity_inputs": entity_inputs,
        "source": "python-sdk",
    }

    # Remove None values from payload
    payload = {k: v for k, v in payload.items() if v is not None}

    # Prepare headers
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        # Make the POST request to the API with headers
        response = requests.post(endpoint, json=payload, headers=headers, timeout=120)

        # Check if the response is successful
        response.raise_for_status()

        # Return the JSON response
        return response.json()
    except requests.RequestException as error:
        logger.error("Error evaluating rule: '%s'", error)
        return None


def eval(  # pylint: disable=redefined-builtin
    prompt,
    response,
    contexts=None,
    eval_types=None,
    attributes=None,
    threshold_score=None,
    store_results=None,
    run_id=None,
    metadata=None,
    shield360_api_key=None,
    shield360_url=None,
    print_results=True,
):
    """
    Run offline evaluation against the Shield360 server.
    Uses the same evaluation engine, rules, and contexts as online/auto evals.
    """
    from shield360.evals.offline import run_eval

    return run_eval(
        prompt=prompt,
        response=response,
        contexts=contexts,
        eval_types=eval_types,
        attributes=attributes,
        threshold_score=threshold_score,
        store_results=store_results,
        run_id=run_id,
        metadata=metadata,
        shield360_api_key=shield360_api_key,
        shield360_url=shield360_url,
        print_results=print_results,
    )


def eval_batch(
    dataset,
    eval_types=None,
    attributes=None,
    threshold_score=None,
    store_results=None,
    run_id=None,
    max_concurrent=5,
    shield360_api_key=None,
    shield360_url=None,
    print_results=True,
):
    """
    Run offline evaluation on a batch of prompt/response pairs.
    """
    from shield360.evals.offline import run_eval_batch

    return run_eval_batch(
        dataset=dataset,
        eval_types=eval_types,
        attributes=attributes,
        threshold_score=threshold_score,
        store_results=store_results,
        run_id=run_id,
        max_concurrent=max_concurrent,
        shield360_api_key=shield360_api_key,
        shield360_url=shield360_url,
        print_results=print_results,
    )


def get_eval_types(shield360_api_key=None, shield360_url=None):
    """
    Fetch available evaluation types from the Shield360 server.
    """
    from shield360.evals.offline import fetch_eval_types

    return fetch_eval_types(
        shield360_api_key=shield360_api_key,
        shield360_url=shield360_url,
    )


def log_agent_invocation(source, target, system=None):
    """
    Record that one agent invoked another.

    Usage:
        shield360.log_agent_invocation("orchestrator", "product_agent")
    """
    try:
        metrics = Shield360Config.metrics_dict
        if metrics:
            record_agent_invocation(metrics, source, target, system)
    except Exception as e:
        logger.debug("Failed to record agent invocation: %s", e)


def log_agent_tool_error(agent_name, tool_name, system=None, model=None):
    """
    Record that a tool execution failed for an agent.

    Usage:
        shield360.log_agent_tool_error("cart_agent", "add_to_cart",
                                      system="anthropic", model="claude-haiku-4-5")
    """
    try:
        metrics = Shield360Config.metrics_dict
        if metrics:
            record_agent_tool_error(
                metrics, agent_name, tool_name, system=system, model=model
            )
    except Exception as e:
        logger.debug("Failed to record agent tool error: %s", e)


def log_score(
    name,
    value,
    *,
    span=None,
    trace_id=None,
    span_id=None,
    comment=None,
    idempotency_key=None,
    metadata=None,
):
    """
    Record an external evaluation score or user feedback on a GenAI span.

    When called inside an instrumented LLM request, the score auto-attaches to
    the active span. You can also pass ``span``, or ``trace_id`` and ``span_id``
    for async feedback against a past trace.

    Returns ``True`` when a score event was emitted and ``False`` otherwise.

    Usage:
        shield360.log_score("user_feedback", True, comment="Helpful response")
        shield360.log_score("quality", 0.85, metadata={"reviewer": "human"})
        shield360.log_score("category", "accurate")
    """
    from shield360.score import record_evaluation_score

    try:
        return record_evaluation_score(
            name,
            value,
            span=span,
            trace_id=trace_id,
            span_id=span_id,
            comment=comment,
            idempotency_key=idempotency_key,
            metadata=metadata,
        )
    except (ValueError, TypeError):
        raise
    except Exception as e:
        logger.debug("Failed to record evaluation score: %s", e)
        return False


@contextmanager
def agent_context(name):
    """
    Context manager that sets the current agent name for metric attribution.

    Any LLM calls made within this context will have their metrics tagged
    with gen_ai.agent.name=<name>.

    Usage:
        with shield360.agent_context("product_agent"):
            # LLM calls here will be attributed to product_agent
            client.messages.create(...)
    """
    token = set_agent_name(name)
    try:
        yield
    finally:
        reset_agent_name(token)


@contextmanager
def agent_version_context(version):
    """
    Context manager that sets the current agent version label.

    LLM calls inside this context will have their chat span / inference event
    tagged with ``gen_ai.agent.version=<version>`` so the server-side
    materializer can group traces by the caller-supplied label in addition to
    the auto-computed ``shield360.agent.version_hash`` fingerprint.

    Usage::

        with shield360.agent_version_context("v3"):
            client.chat.completions.create(...)
    """
    token = set_agent_version(version)
    try:
        yield
    finally:
        reset_agent_version(token)


class using_attributes(ContextDecorator):
    """
    Context manager and decorator to add custom attributes to all
    auto-instrumented spans created within its scope.

    Attributes are only applied to spans created while the context is active.
    Values must be valid OTel attribute types (str, int, float, bool, or
    sequences thereof).

    As context manager:
        with shield360.using_attributes({"user.id": "u1", "team": "ml"}):
            client.chat.completions.create(...)

    As decorator:
        @shield360.using_attributes({"user.id": "u1"})
        def my_func():
            client.chat.completions.create(...)
    """

    def __init__(self, attributes: Dict[str, Any]):
        self._attributes = attributes
        self._token = None

    def __enter__(self):
        self._token = set_custom_attributes(self._attributes)
        return self

    def __exit__(self, *exc):
        reset_custom_attributes(self._token)
        return False


def inject_additional_attributes(fn, attributes: Dict[str, Any]):
    """
    Execute *fn()* with custom span attributes attached to all
    auto-instrumented spans created during its execution.

    Usage:
        response = shield360.inject_additional_attributes(
            lambda: client.chat.completions.create(...),
            {"user.id": "u123", "experiment": "v2"},
        )
    """
    token = set_custom_attributes(attributes)
    try:
        return fn()
    finally:
        reset_custom_attributes(token)


def trace(wrapped):
    """
    Generates a telemetry wrapper for messages to collect metrics.
    """
    if not callable(wrapped):
        raise TypeError(
            f"@trace can only be applied to callable objects, got {type(wrapped).__name__}"
        )

    try:
        __trace = t.get_tracer_provider()
        tracer = __trace.get_tracer(__name__)
    except Exception as tracer_exception:
        logging.error(
            "Failed to initialize tracer: %s", tracer_exception, exc_info=True
        )
        raise

    @wraps(wrapped)
    def wrapper(*args, **kwargs):
        with tracer.start_as_current_span(
            name=wrapped.__name__,
            kind=SpanKind.CLIENT,
        ) as span:
            response = None
            try:
                response = wrapped(*args, **kwargs)
                span.set_attribute(
                    SemanticConvention.GEN_AI_OUTPUT_MESSAGES, response or ""
                )
                span.set_status(Status(StatusCode.OK))
            except Exception as e:
                span.record_exception(e)
                span.set_status(status=Status(StatusCode.ERROR), description=str(e))
                logging.error("Error in %s: %s", wrapped.__name__, e, exc_info=True)
                raise

            try:
                span.set_attribute("function.args", str(args))
                span.set_attribute("function.kwargs", str(kwargs))
                span.set_attribute(
                    SERVICE_NAME,
                    Shield360Config.application_name,
                )
                span.set_attribute(DEPLOYMENT_ENVIRONMENT, Shield360Config.environment)
            except Exception as meta_exception:
                logging.error(
                    "Failed to set metadata for %s: %s",
                    wrapped.__name__,
                    meta_exception,
                    exc_info=True,
                )

            return response

    return wrapper


class TracedSpan:
    """
    A wrapper class for an OpenTelemetry span that provides helper methods
    for setting result and metadata attributes on the span.

    Attributes:
        _span (Span): The underlying OpenTelemetry span.
    """

    def __init__(self, span):
        """
        Initializes the TracedSpan with the given span.

        Params:
            span (Span): The OpenTelemetry span to be wrapped.
        """

        self._span: Span = span

    def set_result(self, result):
        """
        Sets the result attribute on the underlying span.

        Params:
            result: The result to be set as an attribute on the span.
        """

        self._span.set_attribute(SemanticConvention.GEN_AI_OUTPUT_MESSAGES, result)

    def set_metadata(self, metadata: Dict):
        """
        Sets multiple attributes on the underlying span.

        Params:
            metadata (Dict): A dictionary of attributes to be set on the span.
        """

        self._span.set_attributes(attributes=metadata)

    def __enter__(self):
        """
        Enters the context of the TracedSpan, returning itself.

        Returns:
            TracedSpan: The instance of TracedSpan.
        """

        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        """
        Exits the context of the TracedSpan by ending the underlying span.
        """

        self._span.end()


@contextmanager
def start_trace(name: str):
    """
    A context manager that starts a new trace and provides a TracedSpan
    for usage within the context.

    Params:
        name (str): The name of the span.

    Yields:
        TracedSpan: The wrapped span for trace operations.
    """

    __trace = t.get_tracer_provider()
    with __trace.get_tracer(__name__).start_as_current_span(
        name,
        kind=SpanKind.CLIENT,
    ) as span:
        yield TracedSpan(span)
