"""
AWS Lambda support: ``wrap_handler`` traces each invocation as a ``faas`` span
(OpenTelemetry FaaS semantic conventions) and flushes traces, metrics and logs
before the invocation returns, so nothing is lost when Lambda freezes the
execution environment::

    from shield360.aws_lambda import wrap_handler

    @wrap_handler
    def handler(event, context):
        ...

The flush is bounded (``SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS``, 2000 ms by
default, and never past the invocation's own deadline), so a slow or
unreachable collector cannot make the function time out.

The Shield360 Lambda layer needs no code changes: its exec wrapper sets the
function's handler to ``shield360.aws_lambda.handler`` and passes the original
in ``SHIELD360_LAMBDA_HANDLER``. Shield360 starts before the function's module
is imported, so the provider SDKs it imports are instrumented.
"""

import functools
import importlib
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, Optional

from opentelemetry import context as otel_context
from opentelemetry import propagate, trace
from opentelemetry.trace import SpanKind, Status, StatusCode

logger = logging.getLogger("shield360")

DEFAULT_FLUSH_TIMEOUT_MS = 2000
# Time left for the runtime to return the result after the flush gives up.
DEADLINE_MARGIN_MS = 100
TRACER_NAME = "shield360-lambda"

_state = {"cold": True, "initialized": False}
_lock = threading.Lock()


def _take_cold_start() -> bool:
    """True for the first invocation in this execution environment (not for provisioned concurrency)."""
    with _lock:
        cold = _state["cold"]
        _state["cold"] = False
    return cold and os.environ.get("AWS_LAMBDA_INITIALIZATION_TYPE") != "provisioned-concurrency"


def reset_for_testing() -> None:
    """Tests only."""
    _state["cold"] = True
    _state["initialized"] = False
    _original["handler"] = None


def detect_trigger(event: Any) -> str:
    """The ``faas.trigger`` value for an incoming event, read from its shape."""
    if not isinstance(event, dict):
        return "other"
    request_context = event.get("requestContext")
    if isinstance(request_context, dict) and (
        event.get("httpMethod") or request_context.get("http") or request_context.get("elb")
    ):
        return "http"
    if event.get("httpMethod") and event.get("headers") is not None:
        return "http"
    records = event.get("Records")
    if isinstance(records, list) and records and isinstance(records[0], dict):
        source = str(records[0].get("eventSource") or records[0].get("EventSource") or "")
        if source in ("aws:sqs", "aws:sns", "aws:kinesis", "aws:kafka"):
            return "pubsub"
        if source in ("aws:s3", "aws:dynamodb"):
            return "datasource"
    if event.get("source") == "aws.events" and event.get("detail-type") == "Scheduled Event":
        return "timer"
    if event.get("source") == "aws.scheduler":
        return "timer"
    return "other"


def _unqualified_arn(arn: str) -> str:
    parts = arn.split(":")
    return ":".join(parts[:7]) if len(parts) > 7 else arn


def invocation_attributes(event: Any, context: Any, cold_start: bool, trigger: Optional[str] = None) -> Dict[str, Any]:
    """Span attributes for one invocation: FaaS and cloud semantic conventions, plus HTTP basics."""
    trigger = trigger or detect_trigger(event)
    attrs: Dict[str, Any] = {
        "faas.trigger": trigger,
        "faas.coldstart": cold_start,
        "cloud.provider": "aws",
        "cloud.platform": "aws_lambda",
    }
    name = getattr(context, "function_name", None) or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    if name:
        attrs["faas.name"] = name
    version = getattr(context, "function_version", None) or os.environ.get("AWS_LAMBDA_FUNCTION_VERSION")
    if version:
        attrs["faas.version"] = version
    request_id = getattr(context, "aws_request_id", None)
    if request_id:
        attrs["faas.invocation_id"] = request_id
    try:
        memory = int(getattr(context, "memory_limit_in_mb", None) or os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE") or 0)
    except (TypeError, ValueError):
        memory = 0
    if memory > 0:
        attrs["faas.max_memory"] = memory * 1024 * 1024
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if region:
        attrs["cloud.region"] = region
    arn = getattr(context, "invoked_function_arn", None)
    if arn:
        attrs["aws.lambda.invoked_arn"] = arn
        attrs["cloud.resource_id"] = _unqualified_arn(arn)
        parts = arn.split(":")
        if len(parts) >= 5 and parts[4]:
            attrs["cloud.account.id"] = parts[4]
    if trigger == "http" and isinstance(event, dict):
        http = (event.get("requestContext") or {}).get("http") or {}
        method = event.get("httpMethod") or http.get("method")
        if method:
            attrs["http.request.method"] = str(method)
        path = event.get("rawPath") or event.get("path") or http.get("path")
        if path:
            attrs["url.path"] = str(path)
        route_key = event.get("routeKey")
        route = route_key.split(" ", 1)[-1] if route_key and route_key != "$default" else event.get("resource")
        if route:
            attrs["http.route"] = str(route)
    return attrs


def _span_name(context: Any, attrs: Dict[str, Any]) -> str:
    if attrs.get("faas.trigger") == "http" and attrs.get("http.request.method"):
        if attrs.get("http.route"):
            return f"{attrs['http.request.method']} {attrs['http.route']}"
        return str(attrs["http.request.method"])
    return str(getattr(context, "function_name", None) or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or "lambda")


def flush_budget(context: Any, configured: Optional[int] = None) -> int:
    """The flush budget in ms: the configured timeout, cut short by the invocation's deadline."""
    budget = configured
    if budget is None:
        try:
            budget = int(os.environ.get("SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS") or DEFAULT_FLUSH_TIMEOUT_MS)
        except ValueError:
            budget = DEFAULT_FLUSH_TIMEOUT_MS
        if budget <= 0:
            budget = DEFAULT_FLUSH_TIMEOUT_MS
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if callable(remaining):
        try:
            budget = min(budget, max(0, int(remaining()) - DEADLINE_MARGIN_MS))
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    return budget


def _providers():
    found = []
    candidates = [trace.get_tracer_provider()]
    try:
        from opentelemetry import metrics  # pylint: disable=import-outside-toplevel

        candidates.append(metrics.get_meter_provider())
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    try:
        from opentelemetry import _logs  # pylint: disable=import-outside-toplevel

        candidates.append(_logs.get_logger_provider())
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    for provider in candidates:
        if callable(getattr(provider, "force_flush", None)) and provider not in found:
            found.append(provider)
    return found


def flush_telemetry(timeout_ms: int = DEFAULT_FLUSH_TIMEOUT_MS) -> bool:
    """Flushes every registered trace, metric and log provider within ``timeout_ms`` in total.

    Returns True when everything flushed in time. Never raises.
    """
    deadline = time.monotonic() + max(0, timeout_ms) / 1000.0
    ok = True
    for provider in _providers():
        left_ms = int((deadline - time.monotonic()) * 1000)
        if left_ms <= 0:
            return False
        try:
            result = provider.force_flush(timeout_millis=left_ms)
            if result is False:
                ok = False
        except TypeError:
            try:
                provider.force_flush()
            except Exception:  # pylint: disable=broad-exception-caught
                ok = False
        except Exception:  # pylint: disable=broad-exception-caught
            ok = False
    return ok


def init_from_environment() -> None:
    """Starts Shield360 from SHIELD360_* / OTEL_* variables once, named after the function by default."""
    if _state["initialized"]:
        return
    _state["initialized"] = True
    if not os.environ.get("OTEL_SERVICE_NAME") and os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        os.environ["OTEL_SERVICE_NAME"] = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    try:
        import shield360  # pylint: disable=import-outside-toplevel
        from shield360 import _zero_code  # pylint: disable=import-outside-toplevel
        from shield360.cli.config import build_config_from_environment  # pylint: disable=import-outside-toplevel

        if _zero_code.started():
            return
        config = build_config_from_environment()
        config.setdefault("application_name", os.environ.get("OTEL_SERVICE_NAME", "default"))
        shield360.init(**config)
        _zero_code.mark_started()
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Shield360: Lambda start-up failed (%s: %s); the function runs without Shield360.", type(e).__name__, e)


def _sdk_started() -> bool:
    provider = trace.get_tracer_provider()
    return type(provider).__name__ not in ("ProxyTracerProvider", "NoOpTracerProvider")


def _record_result(span, trigger: str, result: Any) -> None:
    if trigger != "http" or not isinstance(result, dict):
        return
    try:
        status = int(result.get("statusCode"))
    except (TypeError, ValueError):
        return
    span.set_attribute("http.response.status_code", status)
    if status >= 500:
        span.set_status(Status(StatusCode.ERROR))


def wrap_handler(
    func: Optional[Callable] = None, *, flush_timeout_ms: Optional[int] = None, auto_init: bool = True
):
    """Wraps a Lambda handler so each invocation is traced and telemetry is flushed before it returns.

    Use as ``@wrap_handler`` or ``@wrap_handler(flush_timeout_ms=1000)``. With ``auto_init``
    (the default), Shield360 starts from the environment when nothing has started it yet.
    """
    if func is None:
        return functools.partial(wrap_handler, flush_timeout_ms=flush_timeout_ms, auto_init=auto_init)
    if not callable(func):
        raise TypeError("Shield360: wrap_handler() expects the Lambda handler function.")
    if auto_init and not _sdk_started():
        init_from_environment()

    @functools.wraps(func)
    def shield360_lambda_handler(event, context):
        cold_start = _take_cold_start()
        trigger = detect_trigger(event)
        attributes = invocation_attributes(event, context, cold_start, trigger)
        parent = otel_context.get_current()
        if trigger == "http" and isinstance(event, dict) and isinstance(event.get("headers"), dict):
            carrier = {str(k).lower(): v for k, v in event["headers"].items() if isinstance(v, str)}
            parent = propagate.extract(carrier)
        kind = SpanKind.CONSUMER if trigger in ("pubsub", "datasource") else SpanKind.SERVER
        tracer = trace.get_tracer(TRACER_NAME)
        try:
            with tracer.start_as_current_span(
                _span_name(context, attributes), context=parent, kind=kind, attributes=attributes
            ) as span:
                result = func(event, context)
                _record_result(span, trigger, result)
                return result
        finally:
            flush_telemetry(flush_budget(context, flush_timeout_ms))

    return shield360_lambda_handler


_original: Dict[str, Optional[Callable]] = {"handler": None}


def load_original_handler(spec: Optional[str] = None) -> Callable:
    """Imports the function's own handler named by ``SHIELD360_LAMBDA_HANDLER`` (``module.function``)."""
    value = (spec if spec is not None else os.environ.get("SHIELD360_LAMBDA_HANDLER", "")).strip()
    if not value:
        raise RuntimeError(
            "Shield360: SHIELD360_LAMBDA_HANDLER is not set; set it to the function's own handler, e.g. app.handler."
        )
    module_path, sep, func_name = value.rpartition(".")
    if not sep or not module_path or not func_name:
        raise RuntimeError(f'Shield360: SHIELD360_LAMBDA_HANDLER "{value}" is not in the form module.function.')
    module = importlib.import_module(module_path.replace("/", "."))
    target = getattr(module, func_name, None)
    if not callable(target):
        raise RuntimeError(f"Shield360: {value} is not a function in {module_path}.")
    return target


def _wrapped_original() -> Callable:
    wrapped = _original["handler"]
    if wrapped is None:
        init_from_environment()
        wrapped = wrap_handler(load_original_handler(), auto_init=False)
        _original["handler"] = wrapped
    return wrapped


def handler(event, context):
    """The entry point the Shield360 layer sets as the function's handler."""
    return _wrapped_original()(event, context)


# Start Shield360 and import the function during the init phase, so the work counts as initialization.
# A failure here is raised again by the first invocation.
if os.environ.get("SHIELD360_LAMBDA_HANDLER") and os.environ.get("SHIELD360_LAMBDA_EAGER", "").lower() != "false":
    try:
        _wrapped_original()
    except Exception:  # pylint: disable=broad-exception-caught
        _original["handler"] = None
