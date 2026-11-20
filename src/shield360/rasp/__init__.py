"""
Shield360 runtime application self-protection (RASP), opt-in.

    shield360.init(rasp={"config_public_key": os.environ["SHIELD360_CONFIG_PUBLIC_KEY"]})
    app = RaspASGIMiddleware(app)          # or RaspWSGIMiddleware, rasp_flask(app), RaspDjangoMiddleware

or ``SHIELD360_RASP=monitor|block``. ``SHIELD360_RASP=off`` always wins.
sdk/rasp/README.md is the contract. Fail open everywhere: the only error RASP
raises on purpose is ``RaspBlockedError``, which the middleware turns into a 403.

This covers request capture, model output as input, the detection engine
and its detectors, virtual patches, custom rules, passive IAST, the signed
config, events, sink rules, and the sink hooks (``_hooks/``: subprocess and ``os`` process functions,
files, outbound HTTP, database drivers, code, module includes, deserialization, XML, HTML
responses), installed when RASP is on. ``rasp_check`` runs a check at a sink
of the app's own.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
from typing import Any, Dict, List, Mapping, Optional, Union
from urllib.parse import urlsplit

from shield360.rasp._config_client import RaspConfigClient, parse_public_keys
from shield360.rasp._context import (
    RaspContext,
    current_context as current_rasp_context,
    inputs_of,
    run_in_rasp_scope,
    run_with_inputs,
)
from shield360.rasp._engine import (
    RemoteConfig,
    current_application_name as rasp_application_name,
    check as rasp_check,
    configure_engine,
    env_setting,
    is_active,
    set_event_sink,
    set_monitor_only,
    set_remote_config,
    set_runtime_disabled,
)
from shield360.rasp._hooks import install_hooks, uninstall_hooks
from shield360.rasp._iast import configure_iast, set_iast_remote, set_iast_sink
from shield360.rasp._middleware import (
    RaspASGIMiddleware,
    RaspDjangoMiddleware,
    RaspWSGIMiddleware,
    is_rasp_blocked,
    rasp_flask,
    record_request_body,
)
from shield360.rasp._model_output import record_model_output, record_model_response, record_tool_arguments
from shield360.rasp._reporter import RaspReporter, collect_components
from shield360.rasp._rule_expr import RULE_EXPR_LIMITS, RULE_FIELDS, compile_rule_expr, evaluate_rule_expr
from shield360.rasp._sinks import BUILT_IN_SINKS, parse_sink_rule, parse_sink_rules, set_sink_rules
from shield360.rasp._types import ATTACK_TYPES, BLOCK_MESSAGE, Finding, RaspBlockedError, RaspInput, block_body
from shield360.rasp._edge_context import parse_edge_keys, sign_verdict, verify_edge_context  # noqa: F401 — protection triangle API

logger = logging.getLogger(__name__)

from shield360.rasp._upload import inspect_upload  # noqa: E402
from shield360.rasp._upload_deep import run_connection_test, set_reputation_client  # noqa: E402
from shield360.rasp._upload_policy import configure_uploads, set_remote_uploads, upload_config  # noqa: E402

__all__ = [
    "ATTACK_TYPES",
    "inspect_upload",
    "BLOCK_MESSAGE",
    "RULE_EXPR_LIMITS",
    "RULE_FIELDS",
    "Finding",
    "RaspASGIMiddleware",
    "RaspBlockedError",
    "RaspContext",
    "RaspDjangoMiddleware",
    "RaspInput",
    "RaspWSGIMiddleware",
    "block_body",
    "compile_rule_expr",
    "current_rasp_context",
    "disable",
    "disable_rasp",
    "enable",
    "enable_rasp",
    "evaluate_rule_expr",
    "init_rasp",
    "inputs_of",
    "is_rasp_blocked",
    "parse_sink_rule",
    "parse_sink_rules",
    "rasp_active",
    "rasp_application_name",
    "rasp_check",
    "rasp_flask",
    "record_model_output",
    "record_model_response",
    "record_request_body",
    "record_tool_arguments",
    "run_in_rasp_scope",
    "run_with_inputs",
    "set_monitor_only",
    "shutdown_rasp",
]

_COMPONENTS_EVERY_S = 24 * 60 * 60
_PRODUCTION = frozenset(("prod", "production"))


def always_allowed_hosts(urls: List[Optional[str]]) -> List[str]:
    """The hosts of the Shield360 URL and the OTLP endpoint (README "SSRF": always allowed)."""
    hosts: List[str] = []
    for u in urls:
        try:
            host = urlsplit(u).hostname if u else None
        except ValueError:
            host = None
        if host and host.lower() not in hosts:
            hosts.append(host.lower())
    return hosts


def tofu_allowed(option: Optional[bool], env: Optional[Mapping[str, str]] = None, environment: Optional[str] = None) -> bool:
    """Whether trust on first use is allowed: the explicit opt-in
    (``allow_unpinned_config`` or ``SHIELD360_CONFIG_TOFU=dev``), never when
    ``NODE_ENV``, ``ENVIRONMENT``, ``ASPNETCORE_ENVIRONMENT`` or the SDK's own
    ``environment`` says production."""
    env = os.environ if env is None else env
    asked = option is True or (env.get("SHIELD360_CONFIG_TOFU") or "").strip().lower() == "dev"
    if not asked:
        return False
    names = [env.get("NODE_ENV"), env.get("ENVIRONMENT"), env.get("ASPNETCORE_ENVIRONMENT"), environment]
    return not any((v or "").strip().lower() in _PRODUCTION for v in names)


_warned_unpinned = False


def _warn_unpinned_once() -> None:
    """One log line per process when the config key is not pinned (not a reported event)."""
    global _warned_unpinned
    if _warned_unpinned:
        return
    _warned_unpinned = True
    logger.warning(
        "Shield360 RASP: the signed config key is not pinned, so the signed config is not used and RASP runs its built-in "
        "defaults in monitor mode. Set config_public_key (or SHIELD360_CONFIG_PUBLIC_KEY) to the environment's public key "
        "from the app's Runtime protection settings in Shield360."
    )


def reset_rasp_warnings() -> None:
    """Tests only: lets the once-per-process warning fire again."""
    global _warned_unpinned
    _warned_unpinned = False


class _Runtime:
    client: Optional[RaspConfigClient] = None
    reporter: Optional[RaspReporter] = None
    components_stop: Optional[threading.Event] = None
    always_allowed: List[str] = []


_runtime = _Runtime()


def _to_remote(c: Dict[str, Any]) -> RemoteConfig:
    return RemoteConfig(
        version=c["version"],
        exp=c["exp"],
        kill_switch=c.get("killSwitch") is True,
        snippets=c.get("snippets") is True,
        report_targets=c.get("reportTargets") is True,
        mode=c.get("mode"),
        attacks=c["attacks"] if isinstance(c.get("attacks"), dict) else {},
        allow=c["allow"] if isinstance(c.get("allow"), dict) else None,
        rules=c["rules"] if isinstance(c.get("rules"), list) else None,
        sinks=c["sinks"] if isinstance(c.get("sinks"), list) else None,
        custom_rules=c["customRules"] if isinstance(c.get("customRules"), list) else None,
        deception=c.get("deception"),
        # SHIELD: protection triangle — the environment's Edge context keys.
        edge_keys=parse_edge_keys(c.get("edgeContext")),
    )


def resolve_rasp_options(option: Union[bool, Dict[str, Any], None], env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Normalizes ``init(rasp=...)``: True, False, or options (a dict means on unless ``enabled`` is False)."""
    e = env_setting(env)
    o = dict(option) if isinstance(option, dict) else {}
    enabled = option is True or (isinstance(option, dict) and o.get("enabled") is not False)
    if option is None and e in ("monitor", "block"):
        enabled = True
    if e == "off":
        enabled = False
    o["enabled"] = enabled
    return o


def shutdown_rasp() -> None:
    """Removes the sink hooks and stops polling, reporting and the components timer (tests, re-init)."""
    uninstall_hooks()
    r = _runtime
    client, reporter, components_stop = r.client, r.reporter, r.components_stop
    r.client = r.reporter = r.components_stop = None
    if client is not None:
        client.stop()
    if components_stop is not None:
        components_stop.set()
    set_event_sink(None)
    set_iast_sink(None)
    if reporter is not None:
        reporter.stop()


def _start_components(reporter: RaspReporter) -> threading.Event:
    stop = threading.Event()

    def run() -> None:
        while True:
            try:
                reporter.report_components(collect_components())
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            if stop.wait(_COMPONENTS_EVERY_S):
                return

    threading.Thread(target=run, name="shield360-rasp-components", daemon=True).start()
    return stop


def init_rasp(
    option: Union[bool, Dict[str, Any], None],
    application_name: str = "default",
    environment: Optional[str] = None,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    sdk_version: Optional[str] = None,
    otlp_endpoint: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    fetch: Any = None,
    urlopen: Any = None,
) -> bool:
    """Turns RASP on (or leaves it off) for this process. Returns whether it is on. Never raises.

    ``option`` is ``True``, ``False``, or a dict of the contract's local
    options: ``enabled``, ``mode``, ``attacks``, ``allow`` (``commands``,
    ``outbound_hosts``, ``file_roots``), ``model_output``, ``remote``,
    ``config_public_key``, ``allow_unpinned_config``, ``cache_dir``,
    ``components``, ``rules_time_budget_ms`` (custom rules' time cap per
    request, default 25), ``iast`` (passive IAST: ``True``, or
    ``{"enabled": True, "sample_rate": 0.5}``; README "Passive IAST").
    """
    try:
        shutdown_rasp()
        env = os.environ if env is None else env
        o = resolve_rasp_options(option, env)
        remote_wanted = o["enabled"] and o.get("remote") is not False and bool(url and api_key)
        key = o.get("config_public_key")
        pinned = parse_public_keys(key if key is not None else env.get("SHIELD360_CONFIG_PUBLIC_KEY"))
        tofu = not pinned and tofu_allowed(o.get("allow_unpinned_config"), env, environment)
        unpinned = remote_wanted and not pinned and not tofu
        configure_engine(
            enabled=o["enabled"],
            application_name=application_name,
            mode=o.get("mode"),
            attacks=o.get("attacks"),
            allow=o.get("allow"),
            model_output=o.get("model_output"),
            # No pinned key while a remote config was expected: built-in defaults, monitor only.
            monitor_only=unpinned,
            env=env,
            rules_time_budget_ms=o.get("rules_time_budget_ms"),
        )
        set_sink_rules(BUILT_IN_SINKS)
        configure_iast(o.get("iast"), application_name=application_name, environment=environment, env=env)
        # SHIELD: uploads — inspection, deep scan and backdoor checks (README "Uploads").
        configure_uploads(o.get("uploads"))
        set_reputation_client(url, api_key)
        if not o["enabled"]:
            return False
        # The outbound check always allows the Shield360 and OTLP hosts.
        _runtime.always_allowed = always_allowed_hosts([url, otlp_endpoint])
        install_hooks(_runtime.always_allowed)

        if url and api_key:
            reporter = RaspReporter(
                url, api_key, application_name, environment=environment, sdk_version=sdk_version, urlopen=urlopen
            )
            reporter.start()
            set_event_sink(reporter)
            set_iast_sink(reporter)
            _runtime.reporter = reporter
            # SHIELD: runtime SCA — when the runtime package report runs it already sends these.
            from shield360.runtime_packages import runtime_packages_active  # pylint: disable=import-outside-toplevel

            if o.get("components") is not False and not runtime_packages_active():
                _runtime.components_stop = _start_components(reporter)

        def warn(reason: str) -> None:
            # Logged once per reason (the client dedupes); trust on first use was already announced at start.
            if reason != "trust_on_first_use":
                logger.warning(
                    "Shield360 RASP: a signed config was refused (%s); the last verified config or the local options stay in force.",
                    reason,
                )

        def on_config(claims: Optional[Dict[str, Any]]) -> None:
            remote = _to_remote(claims) if claims else None
            set_remote_config(remote)
            set_iast_remote(claims)
            set_remote_uploads(claims.get("uploads") if claims else None)
            threading.Thread(target=run_connection_test, args=(upload_config().deep_scan,), daemon=True).start()
            # The platform's sink rules replace the built-in list when present.
            set_sink_rules(parse_sink_rules(remote.sinks) if remote is not None and remote.sinks is not None else BUILT_IN_SINKS)

        if unpinned:
            _warn_unpinned_once()
        elif remote_wanted:
            if tofu:
                logger.warning(
                    "Shield360 RASP: trust on first use is on for the signed config (development only); "
                    "set config_public_key before production."
                )
            client = RaspConfigClient(
                url=str(url),
                api_key=str(api_key),
                app=application_name,
                pinned=pinned,
                allow_unpinned=tofu,
                cache_dir=o.get("cache_dir") or os.path.join(tempfile.gettempdir(), "shield360-rasp"),
                on_config=on_config,
                on_warning=warn,
                fetch=fetch,
            )
            _runtime.client = client
            client.start()
        return True
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Shield360 RASP could not start: %s", type(e).__name__)
        return False


def disable_rasp() -> None:
    """The runtime kill switch: checks return immediately until ``enable_rasp()``."""
    set_runtime_disabled(True)


def enable_rasp() -> None:
    """Undoes ``disable_rasp()``. The env switch and the signed config's kill switch still win."""
    set_runtime_disabled(False)


# The contract's Python names for the runtime switch: shield360.rasp.disable() / enable().
disable = disable_rasp
enable = enable_rasp


def rasp_active() -> bool:
    """Whether RASP checks run right now (on, and no kill switch)."""
    return is_active()
