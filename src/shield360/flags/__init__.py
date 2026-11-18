"""Shield360 feature flags.

    import shield360
    shield360.init(application_name="checkout-api")  # or SHIELD360_URL / SHIELD360_API_KEY

    if shield360.flags.is_enabled("new-checkout", {"key": user.id, "plan": user.plan}):
        ...
    model = shield360.flags.get_flag("model-choice", {"key": user.id}, "gpt-4o-mini")

Rules are fetched in the background and evaluated locally; nothing here raises
into your app, and the default is returned until rules arrive.
"""

from typing import Any, Dict, Optional

from shield360.flags._client import (  # noqa: F401
    DEFAULT_POLL_INTERVAL,
    RULES_PATH,
    SPAN_ATTRIBUTE_PREFIX,
    FlagsClient,
    prompt_ref_of,
)
from shield360.flags._engine import evaluate, validate_flag, validate_segment  # noqa: F401

#: The SDK's own client. It reads init()'s settings when it first fetches.
client = FlagsClient()


def configure(**options) -> None:
    """Sets url, api_key, application_name, poll_interval, timeout or record_on_span."""
    client.configure(**options)


def get_flag(key: str, context: Optional[Dict[str, Any]] = None, default: Any = None) -> Any:
    """The flag's value for this context, or ``default``. Never raises."""
    return client.get_flag(key, context, default)


def get_flag_detail(key: str, context: Optional[Dict[str, Any]] = None, default: Any = None) -> Dict[str, Any]:
    """{value, variation, reason} for this context. Never raises."""
    return client.get_flag_detail(key, context, default)


def is_enabled(key: str, context: Optional[Dict[str, Any]] = None) -> bool:
    """Whether a boolean flag is on for this context. Never raises."""
    return client.is_enabled(key, context)


def model(key: str, context: Optional[Dict[str, Any]] = None, default: str = "") -> str:
    """AI: the provider/model id a model-switch flag serves, or ``default``. Never raises."""
    return client.model(key, context, default)


def prompt(key: str, context: Optional[Dict[str, Any]] = None, default: Optional[Dict[str, Any]] = None, **options) -> Dict[str, Any]:
    """AI: the Prompt Hub prompt a prompt-version flag serves: {name, version, variation, prompt, error}."""
    return client.prompt(key, context, default, **options)


def kill_switch(key: str, context: Optional[Dict[str, Any]] = None) -> bool:
    """AI: whether a kill switch is engaged (True: stop the feature). Not engaged until rules arrive."""
    return client.kill_switch(key, context)


def refresh() -> bool:
    """Fetches the rules now."""
    return client.refresh()


def wait_until_ready(timeout: float = 10.0) -> bool:
    """Blocks until rules have been fetched once, or ``timeout`` seconds pass."""
    return client.wait_until_ready(timeout)


def close() -> None:
    """Stops polling."""
    client.close()


__all__ = [
    "FlagsClient",
    "client",
    "configure",
    "get_flag",
    "get_flag_detail",
    "is_enabled",
    "model",
    "prompt",
    "kill_switch",
    "prompt_ref_of",
    "refresh",
    "wait_until_ready",
    "close",
    "evaluate",
    "validate_flag",
    "validate_segment",
]
