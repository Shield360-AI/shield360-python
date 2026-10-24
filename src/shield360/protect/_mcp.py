"""
Shield Protect -- the pre-execution check on an MCP client's ``tools/call``.

The MCP instrumentation records every call; this is the one place it can
refuse one. The tool's arguments, as canonical JSON, go through the preflight
guards ``init()`` installed, under the process's Protect mode: observe
records, warn records and logs, enforced refuses (and refuses when a guard
fails, or when the arguments are past the scan bound). With no pipeline or no
mode, nothing changes: the call is recorded as before.

Must stay in sync with: sdk/typescript/src/protect/mcp.ts
"""

from __future__ import annotations

import logging
from typing import Any

from shield360._config import Shield360Config
from shield360.guard._base import GuardAction, GuardDeniedError
from shield360.protect._mode import ProtectDeniedError, current_protect_mode, refuses

logger = logging.getLogger(__name__)


def check_mcp_tool_call(tool_name: str, tool_arguments: Any) -> None:
    """Refuse, warn or record a client's tools/call before it is sent."""
    from shield360.protect import canonical_json  # local: the package imports this module

    mode = current_protect_mode()
    pipeline = getattr(Shield360Config, "guard_pipeline", None)
    if pipeline is None or mode is None:
        return
    text = canonical_json(tool_arguments if tool_arguments is not None else {})
    bound = pipeline.scan_bound()
    if refuses(mode) and 0 < bound < len(text):
        raise ProtectDeniedError(
            "oversized",
            f"Shield360 Protect refused MCP tool {tool_name}: {len(text)} characters of arguments "
            f"is more than its guards scan ({bound}).",
        )
    try:
        result = pipeline.evaluate(text, phase="preflight")
    except Exception as exc:
        if refuses(mode):
            raise ProtectDeniedError(
                "guard_failed",
                f"Shield360 Protect refused MCP tool {tool_name}: a guard failed and enforced mode does not run unchecked calls.",
            ) from exc
        raise
    if result.action != GuardAction.DENY:
        return
    if refuses(mode):
        raise GuardDeniedError(result)
    if mode == "warn":
        logger.warning("Shield360 Protect (warn mode): MCP tool %s would have been refused: %s", tool_name, result.explanation)
