"""RASP sink hooks (README "Detection algorithms"): where untrusted input is
checked as it reaches a dangerous sink. ``init_rasp`` installs them when
RASP is on and ``shutdown_rasp`` removes them.

Each hook is installed on its own: one that cannot install (a library shape
it does not know) never stops the others, and inside a hook one missing
target never aborts the rest. Libraries are patched when the app imports
them (``_imports.py``), and at once when it already has; nothing here
imports a library the app did not load.
"""

from __future__ import annotations

from typing import Dict, Sequence

from shield360.rasp._hooks.code import install_code_hooks, uninstall_code_hooks
from shield360.rasp._hooks.db import install_db_hooks, uninstall_db_hooks
from shield360.rasp._hooks.files import install_file_hooks, uninstall_file_hooks
from shield360.rasp._hooks.http import install_http_hooks, uninstall_http_hooks
from shield360.rasp._hooks.include import install_include_hooks, uninstall_include_hooks
from shield360.rasp._hooks.process import install_process_hooks, uninstall_process_hooks
from shield360.rasp._hooks.response import install_response_hook, uninstall_response_hook
from shield360.rasp._hooks.sinks import install_sink_hooks, uninstall_sink_hooks
from shield360.rasp._hooks.template import install_template_hooks, uninstall_template_hooks
from shield360.rasp._hooks.uploads import install_upload_hooks, uninstall_upload_hooks

__all__ = ["install_hooks", "uninstall_hooks"]


def install_hooks(always_allowed_hosts: Sequence[str] = ()) -> Dict[str, bool]:
    """Installs every sink hook; returns which installed. Never raises."""
    out: Dict[str, bool] = {}
    for name, install in (
        ("process", install_process_hooks),
        ("files", install_file_hooks),
        ("http", lambda: install_http_hooks(always_allowed_hosts)),
        ("db", install_db_hooks),
        ("code", install_code_hooks),
        ("include", install_include_hooks),
        ("template", install_template_hooks),
        ("response", install_response_hook),
        ("sinks", install_sink_hooks),
        ("uploads", install_upload_hooks),
    ):
        try:
            out[name] = bool(install())
        except Exception:  # pylint: disable=broad-exception-caught
            out[name] = False
    return out


def uninstall_hooks() -> None:
    """Removes every sink hook. Idempotent; never raises."""
    for uninstall in (
        uninstall_upload_hooks,
        uninstall_sink_hooks,
        uninstall_response_hook,
        uninstall_template_hooks,
        uninstall_include_hooks,
        uninstall_code_hooks,
        uninstall_db_hooks,
        uninstall_http_hooks,
        uninstall_file_hooks,
        uninstall_process_hooks,
    ):
        try:
            uninstall()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
