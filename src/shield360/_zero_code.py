"""State shared between the zero-code start (``shield360-instrument`` and its
sitecustomize bootstrap) and ``shield360.init()``: once the zero-code start
has initialized Shield360, a later ``init()`` in the app's own code is a no-op.
"""

import logging
import os

logger = logging.getLogger("shield360")

_state = {"started": False, "warned": False}


#: RASP's mode for a code-free start when nothing chose one: monitor (reports, never blocks).
DEFAULT_RASP = "monitor"


def default_rasp_to_monitor() -> None:
    """Turns RASP on in monitor mode when ``SHIELD360_RASP`` is unset or empty.

    A code-free start protects the app, it does not only observe it. Set in the
    environment so every reader of the variable agrees.
    """
    if not (os.environ.get("SHIELD360_RASP") or "").strip():
        os.environ["SHIELD360_RASP"] = DEFAULT_RASP


def start_from_environment(*, swallow_exceptions: bool = True) -> None:
    """Initializes Shield360 from SHIELD360_* / OTEL_* environment variables, RASP included.

    Shared by the sitecustomize bootstrap (``shield360-instrument``, ``shield360 run``,
    the Kubernetes operator) and ``import shield360.auto``. Runs once per process.

    :param swallow_exceptions: log one warning and carry on (the default), or raise.
    """
    default_rasp_to_monitor()
    try:
        import shield360  # pylint: disable=import-outside-toplevel,cyclic-import  # late: shield360 imports this module
        from shield360.cli.config import build_config_from_environment  # pylint: disable=import-outside-toplevel

        if started():
            return
        shield360.init(**build_config_from_environment())
        mark_started()

        from shield360.rasp import rasp_active  # pylint: disable=import-outside-toplevel

        if rasp_active():
            from shield360.rasp import _autowire  # pylint: disable=import-outside-toplevel

            _autowire.install()
    except Exception as e:  # pylint: disable=broad-exception-caught
        if not swallow_exceptions:
            raise
        logger.warning("Shield360: zero-code start-up failed (%s: %s); the app runs without Shield360.", type(e).__name__, e)


def mark_started() -> None:
    """Records that the zero-code start initialized Shield360."""
    _state["started"] = True


def started() -> bool:
    """Whether the zero-code start initialized Shield360 in this process."""
    return _state["started"]


def note_skipped_init() -> None:
    """One log line, the first time the app's own ``init()`` is skipped."""
    if _state["warned"]:
        return
    _state["warned"] = True
    logger.warning(
        "Shield360: already started by shield360-instrument from SHIELD360_* environment variables; "
        "this shield360.init() call is ignored."
    )


def reset() -> None:
    """Tests only."""
    _state["started"] = False
    _state["warned"] = False
