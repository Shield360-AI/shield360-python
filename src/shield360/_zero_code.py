"""State shared between the zero-code start (``shield360-instrument`` and its
sitecustomize bootstrap) and ``shield360.init()``: once the zero-code start
has initialized Shield360, a later ``init()`` in the app's own code is a no-op.
"""

import logging

logger = logging.getLogger("shield360")

_state = {"started": False, "warned": False}


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
