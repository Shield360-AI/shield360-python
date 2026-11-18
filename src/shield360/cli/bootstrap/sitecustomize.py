"""
Shield360 zero-code bootstrap.

``shield360-instrument`` puts this directory first on PYTHONPATH, so Python
runs this module at start-up, before the app imports anything. It
initializes Shield360 from SHIELD360_* / OTEL_* environment variables
(telemetry and, with SHIELD360_RASP=monitor|block, RASP and the framework
middleware), the same pattern as OpenTelemetry's auto-instrumentation.

Fail open: a failure logs one warning and the app starts without Shield360.
A later ``shield360.init()`` in the app's own code is a no-op. An app's own
``sitecustomize`` further down the path still runs.
"""

import importlib.machinery
import importlib.util
import logging
import os
import sys

logger = logging.getLogger("shield360")

_HERE = os.path.dirname(os.path.abspath(__file__))


def _drop_from_pythonpath() -> None:
    """Keeps the bootstrap out of child processes the app starts (they are not instrumented)."""
    if "PYTHONPATH" in os.environ:
        python_path = [p for p in os.environ["PYTHONPATH"].split(os.pathsep) if os.path.abspath(p or ".") != _HERE]
        os.environ["PYTHONPATH"] = os.pathsep.join(python_path)


def initialize(*, swallow_exceptions: bool = True) -> None:
    """Initializes Shield360 from the environment.

    :param swallow_exceptions: log one warning and carry on (the default), or raise.
    """
    _drop_from_pythonpath()
    try:
        import shield360  # pylint: disable=import-outside-toplevel
        from shield360 import _zero_code  # pylint: disable=import-outside-toplevel
        from shield360.cli.config import build_config_from_environment  # pylint: disable=import-outside-toplevel

        if _zero_code.started():
            return
        shield360.init(**build_config_from_environment())
        _zero_code.mark_started()

        from shield360.rasp import rasp_active  # pylint: disable=import-outside-toplevel

        if rasp_active():
            from shield360.rasp import _autowire  # pylint: disable=import-outside-toplevel

            _autowire.install()
    except Exception as e:  # pylint: disable=broad-exception-caught
        if not swallow_exceptions:
            raise
        logger.warning("Shield360: zero-code start-up failed (%s: %s); the app runs without Shield360.", type(e).__name__, e)


def _chain_next_sitecustomize() -> None:
    """Runs the next ``sitecustomize`` on the path (the app's or the distribution's), which this one shadows."""
    try:
        paths = [p for p in sys.path if os.path.abspath(p or ".") != _HERE]
        spec = importlib.machinery.PathFinder.find_spec("sitecustomize", paths)
        if spec is None or spec.loader is None or not spec.origin:
            return
        if os.path.dirname(os.path.abspath(spec.origin)) == _HERE:
            return
        module = importlib.util.module_from_spec(spec)
        # The app's module takes the name, so a later `import sitecustomize` finds what it exports.
        ours = sys.modules.get("sitecustomize")
        sys.modules["sitecustomize"] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if ours is not None:
                sys.modules["sitecustomize"] = ours
            raise
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Shield360: the app's own sitecustomize failed: %s", e)


initialize()
_chain_next_sitecustomize()
