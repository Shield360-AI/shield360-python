"""
Zero-code start from inside the app: ``import shield360.auto`` as the first
line of the app's entry module starts Shield360 from SHIELD360_* / OTEL_*
environment variables, telemetry and RASP, before the app imports anything
else. RASP runs in monitor mode (reports, never blocks) unless
``SHIELD360_RASP`` says ``block`` or ``off``.

Use it where the start command cannot change. Where it can, prefer no code
change at all: ``shield360 run -- <command>`` or ``shield360-instrument <command>``,
which load the same start through ``sitecustomize``.

Fail open: a failure logs one warning and the app runs without Shield360.
"""

from shield360._zero_code import start_from_environment

start_from_environment()
