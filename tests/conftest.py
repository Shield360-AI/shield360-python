"""Shared test setup.

SHIELD: AI attack agents — the behavior tracker is per process, so marks from
one test (findings or 404s from the shared test address) would carry into the
next. Each test starts with a fresh tracker.
"""

import pytest

from shield360.rasp._attack_agents import set_attack_agent_tracker


@pytest.fixture(autouse=True)
def _fresh_attack_agent_tracker():
    set_attack_agent_tracker()
    yield
