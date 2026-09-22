# pylint: disable=duplicate-code, no-member
"""
This module contains tests for Agno functionality using the Agno Python library.

Tests cover agent execution with Cohere models.
These tests validate integration with Shield360.

Environment Variables:
    - CO_API_KEY: Cohere API key for authentication.

Note: Ensure the environment is properly configured for Cohere access and Shield360 monitoring
prior to running these tests.
"""

from agno.agent import Agent
from agno.models.cohere import Cohere
import shield360

# Initialize Shield360 monitoring
shield360.init(
    environment="shield360-python-testing", application_name="shield360-python-agno-test"
)


def test_agent_run():
    """
    Tests synchronous agent execution with Cohere.

    Raises:
        AssertionError: If the agent response is not as expected.
    """
    try:
        agent = Agent(model=Cohere(id="command-r-08-2024"), markdown=True)

        response = agent.run("Say 'test passed' in 2 words")
        assert response is not None
        assert response.content is not None

    except Exception as e:
        print(f"Error in test_agent_run: {e}")
        raise e


def test_agent_async_run():
    """
    Tests async agent execution with Cohere.

    Raises:
        AssertionError: If the agent response is not as expected.
    """
    import asyncio

    async def run_async():
        try:
            agent = Agent(model=Cohere(id="command-r-08-2024"), markdown=True)

            response = await agent.arun("Say 'async test passed' in 3 words")
            assert response is not None
            assert response.content is not None

        except Exception as e:
            print(f"Error in test_agent_async_run: {e}")
            raise e

    asyncio.run(run_async())
