# Linting does not install the provider packages, so pylint cannot see that
# this client class is callable. Same artifact as the disabled import-error.
# pylint: disable=not-callable
"""
This module contains tests for Together functionality using the Together Python library.

Tests cover various API endpoints, including chat and embeddings.
These tests validate integration with Shield360.

Environment Variables:
    - TOGETHER_API_KEY: Together API key for authentication.

Note: Ensure the environment is properly configured for Together access and Shield360 monitoring
prior to running these tests.
"""

import pytest
from together import Together, AsyncTogether
import shield360

# Initialize synchronous Together client
sync_client = Together()

# Initialize asynchronous Together client
async_client = AsyncTogether()

# Initialize environment and application name for Shield360 monitoring
shield360.init(
    environment="shield360-python-testing",
    application_name="shield360-python-together-test",
)


def test_sync_together_chat():
    """
    Tests synchronous chat.

    Raises:
        AssertionError: If the response object is not as expected.
    """

    try:
        response = sync_client.chat.completions.create(
            model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
            messages=[
                {"role": "user", "content": "Hi"},
            ],
            max_tokens=1,
            stream=False,
        )
        assert response.model == "meta-llama/Llama-3.3-70B-Instruct-Turbo"

    except Exception as e:
        if "credit_limit" in str(e).lower():
            print("Insufficient balance:", e)
        elif "429" in str(e) or "rate limit" in str(e).lower():
            print("Rate limit exceeded:", e)
        else:
            raise


def test_sync_together_image():
    """
    Tests synchronous image generate.

    Raises:
        AssertionError: If the response object is not as expected.
    """

    try:
        response = sync_client.images.generate(
            prompt="AI Observability dashboard",
            model="black-forest-labs/FLUX.1-dev",
            width=768,
            height=768,
            n=1,
        )
        assert response.model == "black-forest-labs/FLUX.1-dev"

    except Exception as e:
        if "credit_limit" in str(e).lower():
            print("Insufficient balance:", e)
        elif "429" in str(e) or "rate limit" in str(e).lower():
            print("Rate limit exceeded:", e)
        else:
            raise


@pytest.mark.asyncio
async def test_async_together_chat():
    """
    Tests asynchronous chat.

    Raises:
        AssertionError: If the response object is not as expected.
    """

    try:
        response = await async_client.chat.completions.create(
            model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
            messages=[
                {"role": "user", "content": "Hi"},
            ],
            max_tokens=1,
            stream=False,
        )
        assert response.model == "meta-llama/Llama-3.3-70B-Instruct-Turbo"

    except Exception as e:
        if "credit_limit" in str(e).lower():
            print("Insufficient balance:", e)
        elif "429" in str(e) or "rate limit" in str(e).lower():
            print("Rate limit exceeded:", e)
        else:
            raise


@pytest.mark.asyncio
async def test_async_together_image():
    """
    Tests asynchronous image generate.

    Raises:
        AssertionError: If the response object is not as expected.
    """

    try:
        response = await async_client.images.generate(
            prompt="AI Observability dashboard",
            model="black-forest-labs/FLUX.1-dev",
            width=768,
            height=768,
            n=1,
        )
        assert response.model == "black-forest-labs/FLUX.1-dev"

    except Exception as e:
        if "credit_limit" in str(e).lower():
            print("Insufficient balance:", e)
        elif "429" in str(e) or "rate limit" in str(e).lower():
            print("Rate limit exceeded:", e)
        else:
            raise
