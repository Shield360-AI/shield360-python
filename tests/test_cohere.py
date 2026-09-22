# pylint: disable=duplicate-code, no-member
"""
This module contains tests for Cohere functionality using the Cohere Python library.

Tests cover various API endpoints, including chat and embeddings.
These tests validate integration with Shield360.

Environment Variables:
    - CO_API_KEY: Cohere API key for authentication.

Note: Ensure the environment is properly configured for Cohere access and Shield360 monitoring
prior to running these tests.
"""

import cohere
import shield360

# Initialize synchronous Cohere client
sync_client = cohere.Client()

# Initialize environment and application name for Shield360 monitoring
shield360.init(
    environment="shield360-python-testing", application_name="shield360-python-cohere-test"
)


def test_embed():
    """
    Tests synchronous embedding creation.

    Raises:
        AssertionError: If the embedding response object is not as expected.
    """

    try:
        embeddings_resp = sync_client.embed(
            texts=["This is a test"], model="embed-english-v3.0"
        )
        assert embeddings_resp.meta is not None

    except cohere.core.api_error.ApiError as e:
        print("Rate Limited:", e)
    except Exception as e:
        print("An unexpected error occurred")
        raise e


def test_chat():
    """
    Tests synchronous chat.

    Raises:
        AssertionError: If the chat response object is not as expected.
    """

    try:
        chat_resp = sync_client.chat(message="Say this is a test", model="command")
        assert chat_resp.generation_id is not None

    except cohere.core.api_error.ApiError as e:
        print("Rate Limited:", e)
    except Exception as e:
        print("An unexpected error occurred")
        raise e
