# pylint: disable=duplicate-code, no-name-in-module
"""
This module contains tests for Text Generation functionality in HuggingFace Transformers library.

Tests cover the usage of the Transformers' pipeline for generating text.
These tests validate integration with Shield360.

Note: Ensure the environment is properly configured for Transformers and Shield360 monitoring
prior to running these tests.
"""

from transformers import pipeline
import shield360

# Initialize environment and application name for Shield360 monitoring
shield360.init(environment="shield360-testing", application_name="shield360-python-test")


def test_text_transformers():
    """
    Test text generation capabilities from HuggingFace Transformers library.
    """

    pipe = pipeline(task="text-generation", model="Qwen/Qwen2.5-1.5B")
    response = pipe("LLM Observability")
    assert isinstance(response[0]["generated_text"], str)

    chat = [
        {
            "role": "system",
            "content": "You are an OpenTelemetry AI Observability expert",
        },
        {"role": "user", "content": "What is Agent Observability?"},
    ]

    response = pipe(chat, max_new_tokens=100)

    assert isinstance(response[0]["generated_text"][-1]["content"], str)
