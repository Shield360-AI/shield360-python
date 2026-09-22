"""
Shield360 Instrumentors
"""

import importlib

# Mapping of instrumentor names to their required Python packages
MODULE_NAME_MAP = {
    # Shield360 AI/ML instrumentations
    "openai": "openai",
    "anthropic": "anthropic",
    "cohere": "cohere",
    "mistral": "mistralai",
    "bedrock": "boto3",
    "oci": "oci",
    "vertexai": "vertexai",
    "groq": "groq",
    "ollama": "ollama",
    "gpt4all": "gpt4all",
    "elevenlabs": "elevenlabs",
    "vllm": "vllm",
    "google-ai-studio": "google.genai",
    "azure-ai-inference": "azure.ai.inference",
    "langchain": "langchain_core",
    "langgraph": "langgraph",
    "llama_index": "llama_index",
    "haystack": "haystack",
    "mem0": "mem0",
    "chroma": "chromadb",
    "pinecone": "pinecone",
    "qdrant": "qdrant_client",
    "milvus": "pymilvus",
    "transformers": "transformers",
    "litellm": "litellm",
    "crewai": "crewai",
    "ag2": "ag2",
    "autogen": "autogen",
    "pyautogen": "pyautogen",
    "multion": "multion",
    "dynamiq": "dynamiq",
    "agno": "agno",
    "reka-api": "reka",
    "premai": "premai",
    "julep": "julep",
    "astra": "astrapy",
    "ai21": "ai21",
    "controlflow": "controlflow",
    "assemblyai": "assemblyai",
    "crawl4ai": "crawl4ai",
    "firecrawl": "firecrawl",
    "letta": "letta_client",
    "together": "together",
    "pydo": "pydo",
    "gradient": "gradient",
    "openai-agents": "agents",
    "pydantic_ai": "pydantic_ai",
    "sarvam": "sarvamai",
    "browser-use": "browser_use",
    "mcp": "mcp",
    "google-adk": "google.adk",
    "claude-agent-sdk": "claude_agent_sdk",
    "agent-framework": "agent_framework",
    "strands": "strands",
    "smolagents": "smolagents",
    # Database instrumentations
    "psycopg": "psycopg",
    "psycopg-pool": "psycopg_pool",
    # Official OpenTelemetry HTTP Framework instrumentations
    "asgi": "asgiref",
    "django": "django",
    "fastapi": "fastapi",
    "flask": "flask",
    "pyramid": "pyramid",
    "starlette": "starlette",
    "falcon": "falcon",
    "tornado": "tornado",
    # Official OpenTelemetry HTTP Client instrumentations
    "aiohttp-client": "aiohttp",
    "httpx": "httpx",
    "requests": "requests",
    "urllib": "urllib",
    "urllib3": "urllib3",
}

# Common aliases so users can pass intuitive names (e.g. "aiohttp") that
# differ from the canonical keys used in MODULE_NAME_MAP.  The canonical keys
# are not consistent about hyphens versus underscores, so every key whose
# separator can be written the other way is aliased in both directions.
INSTRUMENTOR_ALIASES = {
    "aiohttp": "aiohttp-client",
    "aiohttp_client": "aiohttp-client",
    "oci_genai": "oci",
    "oci-genai": "oci",
    "openai_agents": "openai-agents",
    "google_ai_studio": "google-ai-studio",
    "azure_ai_inference": "azure-ai-inference",
    "reka": "reka-api",
    "reka_api": "reka-api",
    "browser_use": "browser-use",
    "google_adk": "google-adk",
    "claude_agent_sdk": "claude-agent-sdk",
    "agent_framework": "agent-framework",
    "psycopg_pool": "psycopg-pool",
    "llamaindex": "llama_index",
    "llama-index": "llama_index",
    "pydantic-ai": "pydantic_ai",
    "http": "httpx",
    "digitalocean": "pydo",
    "digital_ocean": "pydo",
    "do_gradient": "gradient",
}


def normalize_instrumentor_name(name):
    """Normalize a user-provided instrumentor name for lookup.

    Lowercases the input for case-insensitive matching and resolves any
    configured alias from INSTRUMENTOR_ALIASES.  Returns the canonical key
    used in MODULE_NAME_MAP / INSTRUMENTOR_MAP.
    """
    if not isinstance(name, str):
        return name
    lowered = name.lower()
    return INSTRUMENTOR_ALIASES.get(lowered, lowered)


def normalize_instrumentor_names(names):
    """Normalize a list of user-provided instrumentor names.

    Single entry point for alias resolution + case folding so every code
    path (init kwarg, env var, config file, etc.) stays consistent.
    """
    if not names:
        return []
    return [normalize_instrumentor_name(n) for n in names]


# Dictionary mapping instrumentor names to their full module paths
INSTRUMENTOR_MAP = {
    # Shield360 AI/ML instrumentations
    "openai": "shield360.instrumentation.openai.OpenAIInstrumentor",
    "anthropic": "shield360.instrumentation.anthropic.AnthropicInstrumentor",
    "cohere": "shield360.instrumentation.cohere.CohereInstrumentor",
    "mistral": "shield360.instrumentation.mistral.MistralInstrumentor",
    "bedrock": "shield360.instrumentation.bedrock.BedrockInstrumentor",
    "oci": "shield360.instrumentation.oci_genai.OCIGenAIInstrumentor",
    "vertexai": "shield360.instrumentation.vertexai.VertexAIInstrumentor",
    "groq": "shield360.instrumentation.groq.GroqInstrumentor",
    "ollama": "shield360.instrumentation.ollama.OllamaInstrumentor",
    "gpt4all": "shield360.instrumentation.gpt4all.GPT4AllInstrumentor",
    "elevenlabs": "shield360.instrumentation.elevenlabs.ElevenLabsInstrumentor",
    "vllm": "shield360.instrumentation.vllm.VLLMInstrumentor",
    "google-ai-studio": "shield360.instrumentation.google_ai_studio.GoogleAIStudioInstrumentor",
    "azure-ai-inference": "shield360.instrumentation.azure_ai_inference.AzureAIInferenceInstrumentor",
    "langchain": "shield360.instrumentation.langchain.LangChainInstrumentor",
    "langgraph": "shield360.instrumentation.langgraph.LangGraphInstrumentor",
    "llama_index": "shield360.instrumentation.llamaindex.LlamaIndexInstrumentor",
    "haystack": "shield360.instrumentation.haystack.HaystackInstrumentor",
    "mem0": "shield360.instrumentation.mem0.Mem0Instrumentor",
    "chroma": "shield360.instrumentation.chroma.ChromaInstrumentor",
    "pinecone": "shield360.instrumentation.pinecone.PineconeInstrumentor",
    "qdrant": "shield360.instrumentation.qdrant.QdrantInstrumentor",
    "milvus": "shield360.instrumentation.milvus.MilvusInstrumentor",
    "transformers": "shield360.instrumentation.transformers.TransformersInstrumentor",
    "litellm": "shield360.instrumentation.litellm.LiteLLMInstrumentor",
    "crewai": "shield360.instrumentation.crewai.CrewAIInstrumentor",
    "ag2": "shield360.instrumentation.ag2.AG2Instrumentor",
    "multion": "shield360.instrumentation.multion.MultiOnInstrumentor",
    "autogen": "shield360.instrumentation.ag2.AG2Instrumentor",
    "pyautogen": "shield360.instrumentation.ag2.AG2Instrumentor",
    "dynamiq": "shield360.instrumentation.dynamiq.DynamiqInstrumentor",
    "agno": "shield360.instrumentation.agno.AgnoInstrumentor",
    "reka-api": "shield360.instrumentation.reka.RekaInstrumentor",
    "premai": "shield360.instrumentation.premai.PremAIInstrumentor",
    "julep": "shield360.instrumentation.julep.JulepInstrumentor",
    "astra": "shield360.instrumentation.astra.AstraInstrumentor",
    "ai21": "shield360.instrumentation.ai21.AI21Instrumentor",
    "controlflow": "shield360.instrumentation.controlflow.ControlFlowInstrumentor",
    "assemblyai": "shield360.instrumentation.assemblyai.AssemblyAIInstrumentor",
    "crawl4ai": "shield360.instrumentation.crawl4ai.Crawl4AIInstrumentor",
    "firecrawl": "shield360.instrumentation.firecrawl.FireCrawlInstrumentor",
    "letta": "shield360.instrumentation.letta.LettaInstrumentor",
    "together": "shield360.instrumentation.together.TogetherInstrumentor",
    "pydo": "shield360.instrumentation.pydo.PydoInstrumentor",
    "gradient": "shield360.instrumentation.gradient.GradientInstrumentor",
    "openai-agents": "shield360.instrumentation.openai_agents.OpenAIAgentsInstrumentor",
    "pydantic_ai": "shield360.instrumentation.pydantic_ai.PydanticAIInstrumentor",
    "sarvam": "shield360.instrumentation.sarvam.SarvamInstrumentor",
    "browser-use": "shield360.instrumentation.browser_use.BrowserUseInstrumentor",
    "mcp": "shield360.instrumentation.mcp.MCPInstrumentor",
    "google-adk": "shield360.instrumentation.google_adk.GoogleADKInstrumentor",
    "claude-agent-sdk": "shield360.instrumentation.claude_agent_sdk.ClaudeAgentSDKInstrumentor",
    "agent-framework": "shield360.instrumentation.agent_framework.AgentFrameworkInstrumentor",
    "strands": "shield360.instrumentation.strands.StrandsInstrumentor",
    "smolagents": "shield360.instrumentation.smolagents.SmolAgentsInstrumentor",
    # Database instrumentations
    "psycopg": "shield360.instrumentation.psycopg.PsycopgInstrumentor",
    "psycopg-pool": "shield360.instrumentation.psycopg.PsycopgInstrumentor",
    # Official OpenTelemetry HTTP Framework instrumentations
    "asgi": "opentelemetry.instrumentation.asgi.AsgiInstrumentor",
    "django": "opentelemetry.instrumentation.django.DjangoInstrumentor",
    "fastapi": "opentelemetry.instrumentation.fastapi.FastAPIInstrumentor",
    "flask": "opentelemetry.instrumentation.flask.FlaskInstrumentor",
    "pyramid": "opentelemetry.instrumentation.pyramid.PyramidInstrumentor",
    "starlette": "opentelemetry.instrumentation.starlette.StarletteInstrumentor",
    "falcon": "opentelemetry.instrumentation.falcon.FalconInstrumentor",
    "tornado": "opentelemetry.instrumentation.tornado.TornadoInstrumentor",
    # Official OpenTelemetry HTTP Client instrumentations
    "aiohttp-client": "opentelemetry.instrumentation.aiohttp_client.AioHttpClientInstrumentor",
    "httpx": "opentelemetry.instrumentation.httpx.HTTPXClientInstrumentor",
    "requests": "opentelemetry.instrumentation.requests.RequestsInstrumentor",
    "urllib": "opentelemetry.instrumentation.urllib.URLLibInstrumentor",
    "urllib3": "opentelemetry.instrumentation.urllib3.URLLib3Instrumentor",
}


def get_instrumentor_class(name):
    """
    Get instrumentor class by name.

    Args:
        name (str): Name of the instrumentor

    Returns:
        class: Instrumentor class or None if not found
    """
    if name not in INSTRUMENTOR_MAP:
        return None

    module_path, class_name = INSTRUMENTOR_MAP[name].rsplit(".", 1)

    try:
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except Exception:
        return None


def get_all_instrumentors():
    """
    Get all available instrumentor instances.

    Returns:
        dict: Dictionary of instrumentor instances
    """
    instances = {}

    for name in INSTRUMENTOR_MAP:
        instrumentor_class = get_instrumentor_class(name)
        if instrumentor_class:
            try:
                instances[name] = instrumentor_class()
            except Exception:
                pass  # Skip instrumentors that fail to instantiate

    return instances
