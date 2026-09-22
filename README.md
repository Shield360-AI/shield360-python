<div align="center">
<h3>OpenTelemetry-native</h3>
<h1>AI Observability, Evaluation and Guardrails Framework</h1>

**[Shield360](https://shield360.ai) | [Quickstart](#-getting-started-with-llm-observability) | [Report a Bug](https://github.com/ThinkfleetAI/shield360-python/issues/new)**

[![PyPI](https://img.shields.io/pypi/v/shield360)](https://pypi.org/project/shield360/)
[![Downloads](https://static.pepy.tech/badge/shield360/month)](https://pepy.tech/project/shield360)
[![License](https://img.shields.io/badge/License-Apache%202.0-f80)](LICENSE)

</div>

Shield360 SDK is a monitoring framework built on top of **OpenTelemetry** that gives your complete Observability for your AI stack, from LLMs to vector databases and GPUs, with just one line of code with tracing and metrics. It also allows you to send the generated traces and metrics to your existing monitoring tools like Grafana, New Relic, and more.

This project proudly follows and maintains the [Semantic Conventions](https://github.com/open-telemetry/semantic-conventions/tree/main/docs/gen-ai) with the OpenTelemetry community, consistently updating to align with the latest standards in Observability.

## ⚡ Features

- 🔎 **Auto Instrumentation**: Works with 50+ LLM providers, Agents, Vector databases, and GPUs with just one line of code.
- 🔭 **OpenTelemetry-Native Observability SDKs**: Vendor-neutral SDKs that can send traces and metrics to your existing observability tool like Prometheus and Jaeger.
- 💲 **Cost Tracking for Custom and Fine-Tuned Models**: Pass custom pricing files for accurate budgeting of custom and fine-tuned models.
- 🚀 **Support for Shield360 Features**: Includes support for prompt management and secrets management features available in Shield360.

## Auto Instrumentation Capabilities

| LLMs                                                                      | Vector DBs                                   | Frameworks                                      | GPUs          |
|--------------------------------------------------------------------------|----------------------------------------------|-------------------------------------------------|---------------|
| [✅ OpenAI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/openai.mdx)                      | [✅ ChromaDB](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/chromadb.mdx)       | [✅ Langchain](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/langchain.mdx)      | [✅ NVIDIA](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/nvidia-gpu.mdx) |
| [✅ Ollama](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/ollama.mdx)                      | [✅ Pinecone](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/pinecone.mdx)       | [✅ LiteLLM](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/litellm.mdx)          | [✅ AMD](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/amd-gpu.mdx)      |
| [✅ Anthropic](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/anthropic.mdx)                | [✅ Qdrant](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/qdrant.mdx)           | [✅ LlamaIndex](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/llama-index.mdx)   |               |
| [✅ GPT4All](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/gpt4all.mdx)                    | [✅ Milvus](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/milvus.mdx)           | [✅ Haystack](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/haystack.mdx)        |               |
| [✅ Cohere](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/cohere.mdx)                      | [✅ AstraDB](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/astradb.mdx)         | [✅ EmbedChain](https://shield360.ai)    |               |
| [✅ Mistral](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/mistral.mdx)                    |                                                                          | [✅ Guardrails](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/guardrails.mdx)    |               |
| [✅ Azure OpenAI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/azure-openai.mdx)          |                                                                          | [✅ CrewAI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/crewai.mdx)            |               |
| [✅ Azure AI Inference](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/azure-ai-inference.mdx) |                                                                          | [✅ DSPy](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/dspy.mdx)                |               |
| [✅ GitHub AI Models](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/github-models.mdx)  |                                                                          | [✅ AG2](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/ag2.mdx)                  |               |
| [✅ HuggingFace Transformers](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/huggingface.mdx) |                                                                          | [✅ Dynamiq](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/dynamiq.mdx)          |               |
| [✅ Amazon Bedrock](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/bedrock.mdx)             |                                                                          | [✅ Phidata](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/phidata.mdx)          |               |
| [✅ AI21](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/ai21.mdx)                          |                                                                          | [✅ mem0](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/mem0.mdx)                |               |
| [✅ Vertex AI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/vertexai.mdx)                 |                                                                          | [✅ MultiOn](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/multion.mdx)          |               |
| [✅ Groq](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/groq.mdx)                          |                                                                          | [✅ Julep AI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/julep-ai.mdx)        |               |
| [✅ ElevenLabs](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/elevenlabs.mdx)              |                                                                          | [✅ ControlFlow](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/controlflow.mdx)  |               |
| [✅ vLLM](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/vllm.mdx)                          |                                                                          | [✅ Crawl4AI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/crawl4ai.mdx)        |               |
| [✅ OLA Krutrim](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/krutrim.mdx)                |                                                                          | [✅ FireCrawl](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/firecrawl.mdx)      |               |
| [✅ Google AI Studio](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/google-ai-studio.mdx)  |                                                                          | [✅ Letta](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/letta.mdx)              |               |
| [✅ NVIDIA NIM](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/nvidia-nim.mdx)              |                                                                          | [✅ SwarmZero](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/swarmzero.mdx)      |               |
| [✅ Titan ML](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/titan-ml.mdx)                  |                                                                          |                                                |               |
| [✅ Reka AI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/reka.mdx)                       |                                                                          |                                                |               |
| [✅ xAI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/xai.mdx)                            |                                                                          |                                                |               |
| [✅ Prem AI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/premai.mdx)                     |                                                                          |                                                |               |
| [✅ Assembly AI](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/assemblyai.mdx)             |                                                                          |                                                |               |
| [✅ Together](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/together.mdx)                  |                                                                          |                                                |               |
| [✅ DeepSeek](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/deepseek.mdx)                                                                     |                                                                          |                                                |               |
| [✅ DigitalOcean (pydo)](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/digitalocean.mdx)                                                  |                                                                          |                                                |               |
| [✅ DigitalOcean Gradient](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/integrations/digitalocean-gradient.mdx)                                       |                                                                          |                                                |               |

## Supported Destinations
- [✅ OpenTelemetry Collector](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/otelcol.mdx)
- [✅ Prometheus + Tempo](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/prometheus-tempo.mdx)
- [✅ Prometheus + Jaeger](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/prometheus-jaeger.mdx)
- [✅ Grafana Cloud](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/grafanacloud.mdx)
- [✅ New Relic](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/new-relic.mdx)
- [✅ Elastic](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/elastic.mdx)
- [✅ Middleware.io](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/middleware.mdx)
- [✅ HyperDX](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/hyperdx.mdx)
- [✅ DataDog](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/datadog.mdx)
- [✅ SigNoz](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/signoz.mdx)
- [✅ OneUptime](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/oneuptime.mdx)
- [✅ Dynatrace](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/dynatrace.mdx)
- [✅ OpenObserve](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/openobserve.mdx)
- [✅ Highlight.io](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/highlight.mdx)
- [✅ SigLens](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/siglens.mdx)
- [✅ Oodle](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/oodle.mdx)

## 💿 Installation

```bash
pip install shield360
```

## 🚀 Getting Started with LLM Observability

### Step 1: Install Shield360 SDK

Open your command line or terminal and run:

```bash
pip install shield360
```

### Step 2: Initialize Shield360 in your Application
Integrate Shield360 into your AI applications by adding the following lines to your code.

```python
import shield360

shield360.init()
```

Configure the telemetry data destination as follows:

| Purpose                                   | Parameter/Environment Variable                   | For Sending to Shield360         |
|-------------------------------------------|--------------------------------------------------|--------------------------------|
| Send data to an HTTP OTLP endpoint        | `otlp_endpoint` or `OTEL_EXPORTER_OTLP_ENDPOINT` | `"http://127.0.0.1:4318"`     |
| Authenticate telemetry backends           | `otlp_headers` or `OTEL_EXPORTER_OTLP_HEADERS`   | Not required by default       |

> 💡 Info: If the `otlp_endpoint` or `OTEL_EXPORTER_OTLP_ENDPOINT` is not provided, the Shield360 SDK will output traces directly to your console, which is recommended during the development phase.

#### Example

---

<details>
  <summary>Initialize using Function Arguments</summary>
  
  ---

  Add the following two lines to your application code:
  
  ```python
  import shield360
  
  shield360.init(
    otlp_endpoint="YOUR_OTEL_ENDPOINT", 
    otlp_headers ="YOUR_OTEL_ENDPOINT_AUTH"
  )
  ```

</details>

---

<details>

  <summary>Initialize using Environment Variables</summary>

  ---

  Add the following two lines to your application code:

  ```python
  import shield360

  shield360.init()
  ```
  
  Then, configure the your OTLP endpoint using environment variable:

  ```env
  export OTEL_EXPORTER_OTLP_ENDPOINT = "YOUR_OTEL_ENDPOINT"
  export OTEL_EXPORTER_OTLP_HEADERS = "YOUR_OTEL_ENDPOINT_AUTH"
  ```
</details>

---

### Step 3: Visualize and Optimize!
Now that your LLM observability data is being collected and sent to configured OpenTelemetry destination, the next step is to visualize and analyze this data. This will help you understand your LLM application's performance and behavior and identify where it can be improved.

If you want to use Shield360's Observability Dashboard to monitor LLM usage—like cost, tokens, and user interactions—please check out our [Quickstart Guide](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/quickstart-ai-observability.mdx).

If you're sending metrics and traces to other observability tools, take a look at our [Connections Guide](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/destinations/overview.mdx) to start using a pre-built dashboard we have created for these tools.



## Configuration

### Observability - `shield360.init()`

Below is a detailed overview of the configuration options available, allowing you to adjust Shield360's behavior and functionality to align with your specific observability needs:


| Argument                | Description                                                                                   | Default Value  | Required |
|-------------------------|-----------------------------------------------------------------------------------------------|----------------|----------|
| `environment`           | The deployment environment of the application.                                                | `"default"`    |    Yes   |
| `application_name`      | Identifies the name of your application.                                                      | `"default"`    |    Yes   |
| `tracer`                | An instance of OpenTelemetry Tracer for tracing operations.                                   | `None`         |    No    |
| `meter`                 | An OpenTelemetry Metrics instance for capturing metrics.                                      | `None`         |    No    |
| `otlp_endpoint`         | Specifies the OTLP endpoint for transmitting telemetry data.                                  | `None`         |    No    |
| `otlp_headers`          | Defines headers for the OTLP exporter, useful for backends requiring authentication.          | `None`         |    No    |
| `disable_batch`         | A flag to disable batch span processing, favoring immediate dispatch.                         | `False`        |    No    |
| `capture_message_content`         | Enables tracing of content for deeper insights.                                               | `True`         |    No    |
| `disabled_instrumentors`| List of instrumentors to disable. | `None` |    No    |
| `disable_metrics`       | If set, disables the collection of metrics.                                                   | `False`        |    No    |
| `pricing_json`          | URL or file path of the pricing JSON file.                                             | Bundled `pricing.json`        |    No    |
| `collect_gpu_stats`          | Flag to enable or disable GPU metrics collection.                                         | `False`        |    No    |
| `custom_metrics_attributes`  | Custom key-value attributes applied to every metric recording. Useful for grouping metrics by custom tags (e.g., client ID, team, project). | `None` |    No    |

### Shield360 Prompt Hub - `shield360.get_prompt()`

Below are the parameters for use with the SDK for Shield360 Prompt Hub for prompt management:

| Parameter         | Description                                                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `url`             | Sets the Shield360 URL. Defaults to the `SHIELD360_URL` environment variable.                                                          |
| `api_key`         | Sets the Shield360 API Key. Can also be provided via the `SHIELD360_API_KEY` environment variable.                                     |
| `name`            | Sets the name to fetch a unique prompt. Use this or `prompt_id`.                                                                    |
| `prompt_id`       | Sets the ID to fetch a unique prompt. Use this or `name`. Optional                                                                 |
| `version`         | Set to `True` to get the prompt with variable substitution.. Optional                                                              |
| `shouldCompile`        | Boolean value that compiles the prompt using the provided variables. Optional                                                      |
| `variables`       | Sets the variables for prompt compilation. Optional                                                                                |
| `meta_properties` | Sets the meta-properties for storing in the prompt's access history metadata. Optional                                             |

### Shield360 Vault - `shield360.get_secrets()`

Below are the parameters for use with the SDK for Shield360 Vault for secret management:

| Parameter         | Description                                                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `url`             | Sets the Shield360 URL. Defaults to the `SHIELD360_URL` environment variable.                                                          |
| `api_key`         | Sets the Shield360 API Key. Can also be provided via the `SHIELD360_API_KEY` environment variable.                                     |
| `key`            | Sets the key to fetch a specific secret.     Optional                                                   |
| `should_set_env`        | Boolean value that sets all the secrets as environment variables for the application. Optional                                                     |
| `tags`       | Sets the tags for fetching only the secrets that have the mentioned tags assigned. Optional                                                                                |


### Shield360 Rule Engine - `shield360.evaluate_rule()`

Evaluate trace attributes against the Shield360 Rule Engine to retrieve matching rules and associated entities (contexts, prompts, evaluation configurations).

| Parameter             | Description                                                                                                                        |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `url`                 | Sets the Shield360 URL. Defaults to the `SHIELD360_URL` environment variable.                                                          |
| `api_key`             | Sets the Shield360 API Key. Can also be provided via the `SHIELD360_API_KEY` environment variable.                                     |
| `entity_type`         | Type of entity to match: `"context"`, `"prompt"`, or `"evaluation"`.                                                               |
| `fields`              | Dictionary of trace attributes to evaluate against rules. e.g. `{"gen_ai.system": "openai", "gen_ai.request.model": "gpt-4"}`     |
| `include_entity_data` | If `True`, include full entity data in the response. Default: `False`. Optional                                                    |
| `entity_inputs`       | Optional dictionary of inputs for entity resolution (e.g. prompt variables, version).                                              |

#### Example

```python
import shield360

# Evaluate rules to get matching contexts
result = shield360.evaluate_rule(
    entity_type="context",
    fields={
        "gen_ai.system": "openai",
        "gen_ai.request.model": "gpt-4",
        "service.name": "my-app",
    },
    include_entity_data=True,
)

if result:
    print("Matching rules:", result["matchingRuleIds"])
    print("Entities:", result["entities"])
    # Use with evaluations:
    # contexts = result.get("entity_data", {})
```

### Score ingestion - `shield360.log_score()`

Attach numeric, boolean, or categorical scores and user feedback to a GenAI span. When called inside an instrumented LLM request, the score auto-attaches to the active span.

| Parameter | Description |
|-----------|-------------|
| `name` | Score name, for example `user_feedback` or `quality`. |
| `value` | Numeric, boolean, or categorical score value. |
| `span` | Optional explicit OpenTelemetry span. |
| `trace_id` | Optional trace ID for async feedback against a past trace. |
| `span_id` | Optional span ID for async feedback against a past trace. |
| `comment` | Optional explanation or reviewer comment. |
| `idempotency_key` | Optional key to deduplicate score updates. |
| `metadata` | Optional dictionary of extra event attributes. |

#### Example

```python
import shield360

shield360.init()

# Thumbs up/down style feedback on the current span
shield360.log_score("user_feedback", True, comment="Helpful response")

# Numeric reviewer score
shield360.log_score("quality", 0.85, metadata={"reviewer": "human"})

# Categorical label
shield360.log_score("category", "accurate")
```

## 🛣️ Roadmap

We are dedicated to continuously improving Shield360 SDKs. Here's a look at what's been accomplished and what's on the horizon:

| Feature                                                                                      | Status        |
|----------------------------------------------------------------------------------------------|---------------|
| [OpenTelmetry auto-instrumentation for LLM Providers like OpenAI, Anthropic]()               | ✅ Completed  |
| [OpenTelmetry auto-instrumentation for Vector databases like Pinecone, Chroma]()             | ✅ Completed  |
| [OpenTelmetry auto-instrumentation for LLM Frameworks like LangChain, LlamaIndex]()          | ✅ Completed  |
| [OpenTelemetry-native auto-instrumentation for NVIDIA GPU Monitoring](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/features/gpu.mdx)           | ✅ Completed  |
| [Real-Time Guardrails Implementation](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/features/guardrails.mdx)                                                      | ✅ Completed    |
| [Programmatic Evaluation for LLM Response](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/features/evaluations.mdx)                                                      | ✅ Completed    |
| [OpenTelemetry-native AI Agent Observability]()             | ✅ Completed  |


## 🌱 Contributing

Whether it's big or small, we love contributions 💚. Check out our [Contribution guide](https://github.com/ThinkfleetAI/shield360-python#readme) to get started

Unsure where to start? Here are a few ways to get involved:

- Have a question or some feedback? Reach us at [shield360.ai](https://shield360.ai).

Your input helps us grow and improve, and we're here to support you every step of the way.

## 💚 Community & Support

Connect with the Shield360 community and maintainers for support, discussions, and updates:

- 🌟 If you like it, Leave a star on our [GitHub](https://github.com/ThinkfleetAI/shield360-python)
- 🐞 Report bugs on our [GitHub Issues](https://github.com/ThinkfleetAI/shield360-python/issues) to help us improve Shield360.
