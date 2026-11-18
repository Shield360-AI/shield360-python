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



## Zero-code setup

Turn on Shield360, telemetry and runtime protection (RASP), without changing the app. Install the package into the app's environment and start the app through `shield360-instrument`; everything is configured with environment variables.

```bash
pip install shield360

export OTEL_SERVICE_NAME=orders-api
export SHIELD360_URL=https://app.shield360.ai
export SHIELD360_API_KEY=...                      # from Settings > API keys
export SHIELD360_RASP=monitor                     # or block; leave unset for telemetry only
export SHIELD360_CONFIG_PUBLIC_KEY='{"kty":"OKP",...}'  # Runtime protection settings

shield360-instrument python app.py
shield360-instrument uvicorn main:app --port 8000
shield360-instrument python manage.py runserver   # with DJANGO_SETTINGS_MODULE set
```

The launcher works like `opentelemetry-instrument`: it puts a `sitecustomize` bootstrap first on `PYTHONPATH` and runs the command. Python runs the bootstrap at start-up, before the app imports anything, and it:

- calls `shield360.init()` with the settings from the environment (`OTEL_SERVICE_NAME`, `OTEL_DEPLOYMENT_ENVIRONMENT`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `SHIELD360_URL`, `SHIELD360_API_KEY`, `SHIELD360_DISABLED_INSTRUMENTORS` and the other `SHIELD360_*` variables, see `shield360-instrument --help`);
- with `SHIELD360_RASP=monitor|block`, adds the RASP middleware to apps as they are created: `rasp_flask(app)` for every `Flask(...)`, `RaspASGIMiddleware` as the first user middleware of Starlette and FastAPI apps (inside Starlette's error middleware, so a block from an endpoint is a 403, not a 500), and `shield360.rasp.RaspDjangoMiddleware` first in Django's `MIDDLEWARE`. Middleware the app adds itself as well is harmless: the inner one sees the request is already captured and passes it through;
- then runs the app's own `sitecustomize`, if there is one further down the path, and leaves it as the `sitecustomize` module, so `import sitecustomize` in the app finds what it exports.

Rules it keeps:

- **Fail open.** If Shield360 cannot start, it logs one warning and the app starts without it. If the launcher itself fails, it still runs the command.
- **No double start.** If the app also calls `shield360.init()` itself, that call does nothing (one log line says so); the environment settings stay in force.

Limits:

- Child Python processes the app starts are not instrumented (the bootstrap removes itself from `PYTHONPATH`).
- Frozen apps (PyInstaller, Nuitka, cx_Freeze) and interpreters started with `-I`, `-E` or `-S` skip `PYTHONPATH` or `sitecustomize`, so the launcher has no effect there; call `shield360.init()` in code.
- Servers that fork worker processes (gunicorn, uWSGI in master mode) start Shield360 in the parent before the fork. RASP checks, blocking and the middleware still work in the workers, but the background threads that send RASP events and poll the signed config do not survive the fork, so workers send no RASP events and do not pick up config changes. For those servers, call `shield360.init()` in the worker (gunicorn's `post_fork` hook) instead of using the launcher.
- Django: set `DJANGO_SETTINGS_MODULE` in the environment rather than only in `manage.py`, so the Django instrumentation finds the settings at start-up.
- Other frameworks (Tornado, Falcon, Pyramid, a bare WSGI or ASGI callable) still need the middleware added in code.

No new environment variables: `SHIELD360_RASP` and the variables `shield360.init()` already reads are all it uses.

## AWS Lambda

`shield360.aws_lambda.wrap_handler` traces each invocation as a `faas` span (cold start, trigger, invocation ID, function ARN) and flushes traces, metrics and logs before the invocation returns. The flush waits at most `SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS` (2000 ms by default) and never past the invocation's deadline.

```python
from shield360.aws_lambda import wrap_handler

@wrap_handler
def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
```

With nothing started yet, the wrapper starts Shield360 from the `SHIELD360_*` / `OTEL_*` variables and names the service after the function. To instrument provider SDKs the module imports before the decorator runs, use the Shield360 Lambda layer. It sets the handler to `shield360.aws_lambda.handler`, which starts Shield360 and then imports the function named by `SHIELD360_LAMBDA_HANDLER`. See [AWS Lambda](https://github.com/ThinkfleetAI/shield360-python/blob/main/docs/aws-lambda.mdx).

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
| `capture_message_content`         | Records prompt and completion text. Off unless set here or with `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`. | `False`        |    No    |
| `disabled_instrumentors`| List of instrumentors to disable. | `None` |    No    |
| `disable_metrics`       | If set, disables the collection of metrics.                                                   | `False`        |    No    |
| `pricing_json`          | URL or file path of the pricing JSON file.                                             | Bundled `pricing.json`        |    No    |
| `collect_gpu_stats`          | Flag to enable or disable GPU metrics collection.                                         | `False`        |    No    |
| `custom_metrics_attributes`  | Custom key-value attributes applied to every metric recording. Useful for grouping metrics by custom tags (e.g., client ID, team, project). | `None` |    No    |

> **Message content is off by default.** Prompt and completion text is recorded only when you pass `capture_message_content=True` (or set `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`). Even then, Shield360 stores it only if your organization's [Data retention](https://shield360.ai) setting allows it. Before this release the default was on.

### Code location and release attributes

Shield360 can show AI cost by the code that caused it. To do that, the SDK records where each GenAI call was made and which build made it.

**Code location (span attributes).** Every GenAI span gets three attributes for the first frame in your code. Frames inside Shield360, OpenTelemetry, the standard library and installed packages are skipped.

| Attribute | Example |
| --- | --- |
| `code.function.name` | `app.billing.summarise_cart` |
| `code.file.path` | `app/billing.py` (relative to the code root, the git root or the working directory; no home directory or CI workspace prefix is sent) |
| `code.line.number` | `42` |

Only names, paths and line numbers are recorded. Arguments, local variables and source text are never recorded. Spans that are not GenAI spans are not changed, and existing `code.*` attributes are kept.

| Option | Environment variable | Default |
| --- | --- | --- |
| `capture_code_location=False` turns it off | `SHIELD360_CAPTURE_CODE_LOCATION=false` (or `0`, `no`, `off`) | On |
| Also on database, HTTP, RPC and messaging client spans, to price the costly code patterns `shield360 scan` finds | `SHIELD360_CAPTURE_CALL_LOCATION=false` turns just this off | On |
| `code_root="/srv/app"` sets the directory paths are relative to | `SHIELD360_CODE_ROOT` | Git root, then working directory |

The `init()` option wins over the environment variable.

**Release and commit (resource attributes).** These are worked out once, when `init()` runs:

| Attribute | Source, first match wins |
| --- | --- |
| `service.version` | `service_version=` option, `SHIELD360_SERVICE_VERSION`, `SHIELD360_RELEASE`, `OTEL_SERVICE_VERSION`, `OTEL_RESOURCE_ATTRIBUTES` |
| `vcs.ref.head.revision` | `SHIELD360_GIT_COMMIT`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |
| `vcs.repository.url.full` | `SHIELD360_GIT_REPOSITORY_URL`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |
| `vcs.ref.head.name` | `SHIELD360_GIT_BRANCH`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |

The SDK reads CI variables from GitHub Actions, GitLab CI, Vercel, Netlify, Render, Railway, Heroku, AWS CodeBuild, Buildkite, CircleCI, Bitbucket Pipelines, Azure Pipelines and Jenkins (`GIT_COMMIT`). An explicit `OTEL_RESOURCE_ATTRIBUTES` value beats CI auto-detection. Only the first provider with a commit set is used, so values from different providers are never mixed. A commit must be a 7 to 64 character hex SHA. Repository URLs are sent as `https://host/owner/repo`, with user names, passwords and tokens removed.

```python
shield360.init(service_version="2.3.1")  # or set SHIELD360_RELEASE at deploy time
```

Shield360 groups an application's calls by release (Telemetry → Releases) and compares each release with the one before it. With no release set, the commit the SDK detected is used.

### User feedback - `shield360.feedback()`

Send what one of your users thought of an AI response, against the trace that produced it. Call it from your server with the environment's API key, never from a browser. It never raises; it returns `False` when the rating was not accepted.

```python
trace_id = shield360.get_current_trace_id()  # keep this with the response

# later, when the user rates it
shield360.feedback(1, trace_id=trace_id)                      # thumbs up (-1 is thumbs down)
shield360.feedback(4, trace_id=trace_id, comment="Close, but missed the date")  # stars 1-5
shield360.feedback(1, trace_id=trace_id, scale="stars")       # one star
```

| Parameter | Description |
| --- | --- |
| `score` | `1` or `-1` (thumbs), or `1` to `5` (stars). |
| `trace_id` | The trace rated. Defaults to the active span's trace. |
| `span_id` | The span rated, when it was one call in the trace. Optional |
| `comment` | What the user wrote. Kept only when your organization's Data retention setting stores end users' free text, with secrets and personal data masked. Optional |
| `scale` | `"thumbs"` or `"stars"`. Optional |
| `user_id`, `tenant_id` | Your end user and their tenant. Kept only as a keyed hash. Optional |
| `metadata` | A flat dict of up to 20 short values. Optional |
| `feedback_id` | Your id for the rating; sending it again replaces the earlier one. Optional |

Ratings show on the trace and under Telemetry → Feedback, by release and by feature flag variant.

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

### Agent passports - `shield360.agents`

Check the AI agents that call your API or MCP server. A calling agent sends a Shield360 **agent passport** in the `Shield360-Agent` header: a short-lived signed token that says who the agent is, which organization runs it and, when it acts for a person, that it does. The verifier checks it offline against the issuer's published keys, applies your policy and can report each result to your Shield360 project's inbound decision log. A passport never grants access by itself: your own credentials and permissions still decide what the call may do.

Verifying needs the `cryptography` package:

```bash
pip install 'shield360[agents]'
```

```python
import os
from shield360.agents import AgentVerifier

verifier = AgentVerifier(
    audience="api.example.com",                      # your API host or https origin (or a list)
    # issuers=["https://app.shield360.ai"],          # default
    policy={"mode": "observe"},                      # local policy, merged over the defaults
    policy_from={"api_key": os.environ["SHIELD360_INBOUND_API_KEY"]},  # follow the console policy (cached 60 s)
    report={"api_key": os.environ["SHIELD360_INBOUND_API_KEY"]},       # inbound decision log (batched, never blocks)
)

result = verifier.check(request.headers, route="/v1/jobs", method="POST")
# result.status: "verified" | "absent" | "invalid"
# result.decision: "allow" | "deny"; result.blocked: deny in enforce mode
# result.agent: id, name and, when the issuer sends them, status, environment, risk, owner, reviewed_at, enrolled_at
# result.operator, result.scopes
# result.on_behalf_of: id (a pairwise id), domain, assurance ("delegated" | "named" | "unverified"), mandate
# result.to_dict(): the same camelCase shape as the TypeScript verifier
```

`check` accepts a header mapping, a WSGI environ, ASGI raw headers, a request object with `.headers`, or the passport string, and never raises. Pass `online=True` to also ask the issuer (kill switch, revoked token) for a sensitive operation. The API key is sent as `Authorization: Bearer <key>`; `base_url` defaults to `SHIELD360_URL` or `https://app.shield360.ai`.

Policy fields (snake_case or camelCase): `mode` (`observe` never blocks, `enforce` blocks what the policy denies), `require_agent`, `operators` (allowed operator ids or verified domains; empty allows any), `require_on_behalf_of`, `online`, `min_assurance` (`none` by default; `unverified`, `named` or `delegated` denies a passport without a person, or with weaker assurance, as `assurance_too_low`; a person without a stated assurance counts as `named`). An online check can keep a passport valid but lower its assurance (for example `mandate_revoked`); the result then carries the lower assurance and no mandate. Reason codes are the same as the TypeScript verifier's. Each passport is accepted once; the default replay store is in memory, so pass `replay=` an object with `seen(jti, expires_at) -> bool` backed by shared storage when you run several instances.

```python
# FastAPI / Starlette: request.state.shield360_agent
from shield360.agents import AgentVerifierASGIMiddleware
app.add_middleware(AgentVerifierASGIMiddleware, verifier=verifier)

# Flask / any WSGI app: request.environ["shield360.agent"]
from shield360.agents import AgentVerifierWSGIMiddleware
app.wsgi_app = AgentVerifierWSGIMiddleware(app.wsgi_app, verifier)
```

Both answer `403 {"error": "agent_not_allowed", "reason": ...}` only when the result is blocked. Call `verifier.close()` on shutdown to send queued reports.

#### Agents that sign with Web Bot Auth

On a call without a passport, the verifier also checks a [Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/) signature: the `Signature`, `Signature-Input` and `Signature-Agent` headers that Cloudflare's signed agents send. It fetches the signer's key directory (https on a public host name, no redirects, cached for an hour), accepts Ed25519 keys only, and requires the signature to cover your host and the `Signature-Agent` header.

A verified signature gives `status="verified"` and `via="web-bot-auth"`, with the signer's host as `agent` and `operator`. Your `operators` list therefore applies to signers by host name. `result.signature` holds the signer's URL and the key's thumbprint. Pass `web_bot_auth=False` to ignore signatures.

The middleware, a WSGI environ and request objects (Starlette, Flask, Django) give the verifier the method, path and query it needs. When you pass bare headers, pass them as arguments: `verifier.check(headers, route="/v1/jobs", method="POST", query="page=2")`.

## Application logs

Off by default. Set `SHIELD360_CAPTURE_LOGS=true` (or the init option) to send the application's own log records to Shield360, on the same endpoint and key as traces. `SHIELD360_LOG_LEVEL` sets the lowest level sent (`info` by default; `trace`, `debug`, `info`, `warn`, `error`, `fatal`). Records carry the active trace and span ids, `service.name` and `deployment.environment`; credentials and opaque tokens in messages and attributes are masked before they leave the process; at most 500 records a second per bridge are sent, in batches, and a failure to send never reaches the application.

```python
import logging
import shield360

shield360.init(capture_logs=True, log_level="info")  # or SHIELD360_CAPTURE_LOGS=true
logging.basicConfig(level=logging.INFO)              # the root logger's own level still applies

logging.getLogger("checkout").info("order placed", extra={"order_id": "o-1"})
```

`init()` adds one handler to the root logger. `shield360.capture_logs(logger, level)` attaches it to another logger, and `shield360.stop_capturing_logs()` removes it. The record's scope is the logger name. The attributes are `code.file.path`, `code.function.name`, `code.line.number`, `exception.*` and your `extra` fields. The SDK's own loggers (`shield360`, `opentelemetry`) are never sent. Masking follows the contract every Shield360 SDK shares (`sdk/rasp/README.md`, "Masking"). Credential pairs (`password=…`, `"api_key": "…"`, `Authorization: Bearer …`), bearer credentials and opaque tokens (keys, hashes, base64, JWTs, UUIDs) are masked. So is the whole value of a field named like a credential (`password`, `x-api-key`, `sessionId`), with lists and maps masked item by item. Readable identifiers survive: class names, package and file paths, and stack frames.

## Budget check

Ask Shield360 whether this app may spend on a model call. App budgets (Costs → Budgets → App, by service name) and whole-project budgets with enforcement rules apply. Uses `shield360_url`, `shield360_api_key` and `application_name` from `init()`.

```python
check = shield360.budgets.check(model="gpt-4o", estimated_cost_usd=0.02)
if not check.allowed:
    raise RuntimeError(check.reason)
```

`check()` never raises, reuses a decision for its ttl while the calls checked with it fit in its headroom, and fails open unless `fail_closed=True` (or `SHIELD360_BUDGET_FAIL_CLOSED=1`). Pass `budget_check=True` to `init()` (or set `SHIELD360_BUDGET_CHECK=1`) to check before every call to a supported provider; a blocked call raises `shield360.BudgetExceededError`.

## Cost per end customer

Building a SaaS product on AI? Tag each call with your own customer (and, optionally, the end user inside it) and Shield360 shows cost and margin per end customer. Every span started while a customer is in effect gets `shield360.customer.tenant_id` and `shield360.customer.user_id`, whichever instrumentation started it.

```python
# A process-wide default, e.g. in a single-tenant worker. None clears it.
shield360.set_customer(tenant_id="acme")

# Per request: wins over the default, follows asyncio tasks, and nests.
with shield360.customer(tenant_id=request.tenant_id, user_id=request.user_id):
    client.chat.completions.create(model="gpt-4o", messages=messages)

shield360.get_customer()  # {"tenant_id": ..., "user_id": ...} in effect here, or None
```

`shield360.customer(...)` also works as a decorator. Ids may be strings or numbers; they are trimmed and must be 1–256 characters with no control characters. Invalid ids are dropped silently (never raised, never logged), and a `user_id` without a valid `tenant_id` is dropped too. A span that already carries `shield360.customer.tenant_id` is left as it is. If you pass your own `tracer` to `init()`, add `shield360.CustomerSpanProcessor()` to your provider yourself.

The SDK sends ids as given and never hashes them: user ids are stored only as a keyed hash on Shield360's side; tenant ids are kept as given unless the organisation opts to hash them.

## AI app security

`shield360.init(ai_security=True)` turns on checks on the app's own AI traffic, mapped to the OWASP Top 10 for LLM Applications (2025). Every check reports by default and changes nothing; enforcing is set per check (in code, or per app in Shield360 under the app's **Security** tab), and every check fails open. Events carry kinds, masked tokens and keyed fingerprints, never the checked text.

```python
import shield360
from shield360 import ai_security

shield360.init(application_name="support-bot", ai_security={"policy": {"output": {"mode": "enforce"}}})

@ai_security.tool(permissions={"roles": ["support_lead"]})   # checked for the end user before it runs
def refund_order(order_id: str): ...

with ai_security.end_user(tenant_id="acme", user_id="u-42", roles=["agent"]):
    page = ai_security.scan_context(fetched_html, source="document")       # indirect injection
    answer = ai_security.scan_output(model_text, system_prompt=system)     # PII, secrets, leaks
```

With `ai_security` on, OpenAI, Anthropic, LangChain retrievers and tools, LlamaIndex retrievers and the MCP client session are checked automatically. Checks: `scan_context`, `check_prompt`, `scan_output` / `stream_scanner`, `with_canary`, `@tool` / `define_tool` / `authorize_tool`, `check_limits` / `record_usage`, `check_mcp_tools`, `check_retrieval`. The platform's policy is an Ed25519-signed JWS fetched every minute in the background. It is applied only when it verifies under a key you pin: `config_public_key` (a JWK, PEM or JWKS) or `SHIELD360_CONFIG_PUBLIC_KEY`; copy the environment's key from the app's Security tab. Without a pin the checks run in monitor mode with the policy from code. `allow_unpinned_config=True` trusts the first key seen, for development only.

## Runtime packages

With a Shield360 URL and API key, the SDK reports the packages the process runs so Shield360 can match them against vulnerability data (Security → Code, as a "runtime" target): the Python version, the distributions of every module imported so far, then the other installed distributions (`importlib.metadata`). Each is a name and a version; no path, file or other field leaves the process, and at most 500 are sent. The report goes to `/api/guard/events` with the app's API key, about 15 seconds after start and then once a day, off the call path; it never raises and a report that cannot be delivered is dropped. When runtime protection is on it uses this report instead of sending its own.

Turn it off with `shield360.init(runtime_packages=False)` or `SHIELD360_RUNTIME_PACKAGES=off`.

## Runtime protection (RASP)

Runtime application self-protection is off until you turn it on with `shield360.init(rasp=True)` (or a dict of options) or `SHIELD360_RASP=monitor|block`. `SHIELD360_RASP=off` always wins. It monitors by default; blocking is opt-in per attack type. Every check fails open: the only error RASP raises on purpose is `shield360.RaspBlockedError`, which the middleware turns into a 403 with `{"error", "attack", "rule", "event"}`. Request input stays in memory for the request only. Events name the attack, the rule and where the input came from (`query.id`), never the value. The contract shared by all Shield360 SDKs is [`sdk/rasp/README.md`](../rasp/README.md).

```python
import os
import shield360
from shield360.rasp import RaspASGIMiddleware, RaspWSGIMiddleware, rasp_flask

shield360.init(
    application_name="orders-api",
    rasp={
        "config_public_key": os.environ["SHIELD360_CONFIG_PUBLIC_KEY"],   # from the app's Runtime protection settings
        "attacks": {"sql_injection": "block"},
        "allow": {"outbound_hosts": ["*.example.com"], "file_roots": ["/srv/app/uploads"]},
    },
)

app.add_middleware(RaspASGIMiddleware, framework="fastapi")   # FastAPI / Starlette, or RaspASGIMiddleware(app)
rasp_flask(flask_app)                                          # Flask
# Django: add "shield360.rasp.RaspDjangoMiddleware" to MIDDLEWARE; any WSGI app: RaspWSGIMiddleware(app)
```

With `shield360-instrument` the Flask, FastAPI / Starlette and Django middleware is added for you; see [Zero-code setup](#zero-code-setup).

What this release covers:

- **Request capture**: query, path parameters (Flask, Django), a body of at most 1 MiB (JSON leaves, form fields, short raw text), cookies and the `user-agent`, `referer` and `x-forwarded-for` headers, with percent-decoded forms added. A request with no body or an empty one (`Content-Length: 0`, or on HTTP/1.x neither `Content-Length` nor `Transfer-Encoding`) has a known, empty body, so body-phase custom rules still run; a body the app still hands to `shield360.rasp.record_request_body()` becomes input for the built-in checks, without running the body rules again; a body the middleware does not read (over 1 MiB, chunked with no length, or on a `GET`/`HEAD`/`OPTIONS` that declares one) stays unknown until `shield360.rasp.record_request_body()` hands it over. Multipart bodies are not parsed: a short one is seen as raw text. The input is kept in a `contextvars` context, so threads and tasks started from the request see it.
- **Model output as untrusted input**: what the OpenAI and Anthropic instrumentation sees a model return (completion text and tool-call arguments) joins the inputs inside a request, and outside one in an asyncio task. On a plain worker thread, wrap the job in `shield360.rasp.run_in_rasp_scope(fn)` (nothing is recorded there otherwise, so one job's model output never reaches the next).
- **Detection**: the contract's structural detectors for SQL, NoSQL, command, path, SSRF, code, deserialization, XXE and reflected XSS, held to the shared benign corpus (no false positives) and attack examples.
- **Virtual patches**: the built-in list and the signed config's rules, run before the handler.
- **The signed config**: per-app modes, allow-lists, rules and the kill switch from Shield360, an Ed25519 JWS polled every minute and applied only when it verifies under the key you pin (`config_public_key` or `SHIELD360_CONFIG_PUBLIC_KEY`). Without a pin RASP runs its built-in defaults in monitor mode. `allow_unpinned_config=True` (or `SHIELD360_CONFIG_TOFU=dev`) trusts the first key seen, for development only, and is ignored in production.
- **Deception (decoy paths)**: set per app in Shield360's Runtime protection settings and delivered in the signed config; off unless the config names decoys (there is no local option for them). The middleware checks the path the client sent first (WSGI `RAW_URI`/`REQUEST_URI`, ASGI `raw_path` with `root_path`, else the already-decoded path), before anything else it does. A decoy never reaches your handler: it gets the 404 an unknown path gets (Flask's `NotFound` through your `errorhandler(404)`, Django's `Http404` through `handler404` or the debug page, your Starlette or FastAPI 404 handler, FastAPI's `{"detail": "Not Found"}` and Starlette's `Not Found` by default, and a plain-text `404 Not Found` from other WSGI and ASGI apps, or the WSGI or ASGI app you pass as `not_found=`). The client's address (the one `request.ip` uses, never `X-Forwarded-For`) is then suspicious for the block's `ttlSeconds`: with `action: "block"` its later requests get the 403, with `monitor` they are only reported. `attacks.deception` set to `off` turns it off and `monitor` caps it; without a pinned key it only monitors. Suspicious addresses are kept in memory per process (at most 10,000), so workers and replicas do not share them.
- **Events and components**: sent to Shield360 with the guard reporter when a URL and API key are set, at most 100 a minute, repeats folded.
- **Kill switch**: `shield360.disable_rasp()` / `shield360.enable_rasp()` (also `shield360.rasp.disable()` / `enable()`).
- **Sink hooks**, installed while RASP is on, each library patched only once your app imports it:
  - processes: `subprocess.Popen` (and `run`, `check_output` and asyncio subprocesses built on it), `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `os.posix_spawn`;
  - files: `open`, `os` file operations, `shutil` copies, moves and deletes, and `pathlib` through them;
  - outbound HTTP: `urllib`, `http.client`, `requests` and `httpx` (sync and async), checked against the URL and against the addresses the connection resolves; the Shield360 and OTLP hosts are always allowed;
  - databases: `sqlite3`, `psycopg2`, `psycopg`, `pymysql`, `MySQLdb`, `mysql.connector`, SQLAlchemy `text()` and `exec_driver_sql`, pymongo collections;
  - enterprise databases, each lexed in its own dialect:

    | Database | Drivers | Dialect |
    |---|---|---|
    | SQL Server | `pyodbc`, `pymssql` (cursor `execute`/`executemany`, pyodbc `Connection.execute`, a cursor's `connection`), pymssql's low-level `_mssql` connection (`execute_query`, `execute_non_query`, `execute_scalar`, `execute_row`) | `mssql` |
    | Oracle | `oracledb` (cursor `execute`, `executemany`, `prepare`; `Connection.fetch_df_all`/`fetch_df_batches`; `Pipeline.add_*` statements), `cx_Oracle` (`execute`, `executemany`, `prepare` on cursors of connections from `connect`) | `oracle` |
    | Db2 | `ibm_db_dbi` (`Cursor`), `ibm_db.exec_immediate` and `ibm_db.prepare` | `db2` |
    | Any of them through SQLAlchemy | dialects `mssql`, `oracle`, `ibm_db_sa` | as above |

    `pyodbc` and `pymssql` connection and cursor types cannot be changed or subclassed, so their `connect` returns a thin proxy that forwards every attribute, assignment, iteration and `with` block to the real connection; only an `isinstance` check against the driver's own type sees the proxy. Connections from `cx_Oracle.SessionPool` are not covered;
  - code: `eval`, `exec` and `compile`, through an audit hook (they are never replaced, so they keep the caller's scope);
  - template source (`code.template_injection`): Jinja2 `Environment.from_string` and `Template(...)`, Mako `Template(text=...)`, Django `Template(...)` and `Engine.from_string`; only the source is checked, never render data, with one check per call (`Template(...)` delegating to `from_string` is one check). Templates Django loads from files, and custom delimiters, are not covered;
  - deserializers: `pickle`, `marshal`, `dill`, `cloudpickle`, `jsonpickle`, PyYAML with an unsafe loader; XML: `xml.etree`, `minidom`, `xml.sax`, `lxml`;
  - HTML responses through the RASP middleware (reflected XSS, monitor only);
  - sink rules from the built-in list or the signed config.

Initialize Shield360 before your app's modules import what they use: a function taken out of its module before that (`from os import system`), or a database connection opened earlier, is not checked. `shield360.rasp.rasp_check(sink, fn)` runs a check at a sink of your own.

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


## Guard reports and heartbeat

When `shield360.init` is given `guards` and a Shield360 URL and API key (`shield360_url` / `shield360_api_key`, or `SHIELD360_URL` / `SHIELD360_API_KEY`), the SDK reports to Shield360's `/api/guard/events`:

- **Guard decisions:** every decision other than allow (which guard, what it did, the kind of data found). Never the text that was checked.
- **A heartbeat:** once at start and then about every 5 minutes (jittered), the app's service name, each guard kind's mode (`off`, `warn` or `block`), whether prompt-injection checks are on, and the SDK's name and version. No text, host or user. Shield360 uses it to show that the app's guards are on even when they had nothing to stop, for example for the [Secured by Shield360 badge](https://shield360.ai).

Both go through the same background queue, never raise and never delay a call. Turn the heartbeat off with `guard_heartbeat=False` in `shield360.init`, or `SHIELD360_GUARD_HEARTBEAT=false`.

## 🌱 Contributing

Whether it's big or small, we love contributions 💚. Check out our [Contribution guide](https://github.com/ThinkfleetAI/shield360-python#readme) to get started

Unsure where to start? Here are a few ways to get involved:

- Have a question or some feedback? Reach us at [shield360.ai](https://shield360.ai).

Your input helps us grow and improve, and we're here to support you every step of the way.

## 💚 Community & Support

Connect with the Shield360 community and maintainers for support, discussions, and updates:

- 🌟 If you like it, Leave a star on our [GitHub](https://github.com/ThinkfleetAI/shield360-python)
- 🐞 Report bugs on our [GitHub Issues](https://github.com/ThinkfleetAI/shield360-python/issues) to help us improve Shield360.
