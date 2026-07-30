# Compatibility

Which versions of each package the obsvr SDK works with.

## Python

| Package                   | Declared                            | Verified              |
| ------------------------- | ----------------------------------- | --------------------- |
| `ag2`                     | `>=0.3.2,<1.0`                      | `0.3.2` – `0.14.0`    |
| `anthropic`               | `>=0.16.0`                          | `0.8.0` – `0.120.2`   |
| `boto3`                   | `>=1.34.0`                          | —                     |
| `crewai`                  | `>=0.30.0; python_version < '3.14'` | `1.15.8`              |
| `google-cloud-aiplatform` | `>=1.38.0`                          | —                     |
| `google-generativeai`     | any version                         | `0.8.6`               |
| `haystack-ai`             | `>=2.0.0`                           | `2.0.0` – `3.0.0`     |
| `langchain-core`          | `>=0.2.0`                           | `0.2.0` – `1.5.2`     |
| `llama-index-core`        | `>=0.11.23`                         | `0.11.23` – `0.14.23` |
| `mcp`                     | `>=1.0.0,<2.0.0`                    | `1.29.0`              |
| `openai`                  | `>=1.66.0`                          | `1.0.0` – `2.50.0`    |
| `openai-agents`           | `>=0.0.2`                           | `0.0.2` – `0.19.1`    |
| `opentelemetry-api`       | `>=1.20.0`                          | —                     |
| `pydantic-ai-slim`        | `>=0.4.4`                           | `0.4.4` – `2.19.0`    |
| `starlette`               | `>=0.30.0`                          | `0.30.0` – `1.3.1`    |

`google-generativeai` is the legacy line, end-of-life 2025-08.

## TypeScript

| Package                           | Declared                        | Verified              |
| --------------------------------- | ------------------------------- | --------------------- |
| `@anthropic-ai/sdk`               | `>=0.20.0`                      | `0.20.0` – `0.115.0`  |
| `@aws-sdk/client-bedrock-runtime` | `>=3.587.0`                     | `3.1096.0`            |
| `@google-cloud/vertexai`          | `>=1.0.0`                       | `1.0.0` – `1.12.0`    |
| `@google/genai`                   | —                               | **not supported yet** |
| `@google/generative-ai`           | `>=0.1.0 <1.0.0`                | `0.1.0` – `0.24.1`    |
| `@langchain/core`                 | `>=0.2.0`                       | `0.2.0` – `1.2.3`     |
| `@modelcontextprotocol/sdk`       | `>=1.0.0 <1.25.0 \|\| >=1.30.0` | `1.30.0`              |
| `@openai/agents`                  | `>=0.13.0 <1.0.0`               | `0.13.0` – `0.14.0`   |
| `@opentelemetry/api`              | `>=1.4.0`                       | `1.4.0` – `1.9.1`     |
| `ai`                              | `>=3.3.28`                      | `3.4.33` – `7.0.41`   |
| `llamaindex`                      | `>=0.5.9`                       | `0.5.9` – `0.12.1`    |
| `openai`                          | `>=6.0.0 <8.0.0`                | `6.0.0` – `7.0.0`     |
| `together-ai`                     | `>=0.6.0 <1.0.0`                | `0.6.0` – `0.44.0`    |

`@google/generative-ai` is the legacy line, end-of-life 2025-08. Its replacement `@google/genai` is **not supported yet**.

## Version needed per method

A release can be installable and governed on one method while another does not
exist on the client yet. These are the releases each method first works at.

**This table describes `obsvr.wrap()` and the module interceptor.** The named
compatibility wrappers — `wrapAzureOpenAI`, `wrapTogether`, `wrapCloudflare`,
`wrapOpenAICompatible` — govern `chat.completions.create` and nothing else, so
every other row below is ungoverned and unaudited through them however new the
installed client is. Wrap with `obsvr.wrap()` if you need the rest; it accepts
the same clients.

### `openai` (Python)

| Method                         | Needs            |
| ------------------------------ | ---------------- |
| `chat.completions.create`      | `openai>=1.0.0`  |
| `beta.chat.completions.parse`  | `openai>=1.40.0` |
| `responses.create`             | `openai>=1.66.0` |
| `responses.parse`              | `openai>=1.66.0` |
| `beta.chat.completions.create` | `openai>=1.92.0` |
| `chat.completions.parse`       | `openai>=1.92.0` |
| `beta.responses.create`        | `openai>=2.45.0` |

### `anthropic` (Python)

| Method                 | Needs               |
| ---------------------- | ------------------- |
| `beta.messages.create` | `anthropic>=0.8.0`  |
| `messages.create`      | `anthropic>=0.16.0` |
| `messages.parse`       | `anthropic>=0.77.0` |

## Versions that will not work

| Package | Language | Declared         | Why                                                                                                                            |
| ------- | -------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `ag2`   | Python   | `>=0.3.2,<1.0`   | 1.0 removed the agent class this integration binds, and renamed the import package.                                            |
| `mcp`   | Python   | `>=1.0.0,<2.0.0` | 2.0 renamed the tool descriptor fields the integration reads, which silently disables the schema scan and the capability gate. |

_The Verified columns come from an integration-test matrix run outside this
repository; that harness is not published, so this table is updated by hand when
the matrix is re-run._
