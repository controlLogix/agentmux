# Bedrock gateway compatibility

AMUX-66 retains and repairs the standalone Python gateway. The recovered
translation functions and the preserved CPython 3.12 bytecode remain in place.
This is a repair of the existing path, not a statement that a current provider
account, model, client version or commercial distribution arrangement is qualified.

The gateway accepts a declared subset of Responses requests and translates them
to Bedrock Chat Completions. It does not execute tools. The caller receives tool
calls and remains responsible for their authorization and execution.

## Standalone boundary

The listener binds `127.0.0.1`. Start it through the retained entry point:

```sh
python3 taskmgmt/bedrock_gateway.py --region us-west-2 --model openai.gpt-oss-120b-1:0
```

The owning process must receive two separate secrets from its protected local
environment: `AWS_BEARER_TOKEN_BEDROCK` for AWS and
`AGENTMUX_BEDROCK_GATEWAY_TOKEN` for the local client. The local token must contain
32–4096 printable ASCII characters without spaces and must differ from the AWS key.
Use a randomly generated secret. Do not put either secret in command arguments,
shared configuration, NATS messages or logs. The gateway does not read another
tool's credentials or modify a user's configuration.

Configure the client to send the local token as its bearer credential. For the
Codex custom endpoint method, set `CODEX_CUSTOM_API_KEY` to that same local token;
keep `AWS_BEARER_TOKEN_BEDROCK` in the gateway's environment only. A client
configuration that previously used the AWS key for the local gateway must change
its credential reference. The AWS key is sent only to the configured AWS region's
HTTPS endpoint; redirects and process-wide HTTP proxy settings are refused.
There is no anonymous inference mode. Browser-origin requests are refused.

This token controls access to one owner's standalone process. It does not prove
organization, project, repository or user identity. The gateway has no managed
project route and rejects project/actor claims in the request body. Sharing its
token with another user does not create scoped access. Managed use must wait for
the enrolled identity, provider intent, current approval and owner integration.

`--model` is both the fallback and the initial allowed model. Repeat
`--allow-model MODEL_ID` only for additional models the owner intends to use.
`GET /v1/models` reports that configured list; it does not query AWS or establish
availability. `GET /v1/capabilities` reports the exact local translation limits.
Both require the local token. `/health` and `/v1/health` are public local process
diagnostics; a successful health response does not prove credentials or inference.

## Supported translation

| Input or behavior | Contract |
| --- | --- |
| Paths | `POST /responses` and `POST /v1/responses`, including a trailing slash or query string. |
| Request encoding | One JSON body with one `Content-Length`; at most 8 MiB. Duplicate JSON keys, nonfinite numbers, ambiguous lengths, encoded/chunked bodies and unsupported fields are refused. |
| Messages | Plain strings and `message` items containing text, with system/developer/user/assistant roles. Instructions become a system message. Empty string items retain their position; empty messages are dropped. |
| Tool history | `function_call` and text `function_call_output`; original missing-ID fallbacks remain. |
| Reasoning history | `reasoning` input items are ignored and never logged or forwarded. `item_reference` is unsupported. |
| Tool declarations | Functions and namespaces up to three levels. Names stay unchanged; the first duplicate function name wins. Server-hosted tools and strict structured output are refused before dispatch. |
| Request options | `stream`, `max_output_tokens`, `temperature`, `top_p`, and `tool_choice` values `auto`, `none`, `required`. `store: false` and `parallel_tool_calls: true` are accepted; the opposite values are unsupported. |
| Stream output | Created, text delta/done, item added/done, completed, incomplete and failed Responses events. Function arguments retain their fragments and original item event ordering. |
| Reasoning filter | Closed `<reasoning>` spans are removed across chunk splits. The recovered filter releases text in an unterminated span, preserving the historical malformed-tag behavior. Such output is never logged. |
| Unsupported content | Images, audio, files, stored-response references, server-hosted tools, structured output and unknown request semantics receive an explicit error. |

The module still exposes its recovered translation functions for differential
tests. Those helpers preserve the historical skip/fallback behavior. The HTTP
boundary validates first, so an unsupported item cannot silently disappear from
a dispatched request.

## Failure and resource behavior

Each request makes at most one provider attempt. Error replies contain fixed
categories rather than provider bodies, exception text, URLs, input content or
credentials. Logs contain only fixed event names and numeric counts. The optional
log must be a private, owner-held regular file; symlinks and shared files are refused.

Provider reads have a 30-second idle timeout and a 600-second deadline checked
before and after bounded reads. A blocked read may take up to the remaining idle
timeout to return. The gateway caps upstream data at 16 MiB, individual stream
lines at 256 KiB, stream lines at 65,536 and simultaneous clients at eight.
Request sockets have a 15-second idle timeout. These bounds do not establish a
provider-side cancellation or billing guarantee.

An SSE stream without `[DONE]` fails with `upstream_incomplete`; it does not emit
`response.completed`. Provider truncation or filtering produces
`response.incomplete`, and incomplete tool arguments are not returned as executable
function calls. A detected client disconnect closes the owned upstream response.
There is no separate provider cancellation API or durable reconciliation service
in this standalone path. Timeouts, disconnects and lost replies remain unknown;
the gateway never retries them automatically or asserts that provider work stopped.

Completed responses include an additive `agentmux` object. Its
`usage_provenance` is `provider_reported`, `provider_partial` or `unavailable`.
This distinguishes missing usage from a reported zero while preserving the
existing Responses token fields. `upstream_outcome` records completed, incomplete
or unknown output, and `billing_outcome` remains `unknown`.

## Compatibility changes and checks

The AMUX-66 safety changes deliberately replace anonymous inference, static
unverified model advertising, silently dropped unsupported HTTP inputs, raw error
text, unbounded upstream parsing and false success after an interrupted stream.
The owning issue's review must accept these changes before support is claimed.
The historical wire translations, namespace limit, duplicate handling, short
replies, split/malformed tags and successful tool event order remain characterized.

Run the focused checks using the prepared Python environment:

```sh
python -B dashboard/test_gateway.py
python -B -m unittest dashboard.test_gateway_boundary
```

`test_gateway.py` runs the original bytecode comparison only when CPython can load
the preserved 3.12 artifact. An incompatible interpreter prints a separate skip;
ordinary assertions passing does not mean the bytecode comparison ran. Relay
comparisons omit only the new `agentmux` metadata. Malformed upstream replies now
have their own refusal tests instead of comparing against the old false success.

The opt-in HTTP test uses an owned fake upstream and ephemeral loopback servers:

```sh
python -B dashboard/verify_gateway_e2e.py
```

Run that command only in the serialized local-test slot. It starts no process or
server when imported, uses only synthetic credentials and joins its original
server/thread handles. Current HTTP assertions run on supported Python versions;
the successful HTTP bytecode comparison is a separately reported 3.12 subset.
No default diagnostic sends an inference request.

## Missing historical setup paths

The older README refers to `dashboard/start_gateway.sh`,
`dashboard/setup_bedrock_codex.sh`, `dashboard/probe_bedrock.sh`,
`dashboard/test_models.py` and `bedrock_models.json`; those files are absent from
the retained source. Its `codex-bedrock`, `claude-bedrock` and `--provider bedrock`
setup examples do not establish currently supported manifest methods. This repair
does not recreate scripts that copied credentials from other tools. Use the direct
gateway entry point above for the standalone boundary and the maintained auth
manifest for actual method availability.

Current client/account/model qualification, provider terms and paid distribution
rights remain separate from these offline compatibility checks. Real provider
tests require an explicitly approved account, data and capped budget.
