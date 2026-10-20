"""OpenAI **Responses API** -> AWS Bedrock **Chat Completions** gateway. Stdlib only.

    python3 taskmgmt/bedrock_gateway.py [--port 4000] [--region us-west-2]
                                        [--log /tmp/gw.jsonl] [--verbose]

WHY THIS EXISTS
---------------
codex 0.155.0 speaks only the OpenAI Responses API: it rejects
`wire_api = "chat"` outright ("no longer supported. set wire_api = "responses"").

Bedrock offers an OpenAI-COMPATIBLE endpoint, but it is Chat Completions:

    POST /openai/v1/chat/completions   -> 200, works
    POST /openai/v1/responses          -> 404 "model doesn't support this API"

Both verified against a live key in us-west-2. So the two ends are one API generation
apart and something has to translate. That is this file.

AUTH
----
A Bedrock API key is a bearer token, so no SigV4 signing is needed - just
`Authorization: Bearer <key>`. The key is read from the environment
(AWS_BEARER_TOKEN_BEDROCK) and never logged, never echoed, and never placed in argv.

ORIGINAL SECURITY POSTURE (2026-09-22)
------------------------------------
  - Binds 127.0.0.1 only. A gateway holding a cloud credential must not listen on a
    routable address; that is a confused deputy waiting for a request.
  - Requires no client credential, BECAUSE it is loopback-only and single-user. codex
    still sends its env_key, which is accepted and ignored.
  - Request bodies are capped. The log, when enabled, records the request SHAPE and
    omits the Authorization header.

AMUX-66 REPAIR
-------------
The standalone listener now requires a separate AGENTMUX_BEDROCK_GATEWAY_TOKEN
(at least 32 non-whitespace characters), checks the configured model list and
refuses unsupported request semantics. It never forwards that token to AWS.
This is a single-owner transport defense, not project identity or permission.
Managed/project use remains unavailable until the provider owner contract exists.
Logs contain only fixed event names and counts. Interrupted upstream responses
remain outcome-unknown and are never retried. The translation functions below
retain the recovered behavior; the HTTP and upstream boundaries have explicit
safety changes covered by the boundary tests.

PROVENANCE - READ THIS BEFORE "TIDYING UP"
------------------------------------------
This file was **reconstructed on 2026-09-22**. The original was written on 2026-09-19
and then lost: neither it nor its test suite was ever committed, and both were most
likely deleted alongside the two Bedrock setup scripts during the 2026-09-20 credential
purge - scripts that existed to copy a key out of another tool's settings file and
deserved deleting. This one holds no credential; it reads one from the environment.

What survived was the compiled bytecode, which still loaded on CPython 3.12. This
source was rebuilt from it: every docstring here is the original's, verbatim; the wire
format, constants, control flow and error handling were read out of the bytecode; and
the result was then checked **differentially against the original module**, function by
function, on identical inputs. See dashboard/test_gateway.py, which runs both and
compares, and taskmgmt/recovered/ for the preserved bytecode.

So the odd-looking details here are deliberate reproductions, not fresh choices:
the tool-namespace recursion depth of 3, the `call_0` fallback id, the 800- and
300-character truncations on upstream errors, the hold-back arithmetic in
ReasoningFilter. Changing one changes behaviour that was verified against live Bedrock.
"""
import argparse
import hmac
import json
import math
import os
import re
import socket
import stat
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 8 * 1024 * 1024
UPSTREAM_TIMEOUT = 600
UPSTREAM_IDLE_TIMEOUT = 30
MAX_UPSTREAM_BODY = 16 * 1024 * 1024
MAX_EVENT = 256 * 1024
MAX_EVENTS = 65536
CLIENT_TIMEOUT = 15
MAX_CLIENTS = 8
MODEL_DEFAULT = "openai.gpt-oss-120b-1:0"

STATE = {"region": "us-west-2", "log": None, "verbose": False,
         "model_default": MODEL_DEFAULT, "allowed_models": (MODEL_DEFAULT,)}

REASONING_OPEN = "<reasoning>"
REASONING_CLOSE = "</reasoning>"


def log_event(kind, payload):
    """Write only fixed event names and numeric facts to a private local file."""
    allowed = {
        "responses_request": {"stream", "message_count", "tool_count"},
        "unhandled_input_item": set(), "duplicate_tool": set(),
        "unsupported_tool": set(), "upstream_http_error": {"code"},
        "upstream_error": set(), "stream_error": set(),
        "client_disconnected": set(), "stream_done": {"chars", "tool_calls"},
        "upstream_timeout": set(), "upstream_outcome_unknown": set(),
    }
    if kind not in allowed:
        return
    clean = {key: value for key, value in payload.items()
             if key in allowed[kind] and type(value) in (int, bool)
             and 0 <= int(value) <= MAX_UPSTREAM_BODY}
    path = STATE["log"]
    if not path:
        return
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                             | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                return
            handle.write(json.dumps(
                {"at": time.time(), "kind": kind, "payload": clean}) + "\n")
    except OSError:
        pass


def say(*args):
    if STATE["verbose"]:
        print(*args, file=sys.stderr, flush=True)


def _valid_local_token(token):
    return (32 <= len(token) <= 4096 and all(33 <= ord(char) <= 126 for char in token)
            and token != os.environ.get("AWS_BEARER_TOKEN_BEDROCK"))


class GatewayFailure(Exception):
    """A closed public error category; never carries provider or request text."""
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def capabilities():
    """Describe the local translation contract, not account/model qualification."""
    return {
        "mode": "standalone-single-owner", "managed_project_access": False,
        "authentication": "separate-local-bearer-token",
        "qualification": "offline-contract-only; live account approval required",
        "models": list(STATE["allowed_models"]),
        "input": ["string", "message:text", "function_call", "function_call_output"],
        "ignored_input": ["reasoning"],
        "tools": ["function", "namespace (at most three levels)"],
        "duplicate_tools": "first function with the same name wins",
        "tool_choice": ["auto", "none", "required"],
        "events": ["response.created", "response.output_item.added",
                   "response.output_text.delta", "response.output_text.done",
                   "response.output_item.done", "response.completed",
                   "response.incomplete", "response.failed"],
        "unsupported": ["images", "audio", "files", "item_reference",
                        "server-hosted tools", "stored responses", "structured output",
                        "tool execution", "managed identity", "project authority"],
        "cancellation": "client disconnect closes the upstream connection; provider outcome remains unknown",
        "retry": "none; a lost reply does not establish that inference or billing stopped",
        "limits": {"request_bytes": MAX_BODY, "upstream_bytes": MAX_UPSTREAM_BODY,
                   "stream_event_bytes": MAX_EVENT, "stream_events": MAX_EVENTS,
                   "upstream_idle_seconds": UPSTREAM_IDLE_TIMEOUT,
                   "stream_deadline_seconds": UPSTREAM_TIMEOUT, "clients": MAX_CLIENTS},
    }


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError):
        raise GatewayFailure("invalid_json") from None
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 65536 or depth > 32:
            raise GatewayFailure("json_limit")
        if isinstance(item, float) and not math.isfinite(item):
            raise GatewayFailure("invalid_json")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _fields(value, allowed):
    if not isinstance(value, dict):
        raise GatewayFailure("invalid_request")
    if set(value) - set(allowed):
        raise GatewayFailure("unsupported_field", 422)


def _text(value, *, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str):
        raise GatewayFailure("invalid_request")


def validate_request(body):
    """Reject unsupported semantics before the recovered translator can drop them."""
    _fields(body, {"model", "input", "instructions", "tools", "tool_choice",
                   "max_output_tokens", "temperature", "top_p", "stream",
                   "store", "parallel_tool_calls"})
    _text(body.get("model"), optional=True)
    model = body.get("model") or STATE["model_default"]
    if not isinstance(model, str) or model not in STATE["allowed_models"]:
        raise GatewayFailure("unsupported_model", 422)
    for name in ("stream", "store", "parallel_tool_calls"):
        if name in body and type(body[name]) is not bool:
            raise GatewayFailure("invalid_request")
    if body.get("store") or body.get("parallel_tool_calls") is False:
        raise GatewayFailure("unsupported_field", 422)
    _text(body.get("instructions"), optional=True)
    if "max_output_tokens" in body and (type(body["max_output_tokens"]) is not int
            or not 0 < body["max_output_tokens"] <= 131072):
        raise GatewayFailure("invalid_request")
    for name, maximum in (("temperature", 2), ("top_p", 1)):
        value = body.get(name)
        if value is not None and (type(value) not in (int, float)
                or not math.isfinite(value) or not 0 <= value <= maximum):
            raise GatewayFailure("invalid_request")
    items = body.get("input")
    if isinstance(items, str):
        items = [items]
    if not isinstance(items, list) or len(items) > 1024:
        raise GatewayFailure("invalid_request")
    for item in items:
        if isinstance(item, str):
            continue
        if not isinstance(item, dict):
            raise GatewayFailure("invalid_request")
        kind = item.get("type")
        if kind == "reasoning":
            # Historical clients round-trip private reasoning. Never forward or log it.
            continue
        if kind == "message":
            _fields(item, {"type", "role", "content", "id", "status"})
            if item.get("role", "user") not in ("system", "developer", "user", "assistant"):
                raise GatewayFailure("invalid_request")
            content = item.get("content", [])
            if isinstance(content, str):
                continue
            if not isinstance(content, list) or len(content) > 1024:
                raise GatewayFailure("invalid_request")
            for part in content:
                if isinstance(part, str):
                    continue
                _fields(part, {"type", "text", "refusal", "annotations"})
                if part.get("type") not in ("input_text", "output_text", "refusal"):
                    raise GatewayFailure("unsupported_content", 422)
                _text(part.get("text"), optional=True)
                _text(part.get("refusal"), optional=True)
        elif kind in ("function_call", "function_call_output"):
            _fields(item, {"type", "id", "status", "call_id", "name", "arguments"}
                    if kind == "function_call" else {"type", "id", "call_id", "output"})
            for name in ("call_id", "id", "name", "arguments", "output"):
                _text(item.get(name), optional=True)
        else:
            raise GatewayFailure("unsupported_input", 422)
    count = 0

    def tools(items, depth=0):
        nonlocal count
        if items is None:
            return
        if not isinstance(items, list):
            raise GatewayFailure("invalid_request")
        for item in items:
            count += 1
            if count > 128 or not isinstance(item, dict):
                raise GatewayFailure("tool_limit")
            kind = item.get("type")
            if kind == "namespace" and depth < 3:
                _fields(item, {"type", "name", "description", "tools"})
                tools(item.get("tools"), depth + 1)
            elif kind == "function":
                _fields(item, {"type", "name", "description", "parameters", "strict"})
                if not isinstance(item.get("name"), str) or not item["name"]:
                    raise GatewayFailure("invalid_request")
                _text(item.get("description"), optional=True)
                if item.get("parameters") is not None and not isinstance(item["parameters"], dict):
                    raise GatewayFailure("invalid_request")
                if item.get("strict") is not None and item.get("strict") is not False:
                    raise GatewayFailure("unsupported_tool", 422)
            else:
                raise GatewayFailure("unsupported_tool", 422)
    tools(body.get("tools"))
    if body.get("tool_choice") not in (None, "auto", "none", "required"):
        raise GatewayFailure("unsupported_tool_choice", 422)
    if not to_chat_messages(body):
        raise GatewayFailure("empty_input")


def _usage(value):
    if value is None:
        return
    if not isinstance(value, dict):
        raise GatewayFailure("invalid_upstream", 502)
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        if key in value and (type(value[key]) is not int or not 0 <= value[key] <= 10**12):
            raise GatewayFailure("invalid_upstream", 502)


def _provenance(response, usage, outcome):
    reported = {key for key in ("prompt_tokens", "completion_tokens") if key in (usage or {})}
    response["agentmux"] = {
        "usage_provenance": "provider_reported" if len(reported) == 2 else
                            "provider_partial" if reported else "unavailable",
        "upstream_outcome": outcome, "billing_outcome": "unknown",
    }
    return response


def _upstream_failure(error):
    if isinstance(error, GatewayFailure):
        return error.code, error.status
    if isinstance(error, (TimeoutError, socket.timeout)) or (
            isinstance(error, urllib.error.URLError) and isinstance(error.reason, TimeoutError)):
        return "upstream_timeout", 504
    return "upstream_unavailable", 502


def _tool_calls(value, *, streamed=False):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 128:
        raise GatewayFailure("invalid_upstream", 502)
    for call in value:
        if not isinstance(call, dict) or not isinstance(call.get("function", {}), dict):
            raise GatewayFailure("invalid_upstream", 502)
        if call.get("type") not in (None, "function"):
            raise GatewayFailure("unsupported_upstream_tool", 502)
        if streamed and (type(call.get("index", 0)) is not int
                         or not 0 <= call.get("index", 0) < 128):
            raise GatewayFailure("invalid_upstream", 502)
        values = [call.get("id"), *[call.get("function", {}).get(key)
                                  for key in ("name", "arguments")]]
        if any(item is not None and not isinstance(item, str) for item in values):
            raise GatewayFailure("invalid_upstream", 502)
    return value


def _upstream_object(raw):
    try:
        data = _json(raw)
    except GatewayFailure:
        raise GatewayFailure("invalid_upstream_json", 502) from None
    if not isinstance(data, dict) or "error" in data:
        raise GatewayFailure("invalid_upstream", 502)
    _usage(data.get("usage"))
    choices = data.get("choices", [])
    if not isinstance(choices, list) or len(choices) > 1 or any(not isinstance(c, dict) for c in choices):
        raise GatewayFailure("invalid_upstream", 502)
    return data, choices


def _finish_reason(value):
    if value not in (None, "stop", "tool_calls", "length", "content_filter"):
        raise GatewayFailure("unsupported_upstream_finish", 502)
    return value


def _read_chunks(upstream):
    """Read bounded chunks; check elapsed time even while a peer sends slowly."""
    deadline = time.monotonic() + UPSTREAM_TIMEOUT
    total = 0
    # HTTPResponse.read1 performs at most one underlying read. read(n) can wait
    # indefinitely for n bytes while a peer sends bytes below the idle timeout.
    read = upstream.read1
    while True:
        if time.monotonic() >= deadline:
            raise GatewayFailure("upstream_timeout", 504)
        raw = read(min(65536, MAX_UPSTREAM_BODY - total + 1))
        if time.monotonic() >= deadline:
            raise GatewayFailure("upstream_timeout", 504)
        if not raw:
            return
        total += len(raw)
        if total > MAX_UPSTREAM_BODY:
            raise GatewayFailure("upstream_limit", 502)
        yield raw


def _stream_lines(upstream):
    pending = b""
    events = 0
    for raw in _read_chunks(upstream):
        pending += raw
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            events += 1
            if len(line) + 1 > MAX_EVENT or events > MAX_EVENTS:
                raise GatewayFailure("upstream_limit", 502)
            yield line
        if len(pending) > MAX_EVENT:
            raise GatewayFailure("upstream_limit", 502)
    if pending:
        if len(pending) > MAX_EVENT or events >= MAX_EVENTS:
            raise GatewayFailure("upstream_limit", 502)
        yield pending


# ── request translation ──────────────────────────────────────────────────────

def text_from_content(content):
    """Flatten a Responses content array into plain text."""
    if isinstance(content, str):
        return content
    parts = []
    for part in content or []:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, dict):
            parts.append(part.get("text") or part.get("refusal") or "")
    return "".join(parts)


def to_chat_messages(body):
    """Build Chat Completions `messages` from a Responses request.

    Handles the item kinds codex actually emits: plain strings, `message`,
    `function_call`, and `function_call_output`. Anything unrecognised is skipped
    rather than guessed at, and logged so the gap is visible instead of silent.
    """
    messages = []
    instructions = body.get("instructions")
    if isinstance(instructions, str) and instructions.strip():
        messages.append({"role": "system", "content": instructions})

    items = body.get("input")
    if isinstance(items, str):
        items = [items] if items else []
    if not isinstance(items, list):
        # A number or an object here is malformed input, not something to iterate:
        # iterating a dict yields its keys and would invent messages out of them.
        items = []
    for item in items:
        # A string item is passed through as-is, including an empty one. Filtering
        # blanks here looks tidy and is wrong: codex's turn structure is positional,
        # so dropping an item silently shifts everything after it.
        if isinstance(item, str):
            messages.append({"role": "user", "content": item})
            continue
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "message":
            # An empty message is dropped rather than sent: Bedrock rejects a
            # content-less message outright, which would fail the whole request.
            text = text_from_content(item.get("content"))
            if text:
                messages.append({"role": item.get("role") or "user",
                                 "content": text})
        elif kind == "function_call":
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": item.get("call_id") or item.get("id") or "call_0",
                    "type": "function",
                    "function": {"name": item.get("name") or "",
                                 "arguments": item.get("arguments") or "{}"},
                }],
            })
        elif kind == "function_call_output":
            messages.append({"role": "tool",
                             "tool_call_id": item.get("call_id") or "call_0",
                             "content": item.get("output") or ""})
        elif kind in ("reasoning", "item_reference"):
            # codex round-trips its own reasoning items; Chat Completions has no
            # slot for them and they carry nothing the model needs restated.
            continue
        else:
            log_event("unhandled_input_item",
                      {"type": kind, "keys": sorted(item.keys())})
    return messages


def to_chat_tools(body):
    """Responses tools -> Chat Completions tools.

    Two shape differences and one structural one:

      Responses function: {type:"function", name, description, parameters}
      Chat function:      {type:"function", function:{name, description, parameters}}

    STRUCTURAL: codex groups related tools under a `namespace` item -
    {type:"namespace", name:"multi_agent_v1", description, tools:[ ...functions... ]} -
    which Chat Completions has no concept of. Dropping those groups is what an earlier
    version did, and it silently left the agent with NO tools at all: it could talk but
    not read a file or run a command. They are flattened instead, keeping each inner
    name exactly as codex declared it, because codex matches the tool call it gets back
    by that name.

    `web_search` and other server-hosted tool types genuinely have no equivalent and are
    dropped - but logged, so the gap is visible rather than silent.
    """
    out = []
    seen = set()

    def add(spec):
        if not isinstance(spec, dict):
            return
        name = spec.get("name") or ""
        if not name or name in seen:
            log_event("duplicate_tool", {"name": name})
            return
        seen.add(name)
        out.append({"type": "function", "function": {
            "name": name,
            "description": spec.get("description") or "",
            "parameters": spec.get("parameters") or {"type": "object", "properties": {}},
        }})

    def walk(items, depth):
        for tool in items or []:
            if not isinstance(tool, dict):
                continue
            kind = tool.get("type")
            if kind == "function":
                add(tool)
            elif kind == "namespace" and depth < 3:
                # Bounded rather than unbounded: a cyclic or absurdly nested tool
                # manifest must not take the gateway down with a recursion error.
                walk(tool.get("tools"), depth + 1)
            else:
                log_event("unsupported_tool", {"type": kind, "name": tool.get("name")})

    walk(body.get("tools"), 0)
    return out


class ReasoningFilter:
    """Remove <reasoning> spans from a stream of text fragments.

    NEVER LOSES OUTPUT. Two ways the first version did, both found by running every
    model end to end rather than by reading the code:

      1. It always held back 10 characters in case a `<reasoning` open tag was split
         across deltas. A short reply - "MODEL OK" is 8 characters - was therefore held
         back in its entirety and, because the caller only emitted the flush when a
         delta had already been sent, never appeared at all. Streaming produced zero
         deltas while the non-streaming path was fine.
      2. An unclosed `<reasoning>` discarded everything after it. gpt-oss-20b does
         exactly that, so its answers came back empty. Losing the answer is far worse
         than showing the model's working, so an unterminated span is now treated as a
         malformed tag and released instead of swallowed.
    """

    def __init__(self):
        self.inside = False
        self.pending = ""
        self.swallowed = []

    def feed(self, chunk):
        self.pending += chunk
        out = []
        while self.pending:
            if self.inside:
                index = self.pending.find(REASONING_CLOSE)
                if index < 0:
                    # Hold back only enough to catch a closing tag split across
                    # deltas; everything before that is certainly inside the span.
                    hold = len(REASONING_CLOSE) - 1
                    if len(self.pending) > hold:
                        self.swallowed.append(self.pending[:-hold])
                        self.pending = self.pending[-hold:]
                    break
                self.swallowed.append(self.pending[:index])
                self.pending = self.pending[index + len(REASONING_CLOSE):]
                self.inside = False
                self.swallowed.clear()
                continue
            index = self.pending.find(REASONING_OPEN)
            if index < 0:
                hold = len(REASONING_OPEN) - 1
                if len(self.pending) > hold:
                    out.append(self.pending[:-hold])
                    self.pending = self.pending[-hold:]
                break
            out.append(self.pending[:index])
            self.pending = self.pending[index + len(REASONING_OPEN):]
            self.inside = True
        return "".join(out)

    def flush(self):
        """Everything still held once upstream is done. Emits, never discards."""
        text = self.pending
        if self.inside:
            # Unterminated span: release it rather than lose the answer inside it.
            text = "".join(self.swallowed) + text
        self.pending = ""
        self.swallowed = []
        self.inside = False
        return text


def build_chat_request(body):
    chat = {
        "model": body.get("model") or STATE["model_default"],
        "messages": to_chat_messages(body),
    }
    tools = to_chat_tools(body)
    if tools:
        chat["tools"] = tools
        choice = body.get("tool_choice")
        if choice in ("auto", "none", "required"):
            chat["tool_choice"] = choice
    for source, target in (("max_output_tokens", "max_completion_tokens"),
                           ("temperature", "temperature"),
                           ("top_p", "top_p")):
        if body.get(source) is not None:
            chat[target] = body[source]
    if body.get("stream"):
        chat["stream"] = True
        # Without this Bedrock omits usage from the streamed response entirely.
        chat["stream_options"] = {"include_usage": True}
    return chat


def make_response_object(response_id, model, text, tool_calls, usage, status):
    """The Responses object codex reads back."""
    output = []
    if text:
        output.append({
            "type": "message",
            "id": response_id + "-msg",
            "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        })
    for index, call in enumerate(tool_calls or []):
        function = call.get("function") or {}
        output.append({
            "type": "function_call",
            "id": response_id + "-fc" + str(index),
            "call_id": call.get("id") or "call_" + str(index),
            "name": function.get("name") or "",
            "arguments": function.get("arguments") or "{}",
            "status": "completed",
        })
    usage = usage or {}
    prompt = usage.get("prompt_tokens") or 0
    completion = usage.get("completion_tokens") or 0
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "status": status,
        "model": model,
        "output": output,
        "usage": {"input_tokens": prompt, "output_tokens": completion,
                  "total_tokens": prompt + completion},
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
    }


# ── upstream ─────────────────────────────────────────────────────────────────

def bedrock_url():
    return ("https://bedrock-runtime." + STATE["region"]
            + ".amazonaws.com/openai/v1/chat/completions")


def call_bedrock(chat_body, stream):
    key = os.environ.get("AWS_BEARER_TOKEN_BEDROCK", "")
    if not key:
        raise RuntimeError("AWS_BEARER_TOKEN_BEDROCK is not set in this process")
    request = urllib.request.Request(
        bedrock_url(),
        method="POST",
        data=json.dumps(chat_body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + key,
            "Accept": "text/event-stream" if stream else "application/json",
        },
    )
    # A provider redirect must not forward the bearer credential to a new host.
    # A process-wide proxy setting is not an approved disclosure destination.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=UPSTREAM_IDLE_TIMEOUT)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


class GatewayServer(ThreadingHTTPServer):
    """Bound simultaneous clients and retain handler ownership through close."""
    daemon_threads = False

    def __init__(self, *args, **kwargs):
        self._clients = threading.BoundedSemaphore(MAX_CLIENTS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self._clients.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self._clients.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self._clients.release()

    def handle_error(self, request, address):
        # ThreadingHTTPServer otherwise prints the raw exception and traceback.
        log_event("upstream_error", {})
        say("gateway request failed")


class Gateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "agentmux-bedrock-gateway"

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler includes the untrusted URL in this callback.
        say("http request handled")

    def setup(self):
        super().setup()
        self.connection.settimeout(CLIENT_TIMEOUT)

    def send_json(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            log_event("client_disconnected", {})
            log_event("upstream_outcome_unknown", {})

    def failure(self, code, status, *, dispatched=False):
        self.close_connection = True
        self.send_json(status, {"error": {
            "type": "gateway_error", "code": code, "message": code.replace("_", " "),
            "upstream_outcome": "unknown" if dispatched else "not_dispatched",
            "retryable": False,
        }})

    def authenticated(self):
        expected = os.environ.get("AGENTMUX_BEDROCK_GATEWAY_TOKEN", "")
        headers = self.headers.get_all("Authorization", [])
        if not _valid_local_token(expected):
            self.failure("local_token_not_configured", 503)
            return False
        if (len(headers) != 1 or len(headers[0]) > 8192
                or not hmac.compare_digest(headers[0].encode("utf-8"),
                                           ("Bearer " + expected).encode("utf-8"))):
            self.failure("unauthorized", 401)
            return False
        if self.headers.get("Origin") is not None:
            self.failure("browser_access_unsupported", 403)
            return False
        return True

    def read_body(self):
        if self.headers.get("Transfer-Encoding") is not None:
            raise GatewayFailure("unsupported_transfer_encoding")
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            raise GatewayFailure("missing_body_length", 411)
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,9}", lengths[0]):
            raise GatewayFailure("invalid_body_length")
        size = int(lengths[0])
        if size > MAX_BODY:
            raise GatewayFailure("body_too_large", 413)
        try:
            raw = self.rfile.read(size)
        except (TimeoutError, OSError):
            raise GatewayFailure("body_timeout", 408) from None
        if len(raw) != size:
            raise GatewayFailure("incomplete_body")
        return raw

    def sse(self, event, data):
        self.wfile.write(("event: " + event + "\ndata: "
                          + json.dumps(data) + "\n\n").encode("utf-8"))
        self.wfile.flush()

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in ("/health", "/v1/health"):
            self.send_json(200, {
                "ok": True, "mode": "standalone-single-owner",
                "managed_project_access": False,
            })
            return
        if not self.authenticated():
            return
        if path in ("/capabilities", "/v1/capabilities"):
            self.send_json(200, capabilities())
            return
        if path == "/v1/models":
            self.send_json(200, {"object": "list", "data": [
                {"id": name, "object": "model", "owned_by": "bedrock"}
                for name in STATE["allowed_models"]]})
            return
        self.failure("not_found", 404)

    def do_POST(self):
        # Closing after this request also prevents rejected or unread bodies from
        # becoming a second request on a persistent connection.
        self.close_connection = True
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path not in ("/v1/responses", "/responses"):
            self.failure("unsupported_path", 404)
            return
        if not self.authenticated():
            return
        try:
            content_types = self.headers.get_all("Content-Type", [])
            content_type = content_types[0].split(";", 1)[0].strip().lower() if len(content_types) == 1 else ""
            if content_type != "application/json" or self.headers.get("Content-Encoding") is not None:
                raise GatewayFailure("unsupported_content_type", 415)
            body = _json(self.read_body())
            validate_request(body)
            chat = build_chat_request(body)
        except GatewayFailure as err:
            self.failure(err.code, err.status)
            return

        log_event("responses_request", {
            "stream": bool(body.get("stream")),
            "message_count": len(chat["messages"]), "tool_count": len(chat.get("tools", [])),
        })
        stream = bool(body.get("stream"))
        if not os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):
            self.failure("provider_credential_not_configured", 503)
            return
        upstream = None
        try:
            upstream = call_bedrock(chat, stream)
            if stream:
                self.relay_stream(upstream, chat["model"])
            else:
                self.relay_once(upstream, chat["model"])
        except urllib.error.HTTPError as err:
            log_event("upstream_http_error", {"code": err.code})
            err.close()
            self.failure("upstream_http_error", 502, dispatched=True)
        except Exception as err:
            code, status = _upstream_failure(err)
            log_event("upstream_timeout" if status == 504 else "upstream_error", {})
            self.failure(code, status, dispatched=True)
        finally:
            if upstream is not None:
                upstream.close()

    def relay_once(self, upstream, model):
        try:
            raw = b"".join(_read_chunks(upstream))
            data, choices = _upstream_object(raw)
            if not choices:
                raise GatewayFailure("invalid_upstream", 502)
            message = choices[0].get("message")
            if not isinstance(message, dict) or (message.get("content") is not None
                                                  and not isinstance(message["content"], str)):
                raise GatewayFailure("invalid_upstream", 502)
            calls = _tool_calls(message.get("tool_calls"))
            finish = _finish_reason(choices[0].get("finish_reason"))
            if data.get("id") is not None and not isinstance(data["id"], str):
                raise GatewayFailure("invalid_upstream", 502)
        except Exception as err:
            code, status = _upstream_failure(err)
            log_event("upstream_timeout" if status == 504 else "upstream_error", {})
            self.failure(code, status, dispatched=True)
            return
        reasoning = ReasoningFilter()
        text = reasoning.feed(message.get("content") or "") + reasoning.flush()
        status = "incomplete" if finish in ("length", "content_filter") else "completed"
        if status == "incomplete":
            # A truncated function argument is not an executable tool result.
            calls = []
        response = make_response_object(
            data.get("id") or "resp_gw", model, text,
            calls, data.get("usage"), status)
        if status == "incomplete":
            response["incomplete_details"] = {"reason": "max_output_tokens" if finish == "length" else "content_filter"}
        self.send_json(200, _provenance(response, data.get("usage"), status))

    def relay_stream(self, upstream, model):
        """Translate an upstream Chat Completions SSE stream into Responses events.

        codex reads the deltas to render live output and `response.completed` to finish
        the turn, so the terminating event matters as much as the text.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()

        response_id = "resp_gw_" + str(int(time.time() * 1000))
        item_id = response_id + "-msg"
        reasoning = ReasoningFilter()
        started = False
        pieces = []
        calls = {}
        usage = None
        finish = None
        completed = False

        try:
            self.sse("response.created", {
                "type": "response.created",
                "response": make_response_object(response_id, model, "", [], None,
                                                 "in_progress")})
        except OSError:
            log_event("client_disconnected", {})
            log_event("upstream_outcome_unknown", {})
            return

        def emit(text):
            nonlocal started
            if not text:
                return
            if not started:
                self.sse("response.output_item.added", {
                    "type": "response.output_item.added",
                    "output_index": 0,
                    "item": {"type": "message", "id": item_id, "role": "assistant",
                             "status": "in_progress", "content": []}})
                started = True
            pieces.append(text)
            self.sse("response.output_text.delta", {
                "type": "response.output_text.delta",
                "item_id": item_id, "output_index": 0, "content_index": 0,
                "delta": text})

        try:
            for raw in _stream_lines(upstream):
                try:
                    line = raw.decode("utf-8").strip()
                except UnicodeError:
                    raise GatewayFailure("invalid_upstream_json", 502) from None
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    completed = True
                    break
                chunk, choices = _upstream_object(payload)
                if chunk.get("usage"):
                    usage = chunk["usage"]
                if not choices:
                    continue
                finish = _finish_reason(choices[0].get("finish_reason")) or finish
                delta = choices[0].get("delta")
                if delta is None:
                    delta = {}
                if not isinstance(delta, dict) or (delta.get("content") is not None
                                                  and not isinstance(delta["content"], str)):
                    raise GatewayFailure("invalid_upstream", 502)
                if delta.get("content"):
                    emit(reasoning.feed(delta["content"]))
                for call in _tool_calls(delta.get("tool_calls"), streamed=True):
                    index = call.get("index") or 0
                    slot = calls.setdefault(index, {"id": None, "name": "",
                                                    "arguments": ""})
                    if call.get("id"):
                        slot["id"] = call["id"]
                    function = call.get("function") or {}
                    if function.get("name"):
                        slot["name"] = function["name"]
                    if function.get("arguments"):
                        # Arguments arrive as a JSON string in fragments.
                        slot["arguments"] += function["arguments"]

            if not completed:
                raise GatewayFailure("upstream_incomplete", 502)
            if finish in ("length", "content_filter"):
                calls.clear()
            emit(reasoning.flush())
            text = "".join(pieces)

            if started:
                self.sse("response.output_text.done", {
                    "type": "response.output_text.done",
                    "item_id": item_id, "output_index": 0, "content_index": 0,
                    "text": text})
                self.sse("response.output_item.done", {
                    "type": "response.output_item.done",
                    "output_index": 0,
                    "item": {"type": "message", "id": item_id, "role": "assistant",
                             "status": "completed",
                             "content": [{"type": "output_text", "text": text,
                                          "annotations": []}]}})

            tool_calls = []
            for offset, index in enumerate(sorted(calls)):
                slot = calls[index]
                call_id = slot["id"] or "call_" + str(offset)
                # Raw, NOT defaulted to "{}" here. The streamed item events carry
                # exactly what arrived; only the final response object substitutes a
                # default, via make_response_object.
                arguments = slot["arguments"]
                tool_calls.append({
                    "id": call_id,
                    "type": "function",
                    "function": {"name": slot["name"], "arguments": arguments},
                })
                # output_index is offset + 1 even when no message was produced:
                # index 0 belongs to the assistant message whether or not one exists,
                # so a tool call never takes it.
                item = {"type": "function_call",
                        "id": response_id + "-fc" + str(offset),
                        "call_id": call_id,
                        "name": slot["name"],
                        "arguments": arguments,
                        "status": "in_progress"}
                self.sse("response.output_item.added", {
                    "type": "response.output_item.added",
                    "output_index": offset + 1,
                    "item": item})
                self.sse("response.output_item.done", {
                    "type": "response.output_item.done",
                    "output_index": offset + 1,
                    "item": dict(item, status="completed")})

            status = "incomplete" if finish in ("length", "content_filter") else "completed"
            final = _provenance(make_response_object(response_id, model, text, tool_calls,
                                                     usage, status), usage, status)
            if status == "incomplete":
                final["incomplete_details"] = {"reason": "max_output_tokens" if finish == "length" else "content_filter"}
            event = "response." + status
            self.sse(event, {"type": event, "response": final})
            log_event("stream_done", {"chars": len(text),
                                      "tool_calls": len(tool_calls),
                                      "usage": usage})
        except (BrokenPipeError, ConnectionResetError):
            log_event("client_disconnected", {})
            log_event("upstream_outcome_unknown", {})
        except Exception as err:
            code, status = _upstream_failure(err)
            log_event("upstream_timeout" if status == 504 else "stream_error", {})
            try:
                failure = _provenance(make_response_object(response_id, model, "", [],
                                                          usage, "failed"), usage, "unknown")
                failure["error"] = {"code": code, "message": code.replace("_", " "),
                                    "upstream_outcome": "unknown", "retryable": False}
                self.sse("response.failed", {
                    "type": "response.failed", "response": failure, "error": failure["error"]})
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="Responses API -> Bedrock Chat gateway.")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-west-2"))
    parser.add_argument("--model", default=MODEL_DEFAULT,
                        help="fallback when a request names no model")
    parser.add_argument("--allow-model", action="append", default=[],
                        help="allow this additional model ID; this does not qualify the model")
    parser.add_argument("--log", help="append request/response SHAPES as JSON lines")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", args.region):
        parser.error("region must be an AWS region ID")
    models = tuple(dict.fromkeys([args.model, *args.allow_model]))
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}", model) for model in models):
        parser.error("model IDs must contain only letters, numbers, colon, dot, underscore, slash or hyphen")
    token = os.environ.get("AGENTMUX_BEDROCK_GATEWAY_TOKEN", "")
    if not _valid_local_token(token):
        parser.error("set a separate AGENTMUX_BEDROCK_GATEWAY_TOKEN of 32–4096 printable ASCII characters without spaces")

    STATE.update(region=args.region, log=args.log, verbose=args.verbose,
                 model_default=args.model, allowed_models=models)

    if not os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):
        print("warning: AWS_BEARER_TOKEN_BEDROCK is not set; requests will fail "
              "with 503", file=sys.stderr)

    # 127.0.0.1 and nothing else. See SECURITY POSTURE above.
    server = GatewayServer(("127.0.0.1", args.port), Gateway)
    print("bedrock gateway on http://127.0.0.1:" + str(args.port) + "/v1  ->  "
          + bedrock_url(), file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
