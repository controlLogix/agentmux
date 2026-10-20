#!/usr/bin/env python3
"""Verify the Responses-to-Chat-Completions translation in the Bedrock gateway.

    python3 dashboard/test_gateway.py     # no network, no key, no server

NO LIVE BEDROCK CALL IS MADE and no credential is needed. Everything asserted here
is pure translation: request shaping, tool flattening, the reasoning filter and the
response object codex reads back. `call_bedrock` and the HTTP handler are the only
parts that touch the network, and they are not exercised.

WHY THIS FILE LOOKS UNUSUAL
---------------------------
Both this suite and `taskmgmt/bedrock_gateway.py` were **lost**. Neither was ever
committed, and both were most likely deleted with the two Bedrock setup scripts during
the 2026-09-20 credential purge - a different class of file, since those existed to copy
a key out of another tool's settings and the gateway holds no credential.

All that survived was the bytecode, compiled from a 27,384-byte source on 2026-09-19.
Because its magic matched CPython 3.12 it still imported, which made two things possible
on 2026-09-22: this suite was rebuilt against it, and then **the source itself was
reconstructed** from its docstrings, constants and control flow.

So there are now two implementations, and the last section below runs them side by side
on identical inputs. That is a far stronger check than assertions written from a reading
of the docs: not "does the rewrite satisfy my idea of the spec" but "does it behave like
the thing that actually worked against live Bedrock". It found four real divergences,
three of which no reasonable hand-written test would have guessed.

The comparison is perishable. When CPython can no longer load the 2026-09-19 bytecode
that section skips itself, and the explicit assertions above remain as the specification -
including a named check for each of the three bugs fixed on 2026-09-20, so a future
change cannot quietly reintroduce them.

The preserved bytecode lives in `taskmgmt/recovered/`, deliberately outside
`__pycache__`: that directory is gitignored, and importing the reconstructed source
overwrites the cache entry - which is exactly what happened the first time the rewrite
was imported. Had it not been copied out first, writing the replacement would have
destroyed the only thing available to verify it against.
"""

import importlib.machinery
import importlib.util
import io
import json
import random
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "taskmgmt" / "bedrock_gateway.py"
# The cache entry is the live one, but __pycache__/ and *.py[cod] are both gitignored,
# so it was the ONLY copy of a lost file and untracked - one `git clean -xdf` from
# gone. The preserved copy under recovered/ is the tracked fallback.
CACHED = REPO / "taskmgmt" / "__pycache__" / "bedrock_gateway.cpython-312.pyc"
PRESERVED = REPO / "taskmgmt" / "recovered" / "bedrock_gateway.cpython-312.pyc.bin"
passed = failed = 0


def check(label, expected, actual):
    global passed, failed
    if expected == actual:
        print(f"  ok    {label:<52} {str(actual)[:60]!r}")
        passed += 1
    else:
        print(f"  FAIL  {label:<52} got {actual!r} want {expected!r}")
        failed += 1


def load_gateway():
    """Prefer real source; fall back to the surviving bytecode."""
    if SOURCE.is_file():
        spec = importlib.util.spec_from_file_location("bedrock_gateway", SOURCE)
        origin = f"source ({SOURCE.name})"
    else:
        blob = CACHED if CACHED.is_file() else PRESERVED
        if not blob.is_file():
            print("  FAIL  no gateway found: no source, no cache entry, no preserved copy")
            print("        see taskmgmt/recovered/README.md - this file was the last copy")
            print()
            print("passed 0, failed 1")
            sys.exit(1)
        loader = importlib.machinery.SourcelessFileLoader("bedrock_gateway", str(blob))
        spec = importlib.util.spec_from_file_location("bedrock_gateway", str(blob),
                                                      loader=loader)
        origin = f"BYTECODE ONLY ({blob.name}) - source is missing"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, origin


print("--- loading ---")
gw, origin = load_gateway()
print(f"        loaded from {origin}")
check("module imports", True, hasattr(gw, "to_chat_messages"))
if not SOURCE.is_file():
    print("        NOTE: running against bytecode. A CPython upgrade will break this.")


# ── security posture ─────────────────────────────────────────────────────────
# Asserted against the code object rather than by binding a socket: the point is
# that the literal is in the source, not that one particular run happened to bind
# loopback. A gateway holding a cloud credential must never listen on a routable
# address.

def constants_of(function):
    """Every string constant reachable from a function, nested code included."""
    found = set()
    stack = [function.__code__]
    while stack:
        code = stack.pop()
        for const in code.co_consts:
            if isinstance(const, str):
                found.add(const)
            elif hasattr(const, "co_consts"):
                stack.append(const)
    return found


print("--- security posture ---")
main_constants = constants_of(gw.main)
check("binds loopback only", True, "127.0.0.1" in main_constants)
check("never binds all interfaces", False,
      any(host in main_constants for host in ("0.0.0.0", "::", "")) and "0.0.0.0" in main_constants)
check("request bodies are capped", True, isinstance(gw.MAX_BODY, int) and gw.MAX_BODY > 0)
check("upstream timeout is bounded", True,
      isinstance(gw.UPSTREAM_TIMEOUT, int) and 0 < gw.UPSTREAM_TIMEOUT <= 3600)
check("credential comes from the environment", True,
      any("AWS_BEARER_TOKEN_BEDROCK" in c for c in constants_of(gw.call_bedrock)))
# A literal key would be a 100+ character opaque string sitting in a constant.
suspicious = [c for c in constants_of(gw.call_bedrock) | constants_of(gw.main)
              if len(c) > 80 and " " not in c and "\n" not in c]
check("no long opaque literal in the credential path", [], suspicious)


# ── content flattening ───────────────────────────────────────────────────────

print("--- text_from_content ---")
check("a bare string passes through", "plain", gw.text_from_content("plain"))
check("input_text and output_text concatenate", "ab", gw.text_from_content(
    [{"type": "input_text", "text": "a"}, {"type": "output_text", "text": "b"}]))
check("an unknown part contributes nothing", "", gw.text_from_content([{"type": "weird"}]))
check("empty content is empty text", "", gw.text_from_content([]))


# ── request translation ──────────────────────────────────────────────────────

print("--- to_chat_messages ---")
messages = gw.to_chat_messages({
    "instructions": "be terse",
    "input": [
        "bare string",
        {"type": "message", "role": "user",
         "content": [{"type": "input_text", "text": "hello"}]},
        {"type": "function_call", "name": "read", "arguments": '{"p":1}', "call_id": "c1"},
        {"type": "function_call_output", "call_id": "c1", "output": "365"},
        {"type": "no_such_kind", "x": 1},
    ]})
roles = [m["role"] for m in messages]
check("instructions become the system message", "system", messages[0]["role"])
check("instructions text is carried", "be terse", messages[0]["content"])
check("every item kind is mapped", ["system", "user", "user", "assistant", "tool"], roles)
check("an unrecognised item is skipped, not guessed", 5, len(messages))
check("a bare string becomes a user turn", "bare string", messages[1]["content"])
check("a message item is flattened to text", "hello", messages[2]["content"])

call = messages[3]
check("a function_call becomes an assistant tool_call", None, call["content"])
check("tool_call carries the call id", "c1", call["tool_calls"][0]["id"])
check("tool_call is typed as a function", "function", call["tool_calls"][0]["type"])
check("tool name survives verbatim", "read", call["tool_calls"][0]["function"]["name"])
check("arguments are passed as a string", '{"p":1}',
      call["tool_calls"][0]["function"]["arguments"])
check("function_call_output becomes a tool message", "tool", messages[4]["role"])
check("the tool result is linked by call id", "c1", messages[4]["tool_call_id"])
check("the tool result body is carried", "365", messages[4]["content"])
check("no instructions means no system message", "user",
      gw.to_chat_messages({"input": "hi"})[0]["role"])


# ── tools: the bug that left the agent with none ─────────────────────────────

print("--- to_chat_tools (bug 27: namespace groups must be flattened) ---")
tools = gw.to_chat_tools({"tools": [
    {"type": "function", "name": "shell", "description": "run",
     "parameters": {"type": "object"}},
    {"type": "namespace", "name": "multi_agent_v1", "description": "group", "tools": [
        {"type": "function", "name": "spawn", "description": "s", "parameters": {}},
        {"type": "function", "name": "close", "description": "c", "parameters": {}},
    ]},
    {"type": "web_search"},
]})
names = [t["function"]["name"] for t in tools]
check("a namespace is flattened, not dropped", ["shell", "spawn", "close"], names)
check("inner names are kept verbatim", True, "spawn" in names and "multi_agent_v1" not in names)
check("every tool is nested under 'function'", True,
      all(t["type"] == "function" and "function" in t for t in tools))
check("description survives", "run", tools[0]["function"]["description"])
check("parameters survive", {"type": "object"}, tools[0]["function"]["parameters"])
check("a server-hosted tool is dropped", False, any("web_search" in n for n in names))
check("no tools in means no tools out", [], gw.to_chat_tools({}))
deep = gw.to_chat_tools({"tools": [
    {"type": "namespace", "name": "outer", "tools": [
        {"type": "namespace", "name": "inner", "tools": [
            {"type": "function", "name": "buried", "parameters": {}}]}]}]})
check("a nested namespace is still reached", ["buried"],
      [t["function"]["name"] for t in deep])


# ── the reasoning filter: two bugs that ate the answer ───────────────────────

print("--- ReasoningFilter (bugs 28 and 29: the answer must never be lost) ---")
f = gw.ReasoningFilter()
emitted = f.feed("MODEL OK")
check("a short reply is not emitted early", "", emitted)
check("bug 28: a short reply survives to flush", "MODEL OK", f.flush())

f = gw.ReasoningFilter()
f.feed("<reasoning>thinking out loud</reasoning>")
f.feed("the answer")
check("a closed reasoning span is stripped", "the answer", f.flush())

f = gw.ReasoningFilter()
f.feed("<reasoning>never closed, and the answer is in here")
check("bug 29: an unterminated span is released, not swallowed",
      "never closed, and the answer is in here", f.flush())

f = gw.ReasoningFilter()
f.feed("<reas")
f.feed("oning>x</reasoning>done")
check("a tag split across deltas is still matched", "done", f.flush())

f = gw.ReasoningFilter()
body = "y" * 400
streamed = f.feed(body)
check("long output does emit incrementally", True, len(streamed) > 0)
check("and loses nothing overall", body, streamed + f.flush())

f = gw.ReasoningFilter()
check("plain text with no tags is untouched", "just text", f.feed("just text") + f.flush())


# ── the objects codex reads back ─────────────────────────────────────────────

print("--- build_chat_request ---")
chat = gw.build_chat_request({"model": "openai.gpt-oss-120b-1:0", "input": "hi",
                              "stream": True, "max_output_tokens": 50})
check("model passes through", "openai.gpt-oss-120b-1:0", chat["model"])
check("stream passes through", True, chat["stream"])
check("messages are built", "hi", chat["messages"][-1]["content"])
check("no tools key when none were sent", False, bool(chat.get("tools")))

print("--- make_response_object ---")
obj = gw.make_response_object("resp_1", "m", "hi", [],
                              {"prompt_tokens": 1, "completion_tokens": 2}, "completed")
check("object is a Responses object", "response", obj["object"])
check("id is echoed", "resp_1", obj["id"])
check("status is carried", "completed", obj["status"])
check("text lands in output content", "hi", obj["output"][0]["content"][0]["text"])
check("output is typed for codex", "output_text", obj["output"][0]["content"][0]["type"])
check("prompt tokens map to input_tokens", 1, obj["usage"]["input_tokens"])
check("completion tokens map to output_tokens", 2, obj["usage"]["output_tokens"])
check("totals are summed", 3, obj["usage"]["total_tokens"])

print("--- bedrock_url ---")
gw.STATE["region"] = "us-west-2"
check("url is built from the configured region", True,
      "us-west-2" in gw.bedrock_url())
check("url targets chat completions, not responses", True,
      gw.bedrock_url().endswith("/openai/v1/chat/completions"))
gw.STATE["region"] = "eu-central-1"
check("region is not hardcoded", True, "eu-central-1" in gw.bedrock_url())
gw.STATE["region"] = "us-west-2"


# ── differential against the original bytecode ───────────────────────────────
#
# The strongest check available, and a perishable one. While the 2026-09-19 bytecode
# still loads, the reconstructed source can be run against it on identical inputs and
# compared - not "does the rewrite satisfy my idea of the spec" but "does it behave
# like the thing that actually worked against live Bedrock". Four real divergences
# were found and fixed this way, three of which no reasonable test would have guessed:
# empty string items must NOT be filtered out of `input`, an empty `message` must be
# dropped, tool-call item events carry raw `arguments` rather than a "{}" default, and
# each tool call emits output_item.added before .done.
#
# When CPython can no longer load the bytecode this section skips itself and the rest
# of the suite carries on as an ordinary specification.

print("--- differential against the original bytecode ---")

original = None
if SOURCE.is_file() and PRESERVED.is_file():
    try:
        loader = importlib.machinery.SourcelessFileLoader("gw_original", str(PRESERVED))
        spec = importlib.util.spec_from_file_location("gw_original", str(PRESERVED),
                                                      loader=loader)
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
    except Exception as err:                       # a newer CPython refuses the magic
        # module_from_spec already bound an EMPTY module; left in place, every differ()
        # below compared the source against nothing and failed on AttributeError.
        original = None
        print(f"        skipped: cannot load the 2026-09-19 bytecode ({err})")
        print(f"        it needs CPython 3.12; this is {sys.version.split()[0]}. "
              "Run this file under python3.12 for the differential.")
        print("        the checks above still stand as a specification.")
else:
    print("        skipped: nothing to compare against "
          f"({'no source' if not SOURCE.is_file() else 'no preserved bytecode'})")

if original is not None:
    # Compare translations under the same configured model. The standalone
    # listener now has its documented fallback before main() is invoked too.
    original.STATE["model_default"] = gw.STATE["model_default"]

print("        HTTP safety changes and malformed upstream replies are checked in test_gateway_boundary.py")
print("        relay comparisons omit only the new agentmux usage/outcome metadata")


def differ(label, call, cases):
    """One check per family; the count of compared cases is the interesting part."""
    if original is None:
        return
    bad = []
    for case in cases:
        try:
            a = call(original, case)
        except Exception as err:
            a = f"<{type(err).__name__}>"
        try:
            b = call(gw, case)
        except Exception as err:
            b = f"<{type(err).__name__}>"
        if a != b:
            bad.append((case, a, b))
    if bad:
        print(f"        first divergence: {str(bad[0])[:200]}")
    check(f"{label} ({len(cases)} cases)", 0, len(bad))


FN_SPEC = {"type": "function", "name": "shell", "description": "run",
           "parameters": {"type": "object"}}

differ("text_from_content matches", lambda m, c: m.text_from_content(c), [
    "plain", "", None, [], ["notadict"], [{"type": "input_text", "text": "a"}],
    [{"refusal": "no"}], [{"text": None}], [{"text": "a", "refusal": "b"}]])

differ("to_chat_messages matches", lambda m, b: m.to_chat_messages(b), [
    {"input": "hi"}, {"input": ""}, {"input": "   "}, {"input": None},
    {"input": 7}, {"input": {"weird": 1}}, {"input": ["a", "", "   "]},
    {"instructions": "be terse", "input": "hi"}, {"instructions": "  ", "input": "hi"},
    {"input": [{"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "h"}]}]},
    {"input": [{"type": "message", "role": "assistant", "content": []}]},
    {"input": [{"type": "function_call", "name": "read", "arguments": '{"p":1}',
                "call_id": "c1"}]},
    {"input": [{"type": "function_call"}]},
    {"input": [{"type": "function_call_output", "call_id": "c1", "output": "365"}]},
    {"input": [{"type": "function_call_output"}]},
    {"input": [{"type": "reasoning"}, {"type": "item_reference"}]},
    {"input": [{"type": "mystery", "a": 1}]}, {"input": [{"no_type": 1}]},
    {"input": [12345]}])

differ("to_chat_tools matches", lambda m, b: m.to_chat_tools(b), [
    {"tools": t} for t in [
        [], None, [FN_SPEC], [FN_SPEC, FN_SPEC], [{"type": "function"}],
        [{"type": "function", "name": ""}], [{"type": "web_search"}], ["notadict"],
        [None], [{"type": "namespace", "name": "ns", "tools": [FN_SPEC]}],
        [{"type": "namespace", "name": "ns"}],
        [{"type": "namespace", "name": "a", "tools": [
            {"type": "namespace", "name": "b", "tools": [
                {"type": "namespace", "name": "c", "tools": [
                    {"type": "namespace", "name": "d", "tools": [
                        {"type": "function", "name": "deep", "parameters": {}}]}]}]}]}]]])

differ("build_chat_request matches", lambda m, b: m.build_chat_request(b), [
    {"input": "hi"}, {"model": "m", "input": "hi", "stream": True},
    {"input": "hi", "max_output_tokens": 50, "temperature": 0.5, "top_p": 0.9},
    {"input": "hi", "max_output_tokens": 0}, {"input": "hi", "tools": [FN_SPEC],
                                              "tool_choice": "required"},
    {"input": "hi", "tools": [FN_SPEC], "tool_choice": "bogus"},
    {"input": "hi", "tool_choice": "auto"}])


def response_without_clock(module, case):
    obj = module.make_response_object(*case)
    obj.pop("created_at", None)
    return obj


differ("make_response_object matches", response_without_clock, [
    ("r", "m", text, calls, usage, status)
    for text in ("", "hi")
    for calls in (None, [], [{"id": "c1", "function": {"name": "f",
                                                       "arguments": "{}"}}],
                  [{"function": {"name": "f"}}], [{}])
    for usage in (None, {}, {"prompt_tokens": 1, "completion_tokens": 2},
                  {"completion_tokens": 7})
    for status in ("completed", "failed")])

# The reasoning filter was the one piece inferred rather than read directly, so it is
# fuzzed: random chunk sequences, plus every possible split point of each corpus
# string - which is exactly where a hold-back bug hides.
CORPUS = ["MODEL OK", "y" * 60, "<reasoning>t</reasoning>answer",
          "<reasoning>unclosed answer here", "a<reasoning>b</reasoning>c",
          "</reasoning>orphan", "<reasoning></reasoning>", "partial <reason",
          "<reasoning>nested <reasoning> in </reasoning> out"]
SPLITS = [(text, cut) for text in CORPUS for cut in range(len(text) + 1)]


def filter_split(module, case):
    text, cut = case
    handler = module.ReasoningFilter()
    first = handler.feed(text[:cut])
    second = handler.feed(text[cut:])
    return first, second, handler.flush()


differ("ReasoningFilter matches at every split", filter_split, SPLITS)

random.seed(20260922)
ALPHABET = ["a", " ", "<reasoning>", "</reasoning>", "<reas", "oning>", "<", ">",
            "/reasoning", "x" * 20]
FUZZ = [tuple(random.choice(ALPHABET) for _ in range(random.randint(1, 8)))
        for _ in range(400)]


def filter_fuzz(module, chunks):
    handler = module.ReasoningFilter()
    return [handler.feed(c) for c in chunks], handler.flush()


differ("ReasoningFilter matches under fuzz", filter_fuzz, FUZZ)


# The relay paths, driven through a fake socket. No network, no upstream.
class _WFile:
    def __init__(self):
        self.chunks = []

    def write(self, raw):
        self.chunks.append(raw)

    def flush(self):
        pass


class _Upstream:
    def __init__(self, lines):
        self._lines = lines
        self._body = io.BytesIO(b"".join(lines))

    def __iter__(self):
        return iter(self._lines)

    def read(self):
        return b"".join(self._lines)

    def read1(self, size):
        return self._body.read1(size)


_VOLATILE = re.compile(r'(resp_gw_\d+|"created_at": \d+)')


def _drive(module, case):
    mode, payload = case
    handler = module.Gateway.__new__(module.Gateway)
    handler.wfile = _WFile()
    handler.sent = []
    handler.close_connection = False
    handler.send_response = lambda *a: None
    handler.send_header = lambda *a: None
    handler.end_headers = lambda: None
    handler.send_json = lambda code, obj: handler.sent.append((code, obj))
    if mode == "once":
        handler.relay_once(_Upstream([json.dumps(payload).encode()]), "model-x")
    else:
        lines = [b"data: " + json.dumps(c).encode() + b"\n" for c in payload]
        lines.append(b"data: [DONE]\n")
        handler.relay_stream(_Upstream(lines), "model-x")
    for entry in handler.sent:
        entry[1].pop("created_at", None) if isinstance(entry[1], dict) else None
        if isinstance(entry[1], dict) and entry[1].get("object") == "response":
            entry[1].pop("agentmux", None)
    body = b"".join(handler.wfile.chunks).decode("utf-8", "replace")
    lines = []
    for line in body.splitlines(keepends=True):
        if line.startswith("data: "):
            event = json.loads(line[6:])
            if isinstance(event.get("response"), dict):
                event["response"].pop("agentmux", None)
            line = "data: " + json.dumps(event) + "\n"
        lines.append(line)
    body = "".join(lines)
    return _VOLATILE.sub("X", json.dumps(handler.sent, default=str) + body)


def _delta(content=None, tool_calls=None, usage=None):
    chunk = {"choices": [{"delta": {}}]}
    if content is not None:
        chunk["choices"][0]["delta"]["content"] = content
    if tool_calls is not None:
        chunk["choices"][0]["delta"]["tool_calls"] = tool_calls
    if usage is not None:
        chunk["usage"] = usage
    return chunk


differ("relay_once matches", _drive, [
    ("once", p) for p in [
        {"id": "x1", "choices": [{"message": {"content": "hello"}}],
         "usage": {"prompt_tokens": 3, "completion_tokens": 4}},
        {"choices": [{"message": {"content": ""}}]},
        {"choices": [{"message": {"content": "<reasoning>t</reasoning>a"}}]},
        {"choices": [{"message": {"content": "<reasoning>unclosed"}}]},
        {"choices": [{"message": {"content": None, "tool_calls": [
            {"id": "c1", "function": {"name": "f", "arguments": "{}"}}]}}]}]])

differ("relay_stream matches", _drive, [
    ("stream", s) for s in [
        [_delta("hello "), _delta("world")], [_delta("MODEL OK")],
        [_delta("<reasoning>"), _delta("think"), _delta("</reasoning>"), _delta("a")],
        [_delta("<reasoning>never closed")], [_delta("a" * 300), _delta("b" * 300)],
        [_delta(""), _delta(None)], [],
        [_delta(usage={"prompt_tokens": 1, "completion_tokens": 2})],
        [_delta(tool_calls=[{"index": 0, "id": "c1",
                             "function": {"name": "shell", "arguments": '{"a'}}]),
         _delta(tool_calls=[{"index": 0, "function": {"arguments": '":1}'}}])],
        [_delta(tool_calls=[{"index": 0, "id": "c1", "function": {"name": "a"}}]),
         _delta(tool_calls=[{"index": 1, "id": "c2", "function": {"name": "b"}}])],
        [_delta("text"), _delta(tool_calls=[{"index": 0, "id": "c1",
                                             "function": {"name": "f",
                                                          "arguments": "{}"}}])],
        [_delta(tool_calls=[{"function": {"name": "noindex"}}])],
        [{"choices": [{"delta": {}}]}], [{"choices": []}], [{"no_choices": True}]]])

print()
print(f"passed {passed}, failed {failed}")
sys.exit(1 if failed else 0)
