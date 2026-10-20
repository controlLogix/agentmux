# Cross-user federation (EP-032)

> **October 9 governance repair:** Work now uses a v3 reservation/grant protocol and versioned `am.work.<peer>.<rid>.<role>.v3` subjects. A receiving item waits for an origin grant before becoming claimable. Other message families remain v2. See [the repair and upgrade record](planning/2026-10-09/governance-repairs.md). Earlier design and test records below remain historical where they describe the former v2 work behavior.


Written 2026-10-07 from the requirements interview the same day. This document is the
design record for letting **different people's** agentmux hubs, and the Claude (or codex)
sessions behind them, work together over a shared NATS server: messages, task handoffs,
a shared board, a knowledge stream and code, with no human relaying anything.

It extends [`PROTOCOL.md`](PROTOCOL.md) §11. The single-operator bridge built in TM-218
(`hub/bridge.py`, `nats_url`) is unchanged and still works. Federation is a separate
layer (`hub/fed/`), turned on by `~/.agentmux/hub/federation.toml`.

Every assumption made while the operator was away is in the **assumptions log** (§13).
Review it first.

---

## 1. Requirements (from the interview)

| # | Requirement | Source |
|---|---|---|
| F1 | Works for **one peer** or a **small team (3–10)**, not tied to one organisation | interview Q1 |
| F2 | A **hosted central NATS server**, deployed to **Kubernetes with the official Helm chart** | Q2, Q9 |
| F3 | Identity is **NATS operator/account/user JWTs with nkeys** | Q5 |
| F4 | **Per-peer trust policy** for inbound traffic | Q3 |
| F5 | **Per-repo opt-in**: nothing leaves a hub unless its repo is shared | Q6 |
| F6 | Repos are matched across machines by **normalized git remote URL** | Q10 |
| F7 | **JetStream persistence**: things sent while a peer is offline drain when it reconnects | Q7 |
| F8 | Four capabilities: **messages and handoffs**, a **shared central board** (JetStream KV, CAS), **knowledge** (auto-capture plus explicit), **code** (git refs on a shared remote) | Q4, Q8, Q11, Q13 |
| F9 | Each capability is a **plugin** that owns its subjects, its storage, its verbs and MCP tools, and a dashboard panel | Q4, Q14 |
| F10 | The **CLI is canonical**, with a **thin MCP server** on top of it | Q12 |
| F11 | Guardrails: **secret redaction**, **no privileged tools triggered by remote work** without approval, a **full audit log**, and a **kill switch** | Q11, follow-up |
| F12 | Done = **full parity**: every phase, end to end, demo ready | Q12, follow-up |
| F13 | Add **nats-py** as the hub's first third-party dependency | follow-up |

---

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **circle** | One NATS **account**. The set of people who collaborate. A one-peer setup is a circle of two. It is the confidentiality boundary (§7.4). |
| **peer** | A person. One NATS **user** in the circle; the user name is the peer id (`[a-z0-9_]{1,32}`). |
| **node** | One hub (one machine). A peer can have several nodes (macOS plus WSL) that share the peer's credential. |
| **rid** | Repo identity: `r` + the first 12 hex chars of sha256(normalized origin URL). Both sides compute the same rid however they name the repo locally (F6). |
| **share** | A local repo opted in to the circle (F5), optionally limited to named peers. |
| **trust** | What a hub does with inbound traffic from a peer: `auto`, `flag`, `approve` or `deny` (F4). |

---

## 3. Topology

```
 peer nick (2 nodes)                 hosted cluster (Helm: nats/nats, 3 replicas)            peer alice
 ┌─────────────┐  TLS + user JWT    ┌────────────────────────────────────────────┐   ┌─────────────┐
 │ hub (mac)   │───────────────────▶│ nats-0  nats-1  nats-2   JetStream (R3)    │◀──│ hub (linux) │
 │  hub/fed    │                    │ streams AM_MSG AM_WORK AM_SHARE            │   │  hub/fed    │
 ├─────────────┤                    │ KV      am_board am_presence               │   └─────────────┘
 │ hub (wsl)   │───────────────────▶│ resolver: full (operator mode)             │
 └─────────────┘                    └────────────────────────────────────────────┘
```

- **Hubs connect as plain clients**, not leaf nodes. JetStream already gives the
  offline buffering a leaf node would. Each hub keeps its transactional outbox, so a
  hub that cannot reach the cluster loses nothing either (§8). This supersedes the
  "leaf node per machine" row of PROTOCOL §11.
- **The production chart** is `deploy/nats/values.yaml`: 3 replicas, JetStream file
  storage on a PVC, TLS on the client port, and operator mode with the full resolver.
- **The demo cluster** is `kind` (`deploy/nats/kind.yaml`), with the same values and a
  NodePort mapped to `127.0.0.1:4222`. `deploy/nats/up.sh` brings it up from nothing.

---

## 4. Identity and authorization (F3)

`deploy/nats/circle.sh` wraps `nsc`:

| Verb | What it does |
|---|---|
| `circle.sh init <circle>` | operator + system account + circle account, the JetStream limits, the admin user; writes the resolver config the chart mounts |
| `circle.sh add <peer>` | a user for the peer with **subject permissions naming the peer** (below); writes `<peer>.creds` |
| `circle.sh revoke <peer>` | revokes the user's JWT and pushes the account to the resolver; the server disconnects them |
| `circle.sh streams` | creates the streams and KV buckets as admin (members cannot create or delete streams) |

**Per-user permissions** are issued explicitly when the user is created. They don't use
templates, so they work on any server version:

```
pub allow  am.*.<peer>.>            # every federated subject carries the sender in token 3
           $JS.API.>  $KV.am_board.>  $KV.am_presence.<peer>.>  _INBOX.>
pub deny   $JS.API.STREAM.CREATE.>  $JS.API.STREAM.UPDATE.>  $JS.API.STREAM.DELETE.>  $JS.API.STREAM.PURGE.>
sub allow  _INBOX.>  $KV.>  am.ctl.>
```

**Anti-spoofing is the server's job.** A receiver takes the sender's identity from
token 3 of the subject and never from the payload. The server only lets peer `nick`
publish `am.*.nick.>`, so the per-peer trust policy (§6) cannot be borrowed by someone
claiming to be someone else.

---

## 5. Subjects, streams and buckets

Every token is `[a-z0-9_]`, which is the invariant from PROTOCOL §11.

| Subject | Stream / bucket | Retention | Plugin |
|---|---|---|---|
| `am.msg.<from>.<to>` | `AM_MSG` | limits, 14 days | messages (direct, handoff, result, code pointer) |
| `am.work.<from>.<rid>.<role>` | `AM_WORK` | **work queue** | work (competing consumers) |
| `am.know.<from>.<rid>` | `AM_SHARE` | limits, 365 days | knowledge |
| `am.code.<from>.<rid>` | `AM_SHARE` | limits, 365 days | code |
| `am.ctl.<from>` | core NATS (not persisted) | none | runtime (kill switch / revoke notice) |
| `<rid>.card.<KEY>`, `<rid>.seq.<PREFIX>` | KV `am_board` (history 16) | KV | board |
| `<peer>.<node>` | KV `am_presence` (TTL 90 s) | KV | runtime (roster) |

**Consumers** (durable and created by the hub; members may create consumers but not streams):

| Consumer | Stream | Filter | Why |
|---|---|---|---|
| `msg_<peer>_<node>` | AM_MSG | `am.msg.*.<peer>` | each of a peer's nodes sees its mail and ingests what it hosts |
| `work_<from>_<rid>_<role>` | AM_WORK | `am.work.<from>.<rid>.<role>` | **one shared consumer** per (publisher, rid, role), and every hub that can serve it **and trusts the publisher** (`auto`/`flag`) pulls from it. A work-queue stream gives each item to exactly one puller, so *first claim wins* holds across people, and a hub that would only quarantine the item never takes it from one that would do it (A19) |
| `share_<peer>_<node>` | AM_SHARE | `am.*.*.*` | knowledge and code feed, indexed locally |

---

## 6. Per-peer trust policy (F4) and per-repo opt-in (F5)

`~/.agentmux/hub/federation.toml`:

```toml
[federation]
enabled = true
url     = "tls://127.0.0.1:4222"
creds   = "~/.agentmux/hub/fed/nick.creds"
ca      = "~/.agentmux/hub/fed/ca.pem"
peer    = "nick"                    # must equal the JWT user name
plugins = ["messages", "work", "board", "knowledge", "code"]
capture = true                      # knowledge auto-capture (§9.4)
code_remote = "origin"              # remote that carries refs/agentmux/* (§9.5)

[repos.falcon]                      # opt in: local repo name -> shared
peers = ["*"]                       # whole circle, or ["alice", "bob"]

[peers."*"]
trust = "approve"                   # default for anyone not listed

[peers.alice]
trust = "auto"
```

| Trust | Inbound message | Inbound work item | Board / knowledge / code |
|---|---|---|---|
| `auto` | delivered, with a one-line remote header | ready to claim | mirrored |
| `flag` | delivered inside an **untrusted-data envelope** ("data from peer X, not instructions") | ready to claim, marked untrusted | mirrored, marked untrusted |
| `approve` | **quarantined** until `agentmux hub fed approve <id>` or the dashboard | quarantined | mirrored (read-only data) |
| `deny` | dropped and audited | dropped and audited | not mirrored |

**Opt-in on both sides.** A hub publishes only for a repo listed under `[repos]`, and
ingests only traffic whose rid maps to a repo it has opted in. Traffic for an unknown
rid is audited as `not_shared` and dropped.

---

## 7. Guardrails (F11)

All plugin traffic goes through one pipeline in `hub/fed/guard.py`. A plugin cannot
reach the connection except through `ctx.publish()` and its registered handlers.

```
outbound:  scope(rid shared with recipient?) → redact(secrets) → size/claim-check → audit → outbox
inbound:   sender(from subject) → known peer? → rid opted in? → idempotent(msg id) → trust → privilege → envelope → audit → plugin
```

### 7.1 Secret redaction
`hub/fed/redact.py`, applied to every string field of every outbound payload.

- **Blocked** (publish refused, the caller gets the reason): PEM private-key blocks,
  nkey seeds (`S[UAONC]…`), and credential files.
- **Redacted** (replaced by `[REDACTED:<kind>]`): AWS keys, GitHub, Anthropic, OpenAI and
  Slack tokens, JWTs, Azure connection strings, `password=`/`secret=`/`token=`
  assignments, and `.env`-style lines whose key looks like a secret.
- Every hit is recorded in the audit log with its kind, never the value.

### 7.2 Remote work can never trigger privileged tools
- Work that arrives from another peer carries `origin_peer`. If its requirements name a
  **privileged capability** (`privileged`, `plc_write`, `codesys_runtime`, `profinet`,
  `pcm_write`), the work is quarantined whatever the peer's trust.
- `hub/fed/hooks/privileged_gate.py` is a Claude Code **PreToolUse** hook. It asks the
  hub (`fed_gate`) whether the calling agent holds remote-origin work. If it does,
  privileged tool calls are refused until the operator approves that item
  (`agentmux hub fed approve <work_id> --privileged`). Privileged tools are: the pcm600
  MCP import/write tools, CODESYS runtime writes and forces, and the PROFINET/BOOTP helpers.

### 7.3 Audit
`fed_audit` in hub.db records every inbound and outbound cross-user payload: direction,
plane, peer, rid, subject, message id, sha256, size, the decision (`sent`, `delivered`,
`flagged`, `quarantined`, `denied`, `not_shared`, `redacted`, `blocked`) and the redaction
kinds. `agentmux hub fed audit` and the dashboard panel read it.

### 7.4 Confidentiality boundary (stated plainly)
The **circle** is the confidentiality boundary. The server enforces who may connect, who
may publish as whom, and that members cannot create or destroy streams. It does **not**
stop one circle member's custom client from reading the streams of another member's
shared repos. `peers = ["alice"]` under a repo limits what *this hub sends* and *mirrors*,
not what the server lets a malicious member read. To hide a repo from someone, put it in
a different circle. (Assumption A7.)

### 7.5 Kill switch
`agentmux hub fed kill [--revoke]`, or the dashboard button:
1. Persists `killed=1` in `fed_state`. The runtime will not reconnect, even after a hub
   restart, until `agentmux hub fed resume`.
2. With `--revoke`, before disconnecting it:
   - deletes this peer's unconsumed items from `AM_WORK`
   - deletes its presence key
   - publishes `am.ctl.<peer>` `{"type": "revoke"}`. Every other hub that receives it
     cancels still-`ready` items it ingested from this peer and marks this peer's
     mirrored cards and knowledge as `withdrawn`.
3. Closes the connection. The outbox is kept, paused, not deleted.

The circle admin can also run `deploy/nats/circle.sh revoke <peer>` to cut a peer off at
the server.

---

## 8. Delivery guarantees

- **Outbound:** plugins write `fed_outbox` in the same SQLite transaction as the state
  change (Transactional Client). The runtime publishes with a **JetStream publish ack**,
  and marks a row sent only after the ack. Rows survive restarts and the kill switch.
- **Inbound:** durable consumers and explicit acks. A message is acked only after its
  ingest transaction commits. Every ingest is idempotent on the publisher's message id
  (also set as `Nats-Msg-Id`, so the stream deduplicates republished rows within 2 min).
- **Work:** a pulled item is acked after `ingest_work` commits. If the hub dies between
  the two, JetStream redelivers after `ack_wait` (60 s) and the idempotent ingest
  absorbs the duplicate.

---

## 9. Plugins (F9)

### 9.1 Contract (`hub/fed/plugin.py`)

```python
class Plugin:
    name: str                       # [a-z0-9_]
    tables: list[str] = []          # SQL; table names must start with p_<name>_
    def resources(self) -> dict     # streams/KV/consumers it expects (verified at start)
    async def start(self, ctx)      # subscribe, bind consumers
    async def on_tick(self, ctx)    # 0.5 s housekeeping
    def verbs(self) -> dict         # name -> Verb(handler, help, params, operator_only)
    def panel(self, ctx) -> dict    # {"title", "columns", "rows", "actions"} for the dashboard
    def on_local_event(self, ctx, kind, data)   # e.g. work released -> knowledge capture
```

- `ctx` is the plugin's only view of the world: `publish(plane, subject_tail, payload, rid, to_peer)`,
  `db(fn)`, `store`, `policy`, `kv(bucket)`, `js`, `log`, and `local_repo(rid)` / `rid_of(repo)`.
  It is a Facade, and every publish goes through the guard pipeline (§7).
- **Verbs become CLI and MCP automatically.** A plugin verb `board.claim` is
  `agentmux hub fed board claim …` on the CLI, `fed_board_claim` on the hub socket, and
  `board_claim` as an MCP tool, from one definition.
- **Storage:** each plugin's own `p_<name>_*` tables are created by the runtime, idempotently.
- **Discovery:** built-ins live in `hub/fed/plugins/`. A third-party plugin is any
  importable module named in `plugins = [...]` with a `PLUGIN` attribute.

### 9.2 messages
Direct messages and handoffs across people. **Address:** `peer:<peer>/<repo>/<role>/<agent>`
or `peer:<peer>` (that peer's operator inbox). `<repo>` is the *sender's* local name and
is translated to a rid on the way out and to the receiver's local name on the way in.
Kinds: `note`, `request`, `reply`, `handoff` (body plus optional `work_id` and code ref),
`result`. `agentmux hub post --to peer:alice/falcon/worker/claude_1 …` goes through it,
so existing agent habits carry over.

### 9.3 work
`agentmux hub work add --to role:falcon/worker --federate …`: when federation is on, a
federated role item goes to `am.work.<me>.<rid>.worker` instead of TM-218's core-NATS
queue group. A hub pulls only when it has a live, idle agent that can serve
`role:<local repo>/<role>`, and only from publishers it trusts at `auto` or `flag`
(one consumer per publisher, A19). A privileged requirement still quarantines the item
on the hub that pulled it. The result travels back
as an `am.msg` of kind `result`, and closes the origin's placeholder item.

### 9.4 knowledge
- **Explicit:** `agentmux hub fed know share --repo R --title T "body" [--tag x]...`
- **Auto-capture** (`capture = true`): a work item released `done` with a result, a
  handoff, and a closed federated item each publish a finding (title, result, task key,
  author). Redaction applies as usual.
- Every hub indexes the stream into `p_knowledge_items` with an FTS5 index:
  `agentmux hub fed know search "query"` and the MCP `knowledge_search` are local, fast
  and work offline. A new finding for an opted-in repo rings that repo's idle agents
  with a one-line `[hub] finding from alice: …` (the doorbell, never the full body).

### 9.5 code
A Claim Check: the payload stays in git, and NATS carries the pointer.
`agentmux hub fed code share --repo R [--ref HEAD] [--to peer:alice] --note "…"`:
1. pushes `HEAD` to `<code_remote>` as `refs/agentmux/<peer>/<slug>`
2. publishes `{remote_url, ref, sha, base, files, summary}` to `am.code.<me>.<rid>` (and,
   with `--to`, an `am.msg` handoff)

The receiver runs `agentmux hub fed code fetch <id>`, which fetches the ref into
`refs/agentmux/<from>/<slug>` and **verifies the sha** before reporting success.

With an explicitly selected code owner, the Hub sends code reads and changes
through signed storage commands. The owner retains the original code table,
share IDs, metadata and outbox in their original database. The Hub does not read
code rows directly. The selected source, repository, caller and current grants
must still match before Git runs or a result is returned.

The CLI and MCP generate one operation ID for each code share or fetch request.
After a transport failure they retry once with that same ID. If recovery still
fails, use the reported ID with `--operation-id` and the original arguments.
Reusing the ID with another caller, source or arguments is refused. A new command
gets a new ID, so a later `HEAD` can produce a new share. Explicit completion
records remain in the private Hub operation state; they are not silently evicted
or reused. Recovery still requires current code-owner permission and, for a
handoff, current message-owner permission.

The Hub retains the original Git effect until publication and any handoff are
confirmed together. An uncertain Git effect is not repeated automatically.
Completed results survive response loss and client restart without another push,
fetch, publication or handoff. Cancellation and shutdown join the original work
before releasing borrowed resources.

Older clients without an operation ID can recover a completed result after a
detected response write or drain failure. A successful drain retires that
temporary receipt, but does not prove the caller received it. Indistinguishable
new requests from those clients cannot receive the same retry guarantee. These
selected-owner paths are qualified for native macOS ARM64; other platforms are
not qualified by this work.

### 9.6 board
The shared central board for shared repos, in KV `am_board`:
- **Keys** are minted from `<rid>.seq.<PREFIX>` with compare-and-set, so two people never
  mint the same `SH-12`.
- **Every update is a CAS on the card's KV revision.** A conflict re-reads the card,
  reapplies the change and retries (3 attempts), then reports the conflict.
- **Fields:** key, title, body, status (`todo`, `doing`, `review`, `done`, `blocked`),
  assignee (`peer:…` address), labels, comments[], history[], created_by, updated_by, rev.
- **Every hub watches the bucket** and mirrors cards for its opted-in rids into
  `p_board_cards`, so reads are local. The dashboard panel shows them grouped by status.
- **Verbs:** `board add|list|show|move|assign|comment|claim`. `claim` is "assign to me
  and move to doing" in one CAS.
- cc.db is **not** replaced. Local cards stay local. `board add --from TM-123` copies a
  local card's title and body onto the shared board, and records the link both ways.

---

## 10. Agent surface (F10)

- **CLI (canonical):** `agentmux hub fed <verb>` (in `hub/cli.py`): `status`, `peers`,
  `share`, `unshare`, `trust`, `kill`, `resume`, `quarantine`, `approve`, `deny`,
  `audit`, plus every plugin verb.
- **MCP:** `agentmux hub mcp` (`hub/fed/mcp.py`) is a stdio MCP server with no
  dependencies. Its tools are the core agent verbs (`inbox`, `post`, `claim`, `done`,
  `work_add`) plus every plugin verb, generated from the same registry, and each call
  goes through the hub socket. The server runs as a child of the agent's CLI inside the
  pane, so the hub identifies the caller by process ancestry exactly as it does for the
  CLI. Nothing in the MCP layer asserts an identity.
- **Spawned claude agents** get the MCP server registered in their per-agent config
  automatically when federation is on.

---

## 11. Dashboard

`dashboard/fed_panel.py` + `fed.js` add a **Federation** view, as a client of the hub
socket (like the Hub view):
- the connection and the kill switch
- peers and presence
- the quarantine queue with approve and deny
- one section per plugin, rendered generically from `plugin.panel()`
- the audit tail

---

## 12. Phases

| Phase | Scope | Exit evidence |
|---|---|---|
| 0 | kind + Helm cluster, TLS, operator/JWT circle, streams and buckets, `nats-py` venv, connection runtime with presence | `hub/tests/test_fed_live.py::Phase0`, `deploy/nats/up.sh` |
| 1 | plugin framework, guard pipeline (scope, redact, trust, privilege, audit), quarantine, kill switch, `fed` CLI | `hub/tests/test_fed_unit.py`, `test_fed_live.py::Guardrails` |
| 2 | messages + work plugins on JetStream; result loop | `test_fed_live.py::Messages`, `::Work` |
| 3 | board plugin (KV CAS) | `test_fed_live.py::Board` |
| 4 | knowledge plugin (explicit, auto-capture, FTS) | `test_fed_live.py::Knowledge` |
| 5 | code plugin (git refs + verification) | `test_fed_live.py::Code` |
| 6 | MCP server, dashboard panel, privileged-gate hook, end-to-end demo | `test_fed_mcp.py`, `dashboard/test_fed_panel.py`, `deploy/nats/demo.sh` |

### 12.1 Evidence (2026-10-07)

| Suite | Where it runs | Result |
|---|---|---|
| `hub/tests/test_fed_unit.py` | no NATS | 18/18 |
| `hub/tests/test_fed_live.py` | throwaway operator-mode nats-server (nsc JWTs) | 16/16 |
| `hub/tests/test_fed_live.py` with `AGENTMUX_FED_KIND=1` | the kind cluster: Helm `nats/nats` 2.15.0, 3 replicas, TLS, full resolver | 16/16 |
| `dashboard/test_fed_panel.py` | fake hub socket | 5/5 |
| `dashboard/run_tests.sh` (whole dashboard gate) | macOS | all suites passed (Playwright e2e skipped: not installed) |
| `hub/tests/test_hub_offline.py` + `test_nats_federation.py` | — | 59/60. `test_retire_courier_imports_only_the_undelivered_backlog_once` fails on a clean `HEAD` checkout too (pre-existing, macOS) |
| re-run 2026-10-08, after the governance review | macOS, Python 3.14.8, `.venv` from `hub/requirements.lock` | `test_hub_offline` + `test_fed_unit` + `test_nats_federation` + `test_fed_live` 96/96; `test_fed_panel` 5/5; `test_host_guard` 4/4; `dashboard/run_tests.sh` all suites passed (Playwright e2e skipped). The courier failure above was the test stubbing the harness with `/bin/true`, which macOS does not have; it now uses `shutil.which("true")` |
| `deploy/nats/demo.sh run` | kind cluster | every step ✓, 3.7 s |
| `deploy/nats/demo.sh live` | kind cluster, **two real Claude Code sessions** (nick's lead, alice's worker) | ✓ in about 60 s. nick's Claude carded SH-2 and federated the work. alice's Claude implemented `slugify` plus a 5-assert test, shared the ref, a finding and a handoff, and closed the item. nick's Claude fetched and verified the sha, ran the tests, commented and replied. No human relay. The first live run found three bugs (cross-name addresses, duplicate shares on a bad `--to`, assignee naming), and all three were fixed and covered by tests |

Server-side anti-spoofing was checked by hand as well: `nick` publishing
`am.msg.alice.nick` is refused with a permissions violation, and a member cannot create a stream.

### 12.2 Running it

```bash
deploy/nats/up.sh                  # kind + Helm + TLS + circle + streams (idempotent)
deploy/nats/demo.sh all            # fresh demo hubs, the narrated walkthrough, nick's dashboard on :8790
deploy/nats/demo.sh live           # real Claude sessions for nick and alice (after `demo.sh up`)
deploy/nats/demo.sh as alice fed board list     # poke any hub as that person's operator
.venv/bin/python -m unittest hub.tests.test_fed_unit hub.tests.test_fed_live
AGENTMUX_FED_KIND=1 .venv/bin/python -m unittest hub.tests.test_fed_live    # against the cluster
```

**A real two-person setup:** the circle admin runs `circle.sh init`, `circle.sh add <peer>` per
person, and sends each person their `<peer>.creds` and `ca.pem` over a private channel.
Each person then runs `agentmux hub fed setup`, writes `~/.agentmux/hub/federation.toml`
(§6), runs `agentmux hub fed share <repo>` and `agentmux hub fed trust <peer> --level auto`,
and restarts the hub.

---

## 13. Assumptions log

The operator stepped away after saying "complete phase 0–6 end to end … log
assumptions". Each row is a decision taken without them. Review before production use.

| # | Assumption | Why | How to undo |
|---|---|---|---|
| A1 | The hosted cluster is represented locally by **kind** on Docker Desktop. The same `values.yaml` targets a real cluster | No kube context existed. The demo has to run on this Mac | point `kubectl` at the real cluster and run `up.sh --no-kind` |
| A2 | Installed `kind`, `helm`, `nats-server`, `nats`, `nsc` with Homebrew and started Docker Desktop | Phase 0 can't be built or tested without them | `brew uninstall …` |
| A3 | TLS uses a **self-signed CA** made by `up.sh` with openssl (no cert-manager) | No DNS or ACME on a laptop. Fewer moving parts | set `tls.secretName` to a cert-manager or real certificate |
| A4 | `nats-py==2.16.0`, `nkeys==0.2.1` in a repo-local `.venv`. The hub prefers `.venv/bin/python` when it exists. Federation degrades to "needs `agentmux hub fed setup`" without it | PEP 668 blocks a global install. The core hub stays stdlib-only | delete `.venv` |
| A5 | **One circle per hub** in v1 | Multiple circles need one connection, policy and audit scope each. Nothing asked for it | add `[[circle]]` tables later |
| A6 | A peer's nodes **share one user credential** | User name = peer id keeps anti-spoofing a single subject token | issue `<peer>_<node>` users and change token 3 to the node |
| A7 | **The circle is the confidentiality boundary** (§7.4). Per-repo `peers=[…]` limits sending and mirroring, not what the server lets a member read | Server-enforced per-repo read ACLs would mean reissuing JWTs on every share change | per-share accounts, or tag-templated JetStream ACLs |
| A8 | Hubs connect as **clients**, not leaf nodes | JetStream plus the local outbox already cover offline. Leaf nodes add a server per machine | leaf config is additive |
| A9 | Board **conflict policy**: CAS, re-read and reapply up to 3 times. Each field is last-writer-wins *within* a successful CAS | The interview chose "shared central board, CAS" | — |
| A10 | Shared cards live **beside** cc.db, not in it. `--from TM-x` copies a local card across | cc.db's schema belongs to the dashboard. Writing other people's cards into it risks collisions with local keys | — |
| A11 | Knowledge auto-capture triggers on `done` with a result, handoffs, and closed federated items. Agents' tool output and transcripts are **not** captured | Highest signal for the least noise and the least exposure | `capture = false`, or edit `knowledge.CAPTURE` |
| A12 | Redaction **blocks** private keys, nkey seeds and creds files, and **redacts** everything else it recognises | A private key in a payload is never intended. A token in a log excerpt usually is an accident worth keeping the rest of | edit `redact.BLOCK` |
| A13 | Privileged tool families: pcm600 import/write, CODESYS runtime write/force, PROFINET DCP, BOOTP | These are the repo's existing privileged surfaces (EP-018/019, `taskmgmt/pn_dcp.py`, `bootp_probe.py`) | edit `hooks/privileged_gate.py` `PRIVILEGED` |
| A14 | The default trust for an unlisted peer is `approve` | Safe by default. Per-peer `auto` is one line | `[peers."*"] trust = …` |
| A15 | The demo runs **two people on one Mac** as two `AGENTMUX_HOME`s (nick, alice) with separate creds, and a local bare git repo as the shared remote | There is no second person or machine to use | run `demo.sh` on two machines with real creds |
| A16 | The kill switch's `--revoke` withdraws (marks, cancels unclaimed), but cannot erase data already copied to other hubs | A remote copy cannot be deleted from here. Saying otherwise would be false | — |
| A17 | Board key prefix is `SH` (shared) by default, configurable per repo | Distinct from local `TM-`/`EP-` keys, so a shared card is never mistaken for a local one | `[repos.x] board_prefix = "FAL"` |
| A18 | The MCP server speaks protocol version `2025-06-18` over stdio, hand-written (no SDK) | Keeps the "thin wrapper" with no extra dependency. The surface is three methods | swap in the SDK if it grows |
| A19 | A hub **pulls federated work only from publishers it trusts** at `auto` or `flag`, through one consumer per publisher | Found while testing: with one shared consumer, an untrusting hub pulled and quarantined work that a trusting hub would have done | a peer you set to `approve` can still message you, but its work waits for someone who trusts it |
| A20 | The privileged-gate hook **fails closed only when federation is enabled** on that hub. Without federation, a hub outage doesn't block PLC tools | No remote work can exist without federation | `hooks/privileged_gate.py` `decide` |
| A21 | **Approval releases an item, it doesn't raise trust.** An approved message from an `approve` peer is still framed as REMOTE DATA | Approval means "deliver this", not "obey this sender" | — |
| A22 | The **live demo** starts claude on the default config with `--setting-sources ''`, then adopts the pane, rather than `agentmux spawn` | On macOS Claude Code keeps its login in the Keychain under a name derived from `CLAUDE_CONFIG_DIR`, so the harness's per-agent config mirrors start logged out. Copying Keychain secrets was out of bounds | run `claude` once in a mirror to log it in, or give agents `CLAUDE_CODE_OAUTH_TOKEN` via `$AGENTMUX_HOME/env` |
| A23 | The demo homes live in `~/.agentmux-demo`, not under the repo | macOS caps AF_UNIX socket paths at 104 bytes, and the repo path is too long for `hub/hub.sock` | `AGENTMUX_FED_DEMO_DIR` |
| A24 | The demo and the kind-mode test suite use the **same peer ids** (nick, alice, mallory) on the same cluster, so they must not run at the same time (`demo.sh down` first). The suite wipes the streams | One circle, made by `up.sh` | give the tests their own circle/account |
