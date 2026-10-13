# Design pattern diagrams

Generated from `.context/design-patterns.md` and verified repository evidence. User notes may be added outside the generated sections.

## Abstract pattern architecture

```mermaid
flowchart LR
  Agent[Agent CLI / Claude] -->|FED-15 Messaging Gateway| Hub[Local hub]
  Hub -->|FED-02 Transactional Client| Outbox[(Outbox)]
  Outbox -->|FED-08 Content Filter + FED-07 Message Filter| Bridge[FED-01 Messaging Bridge]
  Bridge -->|FED-03 Guaranteed Delivery| Streams[(JetStream streams)]
  Streams -->|FED-05 Durable Subscriber| Inbound[Inbound guard]
  Streams -->|FED-06 Competing Consumers| Work[Work pullers]
  Inbound -->|FED-04 Idempotent Receiver| Plugins[Capability plugins]
  Plugins -->|FED-17 Facade| Bridge
  Plugins -->|FED-09 Envelope Wrapper| Agent
  Plugins -->|FED-14 Shared Database| KV[(KV board)]
  Plugins -->|FED-11 Claim Check| Git[(Shared git remote)]
  Bridge -->|FED-13 Message Store| Audit[(Audit log)]
  Operator[Operator] -->|FED-12 Control Bus| Bridge
  Envelope[FED-10 Canonical Data Model] -.-> Streams
  Result[FED-16 Correlation Identifier] -.-> Work
```

```plantuml
@startuml
actor Agent
actor Operator
component "Local hub" as Hub
database "Outbox" as Outbox
component "FED-01 Messaging Bridge" as Bridge
database "JetStream streams" as Streams
component "Inbound guard" as Inbound
component "Capability plugins" as Plugins
database "KV board" as KV
database "Shared git remote" as Git
database "Audit log" as Audit
Agent --> Hub : FED-15 Messaging Gateway
Hub --> Outbox : FED-02 Transactional Client
Outbox --> Bridge : FED-08 Content Filter / FED-07 Message Filter
Bridge --> Streams : FED-03 Guaranteed Delivery
Streams --> Inbound : FED-05 Durable Subscriber
Streams --> Plugins : FED-06 Competing Consumers
Inbound --> Plugins : FED-04 Idempotent Receiver
Plugins --> Bridge : FED-17 Facade
Plugins --> Agent : FED-09 Envelope Wrapper
Plugins --> KV : FED-14 Shared Database
Plugins --> Git : FED-11 Claim Check
Bridge --> Audit : FED-13 Message Store
Operator --> Bridge : FED-12 Control Bus
note right of Streams : FED-10 Canonical Data Model (envelope v2, rid)
note right of Plugins : FED-16 Correlation Identifier (origin_id)
@enduml
```

## Concrete implementation architecture

```mermaid
classDiagram
  class Bridge["hub/bridge.py Bridge (FED-01)"]
  class Federation["hub/fed/runtime.py Federation (FED-01, FED-05, FED-12, FED-17)"]
  class Ledger["hub/fed/ledger.py (FED-02, FED-04, FED-13)"]
  class Guard["hub/fed/guard.py (FED-07, FED-09)"]
  class Redact["hub/fed/redact.py scrub (FED-08)"]
  class Envelope["hub/fed/envelope.py + policy.py (FED-10)"]
  class Conn["hub/fed/conn.py STREAMS (FED-03)"]
  class Plugin["hub/fed/plugin.py Plugin"]
  class Messages["plugins/messages.py"]
  class Work["plugins/work.py (FED-06, FED-16)"]
  class Board["plugins/board.py (FED-14)"]
  class Knowledge["plugins/knowledge.py"]
  class Code["plugins/code.py (FED-11)"]
  class Mcp["hub/fed/mcp.py + hub/cli.py fed_main (FED-15)"]
  Federation --> Ledger
  Federation --> Guard
  Guard --> Redact
  Guard --> Envelope
  Federation --> Conn
  Federation o-- Plugin
  Plugin <|-- Messages
  Plugin <|-- Work
  Plugin <|-- Board
  Plugin <|-- Knowledge
  Plugin <|-- Code
  Mcp --> Federation : hub socket verbs
```

```plantuml
@startuml
class "hub/bridge.py Bridge (FED-01)" as Bridge
class "hub/fed/runtime.py Federation (FED-01, FED-05, FED-12, FED-17)" as Federation
class "hub/fed/ledger.py (FED-02, FED-04, FED-13)" as Ledger
class "hub/fed/guard.py (FED-07, FED-09)" as Guard
class "hub/fed/redact.py scrub (FED-08)" as Redact
class "hub/fed/envelope.py + policy.py (FED-10)" as Envelope
class "hub/fed/conn.py STREAMS (FED-03)" as Conn
abstract class "hub/fed/plugin.py Plugin" as Plugin
class "plugins/messages.py" as Messages
class "plugins/work.py (FED-06, FED-16)" as Work
class "plugins/board.py (FED-14)" as Board
class "plugins/knowledge.py" as Knowledge
class "plugins/code.py (FED-11)" as Code
class "hub/fed/mcp.py + cli fed_main (FED-15)" as Mcp
Federation --> Ledger
Federation --> Guard
Guard --> Redact
Guard --> Envelope
Federation --> Conn
Federation o-- Plugin
Plugin <|-- Messages
Plugin <|-- Work
Plugin <|-- Board
Plugin <|-- Knowledge
Plugin <|-- Code
Mcp --> Federation : hub socket verbs
@enduml
```

## Traceability

| Registry ID | Pattern | Role | Repository location | Evidence |
| --- | --- | --- | --- | --- |
| FED-01 | Messaging Bridge | hub messaging <-> NATS | `hub/bridge.py` Bridge, `hub/fed/runtime.py` Federation | `hub/tests/test_fed_live.py`, `hub/tests/test_nats_federation.py` |
| FED-02 | Transactional Client | outbox in the state change's transaction | `hub/fed/runtime.py` Federation.stage, `hub/fed/ledger.py` outbox_add, `hub/store.py` Store._outbox | `hub/tests/test_fed_live.py` |
| FED-03 | Guaranteed Delivery | JetStream file streams, R3 | `hub/fed/conn.py` STREAMS, `hub/fed/admin.py` provision | `hub/tests/test_fed_live.py` |
| FED-04 | Idempotent Receiver | fed_seen + Nats-Msg-Id | `hub/fed/runtime.py` Federation.receive, `hub/fed/ledger.py` seen | `hub/tests/test_fed_live.py` |
| FED-05 | Durable Subscriber | per-node durable pull consumers | `hub/fed/runtime.py` Federation._bind_core | `hub/tests/test_fed_live.py` |
| FED-06 | Competing Consumers | per-publisher work-queue consumers | `hub/fed/plugins/work.py` Work.on_tick | `hub/tests/test_fed_live.py` |
| FED-07 | Message Filter | trust, scope, spoof, privilege | `hub/fed/guard.py` inbound/outbound | `hub/tests/test_fed_unit.py`, `hub/tests/test_fed_live.py` |
| FED-08 | Content Filter | secret redaction/blocking | `hub/fed/redact.py` scrub | `hub/tests/test_fed_unit.py`, `hub/tests/test_fed_live.py` |
| FED-09 | Envelope Wrapper | remote text framed as data | `hub/fed/guard.py` wrap, `hub/fed/plugins/messages.py` | `hub/tests/test_fed_unit.py`, `hub/tests/test_fed_live.py` |
| FED-10 | Canonical Data Model | envelope v2, rid | `hub/fed/envelope.py` make, `hub/fed/policy.py` rid_for_remote | `hub/tests/test_fed_unit.py`, `hub/tests/test_fed_live.py` |
| FED-11 | Claim Check | git refs + pointer | `hub/fed/plugins/code.py` Code.v_share/v_fetch | `hub/tests/test_fed_live.py` |
| FED-12 | Control Bus | kill switch, revoke notice | `hub/fed/runtime.py` _v_kill, Federation._on_ctl | `hub/tests/test_fed_live.py` |
| FED-13 | Message Store | audit log | `hub/fed/ledger.py` audit | `hub/tests/test_fed_live.py` |
| FED-14 | Shared Database | KV board with CAS | `hub/fed/plugins/board.py` Board._write | `hub/tests/test_fed_live.py` |
| FED-15 | Messaging Gateway | CLI + MCP over the hub socket | `hub/fed/mcp.py` handle, `hub/cli.py` fed_main | `hub/tests/test_fed_unit.py` |
| FED-16 | Correlation Identifier | result -> origin item | `hub/fed/plugins/work.py` Work._on_result | `hub/tests/test_fed_live.py` |
| FED-17 | Facade | runtime as plugin ctx | `hub/fed/runtime.py` Federation, `hub/fed/plugin.py` Plugin | `hub/tests/test_fed_live.py` |

## Planned platform rearchitecture (proposal, October 9, 2026)

This section records the proposed destination for review. Existing FED diagrams above describe the current implementation and remain unchanged. PLAN entries have status `planned` and do not claim implemented or approved behavior.

```mermaid
flowchart TB
  Clients["Client / vendor / AG-UI adapters (PLAN-02)"] <--> Bus["NATS message contracts (PLAN-07, PLAN-08, PLAN-11)"]
  Runtime["Plugin construction and scoped clients (PLAN-01, PLAN-04)"] <--> Bus
  Runtime -->|Constructs scoped instances| Assembly["Nested assembly (PLAN-03)"]
  Assembly -->|Owns private child instance| Private["Parent-owned child"]
  Assembly -.->|References reusable package| Independent["Independent child package"]
  Boot["Protected kernel"] -->|Published information only, PLAN-05| Bus
  Bus <--> Work["Task / attempt owners and routing (PLAN-06, PLAN-15)"]
  Bus <--> State["Domain-owned conditional commits (PLAN-09, PLAN-10)"]
  State -->|NATS storage contracts| Records[("Authoritative JetStream records (PLAN-13)")]
  Records -->|Scoped replay| Views["View-building plugins"]
  Views -->|NATS KV API| KV[("Derived current views")]
  Views --> SQL[("Optional rebuildable SQL indexes")]
  Views <--> Bus
  Bus <--> Artifacts["Artifact reference service (PLAN-12)"]
  Bus <--> History["Scoped history and recovery (PLAN-13)"]
  History --> Records
  Bus <--> Control["Surrounding runtime controls (PLAN-14)"]
```

```plantuml
@startuml
component "Protected kernel" as Kernel
component "Client / vendor / AG-UI adapters\nPLAN-02" as Adapters
component "NATS contracts\nPLAN-07, PLAN-08, PLAN-11" as Bus
component "Plugin construction and scoped clients\nPLAN-01, PLAN-04" as Runtime
component "Nested assembly\nPLAN-03" as Assembly
component "Parent-owned child instance" as Private
component "Independent child package" as Independent
component "Task / attempt owners and routing\nPLAN-06, PLAN-15" as Work
component "Domain-owned conditional commits\nPLAN-09, PLAN-10" as State
database "Authoritative JetStream records\nPLAN-13" as Records
component "View-building plugins" as Views
database "Derived NATS KV views" as KV
database "Optional rebuildable SQL indexes" as SQL
component "Artifact reference service\nPLAN-12" as Artifact
database "Required event store\nPLAN-13" as History
component "Surrounding runtime controls\nPLAN-14" as Control
Kernel --> Bus : published information only (PLAN-05)
Adapters <--> Bus
Runtime <--> Bus
Runtime --> Assembly : constructs scoped instances
Assembly *-- Private : owns instance
Assembly ..> Independent : references reusable package
Bus <--> Work
Bus <--> State
State --> Records : NATS storage contracts
Records --> Views : scoped replay
Views --> KV : NATS KV API
Views --> SQL : local index
Views <--> Bus
Bus <--> Artifact
Bus <--> History
History --> Records
Bus <--> Control
@enduml
```

### Proposed contract ownership

| Proposed contract / component | Owning phases | Recorded patterns |
| --- | --- | --- |
| Plugin construction, nested lifecycle, scoped context | P02–P04 | PLAN-01, PLAN-03, PLAN-04, PLAN-05 |
| Client, worker, vendor and UI interfaces | P06, P07, P11 | PLAN-02 |
| Provider and eligible-work policy selection | P05, P08, P10 | PLAN-06, PLAN-15 |
| Shared envelopes and NATS communication | P01–P12 | PLAN-07, PLAN-08, PLAN-11 |
| NATS-owned records, durable intent and duplicate handling | P01, P04, P05, P10 | PLAN-09, PLAN-10, PLAN-13 |
| Scoped replay, derived KV and optional SQL indexes | P04, P07, P12 | PLAN-04, PLAN-13 |
| Artifact exchange, event history, authorized controls | P04, P07, P10, P12 | PLAN-12, PLAN-13, PLAN-14 |

Implementation symbols and files will be registered in the owning phases. The proposal is [docs/planning/2026-10-09/implementation-plan.md](../docs/planning/2026-10-09/implementation-plan.md).

STATE-01 updates only the planned destination. Configuration/registry KV records have their own owner; task-summary KV and SQL views are derived. Same-stream atomic persistence does not make cross-stream transfers, projection updates or tool actions atomic. Separate hubs preserve origin-task and receiver-execution authority. Historical FED diagrams above remain unchanged.


### ADD-01: Existing implementations through reviewed boundaries

This proposal refines PLAN-02. Historical FED diagrams above remain unchanged. Existing behavior stays available until its owning phase proves compatibility and migration. Replacing implementation does not authorize removing capability.

```mermaid
flowchart LR
  Existing["Existing harness, hub plugins, dashboard and tools"] --> Boundary["Retained or extracted code behind PLAN-02 interfaces"]
  Boundary --> Contracts["Scoped NATS contracts"]
  Tests["Existing assertions and new behavior fixtures"] --> Compare["Baseline and candidate evidence"]
  Existing --> Compare
  Boundary --> Compare
  Compare --> Gate["Owning phase review before cutover"]
```

See [component preservation](../docs/planning/2026-10-09/component-preservation.md) for concrete source ownership, tests, gains and migration requirements. This is a verification and migration view; it introduces no new pattern catalog entry.

### LOCAL-01: Planned automatic startup and status

This refines planned PLAN-02 client interfaces and PLAN-14 status/control boundaries. Existing implementation diagrams remain historical. Bootstrap coordination runs before NATS is available and grants no general kernel write access.

```mermaid
flowchart LR
  Client["Installed client startup adapter: PLAN-02"] --> Inspect["Resolve owned instance and local Docker context"]
  Inspect -->|"Healthy compatible instance"| Status["Scoped status through NATS: PLAN-14"]
  Inspect -->|"Absent or stopped"| Compose["Single startup owner: Docker Compose"]
  Compose --> Ready["Bounded readiness and persistence checks"]
  Ready --> Status
  Status --> Views["Same instance and authorized hub details in terminal and dashboard"]
```

P02 verifies bootstrap with explicit later-service fixtures; P06 verifies actual client launch; P07 verifies dashboard consistency; P10 verifies real hub visibility; P12 repeats the packaged workflow. The current plan defines conflict, timeout and recovery handling. No new pattern catalog entry or implemented relationship is claimed.

## October 9 baseline repairs: current work reservation boundary

The diagrams above are preserved as design history. This current detail revises FED-02, FED-04, FED-06, FED-07, FED-10 and FED-16; it does not mark the planned platform phases implemented.

```mermaid
sequenceDiagram
  participant O as Origin work plugin
  participant N as NATS / JetStream
  participant R as Receiving work plugin
  participant W as Local worker
  O->>O: Commit pending task and v3 offer outbox together
  O->>N: Publish versioned offer
  N->>R: Deliver or redeliver
  R->>R: Commit attributed blocked task and claim outbox together
  R->>N: Claim with offer digest and execution identity
  N->>O: Deliver claim
  O->>O: Commit one selected executor and grant outbox together
  O->>N: Publish grant
  N->>R: Deliver matching grant
  R->>R: Validate origin/offer/execution; become ready
  R->>W: Local claim and execution
  W->>R: Done or failed
  R->>R: Terminal state and durable return intent commit together
  R->>N: Retry stable result from outbox after any restart
  N->>O: Deliver result
  O->>O: Validate selected executor, grant, task/repository and content digest
```

An origin or receiver outage delays the exchange without selecting another executor. V2 work consumers use a different exact subject and cannot consume v3 offers. Same-peer nodes are distinct execution identities; the peer credential remains the authenticated principal. Schema migration 5 and snapshot publication are detailed in `docs/planning/2026-10-09/governance-repairs.md`.

## P00 runtime and account refinement — proposed

This detail supports PLAN-02/03/04/05/07/08/09/10/12/13/14. It remains a proposal in `docs/planning/2026-10-09/delivery/decisions/`; the bounded runtime spike proves only client wire interoperability. Existing implementation and historical diagrams above remain unchanged.

```mermaid
flowchart TB
  Host["Client hook / owned launcher: PLAN-02"] --> Compose["Selected local Compose project"]
  Compose --> Broker["NATS infrastructure"]
  subgraph Protected["Protected account and fixed release assembly: PLAN-03"]
    Boot["Boot plugin"] <--> Internal["Internal NATS subjects: PLAN-07"]
    Lifecycle["Kernel lifecycle plugin"] <--> Internal
    Status["Kernel status plugin"] <--> Internal
  end
  Status -->|"Exported information only: PLAN-05"| App["Scoped application NATS accounts"]
  Clients["Python / TypeScript SDK clients: PLAN-04"] <--> App
  Owners["Ordinary domain owner plugins"] <--> App
  Owners -->|"Conditional complete record: PLAN-09/10"| Records["Project JetStream ledger: PLAN-13"]
  Records --> Views["Rebuildable KV / SQL views"]
  Owners --> Artifacts["Immutable artifact references: PLAN-12"]
  App <--> Export["Agreement-scoped federation account"]
  Export <-->|"Leaf link; explicit exports"| Partner["Independent hub / persistence domain"]
```

No application arrow enters the protected account. The broker is shared infrastructure, while account permissions and domain-owner validation enforce distinct boundaries. A leaf link does not merge persistence or ownership. Proposed separate protected processes add lifecycle overhead; P02 must measure it. No Go implementation replaces current Python business logic through this diagram.

## P00 proposed authenticated ingress and configuration ownership

This refines planned PLAN-07/08/09/10 relationships; no running implementation is claimed.

```mermaid
flowchart LR
  Client[Scoped client or verified login] --> Ingress[Enrolled ingress]
  Ingress -->|NATS: signed canonical claims and payload| Owner[Domain owner]
  Keys[Enrolled issuer keys] --> Owner
  Owner -->|Verify identity, scope, digest and replay| Ledger[(Authoritative owner ledger)]
  Ledger -->|After commit, with cursor| View[(Configuration / registry KV view)]
  View --> Reader[Read projection; authorization uses owner revision]
```

## P01 implemented contract verification path

PLAN-08 now has independent executable clients. This path verifies supplied keys and wire integrity; it does not implement the proposed ingress enrollment, grant service or NATS domain owner shown above.

```mermaid
flowchart LR
  Fixtures[Literal vectors and ephemeral fixture keys] --> Harness[Cross-language conformance harness]
  Harness --> Python[Python: jsonschema / rfc8785 / PyNaCl]
  Harness --> TypeScript[TypeScript: Ajv / canonicalize / Node crypto]
  Schemas[contracts/v1 schemas] --> Python
  Schemas --> TypeScript
  Python -->|Signed claims| TypeScript
  TypeScript -->|Signed claims| Python
  Python --> Evidence[Results and source/build hashes]
  TypeScript --> Evidence
```

## P01 closed payloads and semantic verification

This extends the executable PLAN-08 path above. The local registry selects the closed payload schema and expected message kind/service. Each SDK also checks payload/context agreement and semantic invariants; a successful check still requires the caller to resolve trusted keys and enforce current grants. The legacy runtime is unchanged.

```mermaid
flowchart LR
  Envelope["Received versioned envelope"] --> Python["Python verify_envelope / validate_payload"]
  Envelope --> TypeScript["TypeScript verifyEnvelope / validatePayload"]
  Registry["contracts/v1/registry.json: PLAN-08"] --> Python
  Registry --> TypeScript
  Shapes["Closed payload and infrastructure schemas"] --> Python
  Shapes --> TypeScript
  Python --> Checks["Signed audience, digest, context IDs and semantic checks"]
  TypeScript --> Checks
  Checks --> Claims["Verified claims; caller authorization still required"]
```

## P01 storage qualification fixtures

PLAN-09 and PLAN-10 remain planned for production. These concrete locations qualify selected broker primitives and bounded recovery logic in disposable tests only. The fixture does not create a production owner, move SQLite authority or authorize external work.

```mermaid
sequenceDiagram
  participant H as tests/storage/run.py
  participant P as Python fixture client
  participant T as TypeScript fixture client
  participant J as Owned R1 JetStream broker
  H->>P: Complete record and expected subject revision
  H->>T: Competing complete record and same expected revision
  P->>J: Conditional state + provenance + effect intent (PLAN-09)
  T->>J: Conditional competing record (PLAN-09)
  J-->>H: Exactly one accepted revision, one conflict
  H->>J: Publish another record without a reply inbox
  H->>J: Add later record; restart broker after deduplication window
  H->>P: Reconcile original operation ID and digest (PLAN-10)
  H->>T: Reconcile same retained operation independently (PLAN-10)
  P->>J: Authoritative retained-history read
  T->>J: Authoritative retained-history read
  J-->>H: Same earlier outcome, no new publish
```

The same harness stages and commits same-stream atomic batches. A staging reply alone is insufficient. Sequence gaps, stale conditions, an intervening ordinary write and cross-stream attempts must not leave partial batches. An uncommitted batch remains absent after graceful restart. The executed [storage report](../docs/planning/2026-10-09/delivery/evidence/P01/storage-result.json) identifies exact sources/builds and exclusions: native macOS, R3 availability, power loss, production permissions and external-effect execution are not qualified here. Phase acceptance is not implied by this diagram.

## P01 model oracle and scoped leaf qualification

The PLAN-08 model oracle proposes transitions from trusted fixture observations. It does not authenticate evidence or commit state. The separate leaf fixture qualifies PLAN-07/10/11/13 primitives using real brokers and a narrow fixture protocol, not the production plugin runtime.

```mermaid
flowchart LR
  Tables["Five versioned tables / 68 edges"] --> Python["Python transition evaluator"]
  Tables --> TS["TypeScript transition evaluator"]
  Snapshot["Owner state, revision and pending cancellation"] --> Python
  Snapshot --> TS
  Evidence["Supplied authority and guard references"] --> Python
  Evidence --> TS
  Python --> Candidate["Candidate next state; no persistence or execution"]
  TS --> Candidate
```

```mermaid
sequenceDiagram
  participant O as Origin fixture owner / private ledger
  participant A as Origin scoped federation account
  participant B as Receiver scoped federation account
  participant R as Receiver fixture owner / private ledger
  O->>O: Commit reservation and stable offer identity
  O->>A: Scoped offer
  A->>B: Restricted authenticated leaf
  B->>R: Offer
  R->>R: Commit accepted reservation
  R--xO: Acceptance observation deliberately lost
  Note over O,R: Origin stops; receiver retains reservation and hashes read-only input
  R->>R: Commit result; restart receiver
  Note over O,R: Origin restarts; independent ledgers retain different owner states
  O->>A: Reconcile same operation / digest
  A->>B: Restored leaf
  B->>R: Lookup retained acceptance
  R-->>O: Same acceptance and retained result; no second execution
  O->>O: Verify fixture result and record origin acceptance
```

Unrelated accounts cannot observe linked traffic. Bridge credentials cannot access private owner storage or origin acceptance subjects. A negative test widens only generated leaf credentials and confirms that the isolation assertion fails on unrelated traffic. These tests do not qualify real ingress signatures, dynamic grants, cross-host transport security or the final bilateral release demonstration.


## P01 ordered recovery and signed leaf admission

This extends PLAN-07/08/10/11/13 fixture coverage. The earlier narrow leaf protocol remains a separate test. The signed fixture uses the versioned SDK contracts, real local NATS brokers, fixed test keys and a trusted test clock. It does not implement production enrollment, live grants, transport security or the final independently enrolled hub demonstration.

```mermaid
sequenceDiagram
  participant O as Origin fixture / Python SDK
  participant N as Restricted NATS leaf
  participant R as Receiver fixture / TypeScript SDK
  O->>N: Signed delegation-offer (PLAN-07/08)
  N->>R: Preserve envelope bytes
  R->>R: Decode, resolve fixture key, verify audience/signature/scope
  R->>R: Retain offer and signed decision in private ledger (PLAN-13)
  R--xO: Decision publication deliberately lost
  Note over O,R: Receiver reads approved input; both independent brokers restart
  O->>N: Retry same operation and digest (PLAN-10)
  N->>R: Verify replay before retained-outcome lookup
  R->>N: Retained signed decision and execution-report
  N->>O: Python verifies TypeScript signature
  O->>O: Bind decision sender/destination/task/delegation/attempt to offer
  O->>O: Bind result executor/task/delegation/attempt/revision to offer (PLAN-11)
  O->>O: Check artifact bytes and digest; explicitly accept
```

Malformed input, invalid UTF-8, unknown contracts, wrong audience, altered payload and expiry are rejected before fixture owner mutation. Three separately signed decision mismatches and five signed result mismatches pass SDK verification and fail owner binding. Changed replay input cannot cause another execution. Static fixture authorization and fixed payload checks are deliberately limited; valid wire claims do not establish production permission.

The separate `tests/contracts/test_recovery.py` sequence compares both independent evaluators. Its in-memory owner checks current authorization before replay, requires a fresh authorized lookup after command expiry, retains pending cancellation through uncertainty and prevents approval from overriding a hard denial. These observations support PLAN-08/10 contract qualification. They do not establish durable ownership or prove non-admission from a schema alone.

## P01 native evidence runner

This is a delivery verification view of existing PLAN-08 conformance obligations, not an additional runtime design pattern. `tests/contracts/ci.py` and `.github/workflows/contracts.yml` define the following execution. A configured workflow is not evidence of a completed run.

```mermaid
flowchart TD
  Candidate["Feature branch candidate"] --> Hosts["Native Linux and macOS jobs"]
  Hosts --> Build["Locked dependencies and fresh SDK builds"]
  Build --> Broker["Pinned broker archive and checksum verification"]
  Broker --> Suites["SDK, contracts, storage and both leaf fixtures"]
  Build --> Negative["Copied positive fixture with required field removed"]
  Negative --> Failures["Require both SDK assertions to reject it"]
  Suites --> Gates["Tracker, regression retention, component coverage and pattern checks"]
  Failures --> Evidence["Fresh external evidence directory"]
  Gates --> Evidence
  Evidence --> Review["Codex reviews actual results before phase acceptance"]
```

The runner records source/build identity and command exit codes. Fresh reports go outside the checkout so CI cannot overwrite committed review records. Required checks include the regression guard's deliberately removed-assertion test. A passing native job cannot stand in for WSL evidence, production authorization checks or phase approval; task advancement and merging are not performed by this workflow.


## P01 controlled execution and storage boundary extension

These test paths extend PLAN-08/09/10 qualification without creating production owners or plugins.

```mermaid
flowchart LR
  Control["Manual clock and response plan"] --> Provider["FakeProvider: execute / retain result"]
  Provider --> Queue["Delay, drop or reorder callbacks"]
  Queue --> Worker["FakeWorker: observe deadline and cancellation"]
  Worker -->|"Explicit lookup; no automatic retry"| Provider
  View["Stale KV view with source cursor"] --> CAS["Conditional owner write rejects stale revision"]
  CAS --> Read["Both clients read authoritative owner record"]
  Read --> Policy["Current fixture policy revalidation"]
  Policy --> Deny["No new write when policy denies"]
```

The batch fixture loses the final commit reply, restarts the real broker and reconciles both contiguous records after the duplicate window. Unsupported cross-stream, KV, object and tool atomicity claims are rejected by fixture admission. These checks do not qualify production capability registration, external effects or power-loss durability.


## P01 incoming creation invariant fixture

This extends the existing PLAN-09/10 storage fixture boundary. It changes no production owner or hub relationship.

```mermaid
sequenceDiagram
  participant F as Incoming fixture
  participant C as Python or TypeScript client
  participant J as Owned JetStream ledger
  F->>F: Build blocked task, exact origin and one claim intent
  Note over F,J: State, attribution or claim construction failure leaves no record
  F->>C: One complete record with expected revision zero
  C->>J: Conditional publish
  J-->>C: Commit complete record
  Note over F,C: Inject caller exception after commit
  F->>C: Reconcile same operation and digest
  C->>J: Read retained owner record
  J-->>F: Same task, origin and claim intent; no duplicate publish
```

The [bounded review](../docs/planning/2026-10-09/delivery/evidence/P01/parent-change-review.json) identifies exact sources and limits. This is fixture persistence proof; provider dispatch, production authorization and native final-candidate qualification remain separate.


## Existing Windows callback gateway repair

This extends FED-15 at the existing launcher boundary. The P06 plugin adapter remains planned.

```mermaid
sequenceDiagram
  participant P as Agent pane in WSL
  participant W as Windows-owned client
  participant G as Windows Agentmux gateway
  participant C as Selected WSL hub CLI
  participant H as Existing hub
  P->>W: Scoped pane callback context
  W->>G: Agent hub command
  G->>G: Require explicit selection and scoped home
  Note over G,C: Invalid context or lifecycle verb rejected before state creation
  G->>C: Exact arguments through selected WSL binary
  C->>H: Loopback request with private per-agent token
  H->>H: Authenticate registered agent; enforce ownership
  H-->>W: Result or denial
```

The callback review preserves the original findings and records their closure against fresh repaired-source evidence, including a native pane after callbacks on the same tmux server. The diagram describes the repaired gateway contract; no automatic model-provider forwarding or P06 acceptance is claimed.


## Maintained legacy orchestration package restoration

This implements the bounded FED-15 legacy gateway restoration approved in `delivery/evidence/P01/plugin-restoration-spec.md`; P06 framework work stays planned.

```mermaid
flowchart LR
  Host[Existing terminal host] --> Hook[Relevant pre-tool policy check]
  Hook -->|read current roster/live definitions| API[Existing dashboard API]
  Hook -->|allow or clear refusal| Host
  Host --> Skills[Nine reconstructed skill guides]
  Skills --> Binding[Explicit installed runtime binding]
  Binding --> CLI[Existing coordination/dispatch/setup-auth]
  CLI --> API
  Host --> MCP[Roster MCP gateway]
  MCP -->|read only| API
```

Unrelated shell commands bypass external processing. Current runtime identity, checksum and approval checks remain authoritative. The restored host hook adds the live-definition check; direct dashboard HTTP mutation does not enforce that check and remains a documented limitation. The source locations are plugins/agentmux-orchestration/lib, bin/agentmux-plugin and skills/agent-config/scripts/runtime.py. Independent compatibility review qualifies only recorded behavior; no historical source equivalence or P06 framework acceptance is asserted.

## P01 recovered contract and capacity fixtures

These are isolated qualification paths. They do not connect the legacy hub to the new protected kernel or implement production storage policy.

```mermaid
flowchart LR
  Query[Existing scoped status query] --> Observation[PLAN-08 L04 observation reply]
  Observation --> Python[Independent Python validator]
  Observation --> TypeScript[Independent TypeScript validator]
  Bulk[Fixture bulk admission] --> Guard[Persisted budget and reserved record slots]
  Final[Final and reconciliation records] --> Guard
  Guard --> CAS[PLAN-09 conditional complete record append]
  CAS --> Ledger[(Disposable retained JetStream ledger)]
  Ledger --> Replay[PLAN-10 operation lookup after restart]
```

The status schema preserves unavailable and forbidden states; its runtime producer remains later work. Capacity fixtures use one task aggregate and conservative stream framing headroom. An unguarded writer control shows why a full stream cannot promise final-result admission.
