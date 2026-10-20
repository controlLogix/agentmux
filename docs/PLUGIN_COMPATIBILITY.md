# Existing plugin compatibility

The [AMUX-41](https://adag-csai.atlassian.net/browse/AMUX-41) boundary reuses the
existing federation plugins, Markdown parser and roster rules. It gives them
explicit interfaces while their existing entry points and storage owners remain
active. This supplies the mapping for the separate
[ordinary package manager](ORDINARY_PLUGINS.md). The compatibility adapter itself
does not provide process supervision. AMUX-44 adds the built-ins' scoped service
contexts and the separate native process context.

The architectural review uses ADAG Design Patterns 0.5.3:
[assessment](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/assess/SKILL.md),
[guidance](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/guide/SKILL.md),
[refactoring](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/refactor/SKILL.md)
and its enterprise baseline. The review covers ownership, failure handling,
authority, compatibility and the changed UI components. Jira holds findings and
verification results. Repository instructions exclude local pattern registries,
generated diagrams, evidence gates and CI runs.

## Why these boundaries

`TrustedPluginAdapter` is an [Adapter](https://www.dofactory.com/net/adapter-design-pattern):
it gives existing Python plugins a versioned description and delegates to their
original implementation. Rewriting those domains would duplicate behavior and
increase migration risk. Changing the original plugin interface would also break
administrator-installed extensions and direct helper calls. The adapter instead
keeps the original instance, bound commands and results. For the five built-ins,
`builtin_context_factory` supplies the named services belonging to that plugin
instead of forwarding the raw runtime context.

Administrator-installed extensions without a built-in service factory retain
their explicitly legacy `Federation` context. Both paths run trusted Python in
the hub process. The descriptor's trust label describes that assumption; it is
not installation attestation or a sandbox. The scoped API prevents accidental
raw-context sharing but does not isolate hostile native code.

`DefinitionService` groups scoped reads and the existing file writer behind one
interface. Its legacy `boardagents` facade keeps HTTP and CLI callers on that same
writer. A second file service or a second database writer would create conflicting
ownership. `DefinitionPlugin` and `TeamPlugin` separate import and selection from
HTTP, approval storage and process launch without introducing such writers.

## Federation contract

The original contract remains in `hub/fed/plugin.py`; the adapter lives in
`hub/fed/plugin_adapter.py`. `Federation.plugins` retains the original objects for
compatibility; built-in Hub and Code-to-Messages calls use named service owners.
`Federation.plugin_adapters` owns the compatibility wrappers used by lifecycle,
event routing, table initialization and panel composition.

| Existing input | Compatible output and owner |
| --- | --- |
| `Param`, `Verb`, plugin `verbs()` | `contribution()` emits schema version `1.0.0`. Compatibility tests validate its output against `contracts/v1/schemas/legacy-plugin-contribution.schema.json`; the adapter checks the original declaration shapes. It preserves command names, parameter names/types/order, required and positional flags, help and `operator_only`. Registration calls `verbs()` once, after every configured module has loaded, and retains the original bound command objects. |
| `handles`, `on_envelope(ctx, env, decision)` | The descriptor lists the exact envelope types. The existing runtime receives messages, validates routing and policy, handles quarantine and duplicates, then forwards the exact admission decision through the adapter. Metadata never grants a subject or approves a message. |
| `start(ctx)` | Called once when the existing runtime loop starts. Failures propagate as before. No replacement supervisor is implied. |
| `on_connect(ctx)` | Called after each connection session created by the outer runtime loop. The NATS client's own reconnect callback keeps its existing behavior. Work consumers and Board watchers belong to the named service and original session until their resources join. |
| `on_tick(ctx)` | Called by the connected runtime loop. The runtime retains its existing per-plugin error handling. |
| `on_local_event(ctx, kind, data)` and `on_revoke(ctx, peer)` | The existing runtime supplies unchanged arguments and owns logging of plugin failures. |
| `panel(ctx)` | `fed_panel` calls the original provider on the database thread. Titles, columns, rows, actions and `None` results remain intact. `panelId` identifies the provider; it does not imply that every plugin returns a panel. |
| `tables` | The descriptor retains every SQL statement, including indexes and triggers. The existing database owner checks the `p_<plugin>_` prefix and initializes them on the hub database thread. |
| `ctx.db`, `ctx.stage`, `ctx.publish`, `ctx.kv`, direct context access | The five built-ins receive frozen contexts with named domain services, not raw hub/store/database/NATS/session handles. Their service owners retain existing transactions, outbox admission, broker permissions and KV ownership. Unmigrated administrator extensions retain their explicitly legacy context. |

The adapter adds no retry, task, acknowledgement, subscription or transaction.
Hook errors and cancellation propagate to the same runtime owner. Descriptor
validation rejects unsupported contract shapes without logging the plugin object
or context. The descriptor contains declarations, not credentials or live panel
data. It is local metadata, not a new NATS wire message or a complete package
manifest.

The built-in service replacements preserve the existing domain owners:

| Plugin | Named services |
| --- | --- |
| Messages | `AgentDirectory`, `LocalMessages`, `FederationPublisher`, `LocalEvents` |
| Work | `FederatedWorkOwner`, `WorkQueueConsumer` |
| Board | `SharedBoardStore`, `BoardProjection`, with `FederationAudit` inside the owner |
| Knowledge | `KnowledgeOwner`, `AgentDirectory`, `LocalMessages` |
| Code | `GitOperations`, `RepositoryDirectory`, `CodeShareOwner`, `FederatedMessages` |

These services preserve deduplication, reservations, claims, grants, result
validation, audit, projections, indexing/outbox transactions and Git ref/SHA
checks. Canceled database or Git work remains owned until its original executor
operation joins; cancellation does not roll back an effect already committed.

The five built-ins retain these contributions. Parameters remain defined once in
their original `verbs()` methods and are compared field by field with `fed_verbs`.

| Plugin | Commands after `fed_<plugin>_` | Received events | Storage and UI ownership |
| --- | --- | --- | --- |
| Messages | `send` | `message`, `handoff` | Existing hub message store and delivery path; inherited empty panel. |
| Work | `add`, `list` | `work`, `work_claim`, `work_grant`, `result` | Existing work records and offer/claim/grant/result protocol; dynamic consumers and work panel. |
| Board | `add`, `list`, `show`, `move`, `assign`, `comment`, `claim` | No envelope handler; existing KV watcher | Authoritative federation KV with compare-and-set writes; `p_board_cards` remains a local mirror. Board panel remains unchanged. |
| Knowledge | `share`, `search`, `recent`, `show` | `knowledge`, plus existing local completion events | `p_knowledge_*` records, full-text index and trigger; knowledge panel. |
| Code | `share`, `fetch`, `list` | `code` | `p_code_*` records and existing Git ref/SHA checks; code panel and Messages handoff helper. |

The optional protected knowledge selection routes those same knowledge commands
through the existing knowledge owner. It retains the original SQLite rows, full-text
index and trigger, outbox IDs, finding notifications and held approvals. Automatic
capture names the exact committed handoff or work/result source; service identity
alone cannot choose an agent's displayed authorship. The client retains its original
operation before a write and queries that operation after an uncertain reply.
Only a confirmed version conflict permits a new attempt with the original input.
Pending automatic captures recover at the existing federation loop boundary,
including while external federation is disabled or disconnected, using current
service permission. Recovery skips a busy original caller and rechecks its pending
record under the session lock. A completed caller's stale recovery snapshot cannot
start another operation. Shutdown joins the original calls and exchanges.

The native TLS check loads private knowledge selection and enrollment files,
starts the real application-session thread, and covers uncertain replies, scoped
reads, the Hub socket and joined shutdown. Its trusted observation lease remains
controlled by the fixture. It does not qualify installed-runtime or attestor
provisioning; the notification/capture fixture still constructs its sessions.

The protected read path preserves search, recent, show and panel values at the
selected repository scope. It refuses oversized results as a whole. A successful
read does not expose the database or grant access to another repository. Selected
policy updates use the enrolled configuration route completed in
[AMUX-627](https://adag-csai.atlassian.net/browse/AMUX-627), preserving the original
source and journal across unshare, owner replacement and reshare. Authenticated remote
self-revoke uses the enrolled control route completed in
[AMUX-628](https://adag-csai.atlassian.net/browse/AMUX-628), retaining the original
event and withdrawing only that peer's selected repository findings. The combined
policy and control configuration can restart from a committed unshare. Its temporary
startup permission validates the original source structure, expires before readiness,
and does not allow normal data access while unshared. An authorized reshare restores
the original source and control receipts, as verified in
[AMUX-640](https://adag-csai.atlassian.net/browse/AMUX-640). The knowledge
mapping passed its combined owner, caller, recovery and native TLS checks in
[AMUX-283](https://adag-csai.atlassian.net/browse/AMUX-283). Other capability mappings
remain tracked separately in AMUX-45.

The CLI (`hub/cli.py`) and MCP server (`hub/fed/mcp.py`) continue to derive tools
from `fed_verbs`. Operator-only filtering and the dashboard's fixed write
allowlist remain in their existing owners. No new panel action bypass is added.

The runtime's receive, guard and routing functions form the existing
[messaging boundary](https://www.enterpriseintegrationpatterns.com/patterns/messaging/MessagingGateway.html).
The named services keep raw JetStream access inside the owning implementation;
they do not expose it in the built-in plugin context. Administrator extensions
on the legacy path remain trusted and unrestricted. Board KV writes are not made
atomic with SQLite, and the adapter does not claim exactly-once effects across
broker, database and Git.

## Definitions, teams and edits

`taskmgmt/definition_team.py` provides two domain interfaces:

- `DefinitionPlugin.import_all` takes explicit project, home and global roots,
  package description and optional parent description. It reuses the parser's
  checked read and retains all `AgentSpec` fields, original bytes, path, scope and
  source checksum in an immutable versioned manifest. The service's
  `legacy-local-markdown` label describes a local import, not a registered or
  authorized package. The existing list/detail HTTP response is built from these
  manifests. Lists expose neither original bytes nor personas.
- `TeamPlugin.propose_legacy` is the production compatibility entry point for
  board recruitment and dispatch selection. It retains the deterministic
  selector's caps, capability rules, dependency behavior, reviewer preference and
  visible gaps. `TeamPlugin.propose` separately accepts explicit admitted
  revisions; passing references is not authentication. The project owner must
  establish that approval before using the stricter interface.

The parser keeps all four discovery directories and rejects duplicate names
across them; scope order never silently selects a duplicate. Unsupported keys
remain visible diagnostics. Malformed, oversized, symlink and FIFO inputs are
refused. The manifest's source, parsed fields and checksum come from the same
bounded read. The parser does not detect every concurrent in-place rewrite;
saved roster revisions and the edit writer provide the later-change checks. See
[`CONTRACTS_agents.md`](CONTRACTS_agents.md) for fields, defaults and limits.

The board owns roster approval. Proposals store the full resolved definition in
the additive `board_roster_definitions` table, keyed to the existing roster row,
with the project root. Approval preserves the row identity and snapshot. Later
definition edits produce a revision notice and never rewrite the approved
persona. The snapshot digest covers resolved defaults as well as source bytes.
Hiring uses the saved definition. Dispatch validates the approved project and
revision and refuses changed definitions rather than substituting a persona.
A hired lead must be stopped and retired before a different revision is proposed.

Existing rows with no saved definition require a deliberate new proposal and
approval. Migration does not invent a historical snapshot. A no-selection legacy
proposal may retain its existing built-in compatibility lead and visible gap;
it cannot adopt an unrelated discovered lead. Explicit UI/CLI selection proposes
a lead through the existing approval workflow.

Tool intent separates requested and denied tool names from names a host can
enforce. Host support never grants access. Until the host supplies enforcement
capabilities, these restrictions are labeled advisory.

The scoped definition service and legacy facade use one process-wide write lock.
The writer checks path ownership, regular-file identity and the expected checksum,
writes a private temporary file, then replaces the target. Canceling the UI delete
confirmation sends no request. Invalid and stale requests fail before mutation.
Once a write is submitted, the service has no in-flight cancellation protocol.
This preserves the existing single-service writer model; it is not a distributed
writer lock. The file mutation and board audit are separate effects, not a
cross-store atomic transaction. A hostile process with the same directory
ownership can still race the final path check; these legacy files are not an
isolation boundary.

`EditIdentity` carries a user/project binding established by trusted composition.
The service rejects a missing or mismatched binding and ignores body-supplied
identity on that interface. Constructing the value does not authenticate anyone.
When an enrolled application host is injected, definition edits use its local
browser session. The HTTP route requires the session cookie, CSRF token and
matching Host and Origin. The session supplies the enrolled human and project;
browser-supplied identity fields are refused. The definition owner rechecks current
membership, the exact definition grant and hard denials before using the existing
file writer. The retained operation records the authenticated identity, effective
actor and project scope. Completion has its own authorization check; an uncertain
outcome keeps its operation ID so it cannot be mistaken for a fresh sign-in failure.

The legacy server without an injected host still has local audit labels; it does
not authenticate an enrolled human. The retained owner's persistent writer fence
prevents that legacy path from writing directories after handoff. Host/Origin
checks, Unix UID and a command-line account alone do not establish identity.
[AMUX-47](https://adag-csai.atlassian.net/browse/AMUX-47) and
[AMUX-50](https://adag-csai.atlassian.net/browse/AMUX-50) own the local identity and
application-host prerequisites. This describes the implemented route; current
verification results and remaining qualification gaps belong in AMUX-41.

## UI composition

The existing `agents.js` and `teams.js` entry points retain synchronous
`ccc:ready` registration. Features under `dashboard/src/features` own requests,
application state and writes. Reusable fields, lead selection, revision notices
and the definition form live under `dashboard/src/components/molecules` and
`organisms`, with explicit public entry points and focused tests. Components
receive values and callbacks; none imports a feature service or performs a
remote request.

Classic scripts preserve the dashboard's existing startup order without adding
a build system or changing event timing. `index.html` loads the exact dependency
order, and the server serves only explicitly allowlisted asset paths. Component
tests and other source files are not public assets. Loading, empty, stale-result,
write-failure and cancellation behavior stay in the feature or component that
owns the interaction.

## Migration and recovery

No live store is copied or cut over by this extraction. The federation originals,
legacy service facade and existing launch paths remain available. Removing an
adapter requires its replacement to preserve the same callers and pass the
relevant compatibility checks, including all five built-ins. Scoped contexts
preserve those owners; they do not authorize a storage cutover or credential
replacement. Package lifecycle and broader identity work have separate owners.

Do not roll the roster code back to an implementation that rereads current files
for approved hires: that would lose the saved-revision guarantee. Keep the
additive snapshot table and use the deliberate proposal/approval workflow to
recover missing or invalid snapshots. No destructive schema downgrade or silent
persona replacement is part of rollback.

Focused tests cover descriptors and hook delegation, module-load order, checked
imports, deterministic roster choices, stored revisions, edit conflicts and
UI interaction. Existing live federation fixtures exercise the original broker,
hub and Git workflows through the adapter. Actual test results and any remaining
gaps belong in AMUX-41 and AMUX-44; this document does not certify the whole
platform or deferred targets.
