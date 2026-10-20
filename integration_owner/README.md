# Managed external effects

`IntegrationOwner` receives signed intent, query, attempt, completion and
reconciliation commands through the actual `AuthorityReader` and `OwnerLedger`
APIs. With an explicitly enrolled provider resolver, it can dispatch fixed Jira,
Confluence or GitHub requests after retaining a unique claim.
`IntegrationService` supplies an effect-specific subscription and signed replies.
The application host composes it from an explicit integration selection after
identity recovery. For GitHub, it restores and checks an explicitly selected
private client pin before opening the integration connection; a selection with
no enrollment remains receipt-only. Its installed launch remains unqualified.
One focused real TLS/JWT broker case verifies the service traffic described below.
There is no managed dashboard caller. The GitHub worker is not qualified against
a real account.

## Host composition and credentials

The host supplies an actual `AuthorityReader`, `OwnerLedger`, `OwnerBinding`,
provider and credential reference. It can also supply `OwnerArtifacts` and an
Atlassian or GitHub resolver. Callers cannot supply verifier callbacks, write callbacks,
secret values or caller-selected subjects. The ledger must enable
`require_completion_budget=True`.

The binding uses `entityKind: effect` and `ownerDomain: integrations`, with a
project scope. The host must enroll the ID returned by
`intent.effect_id(scope, originalOperationId)`. It depends on the original
operation and scope, never on mutable payload content. Changing a target cannot
obtain a second empty aggregate for the same original operation. The receiver
checks matching ledger, subject, organization, hub, project, provider and
credential reference. It cannot provision a caller-requested stream.

`pin_atlassian_config` creates a private pin for an explicitly selected credential
reference, provider, configuration version, file and HTTPS site. The resolver
checks file ownership, permissions, links, identity and exact pinned content.
Configuration changes require deliberate enrollment; the resolver never silently
repins. It supplies private configuration only to the fixed worker. The pin and
configuration are excluded from shared commands, records, replies and reprs.
`write_atlassian_enrollment` explicitly creates private enrollment once and
returns its file digest for the separate host selection. It never replaces an
existing file. `load_atlassian_enrollment` restores that exact pin and checks the
unchanged config without repinning. The application host first verifies the
selected enrollment file's private custody and digest. These private files must
remain outside workspaces. A fresh pin on every restart would discard the account
binding.

`pin_github_client` pins the resolved `gh` executable, its native configuration
directory, `hosts.yml` metadata and the exact present-or-absent state of
`config.yml`. It never reads or copies either configuration file; `gh`
continues to own the credential. The worker removes inherited GitHub token
overrides, selects the pinned configuration directory and `github.com`, and runs
only fixed prepared arguments. Its private enrollment is create-only and can be
restored without repinning. A changed executable or native-store identity is
refused before dispatch.

## Service composition

`IntegrationService.from_enrolled_host` takes the explicit connection,
`LedgerAuthorityReader`, effect binding, provider, credential reference, stream,
stream identity, retention, private history, artifacts, issuer reference, signing
seed, checkpoint path and commit handler. Optional inputs are the enrolled
provider credential resolver and JetStream domain. It constructs the actual strict ledger,
ingress and receiving owner. It does not provision streams, accounts or grants.

`start()` recovers history and verifies the current enrolled service identity and
signing key before subscribing to exactly
`amx.v1.h.<hub>.o.<organization>.integrations.<effect-id>.command`. Only the five
integration commands below are accepted. Requests prove possession through
`EnrolledIngress`; arbitrary envelopes or HTTP actor labels cannot enter this
subscription. Before signing a reply, the service checks both the issuer and
current operation authority against one final authoritative snapshot. It makes
no further awaited call before signing.

The closed signed reply wrapper contains `schemaVersion`, `claims` and
`signature`. Claims contain purpose `agentmux-integration-command-receipt-v1`,
`hubId`, `profileId`, `authorityId`, `issuerRef`, `requestDigest` and the canonical
`integration-effect-reply` as `receipt`. The client-safe
`receipts.verify_receipt`, also used by the server, checks the enrolled key,
exact complete request digest, identity, operation, original digest and attempt.
This wrapper is validated by the service; it has no separate registered schema.
It is an outcome receipt, not a reusable grant. Failures return only unsigned
`integration_outcome_unconfirmed`, which cannot prove rejection or success.

The subscription accepts only a bounded `_INBOX` reply subject matching the
signed request. At most 32 reply tasks remain owned. Cancellation retains the
original startup, subscription allocation, reply publication and drain tasks.
`close()` joins them before closing the provider worker and private history.
Checkpoint export follows the existing owner cadence and requires host commit
acknowledgement. The focused broker case verifies actual intent/query delivery
and signed replies. Checkpoint export and production host startup still require
their own qualification.

## Commands and replies

All five commands have canonical registry entries and actual authority routes
with audience `integration-owner`. Payloads are closed objects.

`integration-intent` contains `effectRef`, `credentialRef`, `action`, `target` and
`contentRef`. References use `common.reference`. The content reference is null or
a complete `common.artifact` with media type
`application/vnd.agentmux.integration-content+json` and size 1–60000 bytes.
Content bytes stay outside shared command history. The owner retrieves them from
its enrolled artifact store and verifies their exact digest before preparation.

| Action | Exact target fields | Content artifact |
| --- | --- | --- |
| `github-repo-create` | `owner`, `name`, `visibility` | Optional description/options |
| `github-issue-create` | `repository` as `owner/name` | Required title/body/labels |
| `jira-create` | `projectKey`, `issueType` | Required summary/description/labels |
| `jira-comment` | `issueKey` | Required comment |
| `jira-transition` | `issueKey`, `transitionId` | None |
| `confluence-create` | `spaceKey`, nullable `parentId` | Required title/storage body |
| `confluence-update` | `spaceKey`, `pageId`, `expectedVersion` | Required title/storage body |

Numeric external IDs remain strings. `expectedVersion` is a positive integer.
Signed operation context carries identity, scope, deadline, expected owner
revision and approval references; payload booleans cannot replace them.

`integration-effect-query` contains `effectRef`, `originalOperationId` and
`originalPayloadDigest`. Its signed operation ID must differ from the original.
It reads original provenance and latest phase from one validated ledger snapshot.

The three lifecycle commands contain exactly `effectRef`, `originalOperationId`,
`originalPayloadDigest` and `attemptOperationId`:

| Command | Implemented behavior |
| --- | --- |
| `integration-attempt-start` | The attempt ID equals this command's operation ID and differs from the original. Require current approval, exact retained intent and owner revision. Prepare the request, conditionally retain `dispatch-claimed`, then recheck authority before starting the fixed worker. Only the instance receiving the original successful claim acknowledgement may start I/O. Replay or recovery of a lost acknowledgement never dispatches. |
| `integration-attempt-complete` | Use a separate operation ID. Join the original owned worker or use its privately retained observation. Append `applied`, `not-dispatched` or `reconciliation-required` according to that observation. The caller cannot submit a receipt or choose success. |
| `integration-effect-reconcile` | Use a separate operation ID. Run only a fixed read for the known Jira issue or Confluence page. A create with a lost remote ID remains unavailable. Retain `reconciliation-required`; a read never permits another write. |

`IntegrationReply.wire_payload()` validates `integration-effect-reply`. Its six
required fields are `operationId`, `originalOperationId`,
`originalPayloadDigest`, `sequence`, nullable `attemptOperationId` and `phase`.
Phases are `absent`, `intent-committed`, `dispatch-claimed`, `applied`,
`not-dispatched` and `reconciliation-required`. Intent retention alone reports
`intent-committed`, never external success. The host still must authenticate
reply transport and check request correlation before delivery.

## Authority, retention and worker ownership

Actual authority reads check the signed issuer, transport, actor, membership,
deny rules, current grants, exact resource and expiry. Intent and attempt-start
require current approval bound to the exact operation, payload digest, audience,
grant and expected revision. Query and lifecycle admission also check original
intent authority. Direct plugin credentials remain refused until native
capability admission binds the plugin declaration, generation and parent.

The receiver repeats authority checks before append, dispatch and reply
disclosure. It passes `valid_until` to the ledger for the conditional commit.
Each lifecycle record preserves the original effect, target, credential and
artifact references, operation identity and digest. Each new record carries its
own signed command and authorization audit. The full history reader checks those
links and refuses malformed transitions or observations for another target.

Completion capacity is reserved through the actual strict ledger API: intent
reserves three remaining records, the claim two, uncertainty one, and terminal
completion zero. A lost append acknowledgement is queried using the same
operation and digest. Unresolved recovery does not authorize a second append or
write. Conditional append and reservation behavior still need qualification
against the production broker under crash, capacity and recovery conditions;
offline broker fault controls do not prove those cases.

Each provider worker owns the exact prepared request, original thread task and
observation. Cancelling a waiter leaves that task owned. The worker rechecks its
original enrollment pin after the awaited dispatch claim and again at the queued
transport boundary. A changed enrollment before a write produces
`not-dispatched`; a changed enrollment before reconciliation produces an
unavailable read observation. Neither case creates a replacement enrollment.
The GitHub process owner drains bounded output, discards diagnostics and joins the
original process group on timeout or overflow. If the child-side exec report says
the exact pinned executable is missing, the attempt is retained as
`not-dispatched`. Other process-constructor errors and failures after a child may
have started remain uncertain.
Completion releases the task only after the exact observation is retained.
Shutdown waits for original tasks; it does not infer that cancelling a Python
waiter stopped remote work. Capacity is eight outstanding tasks/observations.

| Effect | Required acknowledged identity |
| --- | --- |
| Jira create | Requested project and returned issue key. |
| Jira comment | Original issue key and returned positive comment ID. |
| Jira transition | Original issue key/transition ID and successful HTTP acknowledgement; an empty 204 is valid. |
| Confluence create/update | Exact space, title, positive page ID and expected new version; updates preserve the original page ID. |
| GitHub repository create | Exact requested owner and repository name from a matching `github.com` URL. |
| GitHub issue create | Exact requested repository and positive issue number from a matching `github.com` URL. |

Observations bind the original operation, digest and attempt. They exclude raw
errors, credentials and content. Transport loss or malformed receipts remain
uncertain. Reconciliation observations cannot establish success or authorize a
retry. Repository reconciliation accepts GitHub's canonical name casing only
for the exact requested `owner/name` and retains the requested identity. A late
acknowledgement from the original owned worker can still complete
its attempt after an intervening reconciliation. There is no automatic retry or
compensating-write route.

## Qualification and missing callers

Focused offline tests cover signed admission, revocation, exact payloads,
configuration pinning, immutable lifecycle history, completion reservation,
replay and lost acknowledgements. Two temporary local HTTPS tests use the actual
thread and HTTP path: cancellation preserves worker ownership, and a lost write
reply leads to a read without another write. All fixture processes, threads,
handlers and worker tasks were joined. These tests use synthetic credentials and
local fixtures; no external provider account is qualified.

`platform/deployment/integration_service_live_test.go` reuses the existing
disposable Go TLS/JWT fixture and launches `integration_owner.live_broker`.
Its focused case passed with the actual service, private history, separate
identity connection and exact account-signed service credential. It retained one
approved intent, verified a signed effect query, allowed reads of the selected
effect stream, and denied authority/other-project stream reads and publication
to another project's ledger. No provider worker was configured. The service,
clients, original process waits, output readers and broker were joined.

That case exposed the broker's domain rewrite before permission checks. Named
domain credentials now require both the selected-domain and canonical API forms
for each already-selected stream's `STREAM.INFO` and `STREAM.MSG.GET`; unrelated
streams remain excluded. This does not qualify
installed launch, provider accounts, restart recovery or checkpoint export.

Remaining production work includes host installation and qualification of the
service subscription and authenticated reply transport, operator enrollment and
recovery of private credential pins, stream/account provisioning, verified
content publication, dashboard/tool callers, actual native-client/account
qualification, and broker crash/recovery qualification. The legacy entry points
`Handler.ticket_action`, `Handler.github_endpoint`, `github_login_service` and
authentication selection routes do not become managed callers merely because
this receiver exists. Real provider account/model/client selection and commercial
distribution approval remain separate acceptance criteria. Log publication still
requires explicit authorization for the content being published.
