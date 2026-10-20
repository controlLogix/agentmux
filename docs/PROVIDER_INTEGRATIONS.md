# Provider and external-service integrations

The beta target is native macOS ARM64. The local setup helpers preserve existing
provider choices and credential owners. A saved setting, a present credential
file, or a successful format check does not establish a working provider session.
Live authentication, refresh, model access and actual worker selection need
separate qualification with the intended native client and account.

Development scope, acceptance criteria and review outcomes belong to
[AMUX-66](https://adag-csai.atlassian.net/browse/AMUX-66) and its
[owning epic](https://adag-csai.atlassian.net/browse/AMUX-7). This guide describes
the available interfaces and their limits; it is not a development tracker.

## Retained authentication methods

The manifest in `dashboard/auth.json` retains these eight identifiers. Its
versioned capability fields distinguish local configuration, live authentication
and worker selection. No client version is currently declared qualified by that
manifest. Existing user selections are not changed by these declarations.

| Method ID | Credential owner | Local configuration and remaining limit |
| --- | --- | --- |
| `codex-chatgpt` | Codex native login store | Keep the user's own native login. Agentmux does not copy or inspect its token. Subscription access is distinct from API billing. |
| `codex-api-key` | Operator's private local store; OpenAI API organization | `OPENAI_API_KEY` is a name-only reference outside the secret store. Presence does not prove access, refresh or budget. |
| `codex-custom` | Operator's selected endpoint and private local store | Preserve endpoint, model and generated profile. Uses the Responses API and `CODEX_CUSTOM_API_KEY`. A chat-completions-only server is not equivalent. Existing profiles are not overwritten. |
| `claude-oauth` | Claude Code native login store | Use Anthropic's own sign-in flow and the user's unmodified client. A Windows/WSL credential path does not qualify macOS. |
| `claude-api-key` | Operator's private local store; Anthropic API account | `ANTHROPIC_API_KEY` remains local. API-key presence does not prove model access. |
| `claude-vertex` | Google Application Default Credentials | Preserve project and region. Agentmux does not copy the ADC credential into its own store. Cloud permissions, model terms and billing still apply. |
| `grok-device-code` | The selected Grok client's native login store | Retain the method and existing selection. The native client's device-code behavior and status format remain unqualified; a file check is insufficient. |
| `grok-api-key` | Operator's private local store; xAI API account | Preserve `XAI_API_KEY`. The offline check validates local input only and makes no inference request. |

Pi and Claude Desktop use their native credential owners as described in
[native client setup](NATIVE_CLIENT_SETUP.md). They are not silently assigned a
new method identifier by this compatibility manifest.

## Local setup and recovery

`taskmgmt/setup_auth.py` separates provider settings, method settings and the active
method for each CLI. Legacy flat settings remain under `_v1_settings`; if both
legacy fields already exist, both are retained for operator review. Unknown keys,
unrelated environment entries and comments remain intact. The helper refuses
unsupported syntax rather than executing it.

Secrets are entered through a terminal that can hide input. They are not accepted
as command-line values, printed back, hashed for display, or sent to the dashboard.
Local credential references contain a provider and variable name, never a value.
Private files must be owned regular files without links and use private modes.
Writes use a temporary private file and check that the selected original has not
changed. This does not lock out an unrelated external editor.

`enter-key.sh` updates the xAI credential entry through the literal parser;
it preserves unrelated entries. `verify-grok.sh` checks local configuration and
reports live access as unverified. Neither script sources the environment file
or makes a model request. The launcher's remaining shell-source path still needs
replacement before it can claim the same boundary for worker execution.

`add-allow-rule.py` discovers this checkout and prints the exact proposed rule.
Only `--apply EXACT_RULE` applies that displayed rule. The helper preserves other
settings and retains a private backup when it changes an existing document.
The rule is an operator permission choice; its presence is not platform authority.

On a malformed file, unsafe mode, link or concurrent edit, setup leaves the
original in place. Review it privately, preserve unrelated settings, then rerun
the same setup command. Rotate or refresh credentials through their original
provider or native client. Do not copy native login tokens between configuration
homes. Restore only the intended local setting or reviewed backup; do not reset
an entire client profile to repair one provider.

The legacy `dashboard/verify_model_switch.sh` is not a qualified diagnostic: it
uses the operator's home, kills a named agent, starts a worker and prints its
launch line. Do not use it as an offline check. Actual selection qualification
requires an explicitly approved isolated launch, the intended client version,
an allowed model and a capped provider budget. Stored preferences alone cannot
pass that check.

## Bedrock compatibility

The reconstructed `taskmgmt/bedrock_gateway.py` and preserved CPython 3.12
bytecode remain the compatibility reference. The repair keeps the translation
path and adds a separate local gateway credential, loopback binding, model
restrictions, bounded parsing and fixed errors. Anonymous inference is refused.
The local credential does not establish project or tenant authority.

The gateway's `AGENTMUX_BEDROCK_GATEWAY_TOKEN` must be different from its upstream
`AWS_BEARER_TOKEN_BEDROCK`. A custom Codex client uses the same local gateway token
through `CODEX_CUSTOM_API_KEY`; the AWS credential belongs only to the gateway.
Do not put either value in a profile, command argument or shared record.

This is a retained local compatibility path, not a qualified managed provider.
Existing documentation names `codex-bedrock`, `claude-bedrock`, provider `bedrock`
and scripts such as `start_gateway.sh`, `setup_bedrock_codex.sh` and
`probe_bedrock.sh`. Those are not available method IDs or executable setup paths
in the current manifest/checkout. Do not replace an existing selection with an
invented method. See [the gateway compatibility guide](BEDROCK_COMPATIBILITY.md)
for the exact supported request, stream and fixture boundaries.

Repair is the proposed direction for the retained path. Keeping its anonymous
boundary is unacceptable; deleting it would discard the compatibility reference.
Direct native Bedrock support is a separate alternative that requires client and
model qualification before replacing this adapter. Enabling managed use still
requires the platform authority and durable operation boundaries below. A source
comparison with bytecode is meaningful only on its matching CPython 3.12 runtime;
an incompatible interpreter must report that comparison as skipped.

## GitHub, Jira and Confluence

GitHub credentials remain with `gh`. The helpers pin operations to `github.com`,
build fixed argument lists, send issue bodies through standard input and validate
returned repository or issue URLs against the requested target. Git observations
retain local repository identity and tracking counts. Counts based on local refs
may be stale; refreshing the panel does not fetch or merge Git data. Missing
GitHub data does not erase usable local Git observations.

A GitHub login retains the original process through cancellation and its wait.
While cleanup is incomplete, another login or logout is refused. Cancellation
cannot prove that credentials were never written: check the current native
account before retrying. Native process cleanup and browser behavior require the
isolated process tests as well as offline tests.

Jira Cloud uses email plus API token over HTTPS; Server/Data Center uses a PAT.
The local Atlassian configuration remains a private owner-held file. The client
refuses credential-bearing URLs, redirects and malformed target identifiers. It
limits response size and reports fixed HTTP or connection errors without server
bodies. Cloud ADF bodies, Server text bodies and empty 204 responses are retained.

Issue creation needs a returned key in the selected project. Confluence lookup
must return an unambiguous page with its title, retained ID and usable version;
updates use that ID and the next version. A missing or paginated lookup is not
permission to create another page. The receipt must match the title, type, space
and expected version, and an update must retain its page ID. These checks follow
the [Cloud content response](https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content/)
and [Data Center content response](https://developer.atlassian.com/server/confluence/rest/v9224/api-group-content-resource/).
Log exports accept a bounded regular file in the selected log directory, refuse
links and strip terminal controls before forming Jira or Confluence content.
Log export still needs explicit authorization for the content being published.

These helpers classify a lost, timed-out or malformed write reply as
`OutcomeUnknown`. They do not retry automatically. That classification does not
prevent a second caller from repeating the operation. Before retrying, the
external-effect owner must reconcile the exact operation and remote target.
An in-memory cache, a title lookup, or a browser confirmation is insufficient.
Stopping a worker or restoring a local file must never trigger an unconditional
remote transition, comment, page update or compensating write.

## Managed integration boundary

The current helpers and dashboard routes are legacy interfaces. They do not yet
provide the following required managed tool-plugin boundary:

1. Authenticate every call using the signed platform envelope and current grants.
   Bind user, project, provider/account, target and operation to that decision.
   Request-supplied actor names and `confirm: true` describe intent only.
2. Require current approval for the exact external write and resolve credential
   references inside the owning service. Keep secret values, raw native output
   and private reasoning out of arguments, shared history and NATS records.
3. Persist the operation identity, intended effect and outcome in the durable
   owner before dispatch. Reconcile lost replies and restart recovery before
   allowing another attempt; do not retry an uncertain external write.
4. Carry the admitted provider selection into each newly launched worker and
   report unsupported methods honestly. Scope observations and cached results to
   the admitted user, project and repository; label their freshness.

The identity, storage and capability owners must implement those contracts before
the helpers can be registered as managed integrations. The dashboard routes
`Handler.ticket_action`, `Handler.github_endpoint`, `github_login_service` and
the authentication selection routes need those owners. GitHub UI code also needs
the finishing/cancellation state and stale-ref label. Callback substitutes or
local allow booleans cannot stand in for the missing authority.

The [integration receiving adapter](../integration_owner/README.md) implements
signed intent, query, attempt, completion and reconciliation against the actual
authority and ledger APIs. An explicitly enrolled Atlassian worker can dispatch
after a durable claim, retain its own observation and perform fixed read-only
reconciliation. Shared contracts and authority routes are present. Offline tests
cover signed admission and broker fault controls; two local HTTPS tests cover
actual thread ownership and lost replies. These tests qualify no external account.
An effect-specific service subscription and signed reply verifier are implemented
with offline coverage through actual ingress, authority, ledger and private
history. The application host composes the selected service and restores a
privately stored config pin without repinning. One focused real TLS/JWT broker
test passed for retained intent, signed query replies, own-stream access and
denial of unrelated streams/publications using exact service credentials.
It configured no provider worker. Installed launch, operator enrollment/recovery,
dashboard/tool callers, managed GitHub worker ownership and broker crash/recovery
qualification remain required.

## Terms and distribution

The following primary-source review was made on October 16, 2026. It distinguishes
customer-owned native login from a product that intermediates provider access.
It does not establish that a paid distribution, account, model or order is
approved. Recheck the applicable agreement and model terms before that claim.

| Integration | Distribution constraint |
| --- | --- |
| OpenAI | The Services Agreement permits API integration into customer applications, subject to its terms. ChatGPT sign-in and API credentials apply different account policies; native subscription login is not an API redistribution grant. [Services Agreement](https://openai.com/policies/services-agreement/), [authentication](https://learn.chatgpt.com/docs/auth). |
| Anthropic | Commercial API terms permit customer products subject to their conditions. Claude's native sign-in flow may serve an end user's unmodified client; developers must not collect or intermediate Claude.ai credentials or offer that login as their own application authentication. Product inference should use API keys or a supported cloud provider. [Commercial Terms](https://www.anthropic.com/legal/commercial-terms), [Claude Code credential rules](https://code.claude.com/docs/en/legal-and-compliance). |
| xAI | Enterprise terms cover API integrations distributed as bundled services, with customer responsibility for downstream use. Consumer Grok access has separate terms. A retained device-code method does not establish enterprise/API rights. [Enterprise terms](https://x.ai/legal/terms-of-service-enterprise). |
| Google Vertex AI | Cloud service terms and separate model/provider terms apply. Review the selected model and offering before distribution; a valid ADC credential establishes neither model permission nor redistribution rights. [Google service terms](https://cloud.google.com/terms/service-terms). |
| AWS Bedrock | AWS terms incorporate third-party model terms and Marketplace conditions for applicable models. Some models have abuse-detection retention, so do not promise universal zero retention. Preserve provider provenance and attribution requirements. [AWS section 50.12](https://aws.amazon.com/service-terms/), [third-party model terms](https://aws.amazon.com/legal/bedrock/third-party-models/). |
| GitHub | API use through a third-party product is covered by GitHub's terms and rate restrictions. Tokens cannot be shared to evade rate limits; high-throughput access or service resale may require another arrangement. `gh` ownership does not grant redistribution rights. [GitHub API terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#h-api-terms). |
| Atlassian Cloud | Basic API-token auth is intended for scripts/manual calls. Atlassian says apps collecting customer API tokens or directing customers to create individual 3LO apps do not meet its cloud-app requirements; it recommends one distributable OAuth 3LO app. Preserving local compatibility does not qualify the current token flow for distribution. Server/Data Center rights and deployment terms need separate review. [Atlassian auth guidance](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/). |
| Custom endpoints | The selected host, model license, upstream agreement, retention and authentication rules govern. OpenAI-compatible request syntax alone establishes none of those rights. |
