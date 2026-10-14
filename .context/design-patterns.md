# Design pattern context

This registry records how, where, and why approved Dofactory and Enterprise Integration Patterns are used in this repository. Keep historical entries and transition their status rather than deleting them.

<!-- design-patterns-registry:v1 -->
```json
{
  "schemaVersion": "1.0.0",
  "lastReviewed": "2026-10-14",
  "entries": [
    {
      "id": "FED-01",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Messaging Bridge",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/MessagingBridge.html",
      "referenceDepth": "full-public-reference",
      "how": "Each hub's local messaging (hub.db messages/work_items) is bridged to NATS subjects: TM-218's core-NATS Bridge for one operator's nodes, and EP-032's Federation runtime (JetStream) for other people's hubs.",
      "why": "Agents keep the local hub protocol; crossing to another hub or person must not change how an agent posts or claims.",
      "tradeoffs": "Two bridges coexist (single-operator nats_url and cross-user federation). Simpler alternative: one shared broker for every hub, rejected because it removes local offline operation and per-person trust.",
      "locations": [
        {
          "path": "hub/bridge.py",
          "symbol": "Bridge"
        },
        {
          "path": "hub/fed/runtime.py",
          "symbol": "Federation"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py",
        "hub/tests/test_nats_federation.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-02",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Transactional Client",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/TransactionalClient.html",
      "referenceDepth": "full-public-reference",
      "how": "Work offer creation, incoming attribution/request, origin reservation/grant and result staging each have one SQLite commit boundary. Store migration 5 records a durable return obligation with terminal state; the work plugin retries staging it into the existing NATS outbox.",
      "why": "A crash must never publish something that did not happen or lose something that did (FEDERATION.md 8).",
      "tradeoffs": "At-least-once on the wire, so receivers must be idempotent (FED-04). Alternative: publish directly from the verb, rejected - loses messages on disconnect. The additional claim/grant exchange costs a round trip; new execution waits for its origin. Granted work stays reserved through disconnection.",
      "locations": [
        {
          "path": "hub/fed/runtime.py",
          "symbol": "Federation.stage"
        },
        {
          "path": "hub/fed/ledger.py",
          "symbol": "outbox_add"
        },
        {
          "path": "hub/store.py",
          "symbol": "Store._outbox"
        },
        {
          "path": "hub/fed/plugins/work.py",
          "symbol": "Work"
        },
        {
          "path": "hub/store.py",
          "symbol": "MIGRATIONS"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py",
        "hub/tests/test_governance.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md",
        "docs/planning/2026-10-09/governance-repairs.md"
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "Repairs for six explicitly authorized baseline findings",
          "previous": {
            "how": "Plugins write the outbox row (fed_outbox) and its audit row in the same SQLite transaction as the state change; the runtime publishes with a JetStream ack and only then marks the row sent.",
            "why": "A crash must never publish something that did not happen or lose something that did (FEDERATION.md 8).",
            "tradeoffs": "At-least-once on the wire, so receivers must be idempotent (FED-04). Alternative: publish directly from the verb, rejected - loses messages on disconnect."
          }
        }
      ]
    },
    {
      "id": "FED-03",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Guaranteed Delivery",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/GuaranteedMessaging.html",
      "referenceDepth": "full-public-reference",
      "how": "AM_MSG, AM_WORK and AM_SHARE are file-backed JetStream streams (R3 on the cluster) with a 2-minute duplicate window; messages to an offline peer wait in the stream.",
      "why": "Interview requirement F7: things sent while a peer is offline drain when it reconnects.",
      "tradeoffs": "Needs the cluster's storage and an admin to provision streams. Alternative: core NATS plus local outboxes only, rejected - nothing survives the receiver being offline.",
      "locations": [
        {
          "path": "hub/fed/conn.py",
          "symbol": "STREAMS"
        },
        {
          "path": "hub/fed/admin.py",
          "symbol": "provision"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-04",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Idempotent Receiver",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/IdempotentReceiver.html",
      "referenceDepth": "full-public-reference",
      "how": "Incoming work also deduplicates by origin peer, origin node and immutable offer ID inside its owning transaction. A selected execution/grant and stable result ID survive retries beyond the broker deduplication window.",
      "why": "JetStream redelivers after ack_wait and the outbox is at-least-once (FED-02).",
      "tradeoffs": "fed_seen grows with traffic (pruning is future work). Alternative: exactly-once publishing, not available end to end. Broker acknowledgment alone cannot prevent duplicate execution across consumers; the origin grant is required before readiness.",
      "locations": [
        {
          "path": "hub/fed/runtime.py",
          "symbol": "Federation.receive"
        },
        {
          "path": "hub/fed/ledger.py",
          "symbol": "seen"
        },
        {
          "path": "hub/fed/plugins/work.py",
          "symbol": "Work"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py",
        "hub/tests/test_governance.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md",
        "docs/planning/2026-10-09/governance-repairs.md"
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "Repairs for six explicitly authorized baseline findings",
          "previous": {
            "how": "Every inbound envelope id is recorded in fed_seen after its ingest commits; redeliveries are acked and skipped. Publishes carry Nats-Msg-Id so the stream also drops republished outbox rows.",
            "why": "JetStream redelivers after ack_wait and the outbox is at-least-once (FED-02).",
            "tradeoffs": "fed_seen grows with traffic (pruning is future work). Alternative: exactly-once publishing, not available end to end."
          }
        }
      ]
    },
    {
      "id": "FED-05",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Durable Subscriber",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/DurableSubscription.html",
      "referenceDepth": "full-public-reference",
      "how": "Each node binds durable pull consumers msg_<peer>_<node> (AM_MSG) and share_<peer>_<node> (AM_SHARE) and acks explicitly.",
      "why": "A node that restarts must resume where it stopped, not miss or replay the whole stream.",
      "tradeoffs": "Consumers accumulate on the server per node; removing a node needs consumer cleanup. Alternative: ephemeral subscriptions, rejected - lose traffic across restarts.",
      "locations": [
        {
          "path": "hub/fed/runtime.py",
          "symbol": "Federation._bind_core"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-06",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Competing Consumers",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/CompetingConsumers.html",
      "referenceDepth": "full-public-reference",
      "how": "V3 offers use am.work.<peer>.<rid>.<role>.v3 and work3_<peer>_<rid>_<role> consumers. Pullers honor repository scope, capacity and publisher trust. A receiver stages a claim while blocked; the origin selects one executor before any receiver becomes ready.",
      "why": "First claim wins across people: exactly one hub, then exactly one agent, does each item.",
      "tradeoffs": "One consumer per (publisher, repo, role). Hubs only pull from trusted publishers (A19), so an untrusted hub cannot swallow work. Alternative: per-subject queue groups (TM-218), rejected - no persistence. Old exact-filter consumers cannot swallow v3 offers. Redelivery can create another blocked candidate, but only the origin-selected candidate may execute. Legacy in-flight work needs explicit reconciliation.",
      "locations": [
        {
          "path": "hub/fed/plugins/work.py",
          "symbol": "Work.on_tick"
        },
        {
          "path": "hub/fed/plugins/work.py",
          "symbol": "Work"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py",
        "hub/tests/test_governance.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md",
        "docs/planning/2026-10-09/governance-repairs.md"
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "Repairs for six explicitly authorized baseline findings",
          "previous": {
            "how": "Federated role work goes to a work-queue stream; every hub that can serve (rid, role) pulls from one shared durable consumer per publisher, work_<from>_<rid>_<role>, only when it has idle capacity and trusts the publisher.",
            "why": "First claim wins across people: exactly one hub, then exactly one agent, does each item.",
            "tradeoffs": "One consumer per (publisher, repo, role). Hubs only pull from trusted publishers (A19), so an untrusted hub cannot swallow work. Alternative: per-subject queue groups (TM-218), rejected - no persistence."
          }
        }
      ]
    },
    {
      "id": "FED-07",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Message Filter",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/Filter.html",
      "referenceDepth": "full-public-reference",
      "how": "Validate subject sender, plane, destination, repository and role against the envelope before policy and dispatch. Outgoing staging and control reception validate the same route. Old work protocols are quarantined and cannot bypass the v3 grant by operator approval.",
      "why": "Interview F4/F5: per-peer trust and per-repo opt-in; F11: remote work never triggers privileged tools.",
      "tradeoffs": "Policy lives in each hub, so the circle (account) is the confidentiality boundary (A7). Alternative: server-side per-repo ACLs, deferred - needs JWT reissue on every share change. This authenticates the peer through broker credentials, not independent nodes inside a peer. Semantic task/equipment safety remains a separate boundary.",
      "locations": [
        {
          "path": "hub/fed/guard.py",
          "symbol": "inbound"
        },
        {
          "path": "hub/fed/guard.py",
          "symbol": "outbound"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_unit.py",
        "hub/tests/test_fed_live.py",
        "hub/tests/test_governance.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md",
        "docs/planning/2026-10-09/governance-repairs.md"
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "Repairs for six explicitly authorized baseline findings",
          "previous": {
            "how": "Inbound: drop malformed, spoofed (payload sender differs from the server-enforced subject token), self, unshared-rid and denied-peer traffic; quarantine approve-trust and privileged work. Outbound: refuse repos not shared with the recipient.",
            "why": "Interview F4/F5: per-peer trust and per-repo opt-in; F11: remote work never triggers privileged tools.",
            "tradeoffs": "Policy lives in each hub, so the circle (account) is the confidentiality boundary (A7). Alternative: server-side per-repo ACLs, deferred - needs JWT reissue on every share change."
          }
        }
      ]
    },
    {
      "id": "FED-08",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Content Filter",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/ContentFilter.html",
      "referenceDepth": "full-public-reference",
      "how": "Every string in every outbound payload passes through redact.scrub: private keys, nkey seeds and creds block the publish; tokens, keys and secret assignments are replaced with [REDACTED:<kind>].",
      "why": "Interview F11: secret redaction before anything leaves the hub.",
      "tradeoffs": "Pattern-based: false positives redact harmless text, novel secret formats pass. Alternative: no auto-share of free text, rejected - the user asked for free sharing.",
      "locations": [
        {
          "path": "hub/fed/redact.py",
          "symbol": "scrub"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_unit.py",
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-09",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Envelope Wrapper",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/EnvelopeWrapper.html",
      "referenceDepth": "full-public-reference",
      "how": "Remote text typed into an agent's context is wrapped: a one-line header for auto-trust peers, and a REMOTE DATA ... END REMOTE DATA frame for flag/approve trust.",
      "why": "A peer's message must reach the agent as information, not as instructions to obey (prompt-injection boundary).",
      "tradeoffs": "A frame is advice to the model, not enforcement; enforcement is FED-07 and the privileged gate hook.",
      "locations": [
        {
          "path": "hub/fed/guard.py",
          "symbol": "wrap"
        },
        {
          "path": "hub/fed/plugins/messages.py",
          "symbol": "Messages.on_envelope"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_unit.py",
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-10",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Canonical Data Model",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/CanonicalDataModel.html",
      "referenceDepth": "full-public-reference",
      "how": "Non-work messages remain envelope v2; work, work_claim, work_grant and result use v3. The work subject suffix isolates incompatible consumers, and work data carries immutable offer identity/digest plus origin node and execution/grant references.",
      "why": "Interview F6: two people's differently named clones of one repo must line up.",
      "tradeoffs": "Every plugin must translate at its edge. Alternative: agree on shared names, rejected in the interview. Version isolation prevents unsafe fallback. Upgrades preserve old evidence but require draining or reconciling legacy work rather than fabricating missing authorization.",
      "locations": [
        {
          "path": "hub/fed/envelope.py",
          "symbol": "make"
        },
        {
          "path": "hub/fed/policy.py",
          "symbol": "rid_for_remote"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_unit.py",
        "hub/tests/test_fed_live.py",
        "hub/tests/test_governance.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md",
        "docs/planning/2026-10-09/governance-repairs.md"
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "Repairs for six explicitly authorized baseline findings",
          "previous": {
            "how": "Envelope v2 {v,id,type,from,node,rid,to,at,data} and the repo identity rid = r + sha256(normalized remote)[:12]; local repo names are translated to and from rids at the edge.",
            "why": "Interview F6: two people's differently named clones of one repo must line up.",
            "tradeoffs": "Every plugin must translate at its edge. Alternative: agree on shared names, rejected in the interview."
          }
        }
      ]
    },
    {
      "id": "FED-11",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Claim Check",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/StoreInLibrary.html",
      "referenceDepth": "full-public-reference",
      "how": "Code is pushed to the shared remote as refs/agentmux/<peer>/<slug>; only the pointer (ref, sha, base, files, stat) travels on NATS, and fetch verifies the sha.",
      "why": "Interview F8: share code through git refs; payloads stay small and reviewable.",
      "tradeoffs": "Needs a remote both sides can reach. Alternative: patches in an object store, rejected in the interview.",
      "locations": [
        {
          "path": "hub/fed/plugins/code.py",
          "symbol": "Code.v_share"
        },
        {
          "path": "hub/fed/plugins/code.py",
          "symbol": "Code.v_fetch"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-12",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Control Bus",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/ControlBus.html",
      "referenceDepth": "full-public-reference",
      "how": "am.ctl.<peer> carries the kill switch's revoke notice; receivers cancel unclaimed work from that peer and mark its cards and findings withdrawn. The kill state persists in fed_state.",
      "why": "Interview follow-up: a kill switch that disconnects and revokes outstanding shares.",
      "tradeoffs": "Core NATS (not persisted): a peer offline at revoke time misses the notice and only sees its absence. Alternative: a persisted control stream, possible later.",
      "locations": [
        {
          "path": "hub/fed/runtime.py",
          "symbol": "_v_kill"
        },
        {
          "path": "hub/fed/runtime.py",
          "symbol": "Federation._on_ctl"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-13",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Message Store",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/MessageStore.html",
      "referenceDepth": "full-public-reference",
      "how": "fed_audit records every inbound and outbound cross-user payload: direction, plane, peer, rid, subject, id, sha256, size, decision and reason - never the redacted values.",
      "why": "Interview F11: full audit log of what crossed and why.",
      "tradeoffs": "Grows without pruning yet. Alternative: logs only, rejected - not queryable from the dashboard.",
      "locations": [
        {
          "path": "hub/fed/ledger.py",
          "symbol": "audit"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-14",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Shared Database",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/SharedDataBaseIntegration.html",
      "referenceDepth": "full-public-reference",
      "how": "The shared board is the JetStream KV bucket am_board; every change is a compare-and-set on the card revision, and each hub mirrors cards for its shared repos into p_board_cards.",
      "why": "Interview: a shared central board, CAS.",
      "tradeoffs": "Writes need the connection (reads are local). Alternative: owner-authoritative replicas, rejected in the interview.",
      "locations": [
        {
          "path": "hub/fed/plugins/board.py",
          "symbol": "Board._write"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "FED-15",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Messaging Gateway",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/MessagingGateway.html",
      "referenceDepth": "full-public-reference",
      "how": "Agents never see NATS: the CLI (agentmux hub fed ...) and the stdio MCP server expose verbs generated from one registry and call the hub socket. The existing Windows launcher forwards explicit agent hub commands into the selected WSL distribution and binary. Per-pane token files identify callbacks to the existing loopback TCP hub; callback admission validates explicit selection and scoped home before launch and forbids lifecycle verbs before side effects. A maintained legacy orchestration package is now planned under plugins/agentmux-orchestration: installed skills select the existing runtime through an explicit binding; roster MCP translates read calls to existing dashboard endpoints. Pre-tool checks preserve current product policy as defense in depth. No package location is marked applied before implementation and review. The maintained legacy package now applies the planned gateway at plugins/agentmux-orchestration/bin/agentmux-plugin and lib: bounded GET-only dashboard access, newline roster JSON-RPC, and conservative pre-tool observations. skills/agent-config/scripts/runtime.py forwards a declared command allowlist into the explicitly selected existing runtime using literal argv. Its nine guides preserve existing workflow contracts. Native Windows hook integration remains P06-unqualified.",
      "why": "Interview F10: CLI canonical, thin MCP wrapper. Windows-owned clients cannot retain Linux process ancestry when returning through WSL, so authenticated per-agent gateway context is required to preserve existing hub identity. Original external plugin source is missing, leaving20baseline tests skipped; current source contracts and nine historical workflow names support an explicitly maintained replacement. The original external package was unavailable; maintained source restores the existing observable client workflows without duplicating runtime business rules.",
      "tradeoffs": "The MCP server is hand-written (A18). Alternative: agents use nats directly, rejected - would bypass identity and guardrails. An explicit callback context and Windows Python 3 dependency add setup work; normal operator defaults remain separate. A direct unauthenticated callback or ancestry fallback is simpler but loses agent identity. Tests qualify bounded launcher arguments and real local agent tokens; automatic provider forwarding and authenticated concurrent provider workflows remain unqualified. Recovery is not claimed. Vendoring preserves reviewed command workflows but adds hook/parser, packaging and provenance maintenance; leaving the package external is simpler but currently prevents required preservation checks. Hooks do not replace authoritative runtime authorization or provide complete shell containment. This is newly maintained replacement source with unknown original prose/metadata; unchanged twenty compatibility tests alone cannot prove historical parity. Additional real runtime, path/parser, HTTP and protocol checks are required. The live-definition hook has a preflight race and is absent from direct HTTP mutation enforcement; neither hooks nor this unauthenticated legacy API are production authorization.",
      "locations": [
        {
          "path": "hub/fed/mcp.py",
          "symbol": "handle"
        },
        {
          "path": "hub/cli.py",
          "symbol": "fed_main"
        },
        {
          "path": "agentmux_windows.py",
          "symbol": "command"
        },
        {
          "path": "hub/cli.py",
          "symbol": "main"
        },
        {
          "path": "agentmux.sh",
          "symbol": "cmd_spawn"
        },
        {
          "path": "hub/server.py",
          "symbol": "Hub.spawn"
        },
        {
          "path": "plugins/agentmux-orchestration/bin/agentmux-plugin",
          "symbol": "main"
        },
        {
          "path": "plugins/agentmux-orchestration/lib/gateway.py",
          "symbol": "read"
        },
        {
          "path": "plugins/agentmux-orchestration/lib/roster_mcp.py",
          "symbol": "serve"
        },
        {
          "path": "plugins/agentmux-orchestration/lib/policy.py",
          "symbol": "shell"
        },
        {
          "path": "plugins/agentmux-orchestration/skills/agent-config/scripts/runtime.py",
          "symbol": "main"
        },
        {
          "path": "plugins/agentmux-orchestration/lib/policy.py",
          "symbol": "edit"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_unit.py",
        "hub/tests/test_windows_callbacks.py",
        "docs/planning/2026-10-09/delivery/evidence/P01/windows-callback-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/plugin-restoration/parent-review.json"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ],
      "revisions": [
        {
          "date": "2026-10-09",
          "reason": "P01 existing Windows callback preservation repair; language-neutral plugin adapter remains planned for P06.",
          "previous": {
            "how": "Agents never see NATS: the CLI (agentmux hub fed ...) and the stdio MCP server expose verbs generated from one registry and call the hub socket.",
            "why": "Interview F10: CLI canonical, thin MCP wrapper.",
            "tradeoffs": "The MCP server is hand-written (A18). Alternative: agents use nats directly, rejected - would bypass identity and guardrails.",
            "locations": [
              {
                "path": "hub/fed/mcp.py",
                "symbol": "handle"
              },
              {
                "path": "hub/cli.py",
                "symbol": "fed_main"
              }
            ],
            "verificationEvidence": [
              "hub/tests/test_fed_unit.py"
            ]
          }
        },
        {
          "date": "2026-10-09",
          "reason": "Bounded restoration of missing legacy CLI/roster plugin proposed; runtime implementation remains pending review.",
          "previous": {
            "how": "Agents never see NATS: the CLI (agentmux hub fed ...) and the stdio MCP server expose verbs generated from one registry and call the hub socket. The existing Windows launcher forwards explicit agent hub commands into the selected WSL distribution and binary. Per-pane token files identify callbacks to the existing loopback TCP hub; callback admission validates explicit selection and scoped home before launch and forbids lifecycle verbs before side effects.",
            "why": "Interview F10: CLI canonical, thin MCP wrapper. Windows-owned clients cannot retain Linux process ancestry when returning through WSL, so authenticated per-agent gateway context is required to preserve existing hub identity.",
            "tradeoffs": "The MCP server is hand-written (A18). Alternative: agents use nats directly, rejected - would bypass identity and guardrails. An explicit callback context and Windows Python 3 dependency add setup work; normal operator defaults remain separate. A direct unauthenticated callback or ancestry fallback is simpler but loses agent identity. Tests qualify bounded launcher arguments and real local agent tokens; automatic provider forwarding and authenticated concurrent provider workflows remain unqualified."
          }
        }
      ],
      "history": [
        {
          "date": "2026-10-09",
          "decision": "Applied bounded maintained legacy plugin gateway, independently reviewed; original-source gap retained",
          "previous": {
            "how": "Agents never see NATS: the CLI (agentmux hub fed ...) and the stdio MCP server expose verbs generated from one registry and call the hub socket. The existing Windows launcher forwards explicit agent hub commands into the selected WSL distribution and binary. Per-pane token files identify callbacks to the existing loopback TCP hub; callback admission validates explicit selection and scoped home before launch and forbids lifecycle verbs before side effects. A maintained legacy orchestration package is now planned under plugins/agentmux-orchestration: installed skills select the existing runtime through an explicit binding; roster MCP translates read calls to existing dashboard endpoints. Pre-tool checks preserve current product policy as defense in depth. No package location is marked applied before implementation and review.",
            "why": "Interview F10: CLI canonical, thin MCP wrapper. Windows-owned clients cannot retain Linux process ancestry when returning through WSL, so authenticated per-agent gateway context is required to preserve existing hub identity. Original external plugin source is missing, leaving20baseline tests skipped; current source contracts and nine historical workflow names support an explicitly maintained replacement.",
            "tradeoffs": "The MCP server is hand-written (A18). Alternative: agents use nats directly, rejected - would bypass identity and guardrails. An explicit callback context and Windows Python 3 dependency add setup work; normal operator defaults remain separate. A direct unauthenticated callback or ancestry fallback is simpler but loses agent identity. Tests qualify bounded launcher arguments and real local agent tokens; automatic provider forwarding and authenticated concurrent provider workflows remain unqualified. Recovery is not claimed. Vendoring preserves reviewed command workflows but adds hook/parser, packaging and provenance maintenance; leaving the package external is simpler but currently prevents required preservation checks. Hooks do not replace authoritative runtime authorization or provide complete shell containment.",
            "locations": [
              {
                "path": "hub/fed/mcp.py",
                "symbol": "handle"
              },
              {
                "path": "hub/cli.py",
                "symbol": "fed_main"
              },
              {
                "path": "agentmux_windows.py",
                "symbol": "command"
              },
              {
                "path": "hub/cli.py",
                "symbol": "main"
              },
              {
                "path": "agentmux.sh",
                "symbol": "cmd_spawn"
              },
              {
                "path": "hub/server.py",
                "symbol": "Hub.spawn"
              }
            ]
          }
        },
        {
          "date": "2026-10-09",
          "decision": "Correct maintained gateway locations to declared path/symbol schema and attach independent compatibility proof; no pattern or source scope removed"
        }
      ]
    },
    {
      "id": "FED-16",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Correlation Identifier",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/CorrelationIdentifier.html",
      "referenceDepth": "full-public-reference",
      "how": "Correlate by origin peer/node, origin work ID, offer ID/digest and repository ID, then the selected peer/node/execution and grant. Accept terminal payload state/text only with a matching result digest. Store validated result identity on the origin record.",
      "why": "Results arrive asynchronously, from another person, on a shared inbox subject.",
      "tradeoffs": "Origin ids are only unique per hub; the pair (peer, origin_id) is the key. The result digest binds returned content but does not prove semantic correctness or verify arbitrary external artifacts; full product acceptance remains a later planned contract.",
      "locations": [
        {
          "path": "hub/fed/plugins/work.py",
          "symbol": "Work._on_result"
        },
        {
          "path": "hub/fed/plugins/work.py",
          "symbol": "Work"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py",
        "hub/tests/test_governance.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md",
        "docs/planning/2026-10-09/governance-repairs.md"
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "Repairs for six explicitly authorized baseline findings",
          "previous": {
            "how": "A federated item's result carries origin_id, the publisher's local work id, which closes the fed:pending placeholder on the origin hub.",
            "why": "Results arrive asynchronously, from another person, on a shared inbox subject.",
            "tradeoffs": "Origin ids are only unique per hub; the pair (peer, origin_id) is the key."
          }
        }
      ]
    },
    {
      "id": "FED-17",
      "status": "applied",
      "catalog": "dofactory",
      "pattern": "Facade",
      "source": "https://www.dofactory.com/net/facade-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Plugins get the runtime as ctx: publish/stage, db, kv, policy, post_local, sender_of. They never touch the connection, so every publish passes the guard.",
      "why": "Interview F9: plugins extend capabilities without bypassing guardrails.",
      "tradeoffs": "ctx is wide; a plugin can still read any hub table. Alternative: per-plugin capability objects, possible if third-party plugins appear.",
      "locations": [
        {
          "path": "hub/fed/runtime.py",
          "symbol": "Federation"
        },
        {
          "path": "hub/fed/plugin.py",
          "symbol": "Plugin"
        }
      ],
      "verificationEvidence": [
        "hub/tests/test_fed_live.py"
      ],
      "decisionEvidence": [
        "docs/FEDERATION.md"
      ]
    },
    {
      "id": "PLAN-01",
      "status": "planned",
      "catalog": "dofactory",
      "pattern": "Abstract Factory",
      "source": "https://www.dofactory.com/net/abstract-factory-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Create approved families of scoped service clients when constructing a plugin in each SDK. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03. Implementation locations will be recorded when implemented.",
      "why": "Independent SDKs must receive compatible service contracts and explicit lifetimes.",
      "tradeoffs": "A hand-written factory is simpler initially; factory APIs add abstraction and must not become a global service locator.",
      "locations": [],
      "verificationEvidence": [],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json"
      ]
    },
    {
      "id": "PLAN-02",
      "status": "planned",
      "catalog": "dofactory",
      "pattern": "Adapter",
      "source": "https://www.dofactory.com/net/adapter-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Translate client, worker, vendor, storage and AG-UI protocols at owning plugin boundaries. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P06, P07, P11. Implementation locations will be recorded when implemented. ADD-01 first maps existing CLI, hub plugin, dashboard and protocol implementations to retained or extracted code. A new boundary may wrap that code; any replacement needs behavior and migration evidence before cutover. LOCAL-01 client startup adapters invoke an idempotent local Compose bootstrap and expose the same authorized instance/hub status after start or reuse. Actual host hooks are qualified in P06; the dashboard uses the same contract in P07. P00 proposes command-hook or qualified launcher adapters translating LOCAL-01 status into each host output format. Existing dashboard control capabilities remain available; see delivery/decisions/startup-contract.md and runtime-and-deployment.md. This is a recommendation pending P00 review.",
      "why": "External interfaces differ while internal operations must remain language-neutral and NATS-based.",
      "tradeoffs": "A single bespoke integration is simpler; adapters add translation/version upkeep and cannot invent unsupported host capabilities. Maintaining transition paths and equivalent behavior adds testing cost. Reuse is preferred where contracts and authority permit it; a new framework or language alone is not a replacement justification. Host-specific automatic launch needs actual-host tests and protocol-clean output; manual launch is simpler but does not satisfy the accepted automatic-start requirement.",
      "locations": [],
      "verificationEvidence": [],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/component-preservation.md",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "ADD-01 preserve and extend existing functionality",
          "previous": {
            "how": "Translate client, worker, vendor, storage and AG-UI protocols at owning plugin boundaries. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P06, P07, P11. Implementation locations will be recorded when implemented.",
            "why": "External interfaces differ while internal operations must remain language-neutral and NATS-based.",
            "tradeoffs": "A single bespoke integration is simpler; adapters add translation/version upkeep and cannot invent unsupported host capabilities."
          },
          "reason": "Record explicit reuse obligations without changing historical FED entries or claiming implementation."
        },
        {
          "date": "2026-10-09",
          "decision": "LOCAL-01 approved automatic Compose startup direction",
          "previous": {
            "how": "Translate client, worker, vendor, storage and AG-UI protocols at owning plugin boundaries. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P06, P07, P11. Implementation locations will be recorded when implemented. ADD-01 first maps existing CLI, hub plugin, dashboard and protocol implementations to retained or extracted code. A new boundary may wrap that code; any replacement needs behavior and migration evidence before cutover.",
            "why": "External interfaces differ while internal operations must remain language-neutral and NATS-based.",
            "tradeoffs": "A single bespoke integration is simpler; adapters add translation/version upkeep and cannot invent unsupported host capabilities. Maintaining transition paths and equivalent behavior adds testing cost. Reuse is preferred where contracts and authority permit it; a new framework or language alone is not a replacement justification."
          },
          "reason": "Retain earlier rationale; clarify bootstrap versus runtime control and client status. Planned only, not implementation evidence."
        },
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Translate client, worker, vendor, storage and AG-UI protocols at owning plugin boundaries. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P06, P07, P11. Implementation locations will be recorded when implemented. ADD-01 first maps existing CLI, hub plugin, dashboard and protocol implementations to retained or extracted code. A new boundary may wrap that code; any replacement needs behavior and migration evidence before cutover. LOCAL-01 client startup adapters invoke an idempotent local Compose bootstrap and expose the same authorized instance/hub status after start or reuse. Actual host hooks are qualified in P06; the dashboard uses the same contract in P07.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        }
      ]
    },
    {
      "id": "PLAN-03",
      "status": "planned",
      "catalog": "dofactory",
      "pattern": "Composite",
      "source": "https://www.dofactory.com/net/composite-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Leaf plugins and assemblies expose the same declared lifecycle/inspection component contract. Represent nesting with private-child ownership and independent-child references kept distinct, with explicit instance lifecycles and all inter-plugin calls over NATS. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03. Implementation locations will be recorded when implemented. P00 proposes fixed protected assembly membership and separately supervised processes, with explicit private-child ownership and independent child references for ordinary packages; see delivery/decisions/runtime-and-deployment.md. Process overhead remains to be measured. This is a recommendation pending P00 review. P02 now adds platform/kernel/assembly.Verify to check externally trusted release bytes, fixed four-role membership and contained binary digests before any supervisor spawn. This is the validation boundary for the planned protected composition; it does not yet construct the kernel or expose a Go plugin ABI. P02 now prepares sealed Linux executable snapshots and supervises four distinct role processes through platform/runtime.Prepare and Prepared.Start. Role implementations exchange scoped messages over NATS; a shared stateless protocol codec does not create an in-process plugin channel. Four-process boot and native macOS execution remain under verification, so the complete composition stays planned. The installed-release loader verifies an external enrollment key and detached authorization over exact release and assembly bytes. VerifyRoot and component-wise OpenMember retain one held directory identity and bounded nonblocking reads. LoadBootstrapConfig binds that verified assembly to the enrolled private profile and exact broker/role configuration. Bootstrap composes actual inspection, an OS startup lease, persistent health probing and supervised four-role startup; a reused session owns no processes. Four distinct role processes and host-death cleanup now have real WSL/NATS evidence. Complete Compose startup/reuse/recovery and native macOS boot remain open. The team private credential reader retains every ancestor descriptor through bounded reading, caps the walk at128 directories, and rechecks actual owner/mode/native ACL/mount access before returning bytes. Darwin without CGO refuses rather than replacing native checks. This helper supports separately enrolled configuration; it does not grant authority from path metadata or provide a sandbox.",
      "why": "Assemblies must install and operate together without erasing independent child identity.",
      "tradeoffs": "A flat dependency list is simpler; nesting increases lifecycle/version resolution complexity and must not imply inherited authority.",
      "locations": [
        {
          "path": "platform/kernel/assembly/verify.go",
          "symbol": "Verify"
        },
        {
          "path": "platform/runtime/supervisor.go",
          "symbol": "Prepare"
        },
        {
          "path": "platform/kernel/boot/run.go",
          "symbol": "Run"
        },
        {
          "path": "platform/kernel/lifecycle/run.go",
          "symbol": "Run"
        },
        {
          "path": "platform/kernel/communication/run.go",
          "symbol": "Run"
        },
        {
          "path": "platform/kernel/status/run.go",
          "symbol": "Run"
        },
        {
          "path": "platform/launcher/release.go",
          "symbol": "LoadInstalledRelease"
        },
        {
          "path": "platform/launcher/host_config.go",
          "symbol": "LoadBootstrapConfig"
        },
        {
          "path": "platform/launcher/bootstrap.go",
          "symbol": "Bootstrap"
        },
        {
          "path": "platform/kernel/assembly/verify.go",
          "symbol": "VerifyRoot"
        },
        {
          "path": "platform/kernel/assembly/open_unix.go",
          "symbol": "openMemberFile"
        },
        {
          "path": "platform/privatefs/access.go",
          "symbol": "CheckDescriptor"
        },
        {
          "path": "platform/deployment/team_credentials_unix.go",
          "symbol": "teamReadPrivateChecked"
        }
      ],
      "verificationEvidence": [
        "platform/kernel/assembly/verify_test.go",
        "platform/runtime/supervisor_linux_test.go",
        "platform/kernel/boot/integration_test.go",
        "platform/kernel/assembly/root_test.go",
        "platform/kernel/assembly/open_unix_test.go",
        "platform/kernel/boot/process_integration_test.go",
        "platform/kernel/boot/parent_lifetime_test.go",
        "platform/launcher/release_test.go",
        "platform/launcher/host_config_test.go",
        "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/evidence/P02/P02-T06-acceptance-2740e31.json"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Leaf plugins and assemblies expose the same declared lifecycle/inspection component contract. Represent nesting with private-child ownership and independent-child references kept distinct, with explicit instance lifecycles and all inter-plugin calls over NATS. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        },
        {
          "date": "2026-10-14",
          "reviewer": "Codex",
          "previous": {
            "how": "Leaf plugins and assemblies expose the same declared lifecycle/inspection component contract. Represent nesting with private-child ownership and independent-child references kept distinct, with explicit instance lifecycles and all inter-plugin calls over NATS. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03. Implementation locations will be recorded when implemented. P00 proposes fixed protected assembly membership and separately supervised processes, with explicit private-child ownership and independent child references for ordinary packages; see delivery/decisions/runtime-and-deployment.md. Process overhead remains to be measured. This is a recommendation pending P00 review. P02 now adds platform/kernel/assembly.Verify to check externally trusted release bytes, fixed four-role membership and contained binary digests before any supervisor spawn. This is the validation boundary for the planned protected composition; it does not yet construct the kernel or expose a Go plugin ABI. P02 now prepares sealed Linux executable snapshots and supervises four distinct role processes through platform/runtime.Prepare and Prepared.Start. Role implementations exchange scoped messages over NATS; a shared stateless protocol codec does not create an in-process plugin channel. Four-process boot and native macOS execution remain under verification, so the complete composition stays planned. The installed-release loader verifies an external enrollment key and detached authorization over exact release and assembly bytes. VerifyRoot and component-wise OpenMember retain one held directory identity and bounded nonblocking reads. LoadBootstrapConfig binds that verified assembly to the enrolled private profile and exact broker/role configuration. Bootstrap composes actual inspection, an OS startup lease, persistent health probing and supervised four-role startup; a reused session owns no processes. Four distinct role processes and host-death cleanup now have real WSL/NATS evidence. Complete Compose startup/reuse/recovery and native macOS boot remain open.",
            "tradeoffs": "A flat dependency list is simpler; nesting increases lifecycle/version resolution complexity and must not imply inherited authority.",
            "locations": [
              {
                "path": "platform/kernel/assembly/verify.go",
                "symbol": "Verify"
              },
              {
                "path": "platform/runtime/supervisor.go",
                "symbol": "Prepare"
              },
              {
                "path": "platform/kernel/boot/run.go",
                "symbol": "Run"
              },
              {
                "path": "platform/kernel/lifecycle/run.go",
                "symbol": "Run"
              },
              {
                "path": "platform/kernel/communication/run.go",
                "symbol": "Run"
              },
              {
                "path": "platform/kernel/status/run.go",
                "symbol": "Run"
              },
              {
                "path": "platform/launcher/release.go",
                "symbol": "LoadInstalledRelease"
              },
              {
                "path": "platform/launcher/host_config.go",
                "symbol": "LoadBootstrapConfig"
              },
              {
                "path": "platform/launcher/bootstrap.go",
                "symbol": "Bootstrap"
              },
              {
                "path": "platform/kernel/assembly/verify.go",
                "symbol": "VerifyRoot"
              },
              {
                "path": "platform/kernel/assembly/open_unix.go",
                "symbol": "openMemberFile"
              }
            ],
            "verificationEvidence": [
              "platform/kernel/assembly/verify_test.go",
              "platform/runtime/supervisor_linux_test.go",
              "platform/kernel/boot/integration_test.go",
              "platform/kernel/assembly/root_test.go",
              "platform/kernel/assembly/open_unix_test.go",
              "platform/kernel/boot/process_integration_test.go",
              "platform/kernel/boot/parent_lifetime_test.go",
              "platform/launcher/release_test.go",
              "platform/launcher/host_config_test.go"
            ]
          },
          "note": "Resolved independent current source documentation finding; resource mechanisms are not extra patterns. Component evidence does not prove native or phase acceptance.",
          "evidence": "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json"
        }
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-13",
          "reason": "P02 initial fixed-assembly verification boundary; full protected composition remains pending.",
          "previousHow": "Leaf plugins and assemblies expose the same declared lifecycle/inspection component contract. Represent nesting with private-child ownership and independent-child references kept distinct, with explicit instance lifecycles and all inter-plugin calls over NATS. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03. Implementation locations will be recorded when implemented. P00 proposes fixed protected assembly membership and separately supervised processes, with explicit private-child ownership and independent child references for ordinary packages; see delivery/decisions/runtime-and-deployment.md. Process overhead remains to be measured. This is a recommendation pending P00 review."
        },
        {
          "date": "2026-10-13",
          "reason": "Record actual protected supervisor and separate NATS role implementation while retaining incomplete full composition status.",
          "previousHow": "Leaf plugins and assemblies expose the same declared lifecycle/inspection component contract. Represent nesting with private-child ownership and independent-child references kept distinct, with explicit instance lifecycles and all inter-plugin calls over NATS. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03. Implementation locations will be recorded when implemented. P00 proposes fixed protected assembly membership and separately supervised processes, with explicit private-child ownership and independent child references for ordinary packages; see delivery/decisions/runtime-and-deployment.md. Process overhead remains to be measured. This is a recommendation pending P00 review. P02 now adds platform/kernel/assembly.Verify to check externally trusted release bytes, fixed four-role membership and contained binary digests before any supervisor spawn. This is the validation boundary for the planned protected composition; it does not yet construct the kernel or expose a Go plugin ABI."
        },
        {
          "date": "2026-10-13",
          "reason": "Record actual signed installed-release loader and composed local Bootstrap, retaining unaccepted native and full integration scope.",
          "previousHow": "Leaf plugins and assemblies expose the same declared lifecycle/inspection component contract. Represent nesting with private-child ownership and independent-child references kept distinct, with explicit instance lifecycles and all inter-plugin calls over NATS. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03. Implementation locations will be recorded when implemented. P00 proposes fixed protected assembly membership and separately supervised processes, with explicit private-child ownership and independent child references for ordinary packages; see delivery/decisions/runtime-and-deployment.md. Process overhead remains to be measured. This is a recommendation pending P00 review. P02 now adds platform/kernel/assembly.Verify to check externally trusted release bytes, fixed four-role membership and contained binary digests before any supervisor spawn. This is the validation boundary for the planned protected composition; it does not yet construct the kernel or expose a Go plugin ABI. P02 now prepares sealed Linux executable snapshots and supervises four distinct role processes through platform/runtime.Prepare and Prepared.Start. Role implementations exchange scoped messages over NATS; a shared stateless protocol codec does not create an in-process plugin channel. Four-process boot and native macOS execution remain under verification, so the complete composition stays planned."
        }
      ]
    },
    {
      "id": "PLAN-04",
      "status": "planned",
      "catalog": "dofactory",
      "pattern": "Facade",
      "source": "https://www.dofactory.com/net/facade-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity. The unintegrated terminal-history proposal keeps historical diagnostic access behind the same scoped facade. Its history-only cleanup may retain an exact private staging object after publication joins, while releasing its extra service-lease duplicate so optional diagnostics do not block genuine startup retries. Core incomplete worker cleanup still retains its original lease; historical cleanup cannot publish or replace the shared history slot. The promoted private bootstrap history foundation binds one fixed bounded slot to actual owner, scope, runtime, Compose configuration, engine, server trust and held service lease. It uses generation and inode checks for publication, independently revalidates canonical roots and permissions, and retains exact unpublished staging cleanup ownership. Actual Run and CLI integration remain pending. The installed history reader facade reloads current policy and derives owner/runtime/binding internally. General reads require a free service lease; the creator exception requires the original factory receipt for that exact invocation. Its fixed seven-field document describes only past failure. Main and Run wiring remain open. Owner history is now wired in source: the installed factory derives binding without requiring a receipt descriptor; generic servers remain disabled. The actual protected operation entry begins history, its sole worker records completion, and Run joins publication before teardown. Actual operation creation time preserves preentry failure chronology. Failed startup can finalize under one shared existing core cleanup envelope; healthy runtime retires its optional lease duplicate promptly. Concrete root/staging ownership stays private; public warnings carry a literal fixed code without cleanup ancestry. Actual Run and CLI qualification remain pending. CLI wiring is now in source. Authenticated NATS replies return first; initial ensure still performs genuine admission and startup. Only unavailable status, or an accepted exact creator with unavailable final status, can read the historical facade. The separate tagged history document preserves the original nonzero request error and fixed stderr diagnostic. Earlier wiring-open statements describe prior source stages; actual running and native qualification remain pending. The common connection factory installs a fixed non-capturing NATS error handler before callbacks begin. Known permission, authentication, revocation and account-expiry errors are read from LastError after ordered flushes and waits, before unavailable mapping and accepting a reply. Probe retains its unknown-error rejection. Denied authority never becomes eligible historical fallback. If the trusted private pending refusal comes from an entered canceled core, the facade independently checks full operation binding and the canonical held service lease, then waits for actual completion under the same remaining request context with no held mutex. The same consumed nonce receives the actual completed observation; replay consumption and publication remain unchanged.",
      "why": "Plugin authors need common logging, config and approved services without coupling to implementations.",
      "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup. The proposed narrower staging cleanup owner requires exact directory/name/inode checks and verification that old cleanup preserves a newer generation. Keeping its extra service lease until unlink succeeds is simpler but conflicts with the required retry behavior. Optional history adds private filesystem ownership and timing costs. It remains a diagnostic of past failure, never a current-status authority. After publication has joined and retired, its duplicate lease can close while a concrete staging cleanup owner remains; incomplete core cleanup retains its own original lease. Linux component evidence does not prove installed or Darwin acceptance. Fresh policy reloads add local read costs and refuse drift; accepting caller-supplied history bindings is simpler but would manufacture authority. Reads stay within the caller deadline and a capped local I/O budget; native timing and installed integration require separate checks. Shared cleanup context preserves the original total envelope and exact incomplete core ownership. Quiescent retirement closes only the history duplicate, allowing genuine retries while exact temporary-file cleanup remains owned. Separate immutable warning snapshots add lifecycle rules: one writer before join, serialized cleanup afterward, and no writes on refused gates. Actual six-case component evidence is narrower than running lifecycle acceptance. A capped 200-millisecond history read consumes part of the existing response allowance while preserving one-second receipt cleanup and 300-millisecond output reserve inside the original total deadline. Treating old history as current status would be simpler but falsely claim readiness. Pure budget/emission controls do not prove eligible reader bypass or a running CLI. Fixed callback handling requires explicit sentinel checks; suppressing console text alone would hide denied access as unavailability. A configurable callback is simpler but permits arbitrary text and caller behavior at this private boundary. Actual denied publish and subscribe controls cover the repaired default client; installed CLI output requires separate qualification. This narrow wait prevents a transient cancellation/completion gap from permanently consuming a request without replying. Reopening a nonce would be simpler but risk duplicate publication after ambiguous transport failure. Context and canonical descriptor checks add bounded local work; private operation-seam tests do not establish actual installed Run or native qualification.",
      "locations": [
        {
          "path": "platform/launcher/owner_bridge.go",
          "symbol": "OwnerBridgeClient.Request"
        },
        {
          "path": "platform/launcher/owner_bridge.go",
          "symbol": "OwnerBridgeServer.Run"
        },
        {
          "path": "platform/launcher/session_cleanup.go",
          "symbol": "RuntimeCleanupError"
        },
        {
          "path": "platform/launcher/bootstrap.go",
          "symbol": "BootstrapForInvocation"
        },
        {
          "path": "platform/launcher/local_broker_authority.go",
          "symbol": "inspectLocalBrokerOperation"
        },
        {
          "path": "platform/launcher/docker_archives.go",
          "symbol": "Docker.verifyOwnedTLSArchives"
        },
        {
          "path": "platform/launcher/host_receipt_binding.go",
          "symbol": "BootstrapReceiptBinding"
        },
        {
          "path": "platform/launcher/host_receipt_server.go",
          "symbol": "BridgeServerForInvocation"
        },
        {
          "path": "platform/launcher/owner_bridge_receipt.go",
          "symbol": "emitBootstrapAccepted"
        },
        {
          "path": "platform/runtime/bootstrap_receipt.go",
          "symbol": "BootstrapReceipt"
        },
        {
          "path": "platform/runtime/startup_cleanup_cause.go",
          "symbol": "retainStartupCleanupCause"
        },
        {
          "path": "platform/launcher/bootstrap_operation.go",
          "symbol": "bootstrapOperation.enter"
        },
        {
          "path": "platform/launcher/startup_status.go",
          "symbol": "OwnerStatus.mapStartingContext"
        },
        {
          "path": "platform/launcher/owner_bridge_receipt.go",
          "symbol": "joinedBridgeBootstrapResult"
        },
        {
          "path": "platform/launcher/owner_bridge.go",
          "symbol": "OwnerBridgeServer.refresh"
        },
        {
          "path": "platform/launcher/owner_bridge.go",
          "symbol": "bridgeObservationCleanupFailure"
        },
        {
          "path": "platform/launcher/owner_bridge_probe.go",
          "symbol": "OwnerBridgeClient.probe"
        },
        {
          "path": "platform/launcher/host_policy.go",
          "symbol": "EnsureInvocation.Probe"
        },
        {
          "path": "platform/cmd/agentmux-runtime/main.go",
          "symbol": "initialLookupAllowsStart"
        },
        {
          "path": "platform/launcher/bootstrap_history.go",
          "symbol": "bootstrapHistoryStore"
        },
        {
          "path": "platform/launcher/bootstrap_history_fs.go",
          "symbol": "readCreatorBootstrapHistory"
        },
        {
          "path": "platform/launcher/bootstrap_history_root.go",
          "symbol": "historyRootGuard"
        },
        {
          "path": "platform/launcher/bootstrap_history_stage.go",
          "symbol": "historyStageCleanupError"
        },
        {
          "path": "platform/launcher/host_history_policy.go",
          "symbol": "PreviousBootstrapFailure"
        },
        {
          "path": "platform/launcher/host_history_policy.go",
          "symbol": "CreatorPreviousBootstrapFailure"
        },
        {
          "path": "platform/launcher/owner_bridge_history.go",
          "symbol": "finalizeBootstrapHistory"
        },
        {
          "path": "platform/launcher/owner_bridge_history.go",
          "symbol": "CloseBootstrapHistory"
        },
        {
          "path": "platform/launcher/session_cleanup.go",
          "symbol": "closeOwnedSessionContext"
        },
        {
          "path": "platform/cmd/agentmux-runtime/main_history.go",
          "symbol": "statusHistoryFallback"
        },
        {
          "path": "platform/cmd/agentmux-runtime/main_history.go",
          "symbol": "creatorHistoryFallback"
        },
        {
          "path": "platform/launcher/owner_bridge.go",
          "symbol": "ownerBridgeAsyncErrorHandler"
        },
        {
          "path": "platform/launcher/owner_bridge.go",
          "symbol": "ownerBridgeAuthorityLastError"
        },
        {
          "path": "platform/launcher/bootstrap_operation.go",
          "symbol": "bootstrapOperation.awaitCanceledCoreCompletion"
        }
      ],
      "verificationEvidence": [
        "docs/planning/2026-10-09/delivery/evidence/P02/owner-bridge-receipt/review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/owner-refresh-current/independent-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/initial-owner-probe/affected-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/cli-initial-probe/independent-source-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/history-foundation-promotion/independent-close-cause-closure.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/host-history-policy/independent-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/history-owner-integration/independent-writer-gate-closure.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/cli-history-wiring/independent-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/default-request-authority-repair/independent-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/owner-nonce-completion-window/repaired-component-review.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md",
        "docs/planning/2026-10-09/delivery/decisions/P02-owner-status-bridge.md",
        "docs/planning/2026-10-09/delivery/decisions/P02-local-broker-authentication.md",
        "docs/planning/2026-10-09/delivery/decisions/P02-local-broker-observation-proof.md",
        "docs/planning/2026-10-09/delivery/decisions/P02-history-cleanup-ownership.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "STATE-01 approved NATS persistence direction",
          "previous": {
            "how": "Expose small scoped context service clients instead of broad runtime/database objects. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P04, P08. Implementation locations will be recorded when implemented.",
            "why": "Plugin authors need common logging, config and approved services without coupling to implementations.",
            "tradeoffs": "Direct access is simpler but violates the accepted boundary; facades can grow too wide and require explicit contract ownership."
          },
          "reason": "Preserve the original planning rationale while updating storage placement and recovery boundaries. This is a design revision, not implementation evidence."
        },
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        },
        {
          "date": "2026-10-14",
          "decision": "P02 local owner-status facade implementation in progress",
          "previousHow": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review.",
          "reason": "Independent review found that a detached launch request and a kernel-only observation could not replace the actual owner outcome or L04 refresh. Preserve the full scoped startup contract over NATS.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/P02-owner-status-bridge.md"
        },
        {
          "date": "2026-10-14",
          "decision": "P02 cryptographic local broker authentication required",
          "previousHow": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients.",
          "reason": "An actual synthetic peer received credentials while spoofing advertised broker identity. Keep the facade scoped and authenticate its underlying transport before accepting installed replies.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/P02-local-broker-authentication.md"
        },
        {
          "date": "2026-10-14",
          "decision": "Record concrete Session and service lease cleanup ownership at the existing host facade.",
          "previousHow": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified.",
          "evidence": "docs/planning/2026-10-09/delivery/evidence/P02/combined-cleanup-independent/independent-review.json"
        },
        {
          "date": "2026-10-14",
          "decision": "Record the reviewed one-operation broker proof at the bootstrap facade, without broadening readiness or timing promises.",
          "previousHow": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced.",
          "evidence": [
            "docs/planning/2026-10-09/delivery/evidence/P02/kernel-operation-proof-independent/independent-review.json",
            "docs/planning/2026-10-09/delivery/evidence/P02/real-compose-current/review.json"
          ]
        },
        {
          "date": "2026-10-14",
          "decision": "Record the draft pre-broker lifecycle receipt within the existing startup facade; keep application communication on NATS.",
          "previousHow": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/P02-bootstrap-control-receipt.md",
          "limits": "No installed CLI timing or native platform acceptance. First actual pending CLI run failed the strict ten-second gate; diagnosis and fresh owner revalidation are in progress."
        },
        {
          "date": "2026-10-14",
          "decision": "Retain original startup failure when owned cleanup also fails.",
          "previousHow": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open.",
          "evidence": "docs/planning/2026-10-09/delivery/evidence/P02/startup-cleanup-cause/root-review.json",
          "limits": "Cause/privacy controls and affected actual-process checks pass; no forced simultaneous actual Start/Stop failure or native platform acceptance."
        },
        {
          "date": "2026-10-14",
          "reviewer": "Codex",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins.",
            "locations": [
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "OwnerBridgeClient.Request"
              },
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "OwnerBridgeServer.Run"
              },
              {
                "path": "platform/launcher/session_cleanup.go",
                "symbol": "RuntimeCleanupError"
              },
              {
                "path": "platform/launcher/bootstrap.go",
                "symbol": "BootstrapForInvocation"
              },
              {
                "path": "platform/launcher/local_broker_authority.go",
                "symbol": "inspectLocalBrokerOperation"
              },
              {
                "path": "platform/launcher/docker_archives.go",
                "symbol": "Docker.verifyOwnedTLSArchives"
              },
              {
                "path": "platform/launcher/host_receipt_binding.go",
                "symbol": "BootstrapReceiptBinding"
              },
              {
                "path": "platform/launcher/host_receipt_server.go",
                "symbol": "BridgeServerForInvocation"
              },
              {
                "path": "platform/launcher/owner_bridge_receipt.go",
                "symbol": "emitBootstrapAccepted"
              },
              {
                "path": "platform/runtime/bootstrap_receipt.go",
                "symbol": "BootstrapReceipt"
              },
              {
                "path": "platform/runtime/startup_cleanup_cause.go",
                "symbol": "retainStartupCleanupCause"
              }
            ],
            "verificationEvidence": []
          },
          "note": "Resolved independent current source documentation finding; resource mechanisms are not extra patterns. Component evidence does not prove native or phase acceptance.",
          "evidence": "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json"
        },
        {
          "date": "2026-10-14",
          "reviewer": "Codex",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority.",
            "locations": [
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "OwnerBridgeClient.Request"
              },
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "OwnerBridgeServer.Run"
              },
              {
                "path": "platform/launcher/session_cleanup.go",
                "symbol": "RuntimeCleanupError"
              },
              {
                "path": "platform/launcher/bootstrap.go",
                "symbol": "BootstrapForInvocation"
              },
              {
                "path": "platform/launcher/local_broker_authority.go",
                "symbol": "inspectLocalBrokerOperation"
              },
              {
                "path": "platform/launcher/docker_archives.go",
                "symbol": "Docker.verifyOwnedTLSArchives"
              },
              {
                "path": "platform/launcher/host_receipt_binding.go",
                "symbol": "BootstrapReceiptBinding"
              },
              {
                "path": "platform/launcher/host_receipt_server.go",
                "symbol": "BridgeServerForInvocation"
              },
              {
                "path": "platform/launcher/owner_bridge_receipt.go",
                "symbol": "emitBootstrapAccepted"
              },
              {
                "path": "platform/runtime/bootstrap_receipt.go",
                "symbol": "BootstrapReceipt"
              },
              {
                "path": "platform/runtime/startup_cleanup_cause.go",
                "symbol": "retainStartupCleanupCause"
              },
              {
                "path": "platform/launcher/bootstrap_operation.go",
                "symbol": "bootstrapOperation.enter"
              },
              {
                "path": "platform/launcher/startup_status.go",
                "symbol": "OwnerStatus.mapStartingContext"
              },
              {
                "path": "platform/launcher/owner_bridge_receipt.go",
                "symbol": "joinedBridgeBootstrapResult"
              }
            ],
            "verificationEvidence": [
              "docs/planning/2026-10-09/delivery/evidence/P02/owner-bridge-receipt/review.json",
              "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json"
            ]
          },
          "note": "Current real CLI refresh regression repaired without deadline, authority or freshness relaxation. Independent component review closed; actual installed and native gate evidence remains separate.",
          "evidence": "docs/planning/2026-10-09/delivery/evidence/P02/owner-refresh-current/independent-review.json"
        },
        {
          "date": "2026-10-14",
          "reviewer": "Codex",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status.",
            "locations": [
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "OwnerBridgeClient.Request"
              },
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "OwnerBridgeServer.Run"
              },
              {
                "path": "platform/launcher/session_cleanup.go",
                "symbol": "RuntimeCleanupError"
              },
              {
                "path": "platform/launcher/bootstrap.go",
                "symbol": "BootstrapForInvocation"
              },
              {
                "path": "platform/launcher/local_broker_authority.go",
                "symbol": "inspectLocalBrokerOperation"
              },
              {
                "path": "platform/launcher/docker_archives.go",
                "symbol": "Docker.verifyOwnedTLSArchives"
              },
              {
                "path": "platform/launcher/host_receipt_binding.go",
                "symbol": "BootstrapReceiptBinding"
              },
              {
                "path": "platform/launcher/host_receipt_server.go",
                "symbol": "BridgeServerForInvocation"
              },
              {
                "path": "platform/launcher/owner_bridge_receipt.go",
                "symbol": "emitBootstrapAccepted"
              },
              {
                "path": "platform/runtime/bootstrap_receipt.go",
                "symbol": "BootstrapReceipt"
              },
              {
                "path": "platform/runtime/startup_cleanup_cause.go",
                "symbol": "retainStartupCleanupCause"
              },
              {
                "path": "platform/launcher/bootstrap_operation.go",
                "symbol": "bootstrapOperation.enter"
              },
              {
                "path": "platform/launcher/startup_status.go",
                "symbol": "OwnerStatus.mapStartingContext"
              },
              {
                "path": "platform/launcher/owner_bridge_receipt.go",
                "symbol": "joinedBridgeBootstrapResult"
              },
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "OwnerBridgeServer.refresh"
              },
              {
                "path": "platform/launcher/owner_bridge.go",
                "symbol": "bridgeObservationCleanupFailure"
              }
            ],
            "verificationEvidence": [
              "docs/planning/2026-10-09/delivery/evidence/P02/owner-bridge-receipt/review.json",
              "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json",
              "docs/planning/2026-10-09/delivery/evidence/P02/owner-refresh-current/independent-review.json"
            ]
          },
          "reason": "Record initial scoped probe facade and its unchanged final observation path, preserving prior pattern use and failed installed qualification."
        },
        {
          "date": "2026-10-14",
          "reviewer": "Codex",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup.",
            "decisionEvidence": [
              "docs/planning/2026-10-09/implementation-plan.md",
              "docs/planning/2026-10-09/phases.json",
              "docs/planning/2026-10-09/delivery/decisions/README.md",
              "docs/planning/2026-10-09/delivery/contracts/README.md",
              "docs/planning/2026-10-09/delivery/decisions/P02-owner-status-bridge.md",
              "docs/planning/2026-10-09/delivery/decisions/P02-local-broker-authentication.md",
              "docs/planning/2026-10-09/delivery/decisions/P02-local-broker-observation-proof.md"
            ]
          },
          "reason": "Amend unintegrated history cleanup boundary to preserve genuine retry behavior; H01/H02/H03 findings remain open."
        }
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-14T14:55:59.395818+00:00",
          "reason": "Promote independently reviewed private bootstrap history foundation without runtime integration",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity. The unintegrated terminal-history proposal keeps historical diagnostic access behind the same scoped facade. Its history-only cleanup may retain an exact private staging object after publication joins, while releasing its extra service-lease duplicate so optional diagnostics do not block genuine startup retries. Core incomplete worker cleanup still retains its original lease; historical cleanup cannot publish or replace the shared history slot.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup. The proposed narrower staging cleanup owner requires exact directory/name/inode checks and verification that old cleanup preserves a newer generation. Keeping its extra service lease until unlink succeeds is simpler but conflicts with the required retry behavior."
          }
        },
        {
          "date": "2026-10-14T15:23:24.374979+00:00",
          "reason": "Promote reviewed installed-policy history reader facade; main and Run wiring remain open",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity. The unintegrated terminal-history proposal keeps historical diagnostic access behind the same scoped facade. Its history-only cleanup may retain an exact private staging object after publication joins, while releasing its extra service-lease duplicate so optional diagnostics do not block genuine startup retries. Core incomplete worker cleanup still retains its original lease; historical cleanup cannot publish or replace the shared history slot. The promoted private bootstrap history foundation binds one fixed bounded slot to actual owner, scope, runtime, Compose configuration, engine, server trust and held service lease. It uses generation and inode checks for publication, independently revalidates canonical roots and permissions, and retains exact unpublished staging cleanup ownership. Actual Run and CLI integration remain pending.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup. The proposed narrower staging cleanup owner requires exact directory/name/inode checks and verification that old cleanup preserves a newer generation. Keeping its extra service lease until unlink succeeds is simpler but conflicts with the required retry behavior. Optional history adds private filesystem ownership and timing costs. It remains a diagnostic of past failure, never a current-status authority. After publication has joined and retired, its duplicate lease can close while a concrete staging cleanup owner remains; incomplete core cleanup retains its own original lease. Linux component evidence does not prove installed or Darwin acceptance."
          }
        },
        {
          "date": "2026-10-14T15:34:22.782061+00:00",
          "reason": "Promote independently reviewed owner history integration; running qualification remains pending",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity. The unintegrated terminal-history proposal keeps historical diagnostic access behind the same scoped facade. Its history-only cleanup may retain an exact private staging object after publication joins, while releasing its extra service-lease duplicate so optional diagnostics do not block genuine startup retries. Core incomplete worker cleanup still retains its original lease; historical cleanup cannot publish or replace the shared history slot. The promoted private bootstrap history foundation binds one fixed bounded slot to actual owner, scope, runtime, Compose configuration, engine, server trust and held service lease. It uses generation and inode checks for publication, independently revalidates canonical roots and permissions, and retains exact unpublished staging cleanup ownership. Actual Run and CLI integration remain pending. The installed history reader facade reloads current policy and derives owner/runtime/binding internally. General reads require a free service lease; the creator exception requires the original factory receipt for that exact invocation. Its fixed seven-field document describes only past failure. Main and Run wiring remain open.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup. The proposed narrower staging cleanup owner requires exact directory/name/inode checks and verification that old cleanup preserves a newer generation. Keeping its extra service lease until unlink succeeds is simpler but conflicts with the required retry behavior. Optional history adds private filesystem ownership and timing costs. It remains a diagnostic of past failure, never a current-status authority. After publication has joined and retired, its duplicate lease can close while a concrete staging cleanup owner remains; incomplete core cleanup retains its own original lease. Linux component evidence does not prove installed or Darwin acceptance. Fresh policy reloads add local read costs and refuse drift; accepting caller-supplied history bindings is simpler but would manufacture authority. Reads stay within the caller deadline and a capped local I/O budget; native timing and installed integration require separate checks."
          }
        },
        {
          "date": "2026-10-14T15:47:09.953237+00:00",
          "reason": "Promote reviewed CLI history wiring, preserving actual NATS precedence and failed result",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity. The unintegrated terminal-history proposal keeps historical diagnostic access behind the same scoped facade. Its history-only cleanup may retain an exact private staging object after publication joins, while releasing its extra service-lease duplicate so optional diagnostics do not block genuine startup retries. Core incomplete worker cleanup still retains its original lease; historical cleanup cannot publish or replace the shared history slot. The promoted private bootstrap history foundation binds one fixed bounded slot to actual owner, scope, runtime, Compose configuration, engine, server trust and held service lease. It uses generation and inode checks for publication, independently revalidates canonical roots and permissions, and retains exact unpublished staging cleanup ownership. Actual Run and CLI integration remain pending. The installed history reader facade reloads current policy and derives owner/runtime/binding internally. General reads require a free service lease; the creator exception requires the original factory receipt for that exact invocation. Its fixed seven-field document describes only past failure. Main and Run wiring remain open. Owner history is now wired in source: the installed factory derives binding without requiring a receipt descriptor; generic servers remain disabled. The actual protected operation entry begins history, its sole worker records completion, and Run joins publication before teardown. Actual operation creation time preserves preentry failure chronology. Failed startup can finalize under one shared existing core cleanup envelope; healthy runtime retires its optional lease duplicate promptly. Concrete root/staging ownership stays private; public warnings carry a literal fixed code without cleanup ancestry. Actual Run and CLI qualification remain pending.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup. The proposed narrower staging cleanup owner requires exact directory/name/inode checks and verification that old cleanup preserves a newer generation. Keeping its extra service lease until unlink succeeds is simpler but conflicts with the required retry behavior. Optional history adds private filesystem ownership and timing costs. It remains a diagnostic of past failure, never a current-status authority. After publication has joined and retired, its duplicate lease can close while a concrete staging cleanup owner remains; incomplete core cleanup retains its own original lease. Linux component evidence does not prove installed or Darwin acceptance. Fresh policy reloads add local read costs and refuse drift; accepting caller-supplied history bindings is simpler but would manufacture authority. Reads stay within the caller deadline and a capped local I/O budget; native timing and installed integration require separate checks. Shared cleanup context preserves the original total envelope and exact incomplete core ownership. Quiescent retirement closes only the history duplicate, allowing genuine retries while exact temporary-file cleanup remains owned. Separate immutable warning snapshots add lifecycle rules: one writer before join, serialized cleanup afterward, and no writes on refused gates. Actual six-case component evidence is narrower than running lifecycle acceptance."
          }
        },
        {
          "date": "2026-10-14T16:24:03.752904+00:00",
          "reason": "Preserve hard NATS authority failures while preventing arbitrary callback text in CLI diagnostics",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity. The unintegrated terminal-history proposal keeps historical diagnostic access behind the same scoped facade. Its history-only cleanup may retain an exact private staging object after publication joins, while releasing its extra service-lease duplicate so optional diagnostics do not block genuine startup retries. Core incomplete worker cleanup still retains its original lease; historical cleanup cannot publish or replace the shared history slot. The promoted private bootstrap history foundation binds one fixed bounded slot to actual owner, scope, runtime, Compose configuration, engine, server trust and held service lease. It uses generation and inode checks for publication, independently revalidates canonical roots and permissions, and retains exact unpublished staging cleanup ownership. Actual Run and CLI integration remain pending. The installed history reader facade reloads current policy and derives owner/runtime/binding internally. General reads require a free service lease; the creator exception requires the original factory receipt for that exact invocation. Its fixed seven-field document describes only past failure. Main and Run wiring remain open. Owner history is now wired in source: the installed factory derives binding without requiring a receipt descriptor; generic servers remain disabled. The actual protected operation entry begins history, its sole worker records completion, and Run joins publication before teardown. Actual operation creation time preserves preentry failure chronology. Failed startup can finalize under one shared existing core cleanup envelope; healthy runtime retires its optional lease duplicate promptly. Concrete root/staging ownership stays private; public warnings carry a literal fixed code without cleanup ancestry. Actual Run and CLI qualification remain pending. CLI wiring is now in source. Authenticated NATS replies return first; initial ensure still performs genuine admission and startup. Only unavailable status, or an accepted exact creator with unavailable final status, can read the historical facade. The separate tagged history document preserves the original nonzero request error and fixed stderr diagnostic. Earlier wiring-open statements describe prior source stages; actual running and native qualification remain pending.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup. The proposed narrower staging cleanup owner requires exact directory/name/inode checks and verification that old cleanup preserves a newer generation. Keeping its extra service lease until unlink succeeds is simpler but conflicts with the required retry behavior. Optional history adds private filesystem ownership and timing costs. It remains a diagnostic of past failure, never a current-status authority. After publication has joined and retired, its duplicate lease can close while a concrete staging cleanup owner remains; incomplete core cleanup retains its own original lease. Linux component evidence does not prove installed or Darwin acceptance. Fresh policy reloads add local read costs and refuse drift; accepting caller-supplied history bindings is simpler but would manufacture authority. Reads stay within the caller deadline and a capped local I/O budget; native timing and installed integration require separate checks. Shared cleanup context preserves the original total envelope and exact incomplete core ownership. Quiescent retirement closes only the history duplicate, allowing genuine retries while exact temporary-file cleanup remains owned. Separate immutable warning snapshots add lifecycle rules: one writer before join, serialized cleanup afterward, and no writes on refused gates. Actual six-case component evidence is narrower than running lifecycle acceptance. A capped 200-millisecond history read consumes part of the existing response allowance while preserving one-second receipt cleanup and 300-millisecond output reserve inside the original total deadline. Treating old history as current status would be simpler but falsely claim readiness. Pure budget/emission controls do not prove eligible reader bypass or a running CLI."
          }
        },
        {
          "date": "2026-10-14T16:50:15.694870+00:00",
          "reason": "Preserve one accepted request across actual canceled-core completion",
          "previous": {
            "how": "Expose small scoped context clients for domain commands, approved NATS reads, configuration and artifacts. Injected handles do not expose unrestricted JetStream management or another project's data. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P03, P04, P08. Implementation locations will be recorded when implemented. P00 proposes Python and TypeScript SDK clients that construct scoped domain service handles rather than expose unrestricted storage administration; see delivery/decisions/runtime-and-deployment.md and storage-contract.md. This is a recommendation pending P00 review. P02 adds a narrow local owner-status client and service over an isolated NATS HOST account. OwnerBridgeClient.Request accepts only ensure/status and derives fixed scope-bound subjects; the server returns the unchanged L04 observation from real owning startup or qualified read-only refresh. Broker JSON cannot grant this client protected commands, storage or system privileges. Private enrollment and complete factory comparison remain separate authority checks. This local facade is under implementation and does not complete the P03 common plugin context or later domain clients. P02 now requires enrolled per-profile TLS before credentials reach the owner-status socket, with exact selected Docker ownership inspected separately. Advertised server name/version is not broker authentication. This transport repair is planned and remains unqualified. P02 RuntimeCleanupError retains the actual Bootstrap Session and service lease when process reaping is incomplete. Run transfers only that concrete ownership; the existing reaper releases it on completion, while a bounded explicit retry remains possible. No additional completion waiter, external callback or process identity adoption is introduced. The bootstrap facade consumes one private complete broker inspection in its next kernel observation, bound to the exact original context and admitted policy. The proof is used once, rechecks enrollment, expires within the original budget and is discarded before mutation. TLS authentication and a fresh scoped snapshot remain mandatory. Fixed private archive reads run concurrently only after all broker ownership gates and join before any result. The P02 installed startup facade now has a draft lifecycle receipt bound to its newly spawned verified host and actual admitted operation. Receipt-only output records request acceptance and leaves current instance state unknown; authenticated NATS remains the source of current starting and readiness. Concrete receipt framing has independent Linux component evidence; full installed timing and supported-platform acceptance remain open. The protected startup failure path now preserves both startup and cleanup causes behind fixed safe formatting while returning the same exact owned Group. This repairs diagnostic cause loss without changing process ownership or deadlines. OwnerBridgeServer.Run acquires its actual service lease before starting exactly one bounded Bootstrap operation. Authenticated NATS can report starting only after actual admission and protected preparation mark that private operation entered. Run cancels and joins the exact operation before cleanup; joined completion preserves its actual failure, including concrete cleanup owners. A receipt revalidates the bound owner/profile outside operation locks before one accepted frame. Disconnected receipt I/O is nonfatal; changed enrollment is a core admission failure. Each owner-status refresh uses one fresh exact Docker inspection and one context-bound, single-use kernel observation proof. A later request inspects again; the proof is never stored in the Session or extended. Actual persistence and kernel cleanup failures are joined behind safe presentation and returned from the service loop before publishing a reply, so Run joins the operation and preserves concrete cleanup owners through its existing Session and lease cleanup. The initial ensure lookup now uses EnsureInvocation.Probe, a fixed operation on the existing scoped owner-status facade. It consumes one authenticated native no-responder hint to proceed to ordinary host admission; it grants no current state, readiness or ownership. Status and final ensure requests preserve their existing waiting behavior. Optional request reply subjects must equal the validated nonce-derived address; application replies still derive their destination from the validated request identity. The unintegrated terminal-history proposal keeps historical diagnostic access behind the same scoped facade. Its history-only cleanup may retain an exact private staging object after publication joins, while releasing its extra service-lease duplicate so optional diagnostics do not block genuine startup retries. Core incomplete worker cleanup still retains its original lease; historical cleanup cannot publish or replace the shared history slot. The promoted private bootstrap history foundation binds one fixed bounded slot to actual owner, scope, runtime, Compose configuration, engine, server trust and held service lease. It uses generation and inode checks for publication, independently revalidates canonical roots and permissions, and retains exact unpublished staging cleanup ownership. Actual Run and CLI integration remain pending. The installed history reader facade reloads current policy and derives owner/runtime/binding internally. General reads require a free service lease; the creator exception requires the original factory receipt for that exact invocation. Its fixed seven-field document describes only past failure. Main and Run wiring remain open. Owner history is now wired in source: the installed factory derives binding without requiring a receipt descriptor; generic servers remain disabled. The actual protected operation entry begins history, its sole worker records completion, and Run joins publication before teardown. Actual operation creation time preserves preentry failure chronology. Failed startup can finalize under one shared existing core cleanup envelope; healthy runtime retires its optional lease duplicate promptly. Concrete root/staging ownership stays private; public warnings carry a literal fixed code without cleanup ancestry. Actual Run and CLI qualification remain pending. CLI wiring is now in source. Authenticated NATS replies return first; initial ensure still performs genuine admission and startup. Only unavailable status, or an accepted exact creator with unavailable final status, can read the historical facade. The separate tagged history document preserves the original nonzero request error and fixed stderr diagnostic. Earlier wiring-open statements describe prior source stages; actual running and native qualification remain pending. The common connection factory installs a fixed non-capturing NATS error handler before callbacks begin. Known permission, authentication, revocation and account-expiry errors are read from LastError after ordered flushes and waits, before unavailable mapping and accepting a reply. Probe retains its unknown-error rejection. Denied authority never becomes eligible historical fallback.",
            "tradeoffs": "Direct shared-runtime access is simpler but violates the accepted scopes. Narrow clients add schema/version maintenance; typed handles alone do not sandbox trusted native plugins. Synchronous Bootstrap followed by service subscription is simpler but cannot report genuine starting while startup is in progress. The private operation adds cancellation/join and enrollment revalidation costs; blocked synchronous local filesystem calls remain an explicit timing limit. Receipt-only output conveys past request acceptance and leaves current state unknown; NATS remains the current-status authority. Repeating complete inspection is simpler but consumed the bounded real owner request budget. Same-operation proof reuse adds strict context, scope and freshness checks; it never replaces TLS peer authentication. Fatal handling applies to concrete retained cleanup failures; ordinary missing readiness still reports honest unavailable status. This adds a separate initial lookup path and strict pinned-server frame checks to avoid waiting for an absent subscriber. The simpler unchanged request loop consumes its reply wait before cold admission. Authentication, malformed frames, cancellation and concrete transport cleanup remain failures. Actual installed pending qualification failed separately, so component checks do not establish faster successful startup. The proposed narrower staging cleanup owner requires exact directory/name/inode checks and verification that old cleanup preserves a newer generation. Keeping its extra service lease until unlink succeeds is simpler but conflicts with the required retry behavior. Optional history adds private filesystem ownership and timing costs. It remains a diagnostic of past failure, never a current-status authority. After publication has joined and retired, its duplicate lease can close while a concrete staging cleanup owner remains; incomplete core cleanup retains its own original lease. Linux component evidence does not prove installed or Darwin acceptance. Fresh policy reloads add local read costs and refuse drift; accepting caller-supplied history bindings is simpler but would manufacture authority. Reads stay within the caller deadline and a capped local I/O budget; native timing and installed integration require separate checks. Shared cleanup context preserves the original total envelope and exact incomplete core ownership. Quiescent retirement closes only the history duplicate, allowing genuine retries while exact temporary-file cleanup remains owned. Separate immutable warning snapshots add lifecycle rules: one writer before join, serialized cleanup afterward, and no writes on refused gates. Actual six-case component evidence is narrower than running lifecycle acceptance. A capped 200-millisecond history read consumes part of the existing response allowance while preserving one-second receipt cleanup and 300-millisecond output reserve inside the original total deadline. Treating old history as current status would be simpler but falsely claim readiness. Pure budget/emission controls do not prove eligible reader bypass or a running CLI. Fixed callback handling requires explicit sentinel checks; suppressing console text alone would hide denied access as unavailability. A configurable callback is simpler but permits arbitrary text and caller behavior at this private boundary. Actual denied publish and subscribe controls cover the repaired default client; installed CLI output requires separate qualification."
          }
        }
      ]
    },
    {
      "id": "PLAN-05",
      "status": "planned",
      "catalog": "dofactory",
      "pattern": "Observer",
      "source": "https://www.dofactory.com/net/observer-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Deliver approved kernel information and versioned status updates over NATS subscriptions. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P02, P07. Implementation locations will be recorded when implemented. P00 proposes exported kernel information in a separate account, consumed by ordinary status services without a kernel command path; see delivery/decisions/storage-contract.md. This is a recommendation pending P00 review.",
      "why": "Outside plugins need readiness information while kernel writes remain disallowed.",
      "tradeoffs": "Polling snapshots is simpler; subscriptions require replay/snapshot gap handling and bounded slow consumers.",
      "locations": [],
      "verificationEvidence": [],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Deliver approved kernel information and versioned status updates over NATS subscriptions. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P02, P07. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        }
      ]
    },
    {
      "id": "PLAN-06",
      "status": "planned",
      "catalog": "dofactory",
      "pattern": "Strategy",
      "source": "https://www.dofactory.com/net/strategy-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Select compatible provider, routing, evaluation and execution policies by explicit declared contracts. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P08, P10. Implementation locations will be recorded when implemented.",
      "why": "Customers need replaceable surrounding behavior without kernel replacement.",
      "tradeoffs": "One implementation is simpler; policy/provider compatibility and behavior drift require conformance tests.",
      "locations": [],
      "verificationEvidence": [],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json"
      ]
    },
    {
      "id": "PLAN-07",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Message Bus",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/MessageBus.html",
      "referenceDepth": "full-public-reference",
      "how": "Carry all inter-plugin communication on versioned NATS subjects and schemas. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01–P12. Implementation locations will be recorded when implemented. P00 proposes NATS for every inter-plugin exchange across the fixed protected assembly and ordinary scoped accounts. A bounded three-language request/reply spike proves client interoperability only; it does not qualify lifecycle, security or persistence. See delivery/spikes/runtime/comparison-result.json. This is a recommendation pending P00 review. A P01 fixture now links two independently stored NATS domains through dedicated federation accounts and restricted leaf credentials. Actual commands and observations traverse only the approved subjects; unrelated account and subject traffic is denied. This qualifies static broker boundaries on loopback, not production enrollment, TLS or dynamic trust agreements. The additional signed leaf fixture transports versioned delegation-offer, delegation-decision and execution-report envelopes through the same restricted NATS link. It checks byte preservation and receiving SDK admission before fixture owner mutation. Transport tests use real local brokers and fixed test trust; production hub connection management remains planned.",
      "why": "Accepted requirement mandates NATS locally and across connected systems.",
      "tradeoffs": "Direct local calls are simpler/faster but contradict scope; message contracts add latency, retry, schema and operational cost.",
      "locations": [
        {
          "path": "tests/leaf/run.py",
          "symbol": "Broker"
        },
        {
          "path": "tests/leaf/signed_run.py",
          "symbol": "transfer"
        }
      ],
      "verificationEvidence": [
        "docs/planning/2026-10-09/delivery/spikes/runtime/comparison-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/leaf-denial-negative.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/signed-leaf-result.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Carry all inter-plugin communication on versioned NATS subjects and schemas. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01–P12. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        }
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "P01 pure transition and scoped leaf fixture qualification; production scope remains unchanged.",
          "previous": {
            "status": "planned",
            "how": "Carry all inter-plugin communication on versioned NATS subjects and schemas. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01–P12. Implementation locations will be recorded when implemented. P00 proposes NATS for every inter-plugin exchange across the fixed protected assembly and ordinary scoped accounts. A bounded three-language request/reply spike proves client interoperability only; it does not qualify lifecycle, security or persistence. See delivery/spikes/runtime/comparison-result.json. This is a recommendation pending P00 review.",
            "locations": [],
            "verificationEvidence": [
              "docs/planning/2026-10-09/delivery/spikes/runtime/comparison-result.json"
            ]
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 ordered recovery and signed leaf qualification; production scope and status are unchanged.",
          "previous": {
            "status": "planned",
            "how": "Carry all inter-plugin communication on versioned NATS subjects and schemas. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01–P12. Implementation locations will be recorded when implemented. P00 proposes NATS for every inter-plugin exchange across the fixed protected assembly and ordinary scoped accounts. A bounded three-language request/reply spike proves client interoperability only; it does not qualify lifecycle, security or persistence. See delivery/spikes/runtime/comparison-result.json. This is a recommendation pending P00 review. A P01 fixture now links two independently stored NATS domains through dedicated federation accounts and restricted leaf credentials. Actual commands and observations traverse only the approved subjects; unrelated account and subject traffic is denied. This qualifies static broker boundaries on loopback, not production enrollment, TLS or dynamic trust agreements.",
            "locations": [
              {
                "path": "tests/leaf/run.py",
                "symbol": "Broker"
              }
            ],
            "verificationEvidence": [
              "docs/planning/2026-10-09/delivery/spikes/runtime/comparison-result.json",
              "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json",
              "docs/planning/2026-10-09/delivery/evidence/P01/leaf-denial-negative.json"
            ]
          }
        }
      ]
    },
    {
      "id": "PLAN-08",
      "status": "applied",
      "catalog": "eip",
      "pattern": "Canonical Data Model",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/CanonicalDataModel.html",
      "referenceDepth": "full-public-reference",
      "how": "The separate contracts/v1 package defines closed versioned infrastructure and domain payload schemas. registry.json binds ten contract IDs to their major version, message kind, payload schema and destination service. Independent Python and TypeScript SDK validation checks those bindings, payload/context identity agreement and explicit semantic invariants for manifests, protected assembly, contexts, owner records and attestations. Full envelope verification validates the registered payload plus RFC 8785 payload bytes, Ed25519 claims, signed audience and every duplicated envelope field. The legacy runtime does not import this package. Enrolled-key resolution, live grants, authoritative domain state schemas and full plugin runtime integration remain separate obligations; validated structure and signatures do not authorize execution. P01 now also promotes five lifecycle tables with 68 unchanged edges. Independent Python and TypeScript pure evaluators bind owner snapshot, requested revision, actor evidence and required guard evidence before proposing the next state. Cancellation remains explicit through uncertain execution. These supplied fixture observations are not authenticated authority and the evaluator does not persist, deduplicate or execute work. Ordered recovery fixtures compare full outputs and canonical digests from both SDKs. A separate signed leaf fixture signs offers with Python and decisions/results with TypeScript, then verifies them in the other SDK after transport. Fixture keys are resolved from an explicit issuer/key/revision map and time comes from a trusted test clock. Successful envelope verification still requires the fixture owner to match the retained reservation; five validly signed result mismatches test that separate boundary. Native CI invokes the same conformance harness and deliberately removes a required field from a copied positive fixture, requiring both SDK assertions to fail without changing repository fixtures. Deterministic fake worker/provider fixtures now separate provider execution from callback observation using a manual clock. Explicit delayed, reordered, dropped and cancelled responses exercise unknown outcomes and reconciliation without external tools. These controls are test infrastructure, not production plugin lifecycle or authorization.",
      "why": "Client/provider diversity must not obscure ownership or schema compatibility.",
      "tradeoffs": "Pairwise translation is simpler for two plugins; shared contracts require coordinated version evolution and independent conformance tests. Closed registration makes unsupported commands explicit, but every added domain operation needs a reviewed schema and mapping. Semantic invariants cannot all be expressed by JSON Schema and therefore require matching language implementations. Content-bound validator caches avoid repeated compilation while hashing current schema bytes prevents stale reuse; neither caches nor a supplied valid signature establish authority.",
      "locations": [
        {
          "path": "contracts/v1/schemas/message-envelope.schema.json",
          "symbol": "message-envelope"
        },
        {
          "path": "sdk/python/agentmux_contracts/wire.py",
          "symbol": "canonical_bytes"
        },
        {
          "path": "sdk/typescript/src/index.ts",
          "symbol": "canonicalBytes"
        },
        {
          "path": "contracts/v1/registry.json",
          "symbol": "contracts"
        },
        {
          "path": "sdk/python/agentmux_contracts/validation.py",
          "symbol": "validate_payload"
        },
        {
          "path": "sdk/python/agentmux_contracts/validation.py",
          "symbol": "semantic_errors"
        },
        {
          "path": "sdk/python/agentmux_contracts/attestation.py",
          "symbol": "verify_envelope"
        },
        {
          "path": "sdk/typescript/src/index.ts",
          "symbol": "validatePayload"
        },
        {
          "path": "sdk/typescript/src/index.ts",
          "symbol": "verifyEnvelope"
        },
        {
          "path": "sdk/python/agentmux_contracts/state_models.py",
          "symbol": "evaluate_transition"
        },
        {
          "path": "sdk/typescript/src/state-models.ts",
          "symbol": "evaluateTransition"
        },
        {
          "path": "tests/contracts/test_recovery.py",
          "symbol": "FixtureOwner.both"
        },
        {
          "path": "tests/leaf/signed_run.py",
          "symbol": "Contracts.verify"
        },
        {
          "path": "tests/contracts/ci.py",
          "symbol": "negative_fixture"
        },
        {
          "path": "tests/contracts/fake_execution.py",
          "symbol": "FakeProvider"
        },
        {
          "path": "tests/contracts/fake_execution.py",
          "symbol": "FakeWorker"
        },
        {
          "path": "contracts/v1/schemas/startup-status-observation.schema.json",
          "symbol": "startup-status-observation"
        }
      ],
      "verificationEvidence": [
        "tests/contracts/test_conformance.py",
        "sdk/python/tests/test_contracts.py",
        "sdk/typescript/src/test.ts",
        "tests/contracts/test_payloads.py",
        "tests/contracts/test_semantics.py",
        "tests/contracts/test_state_models.py",
        "docs/planning/2026-10-09/delivery/evidence/P01/recovery-conformance-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/signed-leaf-result.json",
        "tests/contracts/test_fake_execution.py"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md",
        "contracts/v1/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Define versioned envelopes and identity/state vocabulary across languages and hubs. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01, P10. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        },
        {
          "date": "2026-10-09",
          "previousHow": "Define versioned envelopes and identity/state vocabulary across languages and hubs. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01, P10. Implementation locations will be recorded when implemented. P00 proposes shared versioned identities and transition/status fields across languages. Canonical JSON hashing and executable schemas remain P01/P00-T04 work; the spike checks decoded equality only. See delivery/decisions/storage-contract.md and startup-contract.md. This is a recommendation pending P00 review.",
          "reason": "P00 review resolved canonical bytes and authenticated caller binding."
        },
        {
          "date": "2026-10-09",
          "previousHow": "Define versioned envelopes and identity/state vocabulary across languages and hubs. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01, P10. Implementation locations will be recorded when implemented. P00 proposes shared versioned identities and transition/status fields across languages. Canonical JSON hashing and executable schemas remain P01/P00-T04 work; the spike checks decoded equality only. See delivery/decisions/storage-contract.md and startup-contract.md. This is a recommendation pending P00 review. P00 selects RFC 8785 JCS and an enrolled-ingress Ed25519 attestation binding the full operation, payload digest, source, contract and destination. Owners verify enrolled keys, recomputed digests, grants and durable replay state; P00 shapes do not implement this verification.",
          "previousStatus": "planned",
          "reason": "P01 initial executable wire contracts; broader domain/runtime work remains incomplete."
        },
        {
          "date": "2026-10-09",
          "reason": "P01 controlled execution and remaining storage failure qualification; statuses unchanged.",
          "previous": {
            "how": "The separate contracts/v1 package defines closed versioned infrastructure and domain payload schemas. registry.json binds ten contract IDs to their major version, message kind, payload schema and destination service. Independent Python and TypeScript SDK validation checks those bindings, payload/context identity agreement and explicit semantic invariants for manifests, protected assembly, contexts, owner records and attestations. Full envelope verification validates the registered payload plus RFC 8785 payload bytes, Ed25519 claims, signed audience and every duplicated envelope field. The legacy runtime does not import this package. Enrolled-key resolution, live grants, authoritative domain state schemas and full plugin runtime integration remain separate obligations; validated structure and signatures do not authorize execution. P01 now also promotes five lifecycle tables with 68 unchanged edges. Independent Python and TypeScript pure evaluators bind owner snapshot, requested revision, actor evidence and required guard evidence before proposing the next state. Cancellation remains explicit through uncertain execution. These supplied fixture observations are not authenticated authority and the evaluator does not persist, deduplicate or execute work. Ordered recovery fixtures compare full outputs and canonical digests from both SDKs. A separate signed leaf fixture signs offers with Python and decisions/results with TypeScript, then verifies them in the other SDK after transport. Fixture keys are resolved from an explicit issuer/key/revision map and time comes from a trusted test clock. Successful envelope verification still requires the fixture owner to match the retained reservation; five validly signed result mismatches test that separate boundary. Native CI invokes the same conformance harness and deliberately removes a required field from a copied positive fixture, requiring both SDK assertions to fail without changing repository fixtures.",
            "tradeoffs": "Pairwise translation is simpler for two plugins; shared contracts require coordinated version evolution and independent conformance tests. Closed registration makes unsupported commands explicit, but every added domain operation needs a reviewed schema and mapping. Semantic invariants cannot all be expressed by JSON Schema and therefore require matching language implementations. Content-bound validator caches avoid repeated compilation while hashing current schema bytes prevents stale reuse; neither caches nor a supplied valid signature establish authority.",
            "locations": [
              {
                "path": "contracts/v1/schemas/message-envelope.schema.json",
                "symbol": "message-envelope"
              },
              {
                "path": "sdk/python/agentmux_contracts/wire.py",
                "symbol": "canonical_bytes"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "canonicalBytes"
              },
              {
                "path": "contracts/v1/registry.json",
                "symbol": "contracts"
              },
              {
                "path": "sdk/python/agentmux_contracts/validation.py",
                "symbol": "validate_payload"
              },
              {
                "path": "sdk/python/agentmux_contracts/validation.py",
                "symbol": "semantic_errors"
              },
              {
                "path": "sdk/python/agentmux_contracts/attestation.py",
                "symbol": "verify_envelope"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "validatePayload"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "verifyEnvelope"
              },
              {
                "path": "sdk/python/agentmux_contracts/state_models.py",
                "symbol": "evaluate_transition"
              },
              {
                "path": "sdk/typescript/src/state-models.ts",
                "symbol": "evaluateTransition"
              },
              {
                "path": "tests/contracts/test_recovery.py",
                "symbol": "FixtureOwner.both"
              },
              {
                "path": "tests/leaf/signed_run.py",
                "symbol": "Contracts.verify"
              },
              {
                "path": "tests/contracts/ci.py",
                "symbol": "negative_fixture"
              }
            ],
            "verificationEvidence": [
              "tests/contracts/test_conformance.py",
              "sdk/python/tests/test_contracts.py",
              "sdk/typescript/src/test.ts",
              "tests/contracts/test_payloads.py",
              "tests/contracts/test_semantics.py",
              "tests/contracts/test_state_models.py",
              "docs/planning/2026-10-09/delivery/evidence/P01/recovery-conformance-result.json",
              "docs/planning/2026-10-09/delivery/evidence/P01/signed-leaf-result.json"
            ]
          }
        }
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "P01 closed payload registry and independent semantic checks; bounded storage fixture qualification does not implement production ownership.",
          "previous": {
            "status": "applied",
            "how": "The isolated contracts/v1 package defines versioned infrastructure shapes. Independent Python and TypeScript libraries parse strict JSON, produce RFC 8785 bytes and verify Ed25519 attestation/envelope bindings against a supplied trusted key and expected audience. The current legacy runtime does not import these libraries. Domain payload registration, broker-backed ownership, enrollment and full SDK/runtime integration remain P01/later-phase obligations; cryptographic verification does not grant authorization.",
            "tradeoffs": "Pairwise translation is simpler for two plugins; shared contracts need careful evolution and must not become a universal domain schema.",
            "locations": [
              {
                "path": "contracts/v1/schemas/message-envelope.schema.json",
                "symbol": "message-envelope"
              },
              {
                "path": "sdk/python/agentmux_contracts/wire.py",
                "symbol": "canonical_bytes"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "canonicalBytes"
              }
            ],
            "verificationEvidence": [
              "tests/contracts/test_conformance.py",
              "sdk/python/tests/test_contracts.py",
              "sdk/typescript/src/test.ts"
            ]
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 pure transition and scoped leaf fixture qualification; production scope remains unchanged.",
          "previous": {
            "status": "applied",
            "how": "The separate contracts/v1 package defines closed versioned infrastructure and domain payload schemas. registry.json binds ten contract IDs to their major version, message kind, payload schema and destination service. Independent Python and TypeScript SDK validation checks those bindings, payload/context identity agreement and explicit semantic invariants for manifests, protected assembly, contexts, owner records and attestations. Full envelope verification validates the registered payload plus RFC 8785 payload bytes, Ed25519 claims, signed audience and every duplicated envelope field. The legacy runtime does not import this package. Enrolled-key resolution, live grants, authoritative domain state schemas and full plugin runtime integration remain separate obligations; validated structure and signatures do not authorize execution.",
            "locations": [
              {
                "path": "contracts/v1/schemas/message-envelope.schema.json",
                "symbol": "message-envelope"
              },
              {
                "path": "sdk/python/agentmux_contracts/wire.py",
                "symbol": "canonical_bytes"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "canonicalBytes"
              },
              {
                "path": "contracts/v1/registry.json",
                "symbol": "contracts"
              },
              {
                "path": "sdk/python/agentmux_contracts/validation.py",
                "symbol": "validate_payload"
              },
              {
                "path": "sdk/python/agentmux_contracts/validation.py",
                "symbol": "semantic_errors"
              },
              {
                "path": "sdk/python/agentmux_contracts/attestation.py",
                "symbol": "verify_envelope"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "validatePayload"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "verifyEnvelope"
              }
            ],
            "verificationEvidence": [
              "tests/contracts/test_conformance.py",
              "sdk/python/tests/test_contracts.py",
              "sdk/typescript/src/test.ts",
              "tests/contracts/test_payloads.py",
              "tests/contracts/test_semantics.py"
            ]
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 ordered recovery and signed leaf qualification; production scope and status are unchanged.",
          "previous": {
            "status": "applied",
            "how": "The separate contracts/v1 package defines closed versioned infrastructure and domain payload schemas. registry.json binds ten contract IDs to their major version, message kind, payload schema and destination service. Independent Python and TypeScript SDK validation checks those bindings, payload/context identity agreement and explicit semantic invariants for manifests, protected assembly, contexts, owner records and attestations. Full envelope verification validates the registered payload plus RFC 8785 payload bytes, Ed25519 claims, signed audience and every duplicated envelope field. The legacy runtime does not import this package. Enrolled-key resolution, live grants, authoritative domain state schemas and full plugin runtime integration remain separate obligations; validated structure and signatures do not authorize execution. P01 now also promotes five lifecycle tables with 68 unchanged edges. Independent Python and TypeScript pure evaluators bind owner snapshot, requested revision, actor evidence and required guard evidence before proposing the next state. Cancellation remains explicit through uncertain execution. These supplied fixture observations are not authenticated authority and the evaluator does not persist, deduplicate or execute work.",
            "locations": [
              {
                "path": "contracts/v1/schemas/message-envelope.schema.json",
                "symbol": "message-envelope"
              },
              {
                "path": "sdk/python/agentmux_contracts/wire.py",
                "symbol": "canonical_bytes"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "canonicalBytes"
              },
              {
                "path": "contracts/v1/registry.json",
                "symbol": "contracts"
              },
              {
                "path": "sdk/python/agentmux_contracts/validation.py",
                "symbol": "validate_payload"
              },
              {
                "path": "sdk/python/agentmux_contracts/validation.py",
                "symbol": "semantic_errors"
              },
              {
                "path": "sdk/python/agentmux_contracts/attestation.py",
                "symbol": "verify_envelope"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "validatePayload"
              },
              {
                "path": "sdk/typescript/src/index.ts",
                "symbol": "verifyEnvelope"
              },
              {
                "path": "sdk/python/agentmux_contracts/state_models.py",
                "symbol": "evaluate_transition"
              },
              {
                "path": "sdk/typescript/src/state-models.ts",
                "symbol": "evaluateTransition"
              }
            ],
            "verificationEvidence": [
              "tests/contracts/test_conformance.py",
              "sdk/python/tests/test_contracts.py",
              "sdk/typescript/src/test.ts",
              "tests/contracts/test_payloads.py",
              "tests/contracts/test_semantics.py",
              "tests/contracts/test_state_models.py"
            ]
          }
        },
        {
          "date": "2026-10-13",
          "scope": "Recover accepted L04 P01 observation contract",
          "how": "A closed registered reply uses the existing independent SDK validators and signed-recipient boundary. It distinguishes observed zero, unknown work, visible hub inventories and unavailable services.",
          "why": "The request-only schema did not fulfill the approved response contract.",
          "tradeoffs": "A shared wire schema avoids independent terminal/dashboard field meanings but needs versioned compatibility. Simpler alternative: unvalidated display strings; rejected because they cannot preserve unknown/forbidden states. Runtime authentication, filtering and freshness remain owner responsibilities.",
          "evidence": [
            "tests/contracts/test_startup_status.py",
            "tests/contracts/test_payloads.py"
          ],
          "qualification": "Focused qualification and independent repair review in progress; no runtime readiness pass."
        }
      ]
    },
    {
      "id": "PLAN-09",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Transactional Client",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/TransactionalClient.html",
      "referenceDepth": "full-public-reference",
      "how": "Apply a bounded transaction boundary at the owning JetStream record or qualified atomic batch within one stream: state, provenance, operation outcome and recoverable outgoing intent commit together. Consumer acknowledgment, projection updates, cross-stream/hub transfer and external tool actions remain separate recoverable steps. Legacy SQL plus outbox repairs remain relevant to P01 baseline work; STATE-01 supersedes SQL as the preferred new authority. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P05, P10. Implementation locations will be recorded when implemented. P00 prefers one conditional complete entity transition including state, provenance, outcome and effect intent. Same-stream batching requires the P01 SDK/concurrency proof; cross-boundary work remains recoverable. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. Configuration and registry changes also commit to their owner ledger first; KV is a cursor-bearing projection, never a second authoritative write. P01 tests/storage/run.py now qualifies this boundary only in disposable fixture owners: Python and TypeScript conditional publishes append a complete state/provenance/effect-intent record, and a two-client race admits one subject revision. Raw Python and native TypeScript atomic batches are exercised on one file-backed R1 stream. Tests reject sequence gaps, stale conditions (including an intervening ordinary commit), uncommitted batches across graceful restart and attempted cross-stream batches. The opening staging reply is not a durable acknowledgment; only a final commit acknowledgment confirms the batch. Production domain owners remain planned for P04/P05/P10; no legacy authority moved. The next bounded storage extension recovers a complete two-record batch after losing its final acknowledgment and restarting beyond the deduplication window. It also rejects fixture capability declarations spanning another stream, KV, object upload or an external tool before dispatch. Production capability registration and staged artifact recovery remain later work. The P01 incoming fixture constructs blocked state, exact origin hub/node/offer attribution and one claim intent before a single conditional record publish. Both client paths inject construction failures and recover one complete record after a simulated caller exception following commit; independent reads and retries preserve task identity and claim payload digest. This carries AMX-BASE-002 into the complete-record boundary without implementing a production owner.",
      "why": "Crash windows must not lose results or create unattributed executable work.",
      "tradeoffs": "One complete record is simpler than a batch and is preferred when it preserves the invariant. Same-stream atomic batches require pinned server/client qualification and do not create a distributed database/broker/hub/tool transaction. SQL authority is an explicit exception requiring evidence and review. Fixture qualification uses NATS Server 2.15.0 on WSL/Linux only. It does not prove native macOS, replication availability, power-loss durability, account permissions or business-level authorization. Full aggregate records remain preferred over batch coordination. The earlier native-platform exclusion describes the original report. Native macOS and Linux passed the original 14-case suite at a2e9ee6; the additional 18-case candidate needs its own CI evidence. R3 and power-loss remain unqualified. Native Linux/macOS passed the 18-case storage boundary at 7a7d47a. The new 20-case incoming fixture has WSL positive and partial-publication negative proof; its native candidate evidence remains pending. Caller exception is not a killed process or power loss.",
      "locations": [
        {
          "path": "tests/storage/run.py",
          "symbol": "main"
        },
        {
          "path": "tests/storage/python_client.py",
          "symbol": "perform"
        },
        {
          "path": "tests/storage/typescript/src/client.ts",
          "symbol": "execute"
        },
        {
          "path": "tests/storage/capacity.py",
          "symbol": "CapacityOwner.apply"
        }
      ],
      "verificationEvidence": [
        "tests/storage/run.py",
        "docs/planning/2026-10-09/delivery/evidence/P01/storage-result.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md",
        "tests/storage/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "STATE-01 approved NATS persistence direction",
          "previous": {
            "how": "Use a bounded application/local-storage adaptation: authoritative state, provenance and durable outgoing intent commit at one owning storage boundary. NATS publication and consumer acknowledgement remain separate recoverable steps; this does not claim a transactional messaging session spanning the business database and broker. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P04, P05, P10. Implementation locations will be recorded when implemented.",
            "why": "Crash windows must not lose results or create unattributed executable work.",
            "tradeoffs": "Separate writes are simpler but reproduce known defects; atomic local intent does not transact external tool effects or multiple hubs."
          },
          "reason": "Preserve the original planning rationale while updating storage placement and recovery boundaries. This is a design revision, not implementation evidence."
        },
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Apply a bounded transaction boundary at the owning JetStream record or qualified atomic batch within one stream: state, provenance, operation outcome and recoverable outgoing intent commit together. Consumer acknowledgment, projection updates, cross-stream/hub transfer and external tool actions remain separate recoverable steps. Legacy SQL plus outbox repairs remain relevant to P01 baseline work; STATE-01 supersedes SQL as the preferred new authority. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P05, P10. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        },
        {
          "date": "2026-10-09",
          "previousHow": "Apply a bounded transaction boundary at the owning JetStream record or qualified atomic batch within one stream: state, provenance, operation outcome and recoverable outgoing intent commit together. Consumer acknowledgment, projection updates, cross-stream/hub transfer and external tool actions remain separate recoverable steps. Legacy SQL plus outbox repairs remain relevant to P01 baseline work; STATE-01 supersedes SQL as the preferred new authority. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P05, P10. Implementation locations will be recorded when implemented. P00 prefers one conditional complete entity transition including state, provenance, outcome and effect intent. Same-stream batching requires the P01 SDK/concurrency proof; cross-boundary work remains recoverable. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review.",
          "reason": "Removed split config authority."
        },
        {
          "date": "2026-10-09",
          "reason": "P01 controlled execution and remaining storage failure qualification; statuses unchanged.",
          "previous": {
            "how": "Apply a bounded transaction boundary at the owning JetStream record or qualified atomic batch within one stream: state, provenance, operation outcome and recoverable outgoing intent commit together. Consumer acknowledgment, projection updates, cross-stream/hub transfer and external tool actions remain separate recoverable steps. Legacy SQL plus outbox repairs remain relevant to P01 baseline work; STATE-01 supersedes SQL as the preferred new authority. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P05, P10. Implementation locations will be recorded when implemented. P00 prefers one conditional complete entity transition including state, provenance, outcome and effect intent. Same-stream batching requires the P01 SDK/concurrency proof; cross-boundary work remains recoverable. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. Configuration and registry changes also commit to their owner ledger first; KV is a cursor-bearing projection, never a second authoritative write. P01 tests/storage/run.py now qualifies this boundary only in disposable fixture owners: Python and TypeScript conditional publishes append a complete state/provenance/effect-intent record, and a two-client race admits one subject revision. Raw Python and native TypeScript atomic batches are exercised on one file-backed R1 stream. Tests reject sequence gaps, stale conditions (including an intervening ordinary commit), uncommitted batches across graceful restart and attempted cross-stream batches. The opening staging reply is not a durable acknowledgment; only a final commit acknowledgment confirms the batch. Production domain owners remain planned for P04/P05/P10; no legacy authority moved.",
            "tradeoffs": "One complete record is simpler than a batch and is preferred when it preserves the invariant. Same-stream atomic batches require pinned server/client qualification and do not create a distributed database/broker/hub/tool transaction. SQL authority is an explicit exception requiring evidence and review. Fixture qualification uses NATS Server 2.15.0 on WSL/Linux only. It does not prove native macOS, replication availability, power-loss durability, account permissions or business-level authorization. Full aggregate records remain preferred over batch coordination.",
            "locations": [
              {
                "path": "tests/storage/run.py",
                "symbol": "main"
              },
              {
                "path": "tests/storage/python_client.py",
                "symbol": "perform"
              },
              {
                "path": "tests/storage/typescript/src/client.ts",
                "symbol": "execute"
              }
            ],
            "verificationEvidence": [
              "tests/storage/run.py",
              "docs/planning/2026-10-09/delivery/evidence/P01/storage-result.json"
            ]
          }
        }
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "P01 closed payload registry and independent semantic checks; bounded storage fixture qualification does not implement production ownership.",
          "previous": {
            "status": "planned",
            "how": "Apply a bounded transaction boundary at the owning JetStream record or qualified atomic batch within one stream: state, provenance, operation outcome and recoverable outgoing intent commit together. Consumer acknowledgment, projection updates, cross-stream/hub transfer and external tool actions remain separate recoverable steps. Legacy SQL plus outbox repairs remain relevant to P01 baseline work; STATE-01 supersedes SQL as the preferred new authority. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P05, P10. Implementation locations will be recorded when implemented. P00 prefers one conditional complete entity transition including state, provenance, outcome and effect intent. Same-stream batching requires the P01 SDK/concurrency proof; cross-boundary work remains recoverable. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. Configuration and registry changes also commit to their owner ledger first; KV is a cursor-bearing projection, never a second authoritative write.",
            "tradeoffs": "One complete record is simpler than a batch and is preferred when it preserves the invariant. Same-stream atomic batches require pinned server/client qualification and do not create a distributed database/broker/hub/tool transaction. SQL authority is an explicit exception requiring evidence and review.",
            "locations": [],
            "verificationEvidence": []
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 incoming creation invariant qualification; production status unchanged",
          "previous": {
            "how": "Apply a bounded transaction boundary at the owning JetStream record or qualified atomic batch within one stream: state, provenance, operation outcome and recoverable outgoing intent commit together. Consumer acknowledgment, projection updates, cross-stream/hub transfer and external tool actions remain separate recoverable steps. Legacy SQL plus outbox repairs remain relevant to P01 baseline work; STATE-01 supersedes SQL as the preferred new authority. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P05, P10. Implementation locations will be recorded when implemented. P00 prefers one conditional complete entity transition including state, provenance, outcome and effect intent. Same-stream batching requires the P01 SDK/concurrency proof; cross-boundary work remains recoverable. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. Configuration and registry changes also commit to their owner ledger first; KV is a cursor-bearing projection, never a second authoritative write. P01 tests/storage/run.py now qualifies this boundary only in disposable fixture owners: Python and TypeScript conditional publishes append a complete state/provenance/effect-intent record, and a two-client race admits one subject revision. Raw Python and native TypeScript atomic batches are exercised on one file-backed R1 stream. Tests reject sequence gaps, stale conditions (including an intervening ordinary commit), uncommitted batches across graceful restart and attempted cross-stream batches. The opening staging reply is not a durable acknowledgment; only a final commit acknowledgment confirms the batch. Production domain owners remain planned for P04/P05/P10; no legacy authority moved. The next bounded storage extension recovers a complete two-record batch after losing its final acknowledgment and restarting beyond the deduplication window. It also rejects fixture capability declarations spanning another stream, KV, object upload or an external tool before dispatch. Production capability registration and staged artifact recovery remain later work.",
            "tradeoffs": "One complete record is simpler than a batch and is preferred when it preserves the invariant. Same-stream atomic batches require pinned server/client qualification and do not create a distributed database/broker/hub/tool transaction. SQL authority is an explicit exception requiring evidence and review. Fixture qualification uses NATS Server 2.15.0 on WSL/Linux only. It does not prove native macOS, replication availability, power-loss durability, account permissions or business-level authorization. Full aggregate records remain preferred over batch coordination. The earlier native-platform exclusion describes the original report. Native macOS and Linux passed the original 14-case suite at a2e9ee6; the additional 18-case candidate needs its own CI evidence. R3 and power-loss remain unqualified."
          }
        },
        {
          "date": "2026-10-13",
          "scope": "Recover S03 bounded completion reserve qualification",
          "how": "A complete retained capacity record includes budget allocation and operation outcome. Subject-revision compare-and-append serializes contenders; retained operation lookup prevents duplicate charging after restart.",
          "why": "Bulk work must not consume separately budgeted completion/reconciliation capacity. Existing storage cases did not exercise that admission guarantee.",
          "tradeoffs": "Conservative per-record physical slots and two reserved final records sacrifice capacity for an auditable bound. Simpler alternative: payload-only usage thresholds; rejected because record framing and history can consume broker capacity. This single-task fixture does not implement production multi-task policy or disk-failure guarantees.",
          "evidence": [
            "tests/storage/capacity.py",
            "tests/storage/run.py"
          ],
          "qualification": "Real-broker fixture qualification pending; production pattern status stays planned."
        }
      ]
    },
    {
      "id": "PLAN-10",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Idempotent Receiver",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/IdempotentReceiver.html",
      "referenceDepth": "full-public-reference",
      "how": "Bind an operation ID, canonical payload hash and expected version to the durable NATS-owned outcome. Reconcile lost acknowledgments, reject changed-payload ID reuse, and retain outcomes/deletion markers across the agreed replay and restore horizon. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P10. Implementation locations will be recorded when implemented. P00 retains operation outcomes and payload digests beyond broker deduplication windows, with reconciliation-required on missing history. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. P01 Python and TypeScript fixture clients independently scan retained authoritative history to recover an older operation ID and matching digest after later writes, a gracefully restarted broker and expiry of its short deduplication window. They return the existing record without republishing, reject changed digests and report missing history as reconciliation-required. The lost-ack fixture deliberately omits the publisher reply inbox. Production duplicate admission, durable indexes and external-effect control remain planned; fixture reconciliation is not a deployed receiver or exactly-once execution promise. The P01 leaf fixture additionally returns retained acceptance for the same offer bytes and rejects a changed digest after disconnection and independent broker restarts. Its durable receiver record remains unchanged and execution count stays one. Fixture dispatch logic is bounded and does not implement the production receiver. Ordered recovery tests add an explicitly in-memory fixture owner. It checks current authorization and deadline before replay or lookup, binds operation identity to event, actor role and canonical input, returns an identical prior outcome and rejects changed input. A fresh authorized lookup may recover an outcome after the original command expires. Unknown transport outcome permits no automatic reassignment; only a fixture-owned before-dispatch observation produces unavailable. The signed leaf test separately retains the accepted decision before deliberately losing its publication, then reconciles the same signed operation/digest after graceful restarts without another execution. These are bounded recovery checks, not a production admission or grant service. A real KV view deliberately retains an older source cursor. Its conditional write fails; both clients read current owner state, and explicit fixture policy revalidation denies a new write. This qualifies the fixture boundary, not production grant lookup. Lost final batch acknowledgments are reconciled by retained operation identity and digest without another transition.",
      "why": "At-least-once delivery and uncertain replies must not create duplicate task attempts.",
      "tradeoffs": "Broker duplicate windows are simpler but insufficient for business ownership. Durable outcome records and conflict policy cost storage; external actions require their own idempotency or explicit unknown-outcome handling. The fixture scan is bounded to 10,000 retained records and is not a production indexing or retention strategy. Authoritative history costs storage; deterministic recovery requires preserving history or verified checkpoints, rather than interpreting absence as permission to re-execute.",
      "locations": [
        {
          "path": "tests/storage/python_client.py",
          "symbol": "perform"
        },
        {
          "path": "tests/storage/typescript/src/client.ts",
          "symbol": "execute"
        },
        {
          "path": "tests/storage/run.py",
          "symbol": "main"
        },
        {
          "path": "tests/leaf/run.py",
          "symbol": "exercise"
        },
        {
          "path": "tests/contracts/test_recovery.py",
          "symbol": "FixtureOwner.submit"
        },
        {
          "path": "tests/contracts/test_recovery.py",
          "symbol": "FixtureOwner.lookup"
        },
        {
          "path": "tests/leaf/signed_run.py",
          "symbol": "exercise"
        },
        {
          "path": "tests/storage/capacity.py",
          "symbol": "CapacityOwner.replay"
        }
      ],
      "verificationEvidence": [
        "tests/storage/run.py",
        "docs/planning/2026-10-09/delivery/evidence/P01/storage-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/recovery-conformance-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/signed-leaf-result.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md",
        "tests/storage/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "STATE-01 approved NATS persistence direction",
          "previous": {
            "how": "Bind duplicate command/event IDs to a durable prior outcome under the authoritative owner. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P04, P10. Implementation locations will be recorded when implemented.",
            "why": "At-least-once delivery and uncertain replies must not create duplicate task attempts.",
            "tradeoffs": "Best-effort duplicate windows are simpler but inadequate for business ownership; durable retention and conflict policy cost storage."
          },
          "reason": "Preserve the original planning rationale while updating storage placement and recovery boundaries. This is a design revision, not implementation evidence."
        },
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Bind an operation ID, canonical payload hash and expected version to the durable NATS-owned outcome. Reconcile lost acknowledgments, reject changed-payload ID reuse, and retain outcomes/deletion markers across the agreed replay and restore horizon. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P10. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        },
        {
          "date": "2026-10-09",
          "reason": "P01 controlled execution and remaining storage failure qualification; statuses unchanged.",
          "previous": {
            "how": "Bind an operation ID, canonical payload hash and expected version to the durable NATS-owned outcome. Reconcile lost acknowledgments, reject changed-payload ID reuse, and retain outcomes/deletion markers across the agreed replay and restore horizon. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P10. Implementation locations will be recorded when implemented. P00 retains operation outcomes and payload digests beyond broker deduplication windows, with reconciliation-required on missing history. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. P01 Python and TypeScript fixture clients independently scan retained authoritative history to recover an older operation ID and matching digest after later writes, a gracefully restarted broker and expiry of its short deduplication window. They return the existing record without republishing, reject changed digests and report missing history as reconciliation-required. The lost-ack fixture deliberately omits the publisher reply inbox. Production duplicate admission, durable indexes and external-effect control remain planned; fixture reconciliation is not a deployed receiver or exactly-once execution promise. The P01 leaf fixture additionally returns retained acceptance for the same offer bytes and rejects a changed digest after disconnection and independent broker restarts. Its durable receiver record remains unchanged and execution count stays one. Fixture dispatch logic is bounded and does not implement the production receiver. Ordered recovery tests add an explicitly in-memory fixture owner. It checks current authorization and deadline before replay or lookup, binds operation identity to event, actor role and canonical input, returns an identical prior outcome and rejects changed input. A fresh authorized lookup may recover an outcome after the original command expires. Unknown transport outcome permits no automatic reassignment; only a fixture-owned before-dispatch observation produces unavailable. The signed leaf test separately retains the accepted decision before deliberately losing its publication, then reconciles the same signed operation/digest after graceful restarts without another execution. These are bounded recovery checks, not a production admission or grant service.",
            "tradeoffs": "Broker duplicate windows are simpler but insufficient for business ownership. Durable outcome records and conflict policy cost storage; external actions require their own idempotency or explicit unknown-outcome handling. The fixture scan is bounded to 10,000 retained records and is not a production indexing or retention strategy. Authoritative history costs storage; deterministic recovery requires preserving history or verified checkpoints, rather than interpreting absence as permission to re-execute.",
            "locations": [
              {
                "path": "tests/storage/python_client.py",
                "symbol": "perform"
              },
              {
                "path": "tests/storage/typescript/src/client.ts",
                "symbol": "execute"
              },
              {
                "path": "tests/storage/run.py",
                "symbol": "main"
              },
              {
                "path": "tests/leaf/run.py",
                "symbol": "exercise"
              },
              {
                "path": "tests/contracts/test_recovery.py",
                "symbol": "FixtureOwner.submit"
              },
              {
                "path": "tests/contracts/test_recovery.py",
                "symbol": "FixtureOwner.lookup"
              },
              {
                "path": "tests/leaf/signed_run.py",
                "symbol": "exercise"
              }
            ],
            "verificationEvidence": [
              "tests/storage/run.py",
              "docs/planning/2026-10-09/delivery/evidence/P01/storage-result.json",
              "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json",
              "docs/planning/2026-10-09/delivery/evidence/P01/recovery-conformance-result.json",
              "docs/planning/2026-10-09/delivery/evidence/P01/signed-leaf-result.json"
            ]
          }
        }
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "P01 closed payload registry and independent semantic checks; bounded storage fixture qualification does not implement production ownership.",
          "previous": {
            "status": "planned",
            "how": "Bind an operation ID, canonical payload hash and expected version to the durable NATS-owned outcome. Reconcile lost acknowledgments, reject changed-payload ID reuse, and retain outcomes/deletion markers across the agreed replay and restore horizon. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P10. Implementation locations will be recorded when implemented. P00 retains operation outcomes and payload digests beyond broker deduplication windows, with reconciliation-required on missing history. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review.",
            "tradeoffs": "Broker duplicate windows are simpler but insufficient for business ownership. Durable outcome records and conflict policy cost storage; external actions require their own idempotency or explicit unknown-outcome handling.",
            "locations": [],
            "verificationEvidence": []
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 pure transition and scoped leaf fixture qualification; production scope remains unchanged.",
          "previous": {
            "status": "planned",
            "how": "Bind an operation ID, canonical payload hash and expected version to the durable NATS-owned outcome. Reconcile lost acknowledgments, reject changed-payload ID reuse, and retain outcomes/deletion markers across the agreed replay and restore horizon. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P10. Implementation locations will be recorded when implemented. P00 retains operation outcomes and payload digests beyond broker deduplication windows, with reconciliation-required on missing history. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. P01 Python and TypeScript fixture clients independently scan retained authoritative history to recover an older operation ID and matching digest after later writes, a gracefully restarted broker and expiry of its short deduplication window. They return the existing record without republishing, reject changed digests and report missing history as reconciliation-required. The lost-ack fixture deliberately omits the publisher reply inbox. Production duplicate admission, durable indexes and external-effect control remain planned; fixture reconciliation is not a deployed receiver or exactly-once execution promise.",
            "locations": [
              {
                "path": "tests/storage/python_client.py",
                "symbol": "perform"
              },
              {
                "path": "tests/storage/typescript/src/client.ts",
                "symbol": "execute"
              },
              {
                "path": "tests/storage/run.py",
                "symbol": "main"
              }
            ],
            "verificationEvidence": [
              "tests/storage/run.py",
              "docs/planning/2026-10-09/delivery/evidence/P01/storage-result.json"
            ]
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 ordered recovery and signed leaf qualification; production scope and status are unchanged.",
          "previous": {
            "status": "planned",
            "how": "Bind an operation ID, canonical payload hash and expected version to the durable NATS-owned outcome. Reconcile lost acknowledgments, reject changed-payload ID reuse, and retain outcomes/deletion markers across the agreed replay and restore horizon. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P01, P04, P10. Implementation locations will be recorded when implemented. P00 retains operation outcomes and payload digests beyond broker deduplication windows, with reconciliation-required on missing history. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. P01 Python and TypeScript fixture clients independently scan retained authoritative history to recover an older operation ID and matching digest after later writes, a gracefully restarted broker and expiry of its short deduplication window. They return the existing record without republishing, reject changed digests and report missing history as reconciliation-required. The lost-ack fixture deliberately omits the publisher reply inbox. Production duplicate admission, durable indexes and external-effect control remain planned; fixture reconciliation is not a deployed receiver or exactly-once execution promise. The P01 leaf fixture additionally returns retained acceptance for the same offer bytes and rejects a changed digest after disconnection and independent broker restarts. Its durable receiver record remains unchanged and execution count stays one. Fixture dispatch logic is bounded and does not implement the production receiver.",
            "locations": [
              {
                "path": "tests/storage/python_client.py",
                "symbol": "perform"
              },
              {
                "path": "tests/storage/typescript/src/client.ts",
                "symbol": "execute"
              },
              {
                "path": "tests/storage/run.py",
                "symbol": "main"
              },
              {
                "path": "tests/leaf/run.py",
                "symbol": "exercise"
              }
            ],
            "verificationEvidence": [
              "tests/storage/run.py",
              "docs/planning/2026-10-09/delivery/evidence/P01/storage-result.json",
              "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json"
            ]
          }
        },
        {
          "date": "2026-10-13",
          "scope": "Recover S03 bounded completion reserve qualification",
          "how": "A complete retained capacity record includes budget allocation and operation outcome. Subject-revision compare-and-append serializes contenders; retained operation lookup prevents duplicate charging after restart.",
          "why": "Bulk work must not consume separately budgeted completion/reconciliation capacity. Existing storage cases did not exercise that admission guarantee.",
          "tradeoffs": "Conservative per-record physical slots and two reserved final records sacrifice capacity for an auditable bound. Simpler alternative: payload-only usage thresholds; rejected because record framing and history can consume broker capacity. This single-task fixture does not implement production multi-task policy or disk-failure guarantees.",
          "evidence": [
            "tests/storage/capacity.py",
            "tests/storage/run.py"
          ],
          "qualification": "Real-broker fixture qualification pending; production pattern status stays planned."
        }
      ]
    },
    {
      "id": "PLAN-11",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Correlation Identifier",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/CorrelationIdentifier.html",
      "referenceDepth": "full-public-reference",
      "how": "Keep task, delegation, attempt, message, operation and artifact identities linked but distinct. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01, P05, P10. Implementation locations will be recorded when implemented. The P01 leaf fixture correlates an offer, lost acknowledgment lookup and retained result with stable operation identity and digest. Correlation alone never grants authority or accepts a task; only the separate origin owner writes acceptance. The signed leaf owner additionally binds executor hub, task, delegation, attempt and repository revision in a verified execution report to its retained offer. Each negative report is validly re-signed and passes SDK admission before the owner rejects the mismatch. Artifact bytes and digest are checked before origin acceptance; a receiving completion report alone cannot accept the task. Reconciled signed acceptance decisions must also match the reserved sender, destination, task, delegation and attempt. Three SDK-valid task/delegation/attempt mismatches are rejected by the owner without ledger mutation.",
      "why": "Progress and results must bind to the selected executor and correct task version.",
      "tradeoffs": "One overloaded task ID is simpler but loses provenance; more IDs need disciplined propagation and do not authenticate a sender.",
      "locations": [
        {
          "path": "tests/leaf/run.py",
          "symbol": "exercise"
        },
        {
          "path": "tests/leaf/signed_run.py",
          "symbol": "result_matches_offer"
        },
        {
          "path": "tests/leaf/signed_run.py",
          "symbol": "decision_matches_offer"
        }
      ],
      "verificationEvidence": [
        "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/signed-leaf-result.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json"
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "P01 pure transition and scoped leaf fixture qualification; production scope remains unchanged.",
          "previous": {
            "status": "planned",
            "how": "Keep task, delegation, attempt, message, operation and artifact identities linked but distinct. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01, P05, P10. Implementation locations will be recorded when implemented.",
            "locations": [],
            "verificationEvidence": []
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 ordered recovery and signed leaf qualification; production scope and status are unchanged.",
          "previous": {
            "status": "planned",
            "how": "Keep task, delegation, attempt, message, operation and artifact identities linked but distinct. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P01, P05, P10. Implementation locations will be recorded when implemented. The P01 leaf fixture correlates an offer, lost acknowledgment lookup and retained result with stable operation identity and digest. Correlation alone never grants authority or accepts a task; only the separate origin owner writes acceptance.",
            "locations": [
              {
                "path": "tests/leaf/run.py",
                "symbol": "exercise"
              }
            ],
            "verificationEvidence": [
              "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json"
            ]
          }
        }
      ]
    },
    {
      "id": "PLAN-12",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Claim Check",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/StoreInLibrary.html",
      "referenceDepth": "full-public-reference",
      "how": "Send authorized immutable artifact references and digests while owning providers retain the bytes in NATS Object Store where size/retention fit, or an approved external artifact store. Use version/digest names and recheck access on retrieval. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P04, P10, P11. Implementation locations will be recorded when implemented. P00 proposes upload/verify before reference commit and reference-aware orphan collection, using immutable artifact IDs and byte digests. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review.",
      "why": "Code and engineering evidence can exceed safe message sizes and have separate access policies.",
      "tradeoffs": "Inline small evidence is simpler. References require coordinated retention and backups; uploading bytes and committing a task record are separate steps, with incomplete/orphan objects handled explicitly.",
      "locations": [],
      "verificationEvidence": [],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "STATE-01 approved NATS persistence direction",
          "previous": {
            "how": "Send authorized immutable artifact references/digests rather than large payloads in control messages. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P04, P10, P11. Implementation locations will be recorded when implemented.",
            "why": "Code and engineering evidence can exceed safe message sizes and have separate access policies.",
            "tradeoffs": "Inline small payloads are simpler; referenced content requires access rechecks, partial-transfer handling and retention coordination."
          },
          "reason": "Preserve the original planning rationale while updating storage placement and recovery boundaries. This is a design revision, not implementation evidence."
        },
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Send authorized immutable artifact references and digests while owning providers retain the bytes in NATS Object Store where size/retention fit, or an approved external artifact store. Use version/digest names and recheck access on retrieval. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P04, P10, P11. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        }
      ]
    },
    {
      "id": "PLAN-13",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Message Store",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/MessageStore.html",
      "referenceDepth": "full-public-reference",
      "how": "Retain authoritative validated JetStream records with scoped replay, versioned checkpoints and explicit retention. Derive current KV views and optional SQL query indexes without replaying effects. Keep task/audit history separate from acknowledged work queues and bounded presence records. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P04, P07, P10, P12. Implementation locations will be recorded when implemented. P00 proposes non-expiring authoritative history by default, explicit quota rejection, verified checkpoints and fenced restore, with optional rebuildable SQL views. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. The P01 leaf fixture uses distinct private owner-account JetStream ledgers for origin reservation and receiver acceptance/result. Restart restores each record independently; the federation account cannot access the owner stream. No shared global store or production retention guarantee is implied. The signed leaf fixture stores the verified offer, signed acceptance decision and signed result in the receiver private ledger. The origin keeps its own reservation and acceptance record. Restart checks compare retained records before replay; test reports contain public-key fingerprints rather than private seeds. This remains independent local single-node persistence with graceful restarts, not production retention or disaster-recovery qualification.",
      "why": "Recovery, audits and authorized dashboard history must survive disconnected viewers and hubs.",
      "tradeoffs": "A local relational authority simplifies joins and multi-row constraints, but the accepted direction prefers shared NATS persistence. Rebuildable views add lag and recovery complexity; quotas, snapshots, schema evolution, privacy deletion and retention gaps require explicit evidence.",
      "locations": [
        {
          "path": "tests/leaf/run.py",
          "symbol": "append"
        },
        {
          "path": "tests/leaf/run.py",
          "symbol": "latest"
        },
        {
          "path": "tests/leaf/signed_run.py",
          "symbol": "exercise"
        }
      ],
      "verificationEvidence": [
        "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json",
        "docs/planning/2026-10-09/delivery/evidence/P01/signed-leaf-result.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "STATE-01 approved NATS persistence direction",
          "previous": {
            "how": "Retain durable required events/evidence with scoped replay and retention policy. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P04, P07, P12. Implementation locations will be recorded when implemented.",
            "why": "Recovery, audits and authorized dashboard history must survive disconnected viewers and hubs.",
            "tradeoffs": "Ephemeral logs are simpler but cannot support these guarantees; retention, deletion and sensitive data create operating cost."
          },
          "reason": "Preserve the original planning rationale while updating storage placement and recovery boundaries. This is a design revision, not implementation evidence."
        },
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Retain authoritative validated JetStream records with scoped replay, versioned checkpoints and explicit retention. Derive current KV views and optional SQL query indexes without replaying effects. Keep task/audit history separate from acknowledged work queues and bounded presence records. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P04, P07, P10, P12. Implementation locations will be recorded when implemented.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        }
      ],
      "implementationRevisions": [
        {
          "date": "2026-10-09",
          "reason": "P01 pure transition and scoped leaf fixture qualification; production scope remains unchanged.",
          "previous": {
            "status": "planned",
            "how": "Retain authoritative validated JetStream records with scoped replay, versioned checkpoints and explicit retention. Derive current KV views and optional SQL query indexes without replaying effects. Keep task/audit history separate from acknowledged work queues and bounded presence records. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P04, P07, P10, P12. Implementation locations will be recorded when implemented. P00 proposes non-expiring authoritative history by default, explicit quota rejection, verified checkpoints and fenced restore, with optional rebuildable SQL views. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review.",
            "locations": [],
            "verificationEvidence": []
          }
        },
        {
          "date": "2026-10-09",
          "reason": "P01 ordered recovery and signed leaf qualification; production scope and status are unchanged.",
          "previous": {
            "status": "planned",
            "how": "Retain authoritative validated JetStream records with scoped replay, versioned checkpoints and explicit retention. Derive current KV views and optional SQL query indexes without replaying effects. Keep task/audit history separate from acknowledged work queues and bounded presence records. Proposed location: docs/planning/2026-10-09/implementation-plan.md, STATE-01, P04, P07, P10, P12. Implementation locations will be recorded when implemented. P00 proposes non-expiring authoritative history by default, explicit quota rejection, verified checkpoints and fenced restore, with optional rebuildable SQL views. See delivery/decisions/storage-contract.md. This is a recommendation pending P00 review. The P01 leaf fixture uses distinct private owner-account JetStream ledgers for origin reservation and receiver acceptance/result. Restart restores each record independently; the federation account cannot access the owner stream. No shared global store or production retention guarantee is implied.",
            "locations": [
              {
                "path": "tests/leaf/run.py",
                "symbol": "append"
              },
              {
                "path": "tests/leaf/run.py",
                "symbol": "latest"
              }
            ],
            "verificationEvidence": [
              "docs/planning/2026-10-09/delivery/evidence/P01/leaf-result.json"
            ]
          }
        }
      ]
    },
    {
      "id": "PLAN-14",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Control Bus",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/ControlBus.html",
      "referenceDepth": "full-public-reference",
      "how": "Expose surrounding runtime operations for allowed drain, pause, cancellation and recovery over authorized NATS contracts. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P05, P07, P10. Implementation locations will be recorded when implemented. LOCAL-01 startup reads scoped instance/hub status after readiness; P10 supplies real hub observations. Starting local infrastructure before NATS exists remains a bounded host bootstrap operation, not a kernel command channel. P00 proposes one authorized instance/work/partner status contract for terminal and dashboard clients; local pre-broker Compose startup is the bounded infrastructure exception. See delivery/decisions/startup-contract.md. This is a recommendation pending P00 review.",
      "why": "Operators need observable action control without opening protected kernel command channels.",
      "tradeoffs": "Local shell procedures are simpler but harder to govern; controls need authority, durable intent and honest unknown outcomes. Cached status must disclose age and unavailable services; it cannot authorize work, widen hub trust or prove partner capacity.",
      "locations": [],
      "verificationEvidence": [],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json",
        "docs/planning/2026-10-09/delivery/decisions/README.md",
        "docs/planning/2026-10-09/delivery/contracts/README.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-09",
          "decision": "LOCAL-01 approved automatic Compose startup direction",
          "previous": {
            "how": "Expose surrounding runtime operations for allowed drain, pause, cancellation and recovery over authorized NATS contracts. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P05, P07, P10. Implementation locations will be recorded when implemented.",
            "why": "Operators need observable action control without opening protected kernel command channels.",
            "tradeoffs": "Local shell procedures are simpler but harder to govern; controls need authority, durable intent and honest unknown outcomes."
          },
          "reason": "Retain earlier rationale; clarify bootstrap versus runtime control and client status. Planned only, not implementation evidence."
        },
        {
          "date": "2026-10-09",
          "decision": "P00 concrete implementation recommendation; pending review",
          "previousHow": "Expose surrounding runtime operations for allowed drain, pause, cancellation and recovery over authorized NATS contracts. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P03, P05, P07, P10. Implementation locations will be recorded when implemented. LOCAL-01 startup reads scoped instance/hub status after readiness; P10 supplies real hub observations. Starting local infrastructure before NATS exists remains a bounded host bootstrap operation, not a kernel command channel.",
          "evidence": "docs/planning/2026-10-09/delivery/decisions/README.md"
        }
      ]
    },
    {
      "id": "PLAN-15",
      "status": "planned",
      "catalog": "eip",
      "pattern": "Content-Based Router",
      "source": "https://www.enterpriseintegrationpatterns.com/patterns/messaging/ContentBasedRouter.html",
      "referenceDepth": "full-public-reference",
      "how": "Route eligible work using explicit task requirements and current approved capabilities, with optional Jev advice. Proposed location: docs/planning/2026-10-09/implementation-plan.md, P05, P08, P10. Implementation locations will be recorded when implemented.",
      "why": "Connected teams need purposeful work distribution while preserving grants and origin ownership.",
      "tradeoffs": "Manual destination choice is simpler; semantic ranking adds cost/uncertainty and must never replace deterministic eligibility or receiver acceptance.",
      "locations": [],
      "verificationEvidence": [],
      "decisionEvidence": [
        "docs/planning/2026-10-09/implementation-plan.md",
        "docs/planning/2026-10-09/phases.json"
      ]
    },
    {
      "id": "P02-TLS-01",
      "status": "observed",
      "catalog": "dofactory",
      "pattern": "Adapter",
      "source": "https://www.dofactory.com/net/adapter-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "The localtls Dialer implements the NATS custom dialer interface. It opens only the enrolled endpoint and returns a socket after TLS 1.3 chain, DNS, validity and exact leaf-pin checks. NATS treats that returned socket as already secured. The adapter owns cancellation and socket cleanup; protocol, health and status clients share the same immutable trust object. This narrow P02 implementation does not complete the planned client, worker, vendor, storage or UI adapters in PLAN-02. The deployment raw dialer used by historical Probe/Observe and declared Team TLS connections owns only its DialContext sockets. It retains exact failures from owner/SDK/cancellation and concrete RawTransportCleanupError retry state. Probe, Observe and Team clear successful facts on any reported cleanup failure. Team transport remains separate from enrolled local TLS-first authentication; do not equate the two authority policies.",
      "why": "A local peer must prove its enrolled identity before any NATS CONNECT credential is sent. Broker INFO and Docker identity checks alone cannot authenticate a socket.",
      "tradeoffs": "The adapter adds TLS enrollment, fixed trust distribution, expiry/rotation and cleanup obligations. The original protocol cleanup finding and later observer/bridge retry-handle finding are retained in historical reviews and now have independently reviewed repairs. Typed errors retain only the exact owned connection for bounded retry and invalidate successful observations on cleanup failure. Installed Compose and native qualification remain open; Linux transport and focused cleanup checks do not accept the phase. A subsequent health caller cleanup finding has a reviewed concrete-owner repair. Actual helper fault and early fixture cleanup controls pass; outer Probe/Observe result invalidation was reviewed in source, without a claim of forced outer-caller close failure. Native and installed acceptance remains separate. The bare standard NATS dialer is simpler but cannot preserve the exact failed cleanup owner. Raw/socket component fault controls and caller source invalidation do not claim forced full-caller fault injection or native Darwin/Compose acceptance.",
      "locations": [
        {
          "path": "platform/localtls/client.go",
          "symbol": "Dialer"
        },
        {
          "path": "platform/kernel/protocol/transport.go",
          "symbol": "Open"
        },
        {
          "path": "platform/deployment/probe.go",
          "symbol": "ProbeOptions"
        },
        {
          "path": "platform/launcher/transport_cleanup.go",
          "symbol": "TransportCleanupError"
        },
        {
          "path": "platform/deployment/probe_cleanup.go",
          "symbol": "ProbeCleanupError"
        },
        {
          "path": "platform/deployment/raw_transport_cleanup.go",
          "symbol": "RawTransportCleanupError"
        },
        {
          "path": "platform/deployment/team_connection.go",
          "symbol": "TeamConnection.Observe"
        }
      ],
      "verificationEvidence": [
        "platform/localtls/client_test.go",
        "platform/kernel/protocol/server_trust_test.go",
        "platform/deployment/local_tls_probe_test.go",
        "docs/planning/2026-10-09/delivery/evidence/P02/combined-cleanup-independent/independent-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/health-cleanup-independent/independent-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/delivery/decisions/P02-local-broker-authentication.md"
      ],
      "planningRevisions": [
        {
          "date": "2026-10-13",
          "decision": "Record the observed P02 transport adapter without advancing later adapter qualification",
          "reason": "Source and focused tests exist; caller cleanup repair, real Compose and native platform verification remain open."
        },
        {
          "date": "2026-10-14",
          "decision": "Close the concrete protocol, observer and owner-bridge retained cleanup findings from reviewed evidence; keep installed and native qualification open.",
          "previousTradeoffs": "Using the ordinary NATS dialer with claimed INFO identity is simpler but permits credentials to reach an impersonating peer. This adapter adds TLS enrollment, fixed trust distribution, explicit expiry/rotation and cleanup obligations. Independent review found a protocol caller that discards cleanup errors; that repair and native qualification remain open. Passing Linux transport tests are not installed Compose or phase acceptance.",
          "evidence": [
            "docs/planning/2026-10-09/delivery/evidence/P02/shared-tls-cleanup-independent/independent-review.json",
            "docs/planning/2026-10-09/delivery/evidence/P02/combined-cleanup-independent/independent-review.json"
          ]
        },
        {
          "date": "2026-10-14",
          "decision": "Close the health caller retained-owner finding with independent source and actual owned-socket controls; preserve caller integration limits.",
          "previousTradeoffs": "The adapter adds TLS enrollment, fixed trust distribution, expiry/rotation and cleanup obligations. The original protocol cleanup finding and later observer/bridge retry-handle finding are retained in historical reviews and now have independently reviewed repairs. Typed errors retain only the exact owned connection for bounded retry and invalidate successful observations on cleanup failure. Installed Compose and native qualification remain open; Linux transport and focused cleanup checks do not accept the phase.",
          "evidence": "docs/planning/2026-10-09/delivery/evidence/P02/health-cleanup-independent/independent-review.json"
        },
        {
          "date": "2026-10-14",
          "reviewer": "Codex",
          "previous": {
            "how": "The localtls Dialer implements the NATS custom dialer interface. It opens only the enrolled endpoint and returns a socket after TLS 1.3 chain, DNS, validity and exact leaf-pin checks. NATS treats that returned socket as already secured. The adapter owns cancellation and socket cleanup; protocol, health and status clients share the same immutable trust object. This narrow P02 implementation does not complete the planned client, worker, vendor, storage or UI adapters in PLAN-02.",
            "tradeoffs": "The adapter adds TLS enrollment, fixed trust distribution, expiry/rotation and cleanup obligations. The original protocol cleanup finding and later observer/bridge retry-handle finding are retained in historical reviews and now have independently reviewed repairs. Typed errors retain only the exact owned connection for bounded retry and invalidate successful observations on cleanup failure. Installed Compose and native qualification remain open; Linux transport and focused cleanup checks do not accept the phase. A subsequent health caller cleanup finding has a reviewed concrete-owner repair. Actual helper fault and early fixture cleanup controls pass; outer Probe/Observe result invalidation was reviewed in source, without a claim of forced outer-caller close failure. Native and installed acceptance remains separate.",
            "locations": [
              {
                "path": "platform/localtls/client.go",
                "symbol": "Dialer"
              },
              {
                "path": "platform/kernel/protocol/transport.go",
                "symbol": "Open"
              },
              {
                "path": "platform/deployment/probe.go",
                "symbol": "ProbeOptions"
              },
              {
                "path": "platform/launcher/transport_cleanup.go",
                "symbol": "TransportCleanupError"
              },
              {
                "path": "platform/deployment/probe_cleanup.go",
                "symbol": "ProbeCleanupError"
              }
            ],
            "verificationEvidence": [
              "platform/localtls/client_test.go",
              "platform/kernel/protocol/server_trust_test.go",
              "platform/deployment/local_tls_probe_test.go",
              "docs/planning/2026-10-09/delivery/evidence/P02/combined-cleanup-independent/independent-review.json",
              "docs/planning/2026-10-09/delivery/evidence/P02/health-cleanup-independent/independent-review.json"
            ]
          },
          "note": "Resolved independent current source documentation finding; resource mechanisms are not extra patterns. Component evidence does not prove native or phase acceptance.",
          "evidence": "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json"
        }
      ]
    },
    {
      "id": "P02-CONN-01",
      "status": "observed",
      "catalog": "dofactory",
      "pattern": "Decorator",
      "source": "https://www.dofactory.com/net/decorator-design-pattern",
      "referenceDepth": "full-public-reference",
      "how": "Concrete ownedConnection and observeOwnedConnection wrap only sockets created by their owning dialer. They retain the net.Conn interface and delegate ordinary I/O while Close tracks actual closure and retains failed-close ownership for bounded retry. The raw variant additionally preserves failures observed by the SDK or cancellation hook through serial accounting; later successful physical closure does not silently erase that failure.",
      "why": "NATS and TLS may close a socket before outer cleanup. An outer owner must report those actual failures and retain its exact socket without adopting another connection.",
      "tradeoffs": "Using the bare net.Conn and only its final Close result is simpler but loses earlier SDK/cancellation failure and retry ownership. Wrapping adds synchronization, failure accounting and cancellation-hook join obligations. Test injection is restricted to already minted real sockets. Normal local Close syscalls must complete; this is not a generic closer, sandbox or guarantee of preempting a blocked syscall.",
      "locations": [
        {
          "path": "platform/localtls/client.go",
          "symbol": "ownedConnection.Close"
        },
        {
          "path": "platform/deployment/observe.go",
          "symbol": "observeOwnedConnection.Close"
        },
        {
          "path": "platform/deployment/observe.go",
          "symbol": "observeDialer.closeContext"
        }
      ],
      "verificationEvidence": [
        "platform/deployment/raw_transport_cleanup_test.go",
        "docs/planning/2026-10-09/delivery/evidence/P02/shared-tls-cleanup-independent/independent-review.json",
        "docs/planning/2026-10-09/delivery/evidence/P02/raw-team-cleanup-current/worker/review.json"
      ],
      "decisionEvidence": [
        "docs/planning/2026-10-09/delivery/decisions/P02-local-broker-authentication.md",
        "docs/planning/2026-10-09/delivery/evidence/P02/pattern-current-review/root-review.json"
      ],
      "qualificationLimit": "Observed source and component controls only; no phase/native/Compose qualification."
    }
  ]
}
```
