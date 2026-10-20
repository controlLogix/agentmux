"""work: federated role items across people (FEDERATION.md 9.3).

`work add --federate` publishes to am.work.<me>.<rid>.<role>.v3 on the AM_WORK work-queue
stream. Every hub that can serve (rid, role) pulls from ONE shared durable consumer per
publisher, `work3_<from>_<rid>_<role>` - Competing Consumers - and only when it has an
idle agent for it, so exactly one hub gets each item and exactly one local agent claims
it after the origin grants a durable reservation. Redelivery can reach another hub,
but that hub cannot execute without its own matching grant. A hub pulls only from
publishers it trusts at auto or flag (and itself): a hub that
would quarantine the item must not take it from a hub that would do it (assumption A19).
The finished item goes back to its origin as a `result` envelope.
"""
from __future__ import annotations

from hub.profile_context import ProfileContext

import hashlib
import json

from hub import names
from hub.fed import envelope, guard
from hub.store import HubError, now, ulid

PENDING = "fed:pending"


def offer_digest(env):
    data = {k: v for k, v in env["data"].items() if k != "offer_digest"}
    record = {k: env.get(k) for k in ("v", "id", "from", "node", "rid", "to", "type")}
    return digest({**record, "data": data})


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def result_digest(data):
    return digest({"state": data.get("state"), "result": data.get("result")})


def reference(flags):
    return {"origin_id": flags["origin_id"], "origin_node": flags["origin_node"], "offer_id": flags["env"],
            "offer_digest": flags["offer_digest"], "execution_id": flags["execution_id"]}


def valid_reference(flags, env):
    d = env["data"]
    return bool(flags.get("outgoing") and flags.get("protocol") == 3 and
                flags.get("env") == d.get("offer_id") and flags.get("rid") == env.get("rid") and
                flags.get("origin_node") == d.get("origin_node") and
                flags.get("offer_digest") == d.get("offer_digest"))


def matches_offer(flags, env):
    return bool(flags.get("outgoing") and flags.get("env") == env["id"] and flags.get("rid") == env["rid"] and
                flags.get("origin_node") == env["node"] and flags.get("offer_digest") == env["data"]["offer_digest"])


def valid_work_data(env):
    d = env["data"]
    keys = ("origin_id", "offer_digest") if env["type"] == "work" else (
        "origin_id", "origin_node", "offer_id", "offer_digest", "execution_id")
    if any(not isinstance(d.get(k), str) or not 1 <= len(d[k]) <= 128 for k in keys):
        return False
    if len(d["offer_digest"]) != 64 or any(c not in "0123456789abcdef" for c in d["offer_digest"]):
        return False
    if env["type"] != "work" and not envelope.TOKEN.fullmatch(d["origin_node"]):
        return False
    if env["type"] == "work":
        return isinstance(d.get("title"), str) and bool(d["title"].strip())
    if env["type"] == "work_grant":
        return (type(d.get("selected")) is bool and
                all(isinstance(d.get(k), str) and envelope.TOKEN.fullmatch(d[k])
                    for k in ("executor_peer", "executor_node")))
    if env["type"] == "result":
        return (d.get("state") in ("done", "failed") and
                (d.get("result") is None or isinstance(d["result"], str)) and
                isinstance(d.get("by_sender", {}), dict))
    return True


def _current_admission(ctx, env, decision):
    plane = envelope.PLANE_OF[env["type"]]
    tail = [env["rid"], env["data"]["role"]] if plane == "work" else [env["to"]]
    current = guard.inbound(ctx.policy, envelope.subject(plane, env["from"], *tail), env)
    return (current.action != "drop" and
            (current.action != "quarantine" or decision.approved) and
            (decision.local_repo is None or current.local_repo == decision.local_repo))


class _WorkTransactions:
    async def add(self, ctx, caller, to, title, body=None, task_key=None, requirements=None, priority=100):
        ad = names.parse_address(to)
        if ad.kind != "role" or ad.scope in ("*",) or ad.scope.startswith(("group:", "team:")):
            raise HubError("a federated item targets role:<repo>/<role>")
        repo, role = ad.scope, ad.name
        rid = ctx.policy.rid_of(repo)
        if rid is None:
            raise HubError(f"repo {repo!r} is not shared (agentmux hub fed share {repo})")
        created_by = ctx.hub.sender_of(caller)
        sender = ctx.sender_of(caller)

        return await ctx.db(self.stage_offer, ctx, created_by, sender, repo, role, rid,
                            to, title, body, task_key, requirements, priority)

    def stage_offer(self, ctx, created_by, sender, repo, role, rid, to, title,
                    body=None, task_key=None, requirements=None, priority=100):
        """Stage the original offer in the caller's existing Store transaction."""
        with ctx.store.tx():
            if ctx.policy.rid_of(repo) != rid:
                raise HubError("repo sharing changed before offering work")
            w = ctx.store.work_create(created_by, repo, to, title, body, task_key, requirements, priority)
            data = {"origin_id": w["id"], "title": title, "body": body, "task_key": task_key,
                    "requirements": requirements, "priority": priority, "role": role,
                    "sender": {k: v for k, v in sender.items() if k != "repo"}}
            env = envelope.make("work", ctx.me, ctx.node, rid, "*", data)
            # Bind the actual redacted offer, not different local-only content.
            env, _ = guard.outbound(ctx.policy, env, repo, "*")
            env["data"]["offer_digest"] = offer_digest(env)
            flags = {"env": env["id"], "rid": rid, "origin_node": ctx.node, "outgoing": True,
                     "offer_digest": env["data"]["offer_digest"], "role": role, "protocol": 3}
            ctx.store.db.execute("UPDATE work_items SET state='claimed', claimed_by=?, updated=?, fed_flags=? "
                                 "WHERE id=?", (PENDING, now(), json.dumps(flags), w["id"]))
            ctx.stage(env, envelope.subject("work", ctx.me, rid, role), repo, "*")
            return {**ctx.store.work(w["id"]), "federated": env["id"]}

    async def on_local_event(self, ctx, kind, w):
        if kind == "work_released" and w and w.get("origin_peer"):
            await ctx.db(self._stage_result, ctx, w["id"])

    def _stage_result(self, ctx, work_id):
        """Completion commits return intent in Store; this retryable step stages it."""
        with ctx.store.tx():
            w = ctx.store.work(work_id)
            if not w or w["state"] not in ("done", "failed") or not w.get("origin_peer"):
                return
            flags = json.loads(w.get("fed_flags") or "{}")
            if not flags.get("result_pending"):
                return
            if not flags.get("grant_id"):
                raise HubError("legacy federated completion needs operator reconciliation: no executor grant")
            try:
                by_sender = {k: v for k, v in ctx.sender_of(w.get("claimed_by") or "operator").items() if k != "repo"}
            except HubError:
                by_sender = {"operator": True}
            data = reference(flags)
            data.update(state=w["state"], result=w.get("result"), by=w.get("claimed_by"),
                        by_sender=by_sender, grant_id=flags["grant_id"])
            env = envelope.make("result", ctx.me, ctx.node, flags["rid"], w["origin_peer"], data)
            env["id"] = flags["result_id"]
            env, _ = guard.outbound(ctx.policy, env, None, w["origin_peer"])
            env["data"]["result_digest"] = result_digest(env["data"])
            ctx.stage(env, envelope.subject("msg", ctx.me, w["origin_peer"]), None, w["origin_peer"])
            flags["result_pending"] = False
            ctx.store.db.execute("UPDATE work_items SET fed_flags=? WHERE id=?", (json.dumps(flags), work_id))

    async def recover_results(self, ctx):
        rows = await ctx.db(ctx.store.q, "SELECT id FROM work_items WHERE origin_peer IS NOT NULL "
                            "AND state IN ('done','failed') AND json_extract(fed_flags,'$.result_pending')=1 "
                            "AND json_extract(fed_flags,'$.grant_id') IS NOT NULL")
        for row in rows:
            try:
                await ctx.db(self._stage_result, ctx, row["id"])
            except Exception as exc:
                # A refused result stays pending and cannot starve other completions.
                ctx.log("fed: result remains pending", row["id"], type(exc).__name__, str(exc))

    # -- inbound ---------------------------------------------------------------------------
    async def on_connect(self, ctx):
        ctx.session.check_open()

    async def on_tick(self, ctx):
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
        import nats.errors
        session = ctx.session
        session.check_open()
        js = ctx.js
        subscriptions = session.work_subscriptions
        await self.recover_results(ctx)
        shared = ctx.policy.shared()
        if not shared:
            return
        want = {}
        for a in await ctx.db(ctx.store.agents, True):
            if a["repo"] not in shared or a["state"] in ("dead", "starting", "blocked"):
                continue
            snap = json.loads(a["role_snapshot"])
            active = await ctx.db(ctx.store.q1, "SELECT count(*) n FROM work_items WHERE claimed_by=? AND "
                                  "state='claimed'", (a["session"],))
            free = max(0, int(snap.get("max_active", 1)) - active["n"])
            key = (shared[a["repo"]], a["role"], a["repo"])
            want[key] = want.get(key, 0) + free
        publishers = {ctx.me} | {p for p in ctx.peer_ids if ctx.policy.trust(p) in ("auto", "flag")}
        for (rid, role, repo), free in want.items():
            waiting = await ctx.db(ctx.store.q1, "SELECT count(*) n FROM work_items WHERE (state='ready' OR "
                                   "(state='blocked' AND blocked_reason='awaiting origin grant')) AND target=?",
                                   (f"role:{repo}/{role}",))
            room = free - waiting["n"]
            for frm in sorted(publishers):
                if frm != ctx.me and not ctx.policy.may_receive(rid, frm):
                    continue
                if room <= 0:
                    break
                session.check_open()
                if ctx.session is not session:
                    raise HubError("federation work context is stale")
                if frm != ctx.me and (ctx.policy.trust(frm) not in ("auto", "flag") or
                                      not ctx.policy.may_receive(rid, frm)):
                    continue
                if ctx.policy.rid_of(repo) != rid:
                    continue
                key = (frm, rid, role)
                if key not in subscriptions:
                    subscriptions[key] = await session.acquire(js.pull_subscribe(
                        envelope.subject("work", frm, rid, role), durable=f"work3_{frm}_{rid}_{role}", stream="AM_WORK",
                        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60,
                                              deliver_policy=DeliverPolicy.ALL, max_deliver=20)), session.own_subscription)
                session.check_open()
                if ctx.session is not session:
                    raise HubError("federation work context is stale")
                if (ctx.policy.rid_of(repo) != rid or
                        (frm != ctx.me and (ctx.policy.trust(frm) not in ("auto", "flag") or
                                            not ctx.policy.may_receive(rid, frm)))):
                    continue
                try:
                    msgs = await subscriptions[key].fetch(min(room, 5), timeout=0.2)
                except (nats.errors.TimeoutError, TimeoutError):
                    continue
                for m in msgs:
                    session.check_open()
                    if ctx.session is not session:
                        raise HubError("federation work context is stale")
                    if await ctx.receive(m.subject, m.data, m) in ("delivered", "local"):
                        room -= 1

    async def on_envelope(self, ctx, env, dec):
        if env.get("v") != 3:
            raise HubError("federated work requires protocol v3; reconcile legacy in-flight work before upgrade")
        if not valid_work_data(env):
            return "invalid_work"
        if env["type"] == "result":
            return await self._on_result(ctx, env, dec)
        if env["type"] == "work_claim":
            return await ctx.db(self._claim, ctx, env, dec)
        if env["type"] == "work_grant":
            return await ctx.db(self._grant, ctx, env, dec)
        d, frm = env["data"], env["from"]
        local = dec.local_repo or ctx.policy.local_of(env.get("rid") or "")
        if not local:
            return "not_shared"
        if not d.get("origin_id") or d.get("offer_digest") != offer_digest(env):
            raise HubError("offer has no valid immutable task identity")

        return await ctx.db(self._ingest, ctx, env, dec, local)

    def _ingest(self, ctx, env, dec, local):
        d, frm = env['data'], env['from']
        with ctx.store.tx():
            if not _current_admission(ctx, env, dec):
                return "dropped"
            # Reopen only the exact originating node's placeholder.
            if frm == ctx.me and env["node"] == ctx.node:
                w = ctx.store.work(d["origin_id"])
                flags = json.loads((w or {}).get("fed_flags") or "{}")
                if not matches_offer(flags, env):
                    return "stale"
                if flags.get("executor") or w["claimed_by"] != PENDING:
                    return "duplicate"
                flags["executor"] = {"peer": ctx.me, "node": ctx.node, "execution_id": w["id"], "local": True}
                ctx.store.db.execute("UPDATE work_items SET state='ready', claimed_by=NULL, updated=?, fed_flags=? "
                                     "WHERE id=?", (now(), json.dumps(flags), w["id"]))
                return "local"
            dup = ctx.store.q1("SELECT id FROM work_items WHERE origin_peer=? AND "
                              "json_extract(fed_flags,'$.origin_node')=? AND json_extract(fed_flags,'$.env')=?",
                              (frm, env["node"], env["id"]))
            if dup:
                return "duplicate"
            body = guard.wrap(d.get("body") or "", frm, dec.trust, dec.untrusted) if d.get("body") else None
            sender = ctx.address_of(frm, d.get("sender") or {})
            w = ctx.store.work_create(sender, local, f"role:{local}/{d['role']}", d["title"], body,
                                      d.get("task_key"), d.get("requirements"), int(d.get("priority") or 100))
            flags = {"origin_id": d["origin_id"], "origin_node": env["node"], "env": env["id"], "rid": env["rid"],
                     "offer_digest": d["offer_digest"], "execution_id": ulid(), "protocol": 3,
                     "untrusted": dec.untrusted, "privileged_ok": bool(dec.privileged_ok), "approved": dec.approved}
            ctx.store.db.execute("UPDATE work_items SET origin_peer=?, fed_flags=?, state='blocked', "
                                 "blocked_reason='awaiting origin grant' WHERE id=?", (frm, json.dumps(flags), w["id"]))
            claim = envelope.make("work_claim", ctx.me, ctx.node, env["rid"], frm, reference(flags))
            ctx.stage(claim, envelope.subject("msg", ctx.me, frm), local, frm)
            return "delivered"

    def _claim(self, ctx, env, dec):
        d = env["data"]
        if d.get("origin_node") != ctx.node:
            return "other_node"
        with ctx.store.tx():
            if not _current_admission(ctx, env, dec):
                return "dropped"
            w = ctx.store.work(d.get("origin_id")) if d.get("origin_id") else None
            flags = json.loads((w or {}).get("fed_flags") or "{}")
            if not valid_reference(flags, env) or not w:
                return "unbound_claim"
            if not d.get("execution_id"):
                return "unbound_claim"
            selected = flags.get("executor")
            contender = {"peer": env["from"], "node": env["node"], "execution_id": d["execution_id"]}
            if selected is None and w["claimed_by"] == PENDING:
                selected = {**contender, "grant_id": ulid()}
                flags["executor"] = selected
                ctx.store.db.execute("UPDATE work_items SET fed_flags=? WHERE id=?", (json.dumps(flags), w["id"]))
            selected = selected or {}
            accepted = bool(selected.get("grant_id") and w["claimed_by"] == PENDING and
                            all(selected.get(k) == v for k, v in contender.items()))
            grant = envelope.make("work_grant", ctx.me, ctx.node, env["rid"], env["from"],
                                  {**d, "executor_peer": env["from"], "executor_node": env["node"],
                                   "selected": accepted, "grant_id": selected.get("grant_id") if accepted else None})
            # One immutable grant per selected executor; retries cannot create a new permission.
            if accepted:
                grant["id"] = selected["grant_id"]
            ctx.stage(grant, envelope.subject("msg", ctx.me, env["from"]), w["repo"], env["from"])
            return "reserved" if accepted else "already_reserved"

    def _grant(self, ctx, env, dec):
        d = env["data"]
        if d.get("executor_peer") != ctx.me or d.get("executor_node") != ctx.node:
            return "other_node"
        with ctx.store.tx():
            if not _current_admission(ctx, env, dec):
                return "dropped"
            w = ctx.store.q1("SELECT * FROM work_items WHERE origin_peer=? AND json_extract(fed_flags,'$.env')=? "
                             "AND json_extract(fed_flags,'$.execution_id')=?",
                             (env["from"], d.get("offer_id"), d.get("execution_id")))
            if not w:
                return "unbound_grant"
            flags = json.loads(w["fed_flags"])
            if env["node"] != flags["origin_node"] or env["rid"] != flags["rid"] or reference(flags) != {k: d.get(k) for k in reference(flags)}:
                return "unbound_grant"
            if w["state"] != "blocked" or w["blocked_reason"] != "awaiting origin grant":
                return "duplicate"
            if d.get("selected") is not True:
                ctx.store.db.execute("UPDATE work_items SET state='cancelled', result='reserved by another executor', "
                                     "updated=? WHERE id=?", (now(), w["id"]))
                return "not_selected"
            if not d.get("grant_id") or env["id"] != d["grant_id"]:
                return "unbound_grant"
            flags["grant_id"] = d["grant_id"]
            ctx.store.db.execute("UPDATE work_items SET state='ready', blocked_reason=NULL, fed_flags=?, updated=? "
                                 "WHERE id=?", (json.dumps(flags), now(), w["id"]))
            return "delivered"

    async def _on_result(self, ctx, env, dec):
        d = env["data"]
        if d.get("origin_node") != ctx.node:
            return "other_node"
        outcome, w2 = await ctx.db(self._result, ctx, env, dec)
        if w2:
            await ctx.hub._notify_work_owner(w2, w2["claimed_by"])
            await ctx.local_event("fed_result", {**w2, "from_peer": env["from"]})
        return outcome

    def _result(self, ctx, env, dec):
        d = env['data']
        if d.get('origin_node') != ctx.node:
            return 'other_node', None
        with ctx.store.tx():
            if not _current_admission(ctx, env, dec):
                return "dropped", None
            w = ctx.store.work(d.get("origin_id")) if d.get("origin_id") else None
            flags = json.loads((w or {}).get("fed_flags") or "{}")
            selected = flags.get("executor") or {}
            if not w or not valid_reference(flags, env) or any(selected.get(k) != v for k, v in
                    {"peer": env["from"], "node": env["node"], "execution_id": d.get("execution_id"),
                     "grant_id": d.get("grant_id")}.items()) or not selected.get("grant_id"):
                return "unbound_result", None
            if w["claimed_by"] != PENDING:
                return "stale", None
            if d.get("state") not in ("done", "failed") or d.get("result_digest") != result_digest(d):
                return "invalid_result", None
            by = ctx.address_of(env["from"], d.get("by_sender") or {})
            flags["accepted_result"] = {"envelope_id": env["id"], "digest": d["result_digest"], "at": now()}
            ctx.store.db.execute("UPDATE work_items SET state=?, result=?, claimed_by=?, updated=?, fed_flags=? WHERE id=?",
                                 (d["state"], d.get("result"), by, now(), json.dumps(flags), w["id"]))
            return "delivered", ctx.store.q1("SELECT * FROM work_items WHERE id=?", (w["id"],))

    async def on_revoke(self, ctx, peer):
        n = await ctx.db(self._revoke, ctx, peer)
        ctx.log(f"fed: cancelled {n} unclaimed item(s) from {peer}")

    def _revoke(self, ctx, peer, repository=None):
        with ctx.store.tx():
            return ctx.store.db.execute("UPDATE work_items SET state='cancelled', result='withdrawn by ' || ?, "
                                        "updated=? WHERE origin_peer=? AND (? IS NULL OR repo=?) AND (state='ready' OR (state='blocked' AND blocked_reason='awaiting origin grant'))",
                                        (peer, now(), peer, repository, repository)).rowcount

    async def v_list(self, ctx, a, caller):
        return await ctx.db(self._rows, ctx)

    def _rows(self, ctx):
        return ctx.store.q("SELECT id, title, state, claimed_by, origin_peer, task_key, target, result, updated "
                           "FROM work_items WHERE origin_peer IS NOT NULL OR claimed_by=? OR claimed_by LIKE 'peer:%' "
                           "ORDER BY updated DESC LIMIT 50", (PENDING,))

    def panel(self, ctx):
        rows = self._rows(ctx)
        return {"title": "Federated work", "columns": ["id", "title", "state", "from / by", "task_key", "result"],
                "rows": [[r["id"], r["title"], r["state"],
                          (f"from {r['origin_peer']}" if r["origin_peer"] else (r["claimed_by"] or "")),
                          r["task_key"] or "", (r["result"] or "")[:80]] for r in rows]}




from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class FederatedWorkOwner:
    """Keep reservations, grants, result acceptance and outbox in their owner."""
    _owner: Any = field(repr=False)
    _operations: Any = field(default_factory=_WorkTransactions, repr=False)

    async def add(self, caller, to, title, body=None, task_key=None, requirements=None, priority=100):
        return await self._operations.add(self._owner, caller, to, title, body, task_key, requirements, priority)

    async def receive(self, env, decision):
        return await self._operations.on_envelope(self._owner, env, decision)

    async def local_event(self, kind, work):
        return await self._operations.on_local_event(self._owner, kind, work)

    async def recover_results(self):
        return await self._operations.recover_results(self._owner)

    async def revoke(self, peer):
        return await self._operations.on_revoke(self._owner, peer)

    async def rows(self, caller='operator'):
        return await self._owner.db(self._operations._rows, self._owner)

    def panel(self):
        return self._operations.panel(self._owner)


@dataclass(frozen=True, slots=True)
class WorkQueueConsumer:
    """Consume only the eligible work queues; no broker handle leaves the owner."""
    _owner: Any = field(repr=False)
    _operations: Any = field(default_factory=_WorkTransactions, repr=False)
    _session: Any = field(init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "_session", getattr(self._owner, "session", None))

    def check_open(self):
        if self._session is None or self._owner.session is not self._session:
            raise HubError("federation work context is stale")
        self._session.check_open()

    async def poll(self):
        self.check_open()
        return await self._operations.on_tick(self._owner)


@dataclass(frozen=True, slots=True)
class WorkContext:
    work: FederatedWorkOwner
    consumer: WorkQueueConsumer
    profile_context: ProfileContext | None = None


def build_work_context(federation):
    if getattr(federation, '_qualified_work', False):
        if getattr(federation, '_work_commands', None) is None:
            raise HubError('qualified work owner is unavailable')
        return WorkContext(QualifiedWorkOwner(federation),
            WorkQueueConsumer(federation, _QualifiedWorkQueue()))
    return WorkContext(FederatedWorkOwner(federation), WorkQueueConsumer(federation))


@dataclass(frozen=True, slots=True)
class QualifiedWorkOwner:
    """Use signed retained commands for every qualified work call."""
    _owner: Any = field(repr=False)

    async def add(self, *args):
        return await self._owner._work_commands.add(*args)

    async def receive(self, item, decision):
        return await self._owner._work_commands.receive(item, decision)

    async def local_event(self, kind, row):
        return await self._owner._work_commands.local_event(kind, row)

    async def recover_results(self):
        return await self._owner._work_commands.recover_results()

    async def revoke(self, peer):
        return await self._owner._work_commands.revoke(peer)

    async def rows(self, caller='operator'):
        return await self._owner._work_commands.read(caller)

    def panel(self):
        raise HubError('qualified work panel requires its authenticated owner route')


class _QualifiedWorkQueue:
    @staticmethod
    async def _receive(ctx, message):
        import asyncio
        original = asyncio.create_task(ctx.receive(message.subject, message.data, message))
        cancelled = None
        while not original.done():
            try:
                await asyncio.shield(original)
            except asyncio.CancelledError as exc:
                cancelled = exc
        try:
            result = original.result()
        except BaseException:
            if cancelled is not None:
                raise cancelled
            raise
        if cancelled is not None:
            raise cancelled
        return result

    async def on_tick(self, ctx):
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
        import nats.errors
        client, session = ctx._work_commands, ctx.session
        client.check(ctx)
        session.check_open()
        await client.recover_results()
        shared = ctx.policy.shared()
        if not shared:
            return
        rows = await client.service_read({'kind': 'list', 'state': None})
        agents = await ctx.db(ctx.store.agents, True)
        client.confirm_disclosure()
        want = {}
        selected = client.service_repositories()
        for agent in agents:
            if (agent['repo'] not in shared or agent['repo'] not in selected
                    or agent['state'] in ('dead', 'starting', 'blocked')):
                continue
            readiness = await client.service_readiness(agent['session'], repo=agent['repo'])
            free = readiness['capacity']['available']
            key = (shared[agent['repo']], agent['role'], agent['repo'])
            want[key] = want.get(key, 0) + free
        publishers = {ctx.me} | {peer for peer in ctx.peer_ids if ctx.policy.trust(peer) in ('auto', 'flag')}
        for (rid, role, repo), free in want.items():
            waiting = sum((row['state'] == 'ready' or row['state'] == 'blocked'
                and row['blocked_reason'] == 'awaiting origin grant') and row['target'] == f'role:{repo}/{role}'
                for row in rows)
            room = free - waiting
            for peer in sorted(publishers):
                client.confirm_disclosure()
                session.check_open()
                if ctx.session is not session:
                    raise HubError('federation work context is stale')
                if room <= 0:
                    break
                if ctx.policy.rid_of(repo) != rid or peer != ctx.me and (
                        ctx.policy.trust(peer) not in ('auto', 'flag') or not ctx.policy.may_receive(rid, peer)):
                    continue
                key = (peer, rid, role)
                if key not in session.work_subscriptions:
                    session.work_subscriptions[key] = await session.acquire(ctx.js.pull_subscribe(
                        envelope.subject('work', peer, rid, role), durable=f'work3_{peer}_{rid}_{role}', stream='AM_WORK',
                        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60,
                            deliver_policy=DeliverPolicy.ALL, max_deliver=20)), session.own_subscription)
                client.confirm_disclosure()
                if ctx.policy.rid_of(repo) != rid or peer != ctx.me and (
                        ctx.policy.trust(peer) not in ('auto', 'flag') or not ctx.policy.may_receive(rid, peer)):
                    continue
                try:
                    messages = await session.work_subscriptions[key].fetch(min(room, 5), timeout=0.2)
                except (nats.errors.TimeoutError, TimeoutError):
                    continue
                client.confirm_disclosure()
                # A joined child task gives the receive its own private validity
                # group while this capacity read keeps its original deadline.
                for message in messages:
                    session.check_open()
                    if ctx.session is not session:
                        raise HubError('federation work context is stale')
                    if await self._receive(ctx, message) in ('delivered', 'local'):
                        room -= 1
        client.finish_disclosure()
