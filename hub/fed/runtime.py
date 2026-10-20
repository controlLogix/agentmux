"""Federation runtime: one connection, the core consumers, the outbox, presence, the
kill switch, and the plugins (docs/FEDERATION.md).

Runs inside the hub's event loop next to the TM-218 bridge. Everything that touches
hub.db goes through hub.db() (the single db thread), so the runtime adds no locking.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
import time
from contextlib import nullcontext

from hub import names
from hub.fed import config, conn, envelope, guard, ledger
from hub.fed.plugin import Param, Verb
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.policy import Policy, normalize_remote
from hub.fed.session import FederationSession, SessionCleanupFailure
from hub.store import HubError, now

BUILTIN = ("messages", "work", "board", "knowledge", "code")


def _uses_work_owner(federation, item):
    return (getattr(federation, '_qualified_work', False) and isinstance(item, dict)
        and item.get('type') in ('work', 'work_claim', 'work_grant', 'result'))


class Federation:
    def __init__(self, hub, hubdir, log, *, profile_context=None, qualified_board=False, board_commands=None,
                 qualified_messages=False, message_commands=None, qualified_knowledge=False, knowledge_commands=None,
                 qualified_code=False, code_commands=None, qualified_work=False, work_commands=None):
        from hub.profile_context import ProfileContext
        if profile_context is not None and type(profile_context) is not ProfileContext:
            raise HubError("invalid profile context")
        if type(qualified_board) is not bool or (not qualified_board and board_commands is not None):
            raise HubError('invalid qualified board selection')
        if qualified_board:
            from capability_owner.legacy_board_service import LegacyBoardCommandClient
            if type(board_commands) is not LegacyBoardCommandClient or board_commands._hub is not hub:
                raise HubError('qualified board owner route is required')
        self._qualified_board, self._board_commands = qualified_board, board_commands
        if type(qualified_messages) is not bool or (not qualified_messages and message_commands is not None):
            raise HubError('invalid qualified message selection')
        if qualified_messages:
            from capability_owner.legacy_messages_client import LegacyMessageCommandClient
            if type(message_commands) is not LegacyMessageCommandClient or message_commands._hub is not hub:
                raise HubError('qualified message owner route is required')
        self._qualified_messages, self._message_commands = qualified_messages, message_commands
        if type(qualified_knowledge) is not bool or (not qualified_knowledge and knowledge_commands is not None):
            raise HubError('invalid qualified knowledge selection')
        if qualified_knowledge:
            from capability_owner.legacy_knowledge_client import LegacyKnowledgeCommandClient
            if type(knowledge_commands) is not LegacyKnowledgeCommandClient or knowledge_commands._hub is not hub:
                raise HubError('qualified knowledge owner route is required')
        self._qualified_knowledge, self._knowledge_commands = qualified_knowledge, knowledge_commands
        if type(qualified_code) is not bool or (not qualified_code and code_commands is not None):
            raise HubError('invalid qualified code selection')
        if qualified_code:
            from capability_owner.legacy_code_client import LegacyCodeCommandClient
            if type(code_commands) is not LegacyCodeCommandClient or code_commands._hub is not hub:
                raise HubError('qualified code owner route is required')
        self._qualified_code, self._code_commands = qualified_code, code_commands
        if type(qualified_work) is not bool or (not qualified_work and work_commands is not None):
            raise HubError('invalid qualified work selection')
        if qualified_work:
            from capability_owner.legacy_work_client import LegacyWorkCommandClient
            if type(work_commands) is not LegacyWorkCommandClient or work_commands._hub is not hub:
                raise HubError('qualified work owner route is required')
        self._qualified_work, self._work_commands = qualified_work, None
        self._profile_context = profile_context
        self.hub, self.hubdir, self.log = hub, hubdir, log
        self.node = hub.cfg.get("node", "local")
        self.cfg = config.load(hubdir)
        self.nc = self.js = None
        self.connection_cleanup = None
        self.session = None
        self._work_intents = None
        if qualified_work:
            from capability_owner.federated_work_client import FederatedWorkCommandClient, WorkBridgeIntents
            self._work_commands = FederatedWorkCommandClient(self, work_commands)
            self._work_intents = WorkBridgeIntents(self, self._work_commands)
        self._message_intents = None
        if qualified_messages:
            from hub.fed.message_bridge import MessageBridgeIntents
            self._message_intents = MessageBridgeIntents(self, message_commands)
        self._knowledge_intents = None
        if qualified_knowledge:
            from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
            knowledge_commands.bind(self)
            self._knowledge_intents = KnowledgeBridgeIntents(self, knowledge_commands)
        self._code_intents = None
        if qualified_code:
            from hub.fed.code_bridge import CodeBridgeIntents
            code_commands.bind(self)
            self._code_intents = CodeBridgeIntents(self, code_commands)
        self.connected = False
        self.last_error = ""
        self.wake: asyncio.Event | None = None
        self.loop = None
        self.stats = {"published": 0, "received": 0, "delivered": 0, "dropped": 0, "quarantined": 0,
                      "duplicates": 0, "errors": 0}
        self.plugins = {}
        self.plugin_adapters = {}
        self.routes = {}
        self._load_plugins()
        self.verbs = self._core_verbs()
        self.plugin_verbs = {}
        for p in self.plugin_adapters.values():
            for vn, v in p.verbs().items():
                self.verbs[f"fed_{p.name}_{vn}"] = v
                self.plugin_verbs[f"fed_{p.name}_{vn}"] = (p, vn)
        hub.dbx.submit(self._init_db).result()
        self.policy = Policy(self.cfg, {})
        hub.dbx.submit(self._refresh_policy_sync).result()
        self._last_presence = 0.0
        self.peer_ids: set[str] = set(p for p in self.cfg.get("peers", {}) if p != "*")
        self.presence: dict[str, list] = {}         # peer -> its nodes' presence docs (last seen)
        if qualified_messages:
            message_commands.bind(self)

    # -- setup ---------------------------------------------------------------------------
    @property
    def profile_context(self):
        return getattr(self, "_profile_context", None)

    @property
    def fcfg(self):
        return self.cfg["federation"]

    @property
    def me(self):
        return self.fcfg.get("peer", "")

    @property
    def enabled(self):
        return bool(self.fcfg.get("enabled") and self.me and self.fcfg.get("url"))

    def _load_plugins(self):
        for name in self.fcfg.get("plugins", list(BUILTIN)):
            mod = importlib.import_module(f"hub.fed.plugins.{name}" if name in BUILTIN else name)
            p = mod.PLUGIN
            names.check_part(p.name, "plugin")
            adapter = TrustedPluginAdapter(p, builtin_context_factory(name) if name in BUILTIN else None,
                                           profile_context=self.profile_context)
            self.plugins[p.name] = p
            self.plugin_adapters[p.name] = adapter
            for t in adapter.handles:
                self.routes[t] = adapter

    def _init_db(self):
        s = self.hub.store
        fenced = s.migration_fence_status()
        authority_closed = s.migration_authority_closed()
        for p in self.plugin_adapters.values():
            for sql in p.tables:
                head = sql.split("(")[0]
                if f"p_{p.name}_" not in head:
                    raise HubError(f"plugin {p.name}: table must be named p_{p.name}_* ({head.strip()})")
                selected_work = self._qualified_work and hasattr(s, '_selected_custody')
                if authority_closed or fenced is not None and fenced['state'] == 'fenced' or selected_work:
                    declared = re.match(r'\s*CREATE\s+(?:VIRTUAL\s+)?(TABLE|TRIGGER|INDEX)\s+'
                        r'(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\b', sql, re.I)
                    if declared is None:
                        raise HubError('selected database has an invalid plugin schema declaration')
                    kind, name = declared.group(1).lower(), declared.group(2)
                    if s.q1('SELECT 1 FROM sqlite_schema WHERE type=? AND name=?', (kind,name)) is None:
                        if selected_work:
                            raise HubError('selected Work database is missing a required plugin table')
                        raise HubError('fenced legacy database is missing a required plugin table')
                else:
                    s.db.execute(sql)

    def _refresh_policy_sync(self):
        rows = self.hub.store.q("SELECT repo, alias FROM repo_aliases WHERE alias LIKE '%/%' ORDER BY rowid")
        remotes = {}
        for r in rows:
            remotes.setdefault(r["repo"], normalize_remote(r["alias"]))
        self.policy = Policy(self.cfg, remotes)
        return self.policy

    async def refresh_policy(self):
        return await self.db(self._refresh_policy_sync)

    def save_cfg(self):
        config.save(self.hubdir, self.cfg)

    # -- plumbing for plugins (the Facade they get as ctx) -----------------------------------
    @property
    def store(self):
        return self.hub.store

    async def db(self, fn, *a, **kw):
        # Cancelling an await cannot roll back an executor transaction. Keep its
        # exact completion before releasing the operation that submitted it.
        task = asyncio.create_task(self.hub.db(fn, *a, **kw))
        try:
            await asyncio.wait({task})
            return task.result()
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.wait({task})
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not task.cancelled():
                task.exception()
            raise

    async def send_message(self, caller, to, kind, body, ref=None):
        adapter = self.plugin_adapters["messages"]
        return await adapter.original.send(adapter.context(self), caller, to, kind, body, ref)

    async def add_work(self, caller, to, title, body=None, task_key=None, requirements=None, priority=100):
        adapter = self.plugin_adapters["work"]
        return await adapter.original.add(adapter.context(self), caller, to, title, body, task_key,
                                          requirements, priority)

    def kick(self):
        if self.loop and self.wake:
            self.loop.call_soon_threadsafe(self.wake.set)

    def stage(self, env, subject, local_repo=None, to_peer=None):
        """DB thread, INSIDE the caller's transaction: guard, then outbox + audit rows that
        commit (or roll back) with the caller's own state change."""
        envelope.validate_route(subject, env)
        if local_repo is not None and self.policy.rid_of(local_repo) != env.get("rid"):
            raise HubError("repo sharing changed before federation publication")
        plane = subject.split(".")[1]
        try:
            clean, kinds = guard.outbound(self.policy, env, local_repo, to_peer)
        except guard.Refused as e:
            e.audit = ("out", plane, to_peer, env.get("rid"), subject, env.get("id"), env)
            raise
        ledger.outbox_add(self.store, clean["id"], subject, clean)
        ledger.audit(self.store, "out", plane, to_peer, clean.get("rid"), subject, clean["id"], clean,
                     "redacted" if kinds else "staged", {"kinds": sorted(set(kinds))} if kinds else None)
        self.kick()
        return clean, kinds

    async def publish(self, env, subject, local_repo=None, to_peer=None):
        def run():
            with self.store.tx():
                return self.stage(env, subject, local_repo, to_peer)
        return await self.db(run)

    async def kv(self, bucket):
        if not self.connected:
            raise HubError("federation is not connected (agentmux hub fed status)")
        return await self.js.key_value(bucket)

    async def post_local(self, sender, target, kind, body, ref=None, idem=None, meta=None):
        try:
            return await self.hub._post_current(sender, target, kind, body, ref, None, idem, meta=meta)
        except HubError as e:
            self.log("fed: local post failed", target, e)
            return None

    def sender_of(self, caller):
        """Who is speaking, as the wire describes it: rid/role/agent for a shared repo's
        agent, or the operator."""
        if caller in ("operator", "virtual:operator"):
            return {"operator": True}
        if caller == "unregistered":
            raise HubError("unregistered pane: spawn agents with `agentmux hub spawn`")
        sess = caller[6:] if caller.startswith("agent:") else caller
        repo, role, agent = names.split_session(sess)
        return {"repo": repo, "rid": self.policy.rid_of(repo), "role": role, "agent": agent}

    def resolve_repo(self, peer, name):
        """The rid for a repo segment in a peer: address. Accepts MY local name, a rid, or
        the PEER's own name for it (from presence) - an agent copying an address from the
        other side must not have to translate it (found in the live demo, 2026-10-07)."""
        rid = self.policy.rid_of(name)
        if rid:
            return rid
        if self.policy.local_of(name):
            return name
        for doc in self.presence.get(peer, []):
            for r in doc.get("repos", []):
                if r.get("repo") == name and self.policy.local_of(r.get("rid", "")):
                    return r["rid"]
        mine = ", ".join(self.policy.shared()) or "none"
        raise HubError(f"repo {name!r} is not shared with {peer} under that name (your shared repos: {mine}; "
                       f"you may also use {peer}'s own name for it, or its rid)")

    def address_of(self, frm, sender: dict) -> str:
        """A reply-able local address for a remote sender."""
        if not sender or sender.get("operator"):
            return f"peer:{frm}"
        repo = self.policy.local_of(sender.get("rid") or "") or sender.get("rid") or "_"
        return f"peer:{frm}/{repo}/{sender.get('role')}/{sender.get('agent')}"

    async def notify_operator(self, body, idem):
        if self.fcfg.get("primary", True):
            await self.post_local("virtual:hub", "virtual:operator", "note", body, idem=idem)

    # -- the loop --------------------------------------------------------------------------
    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        for p in self.plugin_adapters.values():
            await p.start(self)
        backoff = 1
        while not self.hub.stop.is_set():
            if getattr(self, '_qualified_knowledge', False):
                try:
                    await self._knowledge_commands.recover_captures()
                except Exception as error:
                    self.log('fed: knowledge recovery remains pending', type(error).__name__)
            killed = await self.db(ledger.state_get, self.store, "killed")
            if not self.enabled or killed:
                self.last_error = "killed" if killed else "disabled"
                await self._nap(2)
                continue
            try:
                self.nc = await asyncio.wait_for(self._connect_owned(), 20)
            except Exception as e:  # noqa: BLE001 - every failure is a retry with backoff
                self.last_error = f"connect: {type(e).__name__}: {e}"
                self.log("fed: cannot connect -", self.last_error, f"(retry in {backoff}s)")
                await self._nap(backoff)
                backoff = min(backoff * 2, 30)
                continue
            backoff = 1
            self.session = FederationSession()
            self.js = self.session.jetstream(self.nc)
            self.connected, self.last_error = True, ""
            self.log("fed: connected", self.fcfg["url"], "as", self.me, "node", self.node)
            try:
                await self._bind_core()
                for p in self.plugin_adapters.values():
                    await p.on_connect(self)
                while not self.hub.stop.is_set() and not self.nc.is_closed:
                    if await self.db(ledger.state_get, self.store, "killed"):
                        break
                    if self.nc.is_connected:
                        await self._drain_outbox()
                        await self._presence()
                        for p in self.plugin_adapters.values():
                            try:
                                await p.on_tick(self)
                            except Exception as e:  # noqa: BLE001
                                self.log(f"fed: {p.name} tick error", type(e).__name__, e)
                    for t in self.session.tasks():
                        if t.done() and not t.cancelled() and t.exception():
                            raise t.exception()
                    await self._nap(0.5)
            except Exception as e:  # noqa: BLE001
                self.last_error = f"{type(e).__name__}: {e}"
                self.log("fed: session error -", self.last_error)
            finally:
                self.connected = False
                await self._close_session_owned()
            await self._nap(1)

    async def _close_session_owned(self):
        session = getattr(self, "session", None)
        if session is not None:
            try:
                await session.close()
            except SessionCleanupFailure as error:
                self.last_error = str(error)
                self.log("fed: session cleanup incomplete")
                if asyncio.current_task().cancelling():
                    raise asyncio.CancelledError() from error
                return
        transferred = self.nc is None
        try:
            if self.nc is not None:
                await conn.close(self.nc)
                transferred = True
        except conn.ConnectionCleanupFailure as error:
            self.connection_cleanup = error
            transferred = True
            self.last_error = f"cleanup: {error}"
            self.log("fed: cleanup incomplete -", self.last_error)
            if asyncio.current_task().cancelling():
                raise asyncio.CancelledError() from error
        finally:
            # A cancelled plain-client close has not transferred ownership.
            if transferred:
                self.nc = self.js = None
                self.session = None

    async def finish_cleanup(self):
        """Join retained shutdown attempts before the hub reports it is down."""
        while getattr(self, "session", None) is not None or self.nc is not None or self.connection_cleanup is not None:
            await self._close_session_owned()
            session = getattr(self, "session", None)
            if session is not None:
                if session.close_task.done():
                    raise session.failure
                continue
            if self.connection_cleanup is not None:
                owned = self.connection_cleanup
                try:
                    await owned.retry_close()
                except conn.ConnectionCleanupFailure:
                    if owned.close_task.done():
                        raise
                    continue
                self.connection_cleanup = None

    async def _connect_owned(self):
        # A session timeout retains its exact tasks, subscriptions and client.
        # Rejoin them before creating a replacement connection.
        if getattr(self, "session", None) is not None:
            await self._close_session_owned()
            if self.session is not None:
                raise self.session.failure
        # A failed initial client stays owned across retry/backoff and even run
        # cancellation. Never create another client while its close is pending.
        if self.connection_cleanup is not None:
            try:
                await self.connection_cleanup.retry_close()
            except conn.ConnectionCleanupFailure as error:
                if asyncio.current_task().cancelling():
                    raise asyncio.CancelledError() from error
                raise
            self.connection_cleanup = None
        try:
            return await conn.connect(
                self.fcfg["url"], self.fcfg.get("creds"), self.fcfg.get("ca"), f"agentmux-{self.me}-{self.node}",
                reconnect=True, error_cb=self._on_error, disconnected_cb=self._on_disc,
                reconnected_cb=self._on_reconn)
        except conn.ConnectionCleanupFailure as error:
            self.connection_cleanup = error
            if isinstance(error.operation_error, asyncio.CancelledError):
                raise error.operation_error from error
            if asyncio.current_task().cancelling():
                raise asyncio.CancelledError() from error
            raise

    async def _nap(self, s):
        try:
            await asyncio.wait_for(self.wake.wait(), s)
        except asyncio.TimeoutError:
            pass
        self.wake.clear()

    async def _on_error(self, e):
        self.last_error = f"{type(e).__name__}: {e}"
        self.log("fed: nats error -", self.last_error)

    async def _on_disc(self):
        self.log("fed: disconnected")

    async def _on_reconn(self):
        self.log("fed: reconnected")

    async def _bind_core(self):
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
        cc = dict(ack_policy=AckPolicy.EXPLICIT, ack_wait=60, deliver_policy=DeliverPolicy.ALL, max_deliver=20)
        session = self.session
        session.check_open()
        msg = session.own_subscription(await self.js.pull_subscribe(
            f"am.msg.*.{self.me}", durable=f"msg_{self.me}_{self.node}", stream="AM_MSG", config=ConsumerConfig(**cc)))
        share = session.own_subscription(await self.js.pull_subscribe(
            "am.>", durable=f"share_{self.me}_{self.node}", stream="AM_SHARE", config=ConsumerConfig(**cc)))
        session.own_subscription(await self.nc.subscribe("am.ctl.>", cb=self._on_ctl))
        return [session.start_task("messages", self.consume(msg, "AM_MSG")),
                session.start_task("shares", self.consume(share, "AM_SHARE"))]

    async def consume(self, psub, label, batch=20):
        import nats.errors
        while True:
            try:
                msgs = await psub.fetch(batch, timeout=1)
            except (nats.errors.TimeoutError, asyncio.TimeoutError):
                continue
            except (nats.errors.ConnectionClosedError, asyncio.CancelledError):
                return
            except Exception as e:  # noqa: BLE001 - e.g. mid-reconnect; the durable consumer keeps our place
                self.log(f"fed: {label} fetch error -", type(e).__name__, e)
                await asyncio.sleep(1)
                continue
            for m in msgs:
                await self.receive(m.subject, m.data, m)

    async def receive(self, subject, data, msg=None):
        """The inbound half of the guard pipeline, plus audit, quarantine and idempotency."""
        self.stats["received"] += 1
        plane = subject.split(".")[1] if subject.count(".") >= 2 else "?"
        try:
            env = json.loads(data)
        except ValueError:
            await self.db(self._audit_tx, "in", plane, None, None, subject, None, data, "dropped", {"why": "not json"})
            await _ack(msg)
            return "dropped"
        frm = subject.split(".")[2] if subject.count(".") >= 2 else None
        mid = str(env.get("id", "")) if isinstance(env, dict) else ""
        dec = guard.inbound(self.policy, subject, env)
        if dec.action != "drop" and mid and await self.db(ledger.seen, self.store, mid):
            self.stats["duplicates"] += 1
            if getattr(self, '_qualified_messages', False) and env['type'] in ('message', 'handoff'):
                await self._message_commands.confirm_receive(env)
            if getattr(self, '_qualified_knowledge', False) and env['type'] == 'knowledge':
                await self._knowledge_commands.confirm_receive(env)
            if getattr(self, '_qualified_code', False) and env['type'] == 'code':
                await self._code_commands.confirm_receive(env)
            if _uses_work_owner(self, env) and dec.action == 'deliver':
                with self._work_intents.inbound(subject, env, dec, msg):
                    recovered = await self._work_commands.confirm_seen(env, dec)
                if recovered:
                    self._work_commands.finish_disclosure()
            await _ack(msg)
            return "duplicate"
        return await self.apply(subject, env, dec, msg, plane, frm)

    async def apply(self, subject, env, dec, msg=None, plane=None, frm=None):
        plane = plane or subject.split(".")[1]
        frm = frm or (env.get("from") if isinstance(env, dict) else None)
        rid = env.get("rid") if isinstance(env, dict) else None
        if dec.action == "drop":
            self.stats["dropped"] += 1
            if dec.reason != "self":
                await self.db(self._audit_tx, "in", plane, frm, rid, subject,
                              env.get("id") if isinstance(env, dict) else None, env, "dropped",
                              {"why": dec.reason})
            await _ack(msg)
            return "dropped"
        if dec.action == "quarantine":
            def q():
                with self.store.tx():
                    qid = ledger.quarantine_add(self.store, env, subject, plane, frm, dec.reason)
                    ledger.audit(self.store, "in", plane, frm, rid, subject, env["id"], env, "quarantined",
                                 {"why": dec.reason, "quarantine": qid})
                    ledger.mark_seen(self.store, env["id"])
                return qid
            qid = await self.db(q)
            self.stats["quarantined"] += 1
            await _ack(msg)
            d = env.get("data") or {}
            await self.notify_operator(
                f"[fed] quarantined {env['type']} from {frm} ({dec.reason}): {(d.get('title') or d.get('body') or '')[:120]}"
                f"\n  agentmux hub fed approve {qid}    |    agentmux hub fed deny {qid}", f"fedq:{qid}")
            return "quarantined"
        plugin = self.routes.get(env["type"])
        if plugin is None:
            await self.db(self._audit_tx, "in", plane, frm, rid, subject, env["id"], env, "dropped",
                          {"why": f"no plugin handles {env['type']}"})
            await _ack(msg)
            return "dropped"
        try:
            admission = (self._message_intents.inbound(subject, env, dec, msg)
                if getattr(self, '_qualified_messages', False) and env['type'] in ('message', 'handoff')
                else self._knowledge_intents.inbound(subject, env, dec, msg)
                if getattr(self, '_qualified_knowledge', False) and env['type'] == 'knowledge'
                else self._code_intents.inbound(subject, env, dec, msg)
                if getattr(self, '_qualified_code', False) and env['type'] == 'code'
                else self._work_intents.inbound(subject, env, dec, msg)
                if _uses_work_owner(self, env) else nullcontext())
            with admission:
                outcome = await plugin.on_envelope(self, env, dec) or "delivered"
        except Exception as e:  # noqa: BLE001 - redelivered later; the ingest is idempotent
            self.stats["errors"] += 1
            self.log(f"fed: {plugin.name} failed on {env['id']}:", type(e).__name__, e)
            await self.db(self._audit_tx, "in", plane, frm, rid, subject, env["id"], env, "error", {"error": str(e)})
            if msg is not None:
                await msg.nak(delay=5)
            return "error"
        decision = outcome if outcome != "delivered" else ("flagged" if dec.untrusted else "delivered")

        def done():
            with self.store.tx():
                ledger.audit(self.store, "in", plane, frm, rid, subject, env["id"], env, decision,
                             {"trust": dec.trust, "approved": dec.approved} if dec.trust != "auto" or dec.approved else None)
                ledger.mark_seen(self.store, env["id"])
        await self.db(done)
        if getattr(self, '_qualified_messages', False) and env['type'] in ('message', 'handoff'):
            await self._message_commands.confirm_receive(env)
        if getattr(self, '_qualified_knowledge', False) and env['type'] == 'knowledge':
            await self._knowledge_commands.confirm_receive(env)
        if getattr(self, '_qualified_code', False) and env['type'] == 'code':
            await self._code_commands.confirm_receive(env)
        if _uses_work_owner(self, env):
            await self._work_commands.confirm_receive(env)
            self._work_commands.confirm_disclosure()
        self.stats["delivered"] += 1
        await _ack(msg)
        if _uses_work_owner(self, env):
            self._work_commands.finish_disclosure()
        return decision

    def _audit_tx(self, *a):
        with self.store.tx():
            ledger.audit(self.store, *a)

    async def _drain_outbox(self):
        rows = await self.db(ledger.outbox_pending, self.store)
        for r in rows:
            try:
                await self.js.publish(r["subject"], r["payload"].encode(), timeout=5,
                                      headers={"Nats-Msg-Id": r["msg_id"]})
            except Exception as e:  # noqa: BLE001 - stays in the outbox; retried next pass
                await self.db(ledger.outbox_failed, self.store, r["seq"], f"{type(e).__name__}: {e}")
                self.last_error = f"publish {r['subject']}: {type(e).__name__}: {e}"
                return
            await self.db(ledger.outbox_sent, self.store, r["seq"])
            self.stats["published"] += 1

    async def _presence(self, force=False):
        if not force and time.time() - self._last_presence < float(self.fcfg.get("presence_every_s", 20)):
            return
        self._last_presence = time.time()
        shared = self.policy.shared()
        agents = []
        for a in await self.db(self.store.agents, True):
            if a["repo"] in shared:
                agents.append({"repo": a["repo"], "rid": shared[a["repo"]], "role": a["role"], "agent": a["agent"],
                               "state": a["state"], "cli": a["cli"]})
        doc = {"peer": self.me, "node": self.node, "at": now(), "agents": agents,
               "repos": [{"repo": r, "rid": rid} for r, rid in shared.items()]}
        try:
            kv = await self.js.key_value("am_presence")
            await kv.put(f"{self.me}.{self.node}", json.dumps(doc).encode())
            try:
                keys = await kv.keys()
            except Exception:  # noqa: BLE001 - nats-py raises on an empty bucket
                keys = []
            online, presence = set(), {}
            for k in keys:
                online.add(k.split(".")[0])
                try:
                    presence.setdefault(k.split(".")[0], []).append(json.loads((await kv.get(k)).value))
                except Exception:  # noqa: BLE001 - expired between keys() and get()
                    pass
            self.presence = presence
            self.peer_ids = (online | {p for p in self.cfg.get("peers", {}) if p != "*"}) - {self.me}
        except Exception as e:  # noqa: BLE001
            self.last_error = f"presence: {type(e).__name__}: {e}"

    async def _on_ctl(self, m):
        try:
            env = json.loads(m.data)
            plane, frm, _ = envelope.validate_route(m.subject, env)
            if plane != "ctl":
                return
        except (ValueError, IndexError, TypeError):
            return
        if frm == self.me or env.get("from") != frm or env.get("type") != "revoke":
            return
        self.log("fed: peer", frm, "revoked its shares")
        await self.db(self._audit_tx, "in", "ctl", frm, None, m.subject, env.get("id"), env, "revoke", None)
        for p in self.plugin_adapters.values():
            try:
                if p.name == 'knowledge' and getattr(self, '_qualified_knowledge', False):
                    async with self._knowledge_intents.control(m.subject, env, m):
                        await p.on_revoke(self, frm)
                elif p.name == 'work' and getattr(self, '_qualified_work', False):
                    async with self._work_intents.control(m.subject, env, m):
                        await p.on_revoke(self, frm)
                else:
                    await p.on_revoke(self, frm)
            except Exception as e:  # noqa: BLE001
                self.log(f"fed: {p.name} on_revoke error", e)
        await self.notify_operator(f"[fed] peer {frm} pulled its kill switch: its unclaimed work was withdrawn",
                                   f"fedrevoke:{env.get('id')}")

    # -- events from the hub ---------------------------------------------------------------
    async def local_event(self, kind, data, *, require_completion=False):
        for p in self.plugin_adapters.values():
            try:
                if (p.name == 'knowledge' and getattr(self, '_qualified_knowledge', False)
                        and self.fcfg.get('capture', True)):
                    async with self._knowledge_intents.local_event(kind, data):
                        await p.on_local_event(self, kind, data)
                elif p.name == 'work' and getattr(self, '_qualified_work', False):
                    # The work service follow-on owns a separate private reply
                    # group; finishing it cannot consume a local caller's group.
                    await self._work_commands._joined(p.on_local_event(self, kind, data))
                else:
                    await p.on_local_event(self, kind, data)
            except HubError as e:
                if require_completion:
                    raise
                self.log(f"fed: {p.name} {kind}:", e)
            except guard.Refused as e:
                await self._audit_refusal(e)
                if require_completion:
                    raise
                self.log(f"fed: {p.name} {kind} refused:", e)
            except Exception as e:  # noqa: BLE001
                if require_completion:
                    raise
                self.log(f"fed: {p.name} {kind} error", type(e).__name__, e)

    async def guarded(self, coro):
        """For hub verbs that call into a plugin directly (post to peer:, work add
        --federate): a guard refusal is audited and becomes the caller's error."""
        try:
            return await coro
        except guard.Refused as e:
            await self._audit_refusal(e)
            raise HubError(str(e)) from None

    async def _audit_refusal(self, e):
        a = getattr(e, "audit", None)
        if a:
            # a = (dir, plane, peer, rid, subject, msg_id, payload); the refused payload is
            # hashed and sized in the audit row, never stored.
            await self.db(self._audit_tx, *a, e.decision, {"reason": str(e), "kinds": sorted(set(e.kinds))})

    # -- verbs -----------------------------------------------------------------------------
    async def dispatch(self, verb, a, caller):
        v = self.verbs.get(verb)
        if v is None:
            raise HubError(f"unknown federation verb {verb!r} (agentmux hub fed help)")
        if v.operator_only and caller != "operator":
            raise HubError(f"{verb} is operator-only")
        for pn, p in v.params.items():
            if p.required and a.get(pn) in (None, "", []):
                raise HubError(f"{verb.removeprefix('fed_').replace('_', ' ')} needs --{pn}")
        try:
            if verb in self.plugin_verbs:
                adapter, name = self.plugin_verbs[verb]
                return await adapter.invoke(self, name, a, caller)
            return await v.fn(self, a, caller)
        except guard.Refused as e:
            await self._audit_refusal(e)
            raise HubError(str(e)) from None

    def _core_verbs(self):
        V, P = Verb, Param
        return {
            "fed_status": V(_v_status, "connection, identity, shares, trust, outbox and counters"),
            "fed_peers": V(_v_peers, "who is online in the circle, and which agents and repos they offer"),
            "fed_share": V(_v_share, "opt a local repo in (per-repo opt-in)", {
                "repo": P(required=True, positional=True, help="local repo name"),
                "peers": P("array", help="peer ids, or * for the whole circle (default *)"),
                "remote": P(help="normalized remote to match on, if the repo has no origin alias"),
                "board_prefix": P(help="shared board key prefix (default SH)")}, operator_only=True),
            "fed_unshare": V(_v_unshare, "opt a repo out", {"repo": P(required=True, positional=True)},
                             operator_only=True),
            "fed_trust": V(_v_trust, "set a peer's trust: auto | flag | approve | deny", {
                "peer": P(required=True, positional=True, help="peer id or *"),
                "level": P(required=True, help="auto | flag | approve | deny")}, operator_only=True),
            "fed_kill": V(_v_kill, "KILL SWITCH: disconnect now and stay disconnected; --revoke also withdraws "
                                   "unclaimed work and tells peers", {"revoke": P("boolean")}, operator_only=True),
            "fed_resume": V(_v_resume, "undo the kill switch", operator_only=True),
            "fed_quarantine": V(_v_quarantine, "list inbound items held for approval",
                                {"state": P(help="held (default) | approved | denied | all")}),
            "fed_approve": V(_v_approve, "release a quarantined item", {
                "id": P(required=True, positional=True),
                "privileged": P("boolean", help="also allow privileged tools for this remote work")},
                operator_only=True),
            "fed_deny": V(_v_deny, "discard a quarantined item", {"id": P(required=True, positional=True)},
                          operator_only=True),
            "fed_audit": V(_v_audit, "the cross-user audit log, newest first", {
                "limit": P("integer"), "peer": P(), "since": P("integer")}),
            "fed_gate": V(_v_gate, "does this agent hold remote-origin work? (privileged-tool hook)",
                          {"session": P(help="operator only: ask about another session")}),
            "fed_verbs": V(_v_verbs, "the verb registry (drives the CLI and the MCP tools)"),
            "fed_panel": V(_v_panel, "everything the dashboard's Federation view shows"),
        }


async def _ack(msg):
    if msg is not None:
        try:
            await msg.ack()
        except Exception:  # noqa: BLE001 - redelivery is absorbed by fed_seen
            pass


# -- core verb implementations ---------------------------------------------------------
async def _v_status(fed, a, caller):
    killed = await fed.db(ledger.state_get, fed.store, "killed")
    pol = await fed.refresh_policy()
    return {"enabled": fed.enabled, "peer": fed.me, "node": fed.node, "url": fed.fcfg.get("url") or None,
            "connected": fed.connected, "killed": killed, "last_error": fed.last_error or None,
            "shared": pol.shared(), "unmatched": pol.unmatched(),
            "trust": {p: t.get("trust") for p, t in fed.cfg.get("peers", {}).items()},
            "plugins": list(fed.plugins), "outbox": await fed.db(ledger.outbox_stats, fed.store),
            "stats": fed.stats}


async def _v_peers(fed, a, caller):
    if not fed.connected:
        raise HubError("not connected")
    kv = await fed.js.key_value("am_presence")
    out = []
    try:
        keys = await kv.keys()
    except Exception:  # noqa: BLE001 - nats-py raises when the bucket is empty
        keys = []
    for k in keys:
        try:
            e = await kv.get(k)
            d = json.loads(e.value)
        except Exception:  # noqa: BLE001
            continue
        d["trust"] = fed.policy.trust(d.get("peer", "")) if d.get("peer") != fed.me else "self"
        for r in d.get("repos", []):
            r["local"] = fed.policy.local_of(r["rid"])
        out.append(d)
    return sorted(out, key=lambda d: (d.get("peer") != fed.me, d.get("peer"), d.get("node")))


async def _v_share(fed, a, caller):
    commands = _policy_commands(fed)
    if commands is not None:
        return await commands._joined(_qualified_policy_change(fed, commands, 'share', a, caller))
    repo = a["repo"]
    if not await fed.db(fed.store.q1, "SELECT 1 FROM repos WHERE repo=?", (repo,)):
        raise HubError(f"unknown repo {repo!r} (agentmux hub repo add {repo} <path>)")
    peers = a.get("peers") or ["*"]
    if isinstance(peers, str):
        peers = [p for p in peers.replace(",", " ").split() if p]
    t = {"peers": peers}
    if a.get("remote"):
        t["remote"] = normalize_remote(a["remote"])
    if a.get("board_prefix"):
        t["board_prefix"] = a["board_prefix"].upper()
    fed.cfg["repos"][repo] = t
    fed.save_cfg()
    pol = await fed.refresh_policy()
    if repo not in pol.shared():
        raise HubError(f"{repo} has no git remote to match on: pass --remote <url> (it is saved; fix and re-share)")
    await fed._presence(force=True) if fed.connected else None
    return {"repo": repo, "rid": pol.rid_of(repo), "peers": peers}


async def _v_unshare(fed, a, caller):
    commands = _policy_commands(fed)
    if commands is not None:
        return await commands._joined(_qualified_policy_change(fed, commands, 'unshare', a, caller))
    fed.cfg["repos"].pop(a["repo"], None)
    fed.save_cfg()
    await fed.refresh_policy()
    return {"unshared": a["repo"]}


async def _v_trust(fed, a, caller):
    commands = _policy_commands(fed)
    if commands is not None:
        return await commands._joined(_qualified_policy_change(fed, commands, 'trust', a, caller))
    level = a["level"]
    if level not in config.TRUST_LEVELS:
        raise HubError(f"trust must be one of {', '.join(config.TRUST_LEVELS)}")
    peer = a["peer"]
    if peer != "*":
        names.check_part(peer, "peer")
    fed.cfg["peers"].setdefault(peer, {})["trust"] = level
    fed.save_cfg()
    await fed.refresh_policy()
    return {"peer": peer, "trust": level}


def _policy_commands(fed):
    commands = getattr(fed.hub, '_policy_commands', None)
    if commands is None and any(getattr(fed, name, False) for name in
            ('_qualified_board', '_qualified_messages', '_qualified_knowledge', '_qualified_code', '_qualified_work')):
        raise HubError('an enrolled federation policy owner is required')
    return commands


async def _qualified_policy_change(fed, commands, verb, arguments, caller):
    if verb == 'share' and not await fed.db(fed.store.q1, 'SELECT 1 FROM repos WHERE repo=?', (arguments['repo'],)):
        raise HubError(f"unknown repo {arguments['repo']} (agentmux hub repo add {arguments['repo']} <path>)")
    await commands.change(caller, verb, arguments)
    # The owner has verified both the commit and its selected source projection.
    # Keep this refresh in the original owned verb through caller cancellation.
    fed.cfg = config.load(fed.hubdir)
    policy = await fed.refresh_policy()
    if verb == 'trust':
        return {'peer': arguments['peer'], 'trust': arguments['level']}
    if verb == 'unshare':
        return {'unshared': arguments['repo']}
    repo = arguments['repo']
    if repo not in policy.shared():
        raise HubError(f'{repo} has no git remote to match on')
    if fed.connected:
        await fed._presence(force=True)
    peers = arguments.get('peers') or ['*']
    if isinstance(peers, str):
        peers = peers.replace(',', ' ').split()
    return {'repo': repo, 'rid': policy.rid_of(repo), 'peers': peers}


async def _v_kill(fed, a, caller):
    peer_control = getattr(fed.hub, '_peer_control_commands', None) if a.get('revoke') else None
    if peer_control is not None:
        # The client retains the whole original kill, including local cleanup,
        # when its requesting connection is cancelled.
        return await peer_control._joined(_kill_owned(fed, a, caller, peer_control=peer_control))
    return await _kill_owned(fed, a, caller)


async def _kill_owned(fed, a, caller, *, peer_control=None):
    revoke = bool(a.get("revoke"))
    report = {"killed": True, "revoke": revoke, "at": now()}
    if revoke and fed.connected:
        report["withdrawn_work"] = await _withdraw_work(fed)
        try:
            kv = await fed.js.key_value("am_presence")
            await kv.delete(f"{fed.me}.{fed.node}")
        except Exception as e:  # noqa: BLE001
            report["presence_error"] = str(e)
    if revoke and (fed.connected or peer_control is not None):
        env = envelope.make("revoke", fed.me, fed.node, None, "*", {"reason": a.get("reason") or "kill switch"})
        if peer_control is None:
            await fed.nc.publish(f"am.ctl.{fed.me}", json.dumps(env).encode())
            await fed.nc.flush(timeout=3)
        else:
            try:
                results = await peer_control.revoke(caller, env)
                report['revoke_results'] = results
                report['revoke_publication'] = ('published' if results
                    and all(item['outcome'] == 'published' for item in results) else 'uncertain')
            except Exception:
                # Retained owner/client intent decides recovery. A refused or
                # lost remote reply cannot prevent the original local kill.
                report['revoke_publication'] = 'unconfirmed'
    if revoke:
        report["withdrawn_outbox"] = await fed.db(ledger.outbox_withdraw, fed.store)
    await fed.db(ledger.state_set, fed.store, "killed", report)
    if peer_control is not None and report.get('revoke_publication') == 'published':
        try:
            await peer_control.confirm_killed(report)
        except Exception:
            report['revoke_confirmation'] = 'unconfirmed'
            await fed.db(ledger.state_set, fed.store, 'killed', report)
    await fed.db(fed._audit_tx, "local", "ctl", fed.me, None, None, None, report, "killed", report)
    if fed.nc is not None:
        await conn.close(fed.nc)
    fed.kick()
    return report


async def _withdraw_work(fed):
    """Delete this peer's not-yet-taken items from the AM_WORK work queue."""
    n = 0
    try:
        info = await fed.js.stream_info("AM_WORK")
        first, last = info.state.first_seq, info.state.last_seq
        for seq in range(first, min(last, first + 10000) + 1):
            try:
                m = await fed.js.get_msg("AM_WORK", seq)
            except Exception:  # noqa: BLE001 - already consumed or deleted
                continue
            if m.subject.startswith(f"am.work.{fed.me}."):
                await fed.js.delete_msg("AM_WORK", seq)
                n += 1
    except Exception as e:  # noqa: BLE001
        fed.log("fed: withdraw failed", e)
    return n


async def _v_resume(fed, a, caller):
    await fed.db(ledger.state_set, fed.store, "killed", None)
    await fed.db(fed._audit_tx, "local", "ctl", fed.me, None, None, None, {}, "resumed", None)
    fed.kick()
    return {"resumed": True}


async def _v_quarantine(fed, a, caller):
    st = a.get("state") or "held"
    return await fed.db(ledger.quarantine_list, fed.store, None if st == "all" else st)


async def _v_approve(fed, a, caller):
    q = await fed.db(ledger.quarantine_get, fed.store, a["id"])
    recovery = q is not None and q['state'] == 'approved' and _uses_work_owner(fed, q['envelope'])
    if not q or q["state"] != "held" and not recovery:
        raise HubError(f"no held quarantine item {a['id']}")
    env = q["envelope"]
    dec = guard.Decision("deliver", "approved by operator", fed.policy.trust(q["peer"]), untrusted=True,
                         local_repo=fed.policy.local_of(env.get("rid") or ""), approved=True,
                         privileged_ok=bool(a.get("privileged")))
    plugin = fed.routes.get(env["type"])
    if plugin is None:
        raise HubError(f"no plugin handles {env['type']}")
    admission = (nullcontext() if recovery else fed._message_intents.approved(q, caller)
        if getattr(fed, '_qualified_messages', False) and env['type'] in ('message', 'handoff')
        else fed._knowledge_intents.approved(q, caller, dec)
        if getattr(fed, '_qualified_knowledge', False) and env['type'] == 'knowledge'
        else fed._code_intents.approved(q, caller, dec)
        if getattr(fed, '_qualified_code', False) and env['type'] == 'code'
        else fed._work_intents.approved(q, caller)
        if _uses_work_owner(fed, env) else nullcontext())
    with admission:
        out = (await fed._work_commands.recover_approved(q, caller) if recovery
            else await plugin.on_envelope(fed, env, dec) or "delivered")
    if not recovery:
        await fed.db(ledger.quarantine_decide, fed.store, a["id"], "approved", caller)
    if getattr(fed, '_qualified_messages', False) and env['type'] in ('message', 'handoff'):
        await fed._message_commands.confirm_receive(env, quarantine_id=a['id'], privileged=bool(a.get('privileged')))
    if getattr(fed, '_qualified_knowledge', False) and env['type'] == 'knowledge':
        await fed._knowledge_commands.confirm_receive(env, quarantine_id=a['id'], privileged=bool(a.get('privileged')))
    if getattr(fed, '_qualified_code', False) and env['type'] == 'code':
        await fed._code_commands.confirm_receive(env, quarantine_id=a['id'], privileged=bool(a.get('privileged')))
    await fed.db(fed._audit_tx, "in", q["plane"], q["peer"], env.get("rid"), q["subject"], env["id"], env,
                 "approved", {"quarantine": a["id"], "privileged": bool(a.get("privileged")), "outcome": out})
    if _uses_work_owner(fed, env):
        await fed._work_commands.confirm_receive(env, quarantine_id=a['id'], privileged=bool(a.get('privileged')))
        fed._work_commands.confirm_disclosure()
    return {"approved": a["id"], "outcome": out}


async def _v_deny(fed, a, caller):
    q = await fed.db(ledger.quarantine_get, fed.store, a["id"])
    if not q or not await fed.db(ledger.quarantine_decide, fed.store, a["id"], "denied", caller):
        raise HubError(f"no held quarantine item {a['id']}")
    await fed.db(fed._audit_tx, "in", q["plane"], q["peer"], q["envelope"].get("rid"), q["subject"],
                 q["envelope"]["id"], q["envelope"], "denied", {"quarantine": a["id"]})
    return {"denied": a["id"]}


async def _v_audit(fed, a, caller):
    rows = await fed.db(ledger.audit_tail, fed.store, int(a.get("limit") or 50), a.get("peer"), int(a.get("since") or 0))
    for r in rows:
        if r.get("detail"):
            r["detail"] = json.loads(r["detail"])
    return rows


async def _v_gate(fed, a, caller):
    if getattr(fed, '_qualified_work', False):
        return await fed.hub._qualified_work_gate(a, caller)
    who = a.get("session") if caller == "operator" and a.get("session") else caller
    rows = await fed.db(fed.store.q, "SELECT id, title, origin_peer, fed_flags FROM work_items WHERE claimed_by=? "
                        "AND state IN ('claimed','waiting_children') AND origin_peer IS NOT NULL", (who,))
    remote = []
    for r in rows:
        flags = json.loads(r["fed_flags"] or "{}")
        remote.append({"id": r["id"], "title": r["title"], "peer": r["origin_peer"],
                       "privileged_ok": bool(flags.get("privileged_ok"))})
    return {"session": who, "remote_work": remote,
            "privileged_allowed": all(r["privileged_ok"] for r in remote)}


async def _v_verbs(fed, a, caller):
    out = []
    for name, v in sorted(fed.verbs.items()):
        out.append({"verb": name, "help": v.help, "operator_only": v.operator_only,
                    "params": {k: {"type": p.type, "required": p.required, "help": p.help, "positional": p.positional}
                               for k, p in v.params.items()}})
        if name in ('fed_code_share', 'fed_code_fetch') and getattr(fed, '_qualified_code', False):
            out[-1]['operationIds'] = True
        if name == 'fed_work_add' and getattr(fed.hub, '_work_rpc', None) is not None:
            out[-1]['operationIds'] = True
    return out


async def _v_panel(fed, a, caller):
    st = await _v_status(fed, a, caller)
    try:
        peers = await _v_peers(fed, a, caller) if fed.connected else []
    except HubError:
        peers = []
    knowledge_panel = code_panel = work_panel = None
    if any(getattr(fed, '_qualified_' + domain, False) for domain in ('knowledge', 'code', 'work')):
        with fed.hub._panel_callers(caller) as proofs:
            for domain, title in (('knowledge', 'Knowledge'), ('code', 'Code'), ('work', 'Federated work')):
                if not getattr(fed, '_qualified_' + domain, False):
                    continue
                token = fed.hub._authenticated_caller_context.set(proofs[domain])
                try:
                    value = (await fed._work_commands.read(caller, panel=True) if domain == 'work'
                        else await getattr(fed, '_' + domain + '_commands').read(caller, 'panel', {}))
                    if domain == 'knowledge':
                        knowledge_panel = value
                    elif domain == 'code':
                        code_panel = value
                    else:
                        work_panel = value
                except Exception:
                    value = {'title': title, 'error': title + ' data is unavailable'}
                    if domain == 'knowledge':
                        knowledge_panel = value
                    elif domain == 'code':
                        code_panel = value
                    else:
                        work_panel = value
                finally:
                    fed.hub._authenticated_caller_context.reset(token)

    def sync():
        out = []
        for p in fed.plugin_adapters.values():
            try:
                if p.name == 'knowledge' and knowledge_panel is not None:
                    pan = knowledge_panel
                elif p.name == 'code' and code_panel is not None:
                    pan = code_panel
                elif p.name == 'work' and work_panel is not None:
                    pan = work_panel
                else:
                    pan = p.panel(fed)
            except Exception as e:  # noqa: BLE001
                pan = {"title": p.name, "error": str(e)}
            if pan:
                out.append({"plugin": p.name, **pan})
        return out
    panels = await fed.db(sync)
    quarantine = await _v_quarantine(fed, {}, caller)
    audit = await _v_audit(fed, {"limit": 40}, caller)
    if getattr(fed, '_qualified_code', False):
        try:
            fed._code_commands.confirm_panel_disclosure()
        except Exception:
            panels = [{"plugin": "code", "title": "Code", "error": "Code data is unavailable"}
                if panel.get('plugin') == 'code' else panel for panel in panels]
    if getattr(fed, '_qualified_work', False) and work_panel is not None and 'error' not in work_panel:
        try:
            fed._work_commands.confirm_disclosure()
        except Exception:
            panels = [{'plugin': 'work', 'title': 'Federated work', 'error': 'Federated work data is unavailable'}
                if panel.get('plugin') == 'work' else panel for panel in panels]
    return {"status": st, "peers": peers, "quarantine": quarantine, "audit": audit, "panels": panels}
