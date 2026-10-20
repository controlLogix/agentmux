"""Narrow services for the trusted legacy Knowledge implementation.

Private owner references preserve the existing transactions. These Python objects
are an API boundary, not isolation from hostile code or proof of caller identity.
"""
from __future__ import annotations

from hub.profile_context import ProfileContext

from dataclasses import dataclass
from types import MappingProxyType

from hub.fed import envelope
from hub.store import HubError, now


def _receive_refusal(federation, env, decision):
    policy = federation.policy
    peer, rid = env["from"], env.get("rid")
    if not policy.known_peer(peer) or policy.trust(peer) == "deny":
        return "denied"
    if not rid or not policy.may_receive(rid, peer) or policy.local_of(rid) != decision.local_repo:
        return "not_shared"
    return None


class KnowledgeOwner:
    __slots__ = ("__federation",)

    def __init__(self, federation):
        self.__federation = federation

    def is_shared(self, repo):
        return bool(self.__federation.policy.rid_of(repo or ""))

    async def recover(self):
        # The original local provider has no remote capture acknowledgments.
        return None

    async def index_received(self, env, decision):
        ctx = self.__federation
        def tx():
            with ctx.store.tx():
                refusal = _receive_refusal(ctx, env, decision)
                if refusal:
                    return refusal
                return self.stage_received(env, decision)
        return await ctx.db(tx)

    def stage_received(self, env, decision):
        """Index admitted data in the caller's existing Store transaction."""
        refusal = _receive_refusal(self.__federation, env, decision)
        if refusal:
            return refusal
        self._index(env, decision.local_repo, decision.trust, decision.untrusted)
        return 'delivered'

    async def share(self, caller, repo, title, body, tags=(), ref=None, source="explicit"):
        ctx = self.__federation
        rid = ctx.policy.rid_of(repo)
        if not rid:
            raise HubError(f"repo {repo!r} is not shared (agentmux hub fed share {repo})")
        s = ctx.sender_of(caller)
        author = "operator" if s.get("operator") else f"{s['role']}/{s['agent']}"
        env = envelope.make("knowledge", ctx.me, ctx.node, rid, "*",
                            {"title": title, "body": body, "tags": list(tags), "ref": ref, "author": author,
                             "source": source})

        def tx():
            with ctx.store.tx():
                return self.stage_share(env, repo)
        result = await ctx.db(tx)
        if result is None:
            return None
        clean, kinds = result
        return {"id": env["id"], "repo": repo, "title": clean["data"]["title"], "redacted": sorted(set(kinds))}

    def stage_share(self, env, repo):
        """Stage and index in the caller's existing Store transaction."""
        ctx = self.__federation
        if env['data'].get('source', 'explicit').startswith('auto:') and not ctx.fcfg.get('capture', True):
            return None
        if ctx.policy.rid_of(repo) != env['rid']:
            raise HubError('repo sharing changed before publishing the finding')
        clean, kinds = ctx.stage(env, envelope.subject('know', ctx.me, env['rid']), repo, '*')
        self._index(clean, repo, 'self', False)
        return clean, kinds

    def _index(self, env, repo, trust, untrusted):
        ctx = self.__federation
        d = env["data"]
        ctx.store.db.execute(
            "INSERT OR IGNORE INTO p_knowledge_items (id, rid, repo, from_peer, author, title, body, tags, ref, source, "
            "trust, untrusted, at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (env["id"], env["rid"], repo, env["from"], d.get("author"), d.get("title") or "(untitled)",
             d.get("body") or "", " ".join(d.get("tags") or []), d.get("ref"), d.get("source") or "explicit",
             trust, int(untrusted), env.get("at") or now()))

    async def search(self, a):
        ctx = self.__federation
        q = a["query"]
        fts = " ".join(f'"{w}"' for w in q.replace('"', " ").split() if w)
        if not fts:
            raise HubError("empty query")
        rows = await ctx.db(ctx.store.q,
                            "SELECT k.id, k.repo, k.from_peer, k.author, k.title, snippet(p_knowledge_fts, 1, '[', ']', "
                            "' … ', 16) AS snippet, k.tags, k.ref, k.at, k.untrusted, k.withdrawn "
                            "FROM p_knowledge_fts JOIN p_knowledge_items k ON k.rowid = p_knowledge_fts.rowid "
                            "WHERE p_knowledge_fts MATCH ? AND (? IS NULL OR k.repo = ?) ORDER BY rank LIMIT ?",
                            (fts, a.get("repo"), a.get("repo"), int(a.get("limit") or 10)))
        return rows

    async def recent(self, a):
        ctx = self.__federation
        return await ctx.db(ctx.store.q, "SELECT id, repo, from_peer, author, title, source, tags, ref, at, untrusted, "
                            "withdrawn FROM p_knowledge_items WHERE (? IS NULL OR repo=?) ORDER BY at DESC LIMIT ?",
                            (a.get("repo"), a.get("repo"), int(a.get("limit") or 20)))

    async def show(self, a):
        ctx = self.__federation
        r = await ctx.db(ctx.store.q1, "SELECT * FROM p_knowledge_items WHERE id=?", (a["id"],))
        if not r:
            raise HubError(f"no finding {a['id']}")
        return r

    async def revoke(self, peer):
        ctx = self.__federation
        def tx():
            with ctx.store.tx():
                self.stage_withdrawal(peer)
        await ctx.db(tx)

    def stage_withdrawal(self, peer, repo=None):
        """Retain original findings; a scoped owner withdraws only its repo."""
        return self.__federation.store.db.execute(
            'UPDATE p_knowledge_items SET withdrawn=? WHERE from_peer=? AND withdrawn IS NULL '
            'AND (? IS NULL OR repo=?)', (f'{peer} revoked its shares {now()}', peer, repo, repo)).rowcount

    def panel(self, repo=None):
        ctx = self.__federation
        rows = ctx.store.q("SELECT id, repo, from_peer, author, title, source, at, untrusted, withdrawn "
                           "FROM p_knowledge_items WHERE (? IS NULL OR repo=?) ORDER BY at DESC LIMIT 30", (repo, repo))
        return self.panel_value(rows)

    @staticmethod
    def panel_value(rows):
        return {"title": "Knowledge", "columns": ["at", "repo", "from", "title", "source", "flags"],
                "rows": [[r["at"][:19], r["repo"], f"{r['from_peer']} {r['author'] or ''}", r["title"], r["source"],
                          ("untrusted " if r["untrusted"] else "") + ("withdrawn" if r["withdrawn"] else "")]
                         for r in rows]}


class AgentDirectory:
    __slots__ = ("__federation",)

    def __init__(self, federation):
        self.__federation = federation

    def sender_of(self, caller):
        return MappingProxyType(dict(self.__federation.sender_of(caller)))

    async def live_for_repo(self, repo):
        ctx = self.__federation
        rows = await ctx.db(ctx.store.agents, True)
        return tuple(MappingProxyType(dict(row)) for row in rows if row["repo"] == repo)


class LocalMessages:
    __slots__ = ("__federation",)

    def __init__(self, federation):
        self.__federation = federation

    async def finding(self, env, decision, session):
        ctx = self.__federation
        if getattr(ctx, '_qualified_knowledge', False):
            from capability_owner.legacy_messages_client import LegacyMessageCommandClient
            commands = getattr(ctx, '_message_commands', None)
            if type(commands) is not LegacyMessageCommandClient:
                raise HubError('qualified finding message route is required')
            return await commands.finding(env, session)
        repo = decision.local_repo
        if not repo:
            return
        d = env["data"]
        note = (f"[fed] finding from {env['from']} on {repo}: {(d.get('title') or '')[:100]}"
                f"{' (untrusted data)' if decision.untrusted else ''}\n  agentmux hub fed know show {env['id']}")
        target = f"agent:{session}"
        selected, bindings = target, ()
        hub = getattr(ctx, 'hub', None)
        if hub is not None and getattr(hub, '_legacy_identity', None) is not None:
            try:
                selected, bindings = await hub._current_identity_target(target)
            except HubError as error:
                ctx.log("fed: local post failed", target, error)
                return None

        def post():
            # Check current settings after database dispatch, at the write boundary.
            if (not ctx.fcfg.get("notify_findings", True)
                    or _receive_refusal(ctx, env, decision)):
                return None
            return ctx.store.post(f"peer:{env['from']}", selected, "finding", note, d.get("ref"),
                None, f"know:{env['id']}:{session}", meta=None, identity_bindings=bindings)

        try:
            return await ctx.db(post)
        except HubError as error:
            ctx.log("fed: local post failed", target, error)
            return None


@dataclass(frozen=True, slots=True)
class KnowledgeSettings:
    capture: bool
    notify_findings: bool


@dataclass(frozen=True, slots=True)
class KnowledgeContext:
    settings: KnowledgeSettings
    knowledge: KnowledgeOwner
    agents: AgentDirectory
    messages: LocalMessages
    profile_context: ProfileContext | None = None


class QualifiedKnowledgeOwner:
    __slots__ = ('__client', '__federation')

    def __init__(self, federation):
        from capability_owner.legacy_knowledge_client import LegacyKnowledgeCommandClient
        client = getattr(federation, '_knowledge_commands', None)
        if type(client) is not LegacyKnowledgeCommandClient:
            raise HubError('qualified knowledge owner route is required')
        client.bind(federation)
        client.check(federation)
        self.__client, self.__federation = client, federation

    def is_shared(self, repo):
        return bool(self.__federation.policy.rid_of(repo or ''))

    async def share(self, caller, repo, title, body, tags=(), ref=None, source='explicit'):
        return await self.__client.share(caller, repo, title, body, tags, ref, source)

    async def index_received(self, env, decision):
        return await self.__client.receive(env, decision)

    async def recover(self):
        return await self.__client.recover_captures()

    def _caller(self):
        hub = self.__federation.hub
        proof = hub.current_authenticated_caller()
        admitted = hub._authenticated_callers.get(proof)
        if admitted is None:
            raise HubError('authenticated knowledge caller is required')
        return admitted.caller

    async def search(self, args):
        return await self.__client.read(self._caller(), 'search', args)

    async def recent(self, args):
        return await self.__client.read(self._caller(), 'recent', args)

    async def show(self, args):
        return await self.__client.read(self._caller(), 'show', args)

    async def revoke(self, peer):
        return await self.__client.withdraw(peer)

    def panel(self):
        raise HubError('qualified knowledge panel needs its authenticated async route')


def build_knowledge_context(federation):
    settings = KnowledgeSettings(bool(federation.fcfg.get("capture", True)),
                                 bool(federation.fcfg.get("notify_findings", True)))
    owner = QualifiedKnowledgeOwner(federation) if getattr(federation, '_qualified_knowledge', False) else KnowledgeOwner(federation)
    return KnowledgeContext(settings, owner, AgentDirectory(federation), LocalMessages(federation))
