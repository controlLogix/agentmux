"""knowledge: a shared stream of findings, searchable offline (FEDERATION.md 9.4, assumption A11).

Explicit: `fed know share`. Auto-capture (capture = true): an item released done with
a result, a handoff, and a federated result coming home. Every hub indexes the AM_SHARE
stream for the repos it shares into p_knowledge_items + FTS5, and rings the repo's live
agents with a one-line note (never the body) when a peer's finding arrives.
"""
from __future__ import annotations

from hub.fed.plugin import Param, Plugin, Verb
from hub.store import HubError


class Knowledge(Plugin):
    name = "knowledge"
    handles = ("knowledge",)
    tables = [
        "CREATE TABLE IF NOT EXISTS p_knowledge_items (id TEXT PRIMARY KEY, rid TEXT NOT NULL, repo TEXT, "
        "from_peer TEXT NOT NULL, author TEXT, title TEXT NOT NULL, body TEXT NOT NULL, tags TEXT, ref TEXT, "
        "source TEXT NOT NULL DEFAULT 'explicit', trust TEXT, untrusted INTEGER NOT NULL DEFAULT 0, "
        "withdrawn TEXT, at TEXT NOT NULL) STRICT",
        "CREATE VIRTUAL TABLE IF NOT EXISTS p_knowledge_fts USING fts5(title, body, tags, "
        "content='p_knowledge_items', content_rowid='rowid')",
        "CREATE TRIGGER IF NOT EXISTS p_knowledge_ai AFTER INSERT ON p_knowledge_items BEGIN "
        "INSERT INTO p_knowledge_fts(rowid, title, body, tags) VALUES (new.rowid, new.title, new.body, new.tags); END",
    ]

    def verbs(self):
        P = Param
        return {
            "share": Verb(self.v_share, "publish a finding to everyone the repo is shared with", {
                "repo": P(help="local repo (default: yours)"), "title": P(required=True),
                "body": P(required=True, positional=True), "tags": P("array"), "ref": P()}),
            "search": Verb(self.v_search, "full-text search of every finding shared with you (works offline)", {
                "query": P(required=True, positional=True), "repo": P(), "limit": P("integer")}),
            "recent": Verb(self.v_recent, "newest findings", {"repo": P(), "limit": P("integer")}),
            "show": Verb(self.v_show, "one finding", {"id": P(required=True, positional=True)}),
        }

    async def v_share(self, ctx, a, caller):
        repo = a.get("repo") or ctx.agents.sender_of(caller).get("repo")
        if not repo:
            raise HubError("know share needs --repo")
        tags = a.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        return await self.share(ctx, caller, repo, a["title"], a["body"], tags, a.get("ref"), "explicit")

    async def share(self, ctx, caller, repo, title, body, tags=(), ref=None, source="explicit"):
        return await ctx.knowledge.share(caller, repo, title, body, tags, ref, source)

    async def on_envelope(self, ctx, env, dec):
        outcome = await ctx.knowledge.index_received(env, dec)
        if outcome != "delivered":
            return outcome
        if ctx.settings.notify_findings and dec.local_repo:
            for agent in await ctx.agents.live_for_repo(dec.local_repo):
                await ctx.messages.finding(env, dec, agent["session"])
        return "delivered"

    async def on_local_event(self, ctx, kind, data):
        if not ctx.settings.capture:
            return
        if kind == "work_released" and data and data.get("state") == "done" and data.get("result"):
            repo = data.get("repo")
            if not ctx.knowledge.is_shared(repo or ""):
                return
            caller = data.get("claimed_by") or "operator"
            if caller.startswith(("fed:", "peer:", "nats:")):
                return
            await self.share(ctx, caller, repo, f"done: {data['title']}", data["result"],
                             ["auto", "work"], data.get("task_key") or data["id"], "auto:work")
        elif kind == "handoff_sent" and data.get("repo"):
            await self.share(ctx, data["by"], data["repo"], f"handoff to {data['to']}", data["body"],
                             ["auto", "handoff"], data.get("ref"), "auto:handoff")
        elif kind == "fed_result" and data and data.get("result"):
            repo = data.get("repo")
            if ctx.knowledge.is_shared(repo or ""):
                await self.share(ctx, "operator", repo, f"result from {data['from_peer']}: {data['title']}",
                                 data["result"], ["auto", "result"], data.get("task_key") or data["id"], "auto:result")

    async def v_search(self, ctx, a, caller):
        return await ctx.knowledge.search(a)

    async def v_recent(self, ctx, a, caller):
        return await ctx.knowledge.recent(a)

    async def v_show(self, ctx, a, caller):
        return await ctx.knowledge.show(a)

    async def on_revoke(self, ctx, peer):
        await ctx.knowledge.revoke(peer)

    async def on_tick(self, ctx):
        await ctx.knowledge.recover()

    async def start(self, ctx):
        await ctx.knowledge.recover()

    def panel(self, ctx):
        return ctx.knowledge.panel()


PLUGIN = Knowledge()
