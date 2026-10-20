"""Federated work plugin using the existing work owner and owned queue consumer."""
from hub.fed.plugin import Param, Plugin, Verb
# Keep these protocol helpers available to existing callers.
from hub.fed.work_services import (PENDING, offer_digest, digest, result_digest,
                                   reference, valid_reference, matches_offer, valid_work_data)


class Work(Plugin):
    name = "work"
    handles = ("work", "work_claim", "work_grant", "result")

    def verbs(self):
        return {
            "add": Verb(self.v_add, "offer a role item to every hub in the circle that serves that repo and role", {
                "to": Param(required=True, help="role:<repo>/<role>"),
                "title": Param(required=True), "body": Param(positional=True),
                "task_key": Param(help="board card key (local TM-x or shared SH-x)"),
                "require": Param("array", help="required capabilities"),
                "priority": Param("integer")}),
            "list": Verb(self.v_list, "federated items: outgoing (waiting on a peer) and incoming (from peers)"),
        }


    async def v_add(self, ctx, a, caller):
        req = {"capabilities": a["require"]} if a.get("require") else None
        return await self.add(ctx, caller, a["to"], a["title"], a.get("body"), a.get("task_key"), req,
                              int(a.get("priority") or 100))

    async def add(self, ctx, caller, to, title, body=None, task_key=None, requirements=None, priority=100):
        return await ctx.work.add(caller, to, title, body, task_key, requirements, priority)

    async def on_connect(self, ctx):
        ctx.consumer.check_open()

    async def on_tick(self, ctx):
        return await ctx.consumer.poll()

    async def on_envelope(self, ctx, env, decision):
        return await ctx.work.receive(env, decision)

    async def on_local_event(self, ctx, kind, work):
        return await ctx.work.local_event(kind, work)

    async def recover_results(self, ctx):
        return await ctx.work.recover_results()

    async def on_revoke(self, ctx, peer):
        return await ctx.work.revoke(peer)

    async def v_list(self, ctx, args, caller):
        return await ctx.work.rows(caller)

    def panel(self, ctx):
        return ctx.work.panel()


PLUGIN = Work()
