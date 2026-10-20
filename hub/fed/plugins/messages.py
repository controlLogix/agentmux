"""messages: direct messages and handoffs between people's agents (FEDERATION.md 9.2).

Addresses (the sender's local repo name; translated to a rid on the wire and to the
receiver's local name on arrival):
  peer:<peer>                          that peer's operator inbox
  peer:<peer>/<repo>/<role>            any live holder of the role on that peer's hub
  peer:<peer>/<repo>/<role>/<agent>    one agent
"""
from __future__ import annotations

import re

from hub import names
from hub.fed import envelope, guard
from hub.fed.plugin import Param, Plugin, Verb
from hub.store import HubError

ADDR = re.compile(r"^peer:([a-z0-9_]{1,32})(?:/([a-z0-9_]{1,32})/([a-z0-9_]{1,24})(?:/([a-z0-9_]{1,32}))?)?$")
KINDS = ("note", "request", "reply", "handoff")


def parse_peer_address(addr: str):
    m = ADDR.match(addr or "")
    if not m:
        raise HubError(f"bad peer address {addr!r}: peer:<peer>[/<repo>/<role>[/<agent>]]")
    return m.group(1), m.group(2), m.group(3), m.group(4)


class Messages(Plugin):
    name = "messages"
    handles = ("message", "handoff")

    def verbs(self):
        return {"send": Verb(self.v_send, "send a message or handoff to another person's agent, role or operator", {
            "to": Param(required=True, help="peer:<peer>[/<repo>/<role>[/<agent>]]"),
            "body": Param(required=True, positional=True, help="the text"),
            "kind": Param(help="note | request | reply | handoff (default note)"),
            "ref": Param(help="a task key, card key or work id this is about"),
            "code": Param(help="a code share id to attach (handoff)")})}

    async def v_send(self, ctx, a, caller):
        return await self.send(ctx, caller, a["to"], a.get("kind") or "note", a["body"], a.get("ref"), a.get("code"))

    async def send(self, ctx, caller, to, kind, body, ref=None, code=None, work_id=None):
        if kind not in KINDS:
            raise HubError(f"federated kind must be one of {', '.join(KINDS)}")
        if ctx.commands is not None:
            result = await ctx.commands.send(caller, to, kind, body, ref, code, work_id)
            if kind == 'handoff':
                peer, repo, _, _ = parse_peer_address(to)
                rid = ctx.directory.resolve_repo(peer, repo) if repo else None
                repo = ctx.directory.local_of(rid) if rid else None
                await ctx.events.handoff_sent({'repo': repo, 'to': to, 'body': body, 'ref': ref,
                    'code': code, 'by': caller})
            return result
        peer, repo, role, agent = parse_peer_address(to)
        if peer == ctx.me:
            raise HubError("that is you; use a local address")
        sender = ctx.directory.sender_of(caller)
        rid = ctx.directory.resolve_repo(peer, repo) if repo else None
        repo = ctx.directory.local_of(rid) if rid else None
        target = {"rid": rid, "role": role, "agent": agent} if repo else None
        data = {"kind": kind, "body": body, "ref": ref, "sender": {k: v for k, v in sender.items() if k != "repo"},
                "target": target, "code": code, "work_id": work_id}
        env = envelope.make("handoff" if kind == "handoff" else "message", ctx.me, ctx.node, rid, peer, data)
        await ctx.publisher.publish(env, envelope.subject("msg", ctx.me, peer), repo, peer)
        if kind == "handoff":
            await ctx.events.handoff_sent({"repo": repo, "to": to, "body": body, "ref": ref, "code": code,
                                                   "by": caller})
        return {"id": env["id"], "to": to, "kind": kind, "queued": True}

    async def on_envelope(self, ctx, env, dec):
        if ctx.commands is not None:
            return await ctx.commands.receive(env, dec)
        d = env["data"]
        frm = env["from"]
        t = d.get("target")
        local = dec.local_repo
        if t:
            if not local:
                return "not_shared"
            if t.get("agent"):
                sess = names.session_name(local, t["role"], t["agent"])
                ag = await ctx.directory.agent(sess)
                if not ag or ag["state"] == "dead":
                    if not ctx.settings.primary:
                        return "not_hosted"         # another node of ours may host it
                    target = "virtual:operator"
                    d = {**d, "body": f"(for {sess}, which is not live here)\n{d.get('body', '')}"}
                else:
                    target = f"agent:{sess}"
            else:
                target = f"role:{local}/{t['role']}"
        else:
            if not ctx.settings.primary:
                return "not_hosted"
            target = "virtual:operator"
        kind = "handoff" if env["type"] == "handoff" else (d.get("kind") if d.get("kind") in KINDS else "note")
        # Approval releases the item; it does not raise the sender's trust - still framed as data.
        body = guard.wrap(d.get("body") or "", frm, dec.trust, dec.untrusted)
        if d.get("code"):
            body += f"\n(code attached: agentmux hub fed code fetch {d['code']})"
        sender = ctx.directory.address_of(frm, d.get("sender") or {})
        body += f"\n(reply: agentmux hub post --to {sender} --kind reply \"...\")"
        meta = {"fed": {"peer": frm, "trust": dec.trust, "env": env["id"], "untrusted": dec.untrusted}}
        try:
            posted = await ctx.messages.post(sender, target, kind, body, d.get("ref"), env["id"], meta,
                                             incoming=env, decision=dec,
                                             require_primary=target == "virtual:operator")
            if isinstance(posted, str):
                return posted
            if posted is None:
                return "not_hosted"
        except HubError as e:
            # No live holder of that role here: the operator gets it rather than nobody.
            posted = await ctx.messages.post(sender, "virtual:operator", kind, f"(for {target}: {e})\n{body}",
                                             d.get("ref"), env["id"], meta, incoming=env, decision=dec)
            if isinstance(posted, str):
                return posted
            return "to_operator"
        return "delivered"


PLUGIN = Messages()
