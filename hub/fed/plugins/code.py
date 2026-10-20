"""code: share work in progress as git refs (FEDERATION.md 9.5) - a Claim Check.

The payload stays in git: `code share` pushes a commit to the repo's shared remote as
refs/agentmux/<peer>/<slug> and publishes only the pointer (ref, sha, base, files,
stat, log) to am.code.<me>.<rid>. `code fetch` brings the ref into the receiver's
checkout under the same name and verifies the sha before saying it worked.
"""
from __future__ import annotations

import os
import re
import subprocess

from hub.fed import envelope
from hub.fed.plugin import Param, Plugin, Verb
from hub.fed.policy import normalize_remote
from hub.store import HubError


def git(path, *args, timeout=60):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    r = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True, timeout=timeout, env=env,
                       stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        raise HubError(f"git {' '.join(args[:2])} failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout.strip()


def slugify(s):
    return re.sub(r"[^a-z0-9_]+", "_", (s or "wip").lower()).strip("_")[:40] or "wip"


class Code(Plugin):
    name = "code"
    handles = ("code",)
    tables = [
        "CREATE TABLE IF NOT EXISTS p_code_shares (id TEXT PRIMARY KEY, rid TEXT NOT NULL, repo TEXT, "
        "from_peer TEXT NOT NULL, author TEXT, ref TEXT NOT NULL, sha TEXT NOT NULL, base TEXT, files TEXT, "
        "stat TEXT, log TEXT, note TEXT, untrusted INTEGER NOT NULL DEFAULT 0, fetched TEXT, at TEXT NOT NULL) STRICT",
    ]

    def verbs(self):
        P = Param
        return {
            "share": Verb(self.v_share, "push a commit to the shared remote as refs/agentmux/<you>/<slug> and "
                                        "tell the circle (optionally hand it to someone)", {
                "repo": P(help="local repo (default: yours)"), "ref": P(help="commit-ish (default HEAD)"),
                "note": P(positional=True, help="what it is and what you want done"),
                "to": P(help="peer:<peer>[/<repo>/<role>[/<agent>]] - also send a handoff message"),
                "slug": P(help="name for the ref (default: branch name)"),
                "path": P(help="checkout to push from (default: the caller's cwd)"),
                "operation_id": P(help="reuse the original operation ID when recovering a lost response")}),
            "fetch": Verb(self.v_fetch, "fetch a shared ref into your checkout and verify its sha", {
                "id": P(required=True, positional=True), "path": P(help="checkout (default: the caller's cwd)"),
                "operation_id": P(help="reuse the original operation ID when recovering a lost response")}),
            "list": Verb(self.v_list, "code shared with you", {"repo": P()}),
        }

    async def v_share(self, ctx, a, caller):
        if getattr(ctx.shares, 'qualified', False):
            return await ctx.shares.share(ctx, a, caller)
        s = ctx.repositories.sender(caller)
        repo = a.get("repo") or s.get("repo")
        if not repo:
            raise HubError("code share needs --repo")
        rid = ctx.policy.rid_of(repo)
        if not rid:
            raise HubError(f"repo {repo!r} is not shared (agentmux hub fed share {repo})")
        if a.get("to"):
            # Validate the handoff address BEFORE pushing and publishing: a bad address used
            # to leave one published share per retry (live demo, 2026-10-07).
            from hub.fed.plugins.messages import parse_peer_address
            tpeer, trepo, _, _ = parse_peer_address(a["to"])
            if trepo:
                ctx.repositories.resolve_repo(tpeer, trepo)
        checkout = await ctx.repositories.checkout(repo, a.get("path") or a.get("cwd"), rid)
        ref = a.get("ref") or "HEAD"
        sha = await ctx.git.revision(checkout, ref)
        branch = await ctx.git.branch(checkout, ref) if ref == "HEAD" else ref
        slug = f"{slugify(a.get('slug') or branch)}_{sha[:8]}"
        dest = f"refs/agentmux/{ctx.me}/{slug}"
        await ctx.git.push(checkout, sha, dest)
        base, files, stat, log = await ctx.git.summary(checkout, sha)
        author = "operator" if s.get("operator") else f"{s['role']}/{s['agent']}"
        data = {"ref": dest, "sha": sha, "base": base, "files": files, "stat": stat, "log": log,
                "note": a.get("note") or "", "slug": slug, "author": author, "remote": normalize_remote(checkout.url)}
        env = envelope.make("code", ctx.me, ctx.node, rid, "*", data)

        await ctx.shares.publish(env, repo)
        out = {"id": env["id"], "ref": dest, "sha": sha, "files": len(files), "stat": stat}
        if a.get("to"):
            out["handoff"] = await ctx.messages.send_handoff(
                caller, a["to"], (a.get("note") or f"code {slug}") + f"\n{stat}", env["id"])
        return out

    async def on_envelope(self, ctx, env, dec):
        d = env["data"]
        if not re.fullmatch(r"[0-9a-f]{40}", d.get("sha", "")) or not str(d.get("ref", "")).startswith(
                f"refs/agentmux/{env['from']}/"):
            return "dropped"            # a peer may only point at its own namespace

        return await ctx.shares.receive(env, dec)

    async def v_fetch(self, ctx, a, caller):
        if getattr(ctx.shares, 'qualified', False):
            return await ctx.shares.fetch(ctx, a, caller)
        r = await ctx.shares.get(a["id"])
        if not r:
            raise HubError(f"no code share {a['id']} (agentmux hub fed code list)")
        repo = r["repo"] or ctx.policy.local_of(r["rid"])
        checkout = await ctx.repositories.checkout(repo, a.get("path") or a.get("cwd"), r["rid"])
        got = await ctx.git.fetch_verified(checkout, r)
        await ctx.shares.mark_fetched(a["id"])
        top = checkout.path
        return {"ref": r["ref"], "sha": got, "checkout": top, "verified": True, "files": r["files"].split("\n"),
                "next": [f"git -C {top} diff {r['base'] or r['sha'] + '~1'}..{r['ref']}",
                         f"git -C {top} switch -c {r['ref'].split('/')[-1]} {r['ref']}"]}

    async def v_list(self, ctx, a, caller):
        if getattr(ctx.shares, 'qualified', False):
            return await ctx.shares.list(a, caller)
        return await ctx.shares.list(a.get("repo"))

    def panel(self, ctx):
        rows = ctx.shares.panel_rows()
        return {"title": "Code", "columns": ["at", "from", "ref", "sha", "stat", "note", "fetched"],
                "rows": [[r["at"][:19], f"{r['from_peer']} {r['author'] or ''}", r["ref"], r["sha"][:10], r["stat"],
                          (r["note"] or "")[:60], "yes" if r["fetched"] else ""] for r in rows],
                "actions": [{"verb": "fed_code_fetch", "label": "fetch", "params": ["id"]}]}


PLUGIN = Code()
