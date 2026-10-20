"""Restricted services for the trusted legacy Code plugin.

Private owners keep the existing Git and database implementations. These handles
limit the plugin API; they do not authenticate people or isolate Python code.
"""
from __future__ import annotations

from hub.profile_context import ProfileContext

import asyncio
import os
import time
from dataclasses import dataclass, field
from types import MappingProxyType

from hub.fed import envelope, guard
from hub.fed.policy import rid_for_remote
from hub.store import HubError, now


@dataclass(frozen=True)
class Checkout:
    repo: str
    rid: str
    path: str
    remote: str
    url: str


@dataclass(frozen=True)
class CodeSettings:
    code_remote: str


@dataclass(frozen=True)
class CodePolicy:
    _shared: object

    def rid_of(self, repo):
        return self._shared.get(repo)

    def local_of(self, rid):
        return next((repo for repo, value in self._shared.items() if value == rid), None)


@dataclass(frozen=True, repr=False, init=False)
class _CodeGitPreparation:
    def __new__(cls):
        raise TypeError('Original code Git preparation is required')


@dataclass(frozen=True)
class GitOperations:
    _owner: object = field(repr=False)
    _preparation: object = field(default=None, repr=False)

    async def _run(self, path, *args):
        from hub.fed.plugins.code import git
        worker = asyncio.get_running_loop().run_in_executor(self._owner.hub.io, git, path, *args)
        try:
            await asyncio.wait({worker})
            return worker.result()
        except asyncio.CancelledError:
            # Git may already have pushed or fetched. Keep the original worker
            # through completion rather than abandoning an uncertain effect.
            while not worker.done():
                try:
                    await asyncio.wait({worker})
                except asyncio.CancelledError:
                    continue
            if not worker.cancelled():
                worker.exception()
            raise

    def _check_policy(self, checkout, peer=None):
        f = self._owner
        if f.policy.rid_of(checkout.repo) != checkout.rid:
            raise HubError("code repository sharing changed; retry with current settings")
        if (f.fcfg.get("code_remote") or "origin") != checkout.remote:
            raise HubError("code remote changed; retry with current settings")
        if peer and peer != f.me and (f.policy.trust(peer) == "deny" or not f.policy.may_receive(checkout.rid, peer)):
            raise HubError("code share is no longer allowed by current policy")

    async def _prepare_effect(self, checkout, peer=None):
        await self._check_effect(checkout, peer)
        prepared = object.__new__(_CodeGitPreparation)
        for key, value in dict(owner=self._owner, checkout=checkout, peer=peer,
                creator=asyncio.current_task(), session=self._owner.session,
                deadline=None, binding=None, application_session=None, used=False).items():
            object.__setattr__(prepared, key, value)
        return prepared

    def _authorize_preparation(self, prepared, *, deadline, binding, application_session, effect):
        if (type(prepared) is not _CodeGitPreparation or prepared.owner is not self._owner
                or prepared.creator is not asyncio.current_task() or prepared.deadline is not None
                or type(deadline) not in (float, int) or not time.monotonic() < deadline <= time.monotonic() + 5):
            raise HubError('code Git preparation is unavailable')
        from agentmux_contracts import canonical_bytes
        object.__setattr__(prepared, 'deadline', deadline)
        object.__setattr__(prepared, 'binding', canonical_bytes(binding))
        object.__setattr__(prepared, 'application_session', application_session)
        object.__setattr__(prepared, 'effect', canonical_bytes(effect))
        return prepared

    async def _check_effect(self, checkout, peer=None, *, effect=None):
        f = self._owner
        self._check_policy(checkout, peer)
        prepared = self._preparation
        if prepared is not None:
            if (type(prepared) is not _CodeGitPreparation or prepared.owner is not f
                    or prepared.checkout != checkout or prepared.peer != peer or prepared.used
                    or prepared.deadline is None or time.monotonic() >= prepared.deadline
                    or f.session is not prepared.session or prepared.session.closing):
                raise HubError('code Git preparation is unavailable')
            from agentmux_contracts import strict_loads, canonical_bytes
            if canonical_bytes(effect) != prepared.effect:
                raise HubError('code Git effect changed')
            if f._code_commands._check_git_selection(strict_loads(prepared.binding)) is not prepared.application_session:
                raise HubError('code Git selection changed')
            object.__setattr__(prepared, 'used', True)
            return
        url = await self._run(checkout.path, "remote", "get-url", checkout.remote)
        if rid_for_remote(url) != checkout.rid:
            raise HubError("checkout remote no longer matches the shared repository")
        # The Git lookup yields; check policy again immediately before the effect.
        self._check_policy(checkout, peer)

    async def revision(self, checkout, ref):
        return await self._run(checkout.path, "rev-parse", "--verify", f"{ref}^{{commit}}")

    async def branch(self, checkout, ref):
        return await self._run(checkout.path, "rev-parse", "--abbrev-ref", ref)

    async def push(self, checkout, sha, dest):
        if not dest.startswith(f"refs/agentmux/{self._owner.me}/"):
            raise HubError("code ref is outside the local peer namespace")
        await self._check_effect(checkout, effect={'kind': 'push', 'sha': sha, 'destination': dest})
        await self._run(checkout.path, "push", "--no-verify", checkout.remote, f"+{sha}:{dest}")

    async def summary(self, checkout, sha):
        base = None
        for cand in (f"{checkout.remote}/HEAD", f"{checkout.remote}/main", f"{checkout.remote}/master"):
            try:
                base = await self._run(checkout.path, "merge-base", sha, cand)
                break
            except HubError:
                continue
        rng = f"{base}..{sha}" if base else f"{sha}~1..{sha}"
        files, stat, log = [], "", ""
        try:
            files = (await self._run(checkout.path, "diff", "--name-only", rng)).splitlines()[:200]
            stat = await self._run(checkout.path, "diff", "--shortstat", rng)
            log = "\n".join((await self._run(checkout.path, "log", "--oneline", rng)).splitlines()[:20])
        except HubError:
            pass
        return base, files, stat, log

    async def fetch_verified(self, checkout, share):
        if not share["ref"].startswith(f"refs/agentmux/{share['from_peer']}/"):
            raise HubError("code ref is outside the sharing peer namespace")
        await self._check_effect(checkout, share["from_peer"], effect={'kind': 'fetch', 'share': share})
        await self._run(checkout.path, "fetch", "--no-tags", checkout.remote, f"+{share['ref']}:{share['ref']}")
        got = await self._run(checkout.path, "rev-parse", "--verify", share["ref"])
        if got != share["sha"]:
            raise HubError(f"sha mismatch for {share['ref']}: announced {share['sha'][:12]}, fetched {got[:12]} - "
                           f"the ref moved; ask {share['from_peer']} to share again")
        return got


@dataclass(frozen=True)
class RepositoryDirectory:
    _owner: object = field(repr=False)
    _git: GitOperations
    _settings: CodeSettings

    def sender(self, caller):
        return dict(self._owner.sender_of(caller))

    def resolve_repo(self, peer, repo):
        return self._owner.resolve_repo(peer, repo)

    async def checkout(self, repo, path, rid):
        f = self._owner
        cands = [path] if path else []
        cands += [r["path"] for r in await f.db(f.store.q, "SELECT path FROM repo_paths WHERE repo=?", (repo,))]
        remote = self._settings.code_remote
        for path in cands:
            if not path or not os.path.isdir(path):
                continue
            try:
                top = await self._git._run(path, "rev-parse", "--show-toplevel")
                url = await self._git._run(top, "remote", "get-url", remote)
            except HubError:
                continue
            if rid_for_remote(url) == rid:
                return Checkout(repo, rid, top, remote, url)
        raise HubError(f"no checkout of {repo} whose '{remote}' remote matches the shared repo "
                       "(pass --path, or set code_remote in federation.toml)")


@dataclass(frozen=True)
class CodeShareOwner:
    _owner: object = field(repr=False)

    def _store(self, env, repo, untrusted):
        d = env["data"]
        self._owner.store.db.execute(
            "INSERT OR IGNORE INTO p_code_shares (id, rid, repo, from_peer, author, ref, sha, base, files, stat, log, "
            "note, untrusted, at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (env["id"], env["rid"], repo, env["from"], d.get("author"), d["ref"], d["sha"], d.get("base"),
             "\n".join(d.get("files") or []), d.get("stat"), d.get("log"), d.get("note"), int(untrusted), env.get("at") or now()))

    async def publish(self, env, repo):
        f = self._owner
        def tx():
            with f.store.tx():
                if f.policy.rid_of(repo) != env["rid"]:
                    raise HubError("code repository sharing changed; retry")
                clean, _ = f.stage(env, envelope.subject("code", f.me, env["rid"]), repo, "*")
                self._store(clean, repo, False)
        await f.db(tx)

    async def receive(self, env, decision):
        f = self._owner
        def tx():
            with f.store.tx():
                current = guard.inbound(f.policy, envelope.subject("code", env["from"], env["rid"]), env)
                if (current.action == "drop"
                        or current.local_repo != decision.local_repo
                        or (current.action == "quarantine" and not decision.approved)):
                    return "dropped"
                # Rechecking admission must not rewrite the runtime's approved
                # decision or remove its original untrusted-data framing.
                self._store(env, decision.local_repo, decision.untrusted)
                return "delivered"
        return await f.db(tx)

    async def get(self, share_id):
        f = self._owner
        return await f.db(f.store.q1, "SELECT * FROM p_code_shares WHERE id=?", (share_id,))

    async def mark_fetched(self, share_id):
        f = self._owner
        def tx():
            with f.store.tx():
                f.store.db.execute("UPDATE p_code_shares SET fetched=? WHERE id=?", (now(), share_id))
        await f.db(tx)

    async def list(self, repo):
        f = self._owner
        return await f.db(f.store.q, "SELECT id, repo, from_peer, author, ref, substr(sha,1,12) sha, stat, note, "
                          "fetched, at FROM p_code_shares WHERE (? IS NULL OR repo=?) ORDER BY at DESC LIMIT 50", (repo, repo))

    def panel_rows(self):
        return self._owner.store.q("SELECT id, repo, from_peer, author, ref, sha, stat, note, fetched, at FROM p_code_shares "
                                   "ORDER BY at DESC LIMIT 20")


@dataclass(frozen=True)
class FederatedMessages:
    _owner: object = field(repr=False)

    async def send_handoff(self, caller, to, body, share_id):
        from hub.fed.message_services import build_message_context
        return await self._owner.plugins["messages"].send(build_message_context(self._owner), caller, to,
                                                          "handoff", body, None, share_id)


@dataclass(frozen=True)
class QualifiedCodeOwner:
    _owner: object = field(repr=False)
    qualified = True

    async def share(self, context, arguments, caller):
        return await self._owner._code_commands.share(context, arguments, caller)

    async def fetch(self, context, arguments, caller):
        return await self._owner._code_commands.fetch(context, arguments, caller)

    async def list(self, arguments, caller):
        return await self._owner._code_commands.read(caller, 'list', arguments)

    async def receive(self, item, decision):
        return await self._owner._code_commands.receive(item, decision)

    def panel_rows(self):
        raise HubError('qualified code panel requires its authenticated owner route')


@dataclass(frozen=True)
class CodeContext:
    me: str
    node: str
    settings: CodeSettings
    policy: CodePolicy
    repositories: RepositoryDirectory
    git: GitOperations
    shares: CodeShareOwner | QualifiedCodeOwner
    messages: FederatedMessages
    profile_context: ProfileContext | None = None


def build_code_context(federation):
    settings = CodeSettings(federation.fcfg.get("code_remote") or "origin")
    git = GitOperations(federation)
    return CodeContext(federation.me, federation.node, settings,
                       CodePolicy(MappingProxyType(dict(federation.policy.shared()))),
                       RepositoryDirectory(federation, git, settings), git,
                       (QualifiedCodeOwner(federation) if getattr(federation, '_qualified_code', False)
                        else CodeShareOwner(federation)), FederatedMessages(federation))
