"""board: the shared central board for shared repos (FEDERATION.md 9.6, assumptions A9/A10/A17).

Cards live in the JetStream KV bucket am_board under <rid>.card.<KEY>; keys are minted
from <rid>.seq.<PREFIX> by compare-and-set, and every change is a CAS on the card's
revision (re-read, re-apply, retry). Every hub watches the bucket and mirrors the cards
of the repos it shares into p_board_cards, so reads are local and work offline; writes
need the connection.
"""
from __future__ import annotations

from hub.profile_context import ProfileContext

import asyncio
from dataclasses import dataclass, field
from typing import Any
import json
import os
import urllib.request

from hub.fed import redact
from hub.fed.plugins.messages import parse_peer_address
from hub.store import HubError, now

STATUSES = ("todo", "doing", "review", "done", "blocked")
BUCKET = "am_board"
RETRIES = 3


class Conflict(HubError):
    pass


@dataclass(frozen=True, slots=True)
class PreparedBoardChange:
    """Frozen domain candidate; preparation cannot authorize or publish it."""
    value: bytes = field(repr=False)
    kinds: tuple[str, ...]
    what: str

    @property
    def card(self):
        return json.loads(self.value)


@dataclass(frozen=True, slots=True)
class PreparedBoardAddInput:
    """Resolved add input; local source lookup happens once before allocation."""
    value: bytes = field(repr=False)

    @property
    def fields(self):
        return json.loads(self.value)


def _validate_board_change(change):
    shapes = {"move": {"command", "status"}, "assign": {"command", "to"},
              "comment": {"command", "text"}, "claim": {"command"}}
    if (type(change) is not dict or type(change.get("command")) is not str
            or change["command"] not in shapes or set(change) != shapes[change["command"]]):
        raise HubError("unsupported shared board change")
    if change["command"] == "move" and change["status"] not in STATUSES:
        raise HubError(f"status must be one of {', '.join(STATUSES)}")
    if change["command"] == "assign":
        parse_peer_address(change["to"])
    if change["command"] == "comment" and type(change["text"]) is not str:
        raise HubError("shared board comment needs text")


class _BoardOperations:
    # -- helpers ---------------------------------------------------------------------------
    def _me(self, ctx, caller):
        s = ctx.sender_of(caller)
        if s.get("operator"):
            return f"peer:{ctx.me}"
        return f"peer:{ctx.me}/{s['repo']}/{s['role']}/{s['agent']}"

    async def _resolve(self, ctx, key, repo=None):
        if repo:
            rid = ctx.policy.rid_of(repo)
            if not rid:
                raise HubError(f"repo {repo!r} is not shared")
            return rid, repo
        rows = await ctx.db(ctx.store.q, "SELECT rid, repo FROM p_board_cards WHERE key=? AND deleted=0", (key,))
        rows = [r for r in rows if ctx.policy.local_of(r["rid"])]
        if not rows:
            raise HubError(f"no shared card {key} (agentmux hub fed board list)")
        if len(rows) > 1:
            raise HubError(f"{key} exists in several shared repos; pass --repo")
        return rows[0]["rid"], ctx.policy.local_of(rows[0]["rid"])

    def _clean(self, ctx, card, rid):
        try:
            clean, kinds = redact.scrub(card)
        except redact.Blocked as e:
            from hub.fed import guard
            err = guard.Refused(str(e), "blocked", e.kinds)
            err.audit = ("out", "board", "*", rid, f"$KV.{BUCKET}", card.get("key"), card)
            raise err from None
        return clean, kinds

    def prepare_change(self, ctx, rid, card, change, *, by, at):
        """Freeze exact bytes with explicit attribution/time before any dispatch.

        The trusted caller supplies attribution after authenticating the actor.
        This method performs domain validation/redaction only, never admission.
        """
        _validate_board_change(change)
        candidate = json.loads(json.dumps(card))
        command = change["command"]
        if command == "move":
            candidate["status"] = change["status"]
            what = f"status -> {change['status']}"
        elif command == "assign":
            candidate["assignee"] = change["to"]
            what = f"assigned -> {change['to']}"
        elif command == "comment":
            candidate.setdefault("comments", []).append({"by": by, "at": at, "text": change["text"]})
            what = "comment"
        else:
            if candidate.get("assignee") and candidate["assignee"] != by and candidate.get("status") == "doing":
                raise HubError(f"{candidate['key']} is already being done by {candidate['assignee']}")
            candidate["assignee"], candidate["status"] = by, "doing"
            what = f"claimed by {by}"
        candidate["updated_by"], candidate["updated_at"] = by, at
        candidate.setdefault("history", []).append({"by": by, "at": at, "what": what})
        candidate["history"] = candidate["history"][-50:]
        clean, kinds = self._clean(ctx, candidate, rid)
        return PreparedBoardChange(json.dumps(clean).encode(), tuple(kinds), what)

    def prepare_add_input(self, a):
        title, body, link = a.get("title"), a.get("body") or "", None
        if a.get("from"):
            src = _local_card(a["from"])
            title = title or src.get("title")
            body = body or src.get("body") or src.get("description") or ""
            link = a["from"]
        if not title:
            raise HubError("board add needs --title (or --from TM-x)")
        if a.get("assign"):
            parse_peer_address(a["assign"])
        return PreparedBoardAddInput(json.dumps({"title":title,"body":body,"link":link,
            "assignee":a.get("assign"),"labels":list(a.get("labels") or [])}).encode())

    def prepare_add(self, ctx, rid, key, prepared, *, by, at, operation_marker=None):
        fields=prepared.fields
        link=fields["link"]
        card={"key":key,"rid":rid,"title":fields["title"],"body":fields["body"],"status":"todo",
            "assignee":fields["assignee"],"labels":fields["labels"],"comments":[],
            "history":[{"by":by,"at":at,"what":"created"+(f" from {link}" if link else "")}],
            "created_by":by,"created_at":at,"updated_by":by,"updated_at":at,
            "links":{"local":link} if link else {}}
        if operation_marker is not None:
            card["_agentmuxOperation"]=json.loads(json.dumps(operation_marker))
        clean,kinds=self._clean(ctx,card,rid)
        return PreparedBoardChange(json.dumps(clean).encode(),tuple(kinds),"created")

    async def _write(self, ctx, rid, key, change, caller):
        """CAS loop: read, mutate, update(last=rev); on a lost race re-read and re-apply."""
        import nats.js.errors as jse
        kv = await _board_store(ctx, rid)
        k = f"{rid}.card.{key}"
        for attempt in range(RETRIES):
            try:
                e = await kv.get(k)
            except jse.KeyNotFoundError:
                raise HubError(f"no shared card {key}") from None
            prepared = self.prepare_change(ctx, rid, json.loads(e.value), change,
                                           by=self._me(ctx, caller), at=now())
            clean = prepared.card
            try:
                rev = await kv.update(k, prepared.value, last=e.revision)
            except jse.KeyWrongLastSequenceError:
                await asyncio.sleep(0.05 * (attempt + 1))
                continue
            await self._audit_out(ctx, rid, k, clean, prepared.kinds, prepared.what)
            await ctx.db(self._mirror, ctx, rid, key, clean, rev)
            return {**clean, "rev": rev, "attempts": attempt + 1}
        raise Conflict(f"{key}: lost {RETRIES} compare-and-set races in a row; re-read and try again")

    async def _audit_out(self, ctx, rid, k, card, kinds, what):
        await FederationAudit(ctx).written(rid, k, card, kinds, what)

    def _mirror(self, ctx, rid, key, card, rev, deleted=False):
        with ctx.store.tx():
            if not ctx.policy.local_of(rid):
                return False
            writer = (card.get("updated_by") or "peer:?").split(":", 1)[1].split("/")[0]
            if writer != ctx.me and ctx.policy.trust(writer) == "deny":
                return False
            ctx.store.db.execute(
                "INSERT INTO p_board_cards (rid, key, repo, card, rev, status, assignee, updated_by, updated_at, deleted) "
                "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (rid, key) DO UPDATE SET repo=excluded.repo, card=excluded.card, "
                "rev=excluded.rev, status=excluded.status, assignee=excluded.assignee, updated_by=excluded.updated_by, "
                "updated_at=excluded.updated_at, deleted=excluded.deleted WHERE excluded.rev >= p_board_cards.rev",
                (rid, key, ctx.policy.local_of(rid), json.dumps(card), rev, card.get("status"), card.get("assignee"),
                 card.get("updated_by"), card.get("updated_at"), int(deleted)))
            return True

    # -- verbs -----------------------------------------------------------------------------
    async def v_add(self, ctx, a, caller):
        import nats.js.errors as jse
        repo = a["repo"]
        rid = ctx.policy.rid_of(repo)
        if not rid:
            raise HubError(f"repo {repo!r} is not shared (agentmux hub fed share {repo})")
        prepared_input=self.prepare_add_input(a)
        kv = await _board_store(ctx, rid)
        prefix = ctx.policy.board_prefix(repo)
        seqk = f"{rid}.seq.{prefix}"
        for _ in range(10):                       # mint: CAS on the counter
            try:
                e = await kv.get(seqk)
                n = int(e.value) + 1
                await kv.update(seqk, str(n).encode(), last=e.revision)
                break
            except jse.KeyNotFoundError:
                try:
                    await kv.create(seqk, b"1")
                    n = 1
                    break
                except jse.KeyWrongLastSequenceError:
                    continue
            except jse.KeyWrongLastSequenceError:
                continue
        else:
            raise Conflict("could not mint a card key after 10 races")
        key = f"{prefix}-{n}"
        prepared=self.prepare_add(ctx,rid,key,prepared_input,by=self._me(ctx,caller),at=now())
        clean=prepared.card
        rev = await kv.create(f"{rid}.card.{key}", prepared.value)
        await self._audit_out(ctx, rid, f"{rid}.card.{key}", clean, prepared.kinds, prepared.what)
        await ctx.db(self._mirror, ctx, rid, key, clean, rev)
        return {**clean, "rev": rev}

    async def v_list(self, ctx, a, caller):
        rows = await ctx.db(ctx.store.q, "SELECT rid, key, repo, card, rev FROM p_board_cards WHERE deleted=0 "
                            "ORDER BY updated_at DESC")
        out = []
        for r in rows:
            local = ctx.policy.local_of(r["rid"])
            if not local or (a.get("repo") and a["repo"] != local):
                continue
            c = json.loads(r["card"])
            if a.get("status") and c.get("status") != a["status"]:
                continue
            out.append({"key": c["key"], "repo": local, "status": c.get("status"), "title": c.get("title"),
                        "assignee": c.get("assignee"), "updated_by": c.get("updated_by"),
                        "comments": len(c.get("comments", [])), "rev": r["rev"], "withdrawn": c.get("withdrawn")})
        return out

    async def v_show(self, ctx, a, caller):
        rid, repo = await self._resolve(ctx, a["key"], a.get("repo"))
        r = await ctx.db(ctx.store.q1, "SELECT card, rev FROM p_board_cards WHERE rid=? AND key=?", (rid, a["key"]))
        return {**json.loads(r["card"]), "repo": repo, "rev": r["rev"]}

    async def v_move(self, ctx, a, caller):
        change = {"command": "move", "status": a["status"]}
        _validate_board_change(change)
        rid, _ = await self._resolve(ctx, a["key"], a.get("repo"))
        return await self._write(ctx, rid, a["key"], change, caller)

    async def v_assign(self, ctx, a, caller):
        change = {"command": "assign", "to": a["to"]}
        _validate_board_change(change)
        rid, _ = await self._resolve(ctx, a["key"], a.get("repo"))
        return await self._write(ctx, rid, a["key"], change, caller)

    async def v_comment(self, ctx, a, caller):
        rid, _ = await self._resolve(ctx, a["key"], a.get("repo"))
        return await self._write(ctx, rid, a["key"], {"command": "comment", "text": a["text"]}, caller)

    async def v_claim(self, ctx, a, caller):
        rid, _ = await self._resolve(ctx, a["key"], a.get("repo"))
        return await self._write(ctx, rid, a["key"], {"command": "claim"}, caller)

    # -- the watcher -----------------------------------------------------------------------
    async def on_connect(self, ctx):
        session = ctx.session
        session.check_open()
        session.start_task("board", self._watch(ctx, session, ctx.js))

    async def _watch(self, ctx, session, js):
        import nats.errors
        kv = await js.key_value(BUCKET)
        w = await session.acquire(kv.watch("*.card.*"), session.own_watcher)
        while True:
            try:
                e = await w.updates(timeout=5)
            except (nats.errors.TimeoutError, asyncio.TimeoutError):
                continue
            except (nats.errors.ConnectionClosedError, asyncio.CancelledError):
                return
            if e is None:
                continue
            try:
                await self._on_entry(ctx, e)
            except Exception as ex:  # noqa: BLE001 - one bad card must not stop the mirror
                ctx.log("fed: board mirror error", type(ex).__name__, ex)

    async def _on_entry(self, ctx, e):
        rid, _, key = e.key.split(".", 2)
        if not ctx.policy.local_of(rid):
            return
        if e.operation in ("DEL", "PURGE"):
            def remove():
                with ctx.store.tx():
                    if ctx.policy.local_of(rid):
                        ctx.store.db.execute("UPDATE p_board_cards SET deleted=1 WHERE rid=? AND key=?", (rid, key))
            await ctx.db(remove)
            return
        card = json.loads(e.value)
        writer = (card.get("updated_by") or "peer:?").split(":", 1)[1].split("/")[0]
        if writer != ctx.me and ctx.policy.trust(writer) == "deny":
            return
        prev = await ctx.db(ctx.store.q1, "SELECT assignee, rev FROM p_board_cards WHERE rid=? AND key=?", (rid, key))
        if prev and prev["rev"] >= e.revision:
            return
        if not await ctx.db(self._mirror, ctx, rid, key, card, e.revision):
            return
        if writer != ctx.me:
            from hub.fed import ledger

            def tx():
                with ctx.store.tx():
                    ledger.audit(ctx.store, "in", "board", writer, rid, f"$KV.{BUCKET}.{e.key}", key, card, "mirrored",
                                 {"rev": e.revision, "what": (card.get("history") or [{}])[-1].get("what")})
            await ctx.db(tx)
        a = card.get("assignee") or ""
        if a and a != (prev or {}).get("assignee") and writer != ctx.me and a.startswith(f"peer:{ctx.me}"):
            await self._notify_assignee(ctx, rid, card, writer)

    async def _notify_assignee(self, ctx, rid, card, writer):
        peer, _repo, role, agent = parse_peer_address(card["assignee"])
        local = ctx.policy.local_of(rid)      # the card's rid, in OUR naming - whoever wrote the address
        if agent:
            target = f"agent:{local}-{role}-{agent}"
        elif role:
            target = f"role:{local}/{role}"
        else:
            target = "virtual:operator"
        body = (f"[fed] shared card {card['key']} ({local}) was assigned to you by {writer}: {card.get('title')}\n"
                f"  agentmux hub fed board show {card['key']}    agentmux hub fed board claim {card['key']}")
        async def post(target):
            selected, bindings = target, ()
            hub = getattr(ctx, 'hub', None)
            if hub is not None and getattr(hub, '_legacy_identity', None) is not None:
                try:
                    selected, bindings = await hub._current_identity_target(target)
                except HubError:
                    return None
            def effect():
                if (not local or ctx.policy.local_of(rid) != local or
                        (writer != ctx.me and ctx.policy.trust(writer) == "deny")):
                    return None
                return ctx.store.post(f"peer:{writer}", selected, "note", body, card["key"], None,
                    f"board:{rid}:{card['key']}:{card.get('updated_at')}", identity_bindings=bindings)
            try:
                return await ctx.db(effect)
            except HubError as error:
                ctx.log("fed: local post failed", target, error)
                return None
        r = await post(target)
        if r is None and target != "virtual:operator":
            await post("virtual:operator")

    async def on_revoke(self, ctx, peer):
        def mark():
            with ctx.store.tx():
                for r in ctx.store.q("SELECT rid, key, card FROM p_board_cards WHERE card LIKE ?", (f'%"peer:{peer}%',)):
                    c = json.loads(r["card"])
                    if (c.get("created_by") or "").startswith(f"peer:{peer}"):
                        c["withdrawn"] = f"{peer} revoked its shares"
                        ctx.store.db.execute("UPDATE p_board_cards SET card=? WHERE rid=? AND key=?",
                                             (json.dumps(c), r["rid"], r["key"]))
        await ctx.db(mark)

    def panel(self, ctx):
        rows = ctx.store.q("SELECT rid, card FROM p_board_cards WHERE deleted=0 ORDER BY updated_at DESC LIMIT 100")
        out = []
        for r in rows:
            local = ctx.policy.local_of(r["rid"])
            if not local:
                continue
            c = json.loads(r["card"])
            out.append([c["key"], local, c.get("status"), c.get("title"), c.get("assignee") or "",
                        c.get("updated_by") or "", len(c.get("comments", []))])
        return {"title": "Shared board", "columns": ["key", "repo", "status", "title", "assignee", "updated by",
                                                      "comments"], "rows": out, "group_by": 2,
                "actions": [{"verb": "fed_board_move", "label": "move", "params": ["key", "status"]}]}


def _local_card(key):
    url = os.environ.get("AGENTMUX_DASHBOARD", "http://127.0.0.1:8787")
    try:
        with urllib.request.urlopen(f"{url}/api/board/entity?id={key}", timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        raise HubError(f"cannot read local card {key} from the dashboard at {url} ({e})") from None




@dataclass(frozen=True, slots=True)
class FederationAudit:
    """Board audit writes retain the same ledger and metadata contract."""
    _owner: Any = field(repr=False)

    async def written(self, rid, key, card, kinds, what):
        from hub.fed import ledger
        ctx = self._owner
        def tx():
            with ctx.store.tx():
                ledger.audit(ctx.store, "out", "board", "*", rid, f"$KV.{BUCKET}.{key}", card.get("key"), card,
                             "redacted" if kinds else "written", {"what": what, "kinds": sorted(set(kinds))})
        await ctx.db(tx)


class _ScopedBoardKV:
    """Private board-store handle; every request rechecks the same repository."""
    def __init__(self, owner, kv, rid, repo):
        self._owner, self._kv, self._rid, self._repo = owner, kv, rid, repo

    def _check(self, key):
        if (self._owner.policy.rid_of(self._repo) != self._rid or
                not (key.startswith(f"{self._rid}.card.") or key.startswith(f"{self._rid}.seq."))):
            raise HubError("repo sharing changed before the shared board operation")

    async def get(self, key):
        self._check(key)
        return await self._kv.get(key)

    async def create(self, key, value):
        self._check(key)
        return await self._kv.create(key, value)

    async def update(self, key, value, last):
        self._check(key)
        return await self._kv.update(key, value, last=last)


async def _board_store(owner, rid):
    repo = owner.policy.local_of(rid)
    if not repo:
        raise HubError("repo is no longer shared")
    kv = await owner.kv(BUCKET)
    return _ScopedBoardKV(owner, kv, rid, repo)


@dataclass(frozen=True, slots=True)
class SharedBoardStore:
    """Expose board commands, never the shared bucket or a mutation callback."""
    _owner: Any = field(repr=False)
    _operations: Any = field(default_factory=_BoardOperations, repr=False)

    async def add(self, args, caller):
        return await self._operations.v_add(self._owner, args, caller)

    async def move(self, args, caller):
        return await self._operations.v_move(self._owner, args, caller)

    async def assign(self, args, caller):
        return await self._operations.v_assign(self._owner, args, caller)

    async def comment(self, args, caller):
        return await self._operations.v_comment(self._owner, args, caller)

    async def claim(self, args, caller):
        return await self._operations.v_claim(self._owner, args, caller)


@dataclass(frozen=True, slots=True)
class BoardProjection:
    """Own the local mirror and its connection-scoped watcher."""
    _owner: Any = field(repr=False)
    _operations: Any = field(default_factory=_BoardOperations, repr=False)
    _session: Any = field(init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "_session", getattr(self._owner, "session", None))

    async def connect(self):
        if self._session is None or self._owner.session is not self._session:
            raise HubError("federation board context is stale")
        return await self._operations.on_connect(self._owner)

    async def list(self, args, caller):
        return await self._operations.v_list(self._owner, args, caller)

    async def show(self, args, caller):
        return await self._operations.v_show(self._owner, args, caller)

    async def revoke(self, peer):
        return await self._operations.on_revoke(self._owner, peer)

    def panel(self):
        return self._operations.panel(self._owner)


@dataclass(frozen=True, slots=True)
class BoardContext:
    board: Any
    projection: BoardProjection
    profile_context: ProfileContext | None = None


def build_board_context(federation):
    if getattr(federation, '_qualified_board', False):
        from capability_owner.legacy_board_service import LegacyBoardCommandClient
        client = getattr(federation, '_board_commands', None)
        if type(client) is not LegacyBoardCommandClient:
            raise HubError('qualified board owner route is required')
        client.bind(federation)
        return BoardContext(client, BoardProjection(federation))
    return BoardContext(SharedBoardStore(federation), BoardProjection(federation))
