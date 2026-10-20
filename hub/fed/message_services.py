"""Named legacy message services; private owners retain existing transactions.

These interfaces narrow plugin dependencies. Administrator-installed Python remains
trusted code; private attributes are not an execution sandbox or identity proof.
"""
from __future__ import annotations

from hub.profile_context import ProfileContext

from dataclasses import dataclass, field
from typing import Any

from hub.fed import envelope
from hub.store import HubError


@dataclass(frozen=True, slots=True)
class AgentDirectory:
    _owner: Any = field(repr=False)

    def sender_of(self, caller):
        return self._owner.sender_of(caller)

    def resolve_repo(self, peer, name):
        return self._owner.resolve_repo(peer, name)

    def local_of(self, rid):
        return self._owner.policy.local_of(rid)

    def address_of(self, peer, sender):
        return self._owner.address_of(peer, sender)

    async def agent(self, session):
        return await self._owner.db(self._owner.store.agent, session)


@dataclass(frozen=True, slots=True)
class LocalMessages:
    _owner: Any = field(repr=False)

    async def post(self, sender, target, kind, body, ref, envelope_id, meta, *, incoming, decision, require_primary=False):
        # Preserve the store's durable deduplication and propagate HubError so the
        # plugin can retain its existing operator fallback.
        selected, bindings = target, ()
        hub = getattr(self._owner, 'hub', None)
        if hub is not None and getattr(hub, '_legacy_identity', None) is not None:
            selected, bindings = await hub._current_identity_target(target)

        return await self._owner.db(self._deliver, sender, selected, kind, body, ref, envelope_id, meta,
            incoming=incoming, decision=decision, require_primary=require_primary, identity_bindings=bindings)

    def _deliver(self, sender, target, kind, body, ref, envelope_id, meta, *, incoming, decision,
                 require_primary=False, identity_bindings=()):
        """DB-thread delivery shared with the signed storage owner."""
        peer, rid, local_repo = incoming["from"], incoming.get("rid"), decision.local_repo
        policy = self._owner.policy
        # Approval cannot bypass a later denial or withdrawn repository sharing.
        if not policy.known_peer(peer) or policy.trust(peer) == "deny":
            return "denied"
        if rid and (not policy.may_receive(rid, peer) or policy.local_of(rid) != local_repo):
            return "not_shared"
        if require_primary and not self._owner.fcfg.get("primary", True):
            return None
        return self._owner.store.post(sender, target, kind, body, ref, None,
            f"fed:{envelope_id}", meta=meta, identity_bindings=identity_bindings)



@dataclass(frozen=True, slots=True)
class FederationPublisher:
    _owner: Any = field(repr=False)

    async def publish(self, env, subject, local_repo, peer):
        if (env.get("type") not in ("message", "handoff")
                or env.get("from") != self._owner.me or env.get("to") != peer
                or subject != envelope.subject("msg", self._owner.me, peer)):
            raise HubError("message service only publishes messages and handoffs on its own route")
        if env.get("rid") != (self._owner.policy.rid_of(local_repo) if local_repo else None):
            raise HubError("message repository must match its local shared repository")
        envelope.validate_route(subject, env)
        # The owner rechecks current policy and commits outbox plus audit together.
        return await self._owner.publish(env, subject, local_repo, peer)


@dataclass(frozen=True, slots=True)
class LocalEvents:
    _owner: Any = field(repr=False)

    async def handoff_sent(self, data):
        if (getattr(self._owner, '_qualified_knowledge', False) and self._owner.fcfg.get('capture', True)):
            source = self._owner._message_commands.take_publication_source()
            with self._owner._knowledge_intents.handoff_source(source):
                return await self._owner.local_event('handoff_sent', data)
        return await self._owner.local_event("handoff_sent", data)


@dataclass(frozen=True, slots=True)
class MessageSettings:
    primary: bool


@dataclass(frozen=True, slots=True)
class MessageContext:
    me: str
    node: str
    settings: MessageSettings
    directory: AgentDirectory
    messages: LocalMessages
    publisher: FederationPublisher
    events: LocalEvents
    profile_context: ProfileContext | None = None
    commands: Any = field(default=None, repr=False)


def build_message_context(federation):
    """Build a fresh settings snapshot at each runtime or direct caller boundary."""
    commands = None
    if getattr(federation, '_qualified_messages', False):
        from capability_owner.legacy_messages_client import LegacyMessageCommandClient
        from agentmux_contracts import ContractError
        commands = getattr(federation, '_message_commands', None)
        if type(commands) is not LegacyMessageCommandClient:
            raise ContractError('legacy_message_client_unavailable')
        commands.bind(federation)
        commands.check(federation)
    return MessageContext(
        federation.me, federation.node,
        MessageSettings(bool(federation.fcfg.get("primary", True))),
        AgentDirectory(federation), LocalMessages(federation),
        FederationPublisher(federation), LocalEvents(federation),
        commands=commands,
    )
