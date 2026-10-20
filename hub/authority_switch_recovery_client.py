"""Use one enrolled application session to reach the retained switch owner."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import time

from agentmux_contracts import canonical_bytes, strict_loads
from state_owner.authority_switch import authority_switch_id
from state_owner.authority_switch_service import VerifiedEnrolledRecovery
from state_owner.ledger import StreamIdentity

from .client_launch_session import ApplicationClientSession, ApplicationSessionFailure


class EnrolledAuthoritySwitchRecovery:
    """Bind one public source fence to one verified enrolled owner route."""
    def __init__(self, session, *, public):
        try:
            if not isinstance(session, ApplicationClientSession):
                raise ValueError()
            route = session.authority_switch_recovery_route()
            stream = public['streamIdentity']
            identity = StreamIdentity(datetime.fromisoformat(stream['created']),
                                      stream['minimumSequence'])
            if (set(public) != {'switchId', 'source', 'streamIdentity', 'custodyDirectory'}
                    or route['switchId'] != public['switchId']
                    or route['source'] != public['source']
                    or route['streamIdentity'] != stream
                    or authority_switch_id(public['source']) != public['switchId']):
                raise ValueError()
        except Exception:
            raise ApplicationSessionFailure(session) from None
        self._session = session
        self._public = canonical_bytes(public)
        self._stream_identity = identity

    @classmethod
    def from_sessions(cls, sessions, *, public):
        selected = [session for session in sessions
                    if session.authority_switch_recovery_enabled()]
        if len(selected) != 1:
            raise ApplicationSessionFailure(selected[0] if selected else None)
        return cls(selected[0], public=public)

    def __repr__(self):
        return '<EnrolledAuthoritySwitchRecovery private>'

    @property
    def source(self):
        return strict_loads(self._public)['source']

    async def authorize(self, *, fence, fence_id):
        public = strict_loads(self._public)
        source = public['source']
        if (type(fence) is not dict or fence.get('state') not in ('fenced', 'open')
                or fence_id != source['fenceId'] or fence.get('fenceId') != fence_id
                or fence.get('generation') != source['fenceGeneration']):
            raise ValueError('legacy migration recovery refused')
        operation_id = 'recover_' + hashlib.sha256(canonical_bytes({
            'switchId': public['switchId'], 'source': source,
            'fenceId': fence_id, 'generation': fence['generation']})).hexdigest()[:32]
        result = await __import__('asyncio').to_thread(
            self._session.request_authority_switch_recovery, operation_id,
            deadline=time.monotonic() + 5)
        if type(result) is not VerifiedEnrolledRecovery:
            raise ValueError('legacy migration recovery refused')
        response = strict_loads(result._response)['claims']
        if (response['switchRef'] != {'id': public['switchId'],
                'ownerHubId': response['hubId'], 'revision': 2}
                or response['source'] != source
                or response['stream']['created'] != public['streamIdentity']['created']
                or response['stream']['minimumSequence'] != response['switchRef']['revision']
                or response['stream']['minimumSequence'] <
                    public['streamIdentity']['minimumSequence']
                or datetime.now(timezone.utc) >= result._valid_until):
            raise ValueError('legacy migration recovery refused')
        return result

