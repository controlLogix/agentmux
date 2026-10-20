"""Resolve legacy Hub identities through enrolled application sessions."""
from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections.abc import Mapping

from agentmux_contracts import ContractError, canonical_bytes
from hub import names
from hub.client_launch_session import ApplicationClientSession
from identity.legacy_identity import (
    LegacyIdentityBinding,
    LegacyRegistration,
    VerifiedLegacyAliasResolution,
)

_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')


def _wire_registration(registration):
    return {
        'requestedAddress': registration.requested_address,
        'canonicalSession': registration.canonical_session,
        'registrationGeneration': registration.generation,
        'repository': registration.repository,
        'role': registration.role,
        'agent': registration.agent,
        'state': registration.state,
        'legacyAlias': registration.legacy_alias,
    }


class EnrolledLegacyIdentityResolver:
    """Borrow already opened project sessions and resolve exact Hub repositories."""

    def __init__(self, sessions: Mapping[str, ApplicationClientSession], *, local_source_hub_id: str):
        if (not isinstance(sessions, Mapping) or not sessions
                or type(local_source_hub_id) is not str
                or _ID.fullmatch(local_source_hub_id) is None):
            raise ContractError('legacy_identity_configuration_invalid')
        selected = {}
        for repository, session in sessions.items():
            try:
                canonical = names.check_part(repository, 'repo')
            except (TypeError, ValueError):
                raise ContractError('legacy_identity_configuration_invalid') from None
            if canonical != repository or type(session) is not ApplicationClientSession:
                raise ContractError('legacy_identity_configuration_invalid')
            selected[repository] = session
        self._sessions = selected
        self._local_hub = local_source_hub_id
        self._locks = {id(session): asyncio.Lock() for session in selected.values()}

    @property
    def local_source_hub_id(self):
        return self._local_hub

    @property
    def repositories(self):
        return tuple(sorted(self._sessions))

    @staticmethod
    def _operation_id(repository, selector):
        digest = hashlib.sha256(canonical_bytes({
            'repository': repository,
            **selector,
        })).hexdigest()
        # A retained session request can be consumed only by the same selector.
        return 'legacy_' + digest[:64]

    async def _query(self, repository, *, registrations=None, remote_address=None):
        session = self._sessions.get(repository)
        if session is None:
            raise ContractError('legacy_identity_unavailable')
        selector = ({'registrations': registrations} if remote_address is None
                    else {'remoteAddress': remote_address})
        operation_id = self._operation_id(repository, selector)

        def query():
            return session.query_legacy_aliases(registrations, remote_address=remote_address,
                operation_id=operation_id, deadline=time.monotonic() + 5)

        async with self._locks[id(session)]:
            task = asyncio.create_task(asyncio.to_thread(query))
            try:
                result = await asyncio.shield(task)
            except asyncio.CancelledError as cancelled:
                # The session retains its original request. Keep the per-session
                # serialization lock until that request has finished.
                try:
                    await task
                except Exception:
                    pass
                raise cancelled
            except Exception:
                raise ContractError('legacy_identity_unavailable') from None
        if type(result) is not VerifiedLegacyAliasResolution:
            raise ContractError('legacy_identity_resolution_invalid')
        return result

    async def bind(self, registrations, *, remote_address=None):
        """Resolve one remote address or local registrations grouped by repository."""
        if remote_address is not None:
            if registrations:
                raise ContractError('legacy_identity_resolution_invalid')
            try:
                address = names.parse_address(remote_address)
                repository, _, _ = names.split_session(address.name)
            except (TypeError, ValueError):
                raise ContractError('legacy_identity_resolution_invalid') from None
            if address.kind != 'agent' or str(address) != remote_address:
                raise ContractError('legacy_identity_resolution_invalid')
            result = await self._query(repository, remote_address=remote_address)
            if (len(result.bindings) != 1 or result.bindings[0].local
                    or result.bindings[0].canonical_session != address.name):
                raise ContractError('legacy_identity_resolution_invalid')
            return result

        if (not isinstance(registrations, (tuple, list)) or not registrations
                or any(type(item) is not LegacyRegistration for item in registrations)):
            raise ContractError('legacy_identity_resolution_invalid')
        groups = {}
        for index, registration in enumerate(registrations):
            groups.setdefault(registration.repository, []).append((index, registration))
        if any(repository not in self._sessions or len(items) > 64
               for repository, items in groups.items()):
            raise ContractError('legacy_identity_unavailable')

        async def query_group(repository, items):
            wire = [_wire_registration(registration) for _, registration in items]
            return repository, items, await self._query(repository, registrations=wire)

        results = await asyncio.gather(
            *(query_group(repository, items) for repository, items in groups.items()),
            return_exceptions=True)
        if any(isinstance(result, BaseException) for result in results):
            raise ContractError('legacy_identity_unavailable')
        ordered = [None] * len(registrations)
        deadlines = []
        for _repository, items, resolution in results:
            if len(resolution.bindings) != len(items):
                raise ContractError('legacy_identity_resolution_invalid')
            deadlines.append(resolution.valid_until)
            for (index, registration), binding in zip(items, resolution.bindings):
                if (type(binding) is not LegacyIdentityBinding or not binding.local
                        or binding.canonical_session != registration.canonical_session
                        or binding.registration_generation != registration.generation):
                    raise ContractError('legacy_identity_resolution_invalid')
                ordered[index] = binding
        return VerifiedLegacyAliasResolution(tuple(ordered), min(deadlines))

    async def admit_remote(self, registration, provenance):
        """Revalidate untrusted inbound provenance through the selected owner."""
        fields = {'alias', 'canonicalSession', 'sourceHubId', 'registrationGeneration',
                  'identityRef', 'scope', 'instanceOwner', 'aliasRef', 'authoritySequence'}
        if (type(registration) is not LegacyRegistration or type(provenance) is not dict
                or set(provenance) != fields
                or type(provenance.get('authoritySequence')) is not int
                or provenance['authoritySequence'] < 1):
            raise ContractError('legacy_identity_provenance_invalid')
        selected = LegacyRegistration(registration.requested_address,
            registration.canonical_session, registration.generation, registration.repository,
            registration.role, registration.agent, registration.state, provenance.get('alias'))
        try:
            resolution = await self.bind((selected,))
        except ContractError:
            raise ContractError('legacy_identity_provenance_invalid') from None
        expected = resolution.bindings[0].wire()
        expected_sequence = expected.pop('authoritySequence')
        supplied = dict(provenance)
        supplied_sequence = supplied.pop('authoritySequence')
        if supplied != expected or supplied_sequence > expected_sequence:
            raise ContractError('legacy_identity_provenance_invalid')
        return resolution
