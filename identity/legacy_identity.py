"""Resolve legacy Hub addresses through current retained identity authority.

Alias records are migration provenance. They never authenticate a caller or grant
membership. The adapter reads current owner state for every resolution and returns
an immutable fence that the Hub store must compare with its live registration in
the transaction that creates a delivery or remote outbox entry.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import names
from .authority import AuthorityReader, AuthoritySnapshot, _key

_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')


@dataclass(frozen=True, slots=True, repr=False)
class LegacyRegistration:
    requested_address: str
    canonical_session: str
    generation: int
    repository: str
    role: str
    agent: str
    state: str
    legacy_alias: str | None = None

    def __post_init__(self):
        try:
            repository, role, agent = names.split_session(self.canonical_session)
        except (TypeError, ValueError):
            raise ContractError('legacy_registration_invalid') from None
        if (type(self.requested_address) is not str or not self.requested_address
                or type(self.generation) is not int or not 1 <= self.generation <= 9007199254740991
                or (repository, role, agent) != (self.repository, self.role, self.agent)
                or self.state == 'dead'
                or self.legacy_alias is not None and
                (type(self.legacy_alias) is not str or not self.legacy_alias)):
            raise ContractError('legacy_registration_invalid')

    def __repr__(self):
        return '<LegacyRegistration protected>'


@dataclass(frozen=True, slots=True, repr=False)
class LegacyIdentityBinding:
    alias: str
    canonical_session: str
    source_hub_id: str
    registration_generation: int
    identity_ref: bytes
    scope: bytes
    instance_owner: bytes
    alias_ref: bytes
    authority_sequence: int
    local: bool

    def __post_init__(self):
        if (type(self.alias) is not str or not self.alias
                or type(self.source_hub_id) is not str or _ID.fullmatch(self.source_hub_id) is None
                or type(self.registration_generation) is not int
                or not 1 <= self.registration_generation <= 9007199254740991
                or type(self.authority_sequence) is not int or self.authority_sequence < 1
                or type(self.local) is not bool
                or any(type(value) is not bytes for value in
                       (self.identity_ref, self.scope, self.instance_owner, self.alias_ref))):
            raise ContractError('legacy_identity_binding_invalid')
        try:
            names.split_session(self.canonical_session)
            for raw in (self.identity_ref, self.scope, self.instance_owner, self.alias_ref):
                if canonical_bytes(strict_loads(raw)) != raw:
                    raise ValueError()
        except (ValueError, ContractError):
            raise ContractError('legacy_identity_binding_invalid') from None

    def __repr__(self):
        return '<LegacyIdentityBinding protected>'

    def wire(self):
        """Return bounded provenance for a trusted remote Hub's generation fence."""
        return {
            'alias': self.alias,
            'canonicalSession': self.canonical_session,
            'sourceHubId': self.source_hub_id,
            'registrationGeneration': self.registration_generation,
            'identityRef': strict_loads(self.identity_ref),
            'scope': strict_loads(self.scope),
            'instanceOwner': strict_loads(self.instance_owner),
            'aliasRef': strict_loads(self.alias_ref),
            'authoritySequence': self.authority_sequence,
        }


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedLegacyAliasResolution:
    """Verified bindings with the signed deadline that bounds their use."""
    bindings: tuple[LegacyIdentityBinding, ...]
    valid_until: datetime

    def __post_init__(self):
        if (type(self.bindings) is not tuple or not self.bindings
                or any(type(binding) is not LegacyIdentityBinding for binding in self.bindings)
                or type(self.valid_until) is not datetime
                or self.valid_until.utcoffset() != timedelta(0)):
            raise ContractError('legacy_identity_resolution_invalid')

    def __repr__(self):
        return '<VerifiedLegacyAliasResolution private>'


class LegacyIdentityAdapter:
    """Adapter from legacy registrations to active, scoped identity references."""

    def __init__(self, reader, *, local_source_hub_id, scope, instance_owner=None):
        if (not isinstance(reader, AuthorityReader)
                or type(local_source_hub_id) is not str or _ID.fullmatch(local_source_hub_id) is None
                or not isinstance(scope, dict) or set(scope) !=
                {'organizationId', 'projectId', 'workspaceId'}
                or type(scope.get('organizationId')) is not str
                or not isinstance(instance_owner, (dict, type(None)))):
            raise ContractError('legacy_identity_configuration_invalid')
        self._reader = reader
        self._local_hub = local_source_hub_id
        self._scope = canonical_bytes(scope)
        self._instance_owner = canonical_bytes(instance_owner)

    @property
    def local_source_hub_id(self):
        return self._local_hub

    @property
    def scope(self):
        """Return the exact admitted project scope, never a mutable reference."""
        return strict_loads(self._scope)

    @property
    def instance_owner(self):
        return strict_loads(self._instance_owner)

    async def bind(self, registrations, *, remote_address=None):
        """Resolve local registration snapshots or one remote direct address."""
        if remote_address is not None:
            if registrations:
                raise ContractError('legacy_identity_resolution_invalid')
            try:
                address = names.parse_address(remote_address)
            except (TypeError, ValueError):
                raise ContractError('legacy_identity_resolution_invalid') from None
            if address.kind != 'agent':
                raise ContractError('legacy_identity_resolution_invalid')
            wanted = address.name
        else:
            if (not isinstance(registrations, (tuple, list)) or not registrations
                    or any(type(item) is not LegacyRegistration for item in registrations)):
                raise ContractError('legacy_identity_resolution_invalid')
            wanted = None
        snapshot = await self._reader.current()
        if type(snapshot) is not AuthoritySnapshot:
            raise ContractError('authority_record_invalid')
        record = strict_loads(snapshot.record)
        state = record['state']
        identities = {_key(row['ref']): row for row in state['identities']}
        memberships = state['memberships']
        native = state.get('nativeInstances', [])

        def active(row):
            return row is not None and row['status'] == 'active'

        def authorized(row):
            identity = identities.get(_key(row['identityRef']))
            if not active(identity):
                return False
            scope = strict_loads(self._scope)
            if not any(active(member) and member['identityRef'] == row['identityRef']
                       and member['scope'] == scope for member in memberships):
                return False
            owner = strict_loads(self._instance_owner)
            if owner is None:
                return True
            for item in native:
                host = identities.get(_key(item['hostIdentityRef']))
                if (active(item) and item['owner'] == owner
                        and item['identityRef'] == row['identityRef']
                        and active(host) and host['kind'] == 'service'):
                    return True
            return False

        def candidates(session, *, generation=None, alias=None, local=False):
            rows = [row for row in state.get('legacyAliases', [])
                    if active(row) and row['scope'] == strict_loads(self._scope)
                    and row['instanceOwner'] == strict_loads(self._instance_owner)
                    and row['canonicalSession'] == session
                    and (generation is None or row['registrationGeneration'] == generation)
                    and (alias is None or row['alias'] == alias)
                    and (not local or row['sourceHubId'] == self._local_hub)
                    and authorized(row)]
            groups = {}
            for row in rows:
                key = (canonical_bytes(row['identityRef']), row['sourceHubId'],
                       row['registrationGeneration'], row['canonicalSession'])
                groups.setdefault(key, []).append(row)
            if len(groups) != 1:
                raise ContractError('legacy_identity_ambiguous' if groups else 'legacy_identity_unavailable')
            group = next(iter(groups.values()))
            if alias is None:
                group.sort(key=lambda value: (value['alias'] != session, value['alias']))
            selected = group[0]
            return LegacyIdentityBinding(selected['alias'], selected['canonicalSession'],
                selected['sourceHubId'], selected['registrationGeneration'],
                canonical_bytes(selected['identityRef']), canonical_bytes(selected['scope']),
                canonical_bytes(selected['instanceOwner']), canonical_bytes(selected['ref']),
                snapshot.sequence, local)

        if wanted is not None:
            return (candidates(wanted),)
        result = []
        for registration in registrations:
            result.append(candidates(registration.canonical_session,
                generation=registration.generation, alias=registration.legacy_alias, local=True))
        return tuple(result)

    async def admit_remote(self, registration, provenance):
        """Re-read authority and turn untrusted wire provenance into a local fence."""
        fields = {'alias', 'canonicalSession', 'sourceHubId', 'registrationGeneration',
                  'identityRef', 'scope', 'instanceOwner', 'aliasRef', 'authoritySequence'}
        if (type(registration) is not LegacyRegistration or not isinstance(provenance, dict)
                or set(provenance) != fields or type(provenance.get('authoritySequence')) is not int
                or provenance['authoritySequence'] < 1):
            raise ContractError('legacy_identity_provenance_invalid')
        selected_registration = LegacyRegistration(registration.requested_address,
            registration.canonical_session, registration.generation, registration.repository,
            registration.role, registration.agent, registration.state, provenance.get('alias'))
        current = (await self.bind((selected_registration,)))[0]
        expected = current.wire()
        supplied_sequence = provenance['authoritySequence']
        expected_sequence = expected.pop('authoritySequence')
        supplied = dict(provenance)
        supplied.pop('authoritySequence')
        if (supplied != expected or supplied_sequence > expected_sequence):
            raise ContractError('legacy_identity_provenance_invalid')
        return current
