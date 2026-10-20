"""Native storage admission and recovery for existing federation transactions."""
import asyncio
import base64
from datetime import datetime, timezone
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.message_storage import MessageStorageJournal
from hub.fed.session import FederationSession
from hub.store import Store
from identity.authority import LedgerAuthorityReader
from identity.capability_service import evaluate_capability_service_request
from identity.capability_routes import CAPABILITY_DESTINATIONS
from state_owner.ledger import OwnerBinding
from .messages import MessageActor
from .policy import _reference


class FederatedStorageResource:
    """Host-only base; concrete owners supply fixed commands and source reads."""
    domain = None

    def __init__(self, binding, federation, *, repository, actors,
                 plugin_identity_ref, instance_id, initial_source=None, _bootstrap=None):
        if (self.domain not in ('knowledge', 'code', 'work')
                or type(binding) is not OwnerBinding or binding.owner_domain != 'federation-' + self.domain
                or binding.entity_kind != self.domain + '-channel'
                or type(federation.store) is not Store or type(federation.session) is not FederationSession
                or type(repository) is not str or not repository
                or strict_loads(binding.scope)['projectId'] is None
                or type(actors) is not tuple or not actors or any(type(a) is not MessageActor for a in actors)
                or len({(a.identity_ref, a.transport_ref) for a in actors}) != len(actors)
                or not _reference(plugin_identity_ref) or type(instance_id) is not str
                or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', instance_id) is None
                or initial_source is not None and (type(initial_source) is not dict
                    or set(initial_source) != {'kind', 'id'} or initial_source['kind'] != self.domain
                    or type(initial_source['id']) is not str
                    or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', initial_source['id']) is None)):
            raise ContractError('capability_owner_configuration')
        self.binding, self.repository, self.actors = binding, repository, actors
        self._owner, self._store, self._session = federation, federation.store, federation.session
        if _bootstrap is not None:
            from .policy_bootstrap import PolicyResourceBootstrap
            if type(_bootstrap) is not PolicyResourceBootstrap:
                raise ContractError('capability_owner_configuration')
            self.repository_id = _bootstrap.repository_id(federation, repository)
        else:
            self.repository_id = federation.policy.rid_of(repository)
        if self.repository_id is None:
            raise ContractError('capability_owner_configuration')
        self.plugin_identity, self.instance_id = canonical_bytes(plugin_identity_ref), instance_id
        descriptor = {'hubId': binding.hub_id, 'entityId': binding.entity_id,
            'scope': strict_loads(binding.scope), 'repository': repository, 'repositoryId': self.repository_id,
            'domain': self.domain, 'localPeer': federation.me, 'localNode': federation.node,
            'pluginIdentityRef': plugin_identity_ref, 'instanceId': instance_id,
            'actors': [{'identityRef': strict_loads(a.identity_ref), 'transportRef': strict_loads(a.transport_ref),
                'caller': a.caller} for a in actors], 'initialSource': initial_source}
        self._peer, self._node = federation.me, federation.node
        self._journal = MessageStorageJournal(self._store, canonical_bytes(descriptor), initial_source,
            namespace=self.domain)
        self._lock = asyncio.Lock()
        if _bootstrap is None:
            self._current()
        else:
            from .policy_bootstrap import check_bootstrap
            check_bootstrap(_bootstrap, self)

    def __repr__(self):
        return '<FederatedStorageResource private>'

    def _current(self):
        if (self._owner.store is not self._store or self._owner.session is not self._session
                or self._owner.me != self._peer or self._owner.node != self._node
                or self._owner.policy.rid_of(self.repository) != self.repository_id
                or self._owner.policy.local_of(self.repository_id) != self.repository):
            raise ContractError('capability_resource_stale')
        self._session.check_open()

    def check_request(self, snapshot, claims):
        self._current()
        rows = [row for row in strict_loads(snapshot.record)['state'].get('nativeInstances', [])
            if row['owner'] == claims['owner']]
        if (len(rows) != 1 or rows[0]['status'] != 'active'
                or canonical_bytes(rows[0]['identityRef']) != self.plugin_identity
                or rows[0]['owner']['instanceId'] != self.instance_id
                or canonical_bytes(claims['scope']) != self.binding.scope
                or claims['resourceRef']['id'] != self.binding.entity_id
                or claims['resourceRef']['ownerHubId'] != self.binding.hub_id):
            raise ContractError('capability_access_refused')

    def _actor(self, original):
        actor = canonical_bytes(original['operation']['effectiveActorRef'])
        transport = canonical_bytes(original['ingressAttestation']['claims']['authenticatedTransportRef'])
        matches = [item for item in self.actors if (item.identity_ref, item.transport_ref) == (actor, transport)]
        if len(matches) != 1:
            raise ContractError('capability_access_refused')
        return matches[0]

    async def authorize(self, authority, raw, service_raw):
        if not isinstance(authority, LedgerAuthorityReader) or type(service_raw) is not bytes or len(service_raw) > 98304:
            raise ContractError('capability_access_refused')
        request = strict_loads(service_raw)
        claims = request['claims']
        if (canonical_bytes(request) != service_raw
                or base64.b64decode(claims['envelopeBytes'], validate=True) != raw
                or claims['requestContractId'] not in ('capability-storage-read', 'capability-storage-write', 'capability-outcome-query')
                or claims['serviceId'] != CAPABILITY_DESTINATIONS[claims['requestContractId']]):
            raise ContractError('capability_access_refused')
        snapshot = await authority.current()
        decision = evaluate_capability_service_request(snapshot, service_raw, service_id=claims['serviceId'],
            now=datetime.now(timezone.utc))
        self.check_request(snapshot, claims)
        self._actor(strict_loads(raw))
        return decision

    async def write(self, authority, raw, service_raw):
        async with self._lock:
            await self.authorize(authority, raw, service_raw)
            original = strict_loads(raw)
            value = self._value(original)
            decision = await self.authorize(authority, raw, service_raw)
            def effect():
                self._current()
                return self._effect(value)
            stored = await self._owner.db(self._journal.commit, original,
                original['payload']['resourceRef']['revision'], decision.valid_until, effect)
            return stored['reply']

    async def read(self, revision):
        def load():
            self._current()
            state = self._journal.current()
            if state['revision'] != revision:
                raise ContractError('capability_resource_stale')
            source = state['source']
            value = {'formatVersion': 1, 'source': None} if source is None else self._read_source(source)
            if value is None:
                raise ContractError('capability_resource_stale')
            data = canonical_bytes(value)
            if len(data) > 45000:
                raise ContractError('capability_service_unavailable')
            return data
        return await self._owner.db(load)

    async def reconcile(self, raw):
        original = strict_loads(raw)
        query = original['payload']['input']
        def load():
            self._current()
            result = {**query, 'recordRef': None, 'outcome': 'absent', 'resourceRef': None}
            stored = self._journal.outcome(query['operationId'], query['payloadDigest'])
            if stored is not None:
                if (query['contractId'] != 'capability-storage-write'
                        or stored['envelope']['contractId'] != query['contractId']
                        or stored['envelope']['operation']['effectiveActorRef'] != original['operation']['effectiveActorRef']):
                    raise ContractError('capability_access_refused')
                result.update(recordRef=stored['reply']['receiptRef'], resourceRef=stored['reply']['resourceRef'],
                    outcome='committed' if stored['reply']['outcome'] == 'applied' else 'rejected')
            return result
        return await self._owner.db(load)
