"""Current admitted peer control permits one exact repository withdrawal."""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import ledger
from hub.fed.peer_control import PeerControlIngress
from identity.authority import _active, _indexes, _key, approval_reason, authorization_deadline
from identity.peer_control import check_authority, control_storage
from identity.peer_control import public_credential
from nacl.signing import VerifyKey


@dataclass(frozen=True, repr=False, init=False, slots=True)
class KnowledgeControlAdmission:
    owner: object
    resource: object
    original: bytes
    proof: bytes
    ingress: object
    session: object
    connection: object
    valid_until: datetime

    def __new__(cls):
        raise TypeError('Current admitted peer control is required')


@dataclass(frozen=True, repr=False, init=False, slots=True)
class KnowledgeControlRejection:
    owner: object
    resource: object
    original: bytes
    valid_until: datetime

    def __new__(cls):
        raise TypeError('Current owner refusal is required')


class KnowledgeControlOwner:
    """Own exact control subscriptions; borrow their original knowledge sources."""
    def __init__(self, selection, identity, resources):
        from identity.application_service_selection import ApplicationServiceSelection
        from .knowledge import KnowledgeStorageResource
        if type(selection) is not ApplicationServiceSelection or type(resources) is not tuple:
            raise ContractError('knowledge_control_configuration')
        self._selection, self._identity = selection, identity
        self._resources = resources
        self._authority, self._enrolled = selection.check_storage_identity_source(identity)
        self._routes = {}
        for pin in selection.policy.get('peerControl', {}).get('routes', ()):
            if control_storage(selection.policy, pin)[0] != 'knowledge':
                continue
            matched = [resource for resource in resources if type(resource) is KnowledgeStorageResource
                and resource.binding.hub_id == pin['resourceRef']['ownerHubId']
                and resource.binding.entity_id == pin['resourceRef']['id']
                and strict_loads(resource.binding.scope) == pin['scope']
                and resource.repository == pin['repository']['localName']
                and resource.repository_id == pin['repository']['repositoryId']]
            if len(matched) != 1:
                raise ContractError('knowledge_control_configuration')
            resource = matched[0]
            source = getattr(resource._owner, '_source', None)
            if source is None:
                raise ContractError('knowledge_control_configuration')
            key = (id(resource), pin['peer']['peerId'])
            if key in self._routes:
                raise ContractError('knowledge_control_configuration')
            async def dispatch(message, handle, *, selected=pin, selected_resource=resource):
                ingress = self._routes[(id(selected_resource), selected['peer']['peerId'])]
                await ingress.consume(handle, peer=selected['peer']['peerId'],
                    repository_id=selected['repository']['repositoryId'])
            ingress = PeerControlIngress(selection, identity, source, dispatch, route_id=pin['routeId'])
            self._routes[key] = ingress
            previous = getattr(resource, '_control_owner', None)
            if previous is not None and previous is not self:
                raise ContractError('knowledge_control_configuration')
            resource._control_owner = self
        self._closed, self._ready, self._closing, self._policy_paused = False, False, None, False
        self._active, self._starting = set(), None

    def __repr__(self):
        return '<KnowledgeControlOwner private>'

    def check(self):
        if self._policy_paused:
            raise ContractError('knowledge_control_unavailable')
        self.check_health()

    def check_health(self):
        if self._closed or not self._ready:
            raise ContractError('knowledge_control_unavailable')
        authority, enrolled = self._selection.check_storage_identity_source(self._identity)
        if authority is not self._authority or enrolled is not self._enrolled:
            raise ContractError('knowledge_control_unavailable')
        for ingress in self._routes.values():
            ingress.check_health()

    async def start(self, *, _bootstrap=None):
        if self._closed or self._starting is not None:
            raise ContractError('knowledge_control_unavailable')
        if _bootstrap is not None:
            from .policy_bootstrap import PolicyResourceBootstrap
            if type(_bootstrap) is not PolicyResourceBootstrap:
                raise ContractError('knowledge_control_configuration')
            for resource, _ in self._routes:
                matched = [r for r in self._resources if id(r) == resource]
                if len(matched) != 1:
                    raise ContractError('knowledge_control_configuration')
                _bootstrap.check(matched[0])
        async def opening():
            for ingress in self._routes.values():
                if self._closed:
                    raise ContractError('knowledge_control_unavailable')
                await ingress.start(_bootstrap=_bootstrap)
            if self._closed:
                raise ContractError('knowledge_control_unavailable')
            self._ready = True
        self._starting = (asyncio.create_task(opening(), name='knowledge-control:opening')
            if _bootstrap is None else _bootstrap._start_owned(opening))
        self._starting.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(self._starting)
        self.check()

    async def admit(self, resource, original_raw, valid_until):
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            self.check()
            original = strict_loads(original_raw)
            value = original['payload']['input']
            selector = value['control']
            def refused():
                self.check()
                result = object.__new__(KnowledgeControlRejection)
                for name, value in (('owner', self), ('resource', resource),
                        ('original', original_raw), ('valid_until', valid_until)):
                    object.__setattr__(result, name, value)
                return result
            if (type(selector) is not dict or set(selector) != {'eventId', 'eventDigest', 'subject', 'signature', 'repositoryId'}
                    or selector['repositoryId'] != resource.repository_id
                    or selector['subject'] != 'am.ctl.' + value['peer']
                    or getattr(resource, '_control_owner', None) is not self):
                return refused()
            ingress = self._routes.get((id(resource), value['peer']))
            if ingress is None:
                return refused()
            try:
                await check_authority(self._selection, self._identity, route_id=ingress._route_id)
            except ContractError as error:
                if error.code == 'peer_control_refused':
                    return refused()
                raise
            self.check()
            ingress.check()
            pin = ingress._pin
            _, public = public_credential(pin['peer']['credentialJWT'], account=pin['accountPublicKey'],
                user=pin['peer']['userPublicKey'], peer=pin['peer']['peerId'])
            claims = {'purpose': 'agentmux-peer-control-v1', 'eventId': selector['eventId'],
                'eventDigest': selector['eventDigest'], 'subject': selector['subject'],
                'accountPublicKey': pin['accountPublicKey'], 'resourceRef': pin['resourceRef'],
                'scope': pin['scope'], 'repositoryId': pin['repository']['repositoryId']}
            try:
                VerifyKey(public).verify(canonical_bytes(claims), base64.b64decode(selector['signature'], validate=True))
            except Exception:
                return refused()
            handle = await ingress.recover(selector['eventId'], selector['eventDigest'])
            proof = await ingress.consume(handle, peer=value['peer'], repository_id=resource.repository_id)
            retained = strict_loads(proof)
            if (retained['subject'] != selector['subject'] or retained['signature'] != selector['signature']
                    or retained['event']['from'] != value['peer']
                    or retained['binding']['scope'] != original['operation']['scope']
                    or retained['binding']['resourceRef']['id'] != resource.binding.entity_id
                    or retained['binding']['resourceRef']['ownerHubId'] != resource.binding.hub_id):
                raise ContractError('knowledge_control_refused')
            snapshot = await check_authority(self._selection, self._identity, route_id=ingress._route_id)
            self.check()
            ingress.check()
            now = datetime.now(timezone.utc)
            deadline = min(valid_until, now + timedelta(seconds=5),
                authorization_deadline(strict_loads(snapshot.record)['state'], original, now))
            if deadline <= now:
                raise ContractError('knowledge_control_expired')
            admission = object.__new__(KnowledgeControlAdmission)
            for name, value in (('owner', self), ('resource', resource), ('original', original_raw), ('proof', proof),
                    ('ingress', ingress), ('session', ingress._session), ('connection', ingress._connection),
                    ('valid_until', deadline)):
                object.__setattr__(admission, name, value)
            return admission
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('knowledge_control_cleanup_invalid')
        self._closed = True
        if self._closing is None:
            async def joined():
                if self._starting is not None:
                    await asyncio.gather(self._starting, return_exceptions=True)
                if self._active:
                    await asyncio.gather(*tuple(self._active), return_exceptions=True)
                for ingress in self._routes.values():
                    await ingress.close(timeout=None)
            self._closing = asyncio.create_task(joined(), name='knowledge-control:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('knowledge_control_cleanup_incomplete')
        self._closing.result()

    def begin_policy_pause(self):
        if self._closed:
            raise ContractError('knowledge_control_unavailable')
        self._policy_paused = True
        for ingress in self._routes.values():
            ingress.begin_policy_pause()

    async def join_policy_pause(self):
        if not self._policy_paused:
            raise ContractError('knowledge_control_unavailable')
        if self._active:
            await asyncio.gather(*tuple(self._active), return_exceptions=True)
        for ingress in self._routes.values():
            await ingress.join_policy_pause()

    def end_policy_pause(self):
        if self._closed or not self._policy_paused:
            raise ContractError('knowledge_control_unavailable')
        for ingress in self._routes.values():
            ingress.end_policy_pause()
        self._policy_paused = False


def stage_withdrawal(resource, value, checked):
    """Run only within the original knowledge journal's admitted transaction."""
    from .knowledge_legacy import _Admission
    admission = getattr(checked, 'control', None)
    if (type(checked) is not _Admission or type(admission) is not KnowledgeControlAdmission
            or checked.resource is not resource or admission.resource is not resource
            or admission.original != checked.original or admission.owner is not getattr(resource, '_control_owner', None)
            or admission.owner._closed or datetime.now(timezone.utc) >= min(checked.valid_until, admission.valid_until)
            or admission.session is not admission.ingress._session or admission.connection is not admission.ingress._connection
            or admission.ingress._closed or admission.ingress._policy_paused
            or admission.session.closing or not admission.connection.is_connected):
        raise ContractError('knowledge_control_refused')
    original = strict_loads(checked.original)
    if original['payload']['input'] != {key: val for key, val in value.items() if key != 'command'}:
        raise ContractError('knowledge_control_refused')
    selector = value['control']
    proof_raw = admission.ingress._proof(admission.proof, selector['eventId'], selector['eventDigest'])
    proof = strict_loads(proof_raw)
    source = admission.ingress._store_owner
    source._check_files()
    stored = source._store.q1('SELECT v FROM fed_state WHERE k=?', (admission.ingress._key(selector['eventId']),))
    if (source._store is not resource._store or not getattr(source._worker, 'active', False)
            or stored is None or canonical_bytes(strict_loads(stored['v'])) != proof_raw
            or proof['signature'] != selector['signature'] or proof['subject'] != selector['subject']
            or proof['event']['from'] != value['peer']
            or proof['binding']['repository']['repositoryId'] != resource.repository_id):
        raise ContractError('knowledge_control_refused')
    count = resource._knowledge.stage_withdrawal(value['peer'], resource.repository)
    ledger.audit(resource._store, 'in', 'ctl', value['peer'], resource.repository_id,
        selector['subject'], selector['eventId'], proof['event'], 'knowledge-revoke',
        {'operationId': original['operation']['operationId'], 'eventDigest': selector['eventDigest'],
            'proofDigest': payload_digest(proof), 'routeId': proof['binding']['routeId']})
    return {'withdrawn': count}, resource._journal.current()['source']


def check_recovery(resource, stored, original, snapshot):
    """A committed outcome needs current original service authority, no new peer admission."""
    if (stored['envelope']['contractId'] != 'federation-knowledge-withdraw'
            or 'control' not in stored['envelope']['payload']['input']):
        return
    retained = stored['envelope']['operation']
    current = original['operation']
    if (retained['effectiveActorRef'] != current['effectiveActorRef']
            or retained['caller'] != current['caller'] or retained['scope'] != current['scope']):
        raise ContractError('knowledge_control_refused')
    index = _indexes(strict_loads(snapshot.record)['state'], resource.binding.hub_id)
    now = datetime.now(timezone.utc)
    grant = index['grants'].get(_key(retained['grantRef']))
    candidates = [g for g in index['grants'].values() if _active(g, now)
        and g['callerRef'] == retained['caller']['authenticatedIdentityRef']
        and g['actorRef'] == retained['effectiveActorRef'] and g['scope'] == retained['scope']
        and g['resourceId'] == resource.binding.entity_id and g['contractId'] == 'federation-knowledge-withdraw']
    if (grant not in candidates or grant['decision'] != 'allowed' or grant['delegationRef'] is not None
            or any(g['decision'] == 'denied' for g in candidates)
            or approval_reason(index, grant, retained, audience={'hubId': resource.binding.hub_id,
                'serviceId': 'storage-owner'}, scope=retained['scope'],
                contract='federation-knowledge-withdraw', now=now) is not None):
        raise ContractError('knowledge_control_refused')
