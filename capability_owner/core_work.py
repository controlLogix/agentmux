"""Bind preserved core work ingress to the concrete retained Work owner."""
import asyncio
import base64
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.core_work_transport import CoreWorkIngress
from identity.core_work_transport import (CONTRACTS, body_route, check_authority,
    check_snapshot, identity_generation, refused, selected_route, verify_event)


@dataclass(frozen=True, repr=False, init=False, slots=True)
class CoreWorkAdmission:
    owner: object
    resource: object
    original: bytes
    proof: bytes
    ingress: object
    snapshot: object
    valid_until: datetime
    session: object
    connection: object
    committed: bool

    def __new__(cls):
        raise TypeError('Current core work authority is required')


class CoreWorkOwner:
    """One selected host binds routes first, then one actual Bridge binds dispatch."""
    def __init__(self, selection, identity, resources):
        from identity.application_service_selection import ApplicationServiceSelection
        from .work import WorkStorageResource
        if type(selection) is not ApplicationServiceSelection or type(resources) is not tuple:
            refused()
        self._selection, self._identity = selection, identity
        self._resources = resources
        self._authority, self._enrolled = selection.check_storage_identity_source(identity)
        self._identity_generation = identity_generation(identity)
        self._selection_document = selection.document
        self._routes, self._ingresses, self._bindings = {}, {}, {}
        self._dispatch = None
        grouped = {}
        for route in selection.policy.get('coreWorkTransport', {}).get('routes', ()):
            matches = [r for r in resources if type(r) is WorkStorageResource
                and r.binding.hub_id == route['resourceRef']['ownerHubId']
                and r.binding.entity_id == route['resourceRef']['id']
                and strict_loads(r.binding.scope) == route['scope']
                and r.repository == route['repository']['localName']
                and r.repository_id == route['repository'].get('repositoryId')
                and r._node == route['localNode']]
            if len(matches) != 1:
                refused()
            resource = matches[0]
            source = getattr(resource._owner, '_source', None)
            if (source is None or source._store is not resource._store
                    or source._store.db is not resource._connection
                    or source._executor is not resource._source_worker):
                refused()
            prior = getattr(resource, '_core_work_owner', None)
            if prior is not None and prior is not self:
                refused()
            resource._core_work_owner = self
            self._bindings[id(resource)] = resource._journal.binding
            grouped.setdefault(resource, []).append(route['routeId'])
        for resource, routes in grouped.items():
            async def dispatch(message, handle, *, selected_resource=resource):
                if self._dispatch is None:
                    refused()
                await self._dispatch(selected_resource, message, handle)
            ingress = CoreWorkIngress(selection, identity, resource._owner._source, dispatch,
                route_ids=tuple(routes), resource_binding=resource._journal.binding)
            self._ingresses[id(resource)] = ingress
            for route_id in routes:
                self._routes[route_id] = (resource, ingress)
        self._closed, self._started, self._closing = False, None, None
        self._policy_paused, self._ready = False, False
        self._dispatcher = None
        self._publishers = {}
        self._outbox_task = None
        self._roles_task = None
        self._transport_generation = secrets.token_hex(32)
        self._transport_sessions = {}
        self._transport_duties = None
        from .core_work_client import CoreWorkDispatcher, CoreWorkOutbox
        from .core_work_roles import CoreWorkRoles
        self._dispatcher = CoreWorkDispatcher(self)
        self._dispatch = self._dispatcher.receive
        self._outbox = CoreWorkOutbox(self)
        self._roles = CoreWorkRoles(self)

    def __repr__(self):
        return '<CoreWorkOwner private>'

    def check_health(self):
        """Configured custody is healthy before an explicit receiver activation."""
        if (self._closed or self._selection.document != self._selection_document
                or identity_generation(self._identity) != self._identity_generation):
            refused()
        on_work_thread = any(getattr(ingress._source._worker, 'active', False)
                             for ingress in self._ingresses.values())
        if on_work_thread:
            if (self._identity._closed or self._identity.reader is not self._authority
                    or self._identity.ingress is not self._enrolled):
                refused()
        else:
            authority, enrolled = self._selection.check_storage_identity_source(self._identity)
            if authority is not self._authority or enrolled is not self._enrolled:
                refused()
        for route_id, (resource, ingress) in self._routes.items():
            pin = selected_route(self._selection, route_id)
            if (canonical_bytes(pin) != ingress._routes[route_id]
                    or getattr(resource, '_core_work_owner', None) is not self
                    or resource._journal.binding != self._bindings[id(resource)]):
                refused()
            source = ingress._source
            if (source._store is not resource._store or source._store.db is not resource._connection
                    or source._executor is not resource._source_worker):
                refused()
            if getattr(source._worker, 'active', False):
                source._check_files()
            else:
                source.check_health()
        if self._started is not None and self._started.done():
            if self._started.cancelled() or self._started.exception() is not None or not self._ready:
                refused()
        for task in (self._outbox_task, self._roles_task):
            if task is not None and task.done() and not self._closed:
                refused()

    def check(self):
        self.check_health()
        if self._policy_paused or not self._ready:
            refused()
        for resource, ingress in self._routes.values():
            resource._current()
            ingress.check()

    async def start(self, *, _bootstrap=None, _watch_roles=False):
        if self._closed or self._started is not None or self._dispatch is None:
            refused()
        if type(_watch_roles) is not bool:
            refused()
        if _bootstrap is not None:
            from .policy_bootstrap import PolicyResourceBootstrap
            if type(_bootstrap) is not PolicyResourceBootstrap:
                refused()
            for resource, _ in self._routes.values():
                _bootstrap.check(resource)
        async def opening():
            for ingress in self._ingresses.values():
                await ingress.start()
            from hub.core_work_transport import CoreWorkPublisher
            for route_id in self._routes:
                if 'publisher' in selected_route(self._selection, route_id):
                    publisher = CoreWorkPublisher(self._selection, self._identity, route_id=route_id)
                    self._publishers[route_id] = publisher
                    await publisher.start()
            self._ready = True
            self._transport_sessions = {rid: (ingress, ingress._session, ingress._connection,
                self._publishers.get(rid),
                None if rid not in self._publishers else self._publishers[rid]._session,
                None if rid not in self._publishers else self._publishers[rid]._connection)
                for rid, (_, ingress) in self._routes.items()}
            if self._publishers:
                self._outbox_task = asyncio.create_task(self._outbox.run(), name='core-work:outbox')
                self._outbox_task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            if _watch_roles:
                self._roles_task = asyncio.create_task(self._roles.run(), name='core-work:roles')
                self._roles_task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            self._transport_duties = (self._outbox_task, self._roles_task, self._outbox, self._roles)
        self._started = asyncio.create_task(opening(), name='core-work-owner:opening')
        self._started.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(self._started)
        self.check_health()

    def transport_proof(self, resource, snapshot):
        """Prove this resource's selected core mode on its original Work worker."""
        if not getattr(resource._source._worker, 'active', False):
            refused()
        return self._transport_binding(resource, snapshot, disclosure=False)

    def check_transport_disclosure(self, resource, expected, snapshot, expires):
        """Fence the final signature without reading SQLite on this thread."""
        proof, deadline = self._transport_binding(resource, snapshot, disclosure=True)
        if proof != expected or datetime.now(timezone.utc) >= min(deadline, expires):
            refused()

    def _transport_binding(self, resource, snapshot, *, disclosure):
        from identity.core_work_transport import local_credential, publication_subjects
        from identity.authority import _active, _indexes, _key, approval_reason
        if disclosure:
            self.check_health()
            if self._policy_paused or not self._ready:
                refused()
            for _, ingress in self._routes.values():
                ingress.check()
        else:
            self.check()
        if (self._outbox_task is None or self._outbox_task.done()
                or self._roles_task is None or self._roles_task.done()
                or self._roles._completed_sync is None
                or self._roles._last_error is not None
                or self._transport_duties != (self._outbox_task,self._roles_task,self._outbox,self._roles)):
            refused()
        routes, deadlines = [], []
        index = _indexes(strict_loads(snapshot.record)['state'], resource.binding.hub_id)
        for rid, (current, ingress) in self._routes.items():
            if current is not resource:
                continue
            route = selected_route(self._selection, rid)
            publisher = self._publishers.get(rid)
            held = self._transport_sessions.get(rid)
            if (not route['workSubjects'] or route['resultSubjects'] != ['am.result.' + resource._node]
                    or publisher is None or held is None
                    or held != (ingress, ingress._session, ingress._connection,
                        publisher, publisher._session, publisher._connection)
                    or publisher._closed or publisher._policy_paused
                    or publisher._started is None or not publisher._started.done()
                    or publisher._started.cancelled() or publisher._started.exception() is not None
                    or publisher._selection is not self._selection
                    or publisher._identity is not self._identity
                    or publisher._pin != canonical_bytes(route)
                    or not publisher._connection.is_connected):
                refused()
            publisher._session.check_open()
            # Only actual current interests need a queue. Result subscriptions
            # must exist even while no local agent can accept role work.
            wanted = ((set(ingress._subscriptions) if disclosure else self._roles._interests(resource))
                & set(route['workSubjects']))
            for subject in wanted | set(route['resultSubjects']):
                subscription = ingress._subscriptions.get(subject)
                owned = ingress._session._resources.get(id(subscription))
                dispatcher = ingress._dispatch_tasks.get(subject)
                if (subscription is None or owned is None or owned[1] is not subscription
                        or subscription._closed
                        or not isinstance(dispatcher, asyncio.Task) or dispatcher.done()
                        or subscription._wait_for_msgs_task is not dispatcher
                        or ingress._connection._subs.get(subscription._id) is not subscription):
                    refused()
            for contract in route['peer']['grantRefs']:
                deadlines.append(check_snapshot(route, snapshot, contract))
            for contract in route['publisher']['grantRefs']:
                deadlines.append(check_snapshot(route, snapshot, contract, publisher=True))
            receiver = route['receiver']
            now = datetime.now(timezone.utc)
            for contract, reference in receiver['grantRefs'].items():
                grant = index['grants'].get(_key(reference))
                candidates = [item for item in index['grants'].values() if _active(item, now)
                    and item['callerRef'] == receiver['identityRef']
                    and item['actorRef'] == receiver['identityRef']
                    and item['scope'] == route['scope'] and item['contractId'] == contract
                    and item['resourceId'] == resource.binding.entity_id]
                if (grant not in candidates or grant['decision'] != 'allowed'
                        or grant['delegationRef'] is not None
                        or any(item['decision'] == 'denied' for item in candidates)
                        or approval_reason(index, grant, {'approvalRefs': []},
                            audience={'hubId':resource.binding.hub_id,'serviceId':'storage-owner'},
                            scope=route['scope'], contract=contract, now=now) is not None):
                    refused()
                deadlines.append(datetime.fromisoformat(grant['expiresAt']))
            if not {'federation-work-ingest-legacy', 'federation-work-result-legacy'} <= set(
                    route['publisher']['grantRefs']):
                refused()
            receiver_jwt, _ = local_credential(self._selection, route)
            publisher_jwt, _ = local_credential(self._selection, route, publisher=True)
            from identity.core_work_transport import public_credential
            peer = route['peer']
            peer_claims, _ = public_credential(peer['credentialJWT'], account=route['accountPublicKey'],
                user=peer['userPublicKey'], publish=publication_subjects(route), subscribe=())
            # These tokens have just passed account/key/finite-permission and
            # signature checks. Preserve their expiry in the signed lifetime.
            credential_claims = [peer_claims]
            for token in (receiver_jwt, publisher_jwt):
                body = token.split(b'.')[1]
                credential_claims.append(strict_loads(base64.urlsafe_b64decode(body+b'='*(-len(body)%4))))
            deadlines.extend(datetime.fromtimestamp(claims['exp'], timezone.utc)
                for claims in credential_claims if claims.get('exp', 0))
            routes.append({'route': route, 'sessionNonce': ingress._nonce})
        if not routes:
            refused()
        digest = payload_digest({'purpose': 'agentmux-core-work-mode-v1',
            'generation': self._transport_generation, 'routes': sorted(routes,
                key=lambda item: item['route']['routeId'])})
        return {'mode': 'tm218-core-v1', 'bindingDigest': digest}, min(deadlines)

    async def set_work_subjects(self, subjects):
        self.check()
        wanted = set(subjects)
        allowed = {s for raw in (selected_route(self._selection, rid) for rid in self._routes)
                   for s in raw['workSubjects']}
        if not wanted <= allowed:
            refused()
        for ingress in self._ingresses.values():
            declared = {s for raw in ingress._routes.values() for s in strict_loads(raw)['workSubjects']}
            await ingress.set_work_subjects(wanted & declared)

    def _selector(self, resource, original):
        value = original['payload']['input']
        selector = value.get('coreTransport')
        if (original['contractId'] not in CONTRACTS or type(selector) is not dict
                or set(selector) != {'routeId', 'eventId', 'eventDigest', 'subject', 'signature', 'admissionId'}):
            refused()
        selected = self._routes.get(selector['routeId'])
        if selected is None or selected[0] is not resource:
            refused()
        return selector, selected[1]

    def _load(self, resource, original, snapshot, *, completed=False):
        """Run on this exact Work owner's original DB executor."""
        self.check()
        selector, ingress = self._selector(resource, original)
        source = ingress._source
        if (source._store is not resource._store or source._store.db is not resource._connection
                or source._executor is not resource._source_worker
                or not getattr(source._worker, 'active', False)):
            refused()
        row = resource._store.q1('SELECT v FROM fed_state WHERE k=?',
                                (ingress.key(selector['routeId'], selector['eventId'], selector['admissionId']),))
        if row is None:
            refused()
        raw = row['v'].encode()
        proof, body = ingress.proof(raw, route_id=selector['routeId'],
            event_id=selector['eventId'], event_digest=selector['eventDigest'], admission_id=selector['admissionId'])
        if (proof['signature'] != selector['signature'] or proof['subject'] != selector['subject']
                or proof['authoritySequence'] > snapshot.sequence
                or strict_loads(body) != original['payload']['input']['envelope']):
            refused()
        route = proof['route']
        _, contract, _, _ = body_route(route, body, selector['subject'])
        if contract != original['contractId']:
            refused()
        verify_event(route, body, selector['subject'], selector['signature'])
        deadline = check_snapshot(route, snapshot, contract)
        if not completed:
            if proof['sessionNonce'] != ingress._nonce:
                refused()
            deadline = min(deadline, datetime.fromisoformat(proof['validUntil']))
        if datetime.now(timezone.utc) >= deadline:
            refused()
        return raw, ingress, deadline

    async def admit(self, resource, original_raw, snapshot):
        original = strict_loads(original_raw)
        def load():
            prior = resource._journal.outcome(original['operation']['operationId'],
                                              original['operation']['payloadDigest'])
            completed = prior is not None and prior['reply']['outcome'] in ('applied', 'rejected')
            proof, ingress, deadline = self._load(resource, original, snapshot, completed=completed)
            deadline = min(deadline, datetime.fromisoformat(original['operation']['deadline']))
            admission = object.__new__(CoreWorkAdmission)
            for name, value in (('owner', self), ('resource', resource), ('original', original_raw),
                    ('proof', proof), ('ingress', ingress), ('snapshot', snapshot), ('valid_until', deadline),
                    ('session', ingress._session), ('connection', ingress._connection), ('committed', completed)):
                object.__setattr__(admission, name, value)
            return admission
        return await resource._owner.db(load)

    def check_commit(self, resource, admission):
        if (type(admission) is not CoreWorkAdmission or admission.owner is not self
                or admission.resource is not resource or admission.session is not admission.ingress._session
                or admission.connection is not admission.ingress._connection
                or datetime.now(timezone.utc) >= admission.valid_until):
            refused()
        raw, ingress, _ = self._load(resource, strict_loads(admission.original), admission.snapshot,
                                     completed=admission.committed)
        if raw != admission.proof or ingress is not admission.ingress:
            refused()

    def check_recovery(self, resource, stored, original, snapshot):
        retained = stored['envelope']
        if retained['contractId'] not in CONTRACTS:
            return None
        for name in ('effectiveActorRef', 'caller', 'scope'):
            if retained['operation'][name] != original['operation'][name]:
                refused()
        _, _, deadline = self._load(resource, retained, snapshot, completed=True)
        return deadline

    def begin_policy_pause(self):
        if self._closed:
            refused()
        self._policy_paused = True
        for ingress in self._ingresses.values():
            ingress.begin_policy_pause()
        for publisher in self._publishers.values():
            publisher.begin_policy_pause()

    async def join_policy_pause(self):
        if not self._policy_paused:
            refused()
        await self._roles.join()
        for ingress in self._ingresses.values():
            await ingress.join_policy_pause()
        if self._dispatcher is not None:
            await self._dispatcher.join()
        for publisher in self._publishers.values():
            await publisher.join_policy_pause()
        await self._outbox.join()

    def end_policy_pause(self):
        if self._closed or not self._policy_paused:
            refused()
        for ingress in self._ingresses.values():
            ingress.end_policy_pause()
        for publisher in self._publishers.values():
            publisher.end_policy_pause()
        self._policy_paused = False
        self.check_health()

    async def close(self, *, timeout=5):
        self._closed = True
        if self._closing is None:
            self._closing = asyncio.create_task(self._close(), name='core-work-owner:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('core_work_cleanup_incomplete')
        self._closing.result()

    async def _close(self):
        if self._started is not None:
            await asyncio.gather(self._started, return_exceptions=True)
        if self._outbox_task is not None:
            await asyncio.gather(self._outbox_task, return_exceptions=True)
        if self._roles_task is not None:
            await asyncio.gather(self._roles_task, return_exceptions=True)
        await self._roles.join()
        for ingress in self._ingresses.values():
            await ingress.close(timeout=None)
        if self._dispatcher is not None:
            await self._dispatcher.close()
        for publisher in self._publishers.values():
            await publisher.close(timeout=None)


def check_recovery(resource, stored, original, snapshot):
    if stored['envelope']['contractId'] not in CONTRACTS:
        return None
    owner = getattr(resource, '_core_work_owner', None)
    if type(owner) is not CoreWorkOwner:
        refused()
    return owner.check_recovery(resource, stored, original, snapshot)


def check_disclosure(resource, admission):
    if type(admission) is not CoreWorkAdmission:
        refused()
    admission.owner.check_commit(resource, admission)


def check_disclosure_fence(resource, admission):
    """Check retained custody and time without SQL after the final DB await."""
    if (type(admission) is not CoreWorkAdmission or admission.resource is not resource
            or admission.owner is not getattr(resource, '_core_work_owner', None)
            or admission.owner._closed or admission.owner._policy_paused or admission.ingress._closed
            or admission.ingress._policy_paused
            or admission.session is not admission.ingress._session or admission.session.closing
            or admission.connection is not admission.ingress._connection
            or not admission.connection.is_connected
            or admission.ingress._source._store is not resource._store
            or admission.ingress._source._executor is not resource._source_worker
            or resource._journal.binding != admission.owner._bindings[id(resource)]
            or admission.owner._selection.document != admission.owner._selection_document
            or identity_generation(admission.owner._identity) != admission.owner._identity_generation
            or datetime.now(timezone.utc) >= admission.valid_until):
        refused()
    selector = strict_loads(admission.original)['payload']['input']['coreTransport']
    if (canonical_bytes(selected_route(admission.owner._selection, selector['routeId']))
            != admission.ingress._routes[selector['routeId']]):
        refused()
