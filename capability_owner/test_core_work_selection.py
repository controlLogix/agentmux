"""Selected core Work routes keep channel authority and source custody separate."""
import base64
import copy
import hashlib
import threading
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import AuthoritySnapshot
from identity.core_work_transport import INGEST
from identity.test_authority import ref
from native_security.nats_credentials import _base32
from identity.test_service import _Clock
from .core_work import CoreWorkOwner
from .selected_storage import SelectedStorageHost
from .test_core_work_owner import credential
from .test_selected_work import SelectedWorkPolicyBootstrapTests
from .test_selected_work_lifecycle import SelectedWorkLifecycleTests
from .work import WorkStorageResource


def add_core_route(value, root, channel, scope, record, issued_at, expires_at):
    """Extend the existing fixture with finite, signed receiver and peer grants."""
    repository = channel.get('repository', value['storage']['work']['repository'])
    subject = 'am.work.' + repository['localName'] + '.worker'
    raw, account, receiver_user, _ = credential(31, subscribe=(subject,))
    _, _, peer_user, token = credential(32, publish=(subject,))
    path = root / 'selected-core-receiver.creds'
    path.write_bytes(raw)
    path.chmod(0o600)
    receiver_grants = {contract: ref('core-receiver-' + contract.removeprefix('federation-work-'))
        for contract in (INGEST, 'federation-work-inspect', 'federation-work-outcome')}
    peer_grants = {INGEST: ref('core-peer-ingest-legacy')}
    channel.setdefault('legacyActors', []).append({'identityRef': ref('core-receiver'),
        'transportRef': ref('core-receiver-transport'), 'caller': 'federation', 'grants': receiver_grants})
    route = {'routeId': 'core-second-channel', 'scope': copy.deepcopy(scope),
        'resourceRef': copy.deepcopy(channel['resourceRef']),
        'repository': copy.deepcopy(repository),
        'localNode': value['storage']['work']['localNode'], 'accountPublicKey': account,
        'connection': copy.deepcopy(value['storage']['receivers']['storage']['connection']),
        'workSubjects': [subject], 'resultSubjects': [],
        'receiver': {'identityRef': ref('core-receiver'), 'transportRef': ref('core-receiver-transport'),
            'grantRefs': receiver_grants, 'credentials': {'path': str(path),
                'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'userPublicKey': receiver_user}},
        'peer': {'nodeId': 'remote', 'identityRef': ref('core-peer'), 'transportRef': ref('core-peer-transport'),
            'grantRefs': peer_grants, 'userPublicKey': peer_user, 'credentialJWT': token,
            'publishSubjects': [subject]}}
    route['connection'].pop('jetstreamDomain', None)
    value['coreWorkTransport'] = {'routes': [route]}
    state = record['state']
    transport, grant = copy.deepcopy(state['transports'][0]), copy.deepcopy(state['grants'][0])
    for name, user, grants in (('core-receiver', receiver_user, receiver_grants), ('core-peer', peer_user, peer_grants)):
        state['identities'].append({'ref': ref(name), 'kind': 'service', 'status': 'active',
            'principalId': name, 'externalIdentity': None})
        state['memberships'].append({'ref': ref(name + '-member'), 'identityRef': ref(name),
            'scope': copy.deepcopy(scope), 'status': 'active'})
        state['transports'].append({**transport, 'ref': ref(name + '-transport'), 'identityRef': ref(name),
            'issuerRef': value['identity']['issuer']['issuerRef'], 'method': 'nats-credential-mapping',
            'publicKey': base64.urlsafe_b64encode(_base32(user.encode(), 35)[1:-2]).decode().rstrip('=')})
        for contract, reference in grants.items():
            state['grants'].append({**copy.deepcopy(grant), 'ref': reference, 'callerRef': ref(name),
                'actorRef': ref(name), 'scope': copy.deepcopy(scope), 'resourceId': channel['resourceRef']['id'],
                'contractId': contract, 'decision': 'allowed', 'delegationRef': None,
                'issuedAt': issued_at, 'expiresAt': expires_at})
    return route


def connection():
    """Control only network I/O; selection, credentials and authority stay real."""
    client = AsyncMock()
    client.is_connected = True
    client._subs = {}
    return client


class CoreWorkChannelSelectionTests(SelectedWorkLifecycleTests):
    async def test_second_channel_keeps_shared_default_source_and_exact_route(self):
        await self.host.close(timeout=None)
        self.configure_channels()
        record = strict_loads(self.snapshot.record)
        channel = self.value['storage']['work']['channels'][1]
        route = add_core_route(self.value, self.root, channel, self.other_scope, record,
            self.issuer_start, self.issuer_end)
        snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
        selection = ApplicationServiceSelection(canonical_bytes(self.value))
        host = SelectedStorageHost(selection, identity=self.identity)
        self.addAsyncCleanup(host.close, timeout=None)
        for client in self.clients:
            client.max_payload = 1048576
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch('hub.core_work_transport.new_client', side_effect=lambda **kwargs: connection()):
            await host.start()
            first, second = [item for item in host._resources if type(item) is WorkStorageResource]
            owner, = host._core_work_owners
            ingress = owner._ingresses[id(second)]
            source = first._owner._source
            self.assertIs(second._owner._source, source)
            self.assertIs(ingress._source, source)
            self.assertIs(first._store, second._store)
            self.assertIs(first._connection, second._connection)
            self.assertIs(first._source_worker, second._source_worker)
            self.assertEqual(source._repository, {'localName': 'falcon'})
            self.assertEqual(second.repository, 'other')
            self.assertEqual(strict_loads(second.binding.scope), self.other_scope)
            self.assertEqual(strict_loads(ingress._routes[route['routeId']]), route)
            self.assertIs(owner._routes[route['routeId']][0], second)
            self.assertIn(owner, host._policy_gates())
            self.assertEqual(await second._owner.db(threading.get_ident), await source.db(threading.get_ident))
            owner.check()
            host.check_health()
            with self.assertRaises(ContractError):
                CoreWorkOwner(selection, self.identity, (first,))
            with patch.object(source, '_executor', object()), self.assertRaises(ContractError):
                owner.check_health()
            wrong = copy.deepcopy(self.value)
            wrong['coreWorkTransport']['routes'][0]['scope'] = copy.deepcopy(self.scope)
            with self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(wrong))
            await host.close(timeout=None)
            self.assertTrue(owner._closing.done())
            self.assertTrue(ingress._closing.done())
            self.assertIsNone(source._store)


class CoreWorkSuspendedSelectionTests(SelectedWorkPolicyBootstrapTests):
    def declare_work(self, selected, message):
        descriptor = super().declare_work(selected, message)
        value = selected._selection.policy
        channel = value['storage']['work']['channels'][0]
        # The policy fixture's authority predates the selected service fixture.
        # Enroll that fixture's actual signer as well as the new core actors.
        interval = {key: self.record['state']['transports'][0][key]
            for key in ('issuedAt', 'expiresAt', 'status')}
        self.record['state']['identities'].append({'ref': ref('identity-service'), 'kind': 'service',
            'principalId': 'identity-service', 'status': 'active', 'externalIdentity': None})
        self.record['state']['issuers'].append({'ref': value['identity']['issuer']['issuerRef'],
            'identityRef': ref('identity-service'), 'instanceId': 'instance-one',
            'publicKey': value['identity']['issuer']['publicKey'], **interval})
        add_core_route(value, self.root, channel, value['storage']['scope'], self.record,
            self.record['state']['transports'][0]['issuedAt'], self.record['state']['transports'][0]['expiresAt'])
        selected._selection = ApplicationServiceSelection(canonical_bytes(value))
        return value['storage']['work']

    async def test_genuine_suspended_bootstrap_starts_health_without_live_authority(self):
        async def check(selected, source, descriptor):
            permit = await source._resource_bootstrap(self.transition, 'work')
            self.addAsyncCleanup(permit.close)
            selected._startup_permits['work'] = permit
            await selected._work(descriptor)
            resource = next(item for item in selected._resources if type(item) is WorkStorageResource)
            before = await permit.submit(source._store.q, 'SELECT * FROM work_items')
            with patch('hub.core_work_transport.new_client', side_effect=lambda **kwargs: connection()):
                owner = CoreWorkOwner(selected._selection, selected._identity, (resource,))
            self.addAsyncCleanup(owner.close, timeout=None)
            self.assertTrue(source._policy_suspended)
            self.assertIs(resource._owner._source, source)
            with self.assertRaises(ContractError):
                await owner.start(_bootstrap=object())
            with patch('identity.core_work_transport.datetime', _Clock):
                await owner.start(_bootstrap=permit)
            owner.check_health()
            self.assertTrue(owner._ready)
            with self.assertRaises(ContractError):
                await resource.read(1)
            with self.assertRaises(ContractError):
                await resource._owner.db(source._store.work_create, 'operator', resource.repository,
                    'role:falcon/worker', 'Must not be created during suspended startup')
            with patch.object(resource._owner, '_scope', canonical_bytes({
                    **strict_loads(resource.binding.scope), 'projectId': 'other'})), \
                    self.assertRaises(ContractError):
                permit.check(resource)
            with patch.object(source, '_executor', object()), self.assertRaises(ContractError):
                owner.check_health()
            self.assertEqual(await permit.submit(source._store.q, 'SELECT * FROM work_items'), before)
            permit.expire()
            with self.assertRaises(ContractError):
                permit.check(resource)
            with self.assertRaises(ContractError):
                owner.check()
            await owner.close(timeout=None)
            self.assertTrue(owner._closing.done())
            self.assertTrue(all(ingress._closing.done() for ingress in owner._ingresses.values()))
        await self.run_work_startup(check)
