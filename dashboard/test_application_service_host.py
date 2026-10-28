"""Real service composition with signed enrollment and a controlled broker boundary."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import nkeys
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from nats.js.api import StreamState
from nats.js.errors import APIError, NotFoundError
from application_service_host import ApplicationServiceHost, ApplicationServiceFailure
from definition_commands import LocalDefinitionOutcomeUnconfirmed
from identity.application_service_selection import ApplicationServiceSelection
from identity.local_browser_session import LocalBrowserContext, _CONTEXT_BRAND
import identity.test_application_service_selection as selection_tests
from identity.transitions import transition
from identity.test_authority import SEED
from native_security.nats_credentials import service_policy
from state_owner.backup_host import BackupHost
from state_owner.ledger import owner_subject
from state_owner.test_ledger import FakeJetStream
import test_definition_commands as definitions


def routed_credential(inputs, user_byte):
    policy = service_policy(**inputs)
    account = nkeys.from_seed(nkeys.encode_seed(bytes([1])*32,
        nkeys.PREFIX_BYTE_ACCOUNT))
    user = nkeys.from_seed(nkeys.encode_seed(bytes([user_byte])*32,
        nkeys.PREFIX_BYTE_USER))
    try:
        now = int(datetime.now(timezone.utc).timestamp())
        claims = {'iss': account.public_key.decode(), 'sub': user.public_key.decode(),
            'iat': now, 'exp': now+3600, 'nats': {'type': 'user', 'version': 2,
            'pub': {'allow': list(policy.publish_subjects)},
            'sub': {'allow': list(policy.subscribe_subjects)},
            'resp': policy.response_permissions}}
        encode = lambda value: base64.urlsafe_b64encode(json.dumps(
            value, separators=(',', ':')).encode()).rstrip(b'=')
        signed = encode({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encode(claims)
        token = signed + b'.' + base64.urlsafe_b64encode(
            account.sign(signed)).rstrip(b'=')
        return (b'-----BEGIN NATS USER JWT-----\n' + token +
            b'\n------END NATS USER JWT------\n\n'
            b'-----BEGIN USER NKEY SEED-----\n' + user.seed +
            b'\n------END USER NKEY SEED------\n')
    finally:
        account.wipe()
        user.wipe()


class RoutedJetStream:
    """Offline exact multi-stream broker boundary for routed host composition."""
    def __init__(self, created):
        self.created = created
        self.configs, self.messages = {}, {}
        self.objects = definitions.Objects()
        self.selected_domain = None

    async def add_stream(self, config):
        if config.name in self.configs:
            raise AssertionError('duplicate routed stream')
        self.configs[config.name] = config
        self.messages[config.name] = []
        return await self.stream_info(config.name)

    async def stream_info(self, stream):
        if stream not in self.configs:
            raise NotFoundError()
        messages = self.messages[stream]
        return SimpleNamespace(config=self.configs[stream], created=self.created,
            state=StreamState(messages=len(messages),
                bytes=sum(len(item.data) for item in messages),
                first_seq=1 if messages else 0, last_seq=len(messages),
                num_deleted=0, consumer_count=0))

    async def publish(self, subject, data, *, headers):
        stream = headers['Nats-Expected-Stream']
        messages = self.messages[stream]
        if int(headers['Nats-Expected-Last-Subject-Sequence']) != len(messages):
            raise APIError(err_code=10071)
        item = SimpleNamespace(subject=subject, data=data, seq=len(messages)+1)
        messages.append(item)
        return SimpleNamespace(stream=stream, seq=item.seq, duplicate=False)

    async def get_msg(self, stream, *, subject=None, seq=None, direct=False):
        if stream == 'OBJ_bucket':
            return await self.objects.get_msg(stream, subject=subject, seq=seq,
                                              direct=direct)
        messages = self.messages.get(stream, [])
        if not messages or (seq is not None and seq > len(messages)):
            raise NotFoundError()
        return messages[seq-1 if seq is not None else -1]

    async def object_store(self, bucket):
        if bucket != 'bucket':
            raise AssertionError('wrong routed artifact bucket')
        return self.objects


class Client:
    def __init__(self, jetstream):
        self.js = jetstream
        self.is_connected = False
        self.options = None
        self.subscriptions = []
        self.publish = AsyncMock()

    async def connect(self, **options):
        self.options = options
        self.is_connected = True

    def jetstream(self, **options):
        self.js.selected_domain = options.get('domain')
        return self.js

    async def subscribe(self, subject, **options):
        subscription = SimpleNamespace(subject=subject, callback=options['cb'], unsubscribe=AsyncMock(), drain=AsyncMock())
        self.subscriptions.append(subscription)
        self._agentmux_session.own_subscription(subscription)
        self._agentmux_session.check_open()
        return subscription

    async def flush(self):
        pass

    async def close(self):
        self.is_connected = False
        if self.options is not None:
            await self.options['closed_cb']()


class JetStream(FakeJetStream):
    async def publish(self, subject, data, *, headers):
        selected = headers['Nats-Expected-Stream']
        result = await super().publish(subject, data, headers=dict(headers, **{'Nats-Expected-Stream': 'OWNER'}))
        result.stream = selected
        return result

    async def object_store(self, bucket):
        assert bucket == 'bucket'
        return self.objects

    async def get_msg(self, stream, **options):
        if stream == 'OBJ_bucket':
            return await self.objects.get_msg(stream, **options)
        return await super().get_msg(stream, **options)


class HostComposition(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        selection_tests.ServiceSelectionTests.setUp(self)
        HostComposition.prepare_services(self)

    def prepare_services(self):
        """Provision baseline services for an already prepared selection."""
        if getattr(self, 'include_integration', False):
            selection_tests.ServiceSelectionTests.add_integration(self)
            integration = self.value['integration']
            integration['credentials']['path'] = str(self.root/'integration.creds')
            integration['ledger']['checkpoint'] = {'path': str(self.root/'integration-checkpoint'),
                                                   'commitRef': selection_tests.ref('integration-checkpoint')}
            integration['artifacts']['bucket'] = 'bucket'
        self.roles = ('identity', 'definitions', 'integration') if self.value.get('integration') else ('identity', 'definitions')
        if self.value.get('task'):
            self.roles += ('task',)
        self.value['definitions']['artifacts']['bucket'] = 'bucket'
        for path in self.value['definitions']['directories'].values():
            Path(path).mkdir(mode=0o700, exist_ok=True)
        self.probe = definitions.DefinitionCommandTests()
        self.probe.setUp()
        self.addCleanup(self.probe.tmp.cleanup)
        for index, role in enumerate(self.roles):
            selected = self.value[role]
            policy = service_policy(role=role, hub_id='hub-one', entity_id=selected['ledger']['entityId'],
                scope=selected['ledger']['scope'], stream=selected['ledger']['stream'],
                reply_prefix=selected['credentials']['replyPrefix'], jetstream_domain=selected['connection']['jetstreamDomain'],
                artifact_bucket=(selected['artifacts']['bucket'] if selected.get('artifacts') else None))
            account = nkeys.from_seed(nkeys.encode_seed(bytes([1])*32, nkeys.PREFIX_BYTE_ACCOUNT))
            user = nkeys.from_seed(nkeys.encode_seed(bytes([10+index])*32, nkeys.PREFIX_BYTE_USER))
            try:
                now = int(datetime.now(timezone.utc).timestamp())
                claims = {'iss': account.public_key.decode(), 'sub': user.public_key.decode(), 'iat': now, 'exp': now+3600,
                    'nats': {'type': 'user', 'version': 2, 'pub': {'allow': list(policy.publish_subjects)},
                    'sub': {'allow': list(policy.subscribe_subjects)}, 'resp': policy.response_permissions}}
                encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
                signed = encode({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encode(claims)
                token = signed + b'.' + base64.urlsafe_b64encode(account.sign(signed)).rstrip(b'=')
                raw = (b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n'
                    b'-----BEGIN USER NKEY SEED-----\n' + user.seed + b'\n------END USER NKEY SEED------\n')
                credentials = selected['credentials']
                Path(credentials['path']).write_bytes(raw)
                Path(credentials['path']).chmod(0o600)
                credentials.update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),
                    accountPublicKey=account.public_key.decode(), userPublicKey=user.public_key.decode())
            finally:
                account.wipe()
                user.wipe()
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        backup = self.value['identity']['backup']
        backup_host = BackupHost(*(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self.selection.binding('identity'),
            stream_identity=self.selection.stream_identity('identity'))
        backup_host.enroll_key(backup['keyId'])  # Explicit test setup, before host startup.
        self.clients = []
        for role in self.roles:
            selected = self.value[role]
            js = JetStream(self.selection.retention(role))
            js.config = self.selection.retention(role).stream_config(stream=selected['ledger']['stream'],
                subject=owner_subject(self.selection.binding(role)))
            js.objects = definitions.Objects()
            self.clients.append(Client(js))
        record = copy.deepcopy(self.probe.authority_record)
        state = record['state']
        if self.value.get('integration'):
            selected = self.value['integration']
            identity = {'ref': selection_tests.ref('integration-service'), 'kind': 'service', 'status': 'active',
                        'principalId': 'integration-service', 'externalIdentity': None}
            issuer = {'ref': selected['issuer']['issuerRef'], 'identityRef': identity['ref'], 'status': 'active',
                      'instanceId': 'instance-one', 'publicKey': selected['issuer']['publicKey'],
                      'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end}
            proof = {'purpose': 'agentmux-enrollment-possession-v1', 'profileId': 'profile-one',
                     'authorityId': 'authority-one', 'credential': issuer}
            self.payloads.append({'authorityId': 'authority-one', 'identity': identity, 'issuers': [{'record': issuer,
                'proof': sign_claims(proof, self.selection.load_signing_seed('integration'))}], 'transports': []})
        for payload in self.payloads:
            state = transition(state, 'identity-enroll', payload, hub_id='hub-one')
        state['transports'][0]['issuerRef'] = self.value['definitions']['issuer']['issuerRef']
        record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None, state=state)
        record['operation'].update(expectedVersion=0, scope=self.value['identity']['ledger']['scope'])
        self.clients[0].js.messages = [SimpleNamespace(subject=owner_subject(self.selection.binding('identity')),
                                                       seq=1, data=canonical_bytes(record))]

    async def asyncSetUp(self):
        self.host = ApplicationServiceHost(self.selection)
        self.addAsyncCleanup(self.host.close)

    def request(self):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': self.probe.env['ingressAttestation']['claims']['authenticatedTransportRef'],
            'grantRef': self.probe.env['operation']['grantRef'], 'operationId': 'composed-save', 'expectedVersion': 0,
            'contractId': 'definition-save', 'payload': self.probe.env['payload'], 'approvalRefs': [],
            'issuedAt': (now-timedelta(seconds=1)).isoformat().replace('+00:00','Z'),
            'expiresAt': (now+timedelta(seconds=50)).isoformat().replace('+00:00','Z'),
            'replySubject': '_INBOX.application_client_0001.reply'}
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})

    async def test_selection_runs_actual_owners_and_concrete_checkpoint_custody(self):
        with patch('application_service_host.new_client', side_effect=self.clients) as create:
            await self.host.start()
        self.host.check_health()
        self.assertIsNone(self.host.health_stage)
        with patch.object(self.host._identity, 'check_health', side_effect=ContractError('identity_unavailable')):
            with self.assertRaises(ContractError):
                self.host.check_health()
        self.assertEqual(self.host.health_stage, 'identity')
        self.host.check_health()
        self.assertIsNone(self.host.health_stage)
        self.assertEqual(create.call_count, 2)
        for role, client in zip(('identity','definitions'), self.clients):
            self.assertEqual(client.js.selected_domain, 'enrolled-domain')
            self.assertEqual(client.options['inbox_prefix'], self.value[role]['credentials']['replyPrefix'])
            self.assertFalse(client.options['allow_reconnect'])
            self.assertTrue(client.options['tls_handshake_first'])
        request = self.request()
        command = self.clients[1].subscriptions[0]
        await command.callback(SimpleNamespace(data=request, reply=strict_loads(request)['claims']['replySubject']))
        response = self.clients[1].publish.await_args.args[1]
        self.assertEqual(strict_loads(response)['claims']['receipt']['status'], 'intent-committed')
        self.assertTrue((self.root/'project/.agentmux/agents/worker.md').exists())
        for service in (self.host._identity, self.host._definitions):
            service._cadence._dirty_since = 0
            service._checkpoint_if_due()
            await service._checkpoint_work
        for role in ('identity','definitions'):
            receipt = await self.host._checkpoints[role].resolve()
            self.assertEqual(receipt.receipt.cursor, 1)
        await self.host.close()
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_selected_dashboard_database_builds_the_authenticated_owner(self):
        database = self.root / 'private-dashboard.db'
        self.value['dashboard'] = {
            'scope': copy.deepcopy(self.value['definitions']['ledger']['scope']),
            'resourceRef': selection_tests.ref('dashboard-one'),
            'databasePath': str(database),
        }
        await self.host.close()
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        self.host = ApplicationServiceHost(self.selection)
        self.addAsyncCleanup(self.host.close)
        with patch('application_service_host.ccstore.DB_PATH', database), \
                patch('application_service_host.new_client', side_effect=self.clients):
            await self.host.start()
            self.assertIsNotNone(self.host._dashboard)
            self.assertEqual(self.host._dashboard._scope,
                             canonical_bytes(self.value['dashboard']['scope']))
            self.assertEqual(self.host._dashboard._resource,
                             canonical_bytes(self.value['dashboard']['resourceRef']))
            self.assertTrue(database.is_file())

    async def test_close_fences_receivers_before_waiting_for_startup(self):
        entered, release = asyncio.Event(), asyncio.Event()
        service = SimpleNamespace(_closed=False, close=AsyncMock())
        self.host._services.append(service)
        async def startup():
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await release.wait()
        self.host._startup = asyncio.create_task(startup())
        await entered.wait()
        closing = asyncio.create_task(self.host.close())
        await asyncio.sleep(.01)
        self.assertTrue(service._closed)
        self.assertFalse(closing.done())
        release.set()
        await closing
        service.close.assert_awaited_once()

    async def test_parent_fence_stops_nested_secret_receivers_immediately(self):
        from capability_owner.secret_host import SecretUseHost
        secret = object.__new__(SecretUseHost)
        secret._closed, secret._ready = False, True
        receiver = SimpleNamespace(_closed=False)
        secret._receivers = [receiver]
        secret.close = AsyncMock()
        self.host._secret_use = secret
        self.host._services.append(secret)
        self.host.fence()
        self.assertTrue(receiver._closed)
        self.assertFalse(secret._ready)

    async def test_terminal_cleanup_failure_can_retry_same_owners(self):
        service = SimpleNamespace(_closed=False, close=AsyncMock(side_effect=[OSError('private cleanup'), None]))
        client = SimpleNamespace(close=AsyncMock())
        self.host._services.append(service)
        self.host._clients.append(client)
        with self.assertRaises(ApplicationServiceFailure):
            await self.host.close()
        original = self.host._closing
        client.close.assert_not_awaited()
        await self.host.close()
        self.assertIsNot(self.host._closing, original)
        self.assertEqual(service.close.await_count, 2)
        client.close.assert_awaited_once()

    async def test_ended_lifetime_opens_no_resources(self):
        stop = asyncio.Event()
        stop.set()
        with patch('application_service_host.new_client') as create:
            await self.host.run(stop=stop)
        create.assert_not_called()
        self.assertEqual(self.host._histories, [])

    async def test_connection_loss_fences_all_receivers_before_returning(self):
        services = [SimpleNamespace(_closed=False, close=AsyncMock()) for _ in range(3)]
        self.host._services.extend(services)
        await self.host._lost()
        self.assertTrue(all(service._closed for service in services))
        self.assertTrue(self.host._closed)
        self.assertFalse(self.host._ready)

    async def test_browser_write_timeout_keeps_original_operation_until_completion(self):
        await self.host.close()
        self.host = ApplicationServiceHost(self.selection, browser_write_timeout=.5)
        self.addAsyncCleanup(self.host.close)
        with patch('application_service_host.new_client', side_effect=self.clients):
            await self.host.start()
        context = LocalBrowserContext(canonical_bytes(selection_tests.ref('human')),
            self.selection.binding('definitions').scope,
            canonical_bytes({'id': 'authority-one', 'ownerHubId': 'hub-one', 'revision': 1}),
            1, self.probe.env['operation']['deadline'], _CONTEXT_BRAND)
        self.host._browser_auth.authorize = AsyncMock(return_value=context)
        owner = self.host._definitions.owner
        execute_effect = owner._execute_effect
        handle = self.host._definitions.handle_local_browser
        entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        effects = 0

        async def delayed_effect(*args, **kwargs):
            nonlocal effects
            result = await execute_effect(*args, **kwargs)
            effects += 1
            entered.set()
            await release.wait()
            return result

        async def tracked_handle(*args, **kwargs):
            try:
                return await handle(*args, **kwargs)
            finally:
                finished.set()

        body = {'name': 'worker', 'scope': 'repo', 'description': 'Review changes'}
        with patch.object(owner, '_execute_effect', delayed_effect), \
                patch.object(self.host._definitions, 'handle_local_browser', tracked_handle):
            request = asyncio.create_task(asyncio.to_thread(self.host.browser_definition,
                'cookie', 'csrf', method='POST', target='/api/board/agentdef',
                host=self.host._browser_origin.removeprefix('http://'),
                origin=self.host._browser_origin, body=body))
            await asyncio.wait_for(entered.wait(), 3)
            with self.assertRaises(LocalDefinitionOutcomeUnconfirmed) as raised:
                await request
            operation_id = raised.exception.operation_id
            retained = strict_loads(self.clients[1].js.messages[0].data)
            self.assertEqual(retained['operation']['operationId'], operation_id)
            self.assertEqual(len(self.clients[1].js.messages), 1)
            release.set()
            await asyncio.wait_for(finished.wait(), 3)
        self.assertEqual(effects, 1)
        self.assertEqual(len(self.clients[1].js.messages), 2)
        completion = strict_loads(self.clients[1].js.messages[1].data)
        self.assertEqual(completion['authorizationDecision']['contractId'],
                         'definition-effect-complete')
        self.assertTrue((self.root/'project/.agentmux/agents/worker.md').exists())


class IntegrationComposition(unittest.IsolatedAsyncioTestCase):
    include_integration = True
    setUp = HostComposition.setUp
    asyncSetUp = HostComposition.asyncSetUp

    async def prepare_routed_integration(self):
        from integration_owner.provisioning import IntegrationEffectProvisioner
        routing = {}
        for field, name in (('resourceDirectory', 'effect-resources'),
                ('inventoryDirectory', 'effect-inventory'),
                ('credentialDirectory', 'route-credentials')):
            path = self.root / name
            path.mkdir(mode=0o700)
            routing[field] = str(path)
        identity_backup = self.value['identity']['backup']
        routing.update(backupKeyDirectory=identity_backup['keyDirectory'],
            backupKeyId=identity_backup['keyId'],
            backupDestinationId='integration-backup')
        self.value['integration']['routing'] = routing
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        selected = self.value['integration']
        created = datetime(2026, 10, 17, tzinfo=timezone.utc)
        admin = RoutedJetStream(created)
        issued = []
        async def issue(inputs):
            issued.append(inputs)
            return routed_credential(inputs, 80 + len(issued))
        owner = IntegrationEffectProvisioner(admin, hub_id='hub-one',
            scope=selected['ledger']['scope'], base_stream=selected['ledger']['stream'],
            artifact_bucket=selected['artifacts']['bucket'],
            reply_prefix=selected['credentials']['replyPrefix'],
            jetstream_domain=selected['connection']['jetstreamDomain'],
            account_public_key=selected['credentials']['accountPublicKey'],
            retention=self.selection.retention('integration'),
            max_history_records=selected['ledger']['history']['maxRecords'],
            max_history_bytes=selected['ledger']['history']['maxBytes'],
            resource_directory=routing['resourceDirectory'],
            inventory_directory=routing['inventoryDirectory'],
            credential_directory=routing['credentialDirectory'],
            backup_key_directory=routing['backupKeyDirectory'],
            backup_key_id=routing['backupKeyId'],
            backup_destination_id=routing['backupDestinationId'],
            commit_ref=selected['ledger']['checkpoint']['commitRef'],
            credential_issuer=issue)
        first = await owner.provision('operation-one')
        first.history.close()
        await self.host.close()
        self.host = ApplicationServiceHost(self.selection)
        self.addAsyncCleanup(self.host.close)
        self.clients[2] = Client(admin)
        self.clients.append(Client(admin))
        return owner, admin, issued

    async def select_github_enrollment(self):
        from integration_owner.github_worker import pin_github_client, write_github_enrollment
        binary = self.root / 'gh-never-executed'
        binary.write_bytes(b'synthetic executable; must never run')
        binary.chmod(0o700)
        config = self.root / 'gh-config'
        config.mkdir(mode=0o700)
        hosts = config / 'hosts.yml'
        hosts.write_bytes(b'synthetic credential store; never opened')
        hosts.chmod(0o600)
        pin = pin_github_client(self.value['integration']['credentialRef'],
                               executable=binary, config_dir=config)
        path = self.root / 'github-enrollment.json'
        digest = write_github_enrollment(path, pin)
        self.value['integration']['credentialEnrollment'] = {'path': str(path), 'sha256': digest}
        await self.host.close()
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        self.host = ApplicationServiceHost(self.selection)
        self.addAsyncCleanup(self.host.close)
        return config, path

    async def test_selected_github_pin_builds_worker_without_running_client(self):
        from integration_owner.github_worker import GithubWorker
        await self.select_github_enrollment()
        with patch('application_service_host.new_client', side_effect=self.clients) as create, \
                patch('integration_owner.github_worker._capture_process',
                      side_effect=AssertionError('startup must not execute gh')) as process:
            await self.host.start()
        self.assertEqual(create.call_count, 3)
        self.assertIsInstance(self.host._integration.owner._worker, GithubWorker)
        process.assert_not_called()
        self.host.check_health()
        await self.host.close()
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_changed_github_pin_refuses_before_integration_connection(self):
        config, _ = await self.select_github_enrollment()
        (config / 'config.yml').write_bytes(b'http_unix_socket: /fixture/redirect\n')
        (config / 'config.yml').chmod(0o600)
        with patch('application_service_host.new_client', side_effect=self.clients) as create:
            with self.assertRaisesRegex(ApplicationServiceFailure, '^application_service_start_unconfirmed$'):
                await self.host.start()
        self.assertEqual(create.call_count, 2)
        self.assertIsNone(self.host._integration)
        await self.host.close()
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_optional_selected_integration_joins_all_actual_roles(self):
        with patch('application_service_host.new_client', side_effect=self.clients) as create:
            await self.host.start()
        self.host.check_health()
        self.assertEqual(create.call_count, 3)
        self.assertEqual(len(self.host._services), 3)
        service = self.host._integration
        self.assertTrue(service.ledger.completion_budget_required)
        self.assertEqual(self.clients[2].subscriptions[0].subject, service.subject)
        self.assertEqual(self.clients[2].js.selected_domain, 'enrolled-domain')
        await self.host.close()
        self.assertTrue(service._closed)
        self.assertTrue(service.owner._closed)
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_preprovisioned_router_reconnects_on_complete_generation(self):
        from integration_owner.intent import effect_id
        from integration_owner.service import IntegrationRouterService
        owner, admin, issued = await self.prepare_routed_integration()
        with patch('application_service_host.new_client', side_effect=self.clients) as create:
            await self.host.start()
            self.assertEqual(create.call_count, 3)
            router = self.host._integration
            first_client = self.host._integration_client
            self.assertIsInstance(router, IntegrationRouterService)
            self.assertEqual(router.subject,
                'amx.v1.h.hub-one.o.org-one.integrations.*.command')
            first_id = effect_id(self.value['integration']['ledger']['scope'],
                                 'operation-one')
            first_service = await router._service(first_id, 'operation-one')
            self.assertEqual(first_service._binding.entity_id, first_id)
            self.assertIn(first_service.ledger._stream, admin.configs)
            self.assertIsNotNone(first_service._backup_lifecycle)
            first_service._backup_lifecycle.check()

            second = await owner.provision('operation-two')
            second.history.close()
            self.assertEqual(len(issued), 2)
            self.host._integration_route_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await self.host._integration_route_task
            self.host._integration_route_task = None
            second_id = effect_id(self.value['integration']['ledger']['scope'],
                                  'operation-two')
            with self.assertRaisesRegex(ContractError,
                                        '^integration_route_generation_changed$'):
                await router._service(second_id, 'operation-two')
            self.assertTrue(self.host._integration_route_changed.is_set())
            self.assertTrue(await self.host._refresh_integration_route())
            self.assertTrue(router._closed)
            self.assertTrue(first_service._backup_lifecycle._closed)
            self.assertFalse(first_client.is_connected)
            self.assertIsNot(self.host._integration, router)
            self.assertEqual(create.call_count, 4)
            second_service = await self.host._integration._service(
                second_id, 'operation-two')
            self.assertEqual(second_service._binding.entity_id, second_id)
            self.assertEqual(set(self.host._integration_route.streams),
                             set(admin.configs))
        await self.host.close()
        self.assertTrue(all(not client.is_connected for client in self.clients))


class PolicyComposition(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = HostComposition.asyncSetUp

    def setUp(self):
        from identity.test_policy_selection import add_policy
        HostComposition.setUp(self)
        payload = add_policy(self)
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        current = strict_loads(self.clients[0].js.messages[0].data)
        current['state'] = transition(current['state'], 'identity-enroll', payload, hub_id='hub-one')
        current['state']['identities'].append({'ref': selection_tests.ref('plugin'), 'kind': 'plugin',
            'status': 'active', 'principalId': 'plugin-one', 'externalIdentity': None})
        self.clients[0].js.messages[0].data = canonical_bytes(current)
        selected = self.value['policy']
        policy = self.selection.retention('policy')
        js = JetStream(policy)
        js.config = policy.stream_config(stream=selected['ledger']['stream'],
            subject=owner_subject(self.selection.binding('policy')))
        connection = Client(js)
        connection.max_payload = 98304
        self.clients.append(connection)
        backup = selected['backup']
        host = BackupHost(*(backup[key] for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self.selection.binding('policy'),
            stream_identity=self.selection.stream_identity('policy'))
        host.enroll_key(backup['keyId'])

    async def test_selected_policy_starts_actual_owner_and_joins_before_identity(self):
        from capability_owner.policy_host import PolicyHost
        with patch('application_service_host.new_client', side_effect=self.clients) as create:
            await self.host.start()
        self.host.check_health()
        self.assertEqual(create.call_count, 3)
        policy = self.host._policy_service
        self.assertIsInstance(policy, PolicyHost)
        self.assertIs(policy._authority, self.host._identity.reader)
        self.assertEqual(self.clients[2].subscriptions[0].subject, policy.service.subject)
        self.assertTrue(policy.ledger.completion_budget_required)
        self.assertEqual(self.clients[2].js.messages, [])
        await self.host.close()
        self.assertTrue(policy._closing.done())
        self.assertTrue(policy.service._cleanup_task.done())
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_missing_selected_policy_key_keeps_application_unready(self):
        Path(self.value['policy']['issuer']['keyFile']['path']).unlink()
        with patch('application_service_host.new_client', side_effect=self.clients):
            with self.assertRaises(ApplicationServiceFailure):
                await self.host.start()
        self.assertFalse(self.host._ready)
        self.assertIsNone(self.host._policy_service)
        self.assertFalse(self.clients[2].is_connected)
        await self.host.close()

