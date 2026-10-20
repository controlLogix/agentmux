"""Optional configuration activation through the actual application host."""
import asyncio
import copy
import hashlib
import base64
from pathlib import Path
import unittest
from unittest.mock import patch
from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from identity.test_authority import ref
from identity.test_native_bridge import native_row
from identity.transitions import transition
from native_security.nats_credentials import service_policy
from native_security.test_nats_service_credentials import signed_service
from state_owner.backup_host import BackupHost
from state_owner.ledger import owner_subject
import test_application_service_host as support


class ConfigurationComposition(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = support.HostComposition.asyncSetUp

    def setUp(self):
        support.HostComposition.setUp(self)
        directory = self.root / 'configuration'
        directory.mkdir(mode=0o700)
        selected = copy.deepcopy(self.value['identity'])
        payload, receipt = provision_application_service_issuer(directory / 'issuer.key',
            service_id='configuration-owner', profile_id='profile-one', authority_id='authority-one',
            instance_id='instance-one', identity={'ref': ref('configuration-service'), 'kind': 'service',
                'status': 'active', 'principalId': 'configuration-service', 'externalIdentity': None},
            issuer_ref=ref('configuration-issuer'), issued_at=self.issuer_start, expires_at=self.issuer_end)
        selected['issuer'] = {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
            'issuerRef': ref('configuration-issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']}
        selected['ledger'].update(entityId='configuration-one', stream='CONFIGURATION')
        selected['ledger']['streamIdentity']['minimumSequence'] = 0
        selected['ledger']['history']['path'] = str(directory / 'history.sqlite')
        selected['ledger']['checkpoint'] = {'path': str(directory / 'checkpoint'), 'commitRef': ref('configuration-checkpoint')}
        selected['backup']['destinationId'] = 'configuration-backup'
        for name in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
            path = directory / name
            path.mkdir(mode=0o700)
            selected['backup'][name] = str(path)
        schema = b'{"type":"object"}'
        schema_path = directory / 'config.json'
        schema_path.write_bytes(schema)
        schema_path.chmod(0o600)
        selected.update(owner=native_row()['owner'], schemaRef='config.json',
            requesterReplyPrefix='_INBOX.configuration_caller_0001',
            schemaResources={'config.json': {'path': str(schema_path), 'sha256': 'sha256:' + hashlib.sha256(schema).hexdigest()}})
        producer_seed = bytes([23]) * 32
        producer_key = directory / 'producer.key'
        producer_key.write_bytes(producer_seed)
        producer_key.chmod(0o600)
        producer_public = base64.urlsafe_b64encode(bytes(SigningKey(producer_seed).verify_key)).decode().rstrip('=')
        selected['producer'] = {'identityRef': ref('configuration-service'), 'transportRef': ref('configuration-producer-transport'),
            'grantRef': ref('configuration-producer-grant'), 'publicKey': producer_public,
            'keyFile': {'path': str(producer_key), 'sha256': 'sha256:' + hashlib.sha256(producer_seed).hexdigest()}}
        selected['credentials']['replyPrefix'] = '_INBOX.configuration_service_0001'
        options = dict(role='configuration', hub_id='hub-one', entity_id='configuration-one',
            scope=selected['ledger']['scope'], stream='CONFIGURATION',
            reply_prefix=selected['credentials']['replyPrefix'], jetstream_domain=selected['connection']['jetstreamDomain'])
        raw, account, user = signed_service(options)
        credential_path = directory / 'user.creds'
        credential_path.write_bytes(raw)
        credential_path.chmod(0o600)
        selected['credentials'].update(path=str(credential_path), sha256='sha256:' + hashlib.sha256(raw).hexdigest(),
                                       accountPublicKey=account, userPublicKey=user)
        self.value['configuration'] = selected
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        backup = selected['backup']
        custody = BackupHost(*(backup[name] for name in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self.selection.binding('configuration'),
            stream_identity=self.selection.stream_identity('configuration'))
        custody.enroll_key(backup['keyId'])
        js = support.JetStream(self.selection.retention('configuration'))
        js.config = self.selection.retention('configuration').stream_config(stream='CONFIGURATION',
            subject=owner_subject(self.selection.binding('configuration')))
        self.clients.append(support.Client(js))
        record = strict_loads(self.clients[0].js.messages[0].data)
        record['state'] = transition(record['state'], 'identity-enroll', payload, hub_id='hub-one')
        state = record['state']
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('configuration-producer-transport'), identityRef=ref('configuration-service'),
            issuerRef=ref('configuration-issuer'), publicKey=producer_public)
        state['transports'].append(transport)
        membership = copy.deepcopy(state['memberships'][0])
        membership.update(ref=ref('configuration-producer-member'), identityRef=ref('configuration-service'),
            scope=selected['ledger']['scope'])
        state['memberships'].append(membership)
        grant = copy.deepcopy(state['grants'][0])
        grant.update(ref=ref('configuration-producer-grant'), callerRef=ref('configuration-service'),
            actorRef=ref('configuration-service'), scope=selected['ledger']['scope'],
            contractId='configuration-change', resourceId='configuration-one', definitionTarget=None)
        state['grants'].append(grant)
        self.clients[0].js.messages[0].data = canonical_bytes(record)

    async def start_host(self):
        with patch('application_service_host.new_client', side_effect=self.clients):
            await self.host.start()

    async def test_selected_configuration_starts_with_exact_enrollment_and_health(self):
        await self.start_host()
        configuration = self.host._configuration
        self.assertIn(configuration, self.host._services)
        self.assertIs(configuration.owner._authority, self.host._identity.reader)
        self.assertEqual(configuration.subject, service_policy(**self.selection.service_policy_inputs('configuration')).command_subject)
        self.assertEqual(configuration._reply_prefix, self.value['configuration']['requesterReplyPrefix'] + '.')
        self.assertEqual(self.clients[2].options['inbox_prefix'], self.value['configuration']['credentials']['replyPrefix'])
        self.assertEqual(self.clients[2].js.selected_domain, 'enrolled-domain')
        self.host.check_health()
        configuration._closed = True
        with self.assertRaisesRegex(ContractError, '^configuration_host_unavailable$'):
            self.host.check_health()
        await self.host.close()
        self.assertTrue(configuration.done.is_set())
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_aggregate_close_joins_existing_configuration_close_before_borrowed_resources(self):
        await self.start_host()
        configuration = self.host._configuration
        entered, release = asyncio.Event(), asyncio.Event()
        original = configuration.owner.close
        async def close(*, timeout=3):
            entered.set()
            await release.wait()
            await original(timeout=timeout)
        with patch.object(configuration.owner, 'close', side_effect=close):
            with self.assertRaisesRegex(ContractError, '^configuration_host_cleanup_incomplete$'):
                await configuration.close(timeout=0.01)
            await entered.wait()
            retained = configuration._closing
            aggregate = asyncio.create_task(self.host.close())
            try:
                await asyncio.sleep(0.01)
                self.assertFalse(aggregate.done())
                self.assertIs(configuration._closing, retained)
                self.assertTrue(all(client.is_connected for client in self.clients))
                self.assertTrue(all(not history._closed for history in self.host._histories))
            finally:
                release.set()
                await aggregate
        self.assertTrue(retained.done())
        self.assertTrue(configuration.done.is_set())
        self.assertTrue(all(history._closed for history in self.host._histories))

    async def test_startup_cancellation_retains_original_configuration_subscription(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.clients[2].subscribe
        async def subscribe(subject, **options):
            subscription = await original(subject, **options)
            entered.set()
            await release.wait()
            return subscription
        self.clients[2].subscribe = subscribe
        with patch('application_service_host.new_client', side_effect=self.clients):
            startup = asyncio.create_task(self.host.start())
            await asyncio.wait_for(entered.wait(), 3)
            configuration = self.host._configuration
            allocation = configuration.owner._subscribe_task
            closing = asyncio.create_task(self.host.close())
            try:
                await asyncio.sleep(0.01)
                self.assertIn(configuration, self.host._services)
                self.assertFalse(closing.done())
                self.assertFalse(allocation.done())
                self.assertTrue(all(not history._closed for history in self.host._histories))
            finally:
                release.set()
                results = await asyncio.gather(startup, closing, return_exceptions=True)
        self.assertIsInstance(results[0], support.ApplicationServiceFailure)
        self.assertIsNone(results[1])
        self.assertIs(configuration.owner._subscribe_task, allocation)
        self.assertTrue(allocation.done())
        self.assertFalse(allocation.cancelled())
        self.assertTrue(configuration.done.is_set())
        self.assertTrue(all(history._closed for history in self.host._histories))

    async def test_missing_configuration_key_cannot_report_application_ready(self):
        backup = self.value['configuration']['backup']
        (Path(backup['keyDirectory']) / ('key-' + backup['keyId'] + '.key')).unlink()
        with self.assertRaises(support.ApplicationServiceFailure):
            await self.start_host()
        self.assertFalse(self.host._ready)
        self.assertIsNone(self.host._configuration)
        self.assertFalse(self.clients[2].is_connected)
        await self.host.close()
