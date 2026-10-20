"""Coordinated native subscription and registered foreground service checks.

Reuse the existing TLS/JWT broker and private child handoff. This check requires
the shared live slot; importing this module never starts a broker or Go process.
"""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from capability_owner import test_live as tls_fixture
from capability_owner.test_live import packet, stamp
from identity.service import IdentityService
from identity.configuration_events import ConfigurationEventProducer
from identity.application_enrollment import _read_material
from identity.native_host_selection import NativeHostSelection, write_native_host_selection
from identity.test_authority import ref, SEED
from identity.test_commands import command_fixture
from identity.test_native_bridge import HOST_SEED, native_row
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.configuration_events import ConfigurationEventRoute
from state_owner.configuration_host import ConfigurationHost
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.test_configuration_activation import enroll_event_producer, event_producer, PRODUCER_SEED
from state_owner.test_ledger import record
from capability_owner.resources import RetainedResource
from capability_owner.reply_service import CapabilityReplyService
from tests.storage.run import Broker


class LiveConfigurationSubscriptionTests(unittest.IsolatedAsyncioTestCase):
    _configure_tls_and_users = tls_fixture.LiveCapabilityTests._configure_tls_and_users
    start_tls_broker = tls_fixture.LiveCapabilityTests.start_tls_broker
    connect = tls_fixture.LiveCapabilityTests.connect
    exchange = tls_fixture.LiveCapabilityTests.exchange
    command = tls_fixture.LiveCapabilityTests.command
    write_private = tls_fixture.LiveCapabilityTests.write_private
    wait_handoff = tls_fixture.LiveCapabilityTests.wait_handoff
    read_contract = 'configuration-change-subscribe'
    boundary_checks = False

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_CONFIGURATION_SUBSCRIPTION_LIVE') != '1':
            raise RuntimeError('A coordinated subscription live slot is required')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('Native macOS ARM64 is required')
        binary = Path(os.environ.get('AMX_CONFIGURATION_SUBSCRIPTION_GO_BINARY', ''))
        if not binary.is_absolute() or not binary.is_file():
            raise RuntimeError('A prepared native subscription Go test binary is required')

    def configure_broker_policies(self, policies, reads):
        event = self.read_subject.removesuffix('.command') + '.event.configuration-change'
        policies['storage'] = {
            'publish': {'allow': [self.subjects['DATA'], event] + reads('IDENTITY', 'DATA')},
            'subscribe': {'allow': [self.read_subject, event, self.subjects['DATA']]}}
        self.source_broker_policy = policies['storage']

    async def asyncSetUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='agentmux-configuration-live-')).resolve()
        self.connections = []
        self.go_process = self.go_wait = self.go_output = None
        self.identity = self.receiver = self.broker = None
        self.workspace = self.checkout_store = self.git_executor = None
        self.keep_directory = self.success = False
        self.histories = []
        self.addAsyncCleanup(self.cleanup)
        self.errors, self.permission_events = {}, {}
        self.inbox_prefixes = {role: '_INBOX.' + secrets.token_hex(16)
            for role in ('provisioner', 'identity', 'storage', 'host', 'other-scope')}
        self.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.policy = Retention(4_194_304, 524_288)
        self.issuer_public = base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
        self.bindings = {
            'IDENTITY': OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority', canonical_bytes(self.scope)),
            'DATA': OwnerBinding('hub-one', 'configuration', 'configuration-one', 'configuration', canonical_bytes(self.scope)),
            'OTHER': OwnerBinding('hub-one', 'configuration', 'configuration-other', 'configuration', canonical_bytes(self.scope))}
        self.subjects = {name: owner_subject(binding) for name, binding in self.bindings.items()}
        self.identity_subject = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        self.read_subject = 'amx.v1.h.hub-one.o.org-one.p._.w._.configuration.configuration-one.command'
        self.other_subject = 'amx.v1.h.hub-one.o.other-org.p._.w._.configuration.configuration-one.command'
        self.broker = Broker(self.directory)
        self._configure_tls_and_users()
        event = self.read_subject.removesuffix('.command') + '.event.configuration-change'
        self.assertCountEqual(self.source_broker_policy['publish']['allow'], [
            self.subjects['DATA'], event, '$JS.API.STREAM.INFO.IDENTITY',
            '$JS.API.STREAM.MSG.GET.IDENTITY', '$JS.API.STREAM.INFO.DATA', '$JS.API.STREAM.MSG.GET.DATA'])
        self.assertCountEqual(self.source_broker_policy['subscribe']['allow'], [
            self.read_subject, event, self.subjects['DATA'], self.inbox_prefixes['storage']+'.>'])
        admin = await self.start_tls_broker()
        infos = {name: await admin.jetstream().add_stream(self.policy.stream_config(
            stream=name, subject=subject)) for name, subject in self.subjects.items()}
        self.streams = {name: StreamIdentity(info.created, 0) for name, info in infos.items()}
        metadata = await admin.request('$JS.API.STREAM.INFO.IDENTITY', b'{}', timeout=2)
        self.identity_created = strict_loads(metadata.data)['created']
        initial = self.initial_authority()
        ledger = OwnerLedger(admin.jetstream(), stream='IDENTITY', subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'], retention=self.policy, stream_identity=self.streams['IDENTITY'])
        await ledger.append(initial, expected_sequence=0)
        connection = await self.connect('identity')
        history, backup = self.custody('identity', 'IDENTITY')
        async def committed(receipt):
            self.checkpoint_receipts.append(receipt)
        self.checkpoint_receipts = []
        self.identity = IdentityService(connection, stream='IDENTITY', stream_identity=self.streams['IDENTITY'],
            retention=self.policy, hub_id='hub-one', entity_id='authority-one', profile_id='profile-one',
            organization_id='org-one', issuer_ref=ref('issuer'), signing_seed=SEED, history=history,
            checkpoint_path=self.directory/'identity-checkpoint.json', checkpoint_committed=committed,
            backup_host=backup, backup_key_id='backup-one')
        await self.identity.start()
        self.host = await self.connect('host')
        self.source_connection = await self.connect('storage')
        history, backup = self.custody('configuration', 'DATA')
        self.configuration_ledger = OwnerLedger(self.source_connection.jetstream(), stream='DATA',
            subject=self.subjects['DATA'], binding=self.bindings['DATA'], retention=self.policy,
            stream_identity=self.streams['DATA'], history=history, require_completion_budget=True)
        self.route = ConfigurationEventRoute.from_ledger(self.configuration_ledger,
            account_public_key=self.account_public_key, jetstream_domain=None)
        self.source_pin = {'configurationRef': dict(ref('configuration-one'), revision=0),
            'schemaRef': 'config.json', 'sourceDigest': self.route.source_digest,
            'streamCreated': self.route.stream_created}
        self.write_private('source-ready.json', {'source': self.source_pin, 'cursor': self.route.cursor(0)})
        await self.start_go_child()
        self.row['configurationEventSources'] = [self.source_pin]
        await self.command('identity-native-instance-set', ref('native-admin'), {
            'authorityId': 'authority-one', 'record': self.row, 'previousRef': None})
        checkpoint_root = self.directory/'configuration-checkpoints'
        checkpoint_root.mkdir(mode=0o700)
        checkpoint = CheckpointHost(checkpoint_root/'checkpoint', stream='DATA',
            commit_ref=ref('configuration-checkpoint'), binding=self.bindings['DATA'], stream_identity=self.streams['DATA'])
        self.receiver = ConfigurationHost(self.identity.reader, self.configuration_ledger,
            connection=self.source_connection, owner=self.row['owner'], schema_ref='config.json',
            schema_resources={'config.json': b'{"type":"object"}'}, issuer_ref=ref('issuer'), signing_seed=SEED,
            reply_prefix=self.inbox_prefixes['host']+'.', checkpoint_host=checkpoint,
            backup_host=backup, backup_key_id='backup-one', event_producer=event_producer(self.identity.reader, self.scope),
            event_account_public_key=self.account_public_key)
        await self.receiver.start()
        self.assertEqual(await self.receiver.events.enrollment_pin(), self.source_pin)
        await self.set_configuration(0)

    def custody(self, name, stream):
        history = OwnerHistory(self.directory/(name+'-history.sqlite'), self.bindings[stream],
            stream_identity=self.streams[stream])
        self.histories.append(history)
        roots = [self.directory/(name+'-'+part) for part in ('backup', 'inventory', 'keys')]
        for root in roots:
            root.mkdir(mode=0o700)
        backup = BackupHost(*roots, destination_id=name+'-backup', binding=self.bindings[stream],
            stream_identity=self.streams[stream])
        backup.enroll_key('backup-one')
        return history, backup

    def initial_authority(self):
        initial, _ = command_fixture()
        initial.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        initial['operation'].update(scope=copy.deepcopy(self.scope), expectedVersion=0)
        state = initial['state']
        state['nativeInstances'] = []
        for name, kind in (('host', 'service'), ('plugin', 'plugin')):
            state['identities'].append({'ref': ref(name), 'status': 'active', 'kind': kind,
                'principalId': name+'-one', 'externalIdentity': None})
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('host-transport'), identityRef=ref('host'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('host-member'), identityRef=ref('host'))
        state['memberships'].append(member)
        base = copy.deepcopy(state['grants'][0])
        for name, contract, resource in [('native-admin', 'identity-native-instance-set', 'authority-one')]:
            grant = copy.deepcopy(base)
            grant.update(ref=ref(name), contractId=contract, resourceId=resource)
            state['grants'].append(grant)
        for method in ('bind-instance', 'admit-operation', 'recheck', 'prepare-subscription-call',
                'admit-domain-event', 'prepare-configuration-initialization', 'prepare-configuration-request'):
            grant = copy.deepcopy(base)
            grant.update(ref=ref('host-'+method), callerRef=ref('host'), actorRef=ref('host'),
                contractId='native-authority-'+method, resourceId='plugin-one')
            state['grants'].append(grant)
        for action in ('read', 'set', 'watch', 'change-subscribe'):
            grant = copy.deepcopy(base)
            grant.update(ref=ref('subscription-grant' if action=='change-subscribe' else 'configuration-'+action),
                callerRef=ref('host'), actorRef=ref('host'), contractId='configuration-'+action,
                resourceId='configuration-one')
            state['grants'].append(grant)
        enroll_event_producer(state, self.scope)
        self.row = native_row()
        self.row['facts']['secretReferences'] = []
        self.row['facts']['grant']['actions'] = ['subscribe']
        self.row['facts']['grant']['resourceIds'] = ['configuration-one']
        self.row['facts']['policy']['decisions'] = [{'access': {'action': 'subscribe',
            'resourceClass': 'configuration', 'resourceId': 'configuration-one'}, 'outcome': 'allow'}]
        self.row['facts']['domainBindings'] = [{'id': 'configuration-events',
            'contractId': 'configuration-change-subscribe', 'action': 'subscribe',
            'resourceClass': 'configuration', 'resourceIds': ['configuration-one']}]
        now = datetime.now(timezone.utc)
        def current_times(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key=='issuedAt': value[key] = stamp(now-timedelta(seconds=30))
                    elif key in ('expiresAt', 'deadline'): value[key] = stamp(now+timedelta(minutes=5))
                    elif key=='recordedAt': value[key] = stamp(now)
                    else: current_times(item)
            elif isinstance(value, list):
                for item in value: current_times(item)
        current_times(initial)
        current_times(self.row)
        return initial

    async def start_go_child(self):
        descriptor = os.open(self.directory/'go.private.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        self.go_output = os.fdopen(descriptor, 'wb')
        environment = dict(os.environ, AMX_NATIVE_CONFIGURATION_SUBSCRIPTION_LIVE_DIR=str(self.directory))
        self.go_process = await asyncio.create_subprocess_exec(
            os.environ['AMX_CONFIGURATION_SUBSCRIPTION_GO_BINARY'],
            '-test.run=^TestNativeConfigurationSubscriptionTLSIntegration$', '-test.count=1', '-test.timeout=0',
            env=environment, stdout=self.go_output, stderr=self.go_output)
        self.go_wait = asyncio.create_task(self.go_process.wait())
        declaration = await self.wait_handoff('go-declaration.json', lambda value: True)
        self.assertEqual(set(declaration), {'owner', 'manifestDigest', 'configurationChecksum'})
        self.assertEqual(declaration['configurationChecksum'], 'sha256:'+hashlib.sha256(b'{}').hexdigest())
        self.row.update(declaration)

    async def possession(self, contract, grant, payload, revision):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('host-transport'), 'grantRef': ref(grant),
            'operationId': 'configuration-'+secrets.token_hex(16), 'expectedVersion': revision,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=60))}
        result = await self.identity.ingress.admit(packet(claims, HOST_SEED), cancellation_ref=ref('cancel'))
        self.assertEqual(result.decision.outcome, 'allowed')
        return result.envelope

    async def set_configuration(self, revision):
        payload = {'configurationRef': dict(ref('configuration-one'), revision=revision),
            'owner': self.row['owner'], 'schemaRef': 'config.json',
            'configurationBytes': base64.b64encode(b'{}').decode(), 'secretReferences': []}
        raw = await self.possession('configuration-set', 'configuration-set', payload, revision)
        response = await self.exchange(self.host, self.read_subject, raw, self.host.new_inbox())
        from state_owner.configuration import verify_configuration_response
        verified = verify_configuration_response(response, raw, public_key=self.issuer_public,
            issuer_ref=ref('issuer'), now=datetime.now(timezone.utc))
        self.assertEqual(verified['state']['revision'], revision+1)

    async def test_tls_subscription_delivery_revocation_and_cleanup(self):
        payload = {'resourceRef': dict(ref('configuration-one'), revision=0),
            'eventContractId': 'configuration-change', 'filter': {'owner': self.row['owner'], 'schemaRef': 'config.json'},
            'cursor': self.route.cursor(1)}
        payload['filterDigest'] = payload_digest({k: payload[k] for k in ('resourceRef', 'eventContractId', 'filter')})
        original = await self.possession('configuration-change-subscribe', 'subscription-grant', payload, 0)
        self.write_private('host-signing.seed', HOST_SEED, raw=True)
        self.write_private('original-envelope.json', original, raw=True)
        # Admit the next configuration revision before Go binds the owner.
        # A live native admission must not be rebound with changed facts.
        previous = copy.deepcopy(self.row['ref'])
        self.row['ref']['revision'] += 1
        self.row['facts']['configurationRevision'] = 2
        await self.command('identity-native-instance-set', ref('native-admin'), {
            'authorityId': 'authority-one', 'record': self.row, 'previousRef': previous})
        snapshot = await self.identity.ledger.current()
        ready = {'serverUrl': self.broker.url, 'authoritySubject': self.identity_subject,
            'configurationSubject': self.read_subject, 'credentialsFile': str(self.credentials['host']),
            'caFile': str(self.ca_file), 'tlsName': self.server_name, 'leafCertificateSha256': self.leaf_digest,
            'accountPublicKey': self.account_public_key, 'replyPrefix': self.inbox_prefixes['host'],
            'publishSubjects': [self.identity_subject, self.read_subject,
                '$JS.API.STREAM.INFO.IDENTITY', '$JS.API.STREAM.MSG.GET.IDENTITY'],
            'hostSigningSeedFile': str(self.directory/'host-signing.seed'),
            'originalEnvelopeFile': str(self.directory/'original-envelope.json'),
            'enrollment': {'profileId': 'profile-one', 'hubId': 'hub-one', 'authorityId': 'authority-one',
                'organizationId': 'org-one', 'stream': 'IDENTITY', 'domain': '', 'streamCreated': self.identity_created,
                'minimumSequence': snapshot.sequence, 'maxBytes': self.policy.max_bytes, 'replicas': 1,
                'hostTransportRef': ref('host-transport'), 'hostIdentityRef': ref('host'),
                'issuerRef': ref('issuer'), 'issuerIdentityRef': ref('service'), 'issuerInstanceId': 'ingress-one'},
            'service': {'profileId': 'profile-one', 'hubId': 'hub-one', 'serviceInstanceId': 'ingress-one',
                'serviceIdentityRef': ref('service'), 'signingKeyRef': ref('issuer')},
            'source': self.source_pin, 'cursor': self.route.cursor(1), 'bindingId': 'configuration-events', 'revoked': False}
        self.write_private('fixture-ready.json', ready)
        self.assertEqual(await self.wait_handoff('go-result.json', lambda v: v.get('phase')=='opened'), {'phase': 'opened'})
        await self.set_configuration(1)
        committed = await self.configuration_ledger.current()
        event = canonical_bytes(strict_loads(committed.latest.record)['effects'][0]['payload'])
        self.write_private('expected-event.json', {'eventEnvelopeBytes': base64.b64encode(event).decode()})
        self.assertEqual(await self.wait_handoff('go-result.json', lambda v: v.get('phase')=='event-complete'), {'phase': 'event-complete'})
        await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one', 'targetRef': ref('subscription-grant')})
        await self.assert_revoked_source_refuses_unread_event(event)
        ready['revoked'] = True
        self.write_private('fixture-ready.json', ready)
        result = await self.wait_handoff('go-result.json', lambda v: v.get('phase')=='complete')
        self.assertEqual(result, {'phase': 'complete', 'event': True, 'revocation': True, 'cleanup': True})
        self.assertEqual(await asyncio.wait_for(asyncio.shield(self.go_wait), 3), 0)
        self.assertTrue(all(entry.joined for entry in self.receiver.subscriptions._entries.values()))
        self.assertFalse(self.receiver.owner._watches)
        self.assertFalse(self.errors['storage'] or self.errors['identity'] or self.errors['host'])
        self.success = True

    async def assert_revoked_source_refuses_unread_event(self, expected_event):
        self.assertEqual(len(self.receiver.subscriptions._entries), 1)
        entry, = self.receiver.subscriptions._entries.values()
        cursor = self.route.cursor(1)
        self.assertEqual(entry.cursor, cursor)
        self.assertEqual(entry.offered, self.route.cursor(2))
        # The exact event remains available at the unacknowledged position.
        available = await self.receiver.events.next(cursor)
        self.assertEqual(available.envelope, expected_event)
        opened = strict_loads(entry.authority.open_claims)
        envelope = strict_loads(entry.authority.subscription)
        deadline = datetime.fromisoformat(envelope['operation']['deadline'])
        now = datetime.now(timezone.utc)
        self.assertGreater((deadline-now).total_seconds(), .1)
        claims = copy.deepcopy(opened)
        claims.pop('subscriptionEnvelopeBytes')
        reply = self.inbox_prefixes['host']+'.'+secrets.token_hex(32)
        claims.update(action='next', requestId='request_'+secrets.token_hex(32),
            leaseId=entry.lease_id, cursor=cursor, replySubject=reply,
            issuedAt=stamp(now), expiresAt=stamp(min(deadline, now+timedelta(seconds=4))))
        raw = packet(claims, HOST_SEED, native=True)
        completed, failures = asyncio.Event(), []
        original = self.receiver.subscriptions.handle
        async def observed(request, **kwargs):
            try:
                return await original(request, **kwargs)
            except ContractError as error:
                if request == raw:
                    failures.append((error.code, datetime.now(timezone.utc)))
                raise
            finally:
                if request == raw:
                    completed.set()
        subscription = await self.host.subscribe(reply)
        try:
            with patch.object(self.receiver.subscriptions, 'handle', side_effect=observed), \
                    patch.object(self.receiver.events, 'next', wraps=self.receiver.events.next) as read:
                await self.host.flush(timeout=2)
                await self.host.publish(self.read_subject, raw, reply=reply)
                await asyncio.wait_for(completed.wait(), 1)
                self.assertEqual([code for code, _ in failures], ['subscription_control_not_authorized'])
                self.assertLess(failures[0][1], deadline)
                read.assert_not_called()
                self.assertEqual(subscription.pending_msgs, 0)
            self.assertEqual(entry.cursor, cursor)
            self.assertEqual(entry.offered, self.route.cursor(2))
        finally:
            await subscription.unsubscribe()

    async def _cleanup(self):
        # Keep the supervisor and borrowed services alive while Go still owns
        # an uncertain allocation. Only its original process wait permits exit.
        if self.go_wait is not None:
            if not self.go_wait.done():
                self.keep_directory = True
            code = await asyncio.shield(self.go_wait)
            if code:
                self.keep_directory = True
        if self.go_output is not None:
            self.go_output.close()
        if self.receiver is not None:
            await self._join_cleanup_step('configuration', lambda: self.receiver.close(timeout=None))
        if self.identity is not None:
            await self._join_cleanup_step('identity', self.identity.close)
        for history in self.histories:
            await self._join_cleanup_step('history', history.close)
        for connection in reversed(self.connections):
            await self._join_cleanup_step('connection', connection.close)
        if self.broker is not None:
            await self._join_cleanup_step('broker', self.broker.stop)
        if self.success and not self.keep_directory:
            shutil.rmtree(self.directory)

    async def _join_cleanup_step(self, owner, close):
        while True:
            try:
                result = close()
                if hasattr(result, '__await__'):
                    await result
                return
            except Exception:
                self.keep_directory = True
                attempt = getattr(self, '_cleanup_attempt', 0)
                try:
                    self.write_private('python-cleanup.json', {
                        'phase': 'cleanup-required', 'owner': owner, 'attempt': attempt})
                except OSError:
                    pass  # Keep the owner alive if its private directory needs repair.
                self._cleanup_attempt = await self._wait_cleanup_recovery(attempt)

    async def _wait_cleanup_recovery(self, attempt):
        while True:
            try:
                descriptor = os.open(self.directory/'fixture-cleanup.json', os.O_RDONLY|os.O_NOFOLLOW)
            except OSError:
                pass
            else:
                with os.fdopen(descriptor, 'rb') as source:
                    info = os.fstat(source.fileno())
                    if stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=8192:
                        try:
                            request = strict_loads(source.read(8193))
                        except ContractError:
                            request = None
                        if (type(request) is dict and set(request)=={'attempt'}
                                and type(request['attempt']) is int and request['attempt']>attempt):
                            return request['attempt']
            await asyncio.sleep(.1)

    async def cleanup(self):
        if not hasattr(self, '_cleanup_work'):
            self._cleanup_work = asyncio.create_task(self._cleanup())
        await asyncio.shield(self._cleanup_work)


def _foreground_package(value):
    expected = {'instanceId', 'pin', 'manifestDigest', 'configurationChecksum',
                'schemaRef', 'configurationBytes', 'catalog', 'contracts'}
    if type(value) is not dict or set(value) != expected:
        raise ContractError('foreground_package_invalid')
    pin = value['pin']
    if (type(pin) is not dict or set(pin) != {'packageId', 'version', 'manifestChecksum',
            'packageChecksum', 'provenanceChecksum'} or pin['packageId'] != 'native_foreground'
            or value['instanceId'] != 'plugin-one' or value['schemaRef'] != 'schemas/config.json'
            or value['manifestDigest'] != pin['manifestChecksum']
            or any(type(pin[key]) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', pin[key])
                   for key in ('manifestChecksum', 'packageChecksum', 'provenanceChecksum'))
            or value['configurationBytes'] != base64.b64encode(b'{}').decode()
            or value['configurationChecksum'] != 'sha256:' + hashlib.sha256(b'{}').hexdigest()
            or value['contracts'] != [{'kind': 'tool', 'contractRef': 'urn:fixture:tool'}]):
        raise ContractError('foreground_package_invalid')
    catalog = value['catalog']
    if (type(catalog) is not dict or set(catalog) != {'directory', 'manifestPath', 'sourceId',
            'sourcePath', 'scope', 'sourceFile', 'sourceChecksum', 'limits'}
            or catalog['manifestPath'] != 'manifest.json'
            or any(type(catalog[key]) is not str or not Path(catalog[key]).is_absolute()
                   for key in ('directory', 'sourcePath', 'sourceFile'))):
        raise ContractError('foreground_package_invalid')
    return strict_loads(canonical_bytes(value))


def _foreground_retained_row(snapshot, declaration, instance_id):
    state = strict_loads(snapshot.record)['state']
    rows = [row for row in state.get('nativeInstances', [])
            if row['status'] == 'active' and row['owner']['instanceId'] == instance_id]
    if len(rows) != 1:
        raise ContractError('foreground_activation_not_retained')
    row, = rows
    if (row['ref'] != declaration['recordRef'] or row['owner']['pin'] != declaration['pin']
            or row['owner']['generation'] != 1 or row['relationship'] != 'independent'
            or row['parentOwner'] is not None
            or any(row[key] != declaration[key] for key in
                   ('identityRef', 'manifestDigest', 'configurationChecksum', 'facts',
                    'configurationEventSources'))):
        raise ContractError('foreground_activation_changed')
    return strict_loads(canonical_bytes(row))


class _ForegroundIdentityService(IdentityService):
    """Keep the actual activation request until its configuration owner is ready."""
    def __init__(self, *args, activation_observed, diagnostics=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._activation_observed = activation_observed
        self._diagnostics = diagnostics

    async def handle(self, request_bytes):
        diagnostics = self._diagnostics
        if diagnostics is None:
            return await super().handle(request_bytes)
        return await diagnostics.invoke(diagnostics.authority_kind(request_bytes), super().handle,
            request_bytes, deadline=diagnostics.deadline(request_bytes))

    async def _handle(self, request_bytes):
        response = await super()._handle(request_bytes)
        claims = strict_loads(request_bytes)['claims']
        if (claims.get('purpose') == 'agentmux-native-authority-request-v1'
                and claims.get('method') == 'activate-instance'):
            # The original service has already authorized, committed and read
            # back this activation. Do not replace its response or its owner.
            await self._activation_observed(claims['owner'])
        return response


_FOREGROUND_CONFIGURATION_CODES = frozenset('''
    configuration_unavailable configuration_host_unavailable configuration_owner_closed
    configuration_binding_mismatch configuration_access_refused configuration_native_not_authorized
    configuration_initialization_not_authorized configuration_revision_conflict
    configuration_contract_invalid configuration_value_invalid configuration_history_invalid
    configuration_signer_unavailable configuration_cleanup_incomplete
    configuration_event_producer_required configuration_event_binding configuration_event_resync_required
    configuration_event_publication_not_authorized configuration_event_publication_uncertain
    configuration_watch_expired configuration_watch_receipt_capacity configuration_watch_duplicate
    configuration_watch_capacity configuration_watch_admission_refused configuration_watch_cleanup_incomplete
    configuration_watch_close_expired configuration_watch_close_reply_binding
    configuration_watch_close_source_binding configuration_watch_close_binding
    configuration_watch_receipt_authority configuration_watch_receipt_history_unavailable
    configuration_watch_receipt_signer configuration_watch_receipt_invalid configuration_watch_receipt_binding
    configuration_watch_receipt_early configuration_watch_close_unavailable configuration_watch_allocation_required
    authority_unavailable authority_record_invalid authority_time_invalid owner_commit_uncertain
    owner_history_cache_invalid owner_operation_conflict schema_invalid semantic_invalid invalid_json
    schema_configuration_error unknown_schema size_limit
    identity_service_closed identity_request_invalid identity_actor_unverified owner_body_limit
    native_envelope_encoding native_profile_mismatch native_request_expired native_credential_unavailable
    native_instance_unavailable native_host_not_authorized native_facts_expired native_declaration_mismatch
    native_facts_changed native_operation_binding native_operation_not_authorized
    native_downstream_authority_unavailable native_configuration_binding native_configuration_grant_unavailable
    native_configuration_not_authorized native_activation_not_authorized
'''.split())
_FOREGROUND_AUTHORITY_METHODS = frozenset(('bind-instance', 'admit-operation', 'recheck',
    'prepare-domain-call', 'prepare-configuration-request', 'activate-instance',
    'prepare-configuration-initialization', 'prepare-subscription-call', 'admit-domain-event'))


class _ForegroundConfigurationDiagnostics:
    """Observe the original fixture calls without recording their private inputs."""
    def __init__(self, path):
        self.path = path
        info = path.stat(follow_symlinks=False)
        self.identity = (info.st_dev, info.st_ino)
        self.failed, self.written = False, 0
        self.origin = time.monotonic()
        self.watch_admitted = asyncio.Event()
        self.watch_admission = None

    @staticmethod
    def authority_kind(raw):
        try:
            if type(raw) is bytes and len(raw) <= 65536:
                claims = strict_loads(raw)['claims']
                method = claims['method']
                if (claims['purpose'] == 'agentmux-native-authority-request-v1'
                        and type(method) is str and method in _FOREGROUND_AUTHORITY_METHODS):
                    return 'native-authority-' + method
        except Exception:
            pass
        return 'native-authority-other'

    @staticmethod
    def deadline(raw):
        try:
            if type(raw) is bytes and len(raw) <= 65536:
                value = strict_loads(raw)
                if 'operation' in value:
                    values = (value['operation']['deadline'], value['ingressAttestation']['claims']['expiresAt'])
                else:
                    values = (value['claims']['expiresAt'],)
                parsed = [datetime.fromisoformat(item) for item in values]
                if all(item.tzinfo is not None for item in parsed):
                    return min(parsed)
        except Exception:
            pass
        return None

    @staticmethod
    def kind(raw):
        try:
            if type(raw) is bytes and len(raw) <= 65536:
                value = strict_loads(raw)
                if value.get('claims', {}).get('purpose') == 'agentmux-configuration-watch-close-v1':
                    return 'watch-close'
                contract = value.get('contractId')
                if contract in ('configuration-read', 'configuration-watch', 'configuration-set'):
                    return contract
        except Exception:
            pass
        return 'other'

    @staticmethod
    def code(error):
        if isinstance(error, ContractError):
            if type(error.code) is str and error.code in _FOREGROUND_CONFIGURATION_CODES:
                return error.code
            return 'contract_error'
        return 'handler_error'

    def record(self, kind, phase, code, *, deadline=None):
        now = datetime.now(timezone.utc)
        value = {'kind': 'fixture-configuration', 'request': kind, 'phase': phase, 'code': code,
            'recordedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'elapsedMs': int((time.monotonic() - self.origin) * 1000)}
        if deadline is not None:
            value['deadlineExpired'] = now >= deadline
        raw = canonical_bytes(value) + b'\n'
        try:
            if self.failed or self.written + len(raw) > 65536:
                raise ValueError()
            fd = os.open(self.path, os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != os.getuid() or info.st_nlink != 1
                        or (info.st_dev, info.st_ino) != self.identity
                        or info.st_size > 1048576 - len(raw) or os.write(fd, raw) != len(raw)):
                    raise ValueError()
                self.written += len(raw)
            finally:
                os.close(fd)
        except Exception:
            # Diagnostics cannot replace a result, exception or cancellation.
            self.failed = True

    async def invoke(self, kind, original, *args, deadline=None, **kwargs):
        self.record(kind, 'started', 'started', deadline=deadline)
        try:
            result = await original(*args, **kwargs)
        except asyncio.CancelledError:
            self.record(kind, 'canceled', 'canceled', deadline=deadline)
            raise
        except Exception as error:
            self.record(kind, 'refused', self.code(error), deadline=deadline)
            raise
        self.record(kind, 'succeeded', 'succeeded', deadline=deadline)
        return result

    def install(self, owner):
        receive, handle = owner._receive, owner.handle
        close, admit = owner._watch_controls.handle, owner._watch_controls.admit
        async def received(message):
            self.record(self.kind(message.data), 'received', 'received', deadline=self.deadline(message.data))
            return await receive(message)
        async def handled(raw):
            return await self.invoke(self.kind(raw), handle, raw, deadline=self.deadline(raw))
        async def closed(raw, *, reply_subject):
            return await self.invoke('watch-close', close, raw, reply_subject=reply_subject, deadline=self.deadline(raw))
        def admitted(*args):
            try:
                result = admit(*args)
            except Exception as error:
                self.record('configuration-watch', 'admission-refused', self.code(error))
                raise
            self.record('configuration-watch', 'admitted', 'admitted')
            if self.watch_admission is None:
                self.watch_admission = (owner, args[0])
                self.watch_admitted.set()
            return result
        owner._receive, owner.handle = received, handled
        owner._watch_controls.handle, owner._watch_controls.admit = closed, admitted
        self.record('other', 'installed', 'installed')


class LiveRegisteredContextForegroundTests(LiveConfigurationSubscriptionTests):
    """Run the real foreground command against registered, selected services."""
    private_inbox_roles = ('identity', 'storage', 'host', 'other-scope', 'capability')
    test_tls_subscription_delivery_revocation_and_cleanup = None

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_NATIVE_CONTEXT_FOREGROUND_LIVE') != '1':
            raise RuntimeError('A coordinated foreground native context slot is required')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('Native macOS ARM64 is required')
        for key in ('AMX_NATIVE_CONTEXT_FOREGROUND_GO_BINARY', 'AGENTMUX_PLUGIN_CLI',
                    'AMX_NATIVE_CONTEXT_FOREGROUND_PROFILE'):
            path = Path(os.environ.get(key, ''))
            if not path.is_absolute() or not path.is_file():
                raise RuntimeError('Prepared foreground native context inputs are required')

    def reference(self, name, revision=1):
        return {'id': name, 'ownerHubId': self.hub_id, 'revision': revision}

    def relocate(self, value):
        if isinstance(value, dict):
            return {key: self.relocate(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.relocate(item) for item in value]
        if value == 'hub-one':
            return self.hub_id
        if value == 'profile-one':
            return self.profile_id
        return value

    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        prefix = 'amx.v1.h.' + self.hub_id + '.plugins.plugin-one.'
        policies['host']['publish']['allow'].append(self.capability_subject)
        policies['controller'] = {'publish': {'allow': [prefix+'lifecycle.control']},
                                  'subscribe': {'allow': [prefix+'lifecycle.event']}}
        policies['plugin'] = {'publish': {'allow': [prefix+'lifecycle.event']},
                              'subscribe': {'allow': [prefix+'lifecycle.control']}}
        policies['context'] = {'publish': {'allow': [prefix+'context.reply', prefix+'operation.invoke',
                                                    prefix+'operation.cancel']},
                               'subscribe': {'allow': [prefix+'context.request', prefix+'operation.result']}}
        policies['context-client'] = {'publish': {'allow': [prefix+'context.request', prefix+'operation.result']},
                                      'subscribe': {'allow': [prefix+'context.reply', prefix+'operation.invoke',
                                                               prefix+'operation.cancel']}}
        policies['capability'] = {'publish': {'allow': reads('OTHER') + [self.inbox_prefixes['host']+'.>']},
                                  'subscribe': {'allow': [self.capability_subject]}}
        self.foreground_permissions = policies

    async def asyncSetUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='agentmux-foreground-context-')).resolve()
        self.connections, self.histories = [], []
        self.go_process = self.go_wait = self.go_output = None
        self.identity = self.receiver = self.broker = self.capability = None
        self.workspace = self.checkout_store = self.git_executor = None
        self.keep_directory = self.success = False
        self._configuration_start = None
        self.write_private('diagnostics.private.jsonl', b'', raw=True)
        self._configuration_diagnostics = _ForegroundConfigurationDiagnostics(self.directory/'diagnostics.private.jsonl')
        self.addAsyncCleanup(self.cleanup)
        profile = strict_loads(_read_material(os.environ['AMX_NATIVE_CONTEXT_FOREGROUND_PROFILE'],
                                             max_bytes=65536, return_bytes=True))
        if (type(profile) is not dict or set(profile) != {'schemaVersion', 'hostPolicy',
                'repositoryRoot', 'kernelScope'}
                or profile['schemaVersion'] != '1.0.0'):
            raise ContractError('foreground_profile_invalid')
        self.profile = profile
        self.profile_id, self.hub_id = (profile['kernelScope'][key] for key in ('profileId', 'hubId'))
        self.errors, self.permission_events = {}, {}
        self.inbox_prefixes = {role: '_INBOX.'+secrets.token_hex(16)
            for role in (*self.private_inbox_roles, 'provisioner')}
        self.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.policy = Retention(4_194_304, 524_288)
        self.issuer_public = base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
        self.capability_seed = secrets.token_bytes(32)
        self.capability_public = base64.urlsafe_b64encode(bytes(SigningKey(self.capability_seed).verify_key)).decode().rstrip('=')
        self.bindings = {
            'IDENTITY': OwnerBinding(self.hub_id, 'identity', 'authority-one', 'identity-authority', canonical_bytes(self.scope)),
            'DATA': OwnerBinding(self.hub_id, 'configuration', 'configuration-one', 'configuration', canonical_bytes(self.scope)),
            'OTHER': OwnerBinding(self.hub_id, 'task', 'task-one', 'task', canonical_bytes(self.scope))}
        self.subjects = {name: owner_subject(binding) for name, binding in self.bindings.items()}
        prefix = 'amx.v1.h.'+self.hub_id+'.o.org-one.'
        self.identity_subject = prefix+'identity.authority-one.command'
        self.read_subject = prefix+'p._.w._.configuration.configuration-one.command'
        self.capability_subject = prefix+'p._.w._.capability.storage-owner.command'
        self.other_subject = 'amx.v1.h.'+self.hub_id+'.o.other-org.p._.w._.configuration.configuration-one.command'
        self.broker = Broker(self.directory)
        self._configure_tls_and_users()
        admin = await self.start_tls_broker()
        infos = {name: await admin.jetstream().add_stream(self.policy.stream_config(stream=name, subject=subject))
                 for name, subject in self.subjects.items()}
        self.streams = {name: StreamIdentity(info.created, 0) for name, info in infos.items()}
        self.identity_created = strict_loads((await admin.request('$JS.API.STREAM.INFO.IDENTITY', b'{}', timeout=2)).data)['created']
        ledger = OwnerLedger(admin.jetstream(), stream='IDENTITY', subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'], retention=self.policy, stream_identity=self.streams['IDENTITY'])
        await ledger.append(self.initial_authority(), expected_sequence=0)
        connection = await self.connect('identity')
        history, backup = self.custody('identity', 'IDENTITY')
        self.checkpoint_receipts = []
        async def committed(receipt):
            self.checkpoint_receipts.append(receipt)
        self.identity = _ForegroundIdentityService(connection, stream='IDENTITY', stream_identity=self.streams['IDENTITY'],
            retention=self.policy, hub_id=self.hub_id, entity_id='authority-one', profile_id=self.profile_id,
            organization_id='org-one', issuer_ref=self.reference('issuer'), signing_seed=SEED, history=history,
            checkpoint_path=self.directory/'identity-checkpoint.json', checkpoint_committed=committed,
            backup_host=backup, backup_key_id='backup-one', activation_observed=self.start_allocated_configuration,
            diagnostics=self._configuration_diagnostics)
        await self.identity.start()
        self.host = await self.connect('host')
        self.source_connection = await self.connect('storage')
        self.configuration_history, self.configuration_backup = self.custody('configuration', 'DATA')
        self.configuration_ledger = OwnerLedger(self.source_connection.jetstream(), stream='DATA',
            subject=self.subjects['DATA'], binding=self.bindings['DATA'], retention=self.policy,
            stream_identity=self.streams['DATA'], history=self.configuration_history, require_completion_budget=True)
        self.route = ConfigurationEventRoute.from_ledger(self.configuration_ledger,
            account_public_key=self.account_public_key, jetstream_domain=None)
        await self.start_capability(admin)
        await self.start_go_child()
        await self.prepare_foreground_selection()

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        base = copy.deepcopy(state['grants'][0])
        for name, contract, resource in (
                ('host-activate-instance', 'native-authority-activate-instance', 'plugin-one'),
                ('host-native-admin', 'identity-native-instance-set', 'authority-one'),
                ('host-prepare-domain-call', 'native-authority-prepare-domain-call', 'plugin-one')):
            grant = copy.deepcopy(base)
            grant.update(ref=ref(name), callerRef=ref('host'), actorRef=ref('host'),
                         contractId=contract, resourceId=resource)
            state['grants'].append(grant)
        state['identities'].append({'ref': ref('storage-service'), 'status': 'active', 'kind': 'service',
            'principalId': 'storage-service', 'externalIdentity': None})
        issuer = copy.deepcopy(state['issuers'][0])
        issuer.update(ref=ref('storage-signer'), identityRef=ref('storage-service'), instanceId='storage-one',
                      publicKey=self.capability_public)
        state['issuers'].append(issuer)
        grant = copy.deepcopy(base)
        grant.update(ref=ref('storage-read'), callerRef=ref('host'), actorRef=ref('host'),
                     contractId='capability-storage-read', resourceId='task-one')
        state['grants'].append(grant)
        facts = self.row['facts']
        facts['grant']['actions'] = ['read', 'subscribe']
        facts['grant']['resourceIds'] = ['task-one', 'configuration-one']
        facts['policy']['decisions'].insert(0, {'access': {'action': 'read',
            'resourceClass': 'storage', 'resourceId': 'task-one'}, 'outcome': 'allow'})
        facts['domainBindings'].insert(0, {'id': 'storage-binding', 'contractId': 'capability-storage-read',
            'action': 'read', 'resourceClass': 'storage', 'resourceIds': ['task-one']})
        # No native instance is enrolled here. Only the real manager supplies
        # the epoch and generation in its later signed activation request.
        self.row.pop('owner')
        self.row = self.relocate(self.row)
        return self.relocate(initial)

    async def start_capability(self, admin):
        value = self.relocate(record('foreground-retained-task'))
        value['entityId'] = 'task-one'
        value['operation']['scope'] = copy.deepcopy(self.scope)
        ledger = OwnerLedger(admin.jetstream(), stream='OTHER', subject=self.subjects['OTHER'],
            binding=self.bindings['OTHER'], retention=self.policy, stream_identity=self.streams['OTHER'])
        await ledger.append(value, expected_sequence=0)
        connection = await self.connect('capability')
        resource = RetainedResource.open_existing(connection.jetstream(), binding=self.bindings['OTHER'], stream='OTHER',
            stream_identity=self.streams['OTHER'], retention=self.policy)
        self.capability = CapabilityReplyService(self.identity.reader, resources=[resource], hub_id=self.hub_id,
            profile_id=self.profile_id, authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=self.reference('storage-service'), service_instance_id='storage-one',
            signing_key_ref=self.reference('storage-signer'), signing_seed=self.capability_seed,
            request_signing_key_ref=self.reference('issuer'), connection=connection)
        await self.capability.start()

    async def start_go_child(self):
        descriptor = os.open(self.directory/'go.private.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        self.go_output = os.fdopen(descriptor, 'wb')
        environment = dict(os.environ, AMX_NATIVE_CONTEXT_FOREGROUND_LIVE_DIR=str(self.directory))
        self.go_process = await asyncio.create_subprocess_exec(os.environ['AMX_NATIVE_CONTEXT_FOREGROUND_GO_BINARY'],
            '-test.run=^TestNativeLiveCLIRegisteredContextActivationAndEOF$', '-test.count=1', '-test.timeout=0',
            env=environment, stdout=self.go_output, stderr=self.go_output)
        self.go_wait = asyncio.create_task(self.go_process.wait())
        self.package = _foreground_package(await self.wait_handoff('go-foreground-package.json', lambda value: True))

    def credential_pin(self, role):
        from native_security.nats_credentials import validate as credentials
        path = self.credentials[role]
        raw = _read_material(path, max_bytes=65536, return_bytes=True)
        permissions = self.foreground_permissions[role]
        admitted = credentials(raw, account_public_key=self.account_public_key,
            publish_subjects=permissions['publish']['allow'], subscribe_subjects=permissions['subscribe']['allow'],
            private_inbox=role == 'host')
        return {'path': str(path), 'sha256': 'sha256:'+hashlib.sha256(raw).hexdigest(),
                'userPublicKey': admitted.public_key}

    async def prepare_foreground_selection(self):
        package, profile = self.package, self.profile
        self.source_pin = {'configurationRef': self.reference('configuration-one', 0),
            'schemaRef': package['schemaRef'], 'sourceDigest': self.route.source_digest,
            'streamCreated': self.route.stream_created}
        self.declaration = {key: self.row[key] for key in ('identityRef', 'facts')}
        self.declaration.update(recordRef=self.row['ref'], previousRef=None, pin=package['pin'],
            manifestDigest=package['manifestDigest'], configurationChecksum=package['configurationChecksum'],
            configurationEventSources=[self.source_pin])
        self.write_private('host-signing.seed', HOST_SEED, raw=True)
        ca = {'path': str(self.ca_file), 'sha256': 'sha256:'+hashlib.sha256(self.ca_file.read_bytes()).hexdigest()}
        connection = {'endpoint': self.broker.url, 'serverName': self.server_name,
                      'rootsPEM': self.ca_file.read_text(), 'leafCertificateSHA256': self.leaf_digest}
        state = self.directory/'native-state'
        state.mkdir(mode=0o700)
        snapshot = await self.identity.reader.current()
        service = {'profileId': self.profile_id, 'hubId': self.hub_id, 'serviceInstanceId': 'ingress-one',
                   'serviceIdentityRef': self.reference('service'), 'signingKeyRef': self.reference('issuer')}
        resources = [{'ref': package['schemaRef'], 'file': package['schemaRef']}]
        value = {'schemaVersion': '1.0.0', 'hostPolicy': profile['hostPolicy'], 'ownerUid': os.getuid(),
            'workspaces': [profile['repositoryRoot']], 'kernelScope': profile['kernelScope'],
            'connection': connection,
            'credentials': dict(self.credential_pin('host'), accountPublicKey=self.account_public_key,
                                replyPrefix=self.inbox_prefixes['host']),
            'keys': {'profileId': self.profile_id, 'hubId': self.hub_id, 'authorityId': 'authority-one',
                'organizationId': 'org-one', 'issuerInstanceId': 'ingress-one', 'stream': 'IDENTITY', 'domain': '',
                'streamCreated': self.identity_created, 'minimumSequence': snapshot.sequence,
                'maxBytes': self.policy.max_bytes, 'replicas': 1, 'hostTransportRef': self.reference('host-transport'),
                'hostIdentityRef': self.reference('host'), 'issuerRef': self.reference('issuer'),
                'issuerIdentityRef': self.reference('service')},
            'requestSigner': {'keyFile': {'path': str(self.directory/'host-signing.seed'),
                'sha256': 'sha256:'+hashlib.sha256(HOST_SEED).hexdigest()}, 'ref': self.reference('host-transport'),
                'publicKey': base64.urlsafe_b64encode(bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('=')},
            'destinations': {'plugin-one': 'storage-owner'},
            'capabilityRoutes': [{'bindingId': 'storage-binding', 'requestContractId': 'capability-storage-read',
                'replyContractId': 'capability-content-reply', 'service': {'profileId': self.profile_id,
                    'hubId': self.hub_id, 'serviceId': 'storage-owner', 'serviceInstanceId': 'storage-one',
                    'serviceIdentityRef': self.reference('storage-service'), 'signingKeyRef': self.reference('storage-signer')},
                'scope': self.scope}],
            'activationDeclarations': {'plugin-one': self.declaration},
            'lifecycle': {'connection': connection, 'caFile': ca, 'accountPublicKey': self.account_public_key,
                'controllerCredentials': self.credential_pin('controller'), 'stateDirectory': str(state),
                'bindings': [{'instanceId': 'plugin-one', 'pin': package['pin'],
                    'credentials': self.credential_pin('plugin'), 'workspace': None}]},
            'contextTransport': {'connection': connection, 'caFile': ca, 'accountPublicKey': self.account_public_key,
                'serverCredentials': self.credential_pin('context'),
                'bindings': [{'instanceId': 'plugin-one', 'credentials': self.credential_pin('context-client')}]},
            'configurationRoutes': {'plugin-one': {'configurationRef': self.reference('configuration-one', 0),
                'authorityRef': self.reference('authority-one', strict_loads(snapshot.record)['entityVersion']),
                'service': service, 'scope': self.scope, 'resources': resources}},
            'subscriptionRoutes': [{'bindingId': 'configuration-events', 'source': self.source_pin,
                                    'service': service, 'scope': self.scope}]}
        receipt = write_native_host_selection(self.directory/'native-selection.json', value)
        raw = _read_material(receipt.path, max_bytes=65536, return_bytes=True)
        if raw != canonical_bytes(value) or 'sha256:'+hashlib.sha256(raw).hexdigest() != receipt.digest:
            raise ContractError('foreground_selection_changed')
        # This fixture creates the input. The native command retains and admits
        # the actual registered host before using these service selections.
        selected = NativeHostSelection(raw)
        self.write_private('configuration.json', b'{}', raw=True)
        composition = {'schemaVersion': '1.2.0', 'catalog': [package['catalog']], 'selected': [package['pin']],
            'contracts': package['contracts'], 'platform': {'os': 'darwin', 'arch': 'arm64'},
            'installationMode': 'independent', 'activationTimeoutMs': 30000, 'cleanupTimeoutMs': 8000,
            'driver': selected.driver_options(),
            'topology': {'instances': [{'instanceId': 'plugin-one', 'pin': package['pin'],
                'installationMode': 'independent', 'placement': {'kind': 'local-process'}}],
                'roots': ['plugin-one'], 'children': [], 'dependencies': []},
            'instanceConfigurations': [{'instanceId': 'plugin-one', 'pin': package['pin'],
                'configurationFile': str(self.directory/'configuration.json'), 'resources': resources}],
            'nativeContext': {'profileId': self.profile_id, 'repositoryRoot': profile['repositoryRoot'],
                'selectionPath': receipt.path, 'selectionSHA256': receipt.digest,
                'observability': {'path': str(self.directory/'diagnostics.private.jsonl'), 'maxBytes': 1048576,
                    'eventCodes': ['fixture_event'], 'spanCodes': ['fixture_span'], 'metricCodes': ['fixture_metric']}}}
        selected.context_options()
        selected.load_credentials()
        self.write_private('foreground-composition.json', composition)
        self.write_private('foreground-ready.json', {'compositionPath': str(self.directory/'foreground-composition.json'),
            'compositionSHA256': 'sha256:'+hashlib.sha256(canonical_bytes(composition)).hexdigest()})

    async def start_allocated_configuration(self, owner):
        row = _foreground_retained_row(await self.identity.reader.current(), self.declaration, 'plugin-one')
        if owner != row['owner']:
            raise ContractError('foreground_activation_changed')
        if self._configuration_start is None:
            self.row = row
            self._configuration_start = asyncio.create_task(self._start_allocated_configuration(row))
        elif self.row != row:
            raise ContractError('foreground_activation_changed')
        await asyncio.wait({self._configuration_start})
        self._configuration_start.result()

    async def _start_allocated_configuration(self, row):
        # The Go package owner keeps these files alive until its final wait.
        root = os.open(self.package['catalog']['directory'], os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            schemas = os.open('schemas', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=root)
            try:
                descriptor = os.open('config.json', os.O_RDONLY|os.O_NOFOLLOW, dir_fd=schemas)
                with os.fdopen(descriptor, 'rb') as source:
                    info = os.fstat(source.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 262144):
                        raise ContractError('foreground_schema_invalid')
                    schema = source.read(262145)
            finally:
                os.close(schemas)
        finally:
            os.close(root)
        checkpoint_root = self.directory/'configuration-checkpoints'
        checkpoint_root.mkdir(mode=0o700)
        checkpoint = CheckpointHost(checkpoint_root/'checkpoint', stream='DATA',
            commit_ref=self.reference('configuration-checkpoint'), binding=self.bindings['DATA'],
            stream_identity=self.streams['DATA'])
        producer = ConfigurationEventProducer(self.identity.reader, hub_id=self.hub_id, profile_id=self.profile_id,
            authority_id='authority-one', configuration_id='configuration-one', scope=self.scope,
            identity_ref=self.reference('service'), transport_ref=self.reference('configuration-event-transport'),
            grant_ref=self.reference('configuration-event-grant'), transport_seed=PRODUCER_SEED,
            issuer_ref=self.reference('issuer'), signing_seed=SEED)
        self.receiver = ConfigurationHost(self.identity.reader, self.configuration_ledger,
            connection=self.source_connection, owner=row['owner'], schema_ref=self.package['schemaRef'],
            schema_resources={self.package['schemaRef']: schema}, issuer_ref=self.reference('issuer'), signing_seed=SEED,
            reply_prefix=self.inbox_prefixes['host']+'.', checkpoint_host=checkpoint,
            backup_host=self.configuration_backup, backup_key_id='backup-one', event_producer=producer,
            event_account_public_key=self.account_public_key)
        self._configuration_diagnostics.install(self.receiver.owner)
        await self.receiver.start()
        self.assertEqual(await self.receiver.events.enrollment_pin(), self.source_pin)

    async def _wait_configuration_watch(self, active, *, deadline):
        observer = self._configuration_diagnostics
        observed = asyncio.create_task(observer.watch_admitted.wait())
        try:
            if asyncio.get_running_loop().time() >= deadline:
                self.keep_directory = True
                raise RuntimeError('capability_fixture_handoff_timeout')
            completed, _ = await asyncio.wait({observed, self.go_wait},
                timeout=max(0, deadline-asyncio.get_running_loop().time()),
                return_when=asyncio.FIRST_COMPLETED)
            if self.go_wait.done():
                self.keep_directory = True
                raise RuntimeError('capability_fixture_go_failed')
            if observed not in completed:
                self.keep_directory = True
                raise RuntimeError('capability_fixture_handoff_timeout')
            owner, entry = observer.watch_admission
            admission = entry.admission.result()
            binding = strict_loads(admission.binding)
            expected = {'owner': active['owner'],
                'configurationRef': self.reference('configuration-one', 1),
                'profileId': self.profile_id, 'hubId': self.hub_id, 'authorityId': 'authority-one'}
            if (owner is not self.receiver.owner or owner._watch_controls._entries.get(entry.digest) is not entry
                    or binding['watchRequestDigest'] != entry.digest
                    or any(binding[key] != value for key, value in expected.items())):
                self.keep_directory = True
                raise ContractError('foreground_configuration_watch_changed')
        finally:
            # This waiter observes admission only. The original handler, watch,
            # subscription and Go wait remain with their existing owners.
            if not observed.done():
                observed.cancel()
            await asyncio.gather(observed, return_exceptions=True)

    async def test_registered_foreground_activation_and_eof(self):
        deadline = asyncio.get_running_loop().time()+35
        active = await self.wait_handoff('go-foreground-result.json', lambda value: value.get('phase') == 'active',
            timeout=max(0, deadline-asyncio.get_running_loop().time()))
        self.assertEqual(set(active), {'phase', 'owner', 'configurationChecksum'})
        await self._wait_configuration_watch(active, deadline=deadline)
        row = _foreground_retained_row(await self.identity.reader.current(), self.declaration, 'plugin-one')
        self.assertEqual(active['owner'], row['owner'])
        self.assertEqual(active['configurationChecksum'], self.package['configurationChecksum'])
        retained = await self.configuration_ledger.current()
        self.assertEqual(retained.sequence, 1)
        state = strict_loads(retained.latest.record)['state']
        self.assertEqual(state['owner'], row['owner'])
        self.assertEqual(state['configurationChecksum'], self.package['configurationChecksum'])
        self.assertEqual(state['revision'], 1)
        self.assertEqual(base64.b64decode(state['configurationBytes'], validate=True), b'{}')
        self.write_private('foreground-observed.json', {'owner': row['owner'], 'nativeInstanceRef': row['ref'],
            'configurationRef': self.reference('configuration-one', state['revision'])})
        complete = await self.wait_handoff('go-foreground-result.json', lambda value: value.get('phase') == 'complete', timeout=12)
        self.assertEqual(complete, {'phase': 'complete', 'activation': True, 'retainedOwner': True, 'cleanup': True})
        self.assertEqual(await asyncio.wait_for(asyncio.shield(self.go_wait), 3), 0)
        self.assertFalse(self.receiver.owner._watches)
        self.assertTrue(all(not self.errors[role] for role in ('identity', 'storage', 'host', 'capability')))
        self.success = True

    async def _cleanup(self):
        # The original Go/CLI owner must join before any borrowed service stops.
        if self.go_wait is not None:
            if not self.go_wait.done():
                self.keep_directory = True
            if await asyncio.shield(self.go_wait):
                self.keep_directory = True
        if self._configuration_start is not None:
            try:
                await asyncio.wait({self._configuration_start})
                self._configuration_start.result()
            except Exception:
                self.keep_directory = True
        if self.capability is not None:
            await self._join_cleanup_step('capability', self.capability.close)
        diagnostics = getattr(self, '_configuration_diagnostics', None)
        if diagnostics is not None and diagnostics.failed:
            self.keep_directory = True
        await super()._cleanup()
        if diagnostics is not None:
            self.assertFalse(diagnostics.failed, 'foreground configuration diagnostic capture incomplete')


class LiveAuthenticatedContextIsolationTests(LiveConfigurationSubscriptionTests):
    """Real enrolled identity and native calls; configuration stays controlled in Go."""
    test_tls_subscription_delivery_revocation_and_cleanup = None
    private_inbox_roles = ('provisioner', 'identity', 'storage', 'host', 'other-scope', 'observer')

    async def connect(self, role):
        if role == 'provisioner':
            # Keep the existing five-second startup bound. The owned broker's
            # listener must be ready before creating an admitted NATS client;
            # its internal retry can otherwise retain the first refusal.
            with (self.directory/'server.private.log').open('rb') as log:
                log.seek(0, 2)
                log.seek(max(0, log.tell()-8192))
                ready = b'Server is ready' in log.read(8192)
            if not ready:
                raise OSError('identity_fixture_broker_not_ready')
        return await super().connect(role)

    @classmethod
    def setUpClass(cls):
        if (os.environ.get('AMX_NATIVE_CONTEXT_IDENTITY_LIVE') != '1'
                or platform.system() != 'Darwin' or platform.machine() != 'arm64'):
            raise RuntimeError('A coordinated native identity context slot is required')
        binary = Path(os.environ.get('AMX_NATIVE_CONTEXT_IDENTITY_GO_BINARY', ''))
        if not binary.is_absolute() or not binary.is_file():
            raise RuntimeError('A prepared native identity context Go binary is required')

    def configure_broker_policies(self, policies, reads):
        prefixes = ['amx.v1.h.hub-one.plugins.plugin-'+name+'.' for name in ('a', 'b')]
        event = self.read_subject.removesuffix('.command') + '.event.configuration-change'
        policies['storage'] = {
            'publish': {'allow': [self.subjects['DATA'], event] + reads('IDENTITY', 'DATA')},
            'subscribe': {'allow': [self.read_subject, event, self.subjects['DATA']]}}
        # The shared TLS fixture appends the enrolled IDENTITY read subjects
        # after this hook. Keep this list unique so credential admission sees
        # the exact permissions stored in the generated JWT.
        policies['host'] = {'publish': {'allow': [self.identity_subject, self.read_subject]},
                            'subscribe': {'allow': []}}
        policies['controller'] = {'publish': {'allow': [p+'lifecycle.control' for p in prefixes]},
                                 'subscribe': {'allow': [p+'lifecycle.event' for p in prefixes]}}
        policies['context'] = {
            'publish': {'allow': [p+s for p in prefixes for s in
                ('context.reply', 'operation.invoke', 'operation.cancel')]},
            'subscribe': {'allow': [p+s for p in prefixes for s in ('context.request', 'operation.result')]}}
        policies['observer'] = {'publish': {'allow': [self.inbox_prefixes['observer']+'.observer']},
                                'subscribe': {'allow': [p+'operation.invoke' for p in prefixes]}}
        for name, prefix in zip(('a', 'b'), prefixes):
            policies['plugin-'+name] = {'publish': {'allow': [prefix+'lifecycle.event']},
                                       'subscribe': {'allow': [prefix+'lifecycle.control']}}
            policies['client-'+name] = {
                'publish': {'allow': [prefix+'context.request', prefix+'operation.result']},
                'subscribe': {'allow': [prefix+'context.reply', prefix+'operation.invoke', prefix+'operation.cancel']}}
        self.identity_permissions = policies

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        base = copy.deepcopy(state['grants'][0])
        membership = copy.deepcopy(state['memberships'][0])
        transport = copy.deepcopy(state['transports'][0])
        template = native_row()
        self.rows, self.user_seeds = [], {}
        now = datetime.now(timezone.utc)
        interval = {'issuedAt': stamp(now-timedelta(seconds=30)),
                    'expiresAt': stamp(now+timedelta(minutes=5))}
        for number, name in enumerate(('a', 'b')):
            scope = dict(self.scope, projectId='project-'+name)
            identity = ref('human-'+name)
            state['identities'].append({'ref': identity, 'status': 'active', 'kind': 'human',
                'principalId': 'user-'+name, 'externalIdentity': None})
            self.user_seeds[name] = bytes([23+number])*32
            user_transport = copy.deepcopy(transport)
            user_transport.update(ref=ref('transport-'+name), identityRef=identity,
                publicKey=base64.urlsafe_b64encode(bytes(SigningKey(self.user_seeds[name]).verify_key)).decode().rstrip('='),
                **interval)
            state['transports'].append(user_transport)
            for member_name, member_identity in (('user', identity), ('host', ref('host'))):
                member = copy.deepcopy(membership)
                member.update(ref=ref(member_name+'-member-'+name), identityRef=member_identity, scope=scope)
                state['memberships'].append(member)
            grant = copy.deepcopy(base)
            grant.update(ref=ref('inspect-'+name), callerRef=identity, actorRef=identity,
                scope=scope, contractId='task-inspect', resourceId='task-'+name, **interval)
            state['grants'].append(grant)
            for method in ('bind-instance', 'admit-operation', 'recheck', 'prepare-domain-call',
                    'prepare-subscription-call', 'admit-domain-event',
                    'prepare-configuration-initialization'):
                grant = copy.deepcopy(base)
                grant.update(ref=ref('host-'+method+'-'+name), callerRef=ref('host'), actorRef=ref('host'),
                    scope=scope, contractId='native-authority-'+method, resourceId='plugin-'+name, **interval)
                state['grants'].append(grant)
            row = copy.deepcopy(template)
            row.update(ref=ref('native-instance-'+name))
            row['facts']['grant'].update(grantId='native-grant-'+name, subjectInstanceId='plugin-'+name,
                scope=scope, resourceIds=['task-'+name], policyRef=ref('native-policy-'+name), **interval)
            row['facts']['policy'].update(reference=ref('native-policy-'+name), subjectInstanceId='plugin-'+name,
                scope=scope, decisions=[{'access': {'action': 'inspect', 'resourceClass': 'task',
                    'resourceId': 'task-'+name}, 'outcome': 'allow'}], **interval)
            row['facts'].update(scopeRef=ref('native-scope-'+name), configurationRevision=7,
                domainBindings=[{'id': 'inspect-binding', 'contractId': 'task-inspect', 'action': 'inspect',
                    'resourceClass': 'task', 'resourceIds': ['task-'+name]}])
            row['owner']['instanceId'] = 'plugin-'+name
            if name == 'b':
                row['facts']['configurationRevision'] = 1
                row['facts']['grant']['actions'].append('subscribe')
                row['facts']['grant']['resourceIds'].append('configuration-one')
                row['facts']['policy']['decisions'].append({'access': {'action': 'subscribe',
                    'resourceClass': 'configuration', 'resourceId': 'configuration-one'}, 'outcome': 'allow'})
                row['facts']['domainBindings'].append({'id': 'configuration-events',
                    'contractId': 'configuration-change-subscribe', 'action': 'subscribe',
                    'resourceClass': 'configuration', 'resourceIds': ['configuration-one']})
            self.rows.append(row)
        subscription = copy.deepcopy(base)
        subscription.update(ref=ref('subscription-grant-b'), callerRef=ref('human-b'), actorRef=ref('human-b'),
            scope=dict(self.scope, projectId='project-b'), contractId='configuration-change-subscribe',
            resourceId='configuration-one', **interval)
        state['grants'].append(subscription)
        configuration = copy.deepcopy(base)
        configuration.update(ref=ref('configuration-set-b'), callerRef=ref('host'), actorRef=ref('host'),
            scope=dict(self.scope, projectId='project-b'), contractId='configuration-set',
            resourceId='configuration-one', **interval)
        state['grants'].append(configuration)
        producer_scope = dict(self.scope, projectId='project-b')
        for collection, reference in (('memberships', 'configuration-event-member'),
                ('grants', 'configuration-event-grant')):
            item, = [entry for entry in state[collection] if entry['ref'] == ref(reference)]
            item['scope'] = copy.deepcopy(producer_scope)
        return initial

    async def asyncSetUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='agentmux-context-identity-')).resolve()
        self.connections, self.histories = [], []
        self.go_process = self.go_wait = self.go_output = None
        self.identity = self.receiver = self.broker = None
        self.workspace = self.checkout_store = self.git_executor = None
        self.keep_directory = self.success = False
        self.addAsyncCleanup(self.cleanup)
        self.errors, self.permission_events = {}, {}
        self.inbox_prefixes = {role: '_INBOX.'+secrets.token_hex(16) for role in self.private_inbox_roles}
        self.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.policy = Retention(4_194_304, 524_288)
        self.issuer_public = base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
        subscription_scope = dict(self.scope, projectId='project-b')
        self.bindings = {
            'IDENTITY': OwnerBinding('hub-one', 'identity', 'authority-one',
                'identity-authority', canonical_bytes(self.scope)),
            'DATA': OwnerBinding('hub-one', 'configuration', 'configuration-one',
                'configuration', canonical_bytes(subscription_scope))}
        self.subjects = {name: owner_subject(binding) for name, binding in self.bindings.items()}
        self.identity_subject = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        self.read_subject = 'amx.v1.h.hub-one.o.org-one.p.project-b.w._.configuration.configuration-one.command'
        self.other_subject = 'amx.v1.h.hub-one.o.other-org.p._.w._.configuration.configuration-one.command'
        self.broker = Broker(self.directory)
        self._configure_tls_and_users()
        admin = await self.start_tls_broker()
        infos = {name: await admin.jetstream().add_stream(self.policy.stream_config(
            stream=name, subject=subject)) for name, subject in self.subjects.items()}
        self.streams = {name: StreamIdentity(info.created, 0) for name, info in infos.items()}
        self.identity_created = strict_loads((await admin.request('$JS.API.STREAM.INFO.IDENTITY', b'{}', timeout=2)).data)['created']
        ledger = OwnerLedger(admin.jetstream(), stream='IDENTITY', subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'], retention=self.policy, stream_identity=self.streams['IDENTITY'])
        await ledger.append(self.initial_authority(), expected_sequence=0)
        connection = await self.connect('identity')
        history, backup = self.custody('identity', 'IDENTITY')
        self.checkpoint_receipts = []
        async def committed(receipt):
            self.checkpoint_receipts.append(receipt)
        self.identity = IdentityService(connection, stream='IDENTITY', stream_identity=self.streams['IDENTITY'],
            retention=self.policy, hub_id='hub-one', entity_id='authority-one', profile_id='profile-one',
            organization_id='org-one', issuer_ref=ref('issuer'), signing_seed=SEED, history=history,
            checkpoint_path=self.directory/'identity-checkpoint.json', checkpoint_committed=committed,
            backup_host=backup, backup_key_id='backup-one')
        await self.identity.start()
        self.host = await self.connect('host')
        self.source_connection = await self.connect('storage')
        history, backup = self.custody('configuration', 'DATA')
        self.configuration_ledger = OwnerLedger(self.source_connection.jetstream(), stream='DATA',
            subject=self.subjects['DATA'], binding=self.bindings['DATA'], retention=self.policy,
            stream_identity=self.streams['DATA'], history=history, require_completion_budget=True)
        self.route = ConfigurationEventRoute.from_ledger(self.configuration_ledger,
            account_public_key=self.account_public_key, jetstream_domain=None)
        self.source_pin = {'configurationRef': dict(ref('configuration-one'), revision=0),
            'schemaRef': 'schemas/config.json', 'sourceDigest': self.route.source_digest,
            'streamCreated': self.route.stream_created}
        self.write_private('identity-source-ready.json', {'source': self.source_pin,
            'cursor': self.route.cursor(0)})
        self.delivery_observer = await self.connect('observer')
        self.delivery_subscriptions = [await self.delivery_observer.subscribe(
            'amx.v1.h.hub-one.plugins.plugin-'+name+'.operation.invoke') for name in ('a', 'b')]
        await self.delivery_observer.flush(timeout=2)
        descriptor = os.open(self.directory/'go.private.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        self.go_output = os.fdopen(descriptor, 'wb')
        environment = dict(os.environ, AMX_NATIVE_CONTEXT_IDENTITY_LIVE_DIR=str(self.directory))
        self.go_process = await asyncio.create_subprocess_exec(os.environ['AMX_NATIVE_CONTEXT_IDENTITY_GO_BINARY'],
            '-test.run=^TestNativeLiveAuthenticatedContextIsolation$', '-test.count=1', '-test.timeout=0',
            env=environment, stdout=self.go_output, stderr=self.go_output)
        self.go_wait = asyncio.create_task(self.go_process.wait())
        declarations = await self.wait_handoff('go-identity-declarations.json', lambda value: True)
        self.assertEqual(len(declarations), 2)
        self.assertEqual(declarations[0]['owner']['pin'], declarations[1]['owner']['pin'])
        for row, declaration, name in zip(self.rows, declarations, ('a', 'b')):
            self.assertEqual(set(declaration), {'owner', 'manifestDigest', 'configurationChecksum'})
            self.assertEqual(declaration['owner']['instanceId'], 'plugin-'+name)
            row.update(declaration)
            if name == 'b':
                row['configurationEventSources'] = [self.source_pin]
            await self.command('identity-native-instance-set', ref('native-admin'),
                {'authorityId': 'authority-one', 'record': row, 'previousRef': None})
        checkpoint_root = self.directory/'configuration-checkpoints'
        checkpoint_root.mkdir(mode=0o700)
        checkpoint = CheckpointHost(checkpoint_root/'checkpoint', stream='DATA',
            commit_ref=ref('configuration-checkpoint'), binding=self.bindings['DATA'],
            stream_identity=self.streams['DATA'])
        self.receiver = ConfigurationHost(self.identity.reader, self.configuration_ledger,
            connection=self.source_connection, owner=self.rows[1]['owner'], schema_ref='schemas/config.json',
            schema_resources={'schemas/config.json': b'{"type":"object"}'}, issuer_ref=ref('issuer'),
            signing_seed=SEED, reply_prefix=self.inbox_prefixes['host']+'.', checkpoint_host=checkpoint,
            backup_host=backup, backup_key_id='backup-one',
            event_producer=event_producer(self.identity.reader, subscription_scope),
            event_account_public_key=self.account_public_key)
        await self.receiver.start()
        self.assertEqual(await self.receiver.events.enrollment_pin(), self.source_pin)
        from identity.ingress import EnrolledIngress
        ingress = EnrolledIngress(self.identity.reader, issuer_ref=ref('issuer'), signing_seed=SEED)
        envelopes = []
        for name in ('a', 'b'):
            now = datetime.now(timezone.utc)
            claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
                'authorityId': 'authority-one', 'transportRef': ref('transport-'+name), 'grantRef': ref('inspect-'+name),
                'operationId': 'isolation-'+name, 'expectedVersion': 1, 'contractId': 'task-inspect',
                'payload': {'taskId': 'task-'+name}, 'approvalRefs': [], 'issuedAt': stamp(now),
                'expiresAt': stamp(now+timedelta(seconds=60))}
            admitted = await ingress.admit(packet(claims, self.user_seeds[name]), cancellation_ref=ref('cancel-'+name))
            self.assertEqual(admitted.decision.outcome, 'allowed')
            self.assertIsNotNone(admitted.envelope)
            filename = 'identity-envelope-'+name+'.json'
            self.write_private(filename, admitted.envelope, raw=True)
            envelopes.append(str(self.directory/filename))
        self.write_private('host-signing.seed', HOST_SEED, raw=True)
        self.write_private('identity-observations.private.jsonl', b'', raw=True)
        state = self.directory/'native-state'
        state.mkdir(mode=0o700)
        snapshot = await self.identity.reader.current()
        connection = {'serverURL': self.broker.url, 'caFile': str(self.ca_file),
                      'accountPublicKey': self.account_public_key, 'hubId': 'hub-one'}
        self.write_private('identity-ready.json', {
            'serverUrl': self.broker.url, 'caFile': str(self.ca_file), 'tlsName': self.server_name,
            'leafCertificateSha256': self.leaf_digest, 'accountPublicKey': self.account_public_key,
            'authoritySubject': self.identity_subject, 'configurationSubject': self.read_subject,
            'credentialsFile': str(self.credentials['host']),
            'replyPrefix': self.inbox_prefixes['host'],
            'publishSubjects': self.identity_permissions['host']['publish']['allow'],
            'hostSigningSeedFile': str(self.directory/'host-signing.seed'), 'envelopes': envelopes,
            'observability': str(self.directory/'identity-observations.private.jsonl'),
            'enrollment': {'profileId': 'profile-one', 'hubId': 'hub-one', 'authorityId': 'authority-one',
                'organizationId': 'org-one', 'stream': 'IDENTITY', 'domain': '',
                'streamCreated': self.identity_created, 'minimumSequence': snapshot.sequence,
                'maxBytes': self.policy.max_bytes, 'replicas': 1, 'hostTransportRef': ref('host-transport'),
                'hostIdentityRef': ref('host'), 'issuerRef': ref('issuer'), 'issuerIdentityRef': ref('service'),
                'issuerInstanceId': 'ingress-one'},
            'service': {'profileId': 'profile-one', 'hubId': 'hub-one', 'serviceInstanceId': 'ingress-one',
                'serviceIdentityRef': ref('service'), 'signingKeyRef': ref('issuer')},
            'source': self.source_pin, 'cursor': self.route.cursor(0),
            'bindingId': 'configuration-events',
            'driver': {**connection, 'stateDirectory': str(state),
                'controllerCredentialsFile': str(self.credentials['controller']),
                'bindings': [{'instanceId': 'plugin-'+name, 'pin': declaration['owner']['pin'],
                    'credentialsFile': str(self.credentials['plugin-'+name])}
                    for name, declaration in zip(('a', 'b'), declarations)]},
            'context': {**connection, 'serverCredentialsFile': str(self.credentials['context']),
                'bindings': [{'instanceId': 'plugin-'+name,
                    'clientCredentialsFile': str(self.credentials['client-'+name])} for name in ('a', 'b')]}})

    async def test_authenticated_callers_remain_in_their_exact_scope(self):
        await self._run_authenticated_callers(ref('inspect-b'))

    async def test_online_native_instance_revocation_refuses_same_running_child(self):
        await self._run_authenticated_callers(ref('native-instance-b'))

    async def _run_authenticated_callers(self, revocation_target):
        opened = await self.wait_handoff('identity-subscription.json',
            lambda value: value.get('phase') in ('opened', 'subscribe-refused'))
        self.assertEqual(opened, {'phase': 'opened'})
        await self._set_identity_configuration(0)
        self.assertEqual(await self.wait_handoff('identity-subscription.json',
            lambda value: value.get('phase') == 'event-complete'), {'phase': 'event-complete'})
        await self.command('identity-revoke', ref('grant'),
            {'authorityId': 'authority-one', 'targetRef': ref('subscription-grant-b')})
        self.write_private('identity-subscription-revoked.json', {'revoked': True})
        self.assertEqual(await self.wait_handoff('identity-subscription.json',
            lambda value: value.get('phase') == 'revocation-refused'),
            {'phase': 'revocation-refused'})
        self.assertEqual(await self.wait_handoff('identity-subscription.json',
            lambda value: value.get('phase') == 'joined'), {'phase': 'joined'})
        self.assertEqual(await self.wait_handoff('go-identity-result.json',
            lambda value: value.get('phase') == 'revoke'), {'phase': 'revoke'})
        await self.command('identity-revoke', ref('grant'),
            {'authorityId': 'authority-one', 'targetRef': revocation_target})
        self.write_private('identity-revoked.json', {'revoked': True})
        complete = await self.wait_handoff('go-identity-result.json', lambda value: value.get('phase') == 'complete')
        self.assertEqual(complete, {'phase': 'complete', 'isolation': True,
            'revocation': True, 'subscription': True})
        self.assertEqual(await asyncio.shield(self.go_wait), 0)
        self.assertEqual(strict_loads((self.directory/'identity-cleanup.json').read_bytes()), {'phase': 'joined'})
        self.assertTrue(all(entry.joined for entry in self.receiver.subscriptions._entries.values()))
        self.assertFalse(self.receiver.owner._watches)
        await self.delivery_observer.flush(timeout=2)
        for name, subscription in zip(('a', 'b'), self.delivery_subscriptions):
            message = await subscription.next_msg(timeout=1)
            invocation = strict_loads(message.data)
            self.assertEqual(invocation['owner']['instanceId'], 'plugin-'+name)
            self.assertEqual(invocation['operation']['operationId'], 'isolation-'+name)
            self.assertEqual(subscription.pending_msgs, 0,
                             'a refused or revoked operation reached the child')
            await subscription.unsubscribe()
        self.assertTrue(all(not errors for errors in self.errors.values()))
        self.success = True

    async def _set_identity_configuration(self, revision):
        material = strict_loads((self.directory/'identity-configuration-b.json').read_bytes())
        self.assertEqual(set(material), {'configurationBytes'})
        configuration_bytes = base64.b64decode(material['configurationBytes'], validate=True)
        self.assertEqual('sha256:'+hashlib.sha256(configuration_bytes).hexdigest(),
            self.rows[1]['configurationChecksum'])
        payload = {'configurationRef': dict(ref('configuration-one'), revision=revision),
            'owner': self.rows[1]['owner'], 'schemaRef': 'schemas/config.json',
            'configurationBytes': material['configurationBytes'], 'secretReferences': []}
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('host-transport'), 'grantRef': ref('configuration-set-b'),
            'operationId': 'configuration-'+secrets.token_hex(16), 'expectedVersion': revision,
            'contractId': 'configuration-set', 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=60))}
        admitted = await self.identity.ingress.admit(packet(claims, HOST_SEED),
            cancellation_ref=ref('configuration-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        response = await self.exchange(self.host, self.read_subject, admitted.envelope,
            self.host.new_inbox())
        from state_owner.configuration import verify_configuration_response
        verified = verify_configuration_response(response, admitted.envelope,
            public_key=self.issuer_public, issuer_ref=ref('issuer'), now=datetime.now(timezone.utc))
        self.assertEqual(verified['state']['revision'], revision+1)


class AuthenticatedContextFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_provisioner_waits_for_owned_broker_readiness(self):
        from unittest.mock import AsyncMock
        fixture = LiveAuthenticatedContextIsolationTests('test_authenticated_callers_remain_in_their_exact_scope')
        with tempfile.TemporaryDirectory() as directory:
            fixture.directory = Path(directory)
            log = fixture.directory/'server.private.log'
            log.write_bytes(b'Listening for client connections\n')
            sentinel = object()
            with patch.object(LiveConfigurationSubscriptionTests, 'connect', new=AsyncMock(return_value=sentinel)) as connect:
                with self.assertRaisesRegex(OSError, 'identity_fixture_broker_not_ready'):
                    await fixture.connect('provisioner')
                connect.assert_not_awaited()
                log.write_bytes(b'Server is ready\n'+b'x'*8192)
                with self.assertRaisesRegex(OSError, 'identity_fixture_broker_not_ready'):
                    await fixture.connect('provisioner')
                connect.assert_not_awaited()
                log.write_bytes(b'x'*8192+b'Server is ready\n')
                self.assertIs(await fixture.connect('provisioner'), sentinel)
                connect.assert_awaited_once_with('provisioner')

    async def test_scope_material_uses_current_enrolled_identity(self):
        from identity.authority import AuthoritySnapshot, _indexes
        from identity.ingress import EnrolledIngress
        fixture = LiveAuthenticatedContextIsolationTests('test_authenticated_callers_remain_in_their_exact_scope')
        fixture.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        initial = fixture.initial_authority()
        initial['state']['nativeInstances'] = fixture.rows
        _indexes(initial['state'], 'hub-one')
        by_ref = lambda collection, name: next(item for item in initial['state'][collection]
            if item['ref'] == ref(name))
        project_b = {'organizationId': 'org-one', 'projectId': 'project-b', 'workspaceId': None}
        self.assertEqual(by_ref('grants', 'subscription-grant-b')['scope'], project_b)
        self.assertEqual(by_ref('grants', 'subscription-grant-b')['callerRef'], ref('human-b'))
        self.assertEqual(by_ref('grants', 'subscription-grant-b')['actorRef'], ref('human-b'))
        self.assertEqual(by_ref('grants', 'configuration-set-b')['scope'], project_b)
        self.assertEqual(by_ref('grants', 'configuration-event-grant')['scope'], project_b)
        self.assertEqual(by_ref('memberships', 'configuration-event-member')['scope'], project_b)
        self.assertEqual(fixture.rows[0]['facts']['domainBindings'], [
            {'id': 'inspect-binding', 'contractId': 'task-inspect', 'action': 'inspect',
             'resourceClass': 'task', 'resourceIds': ['task-a']}])
        self.assertEqual(fixture.rows[1]['facts']['domainBindings'][1],
            {'id': 'configuration-events', 'contractId': 'configuration-change-subscribe',
             'action': 'subscribe', 'resourceClass': 'configuration',
             'resourceIds': ['configuration-one']})
        class Reader:
            async def current(self):
                return AuthoritySnapshot(canonical_bytes(initial), 1)
        ingress = EnrolledIngress(Reader(), issuer_ref=ref('issuer'), signing_seed=SEED)
        envelopes = []
        for name, row in zip(('a', 'b'), fixture.rows):
            now = datetime.now(timezone.utc)
            claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
                'authorityId': 'authority-one', 'transportRef': ref('transport-'+name), 'grantRef': ref('inspect-'+name),
                'operationId': 'isolation-'+name, 'expectedVersion': 1, 'contractId': 'task-inspect',
                'payload': {'taskId': 'task-'+name}, 'approvalRefs': [], 'issuedAt': stamp(now),
                'expiresAt': stamp(now+timedelta(seconds=60))}
            admitted = await ingress.admit(packet(claims, fixture.user_seeds[name]), cancellation_ref=ref('cancel-'+name))
            self.assertEqual(admitted.decision.outcome, 'allowed')
            operation = strict_loads(admitted.envelope)['operation']
            self.assertEqual(operation['scope'], row['facts']['grant']['scope'])
            self.assertEqual(operation['caller']['authenticatedIdentityRef'], ref('human-'+name))
            self.assertEqual(operation['effectiveActorRef'], ref('human-'+name))
            envelopes.append(admitted.envelope)
        self.assertNotEqual(envelopes[0], envelopes[1])
        self.assertEqual(unittest.TestLoader().getTestCaseNames(LiveAuthenticatedContextIsolationTests),
                         ['test_authenticated_callers_remain_in_their_exact_scope'])


class ConfigurationSubscriptionSupervisorTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_source_close_retains_worker_until_explicit_recovery(self):
        fixture = LiveConfigurationSubscriptionTests('test_tls_subscription_delivery_revocation_and_cleanup')
        closed, source_calls = [], []
        requested, recover = asyncio.Event(), asyncio.Event()
        fixture.go_wait = asyncio.create_task(asyncio.sleep(0, result=0))
        await fixture.go_wait
        fixture.go_output = None
        fixture.keep_directory = fixture.success = False
        async def source_close(**kwargs):
            source_calls.append(True)
            if len(source_calls)==1:
                raise RuntimeError('controlled source close failure')
            closed.append('source')
        async def identity_close():
            closed.append('identity')
        async def recovery(attempt):
            self.assertEqual(attempt, 0)
            requested.set()
            await recover.wait()
            return 1
        fixture.receiver = SimpleNamespace(close=source_close)
        fixture.identity = SimpleNamespace(close=identity_close)
        fixture.histories = [SimpleNamespace(close=lambda: closed.append('history'))]
        fixture.connections = []
        fixture.broker = SimpleNamespace(stop=lambda: closed.append('broker'))
        states = []
        fixture.write_private = lambda name, value: states.append((name, value))
        fixture._wait_cleanup_recovery = recovery
        cleanup = asyncio.create_task(fixture.cleanup())
        try:
            await requested.wait()
            original_worker = fixture._cleanup_work
            second = asyncio.create_task(fixture.cleanup())
            await asyncio.sleep(0)
            self.assertIs(fixture._cleanup_work, original_worker)
            self.assertFalse(original_worker.done())
            self.assertFalse(cleanup.done() or second.done())
            self.assertEqual(len(source_calls), 1)
            self.assertEqual(closed, [])
            self.assertEqual(states, [('python-cleanup.json', {
                'phase': 'cleanup-required', 'owner': 'configuration', 'attempt': 0})])
            recover.set()
            await asyncio.gather(cleanup, second)
            self.assertIs(fixture._cleanup_work, original_worker)
            self.assertEqual(len(source_calls), 2)
            self.assertEqual(closed, ['source', 'identity', 'history', 'broker'])
        finally:
            recover.set()
            await asyncio.gather(cleanup, fixture._cleanup_work, return_exceptions=True)

    async def test_cancelled_cleanup_keeps_original_go_wait_and_borrowed_services(self):
        fixture = LiveConfigurationSubscriptionTests('test_tls_subscription_delivery_revocation_and_cleanup')
        release, started = asyncio.Event(), asyncio.Event()
        closed = []
        async def original_wait():
            started.set()
            await release.wait()
            closed.append('go')
            return 0
        async def close_service(name, **kwargs):
            closed.append(name)
        fixture.go_wait = asyncio.create_task(original_wait())
        fixture.go_output = None
        fixture.keep_directory = fixture.success = False
        fixture.receiver = SimpleNamespace(close=lambda **kwargs: close_service('source', **kwargs))
        fixture.identity = SimpleNamespace(close=lambda: close_service('identity'))
        fixture.histories = [SimpleNamespace(close=lambda: closed.append('history'))]
        fixture.connections = [SimpleNamespace(close=lambda: close_service('connection'))]
        fixture.broker = SimpleNamespace(stop=lambda: closed.append('broker'))
        await started.wait()
        cleanup = asyncio.create_task(fixture.cleanup())
        try:
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            self.assertTrue(fixture.keep_directory)
            self.assertEqual(closed, [])
            cleanup.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await cleanup
            self.assertFalse(fixture.go_wait.done())
            self.assertFalse(fixture._cleanup_work.done())
            self.assertEqual(closed, [])
            release.set()
            await fixture.cleanup()
            self.assertEqual(closed, ['go', 'source', 'identity', 'history', 'connection', 'broker'])
            self.assertFalse(fixture.go_wait.cancelled())
        finally:
            release.set()
            await asyncio.gather(cleanup, fixture.go_wait, fixture._cleanup_work, return_exceptions=True)


class ForegroundContextSupervisorTests(unittest.IsolatedAsyncioTestCase):
    async def test_foreground_waits_for_original_watch_before_retained_read_or_eof(self):
        for go_fails in (False, True):
            with self.subTest(go_fails=go_fails), tempfile.TemporaryDirectory() as directory:
                fixture = LiveRegisteredContextForegroundTests('test_registered_foreground_activation_and_eof')
                fixture.directory = Path(directory)
                path = fixture.directory/'diagnostics.private.jsonl'
                path.touch(mode=0o600)
                observer = fixture._configuration_diagnostics = _ForegroundConfigurationDiagnostics(path)
                fixture.hub_id, fixture.profile_id = 'hub-one', 'profile-one'
                fixture.keep_directory = False
                active = {'phase': 'active', 'owner': native_row()['owner'],
                    'configurationChecksum': 'sha256:'+'a'*64}
                entry = SimpleNamespace(digest='sha256:'+'b'*64,
                    admission=asyncio.get_running_loop().create_future())
                envelope = {'payload': {'owner': active['owner'],
                    'configurationRef': fixture.reference('configuration-one', 1)}}
                snapshot = object()
                def admit(original, authority, raw):
                    self.assertIs(original, entry)
                    self.assertIs(authority, snapshot)
                    self.assertIs(raw, envelope)
                    self.assertFalse(observer.watch_admitted.is_set())
                    entry.admission.set_result(SimpleNamespace(binding=canonical_bytes({
                        **raw['payload'], 'profileId': fixture.profile_id, 'hubId': fixture.hub_id,
                        'authorityId': 'authority-one', 'watchRequestDigest': entry.digest})))
                    return 'original admission result'
                async def unused(*args, **kwargs):
                    self.fail('watch observer called an unrelated handler')
                owner = SimpleNamespace(_receive=unused, handle=unused,
                    _watch_controls=SimpleNamespace(handle=unused, admit=admit, _entries={entry.digest: entry}))
                fixture.receiver = SimpleNamespace(owner=owner)
                observer.install(owner)
                requested, release_go = asyncio.Event(), asyncio.Event()
                reads, handoffs = [], []
                reached = RuntimeError('controlled retained read reached')
                async def current():
                    self.assertIs(observer.watch_admission[0], owner)
                    self.assertIs(observer.watch_admission[1], entry)
                    reads.append(True)
                    raise reached
                async def handoff(name, accept, *, timeout):
                    self.assertEqual(name, 'go-foreground-result.json')
                    self.assertTrue(0 < timeout <= 35)
                    self.assertTrue(accept(active))
                    handoffs.append(name)
                    requested.set()
                    return active
                async def original_wait():
                    await release_go.wait()
                    return 1 if go_fails else 0
                fixture.identity = SimpleNamespace(reader=SimpleNamespace(current=current))
                fixture.wait_handoff = handoff
                fixture.go_wait = asyncio.create_task(original_wait())
                original = fixture.go_wait
                call = asyncio.create_task(fixture.test_registered_foreground_activation_and_eof())
                try:
                    await requested.wait()
                    await asyncio.sleep(0)
                    self.assertFalse(call.done())
                    self.assertEqual(reads, [])
                    self.assertFalse((fixture.directory/'foreground-observed.json').exists())
                    if go_fails:
                        release_go.set()
                        with self.assertRaisesRegex(RuntimeError, '^capability_fixture_go_failed$'):
                            await call
                        self.assertEqual(reads, [])
                        self.assertTrue(fixture.keep_directory)
                    else:
                        self.assertEqual(owner._watch_controls.admit(entry, snapshot, envelope),
                            'original admission result')
                        with self.assertRaises(RuntimeError) as caught:
                            await call
                        self.assertIs(caught.exception, reached)
                        self.assertEqual(reads, [True])
                    self.assertIs(fixture.go_wait, original)
                    self.assertFalse(original.cancelled())
                    self.assertEqual(handoffs, ['go-foreground-result.json'])
                finally:
                    release_go.set()
                    await asyncio.gather(call, original, return_exceptions=True)

    async def test_foreground_watch_wait_refuses_changed_binding_and_retains_original_go_wait(self):
        for change in ('owner', 'configuration', 'profile', 'entry', 'deadline', 'cancel'):
            with self.subTest(change=change):
                fixture = LiveRegisteredContextForegroundTests('test_registered_foreground_activation_and_eof')
                fixture.hub_id, fixture.profile_id = 'hub-one', 'profile-one'
                fixture.keep_directory = False
                active = {'owner': native_row()['owner']}
                binding = {'owner': copy.deepcopy(active['owner']),
                    'configurationRef': fixture.reference('configuration-one', 1),
                    'profileId': 'profile-one', 'hubId': 'hub-one', 'authorityId': 'authority-one',
                    'watchRequestDigest': 'sha256:'+'a'*64}
                entry = SimpleNamespace(digest=binding['watchRequestDigest'],
                    admission=asyncio.get_running_loop().create_future())
                owner = SimpleNamespace(_watch_controls=SimpleNamespace(_entries={entry.digest: entry}))
                fixture.receiver = SimpleNamespace(owner=owner)
                observer = fixture._configuration_diagnostics = SimpleNamespace(
                    watch_admitted=asyncio.Event(), watch_admission=(owner, entry))
                if change == 'owner':
                    binding['owner']['generation'] += 1
                elif change == 'configuration':
                    binding['configurationRef']['id'] = 'another-configuration'
                elif change == 'profile':
                    binding['profileId'] = 'another-profile'
                elif change == 'entry':
                    owner._watch_controls._entries[entry.digest] = object()
                entry.admission.set_result(SimpleNamespace(binding=canonical_bytes(binding)))
                if change != 'cancel':
                    observer.watch_admitted.set()
                release = asyncio.Event()
                fixture.go_wait = asyncio.create_task(release.wait())
                original = fixture.go_wait
                deadline = asyncio.get_running_loop().time() + (-1 if change == 'deadline' else 35)
                call = asyncio.create_task(fixture._wait_configuration_watch(active, deadline=deadline))
                try:
                    if change == 'cancel':
                        await asyncio.sleep(0)
                        call.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await call
                    elif change == 'deadline':
                        with self.assertRaisesRegex(RuntimeError, '^capability_fixture_handoff_timeout$'):
                            await call
                    else:
                        with self.assertRaisesRegex(ContractError, '^foreground_configuration_watch_changed$'):
                            await call
                    self.assertIs(fixture.go_wait, original)
                    self.assertFalse(original.done())
                    self.assertFalse(original.cancelled())
                finally:
                    release.set()
                    await asyncio.gather(call, original, return_exceptions=True)

    async def test_fixture_connect_retains_paired_client_and_exact_tls_options(self):
        certificate = b'controlled fixture peer certificate'
        peer = SimpleNamespace(version=lambda: 'TLSv1.3', getpeercert=lambda **kwargs: certificate)
        for outcome in ('connected', 'failed', 'canceled'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                fixture = SimpleNamespace(errors={}, permission_events={}, connections=[],
                    directory=Path(directory), broker=SimpleNamespace(url='tls://127.0.0.1:4222'),
                    credentials={'storage': Path(directory)/'storage.creds'}, tls=object(),
                    server_name='broker.example', inbox_prefixes={'storage': '_INBOX.abcdefghijklmnop'},
                    leaf_digest='sha256:'+hashlib.sha256(certificate).hexdigest(), assertEqual=self.assertEqual)
                async def connect(endpoint, **options):
                    self.assertEqual(fixture.connections, [client])
                    self.assertEqual(endpoint, fixture.broker.url)
                    self.assertTrue(callable(options.pop('error_cb')))
                    self.assertEqual(options, {'user_credentials': str(fixture.credentials['storage']),
                        'tls': fixture.tls, 'tls_hostname': fixture.server_name, 'tls_handshake_first': True,
                        'allow_reconnect': False, 'connect_timeout': 2,
                        'inbox_prefix': fixture.inbox_prefixes['storage']})
                    if outcome == 'failed':
                        raise OSError('controlled connection failure')
                    if outcome == 'canceled':
                        raise asyncio.CancelledError()
                client = SimpleNamespace(connect=connect,
                    _transport=SimpleNamespace(_io_writer=SimpleNamespace(get_extra_info=lambda name: peer)))
                with patch.object(tls_fixture, 'new_client', return_value=client) as factory, \
                        patch.object(tls_fixture.nats, 'connect') as raw_connect:
                    if outcome == 'connected':
                        self.assertIs(await tls_fixture.LiveCapabilityTests.connect(fixture, 'storage'), client)
                    else:
                        error = OSError if outcome == 'failed' else asyncio.CancelledError
                        with self.assertRaises(error):
                            await tls_fixture.LiveCapabilityTests.connect(fixture, 'storage')
                    factory.assert_called_once_with()
                    raw_connect.assert_not_called()
                self.assertEqual(fixture.connections, [client])

    async def test_identity_diagnostics_preserve_original_task_reply_and_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'diagnostics.private.jsonl'
            path.touch(mode=0o600)
            diagnostic = _ForegroundConfigurationDiagnostics(path)
            service = object.__new__(_ForegroundIdentityService)
            service._diagnostics = diagnostic
            original_task = asyncio.current_task()
            request = canonical_bytes({'claims': {'purpose': 'agentmux-native-authority-request-v1',
                'method': 'bind-instance', 'expiresAt': stamp(datetime.now(timezone.utc)+timedelta(seconds=5)),
                'input': 'private-payload'}})
            async def original(instance, raw):
                self.assertIs(instance, service)
                self.assertIs(asyncio.current_task(), original_task)
                self.assertEqual(raw, request)
                return b'original private response'
            with patch.object(IdentityService, 'handle', original):
                self.assertEqual(await service.handle(request), b'original private response')
            frames = [strict_loads(line) for line in path.read_bytes().splitlines()]
            self.assertEqual([f['phase'] for f in frames], ['started', 'succeeded'])
            self.assertTrue(all(f['request'] == 'native-authority-bind-instance' and
                f['deadlineExpired'] is False and type(f['elapsedMs']) is int and f['elapsedMs'] >= 0
                and datetime.fromisoformat(f['recordedAt']).tzinfo is not None for f in frames))
            self.assertLessEqual(frames[0]['elapsedMs'], frames[1]['elapsedMs'])
            expired = strict_loads(request)
            expired['claims']['expiresAt'] = stamp(datetime.now(timezone.utc)-timedelta(seconds=1))
            request = canonical_bytes(expired)
            refused = ContractError('native_request_expired')
            async def failure(instance, raw):
                self.assertIs(asyncio.current_task(), original_task)
                raise refused
            with patch.object(IdentityService, 'handle', failure), self.assertRaises(ContractError) as caught:
                await service.handle(request)
            self.assertIs(caught.exception, refused)
            final = strict_loads(path.read_bytes().splitlines()[-1])
            self.assertEqual((final['phase'], final['code'], final['deadlineExpired']),
                ('refused', 'native_request_expired', True))
            for raw in (b'private-secret', canonical_bytes({'claims': {'method': 'private-secret',
                    'purpose': 'agentmux-native-authority-request-v1', 'expiresAt': 'private-secret'}})):
                self.assertEqual(diagnostic.authority_kind(raw), 'native-authority-other')
                self.assertIsNone(diagnostic.deadline(raw))
            self.assertNotIn(b'private-', path.read_bytes())
            self.assertFalse(diagnostic.failed)

    async def test_configuration_diagnostics_preserve_original_calls_and_fixed_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'diagnostics.private.jsonl'
            path.touch(mode=0o600)
            diagnostic = _ForegroundConfigurationDiagnostics(path)
            original_task = asyncio.current_task()
            read = canonical_bytes({'contractId': 'configuration-read', 'payload': 'private-payload'})
            watch = canonical_bytes({'contractId': 'configuration-watch', 'payload': 'private-payload'})
            close = canonical_bytes({'claims': {'purpose': 'agentmux-configuration-watch-close-v1'}})
            refused = ContractError('configuration_watch_admission_refused')
            calls = []
            async def handle(raw):
                self.assertIs(asyncio.current_task(), original_task)
                calls.append(raw)
                if raw == watch:
                    raise refused
                return b'private signed response'
            async def receive(message):
                return await owner.handle(message.data)
            async def control(raw, *, reply_subject):
                self.assertIs(asyncio.current_task(), original_task)
                calls.append((raw, reply_subject))
                return b'private signed cleanup response'
            def admit(entry, authority, envelope):
                calls.append((entry, authority, envelope))
            owner = SimpleNamespace(_receive=receive, handle=handle,
                _watch_controls=SimpleNamespace(handle=control, admit=admit))
            diagnostic.install(owner)
            self.assertEqual(await owner._receive(SimpleNamespace(data=read)), b'private signed response')
            with self.assertRaises(ContractError) as caught:
                await owner._receive(SimpleNamespace(data=watch))
            self.assertIs(caught.exception, refused)
            owner._watch_controls.admit('private-entry', 'private-authority', watch)
            self.assertEqual(await owner._watch_controls.handle(close, reply_subject='private-reply'),
                b'private signed cleanup response')
            self.assertEqual(calls, [read, watch, ('private-entry', 'private-authority', watch), (close, 'private-reply')])
            frames = [strict_loads(line) for line in path.read_bytes().splitlines()]
            self.assertEqual([(f['request'], f['phase'], f['code']) for f in frames], [
                ('other', 'installed', 'installed'),
                ('configuration-read', 'received', 'received'), ('configuration-read', 'started', 'started'),
                ('configuration-read', 'succeeded', 'succeeded'), ('configuration-watch', 'received', 'received'),
                ('configuration-watch', 'started', 'started'),
                ('configuration-watch', 'refused', 'configuration_watch_admission_refused'),
                ('configuration-watch', 'admitted', 'admitted'), ('watch-close', 'started', 'started'),
                ('watch-close', 'succeeded', 'succeeded')])
            self.assertNotIn(b'private-', path.read_bytes())
            self.assertFalse(diagnostic.failed)

    async def test_configuration_diagnostics_redact_unknown_errors_and_preserve_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'diagnostics.private.jsonl'
            path.touch(mode=0o600)
            diagnostic = _ForegroundConfigurationDiagnostics(path)
            for error, code in ((ContractError('private-secret'), 'contract_error'),
                                (RuntimeError('private-secret'), 'handler_error'),
                                (asyncio.CancelledError('private-secret'), 'canceled')):
                async def original():
                    raise error
                with self.assertRaises(type(error)) as caught:
                    await diagnostic.invoke('configuration-watch', original)
                self.assertIs(caught.exception, error)
                self.assertEqual(strict_loads(path.read_bytes().splitlines()[-1])['code'], code)
            for raw in (b'private-secret', b'[]', canonical_bytes({'contractId': 'private-secret'})):
                self.assertEqual(diagnostic.kind(raw), 'other')
            self.assertNotIn(b'private-secret', path.read_bytes())
            self.assertFalse(diagnostic.failed)

    async def test_configuration_diagnostic_failure_does_not_replace_original_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'diagnostics.private.jsonl'
            path.touch(mode=0o600)
            async def original():
                return b'unchanged'
            for change in ('public', 'replaced', 'capacity'):
                path.chmod(0o600)
                diagnostic = _ForegroundConfigurationDiagnostics(path)
                before = path.read_bytes()
                if change == 'public':
                    path.chmod(0o644)
                elif change == 'replaced':
                    path.rename(Path(directory)/'original')
                    path.touch(mode=0o600)
                    before = b''
                else:
                    diagnostic.written = 65536
                self.assertEqual(await diagnostic.invoke('configuration-read', original), b'unchanged')
                self.assertTrue(diagnostic.failed)
                self.assertEqual(path.read_bytes(), before)

    def package(self):
        pin = copy.deepcopy(native_row()['owner']['pin'])
        pin['packageId'] = 'native_foreground'
        return {'instanceId': 'plugin-one', 'pin': pin, 'manifestDigest': pin['manifestChecksum'],
            'configurationChecksum': 'sha256:'+hashlib.sha256(b'{}').hexdigest(),
            'schemaRef': 'schemas/config.json', 'configurationBytes': 'e30=',
            'catalog': {'directory': '/private/package', 'manifestPath': 'manifest.json', 'sourceId': 'fixture',
                'sourcePath': '/private/package/original.md', 'scope': 'repo', 'sourceFile': '/private/source.md',
                'sourceChecksum': 'sha256:'+'a'*64, 'limits': {'maxFileBytes': 134217728,
                    'maxTotalBytes': 268435456, 'maxFiles': 64}},
            'contracts': [{'kind': 'tool', 'contractRef': 'urn:fixture:tool'}]}

    def retained(self):
        package = self.package()
        row = native_row()
        row['owner']['pin'] = package['pin']
        row['configurationChecksum'] = package['configurationChecksum']
        row['configurationEventSources'] = []
        declaration = {key: copy.deepcopy(row[key]) for key in ('identityRef', 'manifestDigest',
            'configurationChecksum', 'facts', 'configurationEventSources')}
        declaration.update(recordRef=copy.deepcopy(row['ref']), pin=copy.deepcopy(row['owner']['pin']))
        return row, declaration

    def test_package_handoff_preserves_pins_and_refuses_predicted_owner(self):
        value = self.package()
        selected = _foreground_package(value)
        value['pin']['version'] = '2.0.0'
        self.assertEqual(selected['pin']['version'], '1.0.0')
        for change in (lambda item: item.update(owner=native_row()['owner']),
                       lambda item: item.update(configurationBytes='eyJjaGFuZ2VkIjp0cnVlfQ=='),
                       lambda item: item.update(configurationChecksum='sha256:'+'0'*64),
                       lambda item: item['pin'].update(packageId='other'),
                       lambda item: item.update(instanceId='other'),
                       lambda item: item['catalog'].update(directory='relative'),
                       lambda item: item.update(schemaRef='../schema.json')):
            candidate = self.package()
            change(candidate)
            with self.assertRaises(ContractError):
                _foreground_package(candidate)

    def test_retained_row_must_match_actual_package_and_configuration(self):
        row, declaration = self.retained()
        snapshot = lambda rows: SimpleNamespace(record=canonical_bytes({'state': {'nativeInstances': rows}}))
        admitted = _foreground_retained_row(snapshot([row]), declaration, 'plugin-one')
        self.assertEqual(admitted, row)
        admitted['owner']['generation'] = 99
        self.assertEqual(row['owner']['generation'], 1)
        for change in (lambda item: item['owner']['pin'].update(packageChecksum='sha256:'+'0'*64),
                       lambda item: item['owner'].update(generation=2),
                       lambda item: item.update(configurationChecksum='sha256:'+'0'*64),
                       lambda item: item['facts'].update(configurationRevision=2),
                       lambda item: item.update(configurationEventSources=[{'changed': True}])):
            candidate = copy.deepcopy(row)
            change(candidate)
            with self.assertRaises(ContractError):
                _foreground_retained_row(snapshot([candidate]), declaration, 'plugin-one')
        for rows in ([], [row, copy.deepcopy(row)]):
            with self.assertRaises(ContractError):
                _foreground_retained_row(snapshot(rows), declaration, 'plugin-one')

    async def test_identity_response_waits_for_original_activation_observer(self):
        events = []
        service = object.__new__(_ForegroundIdentityService)
        owner = native_row()['owner']
        async def original(instance, request):
            events.append('committed')
            return b'original signed response'
        async def observed(actual):
            self.assertEqual(actual, owner)
            events.append('configuration-ready')
        service._activation_observed = observed
        request = canonical_bytes({'claims': {'purpose': 'agentmux-native-authority-request-v1',
            'method': 'activate-instance', 'owner': owner}})
        with patch.object(IdentityService, '_handle', original):
            self.assertEqual(await service._handle(request), b'original signed response')
        self.assertEqual(events, ['committed', 'configuration-ready'])
        async def refused(instance, request):
            raise ContractError('native_activation_not_authorized')
        events.clear()
        with patch.object(IdentityService, '_handle', refused), self.assertRaises(ContractError):
            await service._handle(request)
        self.assertEqual(events, [])

    async def test_complete_selection_uses_registered_scope_and_exact_transport_credentials(self):
        from identity.authority import AuthorityReader
        from identity.test_application_host_selection import selection
        from identity.test_native_transport_selection import credentials
        with tempfile.TemporaryDirectory() as directory:
            fixture = LiveRegisteredContextForegroundTests('test_registered_foreground_activation_and_eof')
            fixture.directory = Path(directory).resolve()
            fixture.hub_id, fixture.profile_id = 'registered_hub', 'profile_registered'
            fixture.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
            fixture.policy = Retention(4_194_304, 524_288)
            fixture.package = self.package()
            fixture.capability_public = base64.urlsafe_b64encode(
                bytes(SigningKey(bytes([13])*32).verify_key)).decode().rstrip('=')
            base = selection()
            kernel = dict(base['kernelScope'], hubId=fixture.hub_id, profileId=fixture.profile_id)
            fixture.profile = {'schemaVersion': '1.0.0', 'hostPolicy': str(fixture.directory/'host.json'),
                'repositoryRoot': str(fixture.directory/'repository'), 'kernelScope': kernel}
            fixture.ca_file = fixture.directory/'ca.pem'
            fixture.ca_file.write_text(base['connection']['rootsPEM'])
            fixture.ca_file.chmod(0o600)
            fixture.broker = SimpleNamespace(url=base['connection']['endpoint'])
            fixture.server_name = base['connection']['serverName']
            fixture.leaf_digest = base['connection']['leafCertificateSHA256']
            fixture.identity_created = stamp(datetime.now(timezone.utc)-timedelta(seconds=1))
            fixture.route = SimpleNamespace(source_digest='sha256:'+'e'*64,
                                            stream_created=fixture.identity_created)
            prefix = 'amx.v1.h.'+fixture.hub_id+'.o.org-one.'
            fixture.identity_subject = prefix+'identity.authority-one.command'
            fixture.read_subject = prefix+'p._.w._.configuration.configuration-one.command'
            fixture.capability_subject = prefix+'p._.w._.capability.storage-owner.command'
            fixture.subjects = {'DATA': 'owner.configuration'}
            fixture.inbox_prefixes = {role: '_INBOX.'+secrets.token_hex(16)
                                     for role in fixture.private_inbox_roles}
            reads = lambda *names: [prefix+name for name in names for prefix in
                                   ('$JS.API.STREAM.INFO.', '$JS.API.STREAM.MSG.GET.')]
            policies = {'host': {'publish': {'allow': [fixture.identity_subject, fixture.read_subject]},
                                 'subscribe': {'allow': [fixture.inbox_prefixes['host']+'.>']}}}
            fixture.configure_broker_policies(policies, reads)
            policies['host']['publish']['allow'].extend(reads('IDENTITY'))
            fixture.credentials = {}
            for index, role in enumerate(('host', 'controller', 'plugin', 'context', 'context-client'), 2):
                policy = policies[role]
                raw, account, _ = credentials(index, policy['publish']['allow'], policy['subscribe']['allow'])
                fixture.account_public_key = account
                path = fixture.directory/(role+'.creds')
                fixture.write_private(path.name, raw, raw=True)
                fixture.credentials[role] = path
            initial = fixture.initial_authority()
            reader = AuthorityReader(None, stream='IDENTITY', subject=fixture.identity_subject,
                hub_id=fixture.hub_id, entity_id='authority-one', profile_id=fixture.profile_id,
                organization_id='org-one')
            snapshot = reader._validate_snapshot(canonical_bytes(initial), 1)
            async def current():
                return snapshot
            fixture.identity = SimpleNamespace(reader=SimpleNamespace(current=current))
            await fixture.prepare_foreground_selection()
            ready = strict_loads((fixture.directory/'foreground-ready.json').read_bytes())
            self.assertEqual(set(ready), {'compositionPath', 'compositionSHA256'})
            raw = Path(ready['compositionPath']).read_bytes()
            self.assertEqual(ready['compositionSHA256'], 'sha256:'+hashlib.sha256(raw).hexdigest())
            composition = strict_loads(raw)
            self.assertEqual(composition['nativeContext']['profileId'], fixture.profile_id)
            self.assertEqual(composition['driver']['hubId'], fixture.hub_id)
            selected = NativeHostSelection((fixture.directory/'native-selection.json').read_bytes())
            selected.load_credentials()
            self.assertEqual(selected.policy['kernelScope'], kernel)
            self.assertEqual(selected.lifecycle_trust_options()['serverName'], fixture.server_name)
            self.assertEqual(selected.context_options()['hubId'], fixture.hub_id)
            self.assertEqual(selected.subscription_routes()[0]['source'], fixture.source_pin)
            self.assertEqual(selected.configuration_routes()['plugin-one']['configurationRef']['revision'], 0)
            self.assertNotIn('owner', selected.activation_declarations()['plugin-one'])
            self.assertFalse(any('_INBOX.' in subject for role in ('controller', 'plugin', 'context', 'context-client')
                for direction in ('publish', 'subscribe') for subject in policies[role][direction]['allow']))

    async def test_cancelled_observer_retains_one_configuration_start_and_cleanup_order(self):
        fixture = LiveRegisteredContextForegroundTests('test_registered_foreground_activation_and_eof')
        row, fixture.declaration = self.retained()
        snapshot = SimpleNamespace(record=canonical_bytes({'state': {'nativeInstances': [row]}}))
        started, release, go_release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        events = []
        async def current():
            return snapshot
        async def close(name, **kwargs):
            events.append(name)
        async def start(actual):
            self.assertEqual(actual, row)
            fixture.receiver = SimpleNamespace(close=lambda **kwargs: close('configuration', **kwargs))
            events.append('configuration-start')
            started.set()
            await release.wait()
            raise ContractError('controlled_configuration_start_failure')
        fixture._configuration_start = None
        fixture._start_allocated_configuration = start
        fixture.identity = SimpleNamespace(reader=SimpleNamespace(current=current), close=lambda: close('identity'))
        call = asyncio.create_task(fixture.start_allocated_configuration(row['owner']))
        await started.wait()
        original = fixture._configuration_start
        call.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await call
        second = asyncio.create_task(fixture.start_allocated_configuration(row['owner']))
        await asyncio.sleep(0)
        self.assertIs(fixture._configuration_start, original)
        self.assertFalse(original.done())
        release.set()
        with self.assertRaises(ContractError):
            await second
        self.assertEqual(events, ['configuration-start'])
        async def original_wait():
            await go_release.wait()
            events.append('go')
            return 1
        fixture.go_wait = asyncio.create_task(original_wait())
        fixture.go_output = None
        fixture.keep_directory = fixture.success = False
        fixture.capability = SimpleNamespace(close=lambda: close('capability'))
        fixture.histories, fixture.connections = [], []
        fixture.broker = SimpleNamespace(stop=lambda: close('broker'))
        cleanup = asyncio.create_task(fixture.cleanup())
        await asyncio.sleep(0)
        cleanup.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cleanup
        self.assertFalse(fixture.go_wait.done())
        self.assertFalse(fixture._cleanup_work.done())
        self.assertEqual(events, ['configuration-start'])
        go_release.set()
        await fixture.cleanup()
        self.assertEqual(events, ['configuration-start', 'go', 'capability', 'configuration', 'identity', 'broker'])
        self.assertTrue(fixture.keep_directory)
        self.assertIs(fixture._configuration_start, original)

    def test_initial_authority_uses_registered_scope_without_native_owner(self):
        fixture = LiveRegisteredContextForegroundTests('test_registered_foreground_activation_and_eof')
        fixture.hub_id, fixture.profile_id = 'hub_registered', 'profile_registered'
        fixture.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        fixture.capability_public = base64.urlsafe_b64encode(bytes(SigningKey(bytes([13])*32).verify_key)).decode().rstrip('=')
        initial = fixture.initial_authority()
        self.assertEqual(initial['ownerHubId'], fixture.hub_id)
        self.assertEqual(initial['state']['nativeInstances'], [])
        self.assertNotIn('owner', fixture.row)
        self.assertNotIn(b'"hub-one"', canonical_bytes(initial))
        self.assertEqual(fixture.row['facts']['grant']['issuerHubId'], fixture.hub_id)
        self.assertEqual(fixture.row['facts']['grant']['actions'], ['read', 'subscribe'])
        self.assertEqual({grant['contractId'] for grant in initial['state']['grants']
            if grant['callerRef'] == fixture.reference('host')} >= {
                'native-authority-activate-instance', 'identity-native-instance-set',
                'configuration-set', 'configuration-read', 'configuration-watch'}, True)
        self.assertEqual(unittest.TestLoader().getTestCaseNames(LiveRegisteredContextForegroundTests),
                         ['test_registered_foreground_activation_and_eof'])
