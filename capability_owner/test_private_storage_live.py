"""Private namespace contracts on the existing coordinated TLS/JWT fixture.

Collection opens no connections. These checks require an explicit live slot and
do not qualify installed service composition or native process supervision.
"""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import platform
import secrets
import shutil
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.service import IdentityService
from identity.capability_service import evaluate_capability_service_request
from identity.native_bridge import verify_response
from identity.test_native_bridge import HOST_SEED
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner import test_task_live as custody_fixture
from tests.storage.run import Broker
from . import test_board_live as board_fixture
from . import test_live as tls_fixture
from .private_storage import PrivateStorageResource
from .reply_service import CapabilityReplyService
from .test_storage_contract import StorageWriteContract


class LivePrivateStorageTests(StorageWriteContract, unittest.IsolatedAsyncioTestCase):
    _configure_tls_and_users = tls_fixture.LiveCapabilityTests._configure_tls_and_users
    start_tls_broker = tls_fixture.LiveCapabilityTests.start_tls_broker
    exchange = tls_fixture.LiveCapabilityTests.exchange
    command = tls_fixture.LiveCapabilityTests.command
    wait_permissions = tls_fixture.LiveCapabilityTests.wait_permissions
    custody = custody_fixture.LiveTaskTests.custody
    admit = board_fixture.LiveBoardPublisherTests.admit
    call = board_fixture.LiveBoardPublisherTests.call
    query = board_fixture.LiveBoardPublisherTests.query
    read_contract = 'capability-storage-write'
    boundary_checks = False
    tls_server_name = 'localhost'
    broker_stream_limit = 3

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_PRIVATE_STORAGE_LIVE') != '1':
            raise RuntimeError('A coordinated private storage live slot is required')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('Native macOS ARM64 is required')

    def configure_broker_policies(self, policies, reads):
        policies['storage'] = {'publish': {'allow': [self.subjects['DATA']] + reads('DATA')},
            'subscribe': {'allow': [self.read_subject, self.outcome_subject]}}
        policies['host']['publish']['allow'].append(self.outcome_subject)

    async def asyncSetUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='agentmux-private-storage-live-')).resolve()
        self.connections, self.histories, self.responders = [], [], []
        self.identity = self.broker = None
        self.success = self.keep_directory = False
        self.addAsyncCleanup(self.cleanup)
        self.errors, self.permission_events = {}, {}
        self.role_connections = {}
        self.inbox_prefixes = {role: '_INBOX.' + secrets.token_hex(16) for role in
            ('provisioner', 'identity', 'storage', 'host', 'other-scope')}
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        self.policy = Retention(4_194_304, 1_048_576)
        self.bindings = {'IDENTITY': OwnerBinding('hub-one', 'identity', 'authority-one',
            'identity-authority', canonical_bytes({**self.scope, 'projectId': None})),
            **{stream: OwnerBinding('hub-one', 'plugin-private', entity, 'plugin-storage',
                canonical_bytes(self.scope)) for stream, entity in (('DATA', 'task-one'), ('OTHER', 'task-other'))}}
        self.subjects = {name: owner_subject(binding) for name, binding in self.bindings.items()}
        self.identity_subject = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        base = 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.'
        self.read_subject = base + 'storage-owner.command'
        self.outcome_subject = base + 'outcome-owner.command'
        self.other_subject = 'amx.v1.h.hub-one.o.other-org.p._.w._.capability.storage-owner.command'
        self.broker = Broker(self.directory)
        self._configure_tls_and_users()
        self.admin = await self.start_tls_broker()
        infos = {name: await self.admin.jetstream().add_stream(self.policy.stream_config(
            stream=name, subject=subject)) for name, subject in self.subjects.items()}
        self.streams = {name: StreamIdentity(info.created, 0) for name, info in infos.items()}
        initial = self.initial_authority()
        bootstrap = OwnerLedger(self.admin.jetstream(), stream='IDENTITY', subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'], retention=self.policy, stream_identity=self.streams['IDENTITY'])
        await bootstrap.append(initial, expected_sequence=0)
        connection = await self.connect('identity')
        history, backup, checkpoint = self.custody('identity', 'IDENTITY')
        from state_owner.checkpoints import CheckpointReceipt
        async def committed(receipt):
            await checkpoint.committed(CheckpointReceipt(receipt.manifest_path, receipt.digest, receipt.cursor))
        self.identity = IdentityService(connection, stream='IDENTITY', stream_identity=self.streams['IDENTITY'],
            retention=self.policy, hub_id='hub-one', entity_id='authority-one', profile_id='profile-one',
            organization_id='org-one', issuer_ref=ref('issuer'), signing_seed=SEED, history=history,
            checkpoint_path=checkpoint.checkpoint_prefix, checkpoint_committed=committed,
            backup_host=backup, backup_key_id='backup-one')
        await self.identity.start()
        self.host = await self.connect('host')
        self.storage = await self.connect('storage')
        self.resource = self.open_resource()
        self.parent['privateStorageResources'] = [{'resourceId': 'task-other', 'scope': self.scope,
            'bindingDigest': self.open_resource(parent=True).binding_digest}]
        self.row['privateStorageResources'] = [{'resourceId': 'task-one', 'scope': self.scope,
            'bindingDigest': self.resource.binding_digest}]
        for row in (self.parent, self.row):
            await self.command('identity-native-instance-set', ref('native-admin'),
                {'authorityId': 'authority-one', 'record': row, 'previousRef': None})
        for service in ('storage-owner', 'outcome-owner'):
            responder = CapabilityReplyService(self.identity.reader, resources=[self.resource], hub_id='hub-one',
                profile_id='profile-one', authority_id='authority-one', service_id=service,
                service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
                signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage)
            self.responders.append(responder)
            await responder.start()
        await self.connect('other-scope')

    def initial_authority(self):
        # Keep the already reviewed private-child authority shape and current
        # timestamps, replacing board permissions with this storage-only scope.
        initial = board_fixture.LiveBoardPublisherTests.initial_authority(self)
        state = initial['state']
        state['grants'] = [grant for grant in state['grants'] if grant['contractId'] not in
            ('federation-board-command', 'federation-board-dispatch', 'federation-board-complete')]
        base = copy.deepcopy(next(g for g in state['grants'] if g['ref'] == ref('capability-storage-write')))
        base.update(ref=ref('capability-storage-read'), contractId='capability-storage-read')
        state['grants'].append(base)
        parent_prepare = copy.deepcopy(next(g for g in state['grants'] if g['ref'] == ref('host-prepare')))
        parent_prepare.update(ref=ref('parent-host-prepare'), resourceId='parent-one')
        state['grants'].append(parent_prepare)
        for row in (self.parent, self.row):
            facts = row['facts']
            facts['grant']['actions'].append('read')
            facts['policy']['decisions'].append({'access': {'action': 'read',
                'resourceClass': 'storage', 'resourceId': 'task-one'}, 'outcome': 'allow'})
            facts['domainBindings'].append({'id': 'private-read', 'contractId': 'capability-storage-read',
                'action': 'read', 'resourceClass': 'storage', 'resourceIds': ['task-one']})
        for binding in self.parent['facts']['domainBindings']:
            binding['resourceIds'].append('task-other')
        self.parent['facts']['grant']['resourceIds'].append('task-other')
        self.parent['facts']['policy']['decisions'].extend([
            {**copy.deepcopy(item), 'access': {**item['access'], 'resourceId': 'task-other'}}
            for item in list(self.parent['facts']['policy']['decisions'])])
        self.row['facts']['parentGrant'] = copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['parentAccess'] = [copy.deepcopy(item['access'])
            for item in self.parent['facts']['policy']['decisions']]
        return initial

    async def connect(self, role):
        connection = await tls_fixture.LiveCapabilityTests.connect(self, role)
        self.role_connections[role] = connection
        return connection

    async def native(self, method, inputs, *, owner=None):
        # Select only one of the already enrolled fixture owners; the bridge
        # still verifies the host credential and that owner's current grants.
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-native-authority-request-v1', 'requestId': 'native-' + secrets.token_hex(16),
            'method': method, 'profileId': 'profile-one', 'hubId': 'hub-one', 'authorityId': 'authority-one',
            'owner': owner or self.row['owner'], 'signingKeyRef': ref('host-transport'),
            'issuedAt': tls_fixture.stamp(now), 'expiresAt': tls_fixture.stamp(now + timedelta(seconds=4)),
            'replySubject': self.host.new_inbox(), 'input': inputs}
        raw = tls_fixture.packet(claims, HOST_SEED, native=True)
        response = await self.exchange(self.host, self.identity_subject, raw, claims['replySubject'])
        return verify_response(response, raw, public_key=self.issuer_public, signing_key_ref=ref('issuer'),
            now=datetime.now(timezone.utc))['result']

    def open_resource(self, *, parent=False):
        name = 'OTHER' if parent else 'DATA'
        return PrivateStorageResource.open_existing(self.storage.jetstream(), binding=self.bindings[name],
            stream=name, stream_identity=self.streams[name], retention=self.policy,
            plugin_identity_ref=ref('parent-plugin' if parent else 'plugin'),
            instance_id='parent-one' if parent else 'plugin-one', package_id=self.row['owner']['pin']['packageId'])

    async def prepare(self, inner, *, parent=False):
        envelope = strict_loads(inner)
        snapshot = await self.identity.reader.current()
        contract = envelope['contractId']
        result = await self.native('prepare-domain-call', {'operation': envelope['operation'],
            'operationAuthorityRef': {**ref('authority-one'), 'revision': snapshot.sequence},
            'bindingId': {'capability-storage-read': 'private-read', 'capability-storage-write': 'board-write',
                'capability-outcome-query': 'board-outcome'}[contract],
            'contractId': contract, 'serviceRequestId': 'request_' + secrets.token_hex(32),
            'serviceReplySubject': self.host.new_inbox(), 'payload': envelope['payload'],
            'originalEnvelopeBytes': base64.b64encode(inner).decode()},
            owner=self.parent['owner'] if parent else self.row['owner'])
        return base64.b64decode(result['serviceRequestBytes'])

    async def contract_prepare(self, operation, revision=0):
        request = await self.prepare(await self.admit('capability-storage-write', {
            'resourceRef': {**ref('task-one'), 'revision': revision}, 'input': {'value': {'value': operation}}},
            operation=operation))
        return request, base64.b64decode(strict_loads(request)['claims']['envelopeBytes'])

    contract_dispatch = call

    async def test_common_storage_write_and_reconcile_preserve_original_references(self):
        await StorageWriteContract.test_common_storage_write_and_reconcile_preserve_original_references(self)
        self.success = True

    async def test_common_storage_replay_and_reconcile_keep_result_after_later_write(self):
        await StorageWriteContract.test_common_storage_replay_and_reconcile_keep_result_after_later_write(self)
        self.success = True

    async def contract_outcome(self, inner):
        operation = strict_loads(inner)['operation']
        request = await self.prepare(await self.admit('capability-outcome-query', {
            'resourceRef': strict_loads(inner)['payload']['resourceRef'], 'input': {
                'contractId': 'capability-storage-write', 'operationId': operation['operationId'],
                'payloadDigest': operation['payloadDigest']}}))
        return await self.call(request)

    async def restart_resource(self):
        # Each old receiver joins before the original connection is reused.
        for responder in self.responders:
            await responder.close()
        self.resource = self.open_resource()
        for service in ('storage-owner', 'outcome-owner'):
            responder = CapabilityReplyService(self.identity.reader, resources=[self.resource], hub_id='hub-one',
                profile_id='profile-one', authority_id='authority-one', service_id=service,
                service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
                signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage)
            self.responders.append(responder)
            await responder.start()

    async def test_lost_actual_append_ack_restart_and_later_write_keep_original_result(self):
        request, inner = await self.contract_prepare('lost-private-ack')
        actual = self.resource.ledger._js.publish
        publications = []
        async def lost_ack(*args, **kwargs):
            acknowledgment = await actual(*args, **kwargs)
            publications.append(acknowledgment.seq)
            raise TimeoutError()
        with patch.object(self.resource.ledger._js, 'publish', side_effect=lost_ack):
            await self.call(request, expect_reply=False)
        self.assertEqual(publications, [1])
        await self.restart_resource()
        recovered = await self.contract_outcome(inner)
        self.assertEqual((recovered['outcome'], recovered['resourceRef']['revision']), ('committed', 1))
        later, _ = await self.contract_prepare('later-private', revision=1)
        second = await self.call(later)
        self.assertEqual(second['resourceRef']['revision'], 2)
        self.assertEqual(await self.contract_outcome(inner), recovered)
        self.assertEqual(strict_loads(await self.resource.read(2)), {'value': 'later-private'})
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 2)
        self.success = True

    async def test_namespace_mapping_withdrawal_parent_namespace_and_stop_refuse(self):
        first, _ = await self.contract_prepare('private-first')
        await self.call(first)
        parent_request = await self.prepare(await self.admit('capability-storage-write', {
            'resourceRef': {**ref('task-one'), 'revision': 1}, 'input': {'value': {'parent': 'must not replace child'}}}),
            parent=True)
        snapshot = await self.identity.reader.current()
        # Ordinary domain authorization permits this exact resource. The
        # namespace's child ownership must independently refuse the parent.
        self.assertEqual(evaluate_capability_service_request(snapshot, parent_request,
            service_id='storage-owner', now=datetime.now(timezone.utc)).outcome, 'allowed')
        with self.assertRaisesRegex(ContractError, '^capability_access_refused$'):
            self.resource.check_request(snapshot, strict_loads(parent_request)['claims'])
        await self.call(parent_request, expect_reply=False)
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 1)
        request, _ = await self.contract_prepare('must-refuse', revision=1)
        previous = self.row['ref']
        self.row = copy.deepcopy(self.row)
        self.row['ref'] = {**previous, 'revision': previous['revision'] + 1}
        self.row.pop('privateStorageResources')
        await self.command('identity-native-instance-set', ref('native-admin'),
            {'authorityId': 'authority-one', 'record': self.row, 'previousRef': previous})
        await self.call(request, expect_reply=False)
        claims = strict_loads(request)['claims']
        await self.responders[0].close()
        with self.assertRaisesRegex(ContractError, '^capability_service_unavailable$'):
            await self.responders[0].handle(request, received_reply_subject=claims['replySubject'])
        self.assertEqual(strict_loads(await self.resource.read(1)), {'value': 'private-first'})
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 1)
        self.assertEqual((await self.admin.jetstream().stream_info('OTHER')).state.messages, 0)
        self.success = True

    async def test_stale_conflict_read_and_revoked_parent_preserve_private_value(self):
        first, _ = await self.contract_prepare('private-original')
        await self.call(first)
        stale, _ = await self.contract_prepare('private-stale')
        result = await self.call(stale)
        self.assertEqual((result['outcome'], result['resourceRef']['revision']), ('conflict', 2))
        # Private conflicts retain a new receipt version with unchanged value;
        # board conflicts retain their separate journal without changing a card.
        read = await self.prepare(await self.admit('capability-storage-read', {
            'resourceRef': {**ref('task-one'), 'revision': 2}, 'input': {}}))
        content = await self.call(read)
        self.assertEqual(strict_loads(base64.b64decode(content['data'])), {'value': 'private-original'})
        pending, _ = await self.contract_prepare('private-revoked', revision=2)
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('parent-row')})
        with self.assertRaisesRegex(ContractError, '^native_parent_binding_invalid$'):
            evaluate_capability_service_request(await self.identity.reader.current(), pending,
                service_id='storage-owner', now=datetime.now(timezone.utc))
        await self.call(pending, expect_reply=False)
        self.assertEqual(strict_loads(await self.resource.read(2)), {'value': 'private-original'})
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 2)
        self.success = True

    async def test_callers_and_namespace_owner_cannot_mutate_other_storage(self):
        for role in ('host', 'storage', 'other-scope'):
            connection = self.role_connections[role]
            subjects = [self.subjects['OTHER'], '$JS.API.STREAM.PURGE.DATA', '$JS.API.STREAM.DELETE.DATA',
                '$JS.API.STREAM.MSG.DELETE.DATA', '$JS.API.STREAM.INFO.OTHER', '$JS.API.STREAM.MSG.GET.OTHER']
            if role != 'storage':
                subjects.extend([self.subjects['DATA'], '$JS.API.STREAM.MSG.GET.DATA'])
            for subject in subjects:
                before = self.errors[role].count('permission')
                await connection.publish(subject, b'{}')
                await connection.flush(timeout=1)
                await self.wait_permissions(role, before + 1)
            for subject in (self.subjects['DATA'], self.subjects['OTHER'], 'amx.v1.h.hub-one.>'):
                before = self.errors[role].count('permission')
                subscription = await connection.subscribe(subject)
                try:
                    await connection.flush(timeout=1)
                    await self.wait_permissions(role, before + 1)
                finally:
                    await subscription.unsubscribe()
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 0)
        self.assertEqual((await self.admin.jetstream().stream_info('OTHER')).state.messages, 0)
        self.success = True

    async def _cleanup(self):
        for responder in reversed(self.responders):
            await responder.close()
        if self.identity is not None:
            await asyncio.wait_for(self.identity.close(), 10)
        for history in reversed(self.histories):
            history.close()
        for connection in reversed(self.connections):
            await connection.close()
        if self.broker is not None:
            self.broker.stop()
        if self.success and not self.keep_directory:
            shutil.rmtree(self.directory)

    async def cleanup(self):
        if not hasattr(self, '_cleanup_work'):
            self._cleanup_work = asyncio.create_task(self._cleanup())
        await asyncio.shield(self._cleanup_work)
