"""Policy owner qualification using the existing owned TLS/JWT broker fixture."""
import base64
import asyncio
import copy
from datetime import datetime, timezone
import hashlib
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
from identity.test_authority import ref, SEED
from identity.test_native_bridge import HOST_SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner import test_task_live as custody_fixture
from tests.storage.run import Broker
from . import test_live as tls_fixture
from . import test_board_live as board_fixture
from . import test_private_storage_live as private_fixture
from .policy import PolicyResource
from .reply_service import CapabilityReplyService, verify_capability_response


class PolicyLiveFixture:
    _configure_tls_and_users = tls_fixture.LiveCapabilityTests._configure_tls_and_users
    start_tls_broker = tls_fixture.LiveCapabilityTests.start_tls_broker
    connect = tls_fixture.LiveCapabilityTests.connect
    exchange = tls_fixture.LiveCapabilityTests.exchange
    command = tls_fixture.LiveCapabilityTests.command
    native = private_fixture.LivePrivateStorageTests.native
    admit = board_fixture.LiveBoardPublisherTests.admit
    wait_permissions = tls_fixture.LiveCapabilityTests.wait_permissions
    custody = custody_fixture.LiveTaskTests.custody
    start_go_child = tls_fixture.LiveCapabilityTests.start_go_child
    wait_handoff = tls_fixture.LiveCapabilityTests.wait_handoff
    write_private = tls_fixture.LiveCapabilityTests.write_private
    service_id = 'policy-owner'
    read_contract = 'capability-policy-evaluate'
    read_class, read_action, private_child = 'policy', 'evaluate', True
    native_go = False
    boundary_checks = False
    tls_server_name = 'localhost'
    broker_stream_limit = 3

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_CAPABILITY_LIVE') != '1':
            raise RuntimeError('A coordinated capability live slot is required')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('Native macOS ARM64 is required')
        if cls.native_go and not Path(os.environ.get('AMX_CAPABILITY_GO_BINARY', '')).is_file():
            raise RuntimeError('A prepared native capability Go test binary is required')

    def configure_broker_policies(self, policies, reads):
        policies['storage']['publish']['allow'] = [self.subjects['DATA']] + reads('DATA')

    def initial_authority(self):
        record = board_fixture.LiveBoardPublisherTests.initial_authority(self)
        state = record['state']
        base = copy.deepcopy(next(g for g in state['grants'] if g['ref'] == ref('capability-storage-write')))
        state['grants'] = [g for g in state['grants'] if g['contractId'] not in (
            'capability-storage-write', 'capability-outcome-query', 'federation-board-command',
            'federation-board-dispatch', 'federation-board-complete')]
        base.update(ref=ref('capability-policy-evaluate'), contractId='capability-policy-evaluate')
        state['grants'].append(base)
        if self.native_go:
            for instance, methods in (('plugin-one', ('bind-instance', 'admit-operation', 'recheck')),
                    ('parent-one', ('bind-instance',))):
                for method in methods:
                    grant = copy.deepcopy(next(g for g in state['grants'] if g['ref'] == ref('host-prepare')))
                    grant.update(ref=ref('policy-' + instance + '-' + method),
                        contractId='native-authority-' + method, resourceId=instance)
                    state['grants'].append(grant)
        query = {'action': 'evaluate', 'resourceClass': 'policy', 'resourceId': 'task-one'}
        self.accesses = [{'action': 'read', 'resourceClass': 'storage', 'resourceId': 'target-allow'},
            {'action': 'write', 'resourceClass': 'storage', 'resourceId': 'target-deny'},
            {'action': 'write', 'resourceClass': 'storage', 'resourceId': 'target-review'}]
        for row in (self.parent, self.row):
            facts = row['facts']
            facts['grant'].update(actions=['read', 'write', 'evaluate'],
                resourceIds=['task-one', 'target-allow', 'target-deny', 'target-review'])
            facts['domainBindings'] = [{'id': 'policy-evaluate', 'contractId': self.read_contract,
                'action': 'evaluate', 'resourceClass': 'policy', 'resourceIds': ['task-one']}]
            facts['policy']['decisions'] = [{'access': query, 'outcome': 'allow'}] + [
                {'access': access, 'outcome': 'allow'} for access in self.accesses]
        self.row['facts']['grant']['policyRef'] = ref('task-one')
        self.row['facts']['policy']['reference'] = ref('task-one')
        for index, outcome in enumerate(('allow', 'deny', 'approval_required'), 1):
            self.row['facts']['policy']['decisions'][index]['outcome'] = outcome
        for access in self.accesses:
            self.parent['facts']['domainBindings'].append({'id': 'parent-' + access['resourceId'],
                'contractId': 'capability-storage-read' if access['action'] == 'read' else 'capability-storage-write',
                'action': access['action'], 'resourceClass': access['resourceClass'], 'resourceIds': [access['resourceId']]})
        self.row['facts']['parentGrant'] = copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['parentAccess'] = [query, *copy.deepcopy(self.accesses)]
        return record

    async def asyncSetUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='agentmux-policy-live-')).resolve()
        self.connections, self.histories = [], []
        self.go_process = self.go_wait = self.go_output = None
        self.identity = self.receiver = self.broker = None
        self.success = self.keep_directory = False
        self.addAsyncCleanup(self.cleanup)
        self.errors, self.permission_events = {}, {}
        self.inbox_prefixes = {role: '_INBOX.' + secrets.token_hex(16) for role in
            ('provisioner', 'identity', 'storage', 'host', 'other-scope')}
        self.scope = copy.deepcopy(getattr(self, 'native_scope',
            {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}))
        self.policy = Retention(4_194_304, 1_048_576)
        self.bindings = {'IDENTITY': OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority',
            canonical_bytes({**self.scope, 'projectId': None})), **{
                stream: OwnerBinding('hub-one', 'policy-evaluations', entity, 'policy-evaluation', canonical_bytes(self.scope))
                for stream, entity in (('DATA', 'task-one'), ('OTHER', 'task-other'))}}
        self.subjects = {name: owner_subject(binding) for name, binding in self.bindings.items()}
        self.identity_subject = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        self.read_subject = 'amx.v1.h.hub-one.o.org-one.p.' + (self.scope['projectId'] or '_') + '.w._.capability.' + self.service_id + '.command'
        self.other_subject = 'amx.v1.h.hub-one.o.other-org.p._.w._.capability.policy-owner.command'
        self.broker = Broker(self.directory)
        self._configure_tls_and_users()
        self.admin = await self.start_tls_broker()
        infos = {name: await self.admin.jetstream().add_stream(self.policy.stream_config(stream=name, subject=subject))
            for name, subject in self.subjects.items()}
        self.streams = {name: StreamIdentity(info.created, 0) for name, info in infos.items()}
        bootstrap = OwnerLedger(self.admin.jetstream(), stream='IDENTITY', subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'], retention=self.policy, stream_identity=self.streams['IDENTITY'])
        await bootstrap.append(self.initial_authority(), expected_sequence=0)
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
        if self.native_go:
            self.row.update(relationship='independent', parentOwner=None)
            self.row['facts'].update(parentGrant=None, parentAccess=[])
            self.row['facts']['grant']['parentGrantRef'] = None
            await self.start_go_child()
            for row in (self.parent, self.row):
                row['facts']['domainBindings'] = [binding for binding in row['facts']['domainBindings']
                    if binding['contractId'] in (self.read_contract, 'capability-outcome-query')]
        if getattr(self, 'recovery_checks', False):
            self.row['facts']['parentAccess'].append({'action': 'inspect', 'resourceClass': 'outcome', 'resourceId': 'task-one'})
        if getattr(self, 'enroll_native_instances', True):
            for row in (self.parent, self.row):
                await self.command('identity-native-instance-set', ref('native-admin'),
                    {'authorityId': 'authority-one', 'record': row, 'previousRef': None})
        await self.start_receiver()

    async def start_receiver(self):
        ledger = OwnerLedger(self.storage.jetstream(), stream='DATA', subject=self.subjects['DATA'],
            binding=self.bindings['DATA'], retention=self.policy, stream_identity=self.streams['DATA'],
            require_completion_budget=True)
        self.resource = PolicyResource(self.bindings['DATA'], ledger, canonical_bytes(ref('task-one')),
            canonical_bytes(ref('plugin')), 'plugin-one')
        self.receiver = CapabilityReplyService(self.identity.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='policy-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage)
        await self.receiver.start()

    async def prepare(self, inner):
        envelope = strict_loads(inner)
        snapshot = await self.identity.reader.current()
        result = await self.native('prepare-domain-call', {'operation': envelope['operation'],
            'operationAuthorityRef': {**ref('authority-one'), 'revision': snapshot.sequence},
            'bindingId': 'policy-evaluate', 'contractId': self.read_contract,
            'serviceRequestId': 'request_' + hashlib.sha256(envelope['operation']['operationId'].encode()).hexdigest(),
            'serviceReplySubject': self.host.new_inbox(), 'payload': envelope['payload'],
            'originalEnvelopeBytes': base64.b64encode(inner).decode()})
        return base64.b64decode(result['serviceRequestBytes'])

    async def call(self, raw):
        response = await self.exchange(self.host, self.read_subject, raw, strict_loads(raw)['claims']['replySubject'])
        return strict_loads(verify_capability_response(response, raw, public_key=self.issuer_public,
            signing_key_ref=ref('issuer'), service_identity_ref=ref('service'), service_instance_id='ingress-one',
            now=datetime.now(timezone.utc)))

    async def assert_refused(self, raw):
        actual = self.receiver.handle
        completed, refusals = asyncio.Event(), []
        async def observed(*args, **kwargs):
            try:
                return await actual(*args, **kwargs)
            except ContractError as error:
                refusals.append(str(error))
                raise
            finally:
                completed.set()
        with patch.object(self.receiver, 'handle', side_effect=observed):
            with self.assertRaises(TimeoutError):
                await self.exchange(self.host, self.read_subject, raw, strict_loads(raw)['claims']['replySubject'])
            await asyncio.wait_for(completed.wait(), .5)
        self.assertEqual(refusals, ['capability_service_unavailable'])

    async def cleanup(self):
        if self.go_wait is not None:
            if not self.go_wait.done():
                self.keep_directory = True
                self.go_process.terminate()
                try:
                    await asyncio.wait_for(asyncio.shield(self.go_wait), 3)
                except TimeoutError:
                    self.go_process.kill()
            if await asyncio.wait_for(asyncio.shield(self.go_wait), 3):
                self.keep_directory = True
        if self.go_output is not None:
            self.go_output.close()
        if self.receiver is not None:
            await self.receiver.close()
        for receiver in getattr(self, 'extra_receivers', []):
            await receiver.close()
        if self.identity is not None:
            await self.identity.close()
        for connection in reversed(self.connections):
            await connection.close()
        for history in self.histories:
            history.close()
        if self.broker is not None:
            self.broker.stop()
        if self.success and not self.keep_directory:
            shutil.rmtree(self.directory)


class LivePolicyTests(PolicyLiveFixture, unittest.IsolatedAsyncioTestCase):
    async def test_tls_policy_outcomes_replay_and_restart(self):
        originals, receipts = [], []
        for access, outcome in zip(self.accesses, ('allow', 'deny', 'approval_required')):
            inner = await self.admit(self.read_contract, {'resourceRef': ref('task-one'), 'input': access})
            originals.append(inner)
            result = await self.call(await self.prepare(inner))
            self.assertEqual(result['outcome'], outcome)
            receipts.append(result)
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 3)
        await self.receiver.close()
        await self.start_receiver()
        self.assertEqual(await self.call(await self.prepare(originals[0])), receipts[0])
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 3)
        await self.receiver.close()
        self.assertTrue(self.receiver._cleanup_task.done())
        self.success = True

    async def test_tls_policy_stale_parent_revocation_and_raw_broker_denials(self):
        for role, connection, subject in (
                ('host', self.host, self.subjects['DATA']),
                ('storage', self.storage, self.subjects['OTHER']),
                ('storage', self.storage, '$JS.API.STREAM.PURGE.DATA'),
                ('storage', self.storage, '$JS.API.STREAM.MSG.DELETE.DATA')):
            expected = len(self.errors[role]) + 1
            await connection.publish(subject, b'{}')
            await connection.flush(timeout=2)
            await self.wait_permissions(role, expected)
        for subject in (self.subjects['DATA'], 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.ledger.>'):
            expected = len(self.errors['host']) + 1
            subscription = await self.host.subscribe(subject)
            try:
                await self.host.flush(timeout=2)
                await self.wait_permissions('host', expected)
            finally:
                await subscription.unsubscribe()
        stale = await self.admit(self.read_contract, {'resourceRef': {**ref('task-one'), 'revision': 2},
            'input': self.accesses[0]})
        await self.assert_refused(await self.prepare(stale))
        current = await self.admit(self.read_contract, {'resourceRef': ref('task-one'), 'input': self.accesses[0]})
        raw = await self.prepare(current)
        await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one', 'targetRef': ref('parent-plugin')})
        self.assertGreater((datetime.fromisoformat(strict_loads(raw)['claims']['validUntil'])
            - datetime.now(timezone.utc)).total_seconds(), 2.5)
        await self.assert_refused(raw)
        for stream in ('DATA', 'OTHER'):
            self.assertEqual((await self.admin.jetstream().stream_info(stream)).state.messages, 0)
        self.success = True


class LiveNativePolicyTests(PolicyLiveFixture, unittest.IsolatedAsyncioTestCase):
    native_go = True

    async def test_native_policy_handle_and_parent_revocation(self):
        inner = await self.admit(self.read_contract, {'resourceRef': ref('task-one'),
            'input': {'action': 'evaluate', 'resourceClass': 'policy', 'resourceId': 'task-one'}})
        self.write_private('host-signing.seed', HOST_SEED, raw=True)
        self.write_private('original-envelope.json', inner, raw=True)
        snapshot = await self.identity.ledger.current()
        metadata = await self.admin.request('$JS.API.STREAM.INFO.IDENTITY', b'{}', timeout=2)
        ready = {'serverUrl': self.broker.url, 'authoritySubject': self.identity_subject,
            'capabilitySubject': self.read_subject, 'credentialsFile': str(self.credentials['host']),
            'caFile': str(self.ca_file), 'tlsName': self.server_name, 'leafCertificateSha256': self.leaf_digest,
            'accountPublicKey': self.account_public_key, 'replyPrefix': self.inbox_prefixes['host'],
            'publishSubjects': [self.identity_subject, self.read_subject,
                '$JS.API.STREAM.INFO.IDENTITY', '$JS.API.STREAM.MSG.GET.IDENTITY'],
            'hostSigningSeedFile': str(self.directory / 'host-signing.seed'),
            'originalEnvelopeFile': str(self.directory / 'original-envelope.json'),
            'enrollment': {'profileId': 'profile-one', 'hubId': 'hub-one', 'authorityId': 'authority-one',
                'organizationId': 'org-one', 'stream': 'IDENTITY', 'domain': '',
                'streamCreated': strict_loads(metadata.data)['created'], 'minimumSequence': snapshot.sequence,
                'maxBytes': self.policy.max_bytes, 'replicas': 1, 'hostTransportRef': ref('host-transport'),
                'hostIdentityRef': ref('host'), 'issuerRef': ref('issuer'), 'issuerIdentityRef': ref('service'),
                'issuerInstanceId': 'ingress-one'},
            'service': {'profileId': 'profile-one', 'hubId': 'hub-one', 'serviceId': 'policy-owner',
                'serviceInstanceId': 'ingress-one', 'serviceIdentityRef': ref('service'), 'signingKeyRef': ref('issuer')},
            'bindingId': 'policy-evaluate', 'resourceRef': ref('task-one'), 'resourceDigest': '',
            'requestContractId': self.read_contract, 'replyContractId': 'capability-policy-evaluate-reply',
            'requestInput': {'action': 'evaluate', 'resourceClass': 'policy', 'resourceId': 'task-one'},
            'replyPayloadDigest': '', 'revoked': False}
        self.write_private('fixture-ready.json', ready)
        result = await self.wait_handoff('go-result.json', lambda value: value.get('phase') == 'read-complete')
        self.assertEqual(result, {'phase': 'read-complete'})
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages, 2)
        await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one', 'targetRef': ref('parent-plugin')})
        ready['revoked'] = True
        self.write_private('fixture-ready.json', ready)
        result = await self.wait_handoff('go-result.json', lambda value: value.get('phase') == 'complete')
        self.assertEqual(result, {'phase': 'complete', 'read': True, 'revocation': True, 'cleanup': True})
        self.assertEqual(await asyncio.wait_for(asyncio.shield(self.go_wait), 3), 0)
        self.success = True

