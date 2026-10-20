"""Coordinated enrolled TLS task inspect, reserve, replay and refusal checks.

Reuse the existing private TLS/JWT broker fixture. Importing this module starts
no broker; the coordinating chat grants the live slot before invocation.
"""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import nkeys
from nacl.signing import SigningKey
from agentmux_contracts import (ContractError, canonical_bytes, payload_digest,
                                strict_loads, validate as validate_contract)
from capability_owner import test_live as tls_fixture
from capability_owner.test_live import packet, stamp
from identity.service import IdentityService, verify_receipt
from identity.ingress import verify_possession
from identity.application_binding import ApplicationObservationLease
from identity.application_client import load_application_client, provision_application_client
from identity.legacy_identity import LegacyIdentityAdapter
from identity.test_authority import ref, SEED
from identity.test_commands import command_fixture
from identity.transitions import transition
from hub import server as hub_server
from hub import cli as hub_cli
from hub.client_launch_connection import ConnectionFailure, selected_publish_subjects
from hub.client_launch_enrollment import open_application_client
from hub.client_launch_session import ApplicationClientSession
from hub.legacy_identity_client import EnrolledLegacyIdentityResolver
from hub.store import HubError, Store
from native_security.nats_credentials import service_policy, validate, validate_service
from native_security.secret_custody import ScopedSecretCustody
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.checkpoints import CheckpointReceipt
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.task_host import TaskHost
from state_owner.task_service import verify_task_reply
from state_owner import test_configuration_live as configuration_fixture
from state_owner.test_ledger import record
from tests.storage.run import Broker


class LiveTaskTests(unittest.IsolatedAsyncioTestCase):
    _configure_tls_and_users = tls_fixture.LiveCapabilityTests._configure_tls_and_users
    start_tls_broker = tls_fixture.LiveCapabilityTests.start_tls_broker
    connect = tls_fixture.LiveCapabilityTests.connect
    exchange = tls_fixture.LiveCapabilityTests.exchange
    command = tls_fixture.LiveCapabilityTests.command
    wait_permissions = tls_fixture.LiveCapabilityTests.wait_permissions
    write_private = tls_fixture.LiveCapabilityTests.write_private
    _join_cleanup_step = configuration_fixture.LiveConfigurationSubscriptionTests._join_cleanup_step
    _wait_cleanup_recovery = configuration_fixture.LiveConfigurationSubscriptionTests._wait_cleanup_recovery
    read_contract = 'task-inspect'
    boundary_checks = False
    response_ttls = {'storage': '8s'}

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_TASK_LIVE') != '1':
            raise RuntimeError('A coordinated task live slot is required')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('Native macOS ARM64 is required')

    def configure_broker_policies(self, policies, reads):
        policy = service_policy(role='task', hub_id='hub-one', entity_id=self.task_id, scope=self.scope,
            stream='DATA', reply_prefix=self.inbox_prefixes['storage'],
            artifact_bucket=getattr(self, 'artifact_bucket', None))
        policies['storage'] = {'publish': {'allow': list(policy.publish_subjects)},
            'subscribe': {'allow': [policy.command_subject]}}
        self.task_policy = policy

    def validate_source_credential(self):
        validate_service(self.credentials['storage'].read_bytes(), account_public_key=self.account_public_key,
            role='task', hub_id='hub-one', entity_id=self.task_id, scope=self.scope,
            stream='DATA', reply_prefix=self.inbox_prefixes['storage'],
            artifact_bucket=getattr(self, 'artifact_bucket', None))

    async def asyncSetUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='agentmux-task-live-')).resolve()
        self.connections, self.histories = [], []
        self.identity = self.receiver = self.broker = None
        self.keep_directory = self.success = False
        self.addAsyncCleanup(self.cleanup)
        self.errors, self.permission_events = {}, {}
        self.inbox_prefixes = {role: '_INBOX.' + secrets.token_hex(16)
            for role in ('provisioner', 'identity', 'storage', 'host', 'other-scope')}
        self.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.task_id = getattr(self, 'task_id', 'task-one')
        self.policy = Retention(4_194_304, 524_288)
        self.issuer_public = base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
        self.bindings = {
            'IDENTITY': OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority', canonical_bytes(self.scope)),
            'DATA': OwnerBinding('hub-one', getattr(self, 'data_domain', 'task'), self.task_id,
                getattr(self, 'data_kind', 'task'), canonical_bytes(self.scope)),
            'OTHER': OwnerBinding('hub-one', 'task', 'task-other', 'task', canonical_bytes(self.scope))}
        self.subjects = {name: owner_subject(binding) for name, binding in self.bindings.items()}
        self.identity_subject = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        self.read_subject = 'amx.v1.h.hub-one.o.org-one.p._.w._.task.'+self.task_id+'.command'
        self.other_subject = 'amx.v1.h.hub-one.o.other-org.p._.w._.task.'+self.task_id+'.command'
        self.broker = Broker(self.directory)
        self._configure_tls_and_users()
        # Validate the generated source credential against the production role,
        # including its exact one-response/eight-second budget.
        self.validate_source_credential()
        admin = await self.start_tls_broker()
        infos = {name: await admin.jetstream().add_stream(self.policy.stream_config(stream=name, subject=subject))
            for name, subject in self.subjects.items()}
        self.streams = {name: StreamIdentity(info.created, 0) for name, info in infos.items()}
        initial = self.initial_authority()
        ledger = OwnerLedger(admin.jetstream(), stream='IDENTITY', subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'], retention=self.policy, stream_identity=self.streams['IDENTITY'])
        await ledger.append(initial, expected_sequence=0)
        if getattr(self, 'seed_ready_task', True):
            task = record('imported-task')
            task['operation']['scope'] = copy.deepcopy(self.scope)
            task.update(effects=[], state={'taskId': 'task-one', 'status': 'ready', 'assignmentEpoch': 0,
                'reservation': None, 'originHubId': 'hub-one', 'taskInputRef': ref('task-input'), 'flags': {},
                'legacyId': 'W01ABC', 'parentKey': 'W00PARENT', 'body': 'Original body',
                'audit': [{'sequence': 7, 'actor': 'original-actor'}]})
            ledger = OwnerLedger(admin.jetstream(), stream='DATA', subject=self.subjects['DATA'],
                binding=self.bindings['DATA'], retention=self.policy, stream_identity=self.streams['DATA'])
            await ledger.append(task, expected_sequence=0)
        connection = await self.connect('identity')
        history, backup, checkpoint = self.custody('identity', 'IDENTITY')
        async def committed(receipt, custody=checkpoint):
            await custody.committed(CheckpointReceipt(receipt.manifest_path, receipt.digest, receipt.cursor))
        self.identity = IdentityService(connection, stream='IDENTITY', stream_identity=self.streams['IDENTITY'],
            retention=self.policy, hub_id='hub-one', entity_id='authority-one', profile_id='profile-one',
            organization_id='org-one', issuer_ref=ref('issuer'), signing_seed=SEED, history=history,
            checkpoint_path=checkpoint.checkpoint_prefix, checkpoint_committed=committed,
            backup_host=backup, backup_key_id='backup-one')
        await self.identity.start()
        self.host = await self.connect('host')
        self.source_connection = await self.connect(getattr(self, 'source_role', 'storage'))
        if not getattr(self, 'create_task_host', True):
            return
        history, backup, checkpoint = self.custody('task', 'DATA')
        self.task_resources = dict(authority=self.identity.reader, ingress=self.identity.ingress,
            stream='DATA', binding=self.bindings['DATA'], stream_identity=self.streams['DATA'], retention=self.policy,
            history=history, checkpoint_host=checkpoint, backup_host=backup, backup_key_id='backup-one',
            issuer_ref=ref('issuer'), signing_seed=SEED, service_identity_ref=ref('service'),
            service_instance_id='ingress-one', requester_reply_prefix=self.inbox_prefixes['host'],
            account_public_key=self.account_public_key)
        self.receiver = TaskHost.from_enrolled_host(self.source_connection, **self.task_resources)
        if getattr(self, 'start_task_host', True):
            await self.receiver.start()

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
        checkpoint = CheckpointHost(self.directory/(name+'-checkpoint'), stream=stream,
            commit_ref=ref(name+'-checkpoint'), binding=self.bindings[stream], stream_identity=self.streams[stream])
        return history, backup, checkpoint

    def initial_authority(self):
        initial, _ = command_fixture()
        initial.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        initial['operation'].update(scope=copy.deepcopy(self.scope), expectedVersion=0)
        state = initial['state']
        base = copy.deepcopy(state['grants'][0])
        for name, contract, resource in [('task-inspect-grant', 'task-inspect', self.task_id),
                ('task-reserve-grant', 'task-reserve', self.task_id)]:
            grant = copy.deepcopy(base)
            grant.update(ref=ref(name), contractId=contract, resourceId=resource)
            state['grants'].append(grant)
        now = datetime.now(timezone.utc)
        fixture_lifetime = (timedelta(minutes=20)
            if getattr(self, 'oidc_terminal_fixture', False) else timedelta(minutes=5))
        def current_times(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == 'issuedAt': value[key] = stamp(now-timedelta(seconds=30))
                    elif key in ('expiresAt', 'deadline'): value[key] = stamp(now+fixture_lifetime)
                    elif key == 'recordedAt': value[key] = stamp(now)
                    else: current_times(item)
            elif isinstance(value, list):
                for item in value: current_times(item)
        current_times(initial)
        return initial

    def request(self, contract, *, operation=None, payload=None, seed=None):
        now = datetime.now(timezone.utc)
        operation = operation or 'task-'+secrets.token_hex(16)
        if payload is None:
            payload = {'taskId': self.task_id}
            if contract == 'task-reserve':
                refs = self.receiver.owner.reservation_references(operation)
                payload.update(delegationId=refs['delegationRef']['id'], attemptId='attempt-one',
                    executorHubId='executor-hub', grantRef=refs['executionGrantRef'],
                    repositoryRevision='retained-source-revision', assignmentEpoch=1)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'),
            'grantRef': ref(contract+'-grant'), 'operationId': operation, 'expectedVersion': 1,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30)),
            'replySubject': self.host.new_inbox()}
        return packet(claims, bytes(reversed(SEED)) if seed is None else seed)

    async def call(self, raw, *, received_reply=None, expect_reply=True):
        reply = received_reply or strict_loads(raw)['claims']['replySubject']
        if not expect_reply:
            with self.assertRaises(asyncio.TimeoutError):
                await self.exchange(self.host, self.read_subject, raw, reply, timeout=.4)
            return None
        response = await self.exchange(self.host, self.read_subject, raw, reply)
        return verify_task_reply(response, raw, binding=self.bindings['DATA'],
            source_pin=self.receiver.service.source_pin, public_key=self.issuer_public,
            signing_key_ref=ref('issuer'), service_identity_ref=ref('service'), service_instance_id='ingress-one',
            minimum_source_revision=1, now=datetime.now(timezone.utc))

    async def test_tls_task_inspect_reserve_restart_replay_and_refusals(self):
        before = await self.call(self.request('task-inspect'))
        self.assertEqual(before.sequence, 1)
        self.assertEqual(strict_loads(before.record)['state']['legacyId'], 'W01ABC')
        raw = self.request('task-reserve', operation='stable-reserve')
        committed = await self.call(raw)
        self.assertEqual(committed.sequence, 2)
        state = strict_loads(committed.record)['state']
        self.assertEqual(state['status'], 'reserved')
        self.assertEqual(state['executionGrant']['ref'], strict_loads(raw)['claims']['payload']['grantRef'])
        self.assertEqual(strict_loads(committed.record)['effects'][0]['contractId'], 'delegation-offer')
        self.assertEqual(state['body'], 'Original body')
        old = self.receiver
        await old.close(timeout=None)
        self.assertTrue(old.done.is_set())
        self.receiver = TaskHost.from_enrolled_host(self.source_connection, **self.task_resources)
        await self.receiver.start()
        replay = await self.call(raw)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record, committed.record)
        after = await self.call(self.request('task-inspect'))
        self.assertEqual(after.record, committed.record)
        await self.call(self.request('task-inspect', seed=bytes([31])*32), expect_reply=False)
        await self.call(self.request('task-inspect'), received_reply=self.host.new_inbox(), expect_reply=False)
        changed = strict_loads(raw)['claims']['payload']
        changed['repositoryRevision'] = 'changed'
        await self.call(self.request('task-reserve', operation='stable-reserve', payload=changed), expect_reply=False)
        await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one',
            'targetRef': ref('task-inspect-grant')})
        await self.call(self.request('task-inspect'), expect_reply=False)
        snapshot = await self.receiver.ledger.current()
        self.assertEqual(snapshot.latest.record, committed.record)
        self.assertEqual(snapshot.latest.sequence, 2)
        # The service borrows identity's actual reader; its own credential must
        # have no raw identity, other-task or stream-management access.
        for subject in ('$JS.API.STREAM.MSG.GET.IDENTITY', '$JS.API.STREAM.MSG.GET.OTHER',
                '$JS.API.STREAM.CREATE.DATA'):
            count = self.errors['storage'].count('permission')
            await self.source_connection.publish(subject, b'{}')
            await self.source_connection.flush(timeout=2)
            await self.wait_permissions('storage', count+1)
        self.assertFalse([error for error in self.errors['identity'] if error != 'permission'])
        self.success = True
    async def _cleanup(self):
        if self.receiver is not None:
            await self._join_cleanup_step('task', lambda: self.receiver.close(timeout=None))
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

    async def cleanup(self):
        if not hasattr(self, '_cleanup_work'):
            self._cleanup_work = asyncio.create_task(self._cleanup())
        await asyncio.shield(self._cleanup_work)


class LiveApplicationAccountCustodyTests(LiveTaskTests):
    """Actual TLS identity owner with real NATS account secrets in custody."""
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None
    seed_ready_task = False
    create_task_host = False

    @property
    def project_scope(self):
        return {'organizationId': 'org-one', 'projectId': 'project-one',
                'workspaceId': None}

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        raw_credential = self.credentials['provisioner'].read_bytes()
        seeds = [line.strip() for line in raw_credential.replace(b'\r\n', b'\n').split(b'\n')
                 if line.strip().startswith(b'SU')]
        if len(seeds) != 1:
            raise RuntimeError('application_account_administrator_credential_invalid')
        prefix, seed_bytes = nkeys.decode_seed(seeds[0])
        if prefix != nkeys.PREFIX_BYTE_USER or len(seed_bytes) != 32:
            raise RuntimeError('application_account_administrator_credential_invalid')
        key = nkeys.from_seed(seeds[0])
        try:
            administrator_public_key = base64.urlsafe_b64encode(
                bytes(SigningKey(seed_bytes).verify_key)).decode().rstrip('=')
        finally:
            key.wipe()
        admin = {'ref': ref('application-account-admin'),
            'principalId': 'application-account-admin', 'kind': 'service',
            'status': 'active', 'externalIdentity': None}
        state['identities'].append(admin)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('application-account-admin-transport'),
            identityRef=admin['ref'], publicKey=administrator_public_key)
        state['transports'].append(transport)
        for name, identity, scope in (
                ('application-account-caller-member', ref('human'), self.project_scope),
                ('application-account-admin-member', admin['ref'], self.project_scope)):
            state['memberships'].append({'ref': ref(name), 'identityRef': identity,
                'scope': copy.deepcopy(scope), 'status': 'active'})
        base = copy.deepcopy(state['grants'][0])
        for name, contract, resource, scope in (
                ('application-account-set-grant', 'identity-application-account-set',
                 'authority-one', self.scope),
                ('application-account-resolve-grant', 'identity-application-account-resolve',
                 'application-account', self.project_scope)):
            grant = copy.deepcopy(base)
            grant.update(ref=ref(name), contractId=contract, resourceId=resource,
                         scope=copy.deepcopy(scope))
            state['grants'].append(grant)
        return initial

    async def asyncSetUp(self):
        await super().asyncSetUp()
        root = self.directory/'application-account-secrets'
        root.mkdir(mode=0o700)
        self.secret_custody = ScopedSecretCustody(root, self.identity.reader)

    def account_issuer_seed(self):
        matches = list((self.directory/'nsc-keys').rglob(self.account_public_key+'.nk'))
        if len(matches) != 1:
            raise RuntimeError('application_account_issuer_seed_unavailable')
        seed = matches[0].read_bytes().strip()
        if nkeys.from_seed(seed).public_key.decode('ascii') != self.account_public_key:
            raise RuntimeError('application_account_issuer_seed_mismatch')
        return seed

    async def rotated_administrator_credential(self):
        """Create and connect a distinct user credential in the fixture account."""
        role = 'rotated-application-account-admin'
        self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
        nsc = Path(os.environ['AGENTMUX_PLUGIN_NSC'])
        common = [str(nsc), '--config-dir', str(self.directory/'nsc-config'),
            '--data-dir', str(self.directory/'nsc-store'),
            '--keystore-dir', str(self.directory/'nsc-keys')]
        log_path = self.directory/'nsc.private.log'
        with log_path.open('ab') as log:
            result = subprocess.run([*common, 'add', 'user', '-a', 'CAPABILITY',
                '-n', role, '--allow-pub', '>', '--allow-sub',
                self.inbox_prefixes[role]+'.>'], stdout=log, stderr=log, timeout=8)
            if result.returncode:
                raise RuntimeError('application_account_rotation_fixture_failed')
            result = subprocess.run([*common, 'generate', 'creds', '-a', 'CAPABILITY',
                '-n', role], stdout=subprocess.PIPE, stderr=log, timeout=8)
        if result.returncode or not result.stdout or len(result.stdout) > 65_536:
            raise RuntimeError('application_account_rotation_fixture_failed')
        path = self.directory/(role+'.creds')
        self.write_private(path.name, result.stdout, raw=True)
        self.credentials[role] = path
        connection = await self.connect(role)
        await connection.flush(timeout=2)
        return path.read_bytes()

    def account_payload(self, revision):
        now = datetime.now(timezone.utc)
        interval = {'status': 'active', 'issuedAt': stamp(now-timedelta(seconds=30)),
                    'expiresAt': stamp(now+timedelta(minutes=3))}
        account_ref = {'id': 'application-account', 'ownerHubId': 'hub-one',
                       'revision': revision}
        credential_ref = {'id': 'application-account-administrator-credential',
                          'ownerHubId': 'hub-one', 'revision': revision}
        issuer_ref = {'id': 'application-account-issuer', 'ownerHubId': 'hub-one',
                      'revision': revision}
        credential = {'ref': credential_ref, 'kind': 'nats-administrator-credential',
            'scope': self.project_scope, 'profileId': 'profile-one',
            'ownerIdentityRef': ref('application-account-admin'), **interval}
        issuer = {'ref': issuer_ref, 'kind': 'nats-account-issuer',
            'scope': self.project_scope, 'profileId': 'profile-one',
            'ownerIdentityRef': ref('application-account-admin'), **interval}
        account = {'ref': account_ref, 'profileId': 'profile-one',
            'scope': self.project_scope, 'accountPublicKey': self.account_public_key,
            'administratorIdentityRef': ref('application-account-admin'),
            'administratorTransportRef': ref('application-account-admin-transport'),
            'administratorCredentialRef': credential_ref,
            'accountIssuerRef': issuer_ref, **interval}
        previous = lambda name: None if revision == 1 else {
            'id': name, 'ownerHubId': 'hub-one', 'revision': revision-1}
        return {'authorityId': 'authority-one', 'record': account,
            'previousRef': previous('application-account'),
            'administratorCredential': {'record': credential,
                'previousRef': previous('application-account-administrator-credential')},
            'accountIssuer': {'record': issuer,
                'previousRef': previous('application-account-issuer')}}

    async def identity_request(self, contract, grant, payload, scope, expected_version,
                               operation_id):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref(grant),
            'operationId': operation_id, 'expectedVersion': expected_version,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=20)),
            'replySubject': self.host.new_inbox()}
        return packet(claims, bytes(reversed(SEED)))

    async def owner_exchange(self, raw, *, timeout=2):
        claims = strict_loads(raw)['claims']
        return await self.exchange(self.host, self.identity_subject, raw,
                                   claims['replySubject'], timeout=timeout)

    async def custody_envelope(self, raw):
        operation = strict_loads(raw)['claims']['operationId']
        admitted = await self.identity.ingress.admit(raw, cancellation_ref={
            'id': 'custody-'+operation, 'ownerHubId': 'hub-one', 'revision': 1})
        self.assertEqual(admitted.decision.outcome, 'allowed')
        self.assertIsNotNone(admitted.envelope)
        return admitted.envelope

    async def test_tls_application_account_custody_rotation_and_revocation(self):
        administrator_credential = self.credentials['provisioner'].read_bytes()
        rotated_administrator_credential = await self.rotated_administrator_credential()
        self.assertFalse(secrets.compare_digest(
            administrator_credential, rotated_administrator_credential))
        account_issuer = self.account_issuer_seed()
        first_payload = self.account_payload(1)
        first_raw = await self.identity_request('identity-application-account-set',
            'application-account-set-grant', first_payload, self.scope, 1,
            'application-account-set-one')
        first_envelope = await self.custody_envelope(first_raw)
        for kind, secret in (('nats-administrator-credential', administrator_credential),
                             ('nats-account-issuer', account_issuer)):
            await self.secret_custody.provision(first_envelope, kind=kind, secret=secret)
        first_response = await self.owner_exchange(first_raw)
        first_receipt = verify_receipt(first_response, first_raw,
            public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertFalse(first_receipt['replayed'])

        replay = verify_receipt(await self.owner_exchange(first_raw), first_raw,
            public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertTrue(replay['replayed'])
        self.assertEqual((replay['sequence'], replay['entityVersion']),
                         (first_receipt['sequence'], first_receipt['entityVersion']))
        retained = strict_loads((await self.identity.ledger.current()).latest.record)
        account = retained['state']['applicationAccounts'][0]
        self.assertEqual((account['administratorCredentialRef']['revision'],
                          account['accountIssuerRef']['revision']), (1, 1))

        first_resolve_payload = {'authorityId': 'authority-one',
            'accountRef': first_payload['record']['ref'], 'profileId': 'profile-one',
            'scope': self.project_scope, 'accountPublicKey': self.account_public_key}
        first_resolve_raw = await self.identity_request('identity-application-account-resolve',
            'application-account-resolve-grant', first_resolve_payload,
            self.project_scope, 0, 'application-account-resolve-one')
        first_resolve_envelope = await self.custody_envelope(first_resolve_raw)
        resolved = strict_loads(await self.owner_exchange(first_resolve_raw))
        validate_contract('identity-application-account-resolution', resolved)
        verify_possession(resolved['claims'], resolved['signature'], self.issuer_public)
        self.assertEqual(resolved['claims']['requestDigest'],
                         payload_digest(strict_loads(first_resolve_raw)))
        for kind, expected in (('nats-administrator-credential', administrator_credential),
                               ('nats-account-issuer', account_issuer)):
            private = await self.secret_custody.resolve(first_resolve_envelope, kind=kind)
            self.assertTrue(secrets.compare_digest(private.private_copy(), expected),
                            'custody bytes differ')
            recovered = await self.secret_custody.recover(first_resolve_envelope, kind=kind)
            self.assertEqual(recovered['revision'], 1)

        second_payload = self.account_payload(2)
        second_raw = await self.identity_request('identity-application-account-set',
            'application-account-set-grant', second_payload, self.scope,
            first_receipt['entityVersion'], 'application-account-set-two')
        second_envelope = await self.custody_envelope(second_raw)
        for kind, secret in (('nats-administrator-credential', rotated_administrator_credential),
                             ('nats-account-issuer', account_issuer)):
            await self.secret_custody.provision(second_envelope, kind=kind, secret=secret)
        second_receipt = verify_receipt(await self.owner_exchange(second_raw), second_raw,
            public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertFalse(second_receipt['replayed'])

        second_resolve_payload = copy.deepcopy(first_resolve_payload)
        second_resolve_payload['accountRef'] = second_payload['record']['ref']
        second_resolve_raw = await self.identity_request('identity-application-account-resolve',
            'application-account-resolve-grant', second_resolve_payload,
            self.project_scope, 0, 'application-account-resolve-two')
        second_resolve_envelope = await self.custody_envelope(second_resolve_raw)
        second_resolution = strict_loads(await self.owner_exchange(second_resolve_raw))
        validate_contract('identity-application-account-resolution', second_resolution)
        self.assertEqual((second_resolution['claims']['administratorCredentialRef']['revision'],
                          second_resolution['claims']['accountIssuerRef']['revision']), (2, 2))
        for kind, expected in (
                ('nats-administrator-credential', rotated_administrator_credential),
                ('nats-account-issuer', account_issuer)):
            self.assertEqual((await self.secret_custody.recover(
                second_resolve_envelope, kind=kind))['revision'], 2)
            private = await self.secret_custody.resolve(second_resolve_envelope, kind=kind)
            self.assertTrue(secrets.compare_digest(private.private_copy(), expected),
                            'rotated custody bytes differ')
            with self.assertRaises(ContractError):
                await self.secret_custody.resolve(first_resolve_envelope, kind=kind)
        old_refusal = strict_loads(await self.owner_exchange(first_resolve_raw, timeout=.4))
        self.assertEqual(old_refusal,
                         {'schemaVersion': '1.0.0', 'error': 'identity_outcome_unconfirmed'})
        self.assertNotIn('administratorCredentialRef', old_refusal)

        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one',
            'targetRef': second_payload['administratorCredential']['record']['ref']})
        with self.assertRaises(ContractError):
            await self.secret_custody.resolve(second_resolve_envelope,
                kind='nats-administrator-credential')
        revoked_refusal = strict_loads(await self.owner_exchange(second_resolve_raw, timeout=.4))
        self.assertEqual(revoked_refusal,
                         {'schemaVersion': '1.0.0', 'error': 'identity_outcome_unconfirmed'})
        self.assertNotIn('administratorCredentialRef', revoked_refusal)
        self.success = True


class LiveLegacyAliasApplicationTests(LiveTaskTests):
    """Actual enrolled application query on the existing owned TLS broker."""
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None
    seed_ready_task = False
    create_task_host = False

    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        self.inbox_prefixes['application'] = '_INBOX.' + secrets.token_hex(16)
        policies['application'] = {
            'publish': {'allow': [self.identity_subject]},
            'subscribe': {'allow': []},
        }

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        project = {'organizationId': 'org-one', 'projectId': 'project-one',
                   'workspaceId': None}
        other_project = {'organizationId': 'org-one', 'projectId': 'project-two',
                         'workspaceId': None}
        base_member = copy.deepcopy(state['memberships'][0])
        for name, identity, scope in (
                ('application-member', ref('human'), project),
                ('other-project-member', ref('human'), other_project),
                ('application-host-member', ref('service'), project)):
            member = copy.deepcopy(base_member)
            member.update(ref=ref(name), identityRef=identity, scope=copy.deepcopy(scope))
            state['memberships'].append(member)
        base_grant = copy.deepcopy(state['grants'][0])
        for name, caller, scope, contract, resource in (
                ('application-bind', ref('human'), project, 'application-bind', 'application-one'),
                ('application-attest', ref('service'), project, 'application-attest', 'application-one'),
                ('local-browser-open', ref('human'), project,
                 'local-browser-session-open', 'authority-one'),
                ('legacy-alias-resolve', ref('human'), project,
                 'identity-legacy-alias-resolve', 'authority-one'),
                ('other-project-resolve', ref('human'), other_project,
                 'identity-legacy-alias-resolve', 'authority-one')):
            grant = copy.deepcopy(base_grant)
            grant.update(ref=ref(name), callerRef=caller, actorRef=caller,
                         scope=copy.deepcopy(scope), contractId=contract, resourceId=resource)
            state['grants'].append(grant)
        state['legacyAliases'] = [
            {'ref': ref('legacy-project-one'), 'status': 'active',
             'identityRef': ref('human'), 'sourceHubId': 'hub-one',
             'scope': copy.deepcopy(project), 'instanceOwner': None,
             'registrationGeneration': 3, 'canonicalSession': 'alpha-worker-w1',
             'alias': 'old-w1'},
            {'ref': ref('legacy-project-two'), 'status': 'active',
             'identityRef': ref('human'), 'sourceHubId': 'hub-one',
             'scope': copy.deepcopy(other_project), 'instanceOwner': None,
             'registrationGeneration': 4, 'canonicalSession': 'beta-worker-w2',
             'alias': 'old-w1'},
            {'ref': ref('legacy-remote'), 'status': 'active',
             'identityRef': ref('human'), 'sourceHubId': 'remote-hub',
             'scope': copy.deepcopy(project), 'instanceOwner': None,
             'registrationGeneration': 5, 'canonicalSession': 'remote-worker-w3',
             'alias': 'old-remote'},
            {'ref': ref('legacy-remote-other-project'), 'status': 'active',
             'identityRef': ref('human'), 'sourceHubId': 'remote-other',
             'scope': copy.deepcopy(other_project), 'instanceOwner': None,
             'registrationGeneration': 5, 'canonicalSession': 'other-worker-w3',
             'alias': 'old-remote'},
            {'ref': ref('legacy-remote-collision-a'), 'status': 'active',
             'identityRef': ref('human'), 'sourceHubId': 'remote-a',
             'scope': copy.deepcopy(project), 'instanceOwner': None,
             'registrationGeneration': 6, 'canonicalSession': 'collision-worker-w4',
             'alias': 'old-collision-a'},
            {'ref': ref('legacy-remote-collision-b'), 'status': 'active',
             'identityRef': ref('human'), 'sourceHubId': 'remote-b',
             'scope': copy.deepcopy(project), 'instanceOwner': None,
             'registrationGeneration': 7, 'canonicalSession': 'collision-worker-w4',
             'alias': 'old-collision-b'},
        ]
        issuer = state['issuers'][0]
        terminal_grants = None
        if getattr(self, 'oidc_terminal_fixture', False):
            state['identities'][0]['externalIdentity'] = {
                'issuer': os.environ['AMX_OIDC_LIVE_ISSUER'],
                'subject': os.environ.get('AMX_OIDC_LIVE_SUBJECT', 'keycloak-user-184')}
            terminal_grants = {}
            for contract in ('oidc-terminal-session-open', 'oidc-terminal-session-status',
                             'oidc-terminal-session-close'):
                name = contract + '-grant'
                grant = copy.deepcopy(base_grant)
                grant.update(ref=ref(name), callerRef=ref('human'), actorRef=ref('human'),
                             scope=copy.deepcopy(project), contractId=contract,
                             resourceId='authority-one')
                state['grants'].append(grant)
                terminal_grants[contract] = ref(name)
        common = {'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'instanceId': 'application-one',
            'callerRef': ref('human'), 'scope': copy.deepcopy(project),
            'grantRef': ref('application-bind'), 'replyIssuerRef': ref('issuer'),
            'replyIssuerPublicKey': issuer['publicKey'],
            'releaseDigest': 'sha256:' + 'a' * 64,
            'policyRef': ref('application-policy'), 'workspaceRef': None}
        now = datetime.now(timezone.utc)
        client_lifetime = (timedelta(minutes=20)
            if getattr(self, 'oidc_terminal_fixture', False) else timedelta(minutes=5))
        interval = (stamp(now-timedelta(seconds=30)), stamp(now+client_lifetime))
        for path, suffix, resolver_grant in (
                (self.directory/'application-client.key', 'current', 'legacy-alias-resolve'),
                (self.directory/'wrong-grant-client.key', 'wrong', 'other-project-resolve')):
            selection = dict(common, transportRef=ref('application-transport-'+suffix),
                legacyAliasResolve={'subject': self.identity_subject,
                    'grantRef': ref(resolver_grant),
                    'transportRef': ref('legacy-transport-'+suffix),
                    'replyIssuerRef': ref('issuer'),
                    'replyIssuerPublicKey': issuer['publicKey']})
            if suffix == 'current':
                selection['localBrowserSessionOpen'] = {'subject': self.identity_subject,
                    'grantRef': ref('local-browser-open'),
                    'transportRef': ref('local-browser-transport'),
                    'replyIssuerRef': ref('issuer'),
                    'replyIssuerPublicKey': issuer['publicKey']}
                if terminal_grants is not None:
                    selection['oidcTerminalSession'] = {'subject': self.identity_subject,
                        'grantRefs': terminal_grants,
                        'transportRef': ref('oidc-terminal-transport'),
                        'replyIssuerRef': ref('issuer'),
                        'replyIssuerPublicKey': issuer['publicKey']}
            payload = provision_application_client(path, selection=selection,
                identity=state['identities'][0], issued_at=interval[0], expires_at=interval[1])
            state = transition(state, 'identity-enroll', payload, hub_id='hub-one')
        initial['state'] = state
        return initial

    async def asyncSetUp(self):
        await super().asyncSetUp()
        project = {'organizationId': 'org-one', 'projectId': 'project-one',
                   'workspaceId': None}
        self.identity.configure_legacy_identity(LegacyIdentityAdapter(self.identity.reader,
            local_source_hub_id='hub-one', scope=project))
        self.application_done = asyncio.Event()
        self.application_lease = ApplicationObservationLease(
            self.application_observation(), self.application_done)
        self.identity.replace_application_lease(self.application_lease)
        credential = validate(self.credentials['application'].read_bytes(),
            account_public_key=self.account_public_key,
            publish_subjects=selected_publish_subjects(
                load_application_client(self.directory/'application-client.key')),
            subscribe_subjects=[self.inbox_prefixes['application']+'.>'], private_inbox=True)
        connection = {'schemaVersion': '1.0.0', 'endpoint': self.broker.url,
            'serverName': self.server_name, 'rootsPEM': self.ca_file.read_text(),
            'leafCertificateSHA256': self.leaf_digest,
            'credentialsFile': str(self.credentials['application']),
            'accountPublicKey': self.account_public_key, 'userPublicKey': credential.public_key,
            'replyPrefix': self.inbox_prefixes['application']}
        self.write_private('application-connection.json', connection)
        workspace = self.directory/'application-workspace'
        workspace.mkdir(mode=0o700)
        self.application_selection = SimpleNamespace(hub_id='hub-one', profile_id='profile-one',
            instance_id='application-one', invocation=SimpleNamespace(workspaces=(str(workspace),)),
            application_client=str(self.directory/'application-client.key'),
            application_connection=str(self.directory/'application-connection.json'))
        self.application_owners = []
        self.application_sessions = []

    def application_observation(self):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-application-runtime-observation-v1',
            'hubId': 'hub-one', 'profileId': 'profile-one', 'instanceId': 'application-one',
            'generation': 1, 'lifetimeId': 'd' * 64,
            'releaseDigest': 'sha256:' + 'a' * 64,
            'policyRef': ref('application-policy'), 'workspaceRef': None,
            'scope': {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None},
            'signingKeyRef': ref('issuer'), 'issuedAt': stamp(now),
            'expiresAt': stamp(now+timedelta(seconds=5))}
        return packet(claims, SEED, native=True)

    def refresh_application_observation(self):
        """Keep the same runtime generation inside its production five-second lease."""
        self.application_lease.refresh(self.application_observation())

    async def open_application(self, key='application-client.key'):
        self.refresh_application_observation()
        loop = asyncio.get_running_loop()
        try:
            owner = await open_application_client(str(self.directory/key),
                str(self.directory/'application-connection.json'), selected=self.application_selection,
                deadline=loop.time()+4, cleanup_deadline=loop.time()+6)
        except ConnectionFailure as error:
            if error.owner not in self.application_owners:
                self.application_owners.append(error.owner)
            raise
        self.application_owners.append(owner)
        return owner

    async def open_application_session(self):
        """Open the production synchronous session without blocking the owner loop."""
        self.refresh_application_observation()
        session = ApplicationClientSession(self.application_selection)
        self.application_sessions.append(session)
        await asyncio.to_thread(session.start, deadline=time.monotonic()+4)
        return session

    async def close_application(self, owner):
        await owner.close(deadline=asyncio.get_running_loop().time()+3)
        self.assertTrue(owner._client.is_closed)
        self.assertFalse(owner._subscriptions)

    async def _cleanup(self):
        for session in reversed(getattr(self, 'application_sessions', [])):
            async def close(retained=session):
                try:
                    complete = await asyncio.to_thread(
                        retained.close, deadline=time.monotonic()+3)
                except Exception:
                    complete = False
                if not complete:
                    complete = await asyncio.to_thread(retained.join_final)
                if not complete:
                    raise RuntimeError('application session cleanup incomplete')
            await self._join_cleanup_step('application-session', close)
        for owner in reversed(getattr(self, 'application_owners', [])):
            await self._join_cleanup_step('application',
                lambda retained=owner: retained.close(
                    deadline=asyncio.get_running_loop().time()+3))
        if hasattr(self, 'application_done'):
            self.application_done.set()
        await super()._cleanup()

    @staticmethod
    def registration(*, session='alpha-worker-w1', generation=3,
                     repository='alpha', role='worker', agent='w1'):
        return {'requestedAddress': 'old-w1', 'canonicalSession': session,
            'registrationGeneration': generation, 'repository': repository,
            'role': role, 'agent': agent, 'state': 'ready', 'legacyAlias': 'old-w1'}

    async def refused(self, registration, *, key='application-client.key'):
        owner = await self.open_application(key)
        loop = asyncio.get_running_loop()
        with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
            await owner.query_legacy_aliases(registrations=[registration],
                operation_id='refused-'+secrets.token_hex(8), deadline=loop.time()+2,
                cleanup_deadline=loop.time()+4)
        self.assertTrue(owner._client.is_closed)
        self.assertFalse(owner._subscriptions)

    async def refused_remote(self, remote_address):
        owner = await self.open_application()
        loop = asyncio.get_running_loop()
        with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
            await owner.query_legacy_aliases(remote_address=remote_address,
                operation_id='refused-remote-'+secrets.token_hex(8), deadline=loop.time()+2,
                cleanup_deadline=loop.time()+4)
        self.assertTrue(owner._client.is_closed)
        self.assertFalse(owner._subscriptions)

    async def exercise_enrolled_hub_path(self):
        """Use the retained production session through resolver, Hub and Store."""
        primary_session = await self.open_application_session()
        primary = EnrolledLegacyIdentityResolver({repository: primary_session for repository in
            ('alpha', 'remote')}, local_source_hub_id='hub-one')
        hub_root = self.directory/'hub-home'
        hub_directory = hub_root/'hub'
        with patch.object(hub_server, 'ROOT', str(hub_root)), \
                patch.object(hub_server, 'HUBDIR', str(hub_directory)):
            hub = hub_server.Hub(legacy_identity=primary)
        try:
            def register(repository, role, agent, generation, legacy=None):
                selected = None
                for current in range(1, generation+1):
                    if selected is not None:
                        hub.store.set_state(selected, 'dead', 'live generation fixture')
                    selected = hub.store.register(repository, role, agent, 'codex', {},
                        legacy=legacy if current == generation else None)
                hub.store.set_state(selected, 'ready')
                return selected

            await hub.db(hub.store.repo_add, 'alpha')
            await hub.db(hub.store.repo_add, 'beta')
            alpha = await hub.db(register, 'alpha', 'worker', 'w1', 3, 'old-w1')
            await hub.db(register, 'beta', 'worker', 'w2', 4)

            local = await hub.dispatch('post', {
                'to': 'old-w1', 'kind': 'note', 'body': 'enrolled local'}, 'operator')
            self.assertEqual(local['recipients'], [alpha])
            local_row = await hub.db(hub.store.q1,
                'SELECT target FROM messages WHERE id=?', (local['id'],))
            self.assertEqual(local_row['target'], 'agent:'+alpha)

            # A remote post uses the repository parsed from the canonical session
            # and records only owner-verified provenance in the transactional outbox.
            self.refresh_application_observation()
            hub.bridge = SimpleNamespace()
            remote = await hub.dispatch('post', {
                'to': 'agent:remote-worker-w3', 'kind': 'note',
                'body': 'enrolled remote'}, 'operator')
            self.assertTrue(remote['remote'])
            outbound = json.loads((await hub.db(hub.store.q1,
                'SELECT payload FROM nats_outbox ORDER BY seq DESC LIMIT 1'))['payload'])
            provenance = outbound['legacyIdentity']
            self.assertEqual((provenance['canonicalSession'], provenance['sourceHubId'],
                              provenance['registrationGeneration']),
                             ('remote-worker-w3', 'remote-hub', 5))

            # Inbound provenance is untrusted input. The resolver selects the
            # current local registration, re-queries authority and then Store
            # checks the same generation before creating the delivery.
            self.refresh_application_observation()
            selected_registration = await hub.db(hub.store.registration, 'agent:'+alpha)
            current = await primary.bind((selected_registration,))
            inbound = await hub.ingest_message({'id': 'live-inbound-one',
                'sender': 'agent:remote-worker-w3', 'target': 'agent:'+alpha,
                'kind': 'note', 'body': 'verified inbound', 'origin': 'remote-node',
                'legacyIdentity': current.bindings[0].wire()})
            self.assertEqual(inbound['recipients'], [alpha])

            # Let one signed resolution expire, prove Store refuses it without
            # mutation, then use the same retained session for a fresh operation.
            self.refresh_application_observation()
            expired = await primary.bind((selected_registration,))
            await asyncio.sleep(max(0, (expired.valid_until-datetime.now(timezone.utc)).total_seconds())+.05)
            count = (await hub.db(hub.store.q1,
                'SELECT count(*) AS n FROM messages'))['n']
            with self.assertRaisesRegex(HubError, 'legacy identity resolution expired'):
                await hub.db(hub.store.post, 'virtual:operator', 'agent:'+alpha,
                    'note', 'expired binding', identity_bindings=expired)
            self.assertEqual((await hub.db(hub.store.q1,
                'SELECT count(*) AS n FROM messages'))['n'], count)
            # The host renews the same observed runtime generation. The retained
            # client connection then renews its binding before this fresh query.
            self.refresh_application_observation()
            fresh = await hub.dispatch('post', {'to': 'agent:'+alpha,
                'kind': 'note', 'body': 'fresh after expiry'}, 'operator')
            self.assertEqual(fresh['recipients'], [alpha])

            # The alpha group succeeds first on this shared retained session;
            # the beta project then refuses. No partial message may be written.
            cross_session = await self.open_application_session()
            hub._legacy_identity = EnrolledLegacyIdentityResolver({
                'alpha': cross_session, 'beta': cross_session},
                local_source_hub_id='hub-one')
            count = (await hub.db(hub.store.q1,
                'SELECT count(*) AS n FROM messages'))['n']
            with self.assertRaisesRegex(HubError, 'legacy_identity_unavailable'):
                await hub.dispatch('post', {'to': 'role:*/worker',
                    'kind': 'note', 'body': 'cross-project refusal'}, 'operator')
            self.assertEqual((await hub.db(hub.store.q1,
                'SELECT count(*) AS n FROM messages'))['n'], count)

            # A new Store incarnation cannot use the binding for generation 3.
            await hub.db(hub.store.set_state, alpha, 'dead', 'live generation change')
            alpha = await hub.db(hub.store.register,
                'alpha', 'worker', 'w1', 'codex', {}, legacy='old-w1')
            await hub.db(hub.store.set_state, alpha, 'ready')
            generation_session = await self.open_application_session()
            hub._legacy_identity = EnrolledLegacyIdentityResolver({
                'alpha': generation_session}, local_source_hub_id='hub-one')
            count = (await hub.db(hub.store.q1,
                'SELECT count(*) AS n FROM messages'))['n']
            with self.assertRaisesRegex(HubError, 'legacy_identity_unavailable'):
                await hub.dispatch('post', {'to': 'old-w1',
                    'kind': 'note', 'body': 'stale generation refusal'}, 'operator')
            self.assertEqual((await hub.db(hub.store.q1,
                'SELECT count(*) AS n FROM messages'))['n'], count)

            # Two current authority mappings for one remote canonical session
            # are ambiguous and must not create a remote message or outbox row.
            ambiguous_session = await self.open_application_session()
            hub._legacy_identity = EnrolledLegacyIdentityResolver({
                'collision': ambiguous_session}, local_source_hub_id='hub-one')
            counts = await hub.db(hub.store.q1,
                'SELECT (SELECT count(*) FROM messages) AS messages, '
                '(SELECT count(*) FROM nats_outbox) AS outbox')
            with self.assertRaisesRegex(HubError, 'legacy_identity_unavailable'):
                await hub.dispatch('post', {'to': 'agent:collision-worker-w4',
                    'kind': 'note', 'body': 'ambiguous refusal'}, 'operator')
            self.assertEqual(await hub.db(hub.store.q1,
                'SELECT (SELECT count(*) FROM messages) AS messages, '
                '(SELECT count(*) FROM nats_outbox) AS outbox'), counts)
        finally:
            await hub.db(hub.store.db.close)
            hub.dbx.shutdown(wait=True)
            hub.io.shutdown(wait=True)

    async def test_tls_enrolled_application_legacy_alias_scope_generation_and_revocation(self):
        owner = await self.open_application()
        loop = asyncio.get_running_loop()
        resolution = await owner.query_legacy_aliases(registrations=[self.registration()],
            operation_id='resolve-current-alias', deadline=loop.time()+2,
            cleanup_deadline=loop.time()+4)
        bindings = resolution.bindings
        self.assertGreater(resolution.valid_until, datetime.now(timezone.utc))
        self.assertEqual(len(bindings), 1)
        binding = bindings[0]
        self.assertEqual((binding.alias, binding.canonical_session, binding.source_hub_id,
                          binding.registration_generation, strict_loads(binding.scope)),
            ('old-w1', 'alpha-worker-w1', 'hub-one', 3,
             {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}))
        await self.close_application(owner)

        owner = await self.open_application()
        loop = asyncio.get_running_loop()
        remote = await owner.query_legacy_aliases(remote_address='agent:remote-worker-w3',
            operation_id='resolve-remote-alias', deadline=loop.time()+2,
            cleanup_deadline=loop.time()+4)
        self.assertGreater(remote.valid_until, datetime.now(timezone.utc))
        self.assertEqual(len(remote.bindings), 1)
        remote_binding = remote.bindings[0]
        self.assertEqual((remote_binding.alias, remote_binding.canonical_session,
                          remote_binding.source_hub_id, remote_binding.registration_generation,
                          strict_loads(remote_binding.scope), remote_binding.local),
            ('old-remote', 'remote-worker-w3', 'remote-hub', 5,
             {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None},
             False))
        await self.close_application(owner)

        await self.exercise_enrolled_hub_path()

        await self.refused(self.registration(session='beta-worker-w2', generation=4,
            repository='beta', agent='w2'))
        await self.refused(self.registration(generation=2))
        await self.refused_remote('agent:other-worker-w3')
        await self.refused_remote('agent:collision-worker-w4')
        await self.refused(self.registration(), key='wrong-grant-client.key')

        owner = await self.open_application()
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('legacy-alias-resolve')})
        loop = asyncio.get_running_loop()
        with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
            await owner.query_legacy_aliases(registrations=[self.registration()],
                operation_id='resolve-revoked-alias', deadline=loop.time()+2,
                cleanup_deadline=loop.time()+4)
        self.assertTrue(owner._client.is_closed)
        self.assertFalse(owner._subscriptions)
        self.assertFalse(self.errors.get('application', []) or self.errors['identity'])
        self.success = True


    async def _tls_local_browser_pairing(self, *, revoke_target=None):
        """Pair through the real owner route and optionally revoke current authority."""
        from application_service_host import ApplicationServiceHost
        from local_browser_auth import LocalBrowserAuth
        import server as dashboard_server
        from server import BacklogServer, Handler

        loop = asyncio.get_running_loop()
        host = object.__new__(ApplicationServiceHost)
        host._closed = False
        host._connection_failure = None
        host._loop = loop
        home_patch = patch.object(dashboard_server, 'HOME_DIR', self.directory)
        home_patch.start()
        server = BacklogServer(('127.0.0.1', 0), Handler, application_host=host)
        port = server.server_address[1]
        host._browser_auth = LocalBrowserAuth(port)
        host._browser_origin = f'http://127.0.0.1:{port}'
        thread = threading.Thread(target=server.serve_forever,
            name='agentmux-live-browser-pairing', daemon=False)
        owner = pending = None
        started = False
        challenge = '2345-6789-ABCD-EFGH-JKMP'

        def pair():
            request = urllib.request.Request(host._browser_origin + '/api/local-auth/pair',
                data=canonical_bytes({'challenge': challenge}), method='POST',
                headers={'Content-Type': 'application/json', 'Origin': host._browser_origin})
            with urllib.request.urlopen(request, timeout=4) as response:
                return response.status, dict(response.headers), json.loads(response.read())

        try:
            self.identity.configure_local_browser_host(host)
            thread.start()
            started = True
            owner = await self.open_application()
            pending = asyncio.create_task(asyncio.to_thread(pair))
            deadline = loop.time() + 2
            while not host._browser_auth._pairings and loop.time() < deadline:
                await asyncio.sleep(.01)
            self.assertTrue(host._browser_auth._pairings)
            result = await owner.local_browser_session_open(challenge=challenge,
                origin=host._browser_origin, operation_id='live-browser-open',
                deadline=loop.time()+2, cleanup_deadline=loop.time()+4)
            status, headers, body = await pending
            self.assertEqual((result['outcome'], status), ('approved', 200))
            self.assertIn('HttpOnly', headers['Set-Cookie'])
            self.assertIn('SameSite=Strict', headers['Set-Cookie'])
            self.assertEqual(len(body['csrfToken']), 43)
            if revoke_target is not None:
                await self.command('identity-revoke', ref('grant'), {
                    'authorityId': 'authority-one', 'targetRef': ref(revoke_target)})
                cookie = headers['Set-Cookie'].split(';', 1)[0]
                expected = ('application_permission_unavailable'
                    if revoke_target == 'application-member'
                    else 'application_credential_unavailable')
                with self.assertRaisesRegex(ContractError, '^' + expected + '$'):
                    await host._browser_auth.authorize(cookie, body['csrfToken'],
                        method='POST', target='/api/board/agentdef',
                        host='127.0.0.1:' + str(port), origin=host._browser_origin,
                        body={'name': 'writer', 'scope': 'repo'})
            self.assertFalse(self.errors.get('application', []) or self.errors['identity'])
            self.success = True
        finally:
            host._browser_auth.close()
            if started:
                server.shutdown()
            server.server_close()
            if pending is not None:
                await asyncio.gather(pending, return_exceptions=True)
            if owner is not None:
                await self.close_application(owner)
            if started:
                await asyncio.to_thread(thread.join, 3)
                self.assertFalse(thread.is_alive())
            home_patch.stop()

    async def test_tls_local_browser_pairing_returns_real_http_cookie(self):
        """Pair one browser challenge through the real TLS owner command and HTTP route."""
        await self._tls_local_browser_pairing()

    async def test_tls_local_browser_current_membership_revocation_refuses(self):
        await self._tls_local_browser_pairing(revoke_target='application-member')

    async def test_tls_local_browser_current_identity_revocation_refuses(self):
        await self._tls_local_browser_pairing(revoke_target='human')

    async def test_real_enrolled_hub_cli_socket_start_routes_and_cleans_up(self):
        """Start the real bootstrap child, use its socket, then join that exact child."""
        root = Path(__file__).resolve().parents[1]
        # Darwin limits Unix socket paths. Keep this owned home short and record
        # its exact identity inside the retained fixture before starting a child.
        hub_home = Path(tempfile.mkdtemp(prefix='amxh-', dir='/tmp')).resolve()
        home_record = self.directory/'enrolled-hub-home.path'
        home_record.write_text(str(hub_home))
        home_record.chmod(0o600)
        hub_directory = hub_home/'hub'
        hub_directory.mkdir(parents=True, mode=0o700)
        config = hub_directory/'config.toml'
        config.write_text('tcp_port = 0\nnats_url = ""\n')
        config.chmod(0o600)

        store = Store(str(hub_directory/'hub.db'))
        try:
            def register(repository, role, agent, generation, legacy=None):
                selected = None
                for current in range(1, generation+1):
                    if selected is not None:
                        store.set_state(selected, 'dead', 'live startup generation fixture')
                    selected = store.register(repository, role, agent, 'codex', {},
                        legacy=legacy if current == generation else None)
                store.set_state(selected, 'ready')
                return selected

            store.repo_add('alpha')
            store.repo_add('beta')
            alpha = register('alpha', 'worker', 'w1', 3, 'old-w1')
            register('beta', 'worker', 'w2', 4)
        finally:
            store.db.close()

        selection = {'schemaVersion': '1.0.0',
            'hostPolicy': str(self.directory/'unused-host-policy.json'),
            'workspaces': list(self.application_selection.invocation.workspaces),
            'instanceId': 'application-one', 'profileId': 'profile-one', 'hubId': 'hub-one',
            'application': {'clientKey': self.application_selection.application_client,
                'connection': self.application_selection.application_connection,
                'repositories': ['alpha']}}
        self.write_private('enrolled-hub-selection.json', selection)
        invalid = copy.deepcopy(selection)
        invalid['application']['repositories'] = []
        self.write_private('invalid-enrolled-hub-selection.json', invalid)
        valid_selection = self.directory/'enrolled-hub-selection.json'
        invalid_selection = self.directory/'invalid-enrolled-hub-selection.json'

        environment = {
            'HOME': str(self.directory/'unused-home'),
            'AGENTMUX_HOME': str(hub_home),
            'AGENTMUX_PYTHON': sys.executable,
            'AGENTMUX_REPO': str(root),
            'AGENTMUX_NO_COURIER': '1',
            'AGENTMUX_SOCKET': 'enrolled-hub-live-unused',
            'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONPATH': os.environ.get('PYTHONPATH', ''),
            'PATH': os.environ.get('PATH', '/usr/bin:/bin:/usr/sbin:/sbin'),
        }
        socket_path = hub_directory/'hub.sock'
        children = []
        original_popen = subprocess.Popen

        def retain_actual_child(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            children.append(process)
            return process

        renewal_stop = asyncio.Event()

        async def renew_observation():
            while not renewal_stop.is_set():
                self.refresh_application_observation()
                try:
                    await asyncio.wait_for(renewal_stop.wait(), 1)
                except asyncio.TimeoutError:
                    pass

        renewal = asyncio.create_task(renew_observation())
        try:
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(hub_cli, 'ROOT', str(hub_home)), \
                    patch.object(hub_cli, 'SOCK', str(socket_path)), \
                    patch.object(subprocess, 'Popen', retain_actual_child):
                with self.assertRaises(hub_cli.Fail):
                    await asyncio.to_thread(hub_cli.start, (str(invalid_selection),))
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
                self.assertFalse(socket_path.exists())

                await asyncio.to_thread(hub_cli.start, (str(valid_selection),))
                self.assertEqual(len(children), 2)
                child = children[1]
                self.assertIsNone(child.poll())
                self.assertTrue(socket_path.is_socket())

                posted = await asyncio.to_thread(hub_cli.call, 'post', {
                    'to': 'old-w1', 'kind': 'note', 'body': 'real enrolled socket route'})
                self.assertEqual(posted['result']['recipients'], [alpha])
                with self.assertRaisesRegex(hub_cli.Fail, 'legacy_identity_unavailable'):
                    await asyncio.to_thread(hub_cli.call, 'post', {
                        'to': 'role:*/worker', 'kind': 'note',
                        'body': 'unselected repository must not partially deliver'})

                await asyncio.to_thread(hub_cli.call, 'shutdown')
                self.assertEqual(await asyncio.to_thread(child.wait, 10), 0)
                self.assertFalse(socket_path.exists())
        finally:
            renewal_stop.set()
            await renewal
            for child in children:
                if child.poll() is None:
                    child.terminate()
                try:
                    await asyncio.to_thread(child.wait, 5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    await asyncio.to_thread(child.wait, 5)

        stored = Store(str(hub_directory/'hub.db'))
        try:
            self.assertEqual(stored.q('SELECT target, body FROM messages ORDER BY created'),
                [{'target': 'agent:'+alpha, 'body': 'real enrolled socket route'}])
        finally:
            stored.db.close()
        self.assertFalse(self.errors.get('application', []) or self.errors['identity'])
        shutil.rmtree(hub_home)
        self.assertFalse(hub_home.exists())
        self.success = True


class LiveOIDCTerminalApplicationTests(LiveLegacyAliasApplicationTests):
    """Real Keycloak login followed by current terminal-session enforcement."""
    test_tls_enrolled_application_legacy_alias_scope_generation_and_revocation = None
    oidc_terminal_fixture = True

    async def asyncSetUp(self):
        await super().asyncSetUp()
        from identity.oidc_adapter import OIDCProvider
        from identity.oidc_device_authorization import OIDCDeviceAuthorizationProvider
        from identity.oidc_terminal_login import OIDCTerminalLoginOwner

        provider = OIDCProvider(os.environ['AMX_OIDC_LIVE_ISSUER'], 'agentmux',
            os.environ['AMX_OIDC_LIVE_KEY_ID'], os.environ['AMX_OIDC_LIVE_PUBLIC_KEY'],
            roots_pem=Path(os.environ['AMX_OIDC_LIVE_ROOTS']).read_text())
        configuration = OIDCDeviceAuthorizationProvider(provider,
            os.environ['AMX_OIDC_LIVE_DEVICE_ENDPOINT'],
            os.environ['AMX_OIDC_LIVE_TOKEN_ENDPOINT'])
        self.terminal_owner = OIDCTerminalLoginOwner(configuration, self.identity)
        self.identity.configure_oidc_terminal(self.terminal_owner)

    async def _approve_terminal(self, owner, label):
        loop = asyncio.get_running_loop()
        opened = await owner.oidc_terminal_command(
            contract_id='oidc-terminal-session-open', payload={},
            operation_id='oidc_open_' + secrets.token_hex(16),
            deadline=loop.time()+10, cleanup_deadline=loop.time()+14)
        print('AMX_OIDC_DEVICE:' + json.dumps({'label': label,
            'verificationUri': opened['verificationUri'],
            'userCode': opened['userCode']}), flush=True)
        attempt_id = opened['attemptId']
        while True:
            await asyncio.sleep(max(1, opened['interval']))
            self.refresh_application_observation()
            status = await owner.oidc_terminal_command(
                contract_id='oidc-terminal-session-status',
                payload={'attemptId': attempt_id},
                operation_id='oidc_status_' + secrets.token_hex(16),
                deadline=loop.time()+10, cleanup_deadline=loop.time()+14)
            if status['outcome'] == 'approved':
                return status['sessionId']

    async def test_keycloak_terminal_injected_expiry_and_membership_revocation(self):
        """Use real login, then inject the server deadline and revoke real authority."""
        owner = await self.open_application()
        session_id = await self._approve_terminal(owner, 'expiry')
        self.refresh_application_observation()
        loop = asyncio.get_running_loop()
        resolved = await owner.query_legacy_aliases(registrations=[self.registration()],
            operation_id='terminal-before-expiry', deadline=loop.time()+3,
            cleanup_deadline=loop.time()+5)
        self.assertEqual(len(resolved.bindings), 1)
        self.identity._oidc_terminal_sessions[session_id]['expiresAt'] = (
            datetime.now(timezone.utc)-timedelta(seconds=1))
        self.refresh_application_observation()
        with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
            await owner.query_legacy_aliases(registrations=[self.registration()],
                operation_id='terminal-after-expiry', deadline=loop.time()+3,
                cleanup_deadline=loop.time()+5)
        self.assertNotIn(session_id, self.identity._oidc_terminal_sessions)

        owner = await self.open_application()
        await self._approve_terminal(owner, 'membership-revocation')
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('application-member')})
        self.refresh_application_observation()
        loop = asyncio.get_running_loop()
        with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
            await owner.query_legacy_aliases(registrations=[self.registration()],
                operation_id='terminal-after-membership-revocation',
                deadline=loop.time()+3, cleanup_deadline=loop.time()+5)
        self.assertFalse(self.errors.get('application', []) or self.errors['identity'])
        self.success = True

    async def test_keycloak_terminal_natural_session_expiry(self):
        """Wait for the fixed production lifetime after one real Keycloak login."""
        owner = await self.open_application()
        session_id = await self._approve_terminal(owner, 'natural-session-expiry')
        self.refresh_application_observation()
        loop = asyncio.get_running_loop()
        before = await owner.query_legacy_aliases(registrations=[self.registration()],
            operation_id='terminal-before-natural-expiry', deadline=loop.time()+3,
            cleanup_deadline=loop.time()+5)
        self.assertEqual(len(before.bindings), 1)
        expires_at = self.identity._oidc_terminal_sessions[session_id]['expiresAt']
        while True:
            remaining = (expires_at-datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                break
            await asyncio.sleep(min(5, remaining))
        self.refresh_application_observation()
        loop = asyncio.get_running_loop()
        with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
            await owner.query_legacy_aliases(registrations=[self.registration()],
                operation_id='terminal-after-natural-expiry', deadline=loop.time()+3,
                cleanup_deadline=loop.time()+5)
        self.assertNotIn(session_id, self.identity._oidc_terminal_sessions)
        self.assertFalse(self.errors.get('application', []) or self.errors['identity'])
        self.success = True


class LiveTaskImportTests(LiveTaskTests):
    """Actual NATS import owner plus the existing TLS inspect/reserve service."""
    seed_ready_task = False
    start_task_host = False

    async def asyncSetUp(self):
        from state_owner import test_task_migration as source_fixture
        from state_owner.task_migration import task_import_identity
        self.source = source_fixture.TaskMigrationTests()
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)
        self.capture = self.source.capture()
        self.legacy_id = (self.source.child if self._testMethodName == 'test_tls_child_import_keeps_parent_and_return_obligation'
            else self.source.parent)['id']
        scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.import_identity = task_import_identity(ref('legacy-source'), self.legacy_id,
            target_hub_id='hub-one', scope=scope)
        self.task_id = self.import_identity['taskId']
        await super().asyncSetUp()

    def initial_authority(self):
        initial = super().initial_authority()
        grant = copy.deepcopy(initial['state']['grants'][-1])
        grant.update(ref=ref('task-import-grant'), contractId='task-import', resourceId=self.task_id)
        initial['state']['grants'].append(grant)
        return initial

    def import_request(self, payload, *, grant=None):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'),
            'grantRef': grant or ref('task-import-grant'), 'operationId': self.import_identity['operationId'],
            'expectedVersion': 0, 'contractId': 'task-import', 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30))}
        return packet(claims, bytes(reversed(SEED)))

    async def admitted_import(self, payload, *, grant=None):
        admitted = await self.identity.ingress.admit(self.import_request(payload, grant=grant),
            cancellation_ref=ref('import-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return admitted.envelope

    async def _run_import(self):
        from state_owner.task_migration import TaskImporter, prepare_task_import
        payload = prepare_task_import(self.capture, self.legacy_id,
            binding=self.bindings['DATA'], source_repository='alpha')
        importer = TaskImporter(self.identity.reader, self.receiver.ledger,
            snapshot=self.capture, source_repository='alpha')
        admitted = await self.admitted_import(payload)
        publish = self.receiver.ledger._js.publish
        async def publish_then_lose_reply(*args, **kwargs):
            await publish(*args, **kwargs)
            raise OSError('private fixture lost commit reply')
        with patch.object(self.receiver.ledger._js, 'publish', side_effect=publish_then_lose_reply):
            with self.assertRaisesRegex(Exception, '^owner_commit_uncertain$'):
                await importer.handle(admitted)
        old = self.receiver
        await old.close(timeout=None)
        self.assertTrue(old.done.is_set())
        self.receiver = TaskHost.from_enrolled_host(self.source_connection, **self.task_resources)
        importer = TaskImporter(self.identity.reader, self.receiver.ledger,
            snapshot=self.capture, source_repository='alpha')
        recovered = await importer.handle(await self.admitted_import(payload))
        self.assertTrue(recovered.replayed)
        repeated = await importer.handle(await self.admitted_import(payload))
        self.assertTrue(repeated.replayed)
        self.assertEqual(repeated.record, recovered.record)
        await self.receiver.start()
        inspected = await self.call(self.request('task-inspect'))
        self.assertEqual(inspected.record, recovered.record)
        imported = strict_loads(recovered.record)
        state = imported['state']
        self.assertEqual(state['status'], 'reconciliation_required')
        self.assertIsNone(state['assignmentEpoch'])
        self.assertIsNone(state['reservation'])
        self.assertEqual(state['migration']['payload'], payload)
        self.assertEqual(payload['sourceRecord'], strict_loads(self.capture.task(self.legacy_id)))
        self.assertFalse(imported['effects'] or imported['artifacts'])
        # TLS reserve has a valid current exact reserve grant, but imported
        # unknown reservations cannot become new execution authority.
        await self.call(self.request('task-reserve', operation='reserve-imported'), expect_reply=False)
        denied = await self.identity.ingress.admit(
            self.import_request(payload, grant=ref('task-inspect-grant')), cancellation_ref=ref('import-cancel'))
        self.assertIsNone(denied.envelope)
        self.source.store.db.execute("UPDATE work_items SET title='Changed captured title' WHERE id=?", (self.legacy_id,))
        later = self.source.capture('later.db')
        changed = prepare_task_import(later, self.legacy_id, binding=self.bindings['DATA'], source_repository='alpha')
        changed_importer = TaskImporter(self.identity.reader, self.receiver.ledger,
            snapshot=later, source_repository='alpha')
        with self.assertRaisesRegex(Exception, '^owner_operation_conflict$'):
            await changed_importer.handle(await self.admitted_import(changed))
        info = await self.source_connection.jetstream().stream_info('DATA')
        self.assertEqual(info.state.messages, 1)
        self.assertEqual(info.state.last_seq, 1)
        final = await self.receiver.ledger.current()
        self.assertEqual(final.latest.record, recovered.record)
        if self._testMethodName == 'test_tls_child_import_keeps_parent_and_return_obligation':
            self.assertEqual(payload['sourceRecord']['work']['parent_id'], self.source.parent['id'])
            self.assertIsNotNone(payload['parentTaskId'])
            self.assertIn('stable-return', payload['sourceRecord']['work']['fed_flags'])
            self.assertEqual(payload['sourceRecord']['work']['blocked_reason'], 'awaiting origin grant')
        self.success = True

    async def test_tls_task_inspect_reserve_restart_replay_and_refusals(self):
        await self._run_import()

    async def test_tls_child_import_keeps_parent_and_return_obligation(self):
        await self._run_import()

    async def test_tls_protected_source_refuses_before_any_target_record(self):
        from state_owner.task_migration import TaskImporter, prepare_task_import
        escaped_token = '\\u0067hp_'+'z'*36
        cases = [('body', '-----BEGIN PRIVATE KEY-----\nsynthetic', 'task_import_protected_source'),
            ('result', 'ghp_'+'z'*36, 'task_import_protected_source'),
            ('requirements', '{"nested":["'+escaped_token+'"]}', 'task_import_protected_source'),
            ('body', '{"number":'+'1'*5000+',"value":"'+escaped_token+'"}', 'task_import_protected_source'),
            ('body', '{"'+escaped_token+'":"ordinary"}', 'task_import_protected_source'),
            ('body', '['*980+'0'+']'*980, 'task_import_source_unavailable')]
        for index, (field, value, code) in enumerate(cases):
            with self.subTest(field=field):
                self.source.store.db.execute('UPDATE work_items SET body=NULL,result=NULL,requirements=NULL WHERE id=?',
                    (self.legacy_id,))
                self.source.store.db.execute('UPDATE work_items SET '+field+'=? WHERE id=?', (value, self.legacy_id))
                captured = self.source.capture('protected-'+str(index)+'.db')
                before = captured.task(self.legacy_id)
                payload = prepare_task_import(captured, self.legacy_id,
                    binding=self.bindings['DATA'], source_repository='alpha')
                importer = TaskImporter(self.identity.reader, self.receiver.ledger,
                    snapshot=captured, source_repository='alpha')
                with self.assertRaisesRegex(ContractError, '^'+code+'$'):
                    await importer.handle(await self.admitted_import(payload))
                self.assertEqual(captured.task(self.legacy_id), before)
                self.assertEqual(strict_loads(before)['work'][field], value)
                info = await self.source_connection.jetstream().stream_info('DATA')
                self.assertEqual(info.state.messages, 0)
                self.assertEqual(info.state.last_seq, 0)
        self.success = True


_TASK_ARTIFACT_SEED = bytes([77])*32


class LiveTaskArtifactTests(LiveTaskTests):
    """Read-only selected artifact custody through the real TLS/JWT owner path."""
    # Reuse the fixture's existing four-stream Object Store capacity option.
    # Actual task contracts and broker policy remain task-specific.
    read_contract = 'capability-artifact-read'
    artifact_bucket = 'CAPABILITY'
    start_task_host = False
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        public = base64.urlsafe_b64encode(bytes(SigningKey(_TASK_ARTIFACT_SEED).verify_key)).decode().rstrip('=')
        state['identities'].append({'ref':ref('task-service'),'kind':'service','status':'active',
            'principalId':'task-service','externalIdentity':None})
        issuer = copy.deepcopy(state['issuers'][0])
        issuer.update(ref=ref('task-issuer'),identityRef=ref('task-service'),instanceId='task-backup-instance',publicKey=public)
        state['issuers'].append(issuer)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('artifact-reader'),identityRef=ref('task-service'),issuerRef=ref('issuer'),publicKey=public)
        state['transports'].append(transport)
        membership = copy.deepcopy(state['memberships'][0])
        membership.update(ref=ref('artifact-reader-member'),identityRef=ref('task-service'))
        state['memberships'].append(membership)
        grant = copy.deepcopy(state['grants'][0])
        grant.update(ref=ref('artifact-reader-grant'),callerRef=ref('task-service'),actorRef=ref('task-service'),
            contractId='task-artifact-backup-read',resourceId=self.task_id)
        state['grants'].append(grant)
        return initial

    async def asyncSetUp(self):
        from state_owner.artifacts import OwnerArtifacts
        await super().asyncSetUp()
        self.provisioner = self.connections[0]
        js = self.provisioner.jetstream()
        store = await js.create_object_store(bucket=self.artifact_bucket,max_bytes=1_048_576)
        self.provisioned_artifacts = OwnerArtifacts(store,js,bucket=self.artifact_bucket,owner_hub_id='hub-one',
            store_ref=ref('task-artifacts'),max_bytes=1024)
        self.artifact_bytes = b'Original retained task artifact'
        self.artifact_ref = await self.provisioned_artifacts.upload(self.artifact_bytes,media_type='text/plain')
        seeded = record('artifact-fixture',version=2,previous=1)
        seeded['operation']['scope'] = copy.deepcopy(self.scope)
        seeded.update(effects=[],artifacts=[self.artifact_ref],state={
            'taskId':self.task_id,'status':'ready','assignmentEpoch':0,'reservation':None,
            'originHubId':'hub-one','taskInputRef':ref('task-input'),'flags':{},'body':'Original task body'})
        ledger = OwnerLedger(js,stream='DATA',subject=self.subjects['DATA'],binding=self.bindings['DATA'],
            retention=self.policy,stream_identity=self.streams['DATA'])
        await ledger.append(seeded,expected_sequence=1)
        self.seeded_record = canonical_bytes(seeded)
        await self.receiver.close(timeout=None)
        source_js = self.source_connection.jetstream()
        source_store = await source_js.object_store(self.artifact_bucket)
        self.selected_artifacts = OwnerArtifacts(source_store,source_js,bucket=self.artifact_bucket,owner_hub_id='hub-one',
            store_ref=ref('task-artifacts'),max_bytes=1024)
        self.task_resources.update(issuer_ref=ref('task-issuer'),signing_seed=_TASK_ARTIFACT_SEED,
            service_identity_ref=ref('task-service'),service_instance_id='task-backup-instance',
            artifacts=self.selected_artifacts,artifact_reader={
                'transport_ref':ref('artifact-reader'),'grant_ref':ref('artifact-reader-grant')})
        self.receiver = TaskHost.from_enrolled_host(self.source_connection,**self.task_resources)

    async def test_tls_artifact_backup_restore_and_permission_denials(self):
        from state_owner.backup import restore_backup
        await self.receiver.start()
        self.receiver.check_health()
        backup = self.task_resources['backup_host']
        entry = backup.latest()
        self.assertEqual(entry.receipt.cursor,2)
        with restore_backup(backup.backup_directory,entry.receipt.manifest_name,expected_digest=entry.receipt.digest,
                key=backup.load_key(entry.key_id),binding=self.bindings['DATA'],stream_identity=self.streams['DATA'],
                history_path=self.directory/'restored-artifact-history.sqlite') as restored:
            self.assertTrue(restored.reconciliation_required)
            self.assertEqual(restored.retrieve(self.artifact_ref),self.artifact_bytes)
            self.assertEqual(restored.history.record(2).record,self.seeded_record)
        for subject in ('$O.CAPABILITY.C.forbidden','$O.CAPABILITY.M.forbidden',
                '$JS.API.STREAM.MSG.GET.IDENTITY','$JS.API.STREAM.INFO.OBJ_OTHER',
                '$JS.API.STREAM.CREATE.OBJ_CAPABILITY','$JS.API.CONSUMER.CREATE.OBJ_CAPABILITY'):
            count = self.errors['storage'].count('permission')
            await self.source_connection.publish(subject,b'{}')
            await self.source_connection.flush(timeout=2)
            await self.wait_permissions('storage',count+1)
        self.success = True

    async def test_tls_current_grant_revocation_during_artifact_read_refuses_backup(self):
        retrieve = self.selected_artifacts.retrieve
        async def read_then_revoke(reference):
            data = await retrieve(reference)
            await self.command('identity-revoke',ref('grant'),{'authorityId':'authority-one',
                'targetRef':ref('artifact-reader-grant')})
            return data
        with patch.object(self.selected_artifacts,'retrieve',side_effect=read_then_revoke):
            with self.assertRaises(ContractError):
                await self.receiver.start()
        self.assertFalse(self.receiver._ready)
        self.assertIsNone(self.task_resources['backup_host'].latest())
        self.assertEqual((await self.receiver.ledger.current()).latest.record,self.seeded_record)
        self.success = True

    async def test_tls_replaced_artifact_refuses_instead_of_omitting_bytes(self):
        key = self.artifact_ref['artifactId']+'.'+self.artifact_ref['version']
        await self.provisioned_artifacts._store.put(key,b'Replaced artifact bytes')
        with self.assertRaises(ContractError):
            await self.receiver.start()
        self.assertFalse(self.receiver._ready)
        self.assertIsNone(self.task_resources['backup_host'].latest())
        self.assertEqual((await self.receiver.ledger.current()).latest.record,self.seeded_record)
        self.success = True

    async def test_tls_missing_maintenance_grant_refuses_before_object_read(self):
        await self.command('identity-revoke',ref('grant'),{'authorityId':'authority-one',
            'targetRef':ref('artifact-reader-grant')})
        with patch.object(self.selected_artifacts,'retrieve',wraps=self.selected_artifacts.retrieve) as retrieve:
            with self.assertRaises(ContractError):
                await self.receiver.start()
            retrieve.assert_not_called()
        self.assertIsNone(self.task_resources['backup_host'].latest())
        self.assertEqual((await self.receiver.ledger.current()).latest.record,self.seeded_record)
        self.success = True



class LiveFederationArchiveTests(LiveTaskTests):
    """Actual five-family archive on the existing private TLS/JWT fixture."""
    seed_ready_task = False
    create_task_host = False
    data_domain = data_kind = 'federation-archive'
    # This existing fixture user has no response grants or command listener.
    # Its name is only a test label; exact archive permissions are set below.
    source_role = 'other-scope'
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None

    async def connect(self, role):
        if role == 'provisioner':
            # The existing startup loop retries this fixed refusal within its
            # original five-second deadline. Do not construct an admitted NATS
            # client while the owned broker is still binding its listener:
            # nats-py can retry internally and retain that initial callback error.
            with (self.directory/'server.private.log').open('rb') as log:
                log.seek(0, 2)
                log.seek(max(0, log.tell()-8192))
                ready = b'Server is ready' in log.read(8192)
            if not ready:
                raise OSError('archive_fixture_broker_not_ready')
        return await super().connect(role)

    def configure_broker_policies(self, policies, reads):
        self.archive_publish = [self.subjects['DATA']] + reads('DATA')
        policies[self.source_role] = {'publish': {'allow': self.archive_publish},
            'subscribe': {'allow': []}}

    def validate_source_credential(self):
        from native_security.nats_credentials import validate
        validate(self.credentials[self.source_role].read_bytes(), account_public_key=self.account_public_key,
            publish_subjects=self.archive_publish,
            subscribe_subjects=[self.inbox_prefixes[self.source_role]+'.>'], private_inbox=True)

    async def asyncSetUp(self):
        from state_owner import test_federation_archive as source_fixture
        self.archive_source_test = source_fixture.FederationSourceTests()
        self.archive_source_test.setUp()
        self.addCleanup(self.archive_source_test.doCleanups)
        self.archive_source = self.archive_source_test.source
        self.import_identity = self.archive_source_test.identity
        self.task_id = self.import_identity['archiveId']
        await super().asyncSetUp()
        self.new_archive_owner()

    def initial_authority(self):
        initial = super().initial_authority()
        grant = copy.deepcopy(initial['state']['grants'][0])
        grant.update(ref=ref('federation-ledger-import-grant'), contractId='federation-ledger-import',
            resourceId=self.task_id)
        initial['state']['grants'].append(grant)
        return initial

    def new_archive_owner(self, source=None):
        from state_owner.federation_archive import FederationArchiveImporter
        self.archive_ledger = OwnerLedger(self.source_connection.jetstream(), stream='DATA',
            subject=self.subjects['DATA'], binding=self.bindings['DATA'], retention=self.policy,
            stream_identity=self.streams['DATA'], require_completion_budget=True)
        self.archive_importer = FederationArchiveImporter(self.identity.reader, self.archive_ledger,
            source=source or self.archive_source)

    async def archive_admitted(self, payload, *, grant='federation-ledger-import-grant'):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': ref(grant),
            'operationId': self.import_identity['operationId'], 'expectedVersion': 0,
            'contractId': 'federation-ledger-import', 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30))}
        admitted = await self.identity.ingress.admit(packet(claims, bytes(reversed(SEED))),
            cancellation_ref=ref('archive-cancel'))
        return admitted

    async def test_tls_complete_archive_lost_reply_recreation_repeat_and_conflict(self):
        from state_owner.federation_archive import (FederationArchiveSource,
            prepare_federation_import, validate_federation_archive, TABLES)
        from hub.fed import ledger as legacy
        binding = self.bindings['DATA']
        payload = prepare_federation_import(self.archive_source, binding=binding)
        admitted = await self.archive_admitted(payload)
        self.assertEqual(admitted.decision.outcome, 'allowed')
        publish = self.archive_ledger._js.publish
        async def lose_reply(*args, **kwargs):
            await publish(*args, **kwargs)
            raise OSError('private fixture lost commit reply')
        with patch.object(self.archive_ledger._js, 'publish', side_effect=lose_reply):
            with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
                await self.archive_importer.handle(admitted.envelope)
        self.new_archive_owner()
        recovered = await self.archive_importer.handle((await self.archive_admitted(payload)).envelope)
        self.assertTrue(recovered.replayed)
        repeated = await self.archive_importer.handle((await self.archive_admitted(payload)).envelope)
        self.assertEqual(recovered.record, repeated.record)
        record = validate_federation_archive(recovered.record, binding, authority_id='authority-one')
        self.assertFalse(record['effects'] or record['artifacts'])
        self.assertEqual(record['state']['status'], 'reconciliation_required')
        self.assertTrue(record['state']['captureComplete'] and record['state']['writerTransferRequired'])
        self.assertEqual(record['state']['payload'], payload)
        store = self.archive_source_test.legacy.store
        for table, (key, _) in TABLES.items():
            family = record['state']['payload']['sourceArchive']['families'][table]
            rows = store.q('SELECT * FROM '+table+' ORDER BY '+key+' COLLATE BINARY')
            self.assertEqual(family['count'], len(rows))
            self.assertEqual([member['row'] for member in family['rows']], rows)
        self.assertEqual(store.q1("SELECT sent FROM fed_outbox WHERE msg_id='withdrawn'")['sent'], 'withdrawn')
        denied = await self.archive_admitted(payload, grant='task-inspect-grant')
        self.assertIsNone(denied.envelope)
        legacy.state_set(store, 'positions', {'old-peer': 43})
        later = FederationArchiveSource(self.archive_source_test.legacy.capture('later.db'),
            source_owner_organization_id='org-one')
        changed = prepare_federation_import(later, binding=binding)
        self.new_archive_owner(later)
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.archive_importer.handle((await self.archive_admitted(changed)).envelope)
        info = await self.source_connection.jetstream().stream_info('DATA')
        self.assertEqual((info.state.messages, info.state.last_seq), (1, 1))
        for subject in ('$JS.API.STREAM.MSG.GET.IDENTITY', '$JS.API.STREAM.MSG.GET.OTHER',
                '$JS.API.STREAM.CREATE.DATA', 'am.work.v3'):
            count = self.errors[self.source_role].count('permission')
            await self.source_connection.publish(subject, b'{}')
            await self.source_connection.flush(timeout=2)
            await self.wait_permissions(self.source_role, count+1)
        self.assertFalse([error for errors in self.errors.values() for error in errors if error != 'permission'])
        self.success = True

    async def test_tls_current_revocation_and_changed_source_refuse_empty_target(self):
        from state_owner.federation_archive import prepare_federation_import
        payload = prepare_federation_import(self.archive_source, binding=self.bindings['DATA'])
        changed = copy.deepcopy(payload)
        changed['captureDigest'] = 'sha256:'+'0'*64
        with self.assertRaisesRegex(ContractError, '^federation_archive_binding_mismatch$'):
            await self.archive_importer.handle((await self.archive_admitted(changed)).envelope)
        admitted = await self.archive_admitted(payload)
        await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one',
            'targetRef': ref('federation-ledger-import-grant')})
        with patch.object(self.archive_source, 'read', wraps=self.archive_source.read) as read:
            with self.assertRaisesRegex(ContractError, '^federation_archive_access_refused$'):
                await self.archive_importer.handle(admitted.envelope)
            read.assert_not_called()
        info = await self.source_connection.jetstream().stream_info('DATA')
        self.assertEqual((info.state.messages, info.state.last_seq), (0, 0))
        self.success = True

    async def test_tls_protected_and_oversize_capture_refuse_without_partial_archive(self):
        from state_owner.federation_archive import FederationArchiveSource, prepare_federation_import
        from hub.fed import ledger as legacy
        payload = prepare_federation_import(self.archive_source, binding=self.bindings['DATA'])
        admitted = await self.archive_admitted(payload)
        self.assertEqual(admitted.decision.outcome, 'allowed')
        source = self.archive_source_test.legacy
        for index, value in enumerate(('ghp_'+'z'*36, 'x'*70000)):
            legacy.state_set(source.store, 'positions', value)
            capture = source.capture('refused-'+str(index)+'.db')
            path = source.root/('refused-'+str(index)+'.db')
            original = path.read_bytes()
            self.new_archive_owner(FederationArchiveSource(capture, source_owner_organization_id='org-one'))
            with patch.object(self.archive_ledger, 'append', wraps=self.archive_ledger.append) as append:
                with self.assertRaises(ContractError):
                    await self.archive_importer.handle(admitted.envelope)
                append.assert_not_called()
            self.assertEqual(path.read_bytes(), original)
            info = await self.source_connection.jetstream().stream_info('DATA')
            self.assertEqual((info.state.messages, info.state.last_seq), (0, 0))
        self.success = True
