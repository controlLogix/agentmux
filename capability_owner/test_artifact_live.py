"""Native artifact handle through selected, actual task and Object Store owners.

The protected ArtifactReadHost and TaskHost are constructed directly from the
validated selection. Full ApplicationServiceHost startup has separate controlled
composition coverage; this test does not claim installed application supervision.
"""
import asyncio
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
from unittest.mock import patch

import nats
import nkeys
from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity import test_task_selection as selection_fixture
from identity.application_service_selection import ApplicationServiceSelection
from identity.artifact_selection import load_artifact_credentials, load_artifact_signing_seed
from identity.test_authority import ref, SEED
from native_security.nats_credentials import artifact_receiver_policy, service_policy, validate_service
from state_owner.artifacts import OwnerArtifacts
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.history import OwnerHistory
from state_owner.task_host import TaskHost
from state_owner.test_ledger import record as retained_record

from .artifact_host import ArtifactReadHost
from . import test_live as native_fixture


class LiveSelectedArtifactTests(native_fixture.LiveArtifactCapabilityTests):
    def setUp(self):
        # Reuse the existing complete protected-selection fixture. Live source
        # pins below replace only its disposable values, not any validator.
        selection_fixture.TaskSelectionTests.setUp(self)
        self.selected_host = self.task_host = self.task_history = None

    def configure_broker_policies(self, policies, reads):
        for role in ('selected-task', 'selected-artifact'):
            self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
        self.task_policy = service_policy(role='task', hub_id='hub-one',
            entity_id='task-one', scope=self.scope, stream='DATA',
            reply_prefix=self.inbox_prefixes['selected-task'], artifact_bucket='CAPABILITY')
        artifact = artifact_receiver_policy(hub_id='hub-one', scope=self.scope,
            reply_prefix=self.inbox_prefixes['selected-artifact'])
        for role, policy in (('selected-task', self.task_policy), ('selected-artifact', artifact)):
            # The shared builder adds the private inbox once for every role.
            policies[role] = {'publish': {'allow': list(policy.publish_subjects)},
                'subscribe': {'allow': [s for s in policy.subscribe_subjects
                    if s != self.inbox_prefixes[role] + '.>']}}

    def _nsc(self, *arguments):
        command = [os.environ['AGENTMUX_PLUGIN_NSC'],
            '--config-dir', str(self.directory/'nsc-config'),
            '--data-dir', str(self.directory/'nsc-store'),
            '--keystore-dir', str(self.directory/'nsc-keys'), *arguments]
        with (self.directory/'nsc.private.log').open('ab') as log:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=log, timeout=8)
        if result.returncode or len(result.stdout) > 65536:
            self.keep_directory = True
            raise RuntimeError('selected_artifact_fixture_nsc_failed')
        return result.stdout

    def _configure_tls_and_users(self):
        super()._configure_tls_and_users()
        # The shared fixture assigns response permissions only to its original
        # roles. These extra roles use the production exact response budgets.
        for role, ttl in (('selected-task', '8s'), ('selected-artifact', '5s')):
            self._nsc('edit', 'user', '-a', 'CAPABILITY', '-n', role,
                '--allow-pub-response', '1', '--response-ttl', ttl)
            self.credentials[role].write_bytes(
                self._nsc('generate', 'creds', '-a', 'CAPABILITY', '-n', role))
        # nsc omits an empty allow list. Preserve the production closed JSON
        # shape and sign it with this fixture's actual enrolled account key.
        path = self.credentials['selected-artifact']
        raw = path.read_bytes()
        token = raw.splitlines()[1]
        header, body, _ = token.split(b'.')
        claims = strict_loads(base64.urlsafe_b64decode(body + b'=' * (-len(body) % 4)))
        claims['nats']['pub'] = {'allow': []}
        claims.pop('jti', None)
        matches = list((self.directory/'nsc-keys').rglob(self.account_public_key+'.nk'))
        if len(matches) != 1:
            raise RuntimeError('selected_artifact_fixture_account_key_unavailable')
        key = nkeys.from_seed(matches[0].read_bytes().strip())
        try:
            self.assertEqual(key.public_key.decode(), self.account_public_key)
            body = base64.urlsafe_b64encode(json.dumps(claims, separators=(',', ':')).encode()).rstrip(b'=')
            signed = header+b'.'+body
            updated = signed+b'.'+base64.urlsafe_b64encode(key.sign(signed)).rstrip(b'=')
            path.write_bytes(raw.replace(token, updated, 1))
        finally:
            key.wipe()

    def _initial_authority(self, original):
        initial, envelope = original()
        state = initial['state']
        selected = self.value['task']
        state['identities'].append({'ref': ref('task-service'), 'kind': 'service',
            'status': 'active', 'principalId': 'task-service', 'externalIdentity': None})
        issuer = copy.deepcopy(state['issuers'][0])
        issuer.update(ref=selected['issuer']['issuerRef'], identityRef=ref('task-service'),
            instanceId=selected['serviceInstanceId'], publicKey=selected['issuer']['publicKey'])
        state['issuers'].append(issuer)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('artifact-reader'), identityRef=ref('task-service'),
            issuerRef=ref('issuer'), publicKey=selected['issuer']['publicKey'])
        state['transports'].append(transport)
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('artifact-reader-member'), identityRef=ref('task-service'))
        state['memberships'].append(member)
        grant = copy.deepcopy(state['grants'][0])
        grant.update(ref=ref('artifact-reader-grant'), callerRef=ref('task-service'),
            actorRef=ref('task-service'), contractId='task-artifact-backup-read', resourceId='task-one')
        state['grants'].append(grant)
        return initial, envelope

    @staticmethod
    def _task_record(*args, **kwargs):
        value = retained_record(*args, **kwargs)
        value.update(effects=[], state={'taskId': 'task-one', 'status': 'ready',
            'assignmentEpoch': 0, 'reservation': None, 'originHubId': 'hub-one',
            'taskInputRef': ref('task-input'), 'flags': {}, 'body': 'Original retained task body'})
        return value

    def _key(self, role, service_id, issuer_ref, seed):
        path = self.root/(role+'-live.key')
        raw = canonical_bytes({'schemaVersion': '1.0.0',
            'purpose': 'agentmux-application-service-key-v1', 'serviceId': service_id,
            'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
            'issuerRef': issuer_ref, 'seed': base64.b64encode(seed).decode()})
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'keyFile': {'path': str(path), 'sha256': 'sha256:'+hashlib.sha256(raw).hexdigest()},
            'issuerRef': issuer_ref,
            'publicKey': base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')}

    def _credentials(self, role, *, artifact=False):
        raw = self.credentials[role].read_bytes()
        if artifact:
            from native_security.nats_credentials import validate_artifact_receiver
            credential = validate_artifact_receiver(raw, account_public_key=self.account_public_key,
                hub_id='hub-one', scope=self.scope, reply_prefix=self.inbox_prefixes[role])
        else:
            inputs = dict(role='identity' if role == 'identity' else 'task', hub_id='hub-one',
                entity_id='authority-one' if role == 'identity' else 'task-one', scope=self.scope,
                stream='IDENTITY' if role == 'identity' else 'DATA', reply_prefix=self.inbox_prefixes[role])
            if role != 'identity':
                inputs['artifact_bucket'] = 'CAPABILITY'
            credential = validate_service(raw, account_public_key=self.account_public_key, **inputs)
        return {'path': str(self.credentials[role]), 'sha256': 'sha256:'+hashlib.sha256(raw).hexdigest(),
            'accountPublicKey': self.account_public_key, 'userPublicKey': credential.public_key,
            'replyPrefix': self.inbox_prefixes[role]}

    async def asyncSetUp(self):
        original = native_fixture.command_fixture
        with patch.object(native_fixture, 'command_fixture', side_effect=lambda: self._initial_authority(original)), \
                patch.object(native_fixture, 'record', side_effect=self._task_record):
            await super().asyncSetUp()
        # Replace the provisional receiver before publishing the Go readiness
        # handoff. No native read has been released to that provisional route.
        await self.receiver.close()
        admin = self.connections[0]
        identity_ledger = self.identity.ledger
        identity_history = identity_ledger._history
        identity = self.value['identity']
        identity['issuer'] = self._key('identity', 'identity-owner', ref('issuer'), SEED)
        identity['ledger'].update(stream='IDENTITY', scope=copy.deepcopy(self.scope),
            streamIdentity={'created': native_fixture.stamp(identity_ledger._identity.created),
                'minimumSequence': identity_ledger._identity.minimum_sequence},
            retention={'maxBytes': self.policy.max_bytes, 'reserveBytes': self.policy.reserve_bytes, 'replicas': 1},
            history={'path': str(identity_history._path), 'maxRecords': identity_history._max_records,
                'maxBytes': identity_history._max_bytes})
        connection = {'endpoint': self.broker.url, 'serverName': self.server_name,
            'rootsPEM': self.ca_file.read_text(), 'leafCertificateSHA256': self.leaf_digest,
            'jetstreamDomain': None}
        identity['connection'] = copy.deepcopy(connection)
        identity['credentials'] = self._credentials('identity')
        task = self.value['task']
        info = await admin.jetstream().stream_info('DATA')
        task['connection'] = copy.deepcopy(connection)
        task['credentials'] = self._credentials('selected-task')
        task['requesterReplyPrefix'] = self.inbox_prefixes['host']
        task['ledger'].update(stream='DATA', scope=copy.deepcopy(self.scope),
            streamIdentity={'created': native_fixture.stamp(info.created), 'minimumSequence': 0},
            retention={'maxBytes': self.policy.max_bytes, 'reserveBytes': self.policy.reserve_bytes, 'replicas': 1})
        task['artifacts'] = {'bucket': 'CAPABILITY', 'storeRef': ref('artifact-store'), 'maxBytes': 45000,
            'reader': {'transportRef': ref('artifact-reader'), 'grantRef': ref('artifact-reader-grant')}}
        self.value['artifact'] = {'resourceRef': ref('task-one'), 'receiver': {
            'connection': connection, 'credentials': self._credentials('selected-artifact', artifact=True),
            'issuer': self._key('artifact', 'artifact-owner', ref('storage-signer'), self.service_seed),
            'serviceIdentityRef': ref('storage-service'), 'serviceInstanceId': 'storage-one',
            'requestSigningKeyRef': ref('issuer')}}
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        self.selection.check_storage_identity_source(self.identity)
        selected = self.selection.service('task')
        task_connection = await self.connect('selected-task')
        self.task_connection = task_connection
        js = task_connection.jetstream()
        artifacts = OwnerArtifacts(await js.object_store('CAPABILITY'), js, bucket='CAPABILITY',
            owner_hub_id='hub-one', store_ref=ref('artifact-store'), max_bytes=45000)
        binding, epoch = self.selection.binding('task'), self.selection.stream_identity('task')
        history = self.task_history = OwnerHistory(selected['ledger']['history']['path'], binding,
            stream_identity=epoch)
        backup = selected['backup']
        backup_host = BackupHost(*(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=binding, stream_identity=epoch)
        backup_host.enroll_key(backup['keyId'])
        pin = selected['ledger']['checkpoint']
        checkpoint = CheckpointHost(pin['path'], stream='DATA', commit_ref=pin['commitRef'],
            binding=binding, stream_identity=epoch)
        self.task_host = TaskHost.from_enrolled_host(task_connection,
            **self.selection.task_kwargs(authority=self.identity.reader, ingress=self.identity.ingress,
                history=history, signing_seed=self.selection.load_signing_seed('task'),
                checkpoint_host=checkpoint, backup_host=backup_host, artifacts=artifacts))
        await self.task_host.start()
        self.task_host.check_health()
        load_artifact_credentials(self.selection)
        self.selected_host = ArtifactReadHost(self.selection, identity=self.identity, task=self.task_host,
            connection=await self.connect('selected-artifact'),
            signing_seed=load_artifact_signing_seed(self.selection))
        await self.selected_host.start()
        self.receiver = self.selected_host._service
        self.assertIs(self.selected_host._resource.ledger, self.task_host.ledger)
        self.assertIs(self.selected_host._resource.artifacts, self.task_host._artifact_custody._artifacts)

    async def test_tls_retained_read_current_authority_and_isolation(self):
        # An empty explicit publish list with response permission must mean
        # reply-only on the real broker, not its unrestricted default.
        for subject in (self.subjects['DATA'], '$JS.API.STREAM.MSG.GET.DATA'):
            before = self.errors['selected-artifact'].count('permission')
            await self.receiver._connection.publish(subject, b'{}')
            await self.receiver._connection.flush(timeout=2)
            await self.wait_permissions('selected-artifact', before+1)
            self.assertEqual(self.errors['selected-artifact'].count('permission'), before+1)
        await self.assert_read_path_refusal()
        for change in (
                lambda c: c.update(scope={'organizationId': 'other-org', 'projectId': None, 'workspaceId': None}),
                lambda c: c.update(owner={**self.row['owner'], 'generation': 2}),
                lambda c: c.update(owner={**self.row['owner'], 'instanceId': 'unbound-caller'}),
                lambda c: c.update(resourceRef=ref('task-other'))):
            await self.read(change=change, expect_reply=False)
        await self.read(resource={**ref('task-one'), 'revision': 2}, expect_reply=False)
        # The prepared Go ArtifactHandle now reaches the selected ArtifactReadHost
        # and actual retained TaskHost/Object Store. Its private parent is revoked
        # between reads, including a signed reply withheld after final admission.
        await self.run_go_read_and_revocation()
        self.assertEqual((await self.task_host.ledger.current()).latest.record, self.original)
        self.assertEqual((await self.connections[0].jetstream().stream_info('DATA')).state.messages, 1)
        self.assertEqual(await self.task_host._artifact_custody._artifacts.retrieve(self.artifact_ref), self.content_bytes)
        await self._joined_read_cleanup()
        await self.task_host.close(timeout=None)
        with self.assertRaises(ContractError):
            self.selected_host._resource.check_current()
        self.success = True

    async def _joined_read_cleanup(self):
        entered, release = asyncio.Event(), asyncio.Event()
        artifacts = self.selected_host._resource.artifacts
        original = artifacts.retrieve
        async def held(reference):
            entered.set()
            await release.wait()
            return await original(reference)
        closing = None
        try:
            with patch.object(artifacts, 'retrieve', side_effect=held):
                read = asyncio.create_task(self.receiver._receiver._artifact_read(
                    self.selected_host._resource, self.artifact_ref))
                await asyncio.wait_for(entered.wait(), 2)
                read.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await read
                closing = asyncio.create_task(self.selected_host.close(timeout=None))
                await asyncio.sleep(.03)
                self.assertFalse(closing.done())
                self.assertFalse(self.task_host._closed)
                self.assertTrue(self.task_connection.is_connected)
                release.set()
                await closing
            self.assertFalse(self.receiver._receiver._workers)
        finally:
            release.set()
            if closing is not None:
                await closing

    async def cleanup_owned(self):
        # Join the original native child before releasing any selected owner.
        if self.go_wait is not None and not self.go_wait.done():
            self.keep_directory = True
            self.go_process.terminate()
            try:
                await asyncio.wait_for(asyncio.shield(self.go_wait), 3)
            except TimeoutError:
                self.go_process.kill()
                await asyncio.wait_for(asyncio.shield(self.go_wait), 3)
        if self.go_wait is not None:
            if await self.go_wait:
                self.keep_directory = True
        if self.go_output is not None:
            self.go_output.close()
        if self.selected_host is not None:
            await self.selected_host.close(timeout=None)
        if self.task_host is not None:
            await self.task_host.close(timeout=None)
        if self.task_history is not None:
            self.task_history.close()
        await super().cleanup_owned()
