"""Signed policy transitions with real owners and controlled Object Store I/O.

These tests exercise real ledger, encryption, history and backup code. The local
broker controls do not qualify broker durability or access controls.
"""
import asyncio
import base64
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.ingress import EnrolledIngress
from identity.test_authority import ref, SEED, NOW
from identity.test_native_bridge import native_row
from identity.test_service import _Clock
from . import test_artifacts as artifact_support
from . import test_configuration as support
from .artifacts import OwnerArtifacts
from .backup import export_backup, restore_backup
from .conversation_migration import ConversationKey
from .federation_policy import (FEDERATION_POLICY_SCHEMA, SCHEMA_REF, MAX_POLICY_BYTES,
    FederationPolicyTarget, FederationPolicyCustody, FederationPolicyOwner, _digest)
from .history import OwnerHistory
from .ledger import StoredRecord, StreamIdentity
from .test_ledger import CREATED


class _Objects(artifact_support.Store):
    """Keep each immutable version in the existing Object Store test control."""
    def __init__(self):
        self.values = {}
        self.puts = 0
        self._name = 'bucket'

    async def put(self, key, data, meta):
        await super().put(key, data, meta)
        self.values[key] = (self.data, self.info)
        self.puts += 1

    async def get_info(self, key):
        self.data, self.info = self.values[key]
        return self.info


class _ObjectJS(artifact_support.JS):
    async def stream_info(self, stream):
        from types import SimpleNamespace
        from nats.js.api import StreamConfig, StorageType, RetentionPolicy, DiscardPolicy
        self.config = getattr(self, 'config', StreamConfig(name='OBJ_bucket',
            subjects=['$O.bucket.C.>', '$O.bucket.M.>'], storage=StorageType.FILE,
            retention=RetentionPolicy.LIMITS, discard=DiscardPolicy.NEW,
            max_bytes=1_048_576, max_age=0, max_msgs=-1, max_msgs_per_subject=-1))
        return SimpleNamespace(config=self.config, created=CREATED)

    async def get_msg(self, stream, *, seq, subject, next, direct):
        # Each immutable fixture subject gets a separate chunk identity, as the
        # actual Object Store does. Never share a mutable last-read payload.
        nuid = subject.removeprefix('$O.bucket.C.')
        data, info = [value for value in self.store.values.values() if value[1].nuid == nuid][0]
        from types import SimpleNamespace
        return SimpleNamespace(data=data, seq=seq, subject=subject)


class FederationPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = support.ConfigurationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        await self.fixture.source.close()
        for name in ('state_owner.federation_policy.datetime', 'identity.ingress.datetime'):
            patch(name, _Clock).start()
        self.record, self.ledger = self.fixture.record, self.fixture.ledger
        self.fixture.owner['instanceId'] = 'federation-policy-one'
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.old = b'[federation]\npeer="nick"\n[repos.falcon]\nremote="example.invalid/falcon"\n[peers.alice]\ntrust="auto"\n'
        self.desired = self.old.replace(b'"auto"', b'"flag"')
        self.target = FederationPolicyTarget.selected(self.ledger._binding,
            source_ref=ref('selected-federation-policy'),
            source={'database': {'path': str(self.root/'hub.db'), 'applicationId': 1, 'userVersion': 1},
                'policy': {'path': str(self.root/'federation.toml'), 'sha256': _digest(self.old)}},
            repository={'localName': 'falcon', 'repositoryId': 'falcon-rid',
                'normalizedRemote': 'example.invalid/falcon'}, local_peer='nick')
        path = self.root/'policy.key'
        path.write_bytes(bytes(range(32)))
        path.chmod(0o600)
        self.key = ConversationKey(path, key_ref=ref('policy-key'))
        self.addCleanup(self.key.close)
        self.store = _Objects()
        self.object_js = _ObjectJS(self.store)
        self.object_js._nc = self.fixture.connection
        self.object_js._prefix = '$JS.API'
        self.fixture.js._nc = self.fixture.connection
        self.fixture.js._prefix = '$JS.API'
        self.store._js = self.object_js
        original_put = self.store.put
        async def put(key, data, meta):
            await original_put(key, data, meta)
            self.store.info.nuid = key.replace('.', '_')
        self.store.put = put
        self.artifacts = OwnerArtifacts(self.store, self.object_js, bucket='bucket', owner_hub_id='hub-one',
            store_ref=ref('policy-artifacts'), max_bytes=MAX_POLICY_BYTES+40)
        self.ingress = EnrolledIngress(self.fixture.authority, issuer_ref=ref('issuer'), signing_seed=SEED)
        self.backup_grant = copy.deepcopy(self.record['state']['grants'][-2])
        self.backup_grant.update(ref=ref('policy-backup'), callerRef=ref('service'), actorRef=ref('service'),
            contractId='configuration-read', resourceId=self.ledger._binding.entity_id)
        self.record['state']['grants'].append(self.backup_grant)
        transport = copy.deepcopy(self.record['state']['transports'][0])
        transport.update(ref=ref('policy-reader'), identityRef=ref('service'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='))
        self.record['state']['transports'].append(transport)
        self.record['state']['memberships'].append(dict(self.record['state']['memberships'][0],
            ref=ref('policy-service-member'), identityRef=ref('service')))
        self.owner = self.make_owner()
        self.addAsyncCleanup(self.owner.close, timeout=None)

    def make_owner(self):
        custody = FederationPolicyCustody(self.target, self.artifacts, self.key, ingress=self.ingress,
            backup_transport_ref=ref('policy-reader'), backup_grant_ref=ref('policy-backup'))
        return FederationPolicyOwner(self.fixture.authority, self.ledger, policy_custody=custody,
            owner=self.fixture.owner, schema_ref=SCHEMA_REF,
            schema_resources={SCHEMA_REF: FEDERATION_POLICY_SCHEMA}, issuer_ref=ref('issuer'),
            signing_seed=SEED, connection=self.fixture.connection, require_native_activation=False)

    def request(self, document=None, *, method='set', revision=0, operation='policy-one'):
        raw = self.fixture.request(method, revision=revision,
            value=b'{"private":1}' if document is None else document)
        envelope = strict_loads(raw)
        if method == 'set':
            envelope['payload'].update(schemaRef=SCHEMA_REF, secretReferences=[ref('policy-key')])
        envelope['operation'].update(operationId=operation, taskId=None, runId=None, attemptId=None,
            delegationRef=None, payloadDigest=payload_digest(envelope['payload']))
        claims = envelope['ingressAttestation']['claims']
        claims['operation'] = copy.deepcopy(envelope['operation'])
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    async def prepared(self, *, desired=None, revision=0, old=None, operation='policy-one'):
        old = self.old if old is None else old
        desired = self.desired if desired is None else desired
        proposal = self.owner.preparation_bytes(previous_revision=revision,
            old_policy=old, desired_policy=desired,
            change={'verb': 'trust', 'arguments': {'peer': 'alice', 'level': 'flag'}})
        raw = self.request(proposal, revision=revision, operation=operation)
        document = await self.owner.prepare(raw, old_policy=old, desired_policy=desired)
        return self.request(document, revision=revision, operation=operation), document

    async def committed(self, **changes):
        request, document = await self.prepared(**changes)
        await self.owner.handle(request)
        return request, document

    async def resolve(self, request, *, owner=None):
        operation = strict_loads(request)['operation']
        return await (owner or self.owner).reconcile(self.request(method='read', revision=1, operation='read-policy'),
            operation_id=operation['operationId'], payload_digest=operation['payloadDigest'])

    async def test_boundary_size_retained_atomic_reference_replay_and_restart(self):
        large = self.desired+b'\n#'+b'x'*(MAX_POLICY_BYTES-len(self.desired)-2)
        self.assertEqual(len(large), MAX_POLICY_BYTES)
        raw, document = await self.committed(desired=large)
        self.assertLessEqual(len(document), 16384)
        record = strict_loads(self.fixture.js.messages[0].data)
        value = strict_loads(document)
        self.assertEqual(record['artifacts'], [value['oldPolicy']['artifactRef'], value['desiredPolicy']['artifactRef']])
        self.assertEqual(record['operation'], strict_loads(raw)['operation'])
        self.assertEqual(record['outcome'], 'committed')
        self.assertEqual((await self.resolve(raw)).policy_bytes, large)
        await self.owner.handle(raw)
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(self.store.puts, 2)
        await self.owner.close(timeout=None)
        replacement = self.make_owner()
        self.addAsyncCleanup(replacement.close, timeout=None)
        self.assertEqual((await self.resolve(raw, owner=replacement)).policy_bytes, large)
        recovered = await replacement.read_current(self.request(method='read', revision=1, operation='restart-read'))
        self.assertEqual(recovered.policy_bytes, large)
        self.assertEqual((recovered.operation_id, recovered.payload_digest),
            (strict_loads(raw)['operation']['operationId'], strict_loads(raw)['operation']['payloadDigest']))
        await replacement.handle(raw)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_upload_is_not_commit_and_unapproved_reference_cannot_change_owner(self):
        request, document = await self.prepared()
        self.assertEqual(self.fixture.js.messages, [])
        with self.assertRaises(ContractError):
            await self.resolve(request)
        envelope = strict_loads(request)
        altered = strict_loads(document)
        altered['target']['selectionDigest'] = 'sha256:'+'0'*64
        changed = self.request(canonical_bytes(altered))
        with self.assertRaisesRegex(ContractError, '^federation_policy_binding$'):
            await self.owner.handle(changed)
        self.assertEqual(self.fixture.js.messages, [])

    async def test_oversize_refuses_before_upload_and_generic_limit_is_unchanged(self):
        with self.assertRaisesRegex(ContractError, '^federation_policy_size$'):
            await self.prepared(desired=b'#'+b'x'*MAX_POLICY_BYTES)
        self.assertEqual(self.store.puts, 0)
        ordinary = self.fixture.new_source()
        self.addAsyncCleanup(ordinary.close)
        with self.assertRaisesRegex(ContractError, '^configuration_unavailable$'):
            await ordinary.prepare_initialization(owner=self.fixture.owner,
                configuration_bytes=b' '*16385, secret_references=[])
        await ordinary.handle(self.fixture.request('set'))
        self.assertEqual(strict_loads(self.fixture.js.messages[0].data)['artifacts'], [])
        # Even a well-formed artifact cannot be smuggled into ordinary history.
        reference = await self.artifacts.upload(b'x', media_type='text/plain')
        record = strict_loads(self.fixture.js.messages[0].data)
        record['artifacts'] = [reference]
        self.fixture.js.messages[0].data = canonical_bytes(record)
        with self.assertRaisesRegex(ContractError, '^configuration_history_invalid$'):
            await ordinary.handle(self.fixture.request())

    async def test_lost_ack_and_retained_artifact_substitution(self):
        raw, document = await self.prepared()
        self.fixture.js.lose_ack = True
        await self.owner.handle(raw)
        await self.owner.handle(raw)
        self.assertEqual(len(self.fixture.js.messages), 1)
        record = strict_loads(self.fixture.js.messages[0].data)
        record['artifacts'].reverse()
        self.fixture.js.messages[0].data = canonical_bytes(record)
        with self.assertRaisesRegex(ContractError, '^configuration_history_invalid$'):
            await self.resolve(raw)

    async def test_revoked_set_grant_refuses_before_upload(self):
        next(g for g in self.record['state']['grants'] if g['ref'] == ref('configuration-set'))['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
            await self.prepared()
        self.assertEqual(self.store.puts, 0)

    async def test_native_slot_overlap_before_preparation_and_during_commit_refuses(self):
        row = native_row()
        row['owner'] = copy.deepcopy(self.fixture.owner)
        row['status'] = 'stopped'
        self.record['state']['nativeInstances'] = [row]
        with self.assertRaises(ContractError):
            await self.prepared()
        self.assertEqual(self.store.puts, 0)
        self.record['state'].pop('nativeInstances')
        raw, _ = await self.prepared()
        original = self.artifacts.retrieve
        async def overlap(reference):
            result = await original(reference)
            self.record['state']['nativeInstances'] = [row]
            return result
        with patch.object(self.artifacts, 'retrieve', side_effect=overlap):
            with self.assertRaises(ContractError):
                await self.owner.handle(raw)
        self.assertEqual(self.fixture.js.messages, [])

    async def test_cancelled_preparation_keeps_original_upload_and_same_result(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.artifacts.upload
        async def blocked(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original(*args, **kwargs)
        proposal = self.owner.preparation_bytes(previous_revision=0, old_policy=self.old,
            desired_policy=self.desired, change={'verb':'trust','arguments':{'peer':'alice','level':'flag'}})
        raw = self.request(proposal)
        with patch.object(self.artifacts, 'upload', side_effect=blocked):
            waiter = asyncio.create_task(self.owner.prepare(raw, old_policy=self.old, desired_policy=self.desired))
            await asyncio.wait_for(entered.wait(), 2)
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            original_task, = self.owner._preparations.values()
            self.assertFalse(original_task.done())
            self.assertTrue(self.owner.custody._pending)
            release.set()
            result = await self.owner.prepare(raw, old_policy=self.old, desired_policy=self.desired)
        self.assertEqual(result, original_task.result())
        self.assertEqual(self.store.puts, 2)
        self.assertFalse(self.owner.custody._pending)

    async def test_history_backup_restores_every_referenced_policy(self):
        raw, document = await self.committed()
        second, second_doc = await self.committed(old=self.desired,
            desired=self.desired.replace(b'"flag"', b'"deny"'), revision=1, operation='policy-two')
        with self.assertRaisesRegex(ContractError, '^federation_policy_stale$'):
            await self.resolve(raw)
        history = OwnerHistory(self.root/'history.sqlite', self.ledger._binding,
            stream_identity=StreamIdentity(CREATED, 0))
        self.addCleanup(history.close)
        for message in self.fixture.js.messages:
            history.verify_source(StoredRecord(message.data, message.seq))
        destination = self.root/'backup'
        destination.mkdir(mode=0o700)
        receipt = await export_backup(destination, history, self.ledger._binding, StreamIdentity(CREATED, 0),
            key=b'b'*32, retrieve_artifact=self.owner.custody.retrieve_backup)
        with restore_backup(destination, receipt.manifest_name, expected_digest=receipt.digest,
                key=b'b'*32, binding=self.ledger._binding, stream_identity=StreamIdentity(CREATED, 0),
                history_path=self.root/'restored.sqlite') as restored:
            self.assertTrue(restored.reconciliation_required)
            self.assertEqual(restored.cursor, 2)
            for content in (document, second_doc):
                for field in ('oldPolicy', 'desiredPolicy'):
                    reference = strict_loads(content)[field]['artifactRef']
                    self.assertEqual(restored.retrieve(reference), await self.artifacts.retrieve(reference))

    async def test_backup_revocation_after_storage_read_refuses_bytes(self):
        _, document = await self.committed()
        reference = strict_loads(document)['desiredPolicy']['artifactRef']
        original = self.artifacts.retrieve
        async def revoke(reference):
            result = await original(reference)
            self.backup_grant['status'] = 'revoked'
            return result
        with patch.object(self.artifacts, 'retrieve', side_effect=revoke):
            with self.assertRaises(ContractError):
                await self.owner.custody.retrieve_backup(reference)

    async def test_read_revocation_during_blob_read_refuses_disclosure(self):
        raw, _ = await self.committed()
        original = self.artifacts.retrieve
        grant = next(g for g in self.record['state']['grants'] if g['ref'] == ref('configuration-read'))
        async def revoke(reference):
            result = await original(reference)
            grant['status'] = 'revoked'
            return result
        with patch.object(self.artifacts, 'retrieve', side_effect=revoke):
            with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
                await self.resolve(raw)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_native_slot_overlap_refuses_recovery_and_backup_before_blob_io(self):
        raw, document = await self.committed()
        row = native_row()
        row['owner'] = copy.deepcopy(self.fixture.owner)
        row['status'] = 'stopped'
        self.record['state']['nativeInstances'] = [row]
        with patch.object(self.artifacts, 'retrieve', wraps=self.artifacts.retrieve) as retrieve:
            with self.assertRaises(ContractError):
                await self.resolve(raw)
            with self.assertRaises(ContractError):
                await self.owner.custody.retrieve_backup(strict_loads(document)['desiredPolicy']['artifactRef'])
            retrieve.assert_not_called()

    async def test_expiring_or_evicting_store_refuses_without_losing_retained_references(self):
        raw, _ = await self.committed()
        from nats.js.api import DiscardPolicy
        for change in ({'max_age':60}, {'discard':DiscardPolicy.OLD}, {'max_msgs':1}, {'allow_msg_ttl':True}):
            config = self.object_js.config
            previous = {key:getattr(config, key) for key in change}
            for key, value in change.items():
                setattr(config, key, value)
            try:
                with self.assertRaisesRegex(ContractError, '^federation_policy_retention_invalid$'):
                    await self.resolve(raw)
            finally:
                for key, value in previous.items():
                    setattr(config, key, value)
        self.assertEqual((await self.resolve(raw)).policy_bytes, self.desired)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_tampered_or_missing_blob_never_returns_old_policy(self):
        raw, document = await self.committed()
        reference = strict_loads(document)['desiredPolicy']['artifactRef']
        key = reference['artifactId']+'.'+reference['version']
        original, info = self.store.values[key]
        self.store.values[key] = (b'tampered', info)
        with self.assertRaises(ContractError):
            await self.resolve(raw)
        self.store.values.pop(key)
        with self.assertRaises(ContractError):
            await self.resolve(raw)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_selected_configuration_host_keeps_policy_backup_and_event_ownership(self):
        from types import SimpleNamespace
        from identity.authority import LedgerAuthorityReader
        from . import test_configuration_activation as event_support
        from .backup_host import BackupHost
        from .checkpoint_host import CheckpointHost
        from .configuration_host import ConfigurationHost
        from .ledger import OwnerBinding, OwnerLedger, owner_subject
        from .test_ledger import FakeJetStream

        await self.owner.close(timeout=None)
        patch('identity.configuration_events.datetime', _Clock).start()
        scope = strict_loads(self.ledger._binding.scope)
        event_support.enroll_event_producer(self.record['state'], scope)
        authority_scope = dict(scope, projectId=None, workspaceId=None)
        authority_binding = OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority',
            canonical_bytes(authority_scope))
        authority_record = copy.deepcopy(self.record)
        authority_record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        authority_record['operation'].update(scope=authority_scope, expectedVersion=0)
        authority_js = FakeJetStream(self.fixture.policy)
        authority_js.config.subjects = [owner_subject(authority_binding)]
        authority_js.messages = [SimpleNamespace(subject=owner_subject(authority_binding), seq=1,
            data=canonical_bytes(authority_record))]
        authority_ledger = OwnerLedger(authority_js, stream='OWNER', subject=owner_subject(authority_binding),
            binding=authority_binding, retention=self.fixture.policy, stream_identity=StreamIdentity(CREATED, 1))
        reader = LedgerAuthorityReader(authority_ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        history = OwnerHistory(self.root/'host-history.sqlite', self.ledger._binding,
            stream_identity=StreamIdentity(CREATED, 0))
        self.addCleanup(history.close)
        directories = [self.root/name for name in ('backups', 'inventory', 'backupkeys', 'checkpoints')]
        for path in directories:
            path.mkdir(mode=0o700)
        backup = BackupHost(*directories[:3], destination_id='policy-backup',
            binding=self.ledger._binding, stream_identity=StreamIdentity(CREATED, 0))
        backup.enroll_key('backup-key')
        checkpoint = CheckpointHost(directories[3]/'checkpoint', stream='OWNER',
            commit_ref=ref('policy-checkpoint'), binding=self.ledger._binding,
            stream_identity=StreamIdentity(CREATED, 0))
        connection = self.fixture.connection
        connection.jetstream = lambda: self.fixture.js
        custody = FederationPolicyCustody(self.target, self.artifacts, self.key,
            ingress=EnrolledIngress(reader, issuer_ref=ref('issuer'), signing_seed=SEED),
            backup_transport_ref=ref('policy-reader'), backup_grant_ref=ref('policy-backup'))
        host = ConfigurationHost.from_enrolled_host(connection, authority=reader, stream='OWNER',
            binding=self.ledger._binding, retention=self.fixture.policy, stream_identity=StreamIdentity(CREATED, 0),
            history=history, owner=self.fixture.owner, schema_ref=SCHEMA_REF,
            schema_resources={SCHEMA_REF:FEDERATION_POLICY_SCHEMA}, issuer_ref=ref('issuer'), signing_seed=SEED,
            reply_prefix='_INBOX.configuration', checkpoint_host=checkpoint, backup_host=backup,
            backup_key_id='backup-key', event_producer=event_support.event_producer(reader, scope),
            event_account_public_key='A'*56, federation_policy=custody)
        self.addAsyncCleanup(host.close, timeout=None)
        await host.start()
        self.owner = host.owner
        self.ledger = host.ledger
        raw, document = await self.committed()
        self.assertFalse(host.owner._require_native_activation)
        self.assertTrue(strict_loads((await host.ledger.current()).latest.record)['effects'])
        await host._backup.run_due()
        entry = backup.latest()
        self.assertEqual(entry.receipt.cursor, 1)
        with restore_backup(backup.backup_directory, entry.receipt.manifest_name,
                expected_digest=entry.receipt.digest, key=backup.load_key(entry.key_id),
                binding=self.ledger._binding, stream_identity=StreamIdentity(CREATED, 0),
                history_path=self.root/'host-restored.sqlite') as restored:
            for name in ('oldPolicy', 'desiredPolicy'):
                reference = strict_loads(document)[name]['artifactRef']
                self.assertEqual(restored.retrieve(reference), await self.artifacts.retrieve(reference))
        await host.close(timeout=None)
        self.assertTrue(host.done.is_set())
        self.assertTrue(host.owner.done.is_set())
        self.assertFalse(history._closed)

    async def test_close_timeout_keeps_original_upload_and_key_borrowed(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.artifacts.upload
        async def blocked(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original(*args, **kwargs)
        with patch.object(self.artifacts, 'upload', side_effect=blocked):
            preparation = asyncio.create_task(self.prepared())
            await asyncio.wait_for(entered.wait(), 2)
            try:
                with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                    await self.owner.close(timeout=.01)
                original_close = self.owner._policy_closing
                self.assertFalse(original_close.done())
                self.assertFalse(self.key._closed)
                self.assertTrue(self.owner.custody._pending)
            finally:
                release.set()
                await self.owner.close(timeout=None)
                await asyncio.gather(preparation, return_exceptions=True)
        self.assertIs(self.owner._policy_closing, original_close)
        self.assertTrue(original_close.done())
        self.assertFalse(self.owner.custody._pending)

    def test_dedicated_credential_policy_keeps_bucket_scope_and_generic_refusal(self):
        from identity.federation_policy_selection import (federation_policy_service_policy,
            validate_federation_policy_service)
        from native_security.nats_credentials import CredentialError, service_policy
        from native_security.test_nats_service_credentials import signed_service_policy
        selected = dict(hub_id='hub-one', entity_id='policy-one', scope=strict_loads(self.ledger._binding.scope),
            stream='POLICY', reply_prefix='_INBOX.federation_policy_0001', artifact_bucket='POLICIES',
            jetstream_domain='LOCAL')
        policy = federation_policy_service_policy(**selected)
        raw, account, user = signed_service_policy(policy)
        self.assertEqual(validate_federation_policy_service(raw, account_public_key=account, **selected).public_key, user)
        for subject in ('$JS.API.>', '$O.OTHER.C.*', '$JS.API.STREAM.PURGE.OBJ_POLICIES',
                '$JS.API.CONSUMER.CREATE.OBJ_POLICIES', '$O.POLICIES.>', '_INBOX.>'):
            widened, account, _ = signed_service_policy(policy,
                lambda value, subject=subject: value['pub']['allow'].append(subject))
            with self.assertRaises(CredentialError):
                validate_federation_policy_service(widened, account_public_key=account, **selected)
        with self.assertRaises(CredentialError):
            service_policy(role='configuration', **selected)

    async def test_close_joins_preparation_waiting_in_original_authority_read(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.fixture.authority.current
        async def blocked():
            entered.set()
            await release.wait()
            return await original()
        with patch.object(self.fixture.authority, 'current', side_effect=blocked):
            preparation = asyncio.create_task(self.prepared())
            await asyncio.wait_for(entered.wait(), 2)
            try:
                with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                    await self.owner.close(timeout=.01)
                original_close = self.owner._policy_closing
                self.assertFalse(original_close.done())
                self.assertTrue(self.owner._policy_calls)
                self.assertEqual(self.store.puts, 0)
            finally:
                release.set()
                with self.assertRaises(ContractError):
                    await preparation
                await self.owner.close(timeout=None)
        self.assertIs(self.owner._policy_closing, original_close)
        self.assertFalse(self.owner._policy_calls or self.owner.custody._pending)
        self.assertEqual(self.store.puts, 0)

    async def test_close_joins_reconcile_after_handle_before_next_authority_read(self):
        raw, _ = await self.committed()
        handled, entered, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original_handle, original_current = self.owner.handle, self.fixture.authority.current
        async def handle(request):
            result = await original_handle(request)
            handled.set()
            return result
        async def current():
            if handled.is_set():
                entered.set()
                await release.wait()
            return await original_current()
        with (patch.object(self.owner, 'handle', side_effect=handle),
                patch.object(self.fixture.authority, 'current', side_effect=current),
                patch.object(self.artifacts, 'retrieve', wraps=self.artifacts.retrieve) as retrieve):
            resolving = asyncio.create_task(self.resolve(raw))
            await asyncio.wait_for(entered.wait(), 2)
            try:
                with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                    await self.owner.close(timeout=.01)
                self.assertFalse(self.owner.done.is_set())
                self.assertTrue(self.owner._policy_calls)
                retrieve.assert_not_called()
            finally:
                release.set()
                with self.assertRaises(ContractError):
                    await resolving
                await self.owner.close(timeout=None)
            retrieve.assert_not_called()
        self.assertTrue(self.owner.done.is_set())


from . import test_task_live as live_support


@unittest.skipUnless(os.environ.get('AMX_FEDERATION_POLICY_LIVE') == '1', 'Coordinated policy live slot required')
class LiveFederationPolicyTests(live_support.LiveTaskTests):
    """The existing native TLS fixture with the actual typed configuration host."""
    seed_ready_task = False
    create_task_host = False
    data_domain = data_kind = 'configuration'
    task_id = 'configuration-one'
    broker_stream_limit = 4
    bucket = 'FEDERATION_POLICIES'
    response_ttls = {'storage': '12s'}
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None

    def configure_broker_policies(self, policies, reads):
        from identity.federation_policy_selection import federation_policy_service_policy
        self.selected_policy = dict(hub_id='hub-one', entity_id=self.task_id, scope=self.scope,
            stream='DATA', reply_prefix=self.inbox_prefixes['storage'], artifact_bucket=self.bucket)
        policy = federation_policy_service_policy(**self.selected_policy)
        self.read_subject = policy.command_subject
        policies['storage'] = {'publish': {'allow': list(policy.publish_subjects)},
            'subscribe': {'allow': [subject for subject in policy.subscribe_subjects
                if subject != self.inbox_prefixes['storage']+'.>']}}
        policies['host']['publish']['allow'] = [self.identity_subject, self.read_subject]

    def validate_source_credential(self):
        from identity.federation_policy_selection import validate_federation_policy_service
        validate_federation_policy_service(self.credentials['storage'].read_bytes(),
            account_public_key=self.account_public_key, **self.selected_policy)

    def initial_authority(self):
        from .test_configuration_activation import enroll_event_producer
        initial = super().initial_authority()
        state = initial['state']
        base = copy.deepcopy(state['grants'][0])
        for method in ('read', 'set'):
            grant = copy.deepcopy(base)
            grant.update(ref=ref('policy-'+method), contractId='configuration-'+method, resourceId=self.task_id)
            state['grants'].append(grant)
        grant = copy.deepcopy(base)
        grant.update(ref=ref('policy-backup'), callerRef=ref('service'), actorRef=ref('service'),
            contractId='configuration-read', resourceId=self.task_id)
        state['grants'].append(grant)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('policy-reader'), identityRef=ref('service'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        enroll_event_producer(state, self.scope)
        return initial

    async def asyncSetUp(self):
        from .configuration_host import ConfigurationHost
        from .test_configuration_activation import event_producer
        await super().asyncSetUp()
        await self.connections[0].jetstream().create_object_store(bucket=self.bucket, max_bytes=1_048_576)
        jetstream = self.source_connection.jetstream()
        store = await jetstream.object_store(self.bucket)
        self.artifacts = OwnerArtifacts(store, jetstream, bucket=self.bucket, owner_hub_id='hub-one',
            store_ref=ref('policy-artifacts'), max_bytes=MAX_POLICY_BYTES+40)
        self.old = b'[federation]\npeer="nick"\n[repos.falcon]\nremote="example.invalid/falcon"\n[peers.alice]\ntrust="auto"\n'
        self.desired = self.old.replace(b'"auto"', b'"flag"')
        self.desired += b'\n#'+b'x'*(MAX_POLICY_BYTES-len(self.desired)-2)
        self.owner_pin = native_row()['owner']
        self.owner_pin['instanceId'] = 'federation-policy-one'
        target = FederationPolicyTarget.selected(self.bindings['DATA'], source_ref=ref('selected-policy'),
            source={'database': {'path':str(self.directory/'original.sqlite'), 'applicationId':1, 'userVersion':1},
                'policy':{'path':str(self.directory/'federation.toml'), 'sha256':_digest(self.old)}},
            repository={'localName':'falcon','repositoryId':'falcon-rid','normalizedRemote':'example.invalid/falcon'},
            local_peer='nick')
        key_path = self.directory/'policy.key'
        key_path.write_bytes(bytes(range(32)))
        key_path.chmod(0o600)
        self.key = ConversationKey(key_path, key_ref=ref('policy-key'))
        self.addCleanup(self.key.close)
        custody = FederationPolicyCustody(target, self.artifacts, self.key, ingress=self.identity.ingress,
            backup_transport_ref=ref('policy-reader'), backup_grant_ref=ref('policy-backup'))
        history, self.policy_backup, checkpoint = self.custody('policy', 'DATA')
        self.receiver = ConfigurationHost.from_enrolled_host(self.source_connection,
            authority=self.identity.reader, stream='DATA', binding=self.bindings['DATA'],
            stream_identity=self.streams['DATA'], retention=self.policy, history=history,
            owner=self.owner_pin, schema_ref=SCHEMA_REF, schema_resources={SCHEMA_REF:FEDERATION_POLICY_SCHEMA},
            issuer_ref=ref('issuer'), signing_seed=SEED, reply_prefix=self.inbox_prefixes['host'],
            checkpoint_host=checkpoint, backup_host=self.policy_backup, backup_key_id='backup-one',
            event_producer=event_producer(self.identity.reader, self.scope),
            event_account_public_key=self.account_public_key, federation_policy=custody)
        await self.receiver.start()

    async def admitted(self, document=None, *, method='set', operation='live-policy'):
        from capability_owner.test_live import packet, stamp
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        revision = 0 if method == 'set' else 1
        payload = {'configurationRef':{'id':self.task_id,'ownerHubId':'hub-one','revision':revision},
            'owner':self.owner_pin}
        if method == 'set':
            payload.update(schemaRef=SCHEMA_REF, configurationBytes=base64.b64encode(document).decode(),
                secretReferences=[ref('policy-key')])
        claims = {'purpose':'agentmux-client-possession-v1','hubId':'hub-one','profileId':'profile-one',
            'authorityId':'authority-one','transportRef':ref('transport'),'grantRef':ref('policy-'+method),
            'operationId':operation,'expectedVersion':revision,'contractId':'configuration-'+method,
            'payload':payload,'approvalRefs':[],'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=30))}
        result = await self.identity.ingress.admit(packet(claims, bytes(reversed(SEED))),
            cancellation_ref=ref('policy-cancel'))
        self.assertEqual(result.decision.outcome, 'allowed')
        return result.envelope

    async def test_actual_tls_policy_commit_backup_recovery_and_broker_refusals(self):
        from .configuration import verify_configuration_response
        from datetime import datetime, timezone
        owner = self.receiver.owner
        proposal = owner.preparation_bytes(previous_revision=0, old_policy=self.old,
            desired_policy=self.desired, change={'verb':'trust','arguments':{'peer':'alice','level':'flag'}})
        raw = await self.admitted(proposal)
        document = await owner.prepare(raw, old_policy=self.old, desired_policy=self.desired)
        request = await self.admitted(document)
        response = await self.exchange(self.host, self.read_subject, request, self.host.new_inbox(), timeout=8)
        verified = verify_configuration_response(response, request, public_key=self.issuer_public,
            issuer_ref=ref('issuer'), now=datetime.now(timezone.utc))
        self.assertEqual(verified['state']['revision'], 1)
        repeated = await self.exchange(self.host, self.read_subject, request, self.host.new_inbox(), timeout=8)
        replay = verify_configuration_response(repeated, request, public_key=self.issuer_public,
            issuer_ref=ref('issuer'), now=datetime.now(timezone.utc))
        self.assertEqual(replay['state'], verified['state'])
        operation = strict_loads(request)['operation']
        committed = await owner.reconcile(await self.admitted(method='read', operation='live-policy-read'),
            operation_id=operation['operationId'], payload_digest=operation['payloadDigest'])
        self.assertEqual(committed.policy_bytes, self.desired)
        await self.receiver._backup.run_due()
        entry = self.policy_backup.latest()
        with restore_backup(self.policy_backup.backup_directory, entry.receipt.manifest_name,
                expected_digest=entry.receipt.digest, key=self.policy_backup.load_key(entry.key_id),
                binding=self.bindings['DATA'], stream_identity=self.streams['DATA'],
                history_path=self.directory/'restored.sqlite') as restored:
            self.assertTrue(restored.reconciliation_required)
            for name in ('oldPolicy', 'desiredPolicy'):
                reference = strict_loads(document)[name]['artifactRef']
                self.assertEqual(restored.retrieve(reference), await self.artifacts.retrieve(reference))
        for subject in ('$JS.API.STREAM.MSG.GET.OTHER', '$JS.API.STREAM.MSG.GET.IDENTITY',
                '$JS.API.STREAM.PURGE.DATA', '$JS.API.STREAM.CREATE.OTHER',
                '$JS.API.STREAM.INFO.OBJ_OTHER', '$O.OTHER.C.chunk', '$O.OTHER.M.entry',
                'amx.v1.h.hub-one.o.other-org.p._.w._.ledger.configuration.configuration-one'):
            before = self.errors['storage'].count('permission')
            await self.source_connection.publish(subject, b'{}')
            await self.source_connection.flush(timeout=2)
            await self.wait_permissions('storage', before+1)
        self.assertEqual((await self.receiver.ledger.current()).sequence, 1)
        self.success = True
