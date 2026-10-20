"""Actual configuration commits retain the original selected Store generation."""
import asyncio
import copy
import base64
import os
import threading
from unittest.mock import AsyncMock, patch
from datetime import timedelta
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.plugins.board import Board
from hub.fed.policy import rid_for_remote
from hub.store import APP_ID, MIGRATIONS, Store
from nacl.signing import SigningKey
from identity.federation_policy_client import verify_policy_preparation
from identity.federation_policy_client import verify_policy_client_response
from agentmux_contracts import sign_claims
from state_owner.federation_policy import FederationPolicyTarget, _digest
from state_owner import test_federation_policy as policy_support
from .federation_policy_transition import FederationPolicyTransition, changed_policy
from .selected_storage import BoardAuditMirrorHost


class FederationPolicyTransitionTests(unittest.IsolatedAsyncioTestCase):
    make_owner = policy_support.FederationPolicyTests.make_owner
    request = policy_support.FederationPolicyTests.request

    async def asyncSetUp(self):
        await policy_support.FederationPolicyTests.asyncSetUp(self)
        # Run borrowed fixture cleanups through this initialized async runner.
        for function, args, kwargs in self.fixture._cleanups:
            self.addCleanup(function, *args, **kwargs)
        self.fixture._cleanups.clear()
        await self.owner.close(timeout=None)
        patcher = patch('capability_owner.federation_policy_transition.datetime', policy_support._Clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        database = self.root/'hub.db'
        store = Store(str(database))
        store.repo_add('falcon')
        for statement in Board.tables:
            store.db.execute(statement)
        store.db.close()
        database.chmod(0o600)
        self.path = self.root/'federation.toml'
        self.path.write_bytes(self.old)
        self.path.chmod(0o600)
        self.pins = {'database': {'path': str(database), 'applicationId': APP_ID,
            'userVersion': len(MIGRATIONS)}, 'policy': {'path': str(self.path), 'sha256': _digest(self.old)}}
        self.repository = {'localName': 'falcon', 'repositoryId': rid_for_remote('example.invalid/falcon'),
            'normalizedRemote': 'example.invalid/falcon', 'counterPrefix': 'SH'}
        self.target = FederationPolicyTarget.selected(self.ledger._binding,
            source_ref=policy_support.ref('selected-federation-policy'), source=self.pins,
            repository=self.repository, local_peer='nick')
        self.owner = self.make_owner()
        self.addAsyncCleanup(self.owner.close, timeout=None)
        self.source = BoardAuditMirrorHost(self.pins, repository=self.repository,
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        self.transition = FederationPolicyTransition(self.owner, [self.source],
            projection_transport_ref=policy_support.ref('policy-reader'),
            projection_grant_ref=policy_support.ref('policy-project'), projection_service_ref=policy_support.ref('service'))
        self.addAsyncCleanup(self.transition.close)

    async def final(self, change=None, *, revision=0, operation='policy-one'):
        change = change or {'verb': 'trust', 'arguments': {'peer': 'alice', 'level': 'flag'}}
        old = self.path.read_bytes()
        desired = changed_policy(old, change, repository=self.repository)
        proposal = self.owner.preparation_bytes(previous_revision=revision,
            old_policy=old, desired_policy=desired, change=change)
        raw = self.request(proposal, revision=revision, operation=operation)
        descriptor = await self.transition.prepare(raw)
        return self.request(descriptor, revision=revision, operation=operation), desired

    async def project_request(self, original, desired, *, operation='project-one', service=True):
        original = strict_loads(original)
        revision = original['operation']['expectedVersion'] + 1
        grant = copy.deepcopy(self.backup_grant)
        grant.update(ref=policy_support.ref('policy-project'), contractId='federation-policy-project')
        self.record['state']['grants'].append(grant)
        now = policy_support._Clock.now()
        stamp = lambda value: value.isoformat().replace('+00:00', 'Z')
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': policy_support.ref('policy-reader' if service else 'transport'),
            'grantRef': grant['ref'], 'operationId': operation, 'expectedVersion': revision,
            'contractId': 'federation-policy-project', 'payload': {
                'configurationRef': {'id': self.ledger._binding.entity_id, 'ownerHubId': 'hub-one', 'revision': revision},
                'owner': copy.deepcopy(self.fixture.owner), 'target': self.target.descriptor,
                'originalOperationId': original['operation']['operationId'],
                'originalPayloadDigest': original['operation']['payloadDigest'], 'desiredPolicyDigest': _digest(desired)},
            'approvalRefs': [], 'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30))}
        packet = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, policy_support.SEED)})
        admitted = await self.ingress.admit(packet, cancellation_ref=policy_support.ref('project-cancel'))
        if admitted.envelope is None:
            raise ContractError('test_project_not_admitted')
        return admitted.envelope

    async def configuration_host(self):
        """Use the existing enrolled host, ledger, event and backup test controls."""
        from types import SimpleNamespace
        from identity.authority import LedgerAuthorityReader
        from identity.ingress import EnrolledIngress
        from state_owner import test_configuration_activation as events
        from state_owner.backup_host import BackupHost
        from state_owner.checkpoint_host import CheckpointHost
        from state_owner.configuration_host import ConfigurationHost
        from state_owner.history import OwnerHistory
        from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
        from state_owner.test_ledger import FakeJetStream, CREATED
        from state_owner.federation_policy import FederationPolicyCustody, SCHEMA_REF, FEDERATION_POLICY_SCHEMA
        await self.transition.close()
        await self.source.close()
        await self.owner.close(timeout=None)
        patcher = patch('identity.configuration_events.datetime', policy_support._Clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        scope = strict_loads(self.ledger._binding.scope)
        events.enroll_event_producer(self.record['state'], scope)
        authority_scope = dict(scope, projectId=None, workspaceId=None)
        binding = OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority', canonical_bytes(authority_scope))
        record = copy.deepcopy(self.record)
        record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        record['operation'].update(scope=authority_scope, expectedVersion=0)
        authority_js = FakeJetStream(self.fixture.policy)
        self._gateway_authority_record, self._gateway_authority_js = record, authority_js
        authority_js.config.subjects = [owner_subject(binding)]
        authority_js.messages = [SimpleNamespace(subject=owner_subject(binding), seq=1, data=canonical_bytes(record))]
        authority_ledger = OwnerLedger(authority_js, stream='OWNER', subject=owner_subject(binding),
            binding=binding, retention=self.fixture.policy, stream_identity=StreamIdentity(CREATED, 1))
        reader = LedgerAuthorityReader(authority_ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        history = OwnerHistory(self.root/'gateway-history.sqlite', self.ledger._binding,
            stream_identity=StreamIdentity(CREATED, 0))
        self.addCleanup(history.close)
        paths = [self.root/name for name in ('backups', 'inventory', 'backupkeys', 'checkpoints')]
        for path in paths:
            path.mkdir(mode=0o700)
        backup = BackupHost(*paths[:3], destination_id='policy-backup', binding=self.ledger._binding,
            stream_identity=StreamIdentity(CREATED, 0))
        backup.enroll_key('backup-key')
        checkpoint = CheckpointHost(paths[3]/'checkpoint', stream='OWNER', commit_ref=policy_support.ref('checkpoint'),
            binding=self.ledger._binding, stream_identity=StreamIdentity(CREATED, 0))
        self.fixture.connection.jetstream = lambda: self.fixture.js
        self.ingress = EnrolledIngress(reader, issuer_ref=policy_support.ref('issuer'), signing_seed=policy_support.SEED)
        custody = FederationPolicyCustody(self.target, self.artifacts, self.key, ingress=self.ingress,
            backup_transport_ref=policy_support.ref('policy-reader'), backup_grant_ref=policy_support.ref('policy-backup'))
        host = ConfigurationHost.from_enrolled_host(self.fixture.connection, authority=reader, stream='OWNER',
            binding=self.ledger._binding, retention=self.fixture.policy, stream_identity=StreamIdentity(CREATED, 0),
            history=history, owner=self.fixture.owner, schema_ref=SCHEMA_REF,
            schema_resources={SCHEMA_REF:FEDERATION_POLICY_SCHEMA}, issuer_ref=policy_support.ref('issuer'),
            signing_seed=policy_support.SEED, reply_prefix='_INBOX.configuration', checkpoint_host=checkpoint,
            backup_host=backup, backup_key_id='backup-key', event_producer=events.event_producer(reader, scope),
            event_account_public_key='A'*56, federation_policy=custody)
        self.addAsyncCleanup(host.close, timeout=None)
        await host.start()
        self.owner, self.ledger = host.owner, host.ledger
        self.source = BoardAuditMirrorHost(self.pins, repository=self.repository, local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        self.transition = FederationPolicyTransition(self.owner, [self.source],
            projection_transport_ref=policy_support.ref('policy-reader'),
            projection_grant_ref=policy_support.ref('policy-project'), projection_service_ref=policy_support.ref('service'), requester_reply_prefix=host._reply_prefix)
        self.addAsyncCleanup(self.transition.close)
        return host

    def possession(self, payload, *, operation='policy-one', revision=0, contract='configuration-set'):
        now = policy_support._Clock.now()
        stamp = lambda value: value.isoformat().replace('+00:00', 'Z')
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': policy_support.ref('transport'),
            'grantRef': policy_support.ref(contract), 'operationId': operation,
            'expectedVersion': revision, 'contractId': contract, 'payload': payload,
            'approvalRefs': [], 'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30))}
        return canonical_bytes({'schemaVersion':'1.0.0', 'claims':claims,
            'signature': sign_claims(claims, bytes(reversed(policy_support.SEED)))})

    async def test_real_commit_changes_original_source_and_replay_has_one_effect(self):
        original = self.source._store
        worker = await self.source.db(threading.get_ident)
        await self.source.db(self.source._store.event, 'board', 'SH-1', 'kept', 'peer:nick')
        raw, desired = await self.final()
        reply = await self.transition.apply(raw)
        self.assertEqual(self.path.read_bytes(), desired)
        self.assertIs(self.source._store, original)
        self.assertEqual(self.source._policy.trust('alice'), 'flag')
        self.assertEqual(self.source._policy_generation, 1)
        self.assertEqual(await self.source.db(threading.get_ident), worker)
        self.assertEqual((await self.source.db(original.q1, 'SELECT event FROM events'))['event'], 'kept')
        self.assertEqual(await self.transition.apply(raw), reply)
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.record['state']['grants'] = []
        with self.assertRaises(ContractError):
            await self.transition.apply(raw)

    async def test_pause_joins_original_sql_and_refuses_new_work_without_fencing_store(self):
        raw, desired = await self.final()
        entered, release = threading.Event(), threading.Event()
        def original():
            entered.set()
            release.wait()
            return self.source._policy.trust('alice')
        old = asyncio.create_task(self.source.db(original))
        change = None
        try:
            async with asyncio.timeout(3):
                while not entered.is_set():
                    await asyncio.sleep(.001)
            change = asyncio.create_task(self.transition.apply(raw))
            async with asyncio.timeout(3):
                while not self.source._policy_paused:
                    await asyncio.sleep(.001)
            self.source.check_health()
            self.assertFalse(self.source._closed)
            with self.assertRaisesRegex(ContractError, '^selected_policy_transition_pending$'):
                await self.source.db(lambda: None)
            self.assertEqual(self.path.read_bytes(), self.old)
            self.assertFalse(change.done())
        finally:
            release.set()
        self.assertEqual(await old, 'auto')
        await change
        self.assertEqual(self.path.read_bytes(), desired)

    async def test_unshare_suspends_then_reshare_uses_same_store_and_history(self):
        original = self.source._store
        await self.source.db(original.event, 'board', 'SH-1', 'kept', 'peer:nick')
        raw, _ = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
        await self.transition.apply(raw)
        self.source.check_health()
        self.assertTrue(self.source._policy_suspended)
        with self.assertRaisesRegex(ContractError, '^selected_policy_not_shared$'):
            await self.source.db(lambda: None)
        raw, _ = await self.final({'verb': 'share', 'arguments': {'repo': 'falcon',
            'remote': 'example.invalid/falcon'}}, revision=1, operation='policy-two')
        await self.transition.apply(raw)
        self.assertFalse(self.source._policy_suspended)
        self.assertIs(self.source._store, original)
        self.assertEqual((await self.source.db(original.q1, 'SELECT event FROM events'))['event'], 'kept')

    async def test_independent_file_change_and_repository_substitution_never_commit(self):
        raw, _ = await self.final()
        self.path.write_bytes(self.old+b'\n# independent edit\n')
        with self.assertRaises(ContractError):
            await self.transition.apply(raw)
        self.assertEqual(len(self.fixture.js.messages), 0)
        self.assertEqual(self.path.read_bytes(), self.old+b'\n# independent edit\n')
        with self.assertRaisesRegex(ContractError, '^federation_policy_change_invalid$'):
            changed_policy(self.old, {'verb': 'unshare', 'arguments': {'repo': 'different'}},
                repository=self.repository)

    async def test_cancellation_retains_original_commit_and_projection(self):
        raw, desired = await self.final()
        entered, release = asyncio.Event(), asyncio.Event()
        append = self.owner._ledger.append
        async def blocked(*args, **kwargs):
            entered.set()
            await release.wait()
            return await append(*args, **kwargs)
        with patch.object(self.owner._ledger, 'append', blocked):
            waiter = asyncio.create_task(self.transition.apply(raw))
            await entered.wait()
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            original, = self.transition._operations.values()
            self.assertFalse(original.done())
            self.assertTrue(self.source._policy_paused)
            release.set()
            await asyncio.wait({original})
            original.result()
        self.assertEqual(self.path.read_bytes(), desired)
        await self.transition.apply(raw)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_substituted_desired_bytes_refuse_before_commit_and_source_resumes(self):
        proposal = self.owner.preparation_bytes(previous_revision=0, old_policy=self.old,
            desired_policy=self.desired, change={'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
        raw = self.request(proposal)
        with self.assertRaisesRegex(ContractError, '^federation_policy_preparation_invalid$'):
            await self.transition.prepare(raw)
        self.assertEqual(len(self.fixture.js.messages), 0)
        self.assertFalse(self.source._policy_paused)
        self.source.check_health()

    async def test_prepared_receipt_has_distinct_purpose_and_exact_proposal_binding(self):
        change = {'verb': 'trust', 'arguments': {'peer': 'alice', 'level': 'flag'}}
        desired = changed_policy(self.old, change, repository=self.repository)
        proposal = self.owner.preparation_bytes(previous_revision=0,
            old_policy=self.old, desired_policy=desired, change=change)
        request = self.request(proposal)
        receipt = await self.transition.prepare_reply(request)
        pins = {'public_key': base64.urlsafe_b64encode(bytes(SigningKey(policy_support.SEED).verify_key)).decode().rstrip('='),
            'issuer_ref': policy_support.ref('issuer'), 'target': self.target.descriptor,
            'now': policy_support._Clock.now()}
        descriptor = verify_policy_preparation(receipt, request, **pins)
        self.assertEqual(strict_loads(descriptor)['projectionIntent']['change'], change)
        self.assertEqual(len(self.fixture.js.messages), 0)
        self.assertEqual(self.path.read_bytes(), self.old)
        for mutate in ('operation', 'target', 'descriptor', 'purpose'):
            response = strict_loads(receipt)
            claims = response['claims']
            if mutate == 'operation':
                claims['operationId'] = 'different-operation'
            elif mutate == 'target':
                claims['target']['repositoryId'] = 'different-repository'
            elif mutate == 'purpose':
                claims['purpose'] = 'agentmux-configuration-response-v1'
            else:
                document = strict_loads(descriptor)
                document['projectionIntent']['change']['arguments']['level'] = 'deny'
                claims['descriptorBytes'] = base64.b64encode(canonical_bytes(document)).decode()
            response['signature'] = sign_claims(claims, policy_support.SEED)
            with self.assertRaises(ContractError):
                verify_policy_preparation(canonical_bytes(response), request, **pins)

    async def test_current_service_reconciles_original_commit_without_new_decision(self):
        raw, desired = await self.final()
        await self.owner.handle(raw)
        self.assertEqual(self.path.read_bytes(), self.old)
        next(grant for grant in self.record['state']['grants']
            if grant['ref'] == policy_support.ref('configuration-set'))['status'] = 'revoked'
        project = await self.project_request(raw, desired)
        receipt = strict_loads(await self.transition.project(project))
        self.assertEqual(receipt['claims']['originalOperationId'], strict_loads(raw)['operation']['operationId'])
        self.assertEqual(self.path.read_bytes(), desired)
        self.assertEqual(self.source._policy.trust('alice'), 'flag')
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(strict_loads(self.fixture.js.messages[0].data)['operation'], strict_loads(raw)['operation'])

    async def test_restart_uses_current_project_grant_while_default_start_still_refuses(self):
        raw, desired = await self.final()
        await self.transition.apply(raw)
        await self.transition.close()
        await self.source.close()
        await self.owner.close(timeout=None)
        refused = BoardAuditMirrorHost(self.pins, repository=self.repository,
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(refused.close)
        with self.assertRaises(ContractError):
            await refused.start()
        await refused.close()
        self.owner = self.make_owner()
        self.addAsyncCleanup(self.owner.close, timeout=None)
        self.source = BoardAuditMirrorHost(self.pins, repository=self.repository,
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        self.transition = FederationPolicyTransition(self.owner, [self.source],
            projection_transport_ref=policy_support.ref('policy-reader'),
            projection_grant_ref=policy_support.ref('policy-project'), projection_service_ref=policy_support.ref('service'))
        self.addAsyncCleanup(self.transition.close)
        project = await self.project_request(raw, desired)
        await self.transition.project(project)
        self.assertEqual(self.source._policy_generation, 1)
        self.assertEqual(self.source._policy.trust('alice'), 'flag')
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_project_cannot_substitute_read_grant_original_outcome_or_target(self):
        raw, desired = await self.final()
        await self.owner.handle(raw)
        read = self.request(method='read', revision=1)
        with self.assertRaises(ContractError):
            await self.transition.project(read)
        project = strict_loads(await self.project_request(raw, desired))
        for name in ('originalOperationId', 'originalPayloadDigest', 'target'):
            value = copy.deepcopy(project)
            if name == 'target':
                value['payload']['target']['repositoryId'] = 'foreign-repository'
            else:
                value['payload'][name] = 'foreign-operation' if name.endswith('Id') else 'sha256:'+'f'*64
            from agentmux_contracts import payload_digest
            value['operation']['payloadDigest'] = payload_digest(value['payload'])
            value['ingressAttestation']['claims']['operation'] = value['operation']
            value['ingressAttestation']['signature'] = sign_claims(value['ingressAttestation']['claims'], policy_support.SEED)
            with self.assertRaises(ContractError):
                await self.transition.project(canonical_bytes(value))
        self.assertEqual(self.path.read_bytes(), self.old)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_other_current_service_transport_or_grant_cannot_replace_selected_route(self):
        raw, desired = await self.final()
        await self.owner.handle(raw)
        project = strict_loads(await self.project_request(raw, desired))
        transport = copy.deepcopy(next(row for row in self.record['state']['transports']
            if row['ref'] == policy_support.ref('policy-reader')))
        transport['ref'] = policy_support.ref('other-policy-reader')
        self.record['state']['transports'].append(transport)
        grant = copy.deepcopy(next(row for row in self.record['state']['grants']
            if row['ref'] == policy_support.ref('policy-project')))
        grant['ref'] = policy_support.ref('other-policy-project')
        self.record['state']['grants'].append(grant)
        for route in ('transport', 'grant'):
            changed = copy.deepcopy(project)
            if route == 'transport':
                changed['ingressAttestation']['claims']['authenticatedTransportRef'] = transport['ref']
            else:
                changed['operation']['grantRef'] = grant['ref']
                changed['ingressAttestation']['claims']['operation'] = changed['operation']
            changed['ingressAttestation']['signature'] = sign_claims(changed['ingressAttestation']['claims'], policy_support.SEED)
            with self.assertRaisesRegex(ContractError, '^federation_policy_projection_refused$'):
                await self.transition.project(canonical_bytes(changed))
        self.assertEqual(self.path.read_bytes(), self.old)

    async def test_close_joins_full_public_authorization_before_any_new_effect(self):
        raw, _ = await self.final()
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.owner._authority.current
        async def blocked():
            entered.set()
            await release.wait()
            return await original()
        with patch.object(self.owner._authority, 'current', blocked):
            waiter = asyncio.create_task(self.transition.apply(raw))
            await entered.wait()
            close = asyncio.create_task(self.transition.close())
            async with asyncio.timeout(2):
                while not self.transition._closed:
                    await asyncio.sleep(0)
            self.assertFalse(close.done())
            self.assertTrue(self.transition._calls)
            release.set()
            with self.assertRaisesRegex(ContractError, '^federation_policy_transition_unavailable$'):
                await waiter
            await close
        self.assertFalse(self.transition._calls or self.transition._operations)
        self.assertEqual(self.path.read_bytes(), self.old)
        self.assertEqual(len(self.fixture.js.messages), 0)

    async def test_external_possession_route_prepares_then_commits_and_binds_actual_inbox(self):
        host = await self.configuration_host()
        change = {'verb': 'trust', 'arguments': {'peer': 'alice', 'level': 'flag'}}
        desired = changed_policy(self.old, change, repository=self.repository)
        proposal = self.owner.preparation_bytes(previous_revision=0, old_policy=self.old, desired_policy=desired, change=change)
        payload = strict_loads(self.request(proposal))['payload']
        request = self.possession(payload)
        reply = host._reply_prefix+'policy-test'
        pins = {'public_key': base64.urlsafe_b64encode(bytes(SigningKey(policy_support.SEED).verify_key)).decode().rstrip('='),
            'issuer_ref': policy_support.ref('issuer'), 'target': self.target.descriptor,
            'owner': self.fixture.owner, 'caller_ref': policy_support.ref('human'),
            'scope': strict_loads(self.ledger._binding.scope), 'now': policy_support._Clock.now(), 'reply_subject': reply}
        response = await self.transition.client_command(request, reply_subject=reply)
        prepared = verify_policy_client_response(response, request, **pins)
        self.assertEqual(prepared.kind, 'prepared')
        self.assertEqual(len(self.fixture.js.messages), 0)
        payload = dict(payload, configurationBytes=base64.b64encode(prepared.data).decode())
        final = self.possession(payload)
        committed = await self.transition.client_command(final, reply_subject=reply)
        result = verify_policy_client_response(committed, final, **pins)
        self.assertEqual(result.kind, 'committed')
        self.assertEqual(self.path.read_bytes(), desired)
        self.assertEqual(len(self.fixture.js.messages), 1)
        for altered in (dict(pins, reply_subject=reply+'-other'), dict(pins, caller_ref=policy_support.ref('other'))):
            with self.assertRaises(ContractError):
                verify_policy_client_response(response, request, **altered)
        with self.assertRaises(ContractError):
            await self.transition.client_command(request, reply_subject='_INBOX.other.unselected')
        with self.assertRaises(ContractError):
            verify_policy_client_response(committed, request, **pins)
        invalid = self.possession(dict(payload, configurationBytes=base64.b64encode(b'[]').decode()),
            operation='invalid-policy')
        with self.assertRaisesRegex(ContractError, '^federation_policy_client_binding$'):
            await self.transition.client_command(invalid, reply_subject=reply)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def current_response(self, host, *, revision=0, operation='read-policy'):
        payload = strict_loads(self.request(method='read', revision=revision))['payload']
        packet = self.possession(payload, operation=operation, revision=revision, contract='configuration-read')
        inbox = host._reply_prefix + operation
        pins = {'public_key': base64.urlsafe_b64encode(bytes(SigningKey(policy_support.SEED).verify_key)).decode().rstrip('='),
            'issuer_ref': policy_support.ref('issuer'), 'target': self.target.descriptor,
            'owner': self.fixture.owner, 'caller_ref': policy_support.ref('human'),
            'scope': strict_loads(self.ledger._binding.scope), 'now': policy_support._Clock.now(), 'reply_subject': inbox}
        response = await self.transition.client_command(packet, reply_subject=inbox)
        verified = verify_policy_client_response(response, packet, **pins)
        self.assertEqual(verified.kind, 'current')
        return strict_loads(verified.data), response, packet, pins

    async def test_external_read_reports_genuine_empty_owner_without_committing(self):
        host = await self.configuration_host()
        current, _, _, _ = await self.current_response(host)
        self.assertEqual(current['configurationRef']['revision'], 0)
        self.assertFalse(current['projected'])
        for name in ('state', 'operation', 'originalOperationId', 'originalPayloadDigest'):
            self.assertIsNone(current[name])
        self.assertEqual(self.fixture.js.messages, [])
        self.assertEqual(self.path.read_bytes(), self.old)

    async def test_external_read_keeps_original_commit_pending_until_projection(self):
        from state_owner.configuration import ConfigurationOwner
        host = await self.configuration_host()
        raw, desired = await self.final()
        await ConfigurationOwner.handle(self.owner, raw)
        current, _, _, _ = await self.current_response(host)
        original = strict_loads(raw)['operation']
        self.assertEqual(current['configurationRef']['revision'], 1)
        self.assertEqual(current['operation'], original)
        self.assertEqual(current['originalOperationId'], original['operationId'])
        self.assertEqual(current['originalPayloadDigest'], original['payloadDigest'])
        self.assertFalse(current['projected'])
        self.assertEqual(self.path.read_bytes(), self.old)
        await self.transition.apply(raw)
        current, _, _, _ = await self.current_response(host, operation='read-projected')
        self.assertTrue(current['projected'])
        self.assertEqual(self.path.read_bytes(), desired)
        self.assertEqual(len(self.fixture.js.messages), 1)
        record = self._gateway_authority_record
        record['state']['grants'] = [grant for grant in record['state']['grants']
            if grant['ref'] != policy_support.ref('configuration-set')]
        self._gateway_authority_js.messages[0].data = canonical_bytes(record)
        current, _, _, _ = await self.current_response(host, operation='read-without-old-write')
        self.assertTrue(current['projected'])
        self.assertEqual(current['operation'], original)
        self.source._policy_paused = True
        current, _, _, _ = await self.current_response(host, operation='read-paused')
        self.assertFalse(current['projected'])
        self.source._policy_paused = False

    async def test_external_read_refuses_current_authority_revocation_during_read(self):
        host = await self.configuration_host()
        original = self.ledger.current
        async def revoke_after_read(*args, **kwargs):
            snapshot = await original(*args, **kwargs)
            record = self._gateway_authority_record
            record['state']['grants'] = [grant for grant in record['state']['grants']
                if grant['ref'] != policy_support.ref('configuration-read')]
            self._gateway_authority_js.messages[0].data = canonical_bytes(record)
            return snapshot
        with patch.object(self.ledger, 'current', revoke_after_read):
            with self.assertRaises(ContractError):
                await self.current_response(host)
        self.assertEqual(self.fixture.js.messages, [])

    async def test_external_current_verifier_refuses_substituted_retained_fields(self):
        host = await self.configuration_host()
        empty, response, packet, pins = await self.current_response(host)
        async def refuses(current, original_response=response, original_packet=packet, original_pins=pins):
            changed = strict_loads(original_response)
            changed['claims']['resultBytes'] = base64.b64encode(canonical_bytes(current)).decode()
            changed['signature'] = sign_claims(changed['claims'], policy_support.SEED)
            with self.assertRaises(ContractError):
                verify_policy_client_response(canonical_bytes(changed), original_packet, **original_pins)
        await refuses(dict(empty, projected=True))
        raw, _ = await self.final()
        await self.transition.apply(raw)
        current, response, packet, pins = await self.current_response(host, operation='read-committed')
        for field, value in (('originalOperationId', 'substituted'), ('originalPayloadDigest', _digest(b'other')),
                ('configurationRef', dict(current['configurationRef'], revision=2)),
                ('target', dict(current['target'], repositoryId='other'))):
            await refuses(dict(current, **{field:value}), response, packet, pins)
        altered = copy.deepcopy(current)
        descriptor = strict_loads(base64.b64decode(altered['state']['configurationBytes']))
        descriptor['projectionIntent']['actorRef'] = policy_support.ref('other')
        encoded = canonical_bytes(descriptor)
        altered['state'].update(configurationBytes=base64.b64encode(encoded).decode(), configurationChecksum=_digest(encoded))
        await refuses(altered, response, packet, pins)
        altered = copy.deepcopy(current)
        altered['operation']['payloadDigest'] = altered['originalPayloadDigest'] = _digest(b'other')
        await refuses(altered, response, packet, pins)

    async def selected_storage_host(self):
        from .test_selected_storage import SelectedStorageCompositionTests
        from identity.ingress import EnrolledIngress
        from identity.authority import AuthoritySnapshot
        from .test_messages_host import selected_messages
        from .selected_storage import SelectedStorageHost
        fixture = SelectedStorageCompositionTests()
        fixture.setUp()
        for function, args, kwargs in fixture._cleanups:
            self.addCleanup(function, *args, **kwargs)
        fixture._cleanups.clear()
        await self.transition.close()
        await self.source.close()
        await self.owner.close(timeout=None)
        self.old += b'\n[repos.osprey]\nremote="example.invalid/osprey"\n'
        self.path.write_bytes(self.old)
        self.pins['policy']['sha256'] = _digest(self.old)
        self.target = FederationPolicyTarget.selected(self.ledger._binding,
            source_ref=policy_support.ref('selected-federation-policy'), source=self.pins,
            repository=self.repository, local_peer='nick')
        fixture.add_board()
        fixture.value['storage']['board'].update(auditMirror=copy.deepcopy(self.pins),
            repository=copy.deepcopy(self.repository), localPeer='nick')
        message = selected_messages(fixture.root, scope=fixture.scope)
        message['source']['policy'] = copy.deepcopy(self.pins['policy'])
        message['repository'] = {'localName': 'osprey', 'repositoryId': rid_for_remote('example.invalid/osprey'),
            'normalizedRemote': 'example.invalid/osprey'}
        other_store = Store(message['source']['database']['path'])
        other_store.repo_add('osprey')
        other_store.db.close()
        fixture.value['storage']['messages'] = message
        selection = fixture.selected()
        identity = fixture.identity
        for function, args, kwargs in fixture._cleanups:
            self.addCleanup(function, *args, **kwargs)
        fixture._cleanups.clear()
        selected = SelectedStorageHost(selection, identity=identity)
        self.addAsyncCleanup(selected.close, timeout=None)
        await self.transition.close()
        await self.source.close()
        await self.owner.close(timeout=None)
        self.source = BoardAuditMirrorHost(self.pins, repository=self.repository,
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        selected._audit = self.source
        current = patch.object(selected._authority, 'current', AsyncMock(
            side_effect=lambda: AuthoritySnapshot(canonical_bytes(self.record), 1)))
        current.start()
        self.addCleanup(current.stop)
        self.fixture.authority = selected._authority
        self.ingress = EnrolledIngress(selected._authority, issuer_ref=policy_support.ref('issuer'),
            signing_seed=policy_support.SEED)
        self.owner = self.make_owner()
        self.addAsyncCleanup(self.owner.close, timeout=None)
        await selected._messages(message)
        second, = selected._message_stores
        from .reply_service import CapabilityReplyService
        receiver = selection.storage_descriptor('storage')
        service = CapabilityReplyService(selected._authority, resources=selected._resources,
            hub_id='hub-one', profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=receiver['serviceIdentityRef'], service_instance_id=receiver['serviceInstanceId'],
            signing_key_ref=receiver['issuer']['issuerRef'], signing_seed=selection.load_storage_signing_seed('storage'),
            request_signing_key_ref=receiver['requestSigningKeyRef'])
        selected._receivers.append(service)
        # Omitting an affected source, or passing an unowned same-file source,
        # must fail before any source is bound or a policy can be written.
        with self.assertRaises(ContractError):
            FederationPolicyTransition(self.owner, [self.source], selected_host=selected)
        self.transition = FederationPolicyTransition(self.owner, [self.source, second],
            selected_host=selected, projection_transport_ref=policy_support.ref('policy-reader'),
            projection_grant_ref=policy_support.ref('policy-project'), projection_service_ref=policy_support.ref('service'))
        self.addAsyncCleanup(self.transition.close)
        return selected, second, message

    async def test_all_declared_sources_sharing_policy_keep_their_original_databases(self):
        selected, second, message = await self.selected_storage_host()
        self.assertEqual(len(self.transition.source_bindings), 2)
        original = (self.source._store, second._store)
        await self.source.db(original[0].event, 'board', 'SH-1', 'board-kept', 'peer:nick')
        await second.db(original[1].event, 'board', 'SH-2', 'message-kept', 'peer:nick')
        raw, desired = await self.final()
        await self.transition.apply(raw)
        self.assertIs(self.source._store, original[0])
        self.assertIs(second._store, original[1])
        self.assertEqual(self.path.read_bytes(), desired)
        self.assertEqual([source._policy.trust('alice') for source in (self.source, second)], ['flag', 'flag'])
        self.assertEqual([source._policy_generation for source in (self.source, second)], [1, 1])
        self.assertIsNone(selected._policy_change)
        self.assertEqual((await second.db(original[1].q1, 'SELECT event FROM events'))['event'], 'message-kept')

        raw, _ = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}},
            revision=1, operation='policy-unshare')
        await self.transition.apply(raw)
        self.assertTrue(self.source._policy_suspended)
        self.assertFalse(second._policy_suspended)
        self.assertEqual(second._policy.rid_of('osprey'), message['repository']['repositoryId'])
        self.assertEqual((await second.db(original[1].q1, 'SELECT event FROM events'))['event'], 'message-kept')

    async def test_resource_bootstrap_requires_original_startup_and_completed_service_projection(self):
        selected, second, _ = await self.selected_storage_host()
        selected._preconstructed_sources.update(board=self.source, messages=second)
        async def startup():
            with self.assertRaises(ContractError):
                await self.source._resource_bootstrap(self.transition, 'board')
            raw, desired = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
            await self.transition.apply(raw)
            with self.assertRaises(ContractError):
                await self.source._resource_bootstrap(self.transition, 'board')
            project = await self.project_request(raw, desired)
            await self.transition.project(project)
            for action in (lambda: self.source._resource_bootstrap(self.transition, 'messages'),
                    lambda: asyncio.create_task(self.source._resource_bootstrap(self.transition, 'board'))):
                with self.assertRaises(ContractError):
                    await action()
            self.source._policy_generation += 1
            with self.assertRaises(ContractError):
                await self.source._resource_bootstrap(self.transition, 'board')
            self.source._policy_generation -= 1
            original_store = self.source._store
            self.source._store = object()
            try:
                with self.assertRaises(ContractError):
                    await self.source._resource_bootstrap(self.transition, 'board')
            finally:
                self.source._store = original_store
            permit = await self.source._resource_bootstrap(self.transition, 'board')
            try:
                self.assertIsNotNone(await permit.submit(self.source._store.q1, 'SELECT repo FROM repos WHERE repo=?', ('falcon',)))
                with self.assertRaisesRegex(ContractError, '^selected_policy_not_shared$'):
                    await self.source.db(self.source._store.q1, 'SELECT 1')
            finally:
                await permit.close()
            with self.assertRaises(ContractError):
                await permit.submit(lambda: None)
        task = asyncio.create_task(startup())
        selected._starting = task
        await task

    async def test_resource_close_joins_original_bootstrap_sql_after_startup_cancellation(self):
        selected, second, _ = await self.selected_storage_host()
        selected._preconstructed_sources.update(board=self.source, messages=second)
        raw, desired = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
        await self.transition.apply(raw)
        project = await self.project_request(raw, desired)
        entered, release = threading.Event(), threading.Event()
        def original_sql():
            entered.set()
            release.wait()
            return self.source._store.q1('SELECT repo FROM repos WHERE repo=?', ('falcon',))
        async def startup():
            await self.transition.project(project)
            permit = await self.source._resource_bootstrap(self.transition, 'board')
            await permit.submit(original_sql)
        task = asyncio.create_task(startup())
        selected._starting = task
        closing = None
        try:
            async with asyncio.timeout(5):
                while not entered.is_set():
                    await asyncio.sleep(.001)
            task.cancel()
            closing = asyncio.create_task(self.source.close())
            await asyncio.sleep(.01)
            self.assertFalse(closing.done())
            self.assertIsNotNone(self.source._store)
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
            if closing is not None:
                await closing
        self.assertIsNone(self.source._store)

    async def test_resource_close_joins_bootstrap_issuance_blocked_in_current_authority(self):
        selected, second, _ = await self.selected_storage_host()
        selected._preconstructed_sources.update(board=self.source, messages=second)
        raw, desired = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
        await self.transition.apply(raw)
        project = await self.project_request(raw, desired)
        entered, release = asyncio.Event(), asyncio.Event()
        current = self.owner._authority.current
        async def blocked():
            entered.set()
            await release.wait()
            return await current()
        async def startup():
            await self.transition.project(project)
            with patch.object(self.owner._authority, 'current', blocked):
                return await self.source._resource_bootstrap(self.transition, 'board')
        task = asyncio.create_task(startup())
        selected._starting = task
        closing = None
        try:
            async with asyncio.timeout(5):
                await entered.wait()
            closing = asyncio.create_task(self.source.close())
            await asyncio.sleep(.01)
            self.assertFalse(closing.done())
            self.assertIsNotNone(self.source._store)
        finally:
            release.set()
            with self.assertRaises(ContractError):
                await task
            if closing is not None:
                await closing
        self.assertEqual(self.source._resource_bootstraps, set())
        self.assertIsNone(self.source._store)

    async def test_refused_precommit_reopens_original_sources_and_actual_receiver(self):
        selected, second, _ = await self.selected_storage_host()
        raw, _ = await self.final()
        original = self.source._policy_candidate
        def revoked(*args):
            result = original(*args)
            next(grant for grant in self.record['state']['grants']
                if grant['ref'] == policy_support.ref('configuration-set'))['status'] = 'revoked'
            return result
        with patch.object(self.source, '_policy_candidate', revoked):
            with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
                await self.transition.apply(raw)
        self.assertIsNone(selected._policy_change)
        self.assertIsNone(self.transition._uncertain)
        self.assertTrue(all(not service._policy_paused for service in selected._receivers))
        self.assertEqual([source._policy_generation for source in (self.source, second)], [0, 0])
        self.assertEqual(await self.source.db(lambda: 'original-board'), 'original-board')
        self.assertEqual(await second.db(lambda: 'original-message'), 'original-message')
        self.assertEqual(self.fixture.js.messages, [])
        self.assertEqual(self.path.read_bytes(), self.old)

    async def test_unknown_commit_cannot_abort_even_when_no_record_is_yet_visible(self):
        selected, second, _ = await self.selected_storage_host()
        raw, _ = await self.final()
        with patch.object(self.fixture.js, 'publish', AsyncMock(side_effect=TimeoutError())):
            with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
                await self.transition.apply(raw)
        self.assertEqual(self.fixture.js.messages, [])
        original = selected._policy_change[2]
        with self.assertRaisesRegex(ContractError, '^selected_policy_transition_pending$'):
            await selected.abort_policy_transition(self.transition)
        self.assertIs(selected._policy_change[2], original)
        self.assertTrue(all(service._policy_paused for service in selected._receivers))
        for source in (self.source, second):
            with self.assertRaisesRegex(ContractError, '^selected_policy_transition_pending$'):
                await source.db(lambda: 'must-not-run')
        self.assertIsNotNone(self.transition._uncertain)

    async def test_changed_policy_prevents_old_admission_abort(self):
        selected, _, _ = await self.selected_storage_host()
        raw, _ = await self.final()
        original = self.source._policy_candidate
        def changed(*args):
            result = original(*args)
            self.path.write_bytes(self.old+b'\n# independent file replacement\n')
            return result
        with patch.object(self.source, '_policy_candidate', changed):
            with self.assertRaises(ContractError):
                await self.transition.apply(raw)
        self.assertIsNotNone(selected._policy_change)
        self.assertTrue(all(service._policy_paused for service in selected._receivers))
        self.assertEqual(self.fixture.js.messages, [])
        self.assertTrue(self.path.read_bytes().endswith(b'# independent file replacement\n'))

    async def test_cancelled_waiter_and_host_close_join_original_sql_before_source_release(self):
        from .selected_storage import SelectedStorageFailure
        selected, _, _ = await self.selected_storage_host()
        raw, _ = await self.final()
        entered, release = threading.Event(), threading.Event()
        store = self.source._store
        def sql():
            with store.tx():
                store.event('board', 'SH-1', 'before-close', 'peer:nick')
                entered.set()
                release.wait()
                store.event('board', 'SH-1', 'after-close', 'peer:nick')
        original_sql = asyncio.create_task(self.source.db(sql))
        waiter = None
        try:
            async with asyncio.timeout(2):
                while not entered.is_set():
                    await asyncio.sleep(.001)
            waiter = asyncio.create_task(self.transition.apply(raw))
            async with asyncio.timeout(2):
                while not self.source._policy_paused:
                    await asyncio.sleep(.001)
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            original_transition, = self.transition._operations.values()
            with self.assertRaises(SelectedStorageFailure):
                await selected.close(timeout=.001)
            original_close = selected._closing
            self.assertFalse(original_transition.done())
            self.assertFalse(original_close.done())
            self.assertIs(self.source._store, store)
            self.assertFalse(original_sql.done())
        finally:
            release.set()
            await original_sql
            await selected.close(timeout=None)
        self.assertIs(selected._closing, original_close)
        self.assertTrue(original_transition.done())
        self.assertIsNone(self.source._store)
        self.assertEqual(self.fixture.js.messages, [])

    async def test_host_close_waits_for_original_commit_after_caller_cancellation(self):
        from .selected_storage import SelectedStorageFailure
        selected, _, _ = await self.selected_storage_host()
        raw, _ = await self.final()
        entered, release = asyncio.Event(), asyncio.Event()
        store = self.source._store
        publish = self.fixture.js.publish
        async def blocked(*args, **kwargs):
            entered.set()
            await release.wait()
            return await publish(*args, **kwargs)
        with patch.object(self.fixture.js, 'publish', blocked):
            waiter = asyncio.create_task(self.transition.apply(raw))
            await entered.wait()
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            original_transition, = self.transition._operations.values()
            try:
                with self.assertRaises(SelectedStorageFailure):
                    await selected.close(timeout=.001)
                original_close = selected._closing
                self.assertFalse(original_transition.done())
                self.assertIs(self.source._store, store)
                self.assertEqual(self.fixture.js.messages, [])
            finally:
                release.set()
                await selected.close(timeout=None)
        self.assertIs(selected._closing, original_close)
        self.assertTrue(original_transition.done())
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(self.path.read_bytes(), self.old)
        self.assertIsNone(self.source._store)
