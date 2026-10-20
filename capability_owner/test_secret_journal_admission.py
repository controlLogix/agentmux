"""Focused admission checks with actual authority and native private custody.

The in-memory broker tests failure ordering. Native broker qualification is in
its separate coordinated module.
"""
import asyncio
import base64
import copy
from dataclasses import replace
from datetime import timedelta
import secrets
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import nkeys
from nats.js.api import StreamState
from nats.js.errors import APIError, NotFoundError

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from capability_owner.secret_consumer import AtlassianAccountCheckEnrollment
from capability_owner.secret_journal_admission import SecretJournalAdmission, SecretJournalPolicy
from capability_owner import test_secret_journal as journal_fixture
from identity import test_application_account as account_fixture
from identity import test_service as service_fixture
from identity.test_authority import ref, SEED
from integration_owner.operator_provisioning import _administrator_subjects
from native_security.secret_custody import ScopedSecretCustody, _resolved_binding
from state_owner.test_ledger import CREATED


class Broker:
    def __init__(self):
        self.streams, self.messages, self.created = {}, {}, {}
        self.creates = 0
        self.lose_create_ack, self.fail_create, self.lose_publish_ack = False, False, False
        self.entered, self.release = asyncio.Event(), asyncio.Event()
        self.hold = False

    async def stream_info(self, stream):
        if stream not in self.streams:
            raise NotFoundError()
        records = self.messages[stream]
        return SimpleNamespace(config=self.streams[stream], created=self.created[stream],
            state=StreamState(messages=len(records), bytes=sum(len(r.data) for r in records),
                first_seq=1 if records else 0, last_seq=len(records), num_deleted=0, consumer_count=0))

    async def add_stream(self, config):
        self.creates += 1
        self.entered.set()
        if self.hold:
            await self.release.wait()
        if self.fail_create:
            raise TimeoutError('PRIVATE synthetic failure')
        if config.name in self.streams:
            raise AssertionError('second create')
        self.streams[config.name], self.messages[config.name] = config, []
        self.created[config.name] = CREATED
        if self.lose_create_ack:
            self.lose_create_ack = False
            raise TimeoutError('PRIVATE lost preparation acknowledgment')
        return await self.stream_info(config.name)

    async def get_msg(self, stream, *, seq=None, subject=None, direct=False):
        if not self.messages[stream] or seq and seq > len(self.messages[stream]):
            raise NotFoundError()
        return self.messages[stream][seq - 1 if seq else -1]

    async def publish(self, subject, data, *, headers):
        stream = headers['Nats-Expected-Stream']
        records = self.messages[stream]
        if int(headers['Nats-Expected-Last-Subject-Sequence']) != len(records):
            raise APIError(err_code=10071)
        records.append(SimpleNamespace(subject=subject, data=data, seq=len(records) + 1))
        if self.lose_publish_ack:
            self.lose_publish_ack = False
            raise TimeoutError('PRIVATE lost ledger acknowledgment')
        return SimpleNamespace(stream=stream, seq=len(records), duplicate=False)


class Client:
    def __init__(self, broker):
        self.broker, self.is_connected, self.closed = broker, False, False

    async def connect(self, **options):
        self.options = options
        token = options['user_jwt_cb']()
        self.claims = strict_loads(base64.urlsafe_b64decode(token.split(b'.')[1] + b'=='))
        options['signature_cb']('nonce')
        self.is_connected = True

    def jetstream(self, **options):
        return self.broker

    async def close(self):
        self.closed, self.is_connected = True, False


class SecretJournalAdmissionTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(journal_fixture.SecretJournalTests.setUpClass.__func__)
    tearDownClass = classmethod(journal_fixture.SecretJournalTests.tearDownClass.__func__)
    request = journal_fixture.SecretJournalTests.request
    store = journal_fixture.SecretJournalTests.store
    proposal = journal_fixture.SecretJournalTests.proposal
    enrolled = journal_fixture.SecretJournalTests.enrolled
    change_current = journal_fixture.SecretJournalTests.change_current
    revoke = journal_fixture.SecretJournalTests.revoke
    fresh_query = journal_fixture.SecretJournalTests.fresh_query

    def setUp(self):
        journal_fixture.SecretJournalTests.setUp(self)
        for target in ('capability_owner.secret_journal_admission.datetime',
                'identity.application_account.datetime', 'native_security.secret_custody.datetime'):
            patch(target, service_fixture._Clock).start()
        patch('native_security.nats_credentials.time.time', return_value=service_fixture.NOW.timestamp()).start()
        self.addCleanup(patch.stopall)
        account = account_fixture.ApplicationAccountTests()
        account.setUp()
        self.account_seed = nkeys.encode_seed(bytes(range(32)), nkeys.PREFIX_BYTE_ACCOUNT)
        key = nkeys.from_seed(self.account_seed)
        self.account_public = key.public_key.decode()
        key.wipe()
        account.record['state']['applicationAccounts'][0]['accountPublicKey'] = self.account_public
        account.payload['accountPublicKey'] = self.account_public
        account.request['payload'] = account.payload
        account.request['operation']['payloadDigest'] = payload_digest(account.payload)
        account.resign()
        self.account_request = canonical_bytes(account.request)
        # Reuse the real public account binding and its signed request in the
        # same current identity ledger used by ordinary-secret authority.
        state = self.record['state']
        for collection in ('identities', 'transports', 'memberships', 'secretReferences', 'applicationAccounts', 'grants'):
            state.setdefault(collection, [])
            known = {row['ref']['id'] for row in state[collection]}
            state[collection].extend(copy.deepcopy(row) for row in account.record['state'][collection]
                if row['ref']['id'] not in known)
        self.store()
        admin_root = self.root / 'administrator'
        admin_root.mkdir(mode=0o700)
        self.account_custody = ScopedSecretCustody(admin_root, self.service.reader)
        self.broker, self.clients, self.admissions = Broker(), [], []
        self.inventory = self.root / 'journal-inventory'
        self.inventory.mkdir(mode=0o700)
        self.policy = SecretJournalPolicy('TEST', canonical_bytes(account.scope), self.account_public,
            'tls://127.0.0.1:4222', 'localhost', self.pem, 'sha256:'+'a'*64,
            self.policy, 2, self.policy.max_bytes * 2)

    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 10

    async def ready(self):
        use = await self.enrolled()
        self.enrollment = AtlassianAccountCheckEnrollment((await self.custody.check(use)).record,
            'https://fixture.example.test', 'cloud', 'fixture@example.test', 'expected', self.pem)
        from capability_owner.secret_journal_admission import _issue
        admin_raw = _issue(self.account_seed, _administrator_subjects(None),
            '_INBOX.admission_admin_00001', valid_until=service_fixture.NOW + timedelta(minutes=5))
        snapshot = await self.service.reader.current()
        for kind, material in (('nats-administrator-credential', admin_raw), ('nats-account-issuer', self.account_seed)):
            self.account_custody._store.provision(_resolved_binding(snapshot, self.account_request,
                kind, service_fixture.NOW), material)
        return self.new_admission()

    def factory(self, **options):
        client = Client(self.broker)
        self.clients.append(client)
        return client

    def new_admission(self, **changes):
        owner = SecretJournalAdmission(policy=changes.get('policy', self.policy), enrollment=self.enrollment,
            authority=self.service.reader, custody=self.custody, account_custody=self.account_custody,
            inventory_root=self.inventory, observation_root=self.root, _client_factory=self.factory)
        self.admissions.append(owner)
        self.addAsyncCleanup(owner.close)
        return owner

    def fresh(self, *, identifier=None):
        envelope = strict_loads(self.outer)
        original = envelope['payload']['originalEnvelope']
        original['operation']['operationId'] = identifier or 'minted-' + secrets.token_hex(16)
        original['ingressAttestation']['claims']['operation'] = copy.deepcopy(original['operation'])
        original['ingressAttestation']['signature'] = sign_claims(original['ingressAttestation']['claims'], SEED)
        envelope['operation']['payloadDigest'] = payload_digest(envelope['payload'])
        envelope['ingressAttestation']['claims']['operation'] = copy.deepcopy(envelope['operation'])
        envelope['ingressAttestation']['signature'] = sign_claims(envelope['ingressAttestation']['claims'], SEED)
        return canonical_bytes(envelope)

    async def open(self, owner, raw=None):
        return await owner.open(raw or self.outer, account_request=self.account_request)

    async def test_two_fresh_originals_reopen_same_creation_and_floor_after_restart(self):
        owner = await self.ready()
        first, second = self.fresh(), self.fresh()
        journal = await self.open(owner, first)
        await journal.prepare(first)
        other = await self.open(owner, second)
        await other.prepare(second)
        self.assertNotEqual(journal._binding.entity_id, other._binding.entity_id)
        self.assertEqual(self.broker.creates, 2)
        self.assertIs(await self.open(owner, first), journal)
        identity = journal._ledger._identity.created
        await owner.close()
        replacement = self.new_admission()
        reopened = await self.open(replacement, first)
        self.assertEqual((await reopened.current())['latest'].sequence, 1)
        self.assertEqual(reopened._ledger._identity.created, identity)
        self.assertEqual(reopened._ledger._minimum_sequence, 1)
        self.assertEqual(self.broker.creates, 2)
        owner_clients = [c for c in self.clients if len(c.claims['nats']['pub']['allow']) == 3]
        self.assertTrue(owner_clients)
        self.assertTrue(all(not any('CREATE' in value or '*' in value or '>' in value
            for value in c.claims['nats']['pub']['allow']) for c in owner_clients))

    async def test_lost_create_and_ledger_ack_keep_exact_original(self):
        owner = await self.ready()
        self.broker.lose_create_ack = True
        journal = await self.open(owner)
        self.broker.lose_publish_ack = True
        prepared = await journal.prepare(self.outer)
        self.assertFalse(prepared.acknowledged)
        await owner.close()
        reopened = await self.open(self.new_admission())
        self.assertEqual((await reopened.current())['latest'].sequence, 1)
        self.assertEqual(self.broker.creates, 1)
        self.assertTrue((await reopened.prepare(self.outer)).replayed)

    async def test_uncertain_missing_create_never_recreates_after_restart(self):
        owner = await self.ready()
        self.broker.fail_create = True
        with self.assertRaises(ContractError): await self.open(owner)
        await owner.close()
        self.broker.fail_create = False
        with self.assertRaisesRegex(ContractError, 'secret_journal_recovery_required'):
            await self.open(self.new_admission())
        self.assertEqual(self.broker.creates, 1)

    async def test_capacity_substitution_and_current_revocation_refuse(self):
        owner = await self.ready()
        await self.open(owner)
        await self.open(owner, self.fresh())
        with self.assertRaisesRegex(ContractError, 'secret_journal_capacity_exhausted'):
            await self.open(owner, self.fresh())
        self.revoke()
        with self.assertRaises(ContractError): await self.open(owner)
        self.assertEqual(self.broker.creates, 2)
        with self.assertRaisesRegex(ContractError, 'secret_journal_assignment_conflict'):
            self.new_admission(policy=replace(self.policy, max_journals=3))

    async def test_unenrolled_and_replaced_streams_are_never_adopted(self):
        owner = await self.ready()
        journal = await self.open(owner)
        stream = journal._ledger._stream
        metadata = self.broker.streams[stream].metadata
        token = metadata['agentmuxSecretJournal']
        metadata['broker-information'] = 'untrusted informational value'
        self.assertIsNone(await journal.current())
        metadata['agentmuxSecretJournal'] = 'substituted-token'
        with self.assertRaisesRegex(ContractError, 'secret_journal_recovery_required'):
            await journal.current()
        with self.assertRaisesRegex(ContractError, 'secret_journal_recovery_required'):
            await self.open(owner)
        metadata['agentmuxSecretJournal'] = token
        self.broker.created[stream] += timedelta(seconds=1)
        with self.assertRaises(ContractError): await self.open(owner)
        self.assertEqual(self.broker.creates, 1)
        self.assertEqual(self.broker.messages[stream], [])

    async def test_untrusted_existing_stream_and_same_id_changed_original_refuse(self):
        owner = await self.ready()
        raw = self.fresh()
        from capability_owner.secret_journal import secret_use_identity
        from state_owner.ledger import OwnerBinding, owner_subject
        operation = strict_loads(raw)['payload']['originalEnvelope']['operation']
        entity = secret_use_identity(operation['scope'], operation['operationId'])
        stream = self.policy.stream(entity)
        binding = OwnerBinding('hub-one', 'ordinary-secret-uses', entity, 'effect', self.policy.scope)
        await self.broker.add_stream(self.policy.retention.stream_config(stream=stream, subject=owner_subject(binding)))
        with self.assertRaisesRegex(ContractError, 'secret_journal_unenrolled_stream'):
            await self.open(owner, raw)
        self.assertEqual(self.broker.creates, 1)
        # An independently valid signed request cannot change the meaning of
        # an already assigned operation ID, even when its payload is unchanged.
        journal = await self.open(owner)
        changed = strict_loads(self.outer)
        original = changed['payload']['originalEnvelope']
        original['operation']['traceId'] = 'substituted-trace'
        original['ingressAttestation']['claims']['operation'] = copy.deepcopy(original['operation'])
        original['ingressAttestation']['signature'] = sign_claims(original['ingressAttestation']['claims'], SEED)
        changed['operation']['payloadDigest'] = payload_digest(changed['payload'])
        changed['ingressAttestation']['claims']['operation'] = copy.deepcopy(changed['operation'])
        changed['ingressAttestation']['signature'] = sign_claims(changed['ingressAttestation']['claims'], SEED)
        with self.assertRaisesRegex(ContractError, 'secret_journal_assignment_conflict'):
            await self.open(owner, canonical_bytes(changed))
        self.assertIsNone(await journal.current())

    async def test_concurrent_observers_cancel_without_releasing_original(self):
        owner = await self.ready()
        self.broker.hold = True
        first = asyncio.create_task(self.open(owner))
        await self.broker.entered.wait()
        second = asyncio.create_task(self.open(owner))
        first.cancel()
        with self.assertRaises(asyncio.CancelledError): await first
        closing = asyncio.create_task(owner.close(timeout=.01))
        with self.assertRaisesRegex(ContractError, 'secret_journal_cleanup_incomplete'): await closing
        self.assertIsNotNone(owner._inventory._fd)
        self.broker.release.set()
        journal = await second
        self.assertEqual(self.broker.creates, 1)
        await owner.close()
        self.assertIsNone(owner._inventory._fd)
        self.assertTrue(all(c.closed for c in self.clients))

    async def test_expired_connection_renews_same_journal_and_refuses_query_before_custody(self):
        owner = await self.ready()
        journal = await self.open(owner)
        await journal.prepare(self.outer)
        query = await self.fresh_query()
        entity = journal._binding.entity_id
        _, old, _ = owner._resources[entity]
        owner._resources[entity] = journal, old, service_fixture.NOW - timedelta(seconds=1)
        reopened = await owner.reopen_query(query, account_request=self.account_request)
        self.assertIs(reopened, journal)
        self.assertTrue(old.closed)
        self.assertEqual((await reopened.current())['latest'].sequence, 1)
        forged = strict_loads(query)
        forged['payload']['input']['payloadDigest'] = 'sha256:' + 'f'*64
        with patch.object(self.account_custody, 'resolve', side_effect=AssertionError('private issuer read')):
            with self.assertRaises(ContractError):
                await owner.reopen_query(canonical_bytes(forged), account_request=self.account_request)

    async def test_closed_consumer_owner_reopens_same_original_observation_on_same_admission(self):
        admission = await self.ready()
        journal = await self.open(admission)
        from capability_owner.ordinary_secret import OrdinarySecretOwner
        from capability_owner.secret_consumer import AtlassianAccountCheckConsumer, SecretConsumerObservation
        from native_security.ordinary_secret_custody import OrdinarySecretCustody
        def consumer_owner(selected):
            signer = journal_fixture.SecretJournalTests.phase_signer(self, selected)
            custody = OrdinarySecretCustody(self.root, self.service.reader)
            consumer = AtlassianAccountCheckConsumer(self.service.reader, self.enrollment)
            owner = OrdinarySecretOwner(selected, signer, custody, consumer)
            self.addAsyncCleanup(owner.close)
            return owner, consumer
        original_owner, original_consumer = consumer_owner(journal)
        await journal.prepare(self.outer)
        group = await journal.current()
        dispatch = await original_owner._phases.admit('ordinary-secret-dispatch', group)
        await journal.advance(dispatch)
        group = await journal.current()
        await journal.save_observation(group, SecretConsumerObservation('accepted', 'account_matched'))
        self.assertEqual(group['state']['phase'], 'dispatching')
        original_creation = journal._ledger._identity.created
        await original_owner.close()
        self.assertTrue(journal._closed)
        self.assertIsNone(journal._observations._fd)
        query = await self.fresh_query()
        entity = journal._binding.entity_id
        old_client = admission._resources[entity][1]
        async def failed_close():
            raise RuntimeError('synthetic private close failure')
        with patch.object(old_client, 'close', failed_close):
            with self.assertRaisesRegex(ContractError, 'integration_operator_cleanup_pending'):
                await admission.reopen_query(query, account_request=self.account_request)
        self.assertIs(admission._resources[entity][0], journal)
        self.assertIn(old_client, admission._clients)
        self.assertFalse(old_client.closed)
        selected = await admission.reopen_query(query, account_request=self.account_request)
        self.assertTrue(old_client.closed)
        self.assertNotIn(old_client, admission._clients)
        recovery_owner, recovery_consumer = consumer_owner(selected)
        receipt = await recovery_owner.recover_query(query)
        self.assertEqual(receipt['outcome'], 'accepted')
        self.assertIsNot(selected, journal)
        self.assertEqual(selected._ledger._identity.created, original_creation)
        self.assertEqual((await selected.current())['latest'].sequence, 3)
        self.assertEqual(self.broker.creates, 1)
        self.assertEqual(len(original_consumer._entries), 0)
        self.assertEqual(len(recovery_consumer._entries), 0)

    async def test_workspace_original_keeps_exact_journal_scope_with_project_account_custody(self):
        await self.ready()
        workspace = {**strict_loads(self.policy.scope), 'workspaceId': 'workspace-one'}
        def grant_workspace(state):
            for actor in ('human', 'custody'):
                state['memberships'].append({'ref': ref(actor+'-workspace-member'),
                    'identityRef': ref(actor), 'scope': workspace, 'status': 'active'})
            for grant in state['grants']:
                if grant['ref']['id'] in ('ordinary-use-grant', 'ordinary-resolve-grant'):
                    grant['scope'] = copy.deepcopy(workspace)
        self.change_current(grant_workspace)
        envelope = strict_loads(self.outer)
        original = envelope['payload']['originalEnvelope']
        envelope['payload']['scope'] = workspace
        for value in (original, envelope):
            value['operation']['scope'] = copy.deepcopy(workspace)
            value['operation']['payloadDigest'] = payload_digest(value['payload'])
            value['ingressAttestation']['claims']['operation'] = copy.deepcopy(value['operation'])
            value['ingressAttestation']['signature'] = sign_claims(value['ingressAttestation']['claims'], SEED)
        self.outer = canonical_bytes(envelope)
        policy = replace(self.policy, scope=canonical_bytes(workspace), namespace='WORKSPACE')
        owner = self.new_admission(policy=policy)
        journal = await self.open(owner)
        self.assertEqual(journal._binding.scope, canonical_bytes(workspace))
        self.assertIn('.w.workspace-one.', journal._ledger._subject)
        await journal.prepare(self.outer)
        self.assertIs(await self.open(owner), journal)
        query = await self.fresh_query()
        self.assertIs(await owner.reopen_query(query, account_request=self.account_request), journal)
        await owner.close()
        replacement = self.new_admission(policy=policy)
        reopened = await self.open(replacement)
        self.assertEqual((await reopened.current())['latest'].sequence, 1)
        self.assertIs(await replacement.reopen_query(query, account_request=self.account_request), reopened)
        for scope in ({**workspace, 'workspaceId': 'sibling-workspace'},
                {**workspace, 'projectId': 'other-project'}):
            wrong = copy.deepcopy(envelope)
            inner = wrong['payload']['originalEnvelope']
            wrong['payload']['scope'] = scope
            for value in (inner, wrong):
                value['operation']['scope'] = scope
                value['operation']['payloadDigest'] = payload_digest(value['payload'])
                value['ingressAttestation']['claims']['operation'] = copy.deepcopy(value['operation'])
                value['ingressAttestation']['signature'] = sign_claims(value['ingressAttestation']['claims'], SEED)
            with self.assertRaises(ContractError):
                await self.open(replacement, canonical_bytes(wrong))
        for scope in (workspace, {**workspace, 'workspaceId': None, 'projectId': 'other-project'}):
            request = strict_loads(self.account_request)
            request['payload']['scope'] = scope
            request['operation']['scope'] = scope
            request['operation']['payloadDigest'] = payload_digest(request['payload'])
            request['ingressAttestation']['claims']['operation'] = copy.deepcopy(request['operation'])
            request['ingressAttestation']['signature'] = sign_claims(request['ingressAttestation']['claims'], SEED)
            with patch.object(self.account_custody, 'resolve', side_effect=AssertionError('private account read')):
                with self.assertRaises(ContractError):
                    await replacement.open(self.outer, account_request=canonical_bytes(request))
        self.assertEqual(self.broker.creates, 1)

    async def test_current_signed_query_cannot_change_an_empty_original_on_cached_or_cold_open(self):
        owner = await self.ready()
        journal = await self.open(owner)
        self.assertIsNone(await journal.current())
        query = await self.fresh_query()
        wrong = journal_fixture.SecretJournalTests.resign_query(query, lambda envelope:
            envelope['payload']['input'].update(payloadDigest='sha256:' + 'f'*64))
        decision = await self.service.reader.evaluate(wrong,
            audience={'hubId': 'hub-one', 'serviceId': 'outcome-owner'})
        self.assertEqual(decision.outcome, 'allowed', decision.reason)
        with patch.object(self.account_custody, 'resolve', side_effect=AssertionError('private issuer read')):
            with self.assertRaisesRegex(ContractError, 'secret_journal_assignment_conflict'):
                await owner.reopen_query(wrong, account_request=self.account_request)
        await owner.close()
        cold = self.new_admission()
        with patch.object(self.account_custody, 'resolve', side_effect=AssertionError('private issuer read')):
            with self.assertRaisesRegex(ContractError, 'secret_journal_assignment_conflict'):
                await cold.reopen_query(wrong, account_request=self.account_request)
        correct = await cold.reopen_query(query, account_request=self.account_request)
        self.assertIsNone(await correct.current())
        self.assertEqual(self.broker.creates, 1)

    async def test_fresh_query_opens_existing_without_use_proof_or_capacity(self):
        owner = await self.ready()
        journal = await self.open(owner)
        await journal.prepare(self.outer)
        query = await self.fresh_query()
        await owner.close()
        replacement = self.new_admission()
        with patch.object(self.custody, 'authorize', side_effect=AssertionError('historical use proof')):
            reopened = await replacement.reopen_query(query, account_request=self.account_request)
        self.assertEqual((await reopened.current())['latest'].sequence, 1)
        self.assertEqual(self.broker.creates, 1)
        before = list(self.inventory.rglob('*'))
        missing = strict_loads(query)
        missing['payload']['input']['operationId'] = 'never-admitted'
        with self.assertRaises(ContractError):
            await replacement.reopen_query(canonical_bytes(missing), account_request=self.account_request)
        self.assertEqual(list(self.inventory.rglob('*')), before)
        self.assertEqual(self.broker.creates, 1)


if __name__ == '__main__':
    unittest.main()
