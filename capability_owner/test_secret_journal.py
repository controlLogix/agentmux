"""Ordinary journal lineage and custody evidence using the existing offline owner."""
import asyncio
import copy
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from capability_owner.secret_consumer import AtlassianAccountCheckEnrollment, SecretConsumerObservation
from capability_owner.secret_consumer import AtlassianAccountCheckConsumer
from capability_owner.ordinary_secret import OrdinarySecretOwner
from capability_owner.secret_journal import PHASE_CONTRACTS, SecretOperationJournal, SecretPhaseSigner, secret_use_identity
from identity import test_service as service_fixture
from identity.test_authority import ref, SEED
from native_security import test_ordinary_secret_custody as custody_fixture
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED


class SecretJournalTests(unittest.IsolatedAsyncioTestCase):
    request = custody_fixture.OrdinaryCustodyTests.request
    store = custody_fixture.OrdinaryCustodyTests.store
    proposal = custody_fixture.OrdinaryCustodyTests.proposal
    enrolled = custody_fixture.OrdinaryCustodyTests.enrolled
    change_current = custody_fixture.OrdinaryCustodyTests.change_current
    revoke = custody_fixture.OrdinaryCustodyTests.revoke

    @classmethod
    def setUpClass(cls):
        cls.cert_directory = tempfile.TemporaryDirectory(prefix='agentmux-secret-journal-roots-')
        root = Path(cls.cert_directory.name)
        config = root / 'fixture.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n'
            '[dn]\nCN=localhost\n[v3]\nbasicConstraints=critical,CA:TRUE\n')
        certificate = root / 'ca.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(root / 'key.pem'), '-out', str(certificate), '-days', '1', '-config', str(config)],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15, env={'PATH': '/usr/bin:/bin'})
        cls.pem = certificate.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.cert_directory.cleanup()

    def setUp(self):
        custody_fixture.OrdinaryCustodyTests.setUp(self)
        patch('capability_owner.secret_journal.datetime', service_fixture._Clock).start()
        patch('identity.authority._utc_now', return_value=service_fixture.NOW).start()
        state = self.record['state']
        grant = next(row for row in state['grants'] if row['ref'] == ref('ordinary-resolve-grant'))
        for name in PHASE_CONTRACTS:
            state['grants'].append({**copy.deepcopy(grant), 'ref': ref(name), 'contractId': name})
        self.store()
        original = strict_loads(self.outer)['payload']['originalEnvelope']['operation']
        self.binding = OwnerBinding('hub-one', 'ordinary-secret-uses',
            secret_use_identity(original['scope'], original['operationId']),
            'effect', canonical_bytes(original['scope']))
        self.journal_js = FakeJetStream(self.policy)
        self.journal_js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(self.binding))

    async def ready(self):
        use = await self.enrolled()
        enrollment = AtlassianAccountCheckEnrollment((await self.custody.check(use)).record,
            'https://fixture.example.test', 'cloud', 'fixture@example.test', 'expected', self.pem)
        self.enrollment = enrollment
        self.journal = self.open_journal()
        self.signer = self.phase_signer(self.journal)
        return self.journal

    def open_journal(self):
        ledger = OwnerLedger(self.journal_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        journal = SecretOperationJournal(ledger, self.service.reader,
            enrollment=self.enrollment, observation_root=self.root)
        self.addAsyncCleanup(journal.close)
        return journal

    def phase_signer(self, journal):
        return SecretPhaseSigner(journal, self.service.ingress, transport_ref=ref('custody-transport'),
            grants={name: ref(name) for name in PHASE_CONTRACTS}, signing_seed=bytes(reversed(SEED)))

    async def dispatch(self):
        await self.journal.prepare(self.outer)
        group = await self.journal.current()
        raw = await self.signer.admit('ordinary-secret-dispatch', group)
        transition = await self.journal.advance(raw)
        self.assertTrue(transition.acknowledged)
        return await self.journal.current()

    async def fresh_query(self):
        def grant(state):
            if not any(row['ref'] == ref('fresh-recovery-grant') for row in state['grants']):
                state['grants'].append({**copy.deepcopy(next(row for row in state['grants']
                    if row['ref'] == ref('ordinary-use-grant'))), 'ref': ref('fresh-recovery-grant'),
                    'contractId': 'capability-outcome-query'})
        self.change_current(grant)
        original = strict_loads(self.outer)['payload']['originalEnvelope']['operation']
        claims = {**copy.deepcopy(self.claims), 'operationId': 'fresh-current-secret-query',
            'grantRef': ref('fresh-recovery-grant'), 'expectedVersion': 1,
            'contractId': 'capability-outcome-query', 'payload': {'resourceRef': ref('ordinary-one'),
                'input': {'contractId': 'capability-secret-use', 'operationId': original['operationId'],
                    'payloadDigest': original['payloadDigest']}}}
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        admitted = await self.service.ingress.admit(request, cancellation_ref=ref('fresh-query-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        return admitted.envelope

    def query_owner(self):
        consumer = AtlassianAccountCheckConsumer(self.service.reader, self.enrollment)
        owner = OrdinarySecretOwner(self.journal, self.signer, self.custody, consumer)
        self.addAsyncCleanup(owner.close)
        return owner

    @staticmethod
    def resign_query(raw, mutate):
        envelope = strict_loads(raw)
        mutate(envelope)
        envelope['operation']['payloadDigest'] = payload_digest(envelope['payload'])
        envelope['ingressAttestation']['claims']['operation'] = copy.deepcopy(envelope['operation'])
        envelope['ingressAttestation']['signature'] = sign_claims(envelope['ingressAttestation']['claims'], SEED)
        return canonical_bytes(envelope)

    async def test_original_target_revision_is_not_an_artificial_journal_revision(self):
        await self.ready()
        transition = await self.journal.prepare(self.outer)
        self.assertEqual(transition.stored.sequence, 1)
        record = strict_loads(transition.stored.record)
        self.assertEqual(record['operation']['expectedVersion'], 1)
        self.assertEqual(record['previousRevision'], 0)
        self.assertEqual(record['state']['resourceRef'], ref('ordinary-one'))
        self.assertTrue(transition.acknowledged)
        replay = await self.journal.prepare(self.outer)
        self.assertTrue(replay.replayed)
        self.assertFalse(replay.acknowledged)

    async def test_exact_private_observation_required_for_completion(self):
        await self.ready()
        group = await self.dispatch()
        raw = await self.signer.admit('ordinary-secret-complete', group, observation_id='fabricated')
        with self.assertRaisesRegex(ContractError, 'ordinary_secret_observation_required'):
            await self.journal.advance(raw)
        observed = SecretConsumerObservation('accepted', 'account_matched')
        identity = await self.journal.save_observation(group, observed)
        phase = await self.signer.admit('ordinary-secret-complete', group, observation_id=identity)
        result = await self.journal.advance(phase)
        self.assertTrue(result.acknowledged)
        self.assertEqual((await self.journal.current())['state']['outcome'], 'accepted')
        replay = await self.journal.advance(phase)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(self.journal_js.messages), 3)

    async def test_current_service_completion_survives_generation_retirement(self):
        await self.ready()
        group = await self.dispatch()
        observed = SecretConsumerObservation('accepted', 'account_matched')
        identity = await self.journal.save_observation(group, observed)
        self.change_current(lambda state: next(row for row in state['ordinarySecretReferences']
            if row['ref']['id'] == 'ordinary-one').update(status='revoked',
                ref={**ref('ordinary-one'), 'revision': 2}))
        self.revoke(name='ordinary-use-grant')
        phase = await self.signer.admit('ordinary-secret-complete', group, observation_id=identity)
        await self.journal.advance(phase)
        with self.assertRaises(ContractError): await self.journal.authorize(self.outer)
        self.assertEqual((await self.journal.current())['state']['outcome'], 'accepted')

    async def test_current_service_revocation_refuses_phase_commit(self):
        await self.ready()
        await self.journal.prepare(self.outer)
        group = await self.journal.current()
        phase = await self.signer.admit('ordinary-secret-dispatch', group)
        self.revoke(name='ordinary-secret-dispatch')
        with self.assertRaises(ContractError): await self.journal.advance(phase)
        self.assertEqual(len(self.journal_js.messages), 1)

    async def test_signed_wrong_claim_original_and_enrollment_never_advance(self):
        await self.ready()
        await self.journal.prepare(self.outer)
        group = await self.journal.current()
        phase = strict_loads(await self.signer.admit('ordinary-secret-dispatch', group))
        for key, value in (('claimRef', ref('foreign-claim')),
                ('originalPayloadDigest', 'sha256:'+'a'*64), ('enrollmentDigest', 'sha256:'+'b'*64)):
            wrong = copy.deepcopy(phase)
            wrong['payload'][key] = value
            wrong['operation']['payloadDigest'] = payload_digest(wrong['payload'])
            claims = wrong['ingressAttestation']['claims']
            claims['operation'] = copy.deepcopy(wrong['operation'])
            wrong['ingressAttestation']['signature'] = sign_claims(claims, SEED)
            with self.subTest(field=key), self.assertRaises(ContractError):
                await self.journal.advance(canonical_bytes(wrong))
        self.assertEqual(len(self.journal_js.messages), 1)

    async def test_retained_original_from_competing_instance_is_not_this_ack(self):
        await self.ready()
        other = self.open_journal()
        original = self.journal._ledger.append
        async def append(record, **kwargs):
            await other.prepare(self.outer)
            return await original(record, **kwargs)
        with patch.object(self.journal._ledger, 'append', append):
            result = await self.journal.prepare(self.outer)
        self.assertFalse(result.acknowledged)
        self.assertTrue(result.replayed)
        self.assertEqual(len(self.journal_js.messages), 1)

    async def test_observation_is_create_or_match_and_bound_to_original_dispatch(self):
        await self.ready()
        group = await self.dispatch()
        accepted = SecretConsumerObservation('accepted', 'account_matched')
        identity = await self.journal.save_observation(group, accepted)
        self.assertEqual(await self.journal.save_observation(group, accepted), identity)
        self.assertEqual(await self.journal.load_observation(group), accepted)
        with self.assertRaises(ContractError):
            await self.journal.save_observation(group, SecretConsumerObservation('rejected', 'http_refused'))
        wrong = copy.deepcopy(group)
        wrong['state']['originalRequestDigest'] = 'sha256:' + 'c'*64
        with self.assertRaises(ContractError): await self.journal.load_observation(wrong)
        wrong = copy.deepcopy(group)
        wrong['state']['dispatchRef']['id'] = 'different-dispatch'
        self.assertIsNone(await self.journal.load_observation(wrong))

    async def test_retained_phase_lineage_tampering_is_refused(self):
        await self.ready()
        await self.dispatch()
        retained = self.journal_js.messages[-1]
        original = retained.data
        for mutate in (lambda state: state['claimRef'].update(id='other'),
                lambda state: state.update(outcome='accepted'),
                lambda state: state['phaseEnvelope'].update(destinationServiceId='other-owner')):
            value = strict_loads(original)
            mutate(value['state'])
            retained.data = canonical_bytes(value)
            with self.assertRaises(ContractError): await self.journal.current()
        retained.data = original

    async def test_fresh_query_recovers_original_after_its_proof_expires(self):
        """A separate current query reads the unchanged historical effect."""
        await self.ready()
        group = await self.dispatch()
        identity = await self.journal.save_observation(group,
            SecretConsumerObservation('accepted', 'account_matched'))
        phase = await self.signer.admit('ordinary-secret-complete', group, observation_id=identity)
        await self.journal.advance(phase)
        self.change_current(lambda state: state['grants'].append({**copy.deepcopy(next(
            row for row in state['grants'] if row['ref'] == ref('ordinary-use-grant'))),
            'ref': ref('fresh-recovery-grant'), 'contractId': 'capability-outcome-query'}))
        original = strict_loads(self.outer)['payload']['originalEnvelope']['operation']
        later = datetime.fromisoformat(original['deadline']) + timedelta(seconds=1)
        class Later(service_fixture._Clock):
            @classmethod
            def now(cls, tz=None): return later
        consumer = AtlassianAccountCheckConsumer(self.service.reader, self.enrollment)
        owner = OrdinarySecretOwner(self.journal, self.signer, self.custody, consumer)
        self.addAsyncCleanup(owner.close)
        claims = {**copy.deepcopy(self.claims), 'operationId': 'fresh-current-secret-query',
            'grantRef': ref('fresh-recovery-grant'), 'expectedVersion': 1,
            'contractId': 'capability-outcome-query', 'payload': {'resourceRef': ref('ordinary-one'),
                'input': {'contractId': 'capability-secret-use', 'operationId': original['operationId'],
                    'payloadDigest': original['payloadDigest']}},
            'issuedAt': later.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (later + timedelta(seconds=20)).isoformat().replace('+00:00', 'Z')}
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        with patch('identity.ingress.datetime', Later), patch('identity.ordinary_secret.datetime', Later), \
                patch('identity.authority._utc_now', return_value=later), \
                patch('capability_owner.secret_journal.datetime', Later):
            query = await self.service.ingress.admit(request, cancellation_ref=ref('fresh-query-cancel'))
            self.assertEqual(query.decision.outcome, 'allowed', query.decision.reason)
            current = await self.service.reader.evaluate(query.envelope,
                audience={'hubId': 'hub-one', 'serviceId': 'outcome-owner'})
            self.assertEqual(current.outcome, 'allowed', current.reason)
            with self.assertRaises(ContractError): await owner.recover(self.outer)
            receipt = await owner.recover_query(query.envelope)
            self.assertEqual(receipt['outcome'], 'accepted')
            self.assertEqual(receipt['receiptRef'], self.journal.ref((await self.journal.current())['latest']))
            reply = await owner.reconcile(query.envelope)
            self.assertEqual(reply['outcome'], 'committed')
            self.assertEqual(reply['recordRef'], receipt['receiptRef'])
        self.assertEqual((await self.journal.current())['state']['outcome'], 'accepted')
        self.assertFalse(consumer._entries)

    async def test_query_absent_pending_and_physical_uncertain_never_claim_committed(self):
        await self.ready()
        owner = self.query_owner()
        query = await self.fresh_query()
        self.assertIsNone(await owner.recover_query(query))
        self.assertEqual((await owner.reconcile(query))['outcome'], 'absent')
        self.assertFalse(self.journal_js.messages)
        await self.journal.prepare(self.outer)
        self.assertEqual((await owner.recover_query(query))['outcome'], 'uncertain')
        with self.assertRaisesRegex(ContractError, 'ordinary_secret_outcome_uncertain'):
            await owner.reconcile(query)
        group = await self.journal.current()
        phase = await self.signer.admit('ordinary-secret-dispatch', group)
        await self.journal.advance(phase)
        self.assertEqual((await owner.recover_query(query))['outcome'], 'uncertain')
        with self.assertRaises(ContractError): await owner.reconcile(query)
        group = await self.journal.current()
        identity = await self.journal.save_observation(group,
            SecretConsumerObservation('uncertain', 'transport_uncertain'))
        phase = await self.signer.admit('ordinary-secret-complete', group, observation_id=identity)
        await self.journal.advance(phase)
        self.assertEqual((await owner.recover_query(query))['outcome'], 'uncertain')
        with self.assertRaises(ContractError): await owner.reconcile(query)
        self.assertFalse(owner._consumer._entries)

    async def test_query_rejected_maps_original_record_without_private_material_or_http(self):
        await self.ready()
        group = await self.dispatch()
        await self.journal.save_observation(group, SecretConsumerObservation('rejected', 'http_refused'))
        owner, query = self.query_owner(), await self.fresh_query()
        with patch.object(self.custody, '_material', side_effect=AssertionError('must not read material')), \
                patch.object(owner._consumer, 'prepare', side_effect=AssertionError('must not prepare HTTP')):
            receipt = await owner.recover_query(query)
            self.assertEqual(receipt['outcome'], 'rejected')
            result = await owner.reconcile(query)
        self.assertEqual((result['outcome'], result['recordRef']), ('rejected', receipt['receiptRef']))
        self.assertEqual(len(self.journal_js.messages), 3)

    async def test_query_current_grants_hard_denials_transport_and_identities_are_required(self):
        await self.ready()
        group = await self.dispatch()
        await self.journal.save_observation(group, SecretConsumerObservation('accepted', 'account_matched'))
        owner, query = self.query_owner(), await self.fresh_query()
        await owner.recover_query(query)
        saved = self.js.messages[-1].data
        for collection, name in (('grants', 'fresh-recovery-grant'), ('grants', 'ordinary-use-grant'),
                ('transports', 'transport'), ('identities', 'human'), ('identities', 'custody'),
                ('identities', 'consumer'), ('memberships', 'ordinary-caller-member')):
            self.js.messages[-1].data = saved
            self.revoke(collection, name)
            with self.subTest(collection=collection, name=name), self.assertRaises(ContractError):
                await owner.recover_query(query)
        for contract in ('capability-outcome-query', 'capability-secret-use'):
            self.js.messages[-1].data = saved
            def deny(state):
                allowed = next(row for row in state['grants'] if row['contractId'] == contract)
                state['grants'].append({**copy.deepcopy(allowed), 'ref': ref('hard-query-denial'),
                                        'decision': 'denied'})
            self.change_current(deny)
            with self.subTest(contract=contract), self.assertRaises(ContractError):
                await owner.recover_query(query)
        self.js.messages[-1].data = saved

    async def test_signed_query_substitutions_and_post_read_revocation_refuse(self):
        await self.ready()
        group = await self.dispatch()
        await self.journal.save_observation(group, SecretConsumerObservation('accepted', 'account_matched'))
        owner, query = self.query_owner(), await self.fresh_query()
        await owner.recover_query(query)
        mutations = (
            lambda e: e['payload']['input'].update(payloadDigest='sha256:'+'f'*64),
            lambda e: e['payload']['input'].update(operationId='other-original'),
            lambda e: e['payload']['resourceRef'].update(revision=2),
            lambda e: e['payload']['resourceRef'].update(id='other-generation'),
            lambda e: e['operation']['scope'].update(projectId='other-project'),
            lambda e: e['operation'].update(effectiveActorRef=ref('consumer')),
            lambda e: e['payload']['input'].update(contractId='capability-process-start'))
        for mutate in mutations:
            with self.subTest(change=mutate), self.assertRaises(ContractError):
                await owner.recover_query(self.resign_query(query, mutate))
        original = self.journal.current
        calls = 0
        async def read():
            nonlocal calls
            result = await original()
            calls += 1
            if calls == 1:
                self.revoke(name='fresh-recovery-grant')
            return result
        with patch.object(self.journal, 'current', read):
            with self.assertRaises(ContractError): await owner.recover_query(query)

    async def test_query_offline_expired_new_proof_and_rotated_generation_refuse(self):
        await self.ready()
        group = await self.dispatch()
        await self.journal.save_observation(group, SecretConsumerObservation('accepted', 'account_matched'))
        owner, query = self.query_owner(), await self.fresh_query()
        await owner.recover_query(query)
        async def unavailable(*args, **kwargs): raise OSError('PRIVATE broker text')
        with patch.object(self.js, 'stream_info', unavailable):
            with self.assertRaises(ContractError) as failure:
                await owner.recover_query(query)
        self.assertNotIn('PRIVATE', str(failure.exception))
        class Later(service_fixture._Clock):
            @classmethod
            def now(cls, tz=None): return service_fixture.NOW + timedelta(seconds=40)
        with patch('capability_owner.secret_journal.datetime', Later):
            with self.assertRaises(ContractError): await owner.recover_query(query)
        self.change_current(lambda state: next(row for row in state['ordinarySecretReferences']
            if row['ref']['id'] == 'ordinary-one').update(status='revoked',
                ref={**ref('ordinary-one'), 'revision': 2}))
        with self.assertRaises(ContractError): await owner.recover_query(query)
        self.assertEqual(len(self.journal_js.messages), 3)
        self.assertFalse(owner._consumer._entries)


if __name__ == '__main__':
    unittest.main()
