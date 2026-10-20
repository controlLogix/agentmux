"""AMUX-683: fresh operation admission on the actual native TLS/JWT broker.

Run only with the coordinator's serialized native slot. The real identity owner,
source custody, account custody, paired NATS clients and approved HTTPS consumer
remain in use. Faults discard exact real broker acknowledgments after commit.
"""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import secrets
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from capability_owner.ordinary_secret import OrdinarySecretOwner
from capability_owner.secret_consumer import AtlassianAccountCheckConsumer
from capability_owner.secret_journal import PHASE_CONTRACTS, SecretPhaseSigner
from capability_owner.secret_journal_admission import SecretJournalAdmission, SecretJournalPolicy, _issue
from capability_owner.test_live import packet, stamp
from capability_owner import test_ordinary_secret_live as ordinary_fixture
from identity.test_authority import ref, SEED
from identity.test_ordinary_secret import SCOPE
from integration_owner.operator_provisioning import _administrator_subjects
from native_security.secret_custody import ScopedSecretCustody
from state_owner import test_task_live as account_fixture
from state_owner.retention import Retention


class _AccountEnrollmentFixture:
    async def asyncSetUp(self):
        # Use its public enrollment helpers and initial authority without creating
        # a custody object that ordinary-secret setup would immediately replace.
        await account_fixture.LiveTaskTests.asyncSetUp(self)


class LiveSecretJournalAdmissionTests(ordinary_fixture.LiveOrdinarySecretOwnerTests,
        _AccountEnrollmentFixture, account_fixture.LiveApplicationAccountCustodyTests):
    broker_stream_limit = 5
    def secret_scope(self):
        if self._testMethodName == 'test_native_two_fresh_originals_lost_create_ack_restart_and_query':
            return {**SCOPE, 'workspaceId': 'workspace-one'}
        return copy.deepcopy(SCOPE)

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        grant = next(row for row in state['grants'] if row['ref'] == ref('ordinary-use-grant'))
        state['grants'].append({**copy.deepcopy(grant), 'ref': ref('ordinary-query-grant'),
            'contractId': 'capability-outcome-query'})
        scope = self.secret_scope()
        if scope['workspaceId'] is not None:
            for actor in ('human', 'custody'):
                state['memberships'].append({'ref': ref(actor+'-workspace-member'),
                    'identityRef': ref(actor), 'scope': copy.deepcopy(scope), 'status': 'active'})
            for row in state['grants']:
                if row['ref']['id'] in ('ordinary-use-grant', 'ordinary-resolve-grant',
                        'ordinary-query-grant', *PHASE_CONTRACTS):
                    row['scope'] = copy.deepcopy(scope)
        return initial

    async def asyncSetUp(self):
        await super().asyncSetUp()
        asyncio.get_running_loop().slow_callback_duration = 10
        self.admissions = []
        account_root = self.directory / 'application-account-secrets'
        account_root.mkdir(mode=0o700)
        self.account_custody = ScopedSecretCustody(account_root, self.identity.reader)
        self.inventory = self.directory / 'journal-admission'
        self.inventory.mkdir(mode=0o700)
        self.addAsyncCleanup(self.close_admissions)
        self.admission_policy = SecretJournalPolicy('NATIVE', canonical_bytes(self.secret_scope()), self.account_public_key,
            self.broker.url, self.server_name, self.ca_file.read_bytes(), self.leaf_digest,
            Retention(1_048_576, 262_144), 2, 2_097_152)

    async def close_admissions(self):
        # Existing owner cleanup joins its exact consumer before admission releases
        # the broker connection or private selection pins.
        await self.cleanup_ordinary()
        for owner in self.admissions:
            await owner.close()
            self.assertFalse(owner._tasks)
            self.assertIsNone(owner._inventory._fd)
        # ScopedSecretCustody has no retained descriptor or close operation. Its
        # methods open and close each exact source synchronously. Release this
        # borrowed reference after every admission operation and client joins.
        self.account_custody = None

    async def stage_administrator(self):
        seed = self.account_issuer_seed()
        administrator = _issue(seed, _administrator_subjects(None),
            '_INBOX.secret_administrator_0001', valid_until=datetime.now(timezone.utc) + timedelta(minutes=2))
        payload = self.account_payload(1)
        version = (await self.identity.ledger.current()).sequence
        raw = await self.identity_request('identity-application-account-set', 'application-account-set-grant',
            payload, self.scope, version, 'admission-account-set')
        envelope = await self.custody_envelope(raw)
        for kind, material in (('nats-administrator-credential', administrator), ('nats-account-issuer', seed)):
            await self.account_custody.provision(envelope, kind=kind, secret=material)
        from identity.service import verify_receipt
        receipt = verify_receipt(await self.owner_exchange(raw), raw, public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertEqual(receipt['decision'], 'allowed')

    async def account_request(self, *, lifetime=None):
        payload = {'authorityId': 'authority-one', 'accountRef': ref('application-account'),
            'profileId': 'profile-one', 'scope': SCOPE, 'accountPublicKey': self.account_public_key}
        raw = await self.identity_request('identity-application-account-resolve', 'application-account-resolve-grant',
            payload, SCOPE, 0, 'journal-account-resolve-' + secrets.token_hex(8))
        if lifetime is not None:
            claims = strict_loads(raw)['claims']
            claims['expiresAt'] = stamp(datetime.now(timezone.utc) + timedelta(seconds=lifetime))
            raw = packet(claims, bytes(reversed(SEED)))
        return await self.custody_envelope(raw)

    async def outcome_query(self, original):
        payload = {'resourceRef': ref('ordinary-one'), 'input': {
            'contractId': 'capability-secret-use', 'operationId': original['operationId'],
            'payloadDigest': original['payloadDigest']}}
        raw = await self.possession('capability-outcome-query', payload, grant='ordinary-query-grant', expected=1)
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('fresh-query-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return admitted.envelope

    def new_admission(self):
        owner = SecretJournalAdmission(policy=self.admission_policy, enrollment=self.enrollment,
            authority=self.identity.reader, custody=self.secret_custody, account_custody=self.account_custody,
            inventory_root=self.inventory, observation_root=self.private_root)
        self.admissions.append(owner)
        return owner

    async def original_request(self):
        # Mint each operation through actual ingress; no preselected fixture ID.
        raw = await self.possession('capability-secret-use', {'resourceRef': ref('ordinary-one'),
            'input': {'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one')}},
            grant='ordinary-use-grant', expected=1)
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('fresh-operation-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return strict_loads(admitted.envelope)

    async def resolve_envelope(self, *, changes=None, allow_refusal=False):
        original = await self.original_request()
        payload = {'authorityId': 'authority-one', 'secretRef': ref('ordinary-one'),
            'generationRef': ref('ordinary-one'), 'profileId': 'profile-one', 'scope': self.secret_scope(),
            'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one'), 'originalEnvelope': original}
        payload.update(changes or {})
        raw = await self.possession('identity-ordinary-secret-resolve', payload, actor='custody',
            grant='ordinary-resolve-grant', expected=0)
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('secret-resolve-cancel'))
        if admitted.decision.outcome != 'allowed' and allow_refusal:
            self.assertEqual(admitted.decision.outcome, 'denied')
            return None
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        return admitted.envelope

    def owner_for(self, journal):
        signer = SecretPhaseSigner(journal, self.identity.ingress, transport_ref=ref('custody-transport'),
            grants={name: ref(name) for name in PHASE_CONTRACTS}, signing_seed=bytes(reversed(SEED)))
        consumer = AtlassianAccountCheckConsumer(self.identity.reader, self.enrollment)
        self.consumers.append(consumer)
        owner = OrdinarySecretOwner(journal, signer, self.secret_custody, consumer)
        self.owners.append(owner)
        return owner

    async def test_native_two_fresh_originals_lost_create_ack_restart_and_query(self):
        await self.stage()
        await self.stage_administrator()
        host = self.new_admission()
        first, second = await self.resolve_envelope(), await self.resolve_envelope()
        ids = [strict_loads(raw)['payload']['originalEnvelope']['operation']['operationId'] for raw in (first, second)]
        self.assertNotEqual(*ids)
        # Lose only the real broker's create reply. The retained token must
        # reconcile the exact original stream without a second CREATE.
        from nats.js.client import JetStreamContext
        original_add = JetStreamContext.add_stream
        creates, returned_metadata = [], []
        async def lost_ack(js, config=None, **kwargs):
            result = await original_add(js, config, **kwargs)
            creates.append(result.config.name)
            returned_metadata.append(set(result.config.metadata))
            if len(creates) == 1:
                raise TimeoutError('synthetic private lost create ACK')
            return result
        with patch.object(JetStreamContext, 'add_stream', lost_ack):
            one = await host.open(first, account_request=await self.account_request())
            two = await host.open(second, account_request=await self.account_request())
        self.assertEqual(len(creates), 2)
        self.assertTrue(all('agentmuxSecretJournal' in keys for keys in returned_metadata))
        self.assertTrue(any(keys != {'agentmuxSecretJournal'} for keys in returned_metadata))
        self.assertNotEqual(one._ledger._stream, two._ledger._stream)
        self.assertEqual(one._binding.scope, canonical_bytes(self.secret_scope()))
        self.assertIn('.w.workspace-one.', one._ledger._subject)
        for changes in ({'consumerRef': ref('custody')}, {'purposeRef': ref('wrong-purpose')},
                {'scope': {**self.secret_scope(), 'workspaceId': 'sibling-workspace'}},
                {'scope': {**self.secret_scope(), 'projectId': 'other-project'}}):
            wrong = await self.resolve_envelope(changes=changes, allow_refusal=True)
            if wrong is not None:
                with self.assertRaises(ContractError):
                    await host.open(wrong, account_request=await self.account_request())
        collision_request = strict_loads(await self.possession('capability-secret-use', {
            'resourceRef': ref('ordinary-one'), 'input': {
                'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one')}},
            grant='ordinary-use-grant', expected=1))['claims']
        collision_request['operationId'] = ids[0]
        collision_original = await self.identity.ingress.admit(packet(collision_request, bytes(reversed(SEED))),
            cancellation_ref=ref('fresh-operation-cancel'))
        self.assertEqual(collision_original.decision.outcome, 'allowed')
        collision = await self.resolve_envelope(changes={
            'originalEnvelope': strict_loads(collision_original.envelope)})
        with self.assertRaisesRegex(ContractError, 'secret_journal_assignment_conflict'):
            await host.open(collision, account_request=await self.account_request())
        self.assertIsNone(await one.current())
        self.assertIsNone(await two.current())
        self.assertEqual(self.https_server.requests, [])
        owner_one, owner_two = self.owner_for(one), self.owner_for(two)
        result_one = await owner_one.use(first)
        result_two = await owner_two.use(second)
        self.assertEqual((result_one['outcome'], result_two['outcome']), ('accepted', 'accepted'))
        self.assertEqual(len(self.https_server.requests), 2)
        self.assertEqual(await owner_one.recover(first), result_one)
        self.assertEqual((await one.current())['latest'].sequence, 3)
        self.assertEqual((await two.current())['latest'].sequence, 3)
        # A third original cannot consume more than the enrolled capacity.
        with self.assertRaisesRegex(ContractError, 'secret_journal_capacity_exhausted'):
            await host.open(await self.resolve_envelope(), account_request=await self.account_request())
        for owner in (owner_one, owner_two):
            await owner.close()
        await host.close()
        self.secret_custody = self.new_custody()
        replacement = self.new_admission()
        reopened = await replacement.open(first, account_request=await self.account_request())
        self.assertEqual(reopened._ledger._minimum_sequence, 3)
        self.assertEqual(await self.owner_for(reopened).recover(first), result_one)
        self.assertEqual(len(self.https_server.requests), 2)
        # Independently signed current query opens this journal without invoking
        # historical use authority or allocating another stream.
        query = await self.outcome_query(strict_loads(second)['payload']['originalEnvelope']['operation'])
        with patch.object(self.secret_custody, 'authorize', side_effect=AssertionError('historical use authority')):
            queried = await replacement.reopen_query(query, account_request=await self.account_request())
        query_owner = self.owner_for(queried)
        self.assertEqual(await query_owner.recover_query(query), result_two)
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('ordinary-query-grant')})
        with self.assertRaises(ContractError):
            await replacement.reopen_query(query, account_request=await self.account_request())
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('ordinary-use-grant')})
        with self.assertRaises(ContractError):
            await replacement.open(first, account_request=await self.account_request())
        self.assertEqual((await reopened.current())['latest'].sequence, 3)
        self.assertEqual((await queried.current())['latest'].sequence, 3)
        self.assertEqual(len(self.https_server.requests), 2)
        self.assertFalse(self.errors['identity'])
        self.success = True

    async def test_native_same_owner_renews_expired_jwt_for_current_query(self):
        await self.stage()
        await self.stage_administrator()
        host = self.new_admission()
        raw = await self.resolve_envelope()
        journal = await host.open(raw, account_request=await self.account_request(lifetime=3))
        await journal.prepare(raw)
        entity = journal._binding.entity_id
        _, old_client, expires = host._resources[entity]
        delay = (expires - datetime.now(timezone.utc)).total_seconds()
        if delay > 0:
            await asyncio.sleep(delay + .1)
        query = await self.outcome_query(strict_loads(raw)['payload']['originalEnvelope']['operation'])
        reopened = await host.reopen_query(query, account_request=await self.account_request())
        self.assertIs(reopened, journal)
        self.assertIsNot(host._resources[entity][1], old_client)
        self.assertTrue(old_client.is_closed)
        self.assertEqual((await reopened.current())['latest'].sequence, 1)
        self.assertEqual(self.https_server.requests, [])
        self.success = True


# Reuse fixture methods, while each existing scenario stays in its original owner.
# Ordinary unittest discovery of this module collects only its two new scenarios.
for _fixture in (ordinary_fixture.LiveOrdinarySecretOwnerTests,
        account_fixture.LiveApplicationAccountCustodyTests):
    for _name in dir(_fixture):
        if _name.startswith('test_') and _name not in vars(LiveSecretJournalAdmissionTests):
            setattr(LiveSecretJournalAdmissionTests, _name, None)
del _fixture, _name
