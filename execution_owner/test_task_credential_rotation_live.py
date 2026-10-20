"""Replace an approved generation through the actual native A/B/C owners."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import sys
from types import SimpleNamespace

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream
from . import test_task_credentials_live as support
from .container import RetainedContainerIntent, TaskContainerAdapter
from .network import SelectedNetwork


class NativeTaskCredentialRotationTests(support.NativeTaskCredentialTests):
    def setUp(self):
        self._replacement_grants_seeded = False
        super().setUp()
        # Select the finite lease before the first reservation or approved plan.
        # Each derived C credential still has its independent 30-second maximum.
        self.profile['limits'].update(maxSeconds=60, offlineSeconds=60)
        # Eight retained 2 MiB streams need more than NSC's decimal 16m.
        self.broker_disk_storage='32m'

    def possession(self, **changes):
        request = strict_loads(super().possession(**changes))
        claims = request['claims']
        issued = datetime.fromisoformat(claims['issuedAt'])
        claims['expiresAt'] = support.stamp(issued+timedelta(seconds=60))
        request['signature'] = sign_claims(claims, bytes(reversed(SEED)))
        return canonical_bytes(request)

    def request(self, contract, *args, **kwargs):
        raw = super().request(contract, *args, **kwargs)
        if contract != 'capability-process-start':
            return raw
        envelope = strict_loads(raw)
        claims = envelope['ingressAttestation']['claims']
        issued = datetime.fromisoformat(claims['issuedAt'])
        end = support.stamp(issued+timedelta(seconds=60))
        envelope['operation']['deadline'] = end
        claims.update(expiresAt=end, operation=copy.deepcopy(envelope['operation']))
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    def sync(self):
        # The inherited offline fixture calls this before copying authority into
        # IDENTITY. Seed only four credential grants and one plan-enrollment grant.
        if not self._replacement_grants_seeded:
            sources = {item['contractId']: item for item in self.record['state']['grants']
                if item['contractId'].startswith('task-credential-') and item['resourceId'] == 'credential'}
            contracts = tuple('task-credential-'+name for name in ('prepare', 'deliver', 'observe', 'retire'))
            if all(contract in sources for contract in contracts):
                if type(self.service.ledger._js) is not FakeJetStream:
                    raise AssertionError('Replacement fixture grants must precede retained authority')
                for contract in contracts:
                    grant = copy.deepcopy(sources[contract])
                    grant.update(ref=ref(contract+'-replacement-grant'), resourceId='credential-next')
                    self.record['state']['grants'].append(grant)
                plan_grant = copy.deepcopy(next(item for item in self.record['state']['grants']
                    if item['ref'] == ref('execution-plan-enroll-grant')))
                plan_grant.update(ref=ref('execution-plan-enroll-replacement-grant'), resourceId='plan-next')
                self.record['state']['grants'].append(plan_grant)
                self._replacement_grants_seeded = True
        super().sync()

    async def phase_for(self, name, *, ledger, credential_ref, run_ref):
        contract = 'task-credential-'+name
        payload = {'credentialRef': credential_ref, 'runRef': run_ref}
        if name == 'prepare':
            payload.update(taskReadGrantRef=ref('worker-read-grant'), taskApprovalRefs=[])
        suffix = '-replacement-grant' if credential_ref == ref('credential-next') else '-grant'
        return self.request(contract, payload, expected=(await ledger.current()).sequence,
            operation=contract+'-'+credential_ref['id'], grantRef=ref(contract+suffix))

    async def rotation_ledger(self, stream, domain, entity, kind):
        binding = OwnerBinding('hub-one', domain, entity, kind, canonical_bytes(self.scope))
        subject = owner_subject(binding)
        js=self.admin.jetstream()
        existing=await js.streams_info();account=await js.account_info()
        expected={'PLAN_NEXT':5,'EXECUTION_NEXT':6,'CREDENTIAL_NEXT':7}
        self.assertEqual(len(existing),expected[stream])
        self.assertTrue(all(item.config.max_bytes==self.policy.max_bytes for item in existing))
        reserved=sum(item.config.max_bytes for item in existing)
        self.assertEqual(account.limits.max_storage,32_000_000)
        self.assertLessEqual(reserved+self.policy.max_bytes,account.limits.max_storage)
        self.assertLessEqual(len(existing)+1,account.limits.max_streams)
        print('Owned rotation storage: '+str({'streamsBefore':len(existing),'reservedBytes':reserved,
            'nextBytes':self.policy.max_bytes,'accountBytes':account.limits.max_storage,
            'streamLimit':account.limits.max_streams}),file=sys.stderr)
        info = await js.add_stream(self.policy.stream_config(stream=stream, subject=subject))
        return OwnerLedger(self.admin.jetstream(), stream=stream, subject=subject, binding=binding,
            retention=self.policy, stream_identity=StreamIdentity(info.created, 0), require_completion_budget=True)

    @staticmethod
    def retained_private(owner, record):
        # Read retained files without pretending expired credentials are usable.
        # Hashes are compared only in memory; no private bytes enter diagnostics.
        with owner._store.access(record['generationRef']) as directory:
            return tuple(hashlib.sha256(owner._store.read(directory, name)).digest()
                for name in ('assignment.json', 'credential.json', 'delivery.json', 'acknowledged.json'))

    def assert_joined(self, owner):
        self.assertFalse(owner._clients or owner._subscriptions or owner._handlers or owner._proofs)
        self.assertFalse(self.real_engine._jobs)

    async def real_read(self, raw):
        result = strict_loads(await self.credentials.inspect_task(raw, self.admission,
            task_inspection=self.inspection(), account_request=self.account_request, intent=self.intent))
        self.assertEqual(result, {'generationRef': self.credential_record['generationRef'],
            'runRef': self.run_ref, 'taskRef': self.credential_record['taskRef'],
            'consumerRef': ref('consumer'), 'status': 'inspected'})
        self.assert_joined(self.credentials)

    async def stop_revoke_retire(self, *, owner, adapter, ledger, run_ref, record):
        self.assert_joined(owner)
        self.assertEqual((await adapter.stop(run_ref)).status, 'terminal')
        self.assert_joined(owner)
        await self.admin_change('identity-revoke', {'authorityId': 'authority-one', 'targetRef': record['transportRef']})
        retire = await self.phase_for('retire', ledger=ledger, credential_ref=record['credentialRef'], run_ref=run_ref)
        result = strict_loads(await owner.retire(retire))
        self.assertEqual(result['phase'], 'retired')
        await adapter.cleanup(run_ref)
        self.assert_joined(owner)
        name = next(iter(adapter._runs.values()))['spec']['name']
        self.assertIsNone(await self.real_engine.find(name))

    async def test_native_new_approved_generation_replaces_retired_original(self):
        self.assertTrue(self._replacement_grants_seeded)
        await self.ready(physical=True)
        await self.deliver()
        await self.credentials.observe(await self.live_phase('observe'))
        await self.real_read(self.deliver_raw)
        old = SimpleNamespace(owner=self.credentials, adapter=self.adapter, ledger=self.credential_ledger,
            admission=self.admission, intent=self.intent, run_ref=self.run_ref,
            record=copy.deepcopy(self.credential_record), prepare=self.prepare_raw,
            deliver=self.deliver_raw, plan=copy.deepcopy(self.plan), plan_ledger=self.plan_ledger)
        original_binding = strict_loads(old.admission.binding)
        original_task_history = tuple(item.record for item in (await self.owner._ledger.current()).records)
        await self.stop_revoke_retire(owner=old.owner, adapter=old.adapter, ledger=old.ledger,
            run_ref=old.run_ref, record=old.record)
        original_history = tuple(item.record for item in (await old.ledger.current()).records)
        original_plan_history = tuple(item.record for item in (await old.plan_ledger.current()).records)
        original_private = self.retained_private(old.owner, old.record)

        # Check retirement before creating the replacement plan. A fresh service
        # command cannot revive the original run.
        with self.assertRaisesRegex(ContractError, '^task_credential_original_mismatch$'):
            await old.owner.prepare(old.prepare, old.admission,
                task_inspection=self.inspection(), account_request=self.account_request)
        old_delivery = await self.phase_for('deliver', ledger=old.ledger,
            credential_ref=old.record['credentialRef'], run_ref=old.run_ref)
        with self.assertRaisesRegex(ContractError, '^task_credential_delivery_already_attempted$'):
            await old.owner.deliver(old_delivery, old.admission, task_inspection=self.inspection(),
                account_request=self.account_request, intent=old.intent)
        with self.assertRaisesRegex(ContractError, '^task_credential_refused$'):
            await old.owner.inspect_task(old_delivery, old.admission, task_inspection=self.inspection(),
                account_request=self.account_request, intent=old.intent)

        # Approve a new immutable profile in its own plan namespace. No task
        # reservation, execution grant, original deadline or offline bound renews.
        self.profile = copy.deepcopy(self.profile)
        self.profile['profileRef'] = {**self.profile['profileRef'], 'revision': self.profile['profileRef']['revision']+1}
        self.profile['credentialRef'] = ref('credential-next')
        self.plan_ledger = await self.rotation_ledger('PLAN_NEXT', 'execution-plans', 'plan-next', 'approved-execution-plan')
        self.plans = self.make_owner()
        self.addAsyncCleanup(self.plans.close)
        sequence = (await self.plan_ledger.current()).sequence
        plan = copy.deepcopy(old.plan)
        plan.update(ref=ref('plan-next'), profile=self.profile,
            issuedAt=support.stamp(datetime.now(timezone.utc)))
        enroll = self.request('execution-plan-enroll', {'plan': plan, 'previousRef': None},
            expected=sequence, operation='approve-replacement-plan',
            grantRef=ref('execution-plan-enroll-replacement-grant'))
        view = await self.plans.handle(enroll, task_inspection=self.inspection())
        self.assertEqual(view.status, 'approved')
        self.plan = plan
        start = self.request('capability-process-start', {'resourceRef': ref('executor'),
            'input': {'planRef': plan['ref']}}, caller='human', expected=1, operation='replacement-start')
        self.admission = await self.plans.admit_start(start, task_inspection=self.inspection())
        binding = strict_loads(self.admission.binding)
        self.run_ref = binding['runRef']
        self.assertNotEqual(self.run_ref, old.run_ref)
        self.assertEqual(binding['taskRef'], old.record['taskRef'])
        self.assertEqual(binding['credentialRef'], ref('credential-next'))
        self.assertEqual(binding['executionValidUntil'], original_binding['executionValidUntil'])
        self.assertLessEqual(self.admission.valid_until, old.admission.valid_until)

        intent_ledger = await self.rotation_ledger('EXECUTION_NEXT', 'execution', self.run_ref['id'], 'attempt')
        first = strict_loads((await old.intent._ledger.current()).records[0].record)
        operation = binding['originalOperation']
        first.update(recordId='replacement-native-intent', entityId=self.run_ref['id'], operation=operation,
            recordedAt=support.stamp(datetime.now(timezone.utc)),
            state={'executionBinding': binding, 'executionPhase': 'start-intent'},
            effects=[{'effectId': 'container-'+self.run_ref['id'].removeprefix('execution-'),
                'contractId': 'execution-container-prepare', 'payloadDigest': payload_digest(binding),
                'grantRef': operation['grantRef'], 'recovery': 'query-before-retry', 'payload': binding}],
            authorizationDecision={'operationId': operation['operationId'], 'decision': 'allowed',
                'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': 'capability-process-start'})
        await intent_ledger.append(first, expected_sequence=0, expected_target_version=1, completion_records=0)
        self.intent = RetainedContainerIntent(intent_ledger, self.admission.binding)
        self.adapter = TaskContainerAdapter(self.plans, self.real_engine, self.host,
            workspace_ref=self.profile['workspaceRef'], network=SelectedNetwork(self.profile['network']['profileRef']))
        self.live_adapter = self.adapter
        self.addAsyncCleanup(self.adapter.close)
        self.credential_ledger = await self.rotation_ledger('CREDENTIAL_NEXT', 'task-credentials', 'credential-next', 'effect')
        self.credentials = self.make_credentials()
        # Refresh only the account service's signed resolve command for the new
        # generation. The human reservation/admission above remains unchanged.
        self.account_request = self.account_envelope()
        prepare = await self.phase_for('prepare', ledger=self.credential_ledger,
            credential_ref=ref('credential-next'), run_ref=self.run_ref)
        prepared = strict_loads(await self.credentials.prepare(prepare, self.admission,
            task_inspection=self.inspection(), account_request=self.account_request))
        self.credential_record = prepared['record']
        await self.admin_change('identity-enroll', prepared['enrollment'])
        self.assertNotEqual(self.credential_record['generationRef'], old.record['generationRef'])
        self.assertNotEqual(self.credential_record['transportRef'], old.record['transportRef'])
        self.assertNotEqual(self.credential_record['userPublicKey'], old.record['userPublicKey'])
        await self.adapter.prepare(self.admission, task_inspection=self.inspection(), intent=self.intent)
        delivery = await self.phase_for('deliver', ledger=self.credential_ledger,
            credential_ref=ref('credential-next'), run_ref=self.run_ref)
        await self.credentials.deliver(delivery, self.admission, task_inspection=self.inspection(),
            account_request=self.account_request, intent=self.intent)
        observe = await self.phase_for('observe', ledger=self.credential_ledger,
            credential_ref=ref('credential-next'), run_ref=self.run_ref)
        await self.credentials.observe(observe)
        await self.real_read(delivery)

        authority = strict_loads((await self.service.reader.current()).record)['state']
        transports = {canonical_bytes(item['ref']): item for item in authority['transports']}
        # The identity owner's tombstone advances the original transport ref.
        revoked_original={**old.record['transportRef'],'revision':old.record['transportRef']['revision']+1}
        self.assertNotIn(canonical_bytes(old.record['transportRef']),transports)
        self.assertEqual(transports[canonical_bytes(revoked_original)]['status'], 'revoked')
        self.assertEqual(transports[canonical_bytes(self.credential_record['transportRef'])]['status'], 'active')
        with self.assertRaises(ContractError):
            await old.owner.prepare(old.prepare, old.admission,
                task_inspection=self.inspection(), account_request=self.account_request)
        old_delivery = await self.phase_for('deliver', ledger=old.ledger,
            credential_ref=old.record['credentialRef'], run_ref=old.run_ref)
        with self.assertRaisesRegex(ContractError, '^task_credential_delivery_already_attempted$'):
            await old.owner.deliver(old_delivery, old.admission, task_inspection=self.inspection(),
                account_request=self.account_request, intent=old.intent)
        with self.assertRaisesRegex(ContractError, '^task_credential_refused$'):
            await old.owner.inspect_task(old_delivery, old.admission, task_inspection=self.inspection(),
                account_request=self.account_request, intent=old.intent)
        self.assertTrue(tuple(item.record for item in (await old.ledger.current()).records) == original_history,
            'Replacement changed the retired original history')
        self.assertTrue(tuple(item.record for item in (await old.plan_ledger.current()).records) == original_plan_history,
            'Replacement changed the original approved plan history')
        self.assertTrue(tuple(item.record for item in (await self.owner._ledger.current()).records) == original_task_history,
            'Replacement changed the original task reservation or execution grant')
        self.assertTrue(self.retained_private(old.owner, old.record) == original_private,
            'Replacement changed the retired private generation')
        self.assertEqual(old.owner._history(await old.ledger.current())['phase'], 'retired')
        self.assert_joined(old.owner)
        await self.stop_revoke_retire(owner=self.credentials, adapter=self.adapter, ledger=self.credential_ledger,
            run_ref=self.run_ref, record=self.credential_record)


for _name in dir(support.NativeTaskCredentialTests):
    if _name.startswith('test_') and _name not in vars(NativeTaskCredentialRotationTests):
        setattr(NativeTaskCredentialRotationTests, _name, None)
