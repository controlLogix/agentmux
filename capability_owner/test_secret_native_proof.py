"""Current native ancestry reaches private custody and the actual stdin task."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, AsyncMock

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from capability_owner.test_secret_consumer import SecretConsumerTests, _TOKEN
from capability_owner.secret_resource import SecretResolveSigner
from capability_owner.secret_journal import SecretOperationJournal, secret_use_identity
from identity.ordinary_secret import NativeSecretProof, OrdinarySecretAuthority
from identity.test_authority import ref, SEED, NOW
from identity.test_native_bridge import native_row, HOST_SEED
from identity.test_ordinary_secret import SCOPE
from identity.test_service import _Clock
from nacl.signing import SigningKey
from native_security.ordinary_secret_custody import OrdinarySecretCustody
from native_security.secret_custody import PrivateSecret
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED


class SecretNativeProofTests(SecretConsumerTests):
    def setUp(self):
        super().setUp()
        clock = patch('capability_owner.secret_resource.datetime', _Clock)
        clock.start()
        self.addCleanup(clock.stop)
        clock = patch('capability_owner.secret_journal.datetime', _Clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.install_native_proof()

    def install_native_proof(self):
        state = self.record['state']
        for name, kind in (('host','service'), ('plugin','plugin'), ('parent-plugin','plugin')):
            state['identities'].append({'ref':ref(name),'kind':kind,'status':'active',
                'principalId':name+'-one','externalIdentity':None})
        state['transports'].append({**copy.deepcopy(state['transports'][0]),
            'ref':ref('host-transport'),'identityRef':ref('host'),
            'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('=')})
        state['memberships'].append({'ref':ref('secret-host-member'),'identityRef':ref('host'),
            'scope':copy.deepcopy(SCOPE),'status':'active'})
        base = copy.deepcopy(state['grants'][0])
        for contract, instance in (('native-authority-prepare-domain-call','plugin-one'),
                                  ('native-authority-recheck','parent-one')):
            state['grants'].append({**copy.deepcopy(base),'ref':ref(instance+'-host'),
                'callerRef':ref('host'),'actorRef':ref('host'),'scope':copy.deepcopy(SCOPE),
                'contractId':contract,'resourceId':instance})
        self.row = native_row()
        facts = self.row['facts']
        facts['grant'].update(scope=copy.deepcopy(SCOPE),actions=['use','inspect'],resourceIds=['ordinary-one'])
        facts['policy'].update(scope=copy.deepcopy(SCOPE),decisions=[{'access':{
            'action':action,'resourceClass':resource,'resourceId':'ordinary-one'},'outcome':'allow'}
            for action,resource in (('use','secret'),('inspect','outcome'))])
        facts['domainBindings']=[{'id':'secret-use','contractId':'capability-secret-use',
            'action':'use','resourceClass':'secret','resourceIds':['ordinary-one']},
            {'id':'secret-outcome','contractId':'capability-outcome-query',
             'action':'inspect','resourceClass':'outcome','resourceIds':['ordinary-one']}]
        facts['secretReferences']=[ref('ordinary-one')]
        self.parent = copy.deepcopy(self.row)
        self.parent.update(ref=ref('native-parent'),identityRef=ref('parent-plugin'))
        self.parent['owner'].update(instanceId='parent-one',epoch='c'*64)
        self.parent['facts']['grant'].update(grantId='parent-grant',subjectInstanceId='parent-one')
        self.parent['facts']['policy']['subjectInstanceId']='parent-one'
        self.row.update(relationship='private',parentOwner=copy.deepcopy(self.parent['owner']))
        facts['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
        facts['grant']['parentGrantRef']=ref('parent-grant')
        facts['parentAccess']=[copy.deepcopy(item['access']) for item in facts['policy']['decisions']]
        state['nativeInstances']=[self.parent,self.row]
        self.js.messages[-1].data = canonical_bytes(self.record)
        outer = strict_loads(self.outer) if type(self.outer) is bytes else self.outer
        original = outer['payload']['originalEnvelope']
        inner = canonical_bytes(original)
        self.raw = canonical_bytes(outer)
        self.wrapper={'purpose':'agentmux-capability-service-request-v1','requestId':original['correlationId'],
            'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one','owner':self.row['owner'],
            'serviceId':'secret-owner','requestContractId':'capability-secret-use',
            'replyContractId':'capability-secret-use-reply','operationId':original['operation']['operationId'],
            'resourceRef':ref('ordinary-one'),'scope':copy.deepcopy(SCOPE),'replySubject':'_INBOX.abcdefghijklmnop',
            'issuedAt':NOW.isoformat().replace('+00:00','Z'),
            'validUntil':(NOW+timedelta(seconds=4)).isoformat().replace('+00:00','Z'),
            'signingKeyRef':ref('issuer'),'hostTransportRef':ref('host-transport'),
            'nativeFactsDigest':payload_digest(facts),'envelopeBytes':base64.b64encode(inner).decode()}
        self.proof = self.native_proof()

    def native_proof(self):
        raw = canonical_bytes({'schemaVersion':'1.0.0','algorithm':'Ed25519',
            'canonicalization':'RFC8785-JCS-UTF8','claims':self.wrapper,
            'signature':sign_claims(self.wrapper,SEED)})
        return NativeSecretProof(raw,canonical_bytes(ref('plugin')),'plugin-one','test-plugin',self.service.ingress)

    def revoke_native_parent(self):
        current = strict_loads(self.js.messages[-1].data)
        next(row for row in current['state']['nativeInstances'] if row['ref']==ref('native-parent'))['status']='revoked'
        self.js.messages[-1].data=canonical_bytes(current)

    async def test_exact_wrapper_and_current_parent_bound_resolution(self):
        authority = OrdinarySecretAuthority(self.service.reader)
        result = await authority.resolve(self.raw,native_proof=self.proof)
        self.assertLessEqual(result.valid_until,NOW+timedelta(seconds=4))
        self.assertEqual(result.original_request_digest,
            payload_digest(self.outer['payload']['originalEnvelope']))
        self.wrapper['resourceRef']=ref('substituted-secret')
        with self.assertRaises(ContractError):
            await authority.resolve(self.raw,native_proof=self.native_proof())
        self.revoke_native_parent()
        with self.assertRaises(ContractError):
            await authority.resolve(self.raw,native_proof=self.proof)

    async def test_internal_resolve_preserves_terminal_original_without_service_session(self):
        original = self.outer['payload']['originalEnvelope']
        original['operation']['terminalSessionId'] = 'opaque-current-session'
        self.resign()
        self.raw = canonical_bytes(self.outer)
        self.wrapper['envelopeBytes'] = base64.b64encode(canonical_bytes(original)).decode()
        self.proof = self.native_proof()
        checked = []
        active = True
        async def authorize(session, caller, scope):
            self.assertEqual((session, caller, scope), ('opaque-current-session', ref('human'), SCOPE))
            checked.append(session)
            if not active:
                raise ContractError('oidc_terminal_session_required')
        self.service.ingress.require_terminal_sessions(authorize)
        signer = SecretResolveSigner(self.service.ingress, enrollment=self.enrollment,
            custody_transport=ref('custody-transport'), custody_seed=bytes(reversed(SEED)),
            resolve_grant=ref('ordinary-resolve-grant'), phase_grants={
                'ordinary-secret-dispatch': ref('dispatch'), 'ordinary-secret-complete': ref('complete')},
            account_transport=ref('transport'), account_seed=bytes(reversed(SEED)),
            account_grant=ref('account-grant'), account_ref=ref('account'), account_public_key='unused')
        resolved = await signer.resolve(canonical_bytes(original), self.proof)
        self.assertEqual(strict_loads(resolved)['payload']['originalEnvelope'], original)
        self.assertTrue(checked)
        self.assertEqual(strict_loads(resolved)['operation']['caller']['kind'], 'service')
        active = False
        with self.assertRaisesRegex(ContractError, '^oidc_terminal_session_required$'):
            await signer.resolve(canonical_bytes(original), self.proof)

    async def test_custody_rechecks_native_parent_before_material_worker(self):
        root=Path(self.directory.name).resolve()
        root.chmod(0o700)
        custody=OrdinarySecretCustody(root,self.service.reader)
        self.addAsyncCleanup(custody.close)
        use=await custody.authorize(self.raw,native_proof=self.proof)
        self.revoke_native_parent()
        with self.assertRaises(ContractError):
            await custody._material(use)
        self.assertEqual(self.server.requests,[])

    async def test_parent_revocation_during_terminal_refresh_refuses(self):
        original = self.outer['payload']['originalEnvelope']
        original['operation']['terminalSessionId'] = 'opaque-current-session'
        self.resign()
        self.raw = canonical_bytes(self.outer)
        self.wrapper['envelopeBytes'] = base64.b64encode(canonical_bytes(original)).decode()
        proof = self.native_proof()
        async def authorize(session, caller, scope):
            self.assertEqual((session, caller, scope), ('opaque-current-session', ref('human'), SCOPE))
            self.revoke_native_parent()
            await asyncio.sleep(0)
        self.service.ingress.require_terminal_sessions(authorize)
        with self.assertRaises(ContractError):
            await OrdinarySecretAuthority(self.service.reader).resolve(self.raw, native_proof=proof)
        self.assertEqual(self.server.requests, [])

    async def test_query_generation_revocation_during_terminal_refresh_refuses(self):
        state = self.record['state']
        grant = next(row for row in state['grants'] if row['ref'] == ref('ordinary-use-grant'))
        state['grants'].append({**copy.deepcopy(grant), 'ref': ref('native-query-grant'),
            'contractId': 'capability-outcome-query'})
        self.store()
        original = self.outer['payload']['originalEnvelope']['operation']
        claims = {**copy.deepcopy(self.claims), 'operationId': 'native-fresh-query',
            'contractId': 'capability-outcome-query', 'grantRef': ref('native-query-grant'),
            'expectedVersion': 1, 'terminalSessionId': 'opaque-current-session',
            'payload': {'resourceRef': ref('ordinary-one'), 'input': {
                'contractId': 'capability-secret-use', 'operationId': original['operationId'],
                'payloadDigest': original['payloadDigest']}}}
        signed = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        admitted = await self.service.ingress.admit(signed, cancellation_ref=ref('query-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        query = strict_loads(admitted.envelope)
        self.wrapper.update(requestId=query['correlationId'], serviceId='outcome-owner',
            requestContractId='capability-outcome-query', replyContractId='capability-outcome-query-reply',
            operationId=query['operation']['operationId'], nativeFactsDigest=payload_digest(self.row['facts']),
            envelopeBytes=base64.b64encode(admitted.envelope).decode())
        proof = self.native_proof()
        root = Path(self.directory.name).resolve()
        root.chmod(0o700)
        binding = OwnerBinding('hub-one', 'ordinary-secret-uses',
            secret_use_identity(SCOPE, original['operationId']), 'effect', canonical_bytes(SCOPE))
        js = FakeJetStream(self.policy)
        js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(binding))
        ledger = OwnerLedger(js, stream='OWNER', subject=owner_subject(binding), binding=binding,
            retention=self.policy, stream_identity=StreamIdentity(CREATED, 0), require_completion_budget=True)
        journal = SecretOperationJournal(ledger, self.service.reader, enrollment=self.enrollment, observation_root=root)
        self.addAsyncCleanup(journal.close)
        refreshed = []
        async def authorize(session, caller, scope):
            self.assertEqual((session, caller, scope), ('opaque-current-session', ref('human'), SCOPE))
            current = strict_loads(self.js.messages[-1].data)
            refreshed.append(True)
            current['state']['ordinarySecretReferences'][0]['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(current)
            await asyncio.sleep(0)
        self.service.ingress.require_terminal_sessions(authorize)
        with self.assertRaises(ContractError):
            await journal.authorize_query(admitted.envelope, native_proof=proof)
        self.assertEqual(refreshed, [True])
        self.assertEqual(self.server.requests, [])

    async def test_actual_send_task_refuses_new_parent_revocation(self):
        original=self.outer['payload']['originalEnvelope']['operation']
        handle=await self.consumer.prepare(self.raw,PrivateSecret(_TOKEN),
            operation_id=original['operationId'],payload_digest=original['payloadDigest'],
            claim_ref='native-send-claim',native_proof=self.proof)
        create_task=asyncio.create_task
        revoked=[]
        def schedule(coroutine,*args,**kwargs):
            if getattr(coroutine,'cr_code',None) is not None and coroutine.cr_code.co_name=='send':
                self.revoke_native_parent()
                revoked.append(True)
            return create_task(coroutine,*args,**kwargs)
        with patch('capability_owner.secret_consumer.asyncio.create_task',side_effect=schedule):
            self.consumer.start(handle)
            with self.assertRaises(ContractError):
                await self.consumer.wait(handle)
        self.assertEqual(revoked,[True])
        self.assertFalse(any(row[2] for row in self.server.requests))
        self.assertTrue(self.consumer._entry(handle).task.done())
        self.assertNotEqual(self.consumer.private_observation(handle).status,'accepted')


from capability_owner.test_secret_journal_admission import SecretJournalAdmissionTests


class SecretQueryAdmissionProofTests(SecretJournalAdmissionTests):
    install_native_proof = SecretNativeProofTests.install_native_proof
    native_proof = SecretNativeProofTests.native_proof

    async def account_signer(self):
        await self.ready()
        self.record = strict_loads(self.js.messages[-1].data)
        self.install_native_proof()
        grant = copy.deepcopy(next(row for row in self.record['state']['grants']
            if row['ref'] == ref('account-resolve-grant')))
        grant.update(ref=ref('secret-account-service-grant'), callerRef=ref('account-admin'), actorRef=ref('account-admin'),
            expiresAt=(NOW+timedelta(seconds=10)).isoformat().replace('+00:00','Z'))
        self.record['state']['grants'].append(grant)
        self.js.messages[-1].data = canonical_bytes(self.record)
        signer = SecretResolveSigner(self.service.ingress, enrollment=self.enrollment,
            custody_transport=ref('custody-transport'), custody_seed=bytes(reversed(SEED)),
            resolve_grant=ref('ordinary-resolve-grant'), phase_grants={
                'ordinary-secret-dispatch': ref('dispatch'), 'ordinary-secret-complete': ref('complete')},
            account_transport=ref('account-admin-transport'), account_seed=bytes(reversed(SEED)),
            account_grant=grant['ref'], account_ref=ref('application-account'), account_public_key=self.account_public)
        return signer, grant

    async def test_account_service_lifetime_does_not_renew_native_use(self):
        from identity.application_account import ApplicationAccountAuthority
        signer, _ = await self.account_signer()
        original = canonical_bytes(strict_loads(self.raw)['payload']['originalEnvelope'])
        with patch('capability_owner.secret_resource.datetime', _Clock):
            account = await signer.account(original, self.proof)
        envelope = strict_loads(account)
        self.assertEqual(envelope['operation']['caller']['kind'], 'service')
        self.assertGreater(datetime.fromisoformat(envelope['operation']['deadline']), NOW+timedelta(seconds=4))
        with patch.object(_Clock, 'now', return_value=NOW+timedelta(seconds=6)):
            resolution = await ApplicationAccountAuthority(self.service.reader).resolve(account)
            self.assertEqual(resolution.account_ref, ref('application-account'))
            self.assertEqual(resolution.valid_until, NOW+timedelta(seconds=10))
            with patch('capability_owner.secret_resource.datetime', _Clock):
                with self.assertRaises(ContractError):
                    await signer.resolve(original, self.proof)
                with self.assertRaises(ContractError):
                    await signer.account(original, self.proof)

    async def test_account_service_and_account_revocation_refuse(self):
        from identity.application_account import ApplicationAccountAuthority
        signer, grant = await self.account_signer()
        original = canonical_bytes(strict_loads(self.raw)['payload']['originalEnvelope'])
        with patch('capability_owner.secret_resource.datetime', _Clock):
            account = await signer.account(original, self.proof)
            grant['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(self.record)
            with self.assertRaises(ContractError):
                await signer.account(original, self.proof)
            grant['status'] = 'active'
            self.record['state']['applicationAccounts'][0]['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(self.record)
            with self.assertRaises(ContractError):
                await ApplicationAccountAuthority(self.service.reader).resolve(account)

    async def test_account_service_checks_actual_terminal_operation(self):
        signer, _ = await self.account_signer()
        envelope = strict_loads(self.raw)
        original = envelope['payload']['originalEnvelope']
        original['operation']['terminalSessionId'] = 'opaque-current-session'
        original['ingressAttestation']['claims']['operation'] = copy.deepcopy(original['operation'])
        original['ingressAttestation']['signature'] = sign_claims(original['ingressAttestation']['claims'], SEED)
        raw = canonical_bytes(original)
        self.wrapper['envelopeBytes'] = base64.b64encode(raw).decode()
        proof = self.native_proof()
        active = True
        async def authorize(session, caller, scope):
            self.assertEqual((session,caller,scope),('opaque-current-session',ref('human'),SCOPE))
            if not active:
                raise ContractError('oidc_terminal_session_required')
        self.service.ingress.require_terminal_sessions(authorize)
        with patch('capability_owner.secret_resource.datetime', _Clock):
            account = await signer.account(raw, proof)
            self.assertEqual(strict_loads(account)['operation']['caller']['kind'], 'service')
            active = False
            with patch.object(signer._ingress, 'admit', new=AsyncMock()) as internal:
                with self.assertRaisesRegex(ContractError, '^oidc_terminal_session_required$'):
                    await signer.account(raw, proof)
                internal.assert_not_awaited()

    async def test_account_signer_refuses_human_transport(self):
        signer, _ = await self.account_signer()
        signer._account_transport = canonical_bytes(ref('transport'))
        signer._account_grant = canonical_bytes(ref('account-resolve-grant'))
        original = canonical_bytes(strict_loads(self.raw)['payload']['originalEnvelope'])
        with patch('capability_owner.secret_resource.datetime', _Clock):
            with self.assertRaisesRegex(ContractError, '^capability_secret_unavailable$'):
                await signer.account(original, self.proof)

    async def test_closed_terminal_query_refuses_before_cached_or_cold_issuer_access(self):
        admission = await self.ready()
        journal = await self.open(admission)
        self.assertIsNone(await journal.current())
        self.record = strict_loads(self.js.messages[-1].data)
        self.install_native_proof()
        query = strict_loads(await self.fresh_query())
        query['operation']['terminalSessionId'] = 'opaque-current-session'
        query['ingressAttestation']['claims']['operation'] = copy.deepcopy(query['operation'])
        query['ingressAttestation']['signature'] = sign_claims(query['ingressAttestation']['claims'], SEED)
        raw = canonical_bytes(query)
        self.wrapper.update(requestId=query['correlationId'], serviceId='outcome-owner',
            requestContractId='capability-outcome-query', replyContractId='capability-outcome-query-reply',
            operationId=query['operation']['operationId'], envelopeBytes=base64.b64encode(raw).decode())
        proof = self.native_proof()
        checked = []
        async def authorize(session, caller, scope):
            self.assertEqual((session, caller, scope), ('opaque-current-session', ref('human'), SCOPE))
            checked.append(True)
            raise ContractError('oidc_terminal_session_required')
        self.service.ingress.require_terminal_sessions(authorize)
        replacement = self.new_admission()
        for owner in (admission, replacement):
            with patch.object(self.account_custody, 'resolve', new=AsyncMock()) as issuer:
                with self.assertRaises(ContractError):
                    await owner.reopen_query(raw, account_request=self.account_request, native_proof=proof)
                issuer.assert_not_awaited()
        self.assertEqual(checked, [True, True])
        self.assertIsNone(await journal.current())
        self.assertEqual(self.broker.creates, 1)
