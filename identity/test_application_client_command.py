"""Enrolled client query signing through the actual integration receiver."""
import copy
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, sign_claims
from identity.application_client import provision_application_client, load_application_client, ApplicationClientKey
from identity.transitions import transition
from identity.ingress import EnrolledIngress
from nacl.signing import SigningKey
from identity.test_authority import ref, SEED
from integration_owner import test_service as support
from integration_owner import test_admission as admission
from integration_owner.intent import effect_id
from integration_owner.receiver import IntegrationOwner
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject


class ClientCommandTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.ServiceTests.setUp
    asyncSetUp = support.ServiceTests.asyncSetUp
    resign = support.ServiceTests.resign
    request = support.ServiceTests.request
    enable_offline_worker = support.ServiceTests.enable_offline_worker
    select_query = admission.AdmissionTests.select_query

    async def enrolled_commands(self):
        issuer = self.record['state']['issuers'][0]
        integration_seed = bytes([10]) * 32
        integration_issuer = copy.deepcopy(issuer)
        integration_issuer.update(ref=ref('integration-command-issuer'), publicKey=base64.urlsafe_b64encode(
            bytes(SigningKey(integration_seed).verify_key)).decode().rstrip('='))
        self.record['state']['issuers'].append(integration_issuer)
        grants = {'integration-intent': ref('grant')}
        for contract, name in (('integration-effect-query', 'dynamic-query-grant'),
                               ('integration-attempt-start', 'start-grant'),
                               ('integration-attempt-complete', 'complete-grant'),
                               ('integration-effect-reconcile', 'reconcile-grant')):
            grant = copy.deepcopy(self.record['state']['grants'][0])
            grant.update(ref=ref(name), contractId=contract)
            self.record['state']['grants'].append(grant)
            grants[contract] = grant['ref']
        self.command_grants = grants
        self.service.ingress = EnrolledIngress(self.authority, issuer_ref=integration_issuer['ref'],
                                               signing_seed=integration_seed)
        self.service._seed, self.service._issuer = integration_seed, canonical_bytes(integration_issuer['ref'])
        selection = {'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
            'instanceId': 'application-one', 'callerRef': ref('human'),
            'scope': copy.deepcopy(self.envelope['operation']['scope']),
            'transportRef': ref('application-transport'), 'grantRef': ref('application-grant'),
            'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': issuer['publicKey'],
            'releaseDigest': 'sha256:' + 'a' * 64, 'policyRef': ref('application-policy'),
            'workspaceRef': None, 'integrationEffectCommands': {
                'contracts': list(grants), 'transportRef': ref('integration-command-transport'),
                'replyIssuerRef': integration_issuer['ref'],
                'replyIssuerPublicKey': integration_issuer['publicKey']}}
        path = Path(self.tmp.name).resolve() / 'command-client.key'
        now = datetime.now(timezone.utc)
        enrollment = provision_application_client(path, selection=selection,
            identity=self.record['state']['identities'][0],
            issued_at=(now - timedelta(seconds=5)).isoformat().replace('+00:00', 'Z'),
            expires_at=(now + timedelta(minutes=5)).isoformat().replace('+00:00', 'Z'))
        self.record['state'] = transition(self.record['state'], 'identity-enroll', enrollment, hub_id='hub-one')
        return load_application_client(path)

    def lifecycle_claims(self, key, contract, operation_id, revision, original_digest,
                         attempt_id='attempt-one', approved=False):
        self.envelope.update(contractId=contract, payload={
            'effectRef': {'id': self.binding.entity_id, 'ownerHubId': 'hub-one', 'revision': revision},
            'originalOperationId': 'operation-one', 'originalPayloadDigest': original_digest,
            'attemptOperationId': attempt_id})
        grant = self.command_grants[contract]
        operation = self.envelope['operation']
        operation.update(operationId=operation_id, expectedVersion=revision,
            payloadDigest=payload_digest(self.envelope['payload']), grantRef=grant, approvalRefs=[])
        if contract == 'integration-attempt-start':
            approver = copy.deepcopy(self.record['state']['grants'][0])
            approver.update(ref=ref('start-approve-grant'), contractId='identity-approve',
                            resourceId=grant['id'])
            self.record['state']['grants'].append(approver)
            approval = copy.deepcopy(self.record['state']['approvals'][0])
            approval.update(ref=ref('start-approval'), grantRef=grant, approverGrantRef=approver['ref'],
                operationId=operation_id, expectedVersion=revision, payloadDigest=operation['payloadDigest'])
            self.record['state']['approvals'].append(approval)
            operation['approvalRefs'] = [approval['ref']]
        elif approved:
            selected_grant = next(item for item in self.record['state']['grants']
                                  if item['ref'] == grant)
            selected_grant['decision'] = 'review-required'
            name = contract.removeprefix('integration-')
            approver = copy.deepcopy(self.record['state']['grants'][0])
            approver.update(ref=ref(name + '-approve-grant'), contractId='identity-approve',
                            resourceId=grant['id'])
            self.record['state']['grants'].append(approver)
            approval = copy.deepcopy(self.record['state']['approvals'][0])
            approval.update(ref=ref(name + '-approval'), grantRef=grant,
                approverGrantRef=approver['ref'], operationId=operation_id,
                expectedVersion=revision, payloadDigest=operation['payloadDigest'])
            self.record['state']['approvals'].append(approval)
            operation['approvalRefs'] = [approval['ref']]
        self.resign()
        claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        claims['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        return claims

    async def enrolled_query(self):
        intent = await self.owner.handle(canonical_bytes(self.envelope))
        self.select_query(intent)
        issuer = self.record['state']['issuers'][0]
        integration_seed = bytes([9]) * 32
        integration_issuer = copy.deepcopy(issuer)
        integration_issuer.update(ref=ref('integration-issuer'), publicKey=base64.urlsafe_b64encode(
            bytes(SigningKey(integration_seed).verify_key)).decode().rstrip('='))
        self.record['state']['issuers'].append(integration_issuer)
        self.service.ingress = EnrolledIngress(self.authority, issuer_ref=integration_issuer['ref'], signing_seed=integration_seed)
        self.service._seed, self.service._issuer = integration_seed, canonical_bytes(integration_issuer['ref'])
        selection = {'hubId':'hub-one','profileId':'profile-one','authorityId':'authority-one',
            'instanceId':'application-one','callerRef':ref('human'),'scope':copy.deepcopy(self.envelope['operation']['scope']),
            'transportRef':ref('query-transport'),'grantRef':ref('application-grant'),
            'replyIssuerRef':ref('issuer'),'replyIssuerPublicKey':issuer['publicKey'],
            'releaseDigest':'sha256:'+'a'*64,'policyRef':ref('application-policy'),'workspaceRef':None,
            'integrationEffectQuery':{'subject':self.service.subject,'grantRef':ref('query-grant'),
                'transportRef':ref('query-command-transport'),
                'originalOperationId':intent.operation_id,'originalPayloadDigest':intent.original_payload_digest,
                'replyIssuerRef':integration_issuer['ref'],'replyIssuerPublicKey':integration_issuer['publicKey']}}
        path = Path(self.tmp.name).resolve()/'client.key'
        now = datetime.now(timezone.utc)
        payload = provision_application_client(path, selection=selection,
            identity=self.record['state']['identities'][0],
            issued_at=(now-timedelta(seconds=5)).isoformat().replace('+00:00','Z'),
            expires_at=(now+timedelta(minutes=5)).isoformat().replace('+00:00','Z'))
        self.record['state'] = transition(self.record['state'],'identity-enroll',payload,hub_id='hub-one')
        key = load_application_client(path)
        claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        claims['transportRef'] = ref('query-command-transport')
        await self.service.start()
        return key, claims

    async def test_selected_query_signs_and_verifies_actual_receiver_receipt(self):
        key, claims = await self.enrolled_query()
        subject = key.command_subject('integration-effect-query')
        request = key.sign_command(claims, subject=subject)
        response = await self.service.handle(request)
        receipt = key.verify_command_response(response, request, subject=subject)
        self.assertEqual(receipt['phase'],'intent-committed')
        self.assertEqual(receipt['operationId'],claims['operationId'])
        changed = strict_loads(response)
        changed['claims']['receipt']['originalPayloadDigest'] = 'sha256:'+'f'*64
        changed['signature'] = sign_claims(changed['claims'],bytes([9])*32)
        with self.assertRaises(ContractError):
            key.verify_command_response(canonical_bytes(changed),request,subject=subject)
        self.record['state']['grants'][-1]['status']='revoked'
        with self.assertRaises(ContractError):
            await self.service.handle(request)

    async def test_unselected_purposes_subject_grants_payload_and_expiry_refuse(self):
        key, claims = await self.enrolled_query()
        subject = key.command_subject('integration-effect-query')
        for mutate in (lambda c:c.update(contractId='integration-attempt-start'),
                       lambda c:c.update(grantRef=ref('application-grant')),
                       lambda c:c.update(transportRef=ref('query-transport')),
                       lambda c:c.update(purpose='agentmux-application-binding-request-v1'),
                       lambda c:c['payload']['effectRef'].update(id='another-effect'),
                       lambda c:c['payload'].update(originalPayloadDigest='sha256:'+'f'*64),
                       lambda c:c.update(expectedVersion=7),
                       lambda c:c.pop('replySubject')):
            changed = copy.deepcopy(claims)
            mutate(changed)
            with self.assertRaises(ContractError):
                key.sign_command(changed,subject=subject)
        with self.assertRaises(ContractError):
            key.sign_command(claims,subject=subject+'.other')
        with self.assertRaises(ContractError):
            key.sign_command(claims,subject=subject,now=datetime.now(timezone.utc)+timedelta(minutes=2))
        material = strict_loads(key._material)
        material.pop('integrationEffectQuery')
        unselected = ApplicationClientKey(material)
        with self.assertRaises(ContractError):
            unselected.sign_command(claims,subject=subject)
        material = strict_loads(key._material)
        material['integrationEffectQuery']['subject'] += '.other'
        with self.assertRaises(ContractError):
            ApplicationClientKey(material)

    async def test_enrolled_commands_sign_and_verify_actual_intent_start_and_complete_receipts(self):
        key = await self.enrolled_commands()
        self.enable_offline_worker()
        await self.service.start()

        intent_claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        intent_claims['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        intent_subject = key.command_subject('integration-intent', intent_claims['operationId'])
        intent_request = key.sign_command(intent_claims, subject=intent_subject)
        intent = key.verify_command_response(await self.service.handle(intent_request), intent_request,
                                             subject=intent_subject)
        self.assertEqual((intent['phase'], intent['sequence']), ('intent-committed', 1))

        start_claims = self.lifecycle_claims(key, 'integration-attempt-start', 'attempt-one', 1,
                                             intent['originalPayloadDigest'])
        start_subject = key.command_subject('integration-attempt-start', 'operation-one')
        start_request = key.sign_command(start_claims, subject=start_subject)
        start = key.verify_command_response(await self.service.handle(start_request), start_request,
                                            subject=start_subject)
        self.assertEqual((start['phase'], start['attemptOperationId']), ('dispatch-claimed', 'attempt-one'))

        complete_claims = self.lifecycle_claims(key, 'integration-attempt-complete', 'complete-one', 2,
                                                intent['originalPayloadDigest'])
        complete_subject = key.command_subject('integration-attempt-complete', 'operation-one')
        complete_request = key.sign_command(complete_claims, subject=complete_subject)
        complete = key.verify_command_response(await self.service.handle(complete_request), complete_request,
                                               subject=complete_subject)
        self.assertEqual((complete['phase'], complete['sequence']), ('applied', 3))

    async def test_enrolled_reconcile_signs_and_verifies_read_only_recovery_receipt(self):
        key = await self.enrolled_commands()
        opener = self.enable_offline_worker()
        await self.service.start()
        claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        claims['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        subject = key.command_subject('integration-intent', claims['operationId'])
        request = key.sign_command(claims, subject=subject)
        intent = key.verify_command_response(await self.service.handle(request), request, subject=subject)

        start_claims = self.lifecycle_claims(key, 'integration-attempt-start', 'attempt-one', 1,
                                             intent['originalPayloadDigest'])
        self.js.lose_ack = True
        subject = key.command_subject('integration-attempt-start', 'operation-one')
        request = key.sign_command(start_claims, subject=subject)
        key.verify_command_response(await self.service.handle(request), request, subject=subject)
        opener.open.assert_not_called()

        reconcile_claims = self.lifecycle_claims(key, 'integration-effect-reconcile', 'reconcile-one', 2,
                                                 intent['originalPayloadDigest'])
        subject = key.command_subject('integration-effect-reconcile', 'operation-one')
        request = key.sign_command(reconcile_claims, subject=subject)
        receipt = key.verify_command_response(await self.service.handle(request), request, subject=subject)
        self.assertEqual((receipt['phase'], receipt['sequence']), ('reconciliation-required', 3))
        self.assertEqual(opener.open.call_args.args[0].get_method(), 'GET')

    async def test_review_required_completion_accepts_exact_approval_and_authority_denies_others(self):
        key = await self.enrolled_commands()
        self.enable_offline_worker()
        await self.service.start()
        claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        claims['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        subject = key.command_subject('integration-intent', claims['operationId'])
        request = key.sign_command(claims, subject=subject)
        intent = key.verify_command_response(await self.service.handle(request), request, subject=subject)
        start = self.lifecycle_claims(key, 'integration-attempt-start', 'attempt-one', 1,
                                      intent['originalPayloadDigest'])
        subject = key.command_subject('integration-attempt-start', 'operation-one')
        request = key.sign_command(start, subject=subject)
        key.verify_command_response(await self.service.handle(request), request, subject=subject)

        complete_grant = self.command_grants['integration-attempt-complete']
        next(item for item in self.record['state']['grants']
             if item['ref'] == complete_grant)['decision'] = 'review-required'
        missing = self.lifecycle_claims(key, 'integration-attempt-complete', 'complete-one', 2,
                                        intent['originalPayloadDigest'])
        subject = key.command_subject('integration-attempt-complete', 'operation-one')
        missing_request = key.sign_command(missing, subject=subject)
        with self.assertRaises(ContractError):
            await self.service.handle(missing_request)
        incorrect = copy.deepcopy(missing)
        incorrect['approvalRefs'] = [ref('approval')]
        incorrect_request = key.sign_command(incorrect, subject=subject)
        with self.assertRaises(ContractError):
            await self.service.handle(incorrect_request)

        approved = self.lifecycle_claims(key, 'integration-attempt-complete', 'complete-one', 2,
                                         intent['originalPayloadDigest'], approved=True)
        approved_request = key.sign_command(approved, subject=subject)
        receipt = key.verify_command_response(await self.service.handle(approved_request),
                                              approved_request, subject=subject)
        self.assertEqual(receipt['phase'], 'applied')

    async def test_review_required_reconcile_accepts_exact_bound_approval(self):
        key = await self.enrolled_commands()
        opener = self.enable_offline_worker()
        await self.service.start()
        claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        claims['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        subject = key.command_subject('integration-intent', claims['operationId'])
        request = key.sign_command(claims, subject=subject)
        intent = key.verify_command_response(await self.service.handle(request), request, subject=subject)
        start = self.lifecycle_claims(key, 'integration-attempt-start', 'attempt-one', 1,
                                      intent['originalPayloadDigest'])
        self.js.lose_ack = True
        subject = key.command_subject('integration-attempt-start', 'operation-one')
        request = key.sign_command(start, subject=subject)
        key.verify_command_response(await self.service.handle(request), request, subject=subject)
        opener.open.assert_not_called()

        reconcile = self.lifecycle_claims(key, 'integration-effect-reconcile', 'reconcile-one', 2,
            intent['originalPayloadDigest'], approved=True)
        subject = key.command_subject('integration-effect-reconcile', 'operation-one')
        request = key.sign_command(reconcile, subject=subject)
        receipt = key.verify_command_response(await self.service.handle(request), request, subject=subject)
        self.assertEqual(receipt['phase'], 'reconciliation-required')

    async def test_lost_intent_reply_is_queried_by_its_signed_original_identity(self):
        key = await self.enrolled_commands()
        await self.service.start()
        intent_claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        intent_claims['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        subject = key.command_subject('integration-intent', intent_claims['operationId'])
        intent_request = key.sign_command(intent_claims, subject=subject)
        await self.service.handle(intent_request)  # The caller receives no reply.

        digest = payload_digest(intent_claims['payload'])
        query_claims = copy.deepcopy(intent_claims)
        query_claims.update(operationId='query-lost-intent', expectedVersion=1,
            contractId='integration-effect-query', grantRef=self.command_grants['integration-effect-query'],
            approvalRefs=[], payload={'effectRef': {
                'id': self.binding.entity_id, 'ownerHubId': 'hub-one', 'revision': 1},
                'originalOperationId': 'operation-one', 'originalPayloadDigest': digest})
        subject = key.command_subject('integration-effect-query', 'operation-one')
        query_grant = next(item for item in self.record['state']['grants']
                           if item['ref'] == self.command_grants['integration-effect-query'])
        query_grant['decision'] = 'review-required'
        missing_request = key.sign_command(query_claims, subject=subject)
        with self.assertRaises(ContractError):
            await self.service.handle(missing_request)
        incorrect = copy.deepcopy(query_claims)
        incorrect['approvalRefs'] = [ref('approval')]
        with self.assertRaises(ContractError):
            await self.service.handle(key.sign_command(incorrect, subject=subject))
        approver = copy.deepcopy(query_grant)
        approver.update(ref=ref('dynamic-query-approve-grant'), contractId='identity-approve',
                        resourceId=query_grant['ref']['id'], decision='allowed')
        self.record['state']['grants'].append(approver)
        approval = copy.deepcopy(self.record['state']['approvals'][0])
        approval.update(ref=ref('dynamic-query-approval'), grantRef=query_grant['ref'],
            approverGrantRef=approver['ref'], operationId=query_claims['operationId'],
            expectedVersion=1, payloadDigest=payload_digest(query_claims['payload']))
        self.record['state']['approvals'].append(approval)
        query_claims['approvalRefs'] = [approval['ref']]
        query_request = key.sign_command(query_claims, subject=subject)
        receipt = key.verify_command_response(await self.service.handle(query_request), query_request,
                                              subject=subject)
        self.assertEqual((receipt['phase'], receipt['originalOperationId'],
                          receipt['originalPayloadDigest']),
                         ('intent-committed', 'operation-one', digest))

    async def test_one_purpose_enrollment_admits_two_exact_effect_grants_and_refuses_substitution(self):
        key = await self.enrolled_commands()
        first = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        first['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        first_subject = key.command_subject('integration-intent', first['operationId'])
        admitted = await self.service.ingress.admit(key.sign_command(first, subject=first_subject),
                                                    cancellation_ref=ref('first-cancel'))
        await self.owner.handle(admitted.envelope)

        second_id = effect_id(key.selection['scope'], 'operation-two')
        second_grant = copy.deepcopy(self.record['state']['grants'][0])
        second_grant.update(ref=ref('second-intent-grant'), resourceId=second_id)
        self.record['state']['grants'].append(second_grant)
        approver = copy.deepcopy(second_grant)
        approver.update(ref=ref('second-intent-approve-grant'), contractId='identity-approve',
                        resourceId=second_grant['ref']['id'])
        self.record['state']['grants'].append(approver)
        second = copy.deepcopy(first)
        second['operationId'] = 'operation-two'
        second['grantRef'] = second_grant['ref']
        second['payload']['effectRef']['id'] = second_id
        approval = copy.deepcopy(self.record['state']['approvals'][0])
        approval.update(ref=ref('second-intent-approval'), grantRef=second_grant['ref'],
            approverGrantRef=approver['ref'], operationId='operation-two',
            payloadDigest=payload_digest(second['payload']))
        self.record['state']['approvals'].append(approval)
        second['approvalRefs'] = [approval['ref']]
        second_subject = key.command_subject('integration-intent', 'operation-two')
        second_binding = OwnerBinding('hub-one', 'integrations', second_id, 'effect',
                                      canonical_bytes(key.selection['scope']))
        second_js = type(self.js)(self.ledger._retention)
        second_js.config.subjects = [owner_subject(second_binding)]
        second_ledger = OwnerLedger(second_js, stream='OWNER', subject=owner_subject(second_binding),
            binding=second_binding, retention=self.ledger._retention,
            stream_identity=self.ledger._identity, require_completion_budget=True)
        second_owner = IntegrationOwner(self.authority, second_ledger, second_binding,
            provider='jira', credential_ref=first['payload']['credentialRef'])
        self.addAsyncCleanup(second_owner.close)
        admitted = await self.service.ingress.admit(key.sign_command(second, subject=second_subject),
                                                    cancellation_ref=ref('second-cancel'))
        await second_owner.handle(admitted.envelope)
        self.assertNotEqual(first_subject, second_subject)

        wrong_resource = copy.deepcopy(second)
        wrong_resource['grantRef'] = first['grantRef']
        with self.assertRaises(ContractError):
            admitted = await self.service.ingress.admit(
                key.sign_command(wrong_resource, subject=second_subject),
                cancellation_ref=ref('wrong-cancel'))
            await second_owner.handle(admitted.envelope)
        other_scope_id = effect_id({**key.selection['scope'], 'projectId': 'other-project'},
                                   'operation-two')
        cross_scope = copy.deepcopy(second)
        cross_scope['payload']['effectRef']['id'] = other_scope_id
        with self.assertRaises(ContractError):
            key.sign_command(cross_scope, subject=second_subject)

    async def test_command_enrollment_refuses_cross_purpose_and_changed_lifecycle_identity(self):
        key = await self.enrolled_commands()
        claims = strict_loads(self.request(reply='_INBOX.abcdefghijklmnop'))['claims']
        claims['transportRef'] = key.selection['integrationEffectCommands']['transportRef']
        subject = key.command_subject('integration-intent', claims['operationId'])
        for mutate in (lambda value: value.update(grantRef={
                           'id': 'start-grant', 'ownerHubId': 'other-hub', 'revision': 1}),
                       lambda value: value.update(transportRef=ref('application-transport')),
                       lambda value: value['payload']['effectRef'].update(id='another-effect'),
                       lambda value: value.update(approvalRefs=[]),
                       lambda value: value.update(expectedVersion=1)):
            changed = copy.deepcopy(claims)
            mutate(changed)
            with self.assertRaises(ContractError):
                key.sign_command(changed, subject=subject)
        with self.assertRaises(ContractError):
            key.sign_command(claims, subject=key.command_subject('integration-intent', 'another-operation'))

        start = self.lifecycle_claims(key, 'integration-attempt-start', 'attempt-one', 1,
                                      'sha256:' + 'b' * 64)
        start['operationId'] = 'different-attempt'
        with self.assertRaises(ContractError):
            key.sign_command(start, subject=subject)

        material = strict_loads(key._material)
        material['integrationEffectCommands']['contracts'].remove('integration-attempt-start')
        unavailable = ApplicationClientKey(material)
        with self.assertRaisesRegex(ContractError, '^application_client_command_unavailable$'):
            unavailable.sign_command(start, subject=subject)
