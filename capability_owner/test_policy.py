"""Actual signed policy queries and retained receipts; broker I/O is controlled."""
import base64
import copy
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED
from . import test_reply_service as support
from .policy import PolicyResource
from .reply_service import CapabilityReplyService


class PolicyFixture:
    request = support.ReplyServiceTests.request
    signed = support.ReplyServiceTests.signed
    call = support.ReplyServiceTests.call
    verify = support.ReplyServiceTests.verify

    def setUp(self):
        support.ReplyServiceTests.setUp(self)
        patch('capability_owner.policy.datetime', _Clock).start()
        facts = self.row['facts']
        facts['grant']['actions'] += ['evaluate', 'write', 'inspect']
        facts['grant']['resourceIds'] += ['native-policy', 'target-one']
        facts['domainBindings'].append({'id': 'policy-evaluate', 'contractId': 'capability-policy-evaluate',
            'action': 'evaluate', 'resourceClass': 'policy', 'resourceIds': ['native-policy']})
        facts['policy']['decisions'] += [
            {'access': {'action': 'evaluate', 'resourceClass': 'policy', 'resourceId': 'native-policy'}, 'outcome': 'allow'},
            {'access': {'action': 'write', 'resourceClass': 'storage', 'resourceId': 'target-one'}, 'outcome': 'deny'},
            {'access': {'action': 'inspect', 'resourceClass': 'storage', 'resourceId': 'target-one'}, 'outcome': 'approval_required'},
            {'access': {'action': 'read', 'resourceClass': 'storage', 'resourceId': 'target-one'}, 'outcome': 'allow'}]
        grant = copy.deepcopy(next(g for g in self.record['state']['grants'] if g['ref'] == ref('capability')))
        grant.update(ref=ref('policy-query'), contractId='capability-policy-evaluate', resourceId='native-policy')
        self.record['state']['grants'].append(grant)
        if getattr(self, 'private_parent', False):
            parent = copy.deepcopy(self.row)
            parent['ref'] = ref('parent-native')
            parent['owner']['instanceId'] = 'parent-one'
            parent['facts']['grant'].update(grantId='parent-native-grant', subjectInstanceId='parent-one',
                policyRef=ref('parent-policy'))
            parent['facts']['policy'].update(reference=ref('parent-policy'), subjectInstanceId='parent-one')
            self.row.update(relationship='private', parentOwner=copy.deepcopy(parent['owner']))
            facts['parentGrant'] = copy.deepcopy(parent['facts']['grant'])
            facts['grant']['parentGrantRef'] = ref('parent-native-grant')
            facts['parentAccess'] = [{'action': 'read', 'resourceClass': 'storage', 'resourceId': 'task-one'},
                {'action': 'evaluate', 'resourceClass': 'policy', 'resourceId': 'native-policy'}]
            self.record['state']['nativeInstances'] = [parent]
            recheck = copy.deepcopy(grant)
            recheck.update(ref=ref('parent-host-recheck'), callerRef=ref('host'), actorRef=ref('host'),
                contractId='native-authority-recheck', resourceId='parent-one')
            self.record['state']['grants'].append(recheck)
        self.js.messages[0].data = canonical_bytes(self.record)

    async def enroll(self):
        original = copy.deepcopy(strict_loads(self.js.messages[-1].data)['state'].get('nativeInstances', []))
        self.claims.update(operationId='enroll-native', contractId='identity-native-instance-set',
            grantRef=ref('native-admin'), payload={'authorityId': 'authority-one',
                'record': self.row, 'previousRef': None})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['nativeInstances'], original + [self.row])

    async def asyncSetUp(self):
        await support.ReplyServiceTests.asyncSetUp(self)
        self.binding = OwnerBinding('hub-one', 'policy-evaluations', 'native-policy', 'policy-evaluation',
            canonical_bytes(self.row['facts']['grant']['scope']))
        self.policy_js = FakeJetStream(self.policy)
        self.policy_js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(self.binding))
        self.resource = self.open_resource()
        self.reply_service = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='policy-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
        self.addAsyncCleanup(self.reply_service.close)

    def open_resource(self):
        ledger = OwnerLedger(self.policy_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        return PolicyResource(self.binding, ledger, canonical_bytes(ref('native-policy')),
            canonical_bytes(ref('plugin')), 'plugin-one')

    async def prepare(self, action='read', *, operation='policy-one', target='target-one'):
        self.claims.update(operationId=operation, contractId='capability-policy-evaluate', grantRef=ref('policy-query'),
            expectedVersion=1, payload={'resourceRef': ref('native-policy'),
                'input': {'action': action, 'resourceClass': 'storage', 'resourceId': target}})
        admitted = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        self.inner = admitted.envelope
        envelope = strict_loads(self.inner)
        self.wrapper.update(serviceId='policy-owner', requestContractId='capability-policy-evaluate',
            replyContractId='capability-policy-evaluate-reply', operationId=operation,
            requestId=envelope['correlationId'], resourceRef=ref('native-policy'),
            nativeFactsDigest=payload_digest(self.row['facts']), envelopeBytes=base64.b64encode(self.inner).decode())
        return self.signed()

class PolicyOwnerTests(PolicyFixture, unittest.IsolatedAsyncioTestCase):
    async def test_query_permission_does_not_grant_requested_access(self):
        for action, expected in (('read', 'allow'), ('write', 'deny'), ('inspect', 'approval_required')):
            raw = await self.prepare(action, operation='policy-' + action)
            response = await self.call(raw)
            receipt = strict_loads(self.verify(response, raw))
            self.assertEqual(receipt['outcome'], expected)
            self.assertEqual(receipt['receiptRef']['revision'], len(self.policy_js.messages))
        self.assertEqual(len(self.policy_js.messages), 3)
        for message in self.policy_js.messages:
            record = strict_loads(message.data)
            self.assertEqual((record['effects'], record['artifacts']), ([], []))
            self.assertEqual(record['state']['policyRef'], ref('native-policy'))

    async def test_identical_replay_after_later_query_keeps_original_receipt(self):
        first = await self.prepare()
        result = strict_loads(self.verify(await self.call(first), first))
        later = await self.prepare('write', operation='policy-later')
        await self.call(later)
        self.assertEqual(strict_loads(self.verify(await self.call(first), first)), result)
        self.assertEqual(len(self.policy_js.messages), 2)

    async def test_lost_append_reply_and_owner_restart_return_original_receipt(self):
        first = await self.prepare()
        self.policy_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^capability_service_unavailable$'):
            await self.call(first)
        self.assertEqual(len(self.policy_js.messages), 1)
        self.resource = self.open_resource()
        self.reply_service._receiver._resources['native-policy'] = self.resource
        result = strict_loads(self.verify(await self.call(first), first))
        self.assertEqual(result['outcome'], 'allow')
        self.assertEqual(result['receiptRef']['revision'], 1)
        self.assertEqual(len(self.policy_js.messages), 1)

    async def test_changed_input_reusing_operation_refuses_without_another_record(self):
        first = await self.prepare()
        await self.call(first)
        changed = await self.prepare('write')
        with self.assertRaisesRegex(ContractError, '^capability_service_unavailable$'):
            await self.call(changed)
        self.assertEqual(len(self.policy_js.messages), 1)

    async def test_missing_requested_rule_denies_and_unsigned_direct_query_refuses(self):
        raw = await self.prepare(target='another-target')
        self.assertEqual(strict_loads(self.verify(await self.call(raw), raw))['outcome'], 'deny')
        with self.assertRaisesRegex(ContractError, '^capability_access_refused$'):
            await self.resource.evaluate(self.service.reader, self.inner, None)
        self.assertEqual(len(self.policy_js.messages), 1)

    async def test_current_query_authority_can_retrieve_original_result_after_policy_change(self):
        first = await self.prepare()
        original_wrapper = copy.deepcopy(self.wrapper)
        result = strict_loads(self.verify(await self.call(first), first))
        reference = copy.deepcopy(self.row['ref'])
        self.row['ref']['revision'] += 1
        for decision in self.row['facts']['policy']['decisions']:
            if decision['access'] == {'action': 'read', 'resourceClass': 'storage', 'resourceId': 'target-one'}:
                decision['outcome'] = 'deny'
        self.claims.update(operationId='change-policy-facts', contractId='identity-native-instance-set',
            grantRef=ref('native-admin'), expectedVersion=len(self.js.messages),
            payload={'authorityId': 'authority-one', 'record': self.row, 'previousRef': reference})
        await self.service.handle(self.request())
        self.wrapper = original_wrapper
        self.wrapper['nativeFactsDigest'] = payload_digest(self.row['facts'])
        refreshed = self.signed()
        self.assertEqual(strict_loads(self.verify(await self.call(refreshed), refreshed)), result)
        later = await self.prepare(operation='policy-after-change')
        self.assertEqual(strict_loads(self.verify(await self.call(later), later))['outcome'], 'deny')
        self.assertEqual(len(self.policy_js.messages), 2)

    async def test_revocation_after_commit_withholds_reply_but_keeps_original_receipt(self):
        first = await self.prepare()
        append = self.resource.ledger.append
        async def commit_then_revoke(*args, **kwargs):
            stored = await append(*args, **kwargs)
            current = strict_loads(self.js.messages[-1].data)
            for grant in current['state']['grants']:
                if grant['ref'] == ref('policy-query'):
                    grant['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(current)
            return stored
        with patch.object(self.resource.ledger, 'append', side_effect=commit_then_revoke):
            with self.assertRaisesRegex(ContractError, '^capability_service_unavailable$'):
                await self.call(first)
        self.assertEqual(len(self.policy_js.messages), 1)
        self.assertEqual(strict_loads(self.policy_js.messages[0].data)['state']['outcome'], 'allow')

    async def test_stopped_and_wrong_instance_resources_refuse_before_receipt(self):
        first = await self.prepare()
        from dataclasses import replace
        foreign = replace(self.resource, instance_id='foreign-instance')
        self.reply_service._receiver._resources['native-policy'] = foreign
        with self.assertRaisesRegex(ContractError, '^capability_service_unavailable$'):
            await self.call(first)
        self.assertEqual(self.policy_js.messages, [])
        self.reply_service._receiver._resources['native-policy'] = self.resource
        await self.reply_service.close()
        with self.assertRaisesRegex(ContractError, '^capability_service_unavailable$'):
            await self.call(first)
        self.assertEqual(self.policy_js.messages, [])


class ParentPolicyOwnerTests(PolicyFixture, unittest.IsolatedAsyncioTestCase):
    private_parent = True

    async def test_parent_can_allow_query_without_delegating_requested_access(self):
        raw = await self.prepare()
        access = {'action': 'read', 'resourceClass': 'storage', 'resourceId': 'target-one'}
        self.assertIn({'access': access, 'outcome': 'allow'}, self.row['facts']['policy']['decisions'])
        self.assertNotIn(access, self.row['facts']['parentAccess'])
        response = await self.call(raw)
        self.assertEqual(strict_loads(self.verify(response, raw))['outcome'], 'deny')
        self.assertEqual(len(self.policy_js.messages), 1)
