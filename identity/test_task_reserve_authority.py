"""Reservation correlation never supplies delegated execution authority."""
import copy
from datetime import timedelta
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity import test_service as support
from identity.test_authority import fixture, ref, SEED, NOW
from identity.authority import evaluate_snapshot


class TaskReserveAuthorityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        support.ServiceTests.setUp(self)
        self.record['state']['grants'][0].update(contractId='task-reserve',resourceId='task-one')
        self.envelope=fixture()[1]
        self.envelope.update(contractId='task-reserve',destinationServiceId='task-owner',payload={
            'taskId':'task-one','delegationId':'delegation-one','attemptId':'attempt-one',
            'executorHubId':'executor-hub','grantRef':ref('execution-grant'),
            'repositoryRevision':'commit-one','assignmentEpoch':7})
        self.envelope['operation'].update(taskId='task-one',attemptId='attempt-one',
            delegationRef=ref('delegation-one'),expectedVersion=3,
            scope=copy.deepcopy(self.record['state']['grants'][0]['scope']))

    def signed(self):
        envelope=copy.deepcopy(self.envelope)
        envelope['operation']['payloadDigest']=payload_digest(envelope['payload'])
        claims=envelope['ingressAttestation']['claims']
        claims.update(contractId='task-reserve',operation=copy.deepcopy(envelope['operation']),
            audience={'hubId':'hub-one','serviceId':'task-owner'})
        envelope['ingressAttestation']['signature']=sign_claims(claims,SEED)
        return canonical_bytes(envelope)

    async def evaluate(self,raw=None,**kwargs):
        self.js.messages[0].data=canonical_bytes(self.record)
        return evaluate_snapshot(await self.service.reader.current(),raw or self.signed(),now=NOW,
            audience=kwargs.get('audience',{'hubId':'hub-one','serviceId':'task-owner'}))

    async def test_direct_authority_with_distinct_execution_grant_and_correlation(self):
        result=await self.evaluate()
        self.assertEqual(result.outcome,'allowed')
        op=strict_loads(result.operation)
        self.assertEqual(op['delegationRef'],ref('delegation-one'))
        self.assertNotEqual(op['grantRef'],self.envelope['payload']['grantRef'])
        self.assertEqual(op['expectedVersion'],3)
        self.assertEqual(self.envelope['payload']['assignmentEpoch'],7)

    async def test_context_does_not_bypass_actor_scope_grant_or_native_restrictions(self):
        original_record=copy.deepcopy(self.record);original=copy.deepcopy(self.envelope)
        changes=[lambda:self.envelope['operation'].update(effectiveActorRef=ref('service')),
            lambda:self.envelope['operation']['scope'].update(projectId='other'),
            lambda:self.record['state']['grants'][0].update(resourceId='other'),
            lambda:self.record['state']['grants'][0].update(delegationRef=ref('delegation-one')),
            lambda:self.record['state']['grants'][0].update(decision='denied')]
        for change in changes:
            self.record=copy.deepcopy(original_record);self.envelope=copy.deepcopy(original);change()
            self.assertNotEqual((await self.evaluate()).outcome,'allowed')
        self.record=copy.deepcopy(original_record);self.envelope=copy.deepcopy(original)
        caller=self.envelope['operation']['caller']
        next(i for i in self.record['state']['identities'] if i['ref']==caller['authenticatedIdentityRef'])['kind']='plugin'
        caller['kind']='plugin'
        self.assertEqual((await self.evaluate()).reason,'native_capability_admission_required')

    async def test_missing_wrong_hub_and_epoch_as_revision_correlation_refuse(self):
        for correlation in (None,dict(ref('delegation-one'),ownerHubId='other'),
                            dict(ref('delegation-one'),revision=7),ref('wrong-delegation')):
            self.envelope['operation']['delegationRef']=correlation
            try:result=await self.evaluate()
            except ContractError:continue
            self.assertNotEqual(result.outcome,'allowed')

    async def test_exact_replay_rechecks_current_grant_and_preserves_signed_version(self):
        raw=self.signed();first=await self.evaluate(raw)
        shorter=NOW+timedelta(seconds=2)
        self.record['state']['grants'][0]['expiresAt']=shorter.isoformat().replace('+00:00','Z')
        second=await self.evaluate(raw)
        self.assertEqual(first.operation,second.operation)
        self.assertEqual(second.valid_until,shorter)
        self.record['state']['grants'][0]['status']='revoked'
        self.assertNotEqual((await self.evaluate(raw)).outcome,'allowed')

    async def test_wrong_audience_and_changed_signed_version_refuse(self):
        with self.assertRaises(ContractError):
            await self.evaluate(audience={'hubId':'hub-one','serviceId':'other-owner'})
        envelope=strict_loads(self.signed());envelope['operation']['expectedVersion']=4
        with self.assertRaises(ContractError):await self.evaluate(canonical_bytes(envelope))
