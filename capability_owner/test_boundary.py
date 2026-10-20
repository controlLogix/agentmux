"""Receiver fault controls; test-only decisions do not qualify live authority.

The receiver still accepts only AuthorityReader in production. These tests control
that concrete reader's result to exercise the boundary after a data read. Real
signature/grant refusal is tested separately in test_receiver.
"""
import asyncio
import copy
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import Decision
from sdk.python.tests.test_contracts import SEED
from . import test_receiver


class BoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await test_receiver.ReceiverTests.asyncSetUp(self)
        self.envelope['contractId']='capability-storage-read'
        self.envelope['destinationServiceId']='storage-owner'
        self.envelope['payload']={'resourceRef':self.ref,'input':{}}
        self.resign()

    def resign(self):
        self.envelope['operation']['payloadDigest']=payload_digest(self.envelope['payload'])
        claims=self.envelope['ingressAttestation']['claims']
        claims['contractId']=self.envelope['contractId']
        claims['audience']['serviceId']=self.envelope['destinationServiceId']
        claims['operation']=copy.deepcopy(self.envelope['operation'])
        self.envelope['ingressAttestation']['signature']=sign_claims(claims,SEED)
        self.raw=canonical_bytes(self.envelope)
        self.allowed=Decision('allowed','test_control',1,
            canonical_bytes(self.envelope['operation']),'user-one',canonical_bytes(self.ref))

    async def test_revoked_after_read_withholds_result(self):
        denied=Decision('denied','revoked',2)
        with patch.object(self.reader,'evaluate',side_effect=[self.allowed,denied]) as evaluate:
            with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                await self.receiver.handle(self.raw)
            self.assertEqual(evaluate.await_count,2)
            self.assertEqual(evaluate.await_args.kwargs['audience'],
                {'hubId':'hub-one','serviceId':'storage-owner'})

    async def test_owner_scope_is_checked_even_if_reader_allows(self):
        self.envelope['operation']['scope']['projectId']='other-project'
        self.resign()
        with patch.object(self.reader,'evaluate',return_value=self.allowed):
            with patch.object(self.resource.ledger,'current',side_effect=AssertionError('must not read')):
                with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                    await self.receiver.handle(self.raw)

    async def test_tampered_owner_ref_and_extra_input_refused_before_read(self):
        for change in ('hub','extra'):
            envelope=copy.deepcopy(self.envelope)
            if change=='hub': envelope['payload']['resourceRef']['ownerHubId']='other-hub'
            else: envelope['payload']['input']['sql']='private-query'
            with patch.object(self.reader,'evaluate',side_effect=AssertionError('must not authorize')):
                with self.assertRaises(ContractError) as caught:
                    await self.receiver.handle(canonical_bytes(envelope))
            self.assertNotIn('private-query',str(caught.exception))

    async def test_response_binds_complete_request_and_hides_private_repr(self):
        with patch.object(self.reader,'evaluate',return_value=self.allowed):
            response=await self.receiver.handle(self.raw)
        self.assertEqual(response.request_digest,payload_digest(self.envelope))
        self.assertEqual(response.operation_id,self.envelope['operation']['operationId'])
        self.assertEqual(response.contract_id,'capability-content-reply')
        self.assertNotIn('task-one',repr(response))
        self.assertLessEqual(len(response.payload),65536)

    async def test_cancellation_during_authority_read_is_joined(self):
        entered=asyncio.Event()
        async def blocked(*args,**kwargs):
            entered.set()
            await asyncio.Future()
        with patch.object(self.reader,'evaluate',side_effect=blocked):
            request=asyncio.create_task(self.receiver.handle(self.raw))
            await entered.wait()
            await self.receiver.close(timeout=1)
            self.assertTrue(request.cancelled())
            self.assertFalse(self.receiver._active)

    async def test_suppressed_dependency_cancellation_cannot_disclose(self):
        entered=asyncio.Event()
        calls=0
        async def suppress(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==1:
                entered.set()
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    pass
            return self.allowed
        with patch.object(self.reader,'evaluate',side_effect=suppress):
            request=asyncio.create_task(self.receiver.handle(self.raw))
            await entered.wait()
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request
            self.assertFalse(self.receiver._active)

    async def test_unavailable_effect_is_not_a_successful_receipt(self):
        for contract,service,inputs in (
            ('capability-storage-write','storage-owner',{'value':{'status':'accepted'}}),
            ('capability-secret-use','secret-owner',{'consumerRef':self.ref,'purposeRef':self.ref}),
            ('capability-process-start','process-owner',{'planRef':self.ref}),
            ('capability-process-cancel','process-owner',{'runRef':self.ref}),
            ('capability-policy-evaluate','policy-owner',{'action':'read','resourceClass':'storage','resourceId':'task-one'}),
            ('capability-decision-request','decision-owner',{'proposalRef':self.ref})):
            self.envelope['contractId']=contract
            self.envelope['destinationServiceId']=service
            self.envelope['payload']['input']=inputs
            self.resign()
            with patch.object(self.reader,'evaluate',return_value=self.allowed):
                with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                    await self.receiver.handle(self.raw)
        self.assertEqual(len(self.js.messages),1)
