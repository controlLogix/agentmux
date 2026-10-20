"""Producer events use real enrolled transport proof and exact authority grants."""
import base64
import copy
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity import test_service
from identity.test_authority import ref, SEED, NOW
from identity.test_native_bridge import native_row, HOST_SEED
from identity.configuration_events import ConfigurationEventProducer
from identity.authority import evaluate_snapshot


class ConfigurationEventTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        test_service.ServiceTests.setUp(self)
        patch('identity.configuration_events.datetime',test_service._Clock).start()
        state=self.record['state']
        transport=copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('producer-transport'),identityRef=ref('service'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        membership=copy.deepcopy(state['memberships'][0]);membership.update(ref=ref('producer-member'),identityRef=ref('service'))
        state['memberships'].append(membership)
        grant=copy.deepcopy(state['grants'][0]);grant.update(ref=ref('producer-grant'),callerRef=ref('service'),actorRef=ref('service'),
            contractId='configuration-change',resourceId='configuration-one')
        state['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)
        self.producer=ConfigurationEventProducer(self.service.reader,hub_id='hub-one',profile_id='profile-one',
            authority_id='authority-one',configuration_id='configuration-one',scope=grant['scope'],identity_ref=ref('service'),
            transport_ref=ref('producer-transport'),grant_ref=ref('producer-grant'),transport_seed=HOST_SEED,
            issuer_ref=ref('issuer'),signing_seed=SEED)
        self.operation=copy.deepcopy(self.record['operation'])
        self.payload={'configurationRef':ref('configuration-one'),'owner':native_row()['owner'],
            'schemaRef':'config.json','configurationChecksum':'sha256:'+'a'*64}

    async def test_signed_event_has_transport_proof_exact_payload_and_producer_authority(self):
        prepared=await self.producer.prepare_change_event(self.payload,operation=self.operation)
        event=strict_loads(prepared.envelope)
        self.assertEqual(event['kind'],'event')
        self.assertEqual(event['contractId'],'configuration-change')
        self.assertEqual(event['payload'],self.payload)
        self.assertEqual(event['ingressAttestation']['claims']['authenticatedTransportRef'],ref('producer-transport'))
        self.assertEqual(event['operation']['caller']['authenticatedIdentityRef'],ref('service'))
        self.assertEqual(event['operation']['payloadDigest'],payload_digest(self.payload))
        self.assertEqual(evaluate_snapshot(await self.service.reader.current(),prepared.envelope,
            audience={'hubId':'hub-one','serviceId':'configuration-owner'},now=NOW).outcome,'allowed')
        second=await self.producer.prepare_change_event(self.payload,operation=self.operation)
        self.assertEqual(strict_loads(second.envelope)['operation']['operationId'],event['operation']['operationId'])
        self.assertEqual(len(self.js.messages),1)

    async def test_no_producer_permission_or_wrong_aggregate_refuses(self):
        wrong=copy.deepcopy(self.payload);wrong['configurationRef']['id']='other'
        with self.assertRaises(ContractError):await self.producer.prepare_change_event(wrong,operation=self.operation)
        next(g for g in self.record['state']['grants'] if g['ref']==ref('producer-grant'))['decision']='denied'
        self.js.messages[0].data=canonical_bytes(self.record)
        with self.assertRaises(ContractError):await self.producer.prepare_change_event(self.payload,operation=self.operation)

    async def test_event_cannot_include_configuration_or_secrets_or_extend_expired_operation(self):
        for field in ('configurationBytes','secretReferences'):
            payload=dict(self.payload,**{field:[]})
            with self.assertRaises(ContractError):await self.producer.prepare_change_event(payload,operation=self.operation)
        self.operation['deadline']=NOW.isoformat().replace('+00:00','Z')
        with self.assertRaisesRegex(ContractError,'configuration_event_expired'):
            await self.producer.prepare_change_event(self.payload,operation=self.operation)

    async def test_subscription_needs_separate_grant_and_exact_filter_and_revision_floor(self):
        from identity.ingress import EnrolledIngress
        payload={'resourceRef':ref('configuration-one'),'eventContractId':'configuration-change',
            'filter':{'owner':self.payload['owner'],'schemaRef':'config.json'},
            'cursor':{'sourceDigest':'sha256:'+'b'*64,'streamCreated':'2026-10-09T12:00:00Z','sequence':1}}
        payload['filterDigest']=payload_digest({k:payload[k] for k in ('resourceRef','eventContractId','filter')})
        self.claims.update(contractId='configuration-change-subscribe',payload=payload)
        ingress=EnrolledIngress(self.service.reader,issuer_ref=ref('issuer'),signing_seed=SEED)

        async def admit():
            return await ingress.admit(test_service.ServiceTests.request(self),cancellation_ref=ref('subscribe-cancel'))

        self.assertIsNone((await admit()).envelope)
        grant=next(g for g in self.record['state']['grants'] if g['ref']==ref('grant'))
        grant.update(contractId='configuration-change-subscribe',resourceId='configuration-one')
        self.js.messages[0].data=canonical_bytes(self.record)
        admitted=await admit()
        self.assertEqual(admitted.decision.outcome,'allowed')
        self.assertIsNotNone(admitted.envelope)
        original=copy.deepcopy(payload)
        for mutate in (lambda p:p.update(filterDigest='sha256:'+'c'*64),
                       lambda p:p['cursor'].update(sequence=0)):
            payload=copy.deepcopy(original); mutate(payload); self.claims['payload']=payload
            denied=await admit()
            self.assertIsNone(denied.envelope)
            self.assertEqual(denied.decision.reason,'configuration_subscription_binding')
