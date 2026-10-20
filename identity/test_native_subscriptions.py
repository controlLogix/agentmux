"""Native subscriptions retain independent subscriber and producer authority."""
import base64
import copy
import unittest
from datetime import timedelta
from unittest.mock import patch
from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity import test_native_bridge as fixtures
from identity.test_authority import ref, NOW, SEED
from identity.test_service import _Clock
from identity.configuration_events import ConfigurationEventProducer


class NativeSubscriptionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixtures.NativeBridgeTests.setUp(self)
        patch('identity.configuration_events.datetime', _Clock).start()
        state=self.record['state']
        for method in ('prepare-subscription-call','admit-domain-event'):
            grant=copy.deepcopy(state['grants'][0])
            grant.update(ref=ref(method),callerRef=ref('host'),actorRef=ref('host'),
                contractId='native-authority-'+method,resourceId='plugin-one')
            state['grants'].append(grant)
        for name,contract,caller in [('subscriber','configuration-change-subscribe',state['grants'][0]['callerRef']),
                                     ('producer','configuration-change',ref('service'))]:
            grant=copy.deepcopy(state['grants'][0])
            grant.update(ref=ref(name),callerRef=caller,actorRef=caller,contractId=contract,resourceId='configuration-one')
            state['grants'].append(grant)
        transport=copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('producer-transport'),identityRef=ref('service'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(fixtures.HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        member=copy.deepcopy(state['memberships'][0]);member.update(ref=ref('producer-member'),identityRef=ref('service'))
        state['memberships'].append(member)
        self.js.messages[0].data=canonical_bytes(self.record)
        facts=self.row['facts']
        facts['grant']['actions'].append('subscribe');facts['grant']['resourceIds'].append('configuration-one')
        facts['policy']['decisions'].append({'access':{'action':'subscribe','resourceClass':'configuration',
            'resourceId':'configuration-one'},'outcome':'allow'})
        facts['domainBindings'].append({'id':'subscription','contractId':'configuration-change-subscribe',
            'action':'subscribe','resourceClass':'configuration','resourceIds':['configuration-one']})
        from state_owner.test_configuration import ConfigurationTests
        from state_owner.configuration_events import ConfigurationEventRoute
        configuration=ConfigurationTests();configuration.setUp()
        self.addCleanup(configuration.doCleanups);self.addAsyncCleanup(configuration.source.close)
        self.configuration_ledger=configuration.ledger
        self.route=ConfigurationEventRoute.from_ledger(configuration.ledger,
            account_public_key='A'*56,jetstream_domain='SELECTED')
        self.row['configurationEventSources']=[{'configurationRef':ref('configuration-one'),
            'schemaRef':'config.json','sourceDigest':self.route.source_digest,'streamCreated':self.route.stream_created}]
        self.producer=ConfigurationEventProducer(self.service.reader,hub_id='hub-one',profile_id='profile-one',
            authority_id='authority-one',configuration_id='configuration-one',scope=grant['scope'],
            identity_ref=ref('service'),transport_ref=ref('producer-transport'),grant_ref=ref('producer'),
            transport_seed=fixtures.HOST_SEED,issuer_ref=ref('issuer'),signing_seed=SEED)

    enroll=fixtures.NativeBridgeTests.enroll
    request=fixtures.NativeBridgeTests.request
    bridge_request=fixtures.NativeBridgeTests.bridge_request
    operation_envelope=fixtures.NativeBridgeTests.operation_envelope

    async def prepare(self, mutate=None):
        await self.enroll()
        original=await self.operation_envelope()
        payload={'resourceRef':ref('configuration-one'),'eventContractId':'configuration-change',
            'filter':{'owner':copy.deepcopy(self.row['owner']),
                      'schemaRef':self.row['configurationEventSources'][0]['schemaRef']},
            'cursor':self.route.cursor(1)}
        if mutate:mutate(payload)
        payload['filterDigest']=payload_digest({k:payload[k] for k in ('resourceRef','eventContractId','filter')})
        inp={'operation':strict_loads(original)['operation'],'operationAuthorityRef':dict(ref('authority-one'),revision=2),
            'originalEnvelopeBytes':base64.b64encode(original).decode(),'bindingId':'subscription',
            'contractId':'configuration-change-subscribe','serviceRequestId':'request_'+'d'*64,'payload':payload}
        reply=strict_loads(await self.service.native.handle(self.bridge_request('prepare-subscription-call',inp)))
        self.inp={k:inp[k] for k in ('operation','operationAuthorityRef','originalEnvelopeBytes')}
        self.inp['subscriptionEnvelopeBytes']=reply['claims']['result']['envelopeBytes']
        self.event_payload={'configurationRef':dict(ref('configuration-one'),revision=2),'owner':self.row['owner'],
            'schemaRef':payload['filter']['schemaRef'],'configurationChecksum':'sha256:'+'e'*64}
        return reply

    async def event(self,payload=None):
        prepared=await self.producer.prepare_change_event(payload or self.event_payload,operation=self.inp['operation'])
        return base64.b64encode(prepared.envelope).decode()

    async def admit(self):
        return strict_loads(await self.service.native.handle(self.bridge_request('admit-domain-event',self.inp)))

    async def test_actual_producer_event_admits_new_revision_with_original_lifetime(self):
        opening=await self.prepare()
        self.inp['eventEnvelopeBytes']=await self.event()
        admitted=await self.admit()
        self.assertEqual(strict_loads(base64.b64decode(admitted['claims']['result']['payloadBytes'])),self.event_payload)
        self.assertLessEqual(admitted['claims']['validUntil'],opening['claims']['validUntil'])
        event=strict_loads(base64.b64decode(self.inp['eventEnvelopeBytes']))
        self.assertEqual(event['payload']['configurationRef']['revision'],2)

    async def test_existing_maximum_schema_reference_fits_signed_native_frames(self):
        self.row['configurationEventSources'][0]['schemaRef']='a'*4096
        await self.prepare();self.inp['eventEnvelopeBytes']=await self.event()
        admitted=await self.admit()
        self.assertEqual(len(strict_loads(base64.b64decode(admitted['claims']['result']['payloadBytes']))['schemaRef']),4096)
        from agentmux_contracts import validate
        payload=copy.deepcopy(self.event_payload);payload['schemaRef']+='a'
        with self.assertRaises(ContractError):validate('configuration-change',payload)

    async def test_wrong_source_schema_owner_or_stream_refuses_preparation(self):
        from state_owner.configuration_events import ConfigurationEventRoute
        wrong_account=ConfigurationEventRoute.from_ledger(self.configuration_ledger,
            account_public_key='A'+'B'*55,jetstream_domain='SELECTED')
        await self.enroll()
        original=await self.operation_envelope()
        # Each case starts from the same enrolled row without another write.
        for mutate in (lambda p:p['cursor'].update(sourceDigest=wrong_account.source_digest),
                       lambda p:p['cursor'].update(streamCreated='2026-10-09T12:00:01Z'),
                       lambda p:p['filter'].update(schemaRef='other.json'),
                       lambda p:p['filter']['owner'].update(generation=99)):
            payload={'resourceRef':ref('configuration-one'),'eventContractId':'configuration-change',
                'filter':{'owner':copy.deepcopy(self.row['owner']),'schemaRef':'config.json'},
                'cursor':self.route.cursor(1)}
            mutate(payload)
            payload['filterDigest']=payload_digest({k:payload[k] for k in ('resourceRef','eventContractId','filter')})
            inp={'operation':strict_loads(original)['operation'],'operationAuthorityRef':dict(ref('authority-one'),revision=2),
                'originalEnvelopeBytes':base64.b64encode(original).decode(),'bindingId':'subscription',
                'contractId':'configuration-change-subscribe','serviceRequestId':'request_'+'d'*64,'payload':payload}
            with self.assertRaisesRegex(ContractError,'native_subscription_source_binding'):
                await self.service.native.handle(self.bridge_request('prepare-subscription-call',inp))

    async def test_event_wrong_owner_schema_or_old_revision_refuses(self):
        await self.prepare()
        for mutate in (lambda p:p['owner'].update(generation=99),lambda p:p.update(schemaRef='other.json'),
                       lambda p:p['configurationRef'].update(revision=1)):
            payload=copy.deepcopy(self.event_payload);mutate(payload)
            self.inp['eventEnvelopeBytes']=await self.event(payload)
            with self.assertRaisesRegex(ContractError,'native_subscription_event_binding'):await self.admit()

    async def test_current_producer_revocation_refuses_original_event(self):
        await self.prepare();self.inp['eventEnvelopeBytes']=await self.event()
        latest=strict_loads(self.js.messages[-1].data)
        next(g for g in latest['state']['grants'] if g['ref']==ref('producer'))['decision']='denied'
        self.js.messages[-1].data=canonical_bytes(latest)
        with self.assertRaisesRegex(ContractError,'native_subscription_not_authorized'):await self.admit()

    async def test_current_subscriber_denial_and_owner_revocation_refuse(self):
        await self.prepare();self.inp['eventEnvelopeBytes']=await self.event()
        original=self.js.messages[-1].data
        for change in (lambda s:next(g for g in s['grants'] if g['ref']==ref('subscriber')).update(decision='denied'),
                       lambda s:s['nativeInstances'][0].update(status='revoked'),
                       lambda s:s['nativeInstances'][0].pop('configurationEventSources')):
            latest=strict_loads(original);change(latest['state']);self.js.messages[-1].data=canonical_bytes(latest)
            with self.assertRaises(ContractError):await self.admit()

    async def test_expired_original_subscription_cannot_be_renewed_by_fresh_native_call(self):
        await self.prepare();self.inp['eventEnvelopeBytes']=await self.event()
        class Later(_Clock):
            @classmethod
            def now(cls,tz=None):return NOW+timedelta(seconds=5)
        with patch('identity.native_bridge.datetime',Later):
            request=self.bridge_request('admit-domain-event',self.inp,
                issuedAt=(NOW+timedelta(seconds=5)).isoformat().replace('+00:00','Z'),
                expiresAt=(NOW+timedelta(seconds=9)).isoformat().replace('+00:00','Z'))
            with self.assertRaises(ContractError):await self.service.native.handle(request)
