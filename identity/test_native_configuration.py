"""Native configuration preparation retains independent ordinary authorization."""
import base64
import copy
import hashlib
from datetime import timedelta
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, payload_digest
from identity import test_native_bridge as fixtures
from identity.test_authority import ref, NOW
from identity.authority import evaluate_snapshot


class NativeConfigurationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixtures.NativeBridgeTests.setUp(self)
        state=self.record['state']
        for name,contract,resource in [('prepare','native-authority-prepare-configuration-request','plugin-one'),
                                       ('initialize','native-authority-prepare-configuration-initialization','plugin-one'),
                                       ('set','configuration-set','configuration-one'),
                                       ('read','configuration-read','configuration-one'),
                                       ('watch','configuration-watch','configuration-one')]:
            grant=copy.deepcopy(state['grants'][0])
            grant.update(ref=ref('config-'+name),callerRef=ref('host'),actorRef=ref('host'),contractId=contract,resourceId=resource)
            state['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)

    enroll=fixtures.NativeBridgeTests.enroll
    request=fixtures.NativeBridgeTests.request
    bridge_request=fixtures.NativeBridgeTests.bridge_request

    def inp(self,contract='configuration-read'):
        result={'configurationRef':ref('configuration-one'),'contractId':contract,'cancellationRef':ref('configuration-cancel')}
        if contract=='configuration-watch':result['afterRevision']=1
        return result

    async def prepare(self,inp=None):
        raw=self.bridge_request('prepare-configuration-request',inp or self.inp())
        return raw, strict_loads(await self.service.native.handle(raw))

    async def test_read_and_watch_preserve_exact_owner_cancellation_and_deadline(self):
        await self.enroll()
        for contract in ('configuration-read','configuration-watch'):
            inp=self.inp(contract)
            request,response=await self.prepare(inp)
            raw=base64.b64decode(response['claims']['result']['envelopeBytes'])
            envelope=strict_loads(raw)
            self.assertEqual(envelope['payload'],dict(configurationRef=inp['configurationRef'],owner=self.row['owner'],
                **({'afterRevision':1} if contract=='configuration-watch' else {})))
            self.assertEqual(envelope['operation']['cancellationRef'],inp['cancellationRef'])
            self.assertEqual(envelope['operation']['caller']['authenticatedIdentityRef'],ref('host'))
            self.assertEqual(envelope['operation']['payloadDigest'],payload_digest(envelope['payload']))
            self.assertEqual(envelope['operation']['deadline'],response['claims']['validUntil'])
            self.assertLessEqual(response['claims']['validUntil'],strict_loads(request)['claims']['expiresAt'])
            decision=evaluate_snapshot(await self.service.reader.current(),raw,
                audience={'hubId':'hub-one','serviceId':'configuration-owner'},now=NOW)
            self.assertEqual(decision.outcome,'allowed')

    async def test_missing_native_or_ordinary_grant_and_denial_refuse(self):
        original=copy.deepcopy(self.record)
        for target,decision in (('config-prepare','revoked'),('config-read','revoked'),('config-read','denied'),('config-read','review-required')):
            self.record=copy.deepcopy(original)
            grant=next(g for g in self.record['state']['grants'] if g['ref']['id']==target)
            grant.update(**({'status':'revoked'} if decision=='revoked' else {'decision':decision}))
            self.record['state']['nativeInstances']=[self.row]
            self.js.messages[0].data=canonical_bytes(self.record)
            # Each source mutation gets a fresh real ledger reader so no cache can hide it.
            from identity.native_bridge import NativeAuthorityProvider
            from identity.authority import LedgerAuthorityReader
            from state_owner.ledger import OwnerLedger
            ledger=OwnerLedger(self.js,stream=self.service.ledger._stream,subject=self.service.ledger._subject,
                binding=self.service.ledger._binding,retention=self.service.ledger._retention,stream_identity=self.service.ledger._identity)
            reader=LedgerAuthorityReader(ledger,hub_id='hub-one',entity_id='authority-one',profile_id='profile-one',organization_id='org-one')
            provider=NativeAuthorityProvider(reader,issuer_ref=ref('issuer'),signing_seed=fixtures.SEED)
            with self.assertRaises(ContractError):await provider.handle(self.bridge_request('prepare-configuration-request',self.inp()))

    async def test_cross_hub_set_and_malformed_inputs_refuse(self):
        await self.enroll()
        for change in (lambda i:i['configurationRef'].update(ownerHubId='other'),
                       lambda i:i['cancellationRef'].update(ownerHubId='other'),
                       lambda i:i.update(contractId='configuration-set'),lambda i:i.pop('cancellationRef'),
                       lambda i:i.update(afterRevision=0)):
            inp=self.inp();change(inp)
            with self.assertRaises(ContractError):await self.prepare(inp)
        inp=self.inp('configuration-watch');inp.pop('afterRevision')
        with self.assertRaises(ContractError):await self.prepare(inp)

    async def test_ordinary_grant_expiry_shortens_original_native_request(self):
        grant=next(g for g in self.record['state']['grants'] if g['ref']['id']=='config-read')
        grant['expiresAt']=(NOW+timedelta(seconds=1)).isoformat().replace('+00:00','Z')
        self.js.messages[0].data=canonical_bytes(self.record)
        await self.enroll()
        _,response=await self.prepare()
        envelope=strict_loads(base64.b64decode(response['claims']['result']['envelopeBytes']))
        self.assertEqual(envelope['operation']['deadline'],(NOW+timedelta(seconds=1)).isoformat(timespec='microseconds').replace('+00:00','Z'))

    async def test_initialization_uses_actual_owner_and_exact_admitted_bytes(self):
        from state_owner.test_configuration import ConfigurationTests
        from state_owner.configuration import ConfigurationOwner, verify_configuration_response
        from identity.configuration_events import ConfigurationEventProducer
        from nacl.signing import SigningKey
        from unittest.mock import patch
        from identity.test_service import _Clock
        clock_patch=patch('identity.configuration_events.datetime',_Clock)
        clock_patch.start(); self.addCleanup(clock_patch.stop)
        state=self.record['state']
        transport=copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('producer-transport'),identityRef=ref('service'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(fixtures.HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        membership=copy.deepcopy(state['memberships'][0])
        membership.update(ref=ref('producer-member'),identityRef=ref('service'))
        state['memberships'].append(membership)
        grant=copy.deepcopy(state['grants'][0])
        grant.update(ref=ref('producer-grant'),callerRef=ref('service'),actorRef=ref('service'),
            contractId='configuration-change',resourceId='configuration-one')
        state['grants'].append(grant)
        value=b'{"private":1}'
        self.row['configurationChecksum']='sha256:'+hashlib.sha256(value).hexdigest()
        self.js.messages[0].data=canonical_bytes(self.record)
        await self.enroll()
        payload={'configurationRef':dict(ref('configuration-one'),revision=0),'owner':self.row['owner'],
            'schemaRef':'config.json','configurationBytes':base64.b64encode(value).decode(),'secretReferences':[]}
        inp={'payload':payload,'cancellationRef':ref('initialization-cancel')}
        response=strict_loads(await self.service.native.handle(self.bridge_request('prepare-configuration-initialization',inp)))
        raw=base64.b64decode(response['claims']['result']['envelopeBytes'])
        envelope=strict_loads(raw)
        self.assertEqual(envelope['contractId'],'configuration-set')
        self.assertEqual(envelope['payload'],payload)
        self.assertEqual(envelope['operation']['cancellationRef'],inp['cancellationRef'])
        fixture=ConfigurationTests();fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.addAsyncCleanup(fixture.source.close)
        from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject
        binding=OwnerBinding('hub-one','configuration','configuration-one','configuration',
            canonical_bytes(self.row['facts']['grant']['scope']))
        fixture.js.config.subjects=[owner_subject(binding)]
        ledger=OwnerLedger(fixture.js,stream='OWNER',subject=owner_subject(binding),binding=binding,
            retention=fixture.policy,stream_identity=fixture.ledger._identity,require_completion_budget=True)
        owner=ConfigurationOwner(self.service.reader,ledger,owner=self.row['owner'],schema_ref='config.json',
            schema_resources={'config.json':b'{"type":"object"}'},issuer_ref=ref('issuer'),signing_seed=fixtures.SEED,
            event_producer=ConfigurationEventProducer(self.service.reader,hub_id='hub-one',profile_id='profile-one',
                authority_id='authority-one',configuration_id='configuration-one',scope=grant['scope'],
                identity_ref=ref('service'),transport_ref=ref('producer-transport'),grant_ref=ref('producer-grant'),
                transport_seed=fixtures.HOST_SEED,issuer_ref=ref('issuer'),signing_seed=fixtures.SEED))
        self.addAsyncCleanup(owner.close)
        signed=await owner.handle(raw)
        checked=verify_configuration_response(signed,raw,public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'),now=NOW)
        self.assertEqual(checked['state']['revision'],1)
        self.assertEqual(base64.b64decode(checked['state']['configurationBytes']),value)
        for change in (lambda p:p['owner'].update(generation=99),
                       lambda p:p['configurationRef'].update(revision=1),
                       lambda p:p.update(configurationBytes=base64.b64encode(b'{}').decode()),
                       lambda p:p.update(secretReferences=[ref('unadmitted-secret')])):
            changed=copy.deepcopy(payload);change(changed)
            with self.assertRaises(ContractError):
                await self.service.native.handle(self.bridge_request('prepare-configuration-initialization',
                    {'payload':changed,'cancellationRef':inp['cancellationRef']}))

    async def refused_initialization(self, grant_name):
        value=b'{}'
        self.row['configurationChecksum']='sha256:'+hashlib.sha256(value).hexdigest()
        next(g for g in self.record['state']['grants'] if g['ref']==ref(grant_name))['decision']='denied'
        self.js.messages[0].data=canonical_bytes(self.record)
        await self.enroll()
        payload={'configurationRef':dict(ref('configuration-one'),revision=0),'owner':self.row['owner'],
            'schemaRef':'config.json','configurationBytes':base64.b64encode(value).decode(),'secretReferences':[]}
        with self.assertRaises(ContractError):
            await self.service.native.handle(self.bridge_request('prepare-configuration-initialization',
                {'payload':payload,'cancellationRef':ref('initialization-cancel')}))

    async def test_initialization_needs_its_own_native_method_grant(self):
        await self.refused_initialization('config-initialize')

    async def test_initialization_needs_ordinary_set_authority(self):
        await self.refused_initialization('config-set')
