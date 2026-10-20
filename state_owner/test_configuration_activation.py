"""Fresh owners require actual retained identity activation and a new write."""
import copy
import base64
import hashlib
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.test_authority import fixture, ref, SEED
from identity import test_native_activation as activation_support
from identity.test_service import _Clock
from identity.configuration_events import ConfigurationEventProducer
from nacl.signing import SigningKey
from state_owner.configuration import ConfigurationOwner
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner import test_configuration as configuration_support
from state_owner.test_ledger import FakeJetStream, CREATED

PRODUCER_SEED = bytes([23]) * 32


def enroll_event_producer(state, scope):
    identity = ref('service')
    transport = copy.deepcopy(state['transports'][0])
    transport.update(ref=ref('configuration-event-transport'), identityRef=identity,
        issuerRef=ref('issuer'), publicKey=base64.urlsafe_b64encode(
            bytes(SigningKey(PRODUCER_SEED).verify_key)).decode().rstrip('='))
    state['transports'].append(transport)
    grant = copy.deepcopy(state['grants'][0])
    grant.update(ref=ref('configuration-event-grant'), callerRef=identity, actorRef=identity,
        contractId='configuration-change', resourceId='configuration-one', scope=copy.deepcopy(scope))
    state['grants'].append(grant)
    membership = copy.deepcopy(state['memberships'][0])
    membership.update(ref=ref('configuration-event-member'), identityRef=identity, scope=copy.deepcopy(scope))
    state['memberships'].append(membership)


def event_producer(authority, scope):
    return ConfigurationEventProducer(authority, hub_id='hub-one', profile_id='profile-one',
        authority_id='authority-one', configuration_id='configuration-one',
        scope=scope,
        identity_ref=ref('service'), transport_ref=ref('configuration-event-transport'),
        grant_ref=ref('configuration-event-grant'), transport_seed=PRODUCER_SEED,
        issuer_ref=ref('issuer'), signing_seed=SEED)


class ConfigurationActivationTests(unittest.IsolatedAsyncioTestCase):
    request = activation_support.NativeActivationTests.request
    bridge_request = activation_support.NativeActivationTests.bridge_request
    activation = activation_support.NativeActivationTests.activation
    configuration_request = configuration_support.ConfigurationTests.request
    call = configuration_support.ConfigurationTests.call

    def setUp(self):
        activation_support.NativeActivationTests.setUp(self)
        patch('state_owner.configuration.datetime', _Clock).start()
        patch('state_owner.configuration_watch_control.datetime', _Clock).start()
        patch('identity.configuration_events.datetime', _Clock).start()
        self.envelope = fixture()[1]
        scope = self.row['facts']['grant']['scope']
        self.envelope['operation'].update(scope=copy.deepcopy(scope),
            caller={'principalId': 'host-one', 'kind': 'service', 'authenticatedIdentityRef': ref('host')},
            effectiveActorRef=ref('host'))
        self.envelope['ingressAttestation']['claims']['authenticatedTransportRef'] = ref('host-transport')
        for name in ('read', 'set', 'watch'):
            grant = copy.deepcopy(self.record['state']['grants'][0])
            grant.update(ref=ref('configuration-' + name), callerRef=ref('host'), actorRef=ref('host'),
                contractId='configuration-' + name, resourceId='configuration-one')
            self.record['state']['grants'].append(grant)
        method = copy.deepcopy(self.record['state']['grants'][-1])
        method.update(ref=ref('configuration-initialize'),
            contractId='native-authority-prepare-configuration-initialization', resourceId='plugin-one')
        self.record['state']['grants'].append(method)
        read_method = copy.deepcopy(method)
        read_method.update(ref=ref('configuration-prepare'), contractId='native-authority-prepare-configuration-request')
        self.record['state']['grants'].append(read_method)
        enroll_event_producer(self.record['state'], scope)
        self.js.messages[0].data = canonical_bytes(self.record)
        self.binding = OwnerBinding('hub-one', 'configuration', 'configuration-one', 'configuration', canonical_bytes(scope))
        policy = Retention(16 * 131072, 131072)
        self.configuration_js = FakeJetStream(policy)
        self.configuration_js.config.subjects = [owner_subject(self.binding)]
        ledger = OwnerLedger(self.configuration_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=policy, stream_identity=StreamIdentity(CREATED, 0), require_completion_budget=True)
        admitted = copy.deepcopy(self.row['owner'])
        admitted.update(epoch='b' * 64, generation=1)
        self.producer = event_producer(self.service.reader, scope)
        self.source = ConfigurationOwner(self.service.reader, ledger, owner=admitted,
            schema_ref='config.json', schema_resources={'config.json': b'{"type":"object"}'},
            issuer_ref=ref('issuer'), signing_seed=SEED, event_producer=self.producer)
        self.addAsyncCleanup(self.source.close)
        self.owner, self.number = copy.deepcopy(self.row['owner']), 0
        self.value = b' {"private":1} '
        self.row['configurationChecksum'] = 'sha256:' + hashlib.sha256(self.value).hexdigest()
        self.row['facts']['secretReferences'] = [ref('secret-reference')]

    async def test_initial_activation_new_record_rebind_and_old_history(self):
        proposal = await self.source.prepare_initialization(owner=self.owner,
            configuration_bytes=self.value, secret_references=self.row['facts']['secretReferences'])
        self.assertEqual(proposal['configurationRef']['revision'], 0)
        self.assertEqual(self.configuration_js.messages, [])
        raw = self.configuration_request('set')
        with self.assertRaisesRegex(ContractError, '^configuration_binding_mismatch$'):
            await self.call(raw)
        activated = strict_loads(await self.service.handle(self.activation()))
        self.assertEqual(activated['claims']['result']['enrollmentRef'], self.row['ref'])
        result = await self.call(raw)
        self.assertEqual(result['owner'], self.owner)
        self.assertEqual(result['state']['revision'], 1)
        original = self.configuration_js.messages[0].data
        self.assertEqual((await self.call(raw))['state'], result['state'])
        self.assertEqual((await self.call(self.configuration_request()))['state'], result['state'])
        self.assertEqual(len(self.configuration_js.messages), 1)

        old_read = self.configuration_request(revision=1)
        previous = copy.deepcopy(self.row['ref'])
        self.row['ref']['revision'] += 1
        self.row['owner']['generation'] += 1
        self.row['facts']['configurationRevision'] = 2
        self.owner = copy.deepcopy(self.row['owner'])
        await self.service.handle(self.activation(previousRef=previous, expectedVersion=2))
        await self.call(self.configuration_request('set', revision=1))
        self.assertEqual(self.configuration_js.messages[0].data, original)
        self.assertEqual(strict_loads(self.configuration_js.messages[1].data)['state']['owner'], self.owner)
        with self.assertRaisesRegex(ContractError, '^configuration_binding_mismatch$'):
            await self.call(old_read)
        self.assertEqual((await self.call(self.configuration_request(revision=2)))['state']['revision'], 2)

    async def test_activation_does_not_allow_changed_configuration_or_stale_revision(self):
        await self.service.handle(self.activation())
        for changes in ({'value': b'{"private":2}'}, {'revision': 1}):
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                await self.call(self.configuration_request('set', **changes))
        self.assertEqual(self.configuration_js.messages, [])
        await self.call(self.configuration_request('set'))
        self.row['owner']['generation'] += 1
        self.owner = copy.deepcopy(self.row['owner'])
        with self.assertRaises(ContractError):
            await self.call(self.configuration_request('set', revision=1))
        self.assertEqual(len(self.configuration_js.messages), 1)

    async def test_changed_secret_reference_and_stale_selected_owner_cannot_commit(self):
        await self.service.handle(self.activation())
        envelope = strict_loads(self.configuration_request('set'))
        envelope['payload']['secretReferences'] = []
        envelope['operation']['payloadDigest'] = payload_digest(envelope['payload'])
        claims = envelope['ingressAttestation']['claims']
        claims['operation'] = copy.deepcopy(envelope['operation'])
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        with self.assertRaises(ContractError):
            await self.call(canonical_bytes(envelope))
        self.owner.update(epoch='b' * 64, generation=1)
        with self.assertRaises(ContractError):
            await self.call(self.configuration_request('set'))
        self.assertEqual(self.configuration_js.messages, [])

    async def test_native_revocation_after_commit_refuses_success_and_retry(self):
        await self.revocation_after_commit(ref('plugin'))

    async def test_method_revocation_after_commit_refuses_success_and_retry(self):
        await self.revocation_after_commit(ref('configuration-initialize'))

    async def revocation_after_commit(self, target):
        await self.service.handle(self.activation())
        original = self.source._ledger.append
        async def revoke_after_commit(*args, **kwargs):
            stored = await original(*args, **kwargs)
            self.claims.update(operationId='revoke-configuration-plugin', expectedVersion=2,
                contractId='identity-revoke', grantRef=ref('grant'),
                payload={'authorityId': 'authority-one', 'targetRef': target})
            await self.service.handle(self.request())
            return stored
        raw = self.configuration_request('set')
        with patch.object(self.source._ledger, 'append', side_effect=revoke_after_commit):
            with self.assertRaises(ContractError):
                await self.call(raw)
        with self.assertRaises(ContractError):
            await self.call(raw)
        self.assertEqual(len(self.configuration_js.messages), 1)

    async def test_method_revocation_after_preparation_cannot_commit(self):
        await self.service.handle(self.activation())
        payload = await self.source.prepare_initialization(owner=self.owner,
            configuration_bytes=self.value, secret_references=self.row['facts']['secretReferences'])
        response = strict_loads(await self.service.native.handle(self.bridge_request(
            'prepare-configuration-initialization', {'payload': payload, 'cancellationRef': ref('initialize-cancel')})))
        raw = base64.b64decode(response['claims']['result']['envelopeBytes'])
        self.claims.update(operationId='revoke-initialization-method', expectedVersion=2,
            contractId='identity-revoke', grantRef=ref('grant'),
            payload={'authorityId': 'authority-one', 'targetRef': ref('configuration-initialize')})
        await self.service.handle(self.request())
        with self.assertRaisesRegex(ContractError, '^configuration_initialization_not_authorized$'):
            await self.call(raw)
        self.assertEqual(self.configuration_js.messages, [])

    async def test_exact_selected_owner_without_activation_cannot_commit(self):
        ledger = self.source._ledger
        await self.source.close()
        self.source = ConfigurationOwner(self.service.reader, ledger, owner=self.owner,
            schema_ref='config.json', schema_resources={'config.json': b'{"type":"object"}'},
            issuer_ref=ref('issuer'), signing_seed=SEED, event_producer=self.producer)
        self.addAsyncCleanup(self.source.close)
        with self.assertRaisesRegex(ContractError, '^configuration_binding_mismatch$'):
            await self.call(self.configuration_request('set'))
        self.assertEqual(self.configuration_js.messages, [])

    async def prepared_read(self):
        await self.service.handle(self.activation())
        await self.call(self.configuration_request('set'))
        response = strict_loads(await self.service.native.handle(self.bridge_request(
            'prepare-configuration-request', {'configurationRef': dict(ref('configuration-one'), revision=1),
                'contractId': 'configuration-read', 'cancellationRef': ref('read-cancel')})))
        return base64.b64decode(response['claims']['result']['envelopeBytes'])

    async def revoke(self, target):
        self.claims.update(operationId='revoke-before-disclosure', expectedVersion=2,
            contractId='identity-revoke', grantRef=ref('grant'),
            payload={'authorityId': 'authority-one', 'targetRef': target})
        await self.service.handle(self.request())

    async def test_prepared_read_after_plugin_revocation_cannot_disclose(self):
        raw = await self.prepared_read()
        response = strict_loads(await self.service.native.handle(self.bridge_request(
            'prepare-configuration-request', {'configurationRef': dict(ref('configuration-one'), revision=1),
                'contractId': 'configuration-watch', 'afterRevision': 0,
                'cancellationRef': ref('watch-cancel')})))
        watch_raw = base64.b64decode(response['claims']['result']['envelopeBytes'])
        from capability_owner.test_reply_service import Connection
        self.source._connection = Connection()
        await self.revoke(ref('plugin'))
        for request in (raw, watch_raw):
            with self.assertRaises(ContractError):
                await self.call(request)
        self.assertFalse(self.source._watches)

    async def test_prepared_read_after_method_revocation_cannot_disclose(self):
        raw = await self.prepared_read()
        await self.revoke(ref('configuration-prepare'))
        with self.assertRaisesRegex(ContractError, '^configuration_native_not_authorized$'):
            await self.call(raw)

    async def test_read_does_not_require_initialization_method_authority(self):
        raw = await self.prepared_read()
        await self.revoke(ref('configuration-initialize'))
        self.assertEqual((await self.call(raw))['state']['revision'], 1)

    async def test_prepared_read_after_generation_replacement_cannot_disclose(self):
        raw = await self.prepared_read()
        previous = copy.deepcopy(self.row['ref'])
        self.row['ref']['revision'] += 1
        self.row['owner']['generation'] += 1
        self.row['facts']['configurationRevision'] = 2
        await self.service.handle(self.activation(previousRef=previous, expectedVersion=2))
        with self.assertRaisesRegex(ContractError, '^configuration_binding_mismatch$'):
            await self.call(raw)
        self.assertEqual(len(self.configuration_js.messages), 1)
