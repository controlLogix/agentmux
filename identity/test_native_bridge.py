"""Native authority resolves persisted enrollment through the real owner ledger."""
import base64
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.native_bridge import verify_response
from identity.test_authority import ref, SEED, NOW
from identity import test_service
from identity.test_service import _Clock

HOST_SEED = bytes([7]) * 32


def native_row():
    """A complete independent instance enrolled by an organization administrator."""
    digest = 'sha256:' + 'a' * 64
    scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
    times = {'issuedAt': '2026-10-09T12:00:00Z', 'expiresAt': '2026-10-09T12:10:00Z'}
    access = {'action': 'inspect', 'resourceClass': 'task', 'resourceId': 'task-one'}
    return {'ref': ref('native-instance'), 'status': 'active',
        'owner': {'pin': {'packageId': 'test-plugin', 'version': '1.0.0',
                         'manifestChecksum': digest, 'packageChecksum': digest,
                         'provenanceChecksum': digest},
                  'instanceId': 'plugin-one', 'epoch': 'b' * 64, 'generation': 1},
        'identityRef': ref('plugin'), 'hostIdentityRef': ref('host'),
        'manifestDigest': digest, 'relationship': 'independent', 'parentOwner': None,
        'configurationChecksum': digest,
        'facts': {'grant': {'grantId': 'native-grant', 'issuerHubId': 'hub-one',
                    'subjectInstanceId': 'plugin-one', 'scope': scope, 'actions': ['inspect'],
                    'resourceIds': ['task-one'], **times, 'policyRef': ref('native-policy'),
                    'parentGrantRef': None, 'revision': 1},
                  'policy': {'reference': ref('native-policy'), 'subjectInstanceId': 'plugin-one',
                    'scope': copy.deepcopy(scope), **times,
                    'decisions': [{'access': access, 'outcome': 'allow'}]},
                  'parentGrant': None, 'parentAccess': [], 'scopeRef': ref('native-scope'),
                  'configurationRevision': 1, 'secretReferences': [],
                  'domainBindings': [{'id': 'inspect-binding', 'contractId': 'task-inspect',
                      'action': 'inspect', 'resourceClass': 'task', 'resourceIds': ['task-one']}]}}


class NativeBridgeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Reuse the controlled broker fixture, not a fake authority reader or owner.
        test_service.ServiceTests.setUp(self)
        patch('identity.native_bridge.datetime', _Clock).start()
        self.row = native_row()
        state = self.record['state']
        state['nativeInstances'] = []
        for name, kind in [('host', 'service'), ('plugin', 'plugin')]:
            state['identities'].append({'ref': ref(name), 'status': 'active',
                                       'kind': kind, 'principalId': name + '-one', 'externalIdentity': None})
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('host-transport'), identityRef=ref('host'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        membership = copy.deepcopy(state['memberships'][0])
        membership.update(ref=ref('host-member'), identityRef=ref('host'))
        state['memberships'].append(membership)
        for method in ('bind-instance', 'admit-operation', 'recheck', 'prepare-domain-call'):
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=ref('host-' + method), callerRef=ref('host'), actorRef=ref('host'),
                         contractId='native-authority-' + method, resourceId='plugin-one')
            state['grants'].append(grant)
        for name, contract, resource in [('native-admin', 'identity-native-instance-set', 'authority-one'),
                                         ('inspect', 'task-inspect', 'task-one')]:
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=ref(name), contractId=contract, resourceId=resource)
            state['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)

    request = test_service.ServiceTests.request

    async def enroll(self):
        self.claims.update(operationId='enroll-native', contractId='identity-native-instance-set',
            grantRef=ref('native-admin'), payload={'authorityId': 'authority-one',
                                                  'record': self.row, 'previousRef': None})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['nativeInstances'], [self.row])

    def bridge_request(self, method='bind-instance', inp=None, **overrides):
        claims = {'purpose': 'agentmux-native-authority-request-v1', 'requestId': 'native-request',
            'method': method, 'profileId': 'profile-one', 'hubId': 'hub-one',
            'authorityId': 'authority-one', 'owner': copy.deepcopy(self.row['owner']),
            'signingKeyRef': ref('host-transport'), 'issuedAt': NOW.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (NOW + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'),
            'replySubject': '_INBOX.abcdefghijklmnop',
            'input': inp if inp is not None else {k: self.row[k] for k in
                ('manifestDigest', 'relationship', 'parentOwner', 'configurationChecksum')}}
        claims.update(overrides)
        return canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, HOST_SEED)})

    async def test_prepared_capability_request_binds_native_owner_and_current_authority(self):
        from identity.capability_service import evaluate_capability_service_request
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('storage-read'), contractId='capability-storage-read', resourceId='task-one')
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        binding = copy.deepcopy(self.row['facts']['domainBindings'][0])
        binding.update(id='storage-binding', contractId='capability-storage-read')
        self.row['facts']['domainBindings'].append(binding)
        await self.enroll()
        original = await self.operation_envelope()
        inp = {'operation': strict_loads(original)['operation'],
               'operationAuthorityRef': dict(ref('authority-one'), revision=2),
               'bindingId': 'storage-binding', 'contractId': 'capability-storage-read',
               'serviceRequestId': 'request_' + 'c' * 64, 'serviceReplySubject': '_INBOX.abcdefghijklmnop',
               'payload': {'resourceRef': ref('task-one'), 'input': {}},
               'originalEnvelopeBytes': base64.b64encode(original).decode()}
        reply = strict_loads(await self.service.native.handle(self.bridge_request('prepare-domain-call', inp)))
        raw = base64.b64decode(reply['claims']['result']['serviceRequestBytes'])
        snapshot = await self.service.reader.current()
        decision = evaluate_capability_service_request(snapshot, raw, service_id='storage-owner', now=NOW)
        self.assertEqual(decision.outcome, 'allowed')
        wrapped = strict_loads(raw)
        self.assertEqual(wrapped['claims']['replySubject'], inp['serviceReplySubject'])
        wrapped['claims']['owner']['generation'] += 1
        wrapped['signature'] = sign_claims(wrapped['claims'], SEED)
        with self.assertRaisesRegex(ContractError, 'capability_service_native_unavailable'):
            evaluate_capability_service_request(snapshot, canonical_bytes(wrapped), service_id='storage-owner', now=NOW)
        self.claims.update(operationId='revoke-host-transport', expectedVersion=2,
            contractId='identity-revoke', grantRef=ref('grant'),
            payload={'authorityId': 'authority-one', 'targetRef': ref('host-transport')})
        await self.service.handle(self.request())
        with self.assertRaisesRegex(ContractError, 'capability_service_credential_unavailable'):
            evaluate_capability_service_request(await self.service.reader.current(), raw,
                                                service_id='storage-owner', now=NOW)

    async def test_fresh_storage_attempt_preserves_business_operation_deadline(self):
        from identity.capability_service import evaluate_capability_service_request
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('storage-write'), contractId='capability-storage-write', resourceId='task-one')
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        binding = copy.deepcopy(self.row['facts']['domainBindings'][0])
        binding.update(id='storage-binding', contractId='capability-storage-write')
        self.row['facts']['domainBindings'].append(binding)
        await self.enroll()
        original = await self.operation_envelope()
        source = strict_loads(original)['operation']
        inp = {'operation': source,
               'operationAuthorityRef': dict(ref('authority-one'), revision=2),
               'bindingId': 'storage-binding', 'contractId': 'capability-storage-write',
               'serviceRequestId': 'request_' + 'c' * 64,
               'serviceReplySubject': '_INBOX.abcdefghijklmnop',
               'payload': {'resourceRef': ref('task-one'), 'input': {'value': {'saved': True}}},
               'originalEnvelopeBytes': base64.b64encode(original).decode()}
        attempts = []
        for seconds in (2, 4):
            expiry = (NOW + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')
            reply = strict_loads(await self.service.native.handle(
                self.bridge_request('prepare-domain-call', inp, expiresAt=expiry)))
            raw = base64.b64decode(reply['claims']['result']['serviceRequestBytes'])
            decision = evaluate_capability_service_request(await self.service.reader.current(),
                raw, service_id='storage-owner', now=NOW)
            self.assertEqual(decision.outcome, 'allowed')
            wrapped = strict_loads(raw)
            envelope = strict_loads(base64.b64decode(wrapped['claims']['envelopeBytes']))
            self.assertEqual(envelope['ingressAttestation']['claims']['expiresAt'],
                (NOW + timedelta(seconds=seconds)).isoformat(timespec='microseconds').replace('+00:00', 'Z'))
            with self.assertRaisesRegex(ContractError, '^capability_service_expired$'):
                evaluate_capability_service_request(await self.service.reader.current(),
                    raw, service_id='storage-owner', now=NOW + timedelta(seconds=seconds))
            attempts.append(envelope['operation'])
        self.assertEqual(attempts[0], attempts[1])
        self.assertEqual(attempts[0]['deadline'], source['deadline'])

    async def test_persisted_enrollment_signed_binding_and_revocation(self):
        with self.assertRaisesRegex(ContractError, 'native_instance_unavailable'):
            await self.service.native.handle(self.bridge_request())
        await self.enroll()
        request = self.bridge_request()
        response = await self.service.native.handle(request)
        claims = verify_response(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], signing_key_ref=ref('issuer'), now=NOW)
        self.assertEqual(claims['result'], self.row['facts'])
        self.assertEqual(claims['authoritySequence'], 2)
        wrong = strict_loads(request); wrong['claims']['owner']['generation'] = 2
        with self.assertRaisesRegex(ContractError, 'native_response_binding'):
            verify_response(response, canonical_bytes(wrong),
                public_key=self.record['state']['issuers'][0]['publicKey'],
                signing_key_ref=ref('issuer'), now=NOW)
        with self.assertRaisesRegex(ContractError, 'native_response_binding'):
            verify_response(response, request,
                public_key=self.record['state']['issuers'][0]['publicKey'],
                signing_key_ref=ref('issuer'), now=NOW + timedelta(seconds=4))
        self.claims.update(operationId='revoke-native', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=2, payload={'authorityId': 'authority-one', 'targetRef': ref('native-instance')})
        await self.service.handle(self.request())
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['nativeInstances'][0]['ref']['revision'], 2)
        with self.assertRaisesRegex(ContractError, 'native_instance_unavailable'):
            await self.service.native.handle(request)

    async def test_owner_profile_and_signature_must_match(self):
        await self.enroll()
        owner = copy.deepcopy(self.row['owner']); owner['generation'] = 2
        for request, error in [(self.bridge_request(owner=owner), 'native_instance_unavailable'),
                               (self.bridge_request(profileId='profile-other'), 'native_profile_mismatch')]:
            with self.assertRaisesRegex(ContractError, error): await self.service.native.handle(request)
        request = strict_loads(self.bridge_request())
        request['signature'] = sign_claims(request['claims'], SEED)
        with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
            await self.service.native.handle(canonical_bytes(request))

    async def test_host_method_hard_denial_wins(self):
        deny = copy.deepcopy(self.record['state']['grants'][1])
        deny.update(ref=ref('deny-bind'), decision='denied')
        self.record['state']['grants'].append(deny)
        self.js.messages[0].data = canonical_bytes(self.record)
        await self.enroll()
        with self.assertRaisesRegex(ContractError, 'native_host_not_authorized'):
            await self.service.native.handle(self.bridge_request())

    async def test_expiry_after_awaited_ledger_read(self):
        await self.enroll()
        request = self.bridge_request()
        class LaterClock(_Clock):
            @classmethod
            def now(cls, tz=None): return NOW + timedelta(seconds=4)
        original = self.js.stream_info
        async def advance(*args, **kwargs):
            result = await original(*args, **kwargs)
            patch('identity.native_bridge.datetime', LaterClock).start()
            return result
        self.js.stream_info = advance
        with self.assertRaisesRegex(ContractError, 'native_request_expired'):
            await self.service.native.handle(request)

    async def test_offline_authority_never_returns_retained_native_facts(self):
        await self.enroll()
        with patch.object(self.service.reader, 'current',
                          side_effect=TimeoutError('offline')) as current:
            with self.assertRaisesRegex(TimeoutError, '^offline$'):
                await self.service.native.handle(self.bridge_request())
        current.assert_awaited_once_with()

    async def operation_envelope(self):
        self.claims.update(operationId='inspect-operation', contractId='task-inspect',
                           grantRef=ref('inspect'), payload={'taskId': 'task-one'})
        result = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        self.assertEqual(result.decision.outcome, 'allowed')
        return result.envelope

    async def test_admit_recheck_and_original_envelope_tampering(self):
        await self.enroll()
        original = await self.operation_envelope()
        inp = {'envelopeBytes': base64.b64encode(original).decode(),
               'audience': {'hubId': 'hub-one', 'serviceId': 'task-owner'}}
        admitted = strict_loads(await self.service.native.handle(self.bridge_request('admit-operation', inp)))['claims']['result']
        recheck = {'instanceFactsDigest': payload_digest(self.row['facts']),
            'operation': admitted['operation'], 'operationAuthorityRef': admitted['authorityRef'],
            'originalEnvelopeBytes': inp['envelopeBytes']}
        checked = strict_loads(await self.service.native.handle(self.bridge_request('recheck', recheck)))
        self.assertEqual(checked['claims']['result']['operationAuthorityRef']['revision'], 2)
        changed = copy.deepcopy(recheck); changed['operation']['operationId'] = 'forged-operation'
        with self.assertRaisesRegex(ContractError, 'native_operation_binding'):
            await self.service.native.handle(self.bridge_request('recheck', changed))
        envelope = strict_loads(original); envelope['payload']['taskId'] = 'task-other'
        changed = copy.deepcopy(recheck); changed['originalEnvelopeBytes'] = base64.b64encode(canonical_bytes(envelope)).decode()
        with self.assertRaises(ContractError):
            await self.service.native.handle(self.bridge_request('recheck', changed))

    async def test_identity_revocation_keeps_retained_native_row_readable(self):
        await self.enroll()
        self.claims.update(operationId='revoke-plugin', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=2, payload={'authorityId': 'authority-one', 'targetRef': ref('plugin')})
        receipt = strict_loads(await self.service.handle(self.request()))['claims']['receipt']
        self.assertEqual(receipt['decision'], 'allowed')
        snapshot = await self.service.reader.current()
        state = strict_loads(snapshot.record)['state']
        self.assertEqual(state['nativeInstances'], [self.row])
        self.assertEqual(next(i for i in state['identities'] if i['ref']['id'] == 'plugin')['status'], 'revoked')
        with self.assertRaisesRegex(ContractError, 'native_instance_unavailable'):
            await self.service.native.handle(self.bridge_request())

    async def test_malformed_original_and_null_authority_ref_are_protocol_errors(self):
        await self.enroll()
        original = await self.operation_envelope()
        inp = {'instanceFactsDigest': payload_digest(self.row['facts']),
               'operation': strict_loads(original)['operation'], 'operationAuthorityRef': None,
               'originalEnvelopeBytes': base64.b64encode(original).decode()}
        with self.assertRaisesRegex(ContractError, 'native_operation_binding'):
            await self.service.native.handle(self.bridge_request('recheck', inp))
        inp['originalEnvelopeBytes'] = base64.b64encode(b'{}').decode()
        with self.assertRaisesRegex(ContractError, 'schema_invalid'):
            await self.service.native.handle(self.bridge_request('recheck', inp))
