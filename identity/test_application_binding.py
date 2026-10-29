"""Actual retained authority with controlled host lifetime and signed observations."""
import asyncio
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch, AsyncMock

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.application_binding import ApplicationBindingProvider, ApplicationObservationLease, verify_response
from identity import test_service
from identity.test_authority import ref, SEED, NOW


def signed(claims, seed=SEED):
    return canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
        'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims, 'signature': sign_claims(claims, seed)})


class ApplicationBindingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        test_service.ServiceTests.setUp(self)
        patch('identity.application_binding.datetime', test_service._Clock).start()
        state = self.record['state']
        grant = copy.deepcopy(state['grants'][0])
        grant.update(ref=ref('application-client'), contractId='application-bind', resourceId='application-one')
        state['grants'].append(grant)
        attest = copy.deepcopy(grant)
        attest.update(ref=ref('application-host'), contractId='application-attest',
                      callerRef=ref('service'), actorRef=ref('service'))
        state['grants'].append(attest)
        membership = copy.deepcopy(state['memberships'][0])
        membership.update(ref=ref('host-member'), identityRef=ref('service'))
        state['memberships'].append(membership)
        self.js.messages[0].data = canonical_bytes(self.record)
        times = {'issuedAt': NOW.isoformat().replace('+00:00', 'Z'),
                 'expiresAt': (NOW + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}
        shared = {'hubId': 'hub-one', 'profileId': 'profile-one', 'instanceId': 'application-one', 'generation': 1, 'lifetimeId': 'd' * 64,
                  'releaseDigest': 'sha256:' + 'a' * 64, 'policyRef': ref('policy'), 'workspaceRef': None, **times}
        self.observed = {'purpose': 'agentmux-application-runtime-observation-v1',
                         **shared, 'scope': copy.deepcopy(grant['scope']), 'signingKeyRef': ref('issuer')}
        self.binding = {'purpose': 'agentmux-application-binding-request-v1', **shared,
            'requestId': 'bind-request', 'nonce': 'b' * 64, 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('application-client'),
            'replySubject': '_INBOX.abcdefghijklmnop'}
        self.done = asyncio.Event()
        self.make_provider()

    request = test_service.ServiceTests.request

    def make_provider(self, seed=SEED):
        self.lease = ApplicationObservationLease(signed(self.observed, seed), self.done)
        self.provider = ApplicationBindingProvider(self.service.reader, observation_lease=self.lease,
                                                   issuer_ref=ref('issuer'), signing_seed=SEED)

    def binding_request(self):
        return signed(self.binding, bytes(reversed(SEED)))

    async def test_signed_observation_delivery_and_lifetime_end(self, end=True):
        import base64
        patch('identity.observation_updates.datetime', test_service._Clock).start()
        transport = copy.deepcopy(self.record['state']['transports'][0])
        transport.update(ref=ref('attestor-transport'), identityRef=ref('service'),
                         publicKey=self.record['state']['issuers'][0]['publicKey'])
        self.record['state']['transports'].append(transport)
        self.js.messages[0].data = canonical_bytes(self.record)
        claims = {'purpose': 'agentmux-application-observation-update-v1',
            'requestId': 'observation-one', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'action': 'refresh', 'generation': 1,
            'lifetimeId': 'd' * 64, 'transportRef': ref('attestor-transport'),
            'observationBytes': base64.b64encode(signed(self.observed)).decode(),
            'replySubject': '_INBOX.abcdefghijklmnop', 'issuedAt': self.observed['issuedAt'],
            'expiresAt': self.observed['expiresAt']}
        from types import SimpleNamespace
        from identity.ingress import verify_possession
        self.service._connection.publish = AsyncMock()
        request = signed(claims)
        # A substituted NATS reply cannot install a lease or receive a receipt.
        await self.service._receive(SimpleNamespace(data=request, reply='_INBOX.wrongreplyinboxxx'))
        self.assertIsNone(self.service._application_lease)
        self.service._connection.publish.assert_not_awaited()
        await self.service._receive(SimpleNamespace(data=request, reply=claims['replySubject']))
        self.service._connection.publish.assert_awaited_once()
        destination, raw_receipt = self.service._connection.publish.await_args.args
        self.assertEqual(destination, claims['replySubject'])
        receipt = strict_loads(raw_receipt)
        verify_possession(receipt['claims'], receipt['signature'],
                          self.record['state']['issuers'][0]['publicKey'])
        self.assertEqual(receipt['claims']['requestDigest'], payload_digest(strict_loads(request)))
        self.assertEqual(receipt['claims']['action'], 'refresh')
        await self.service.handle(self.binding_request())
        self.update_claims = copy.deepcopy(claims)
        if not end:
            return
        claims.update(action='end', requestId='end-one')
        await self.service.handle(signed(claims))
        with self.assertRaisesRegex(ContractError, 'application_lifetime_ended'):
            await self.service.handle(self.binding_request())
        claims.update(action='refresh', requestId='replay-one')
        with self.assertRaisesRegex(ContractError, 'application_lifetime_ended'):
            await self.service.handle(signed(claims))

    async def test_expired_binding_allows_new_verified_generation_after_lost_end(self):
        import base64
        await self.test_signed_observation_delivery_and_lifetime_end(end=False)
        self.assertFalse(self.service._application_lease.done.is_set())
        class Later(test_service._Clock):
            @classmethod
            def now(cls, tz=None): return NOW + timedelta(seconds=6)
        patch('identity.observation_updates.datetime', Later).start()
        fresh = copy.deepcopy(self.observed)
        fresh.update(generation=2, lifetimeId='e' * 64,
            issuedAt=(NOW + timedelta(seconds=6)).isoformat().replace('+00:00', 'Z'),
            expiresAt=(NOW + timedelta(seconds=10)).isoformat().replace('+00:00', 'Z'))
        claims = copy.deepcopy(self.update_claims)
        claims.update(generation=2, lifetimeId='e' * 64, requestId='new-runtime',
            issuedAt=fresh['issuedAt'], expiresAt=fresh['expiresAt'],
            observationBytes=base64.b64encode(signed(fresh)).decode())
        await self.service.handle(signed(claims))
        self.assertEqual(self.service._application_lease.generation, 2)
        stale = copy.deepcopy(fresh); stale.update(generation=1, lifetimeId='d' * 64)
        claims.update(generation=1, lifetimeId='d' * 64, requestId='stale-runtime',
                      observationBytes=base64.b64encode(signed(stale)).decode())
        with self.assertRaisesRegex(ContractError, 'application_generation_mismatch'):
            await self.service.handle(signed(claims))

    async def test_host_refresh_and_generation_replacement(self):
        fresh = copy.deepcopy(self.observed)
        fresh['issuedAt'] = (NOW + timedelta(seconds=6)).isoformat().replace('+00:00', 'Z')
        fresh['expiresAt'] = (NOW + timedelta(seconds=10)).isoformat().replace('+00:00', 'Z')
        self.lease.refresh(signed(fresh))
        with self.assertRaisesRegex(ContractError, 'application_refresh_mismatch'):
            self.lease.refresh(signed(self.observed))
        changed = copy.deepcopy(fresh); changed.update(generation=2, lifetimeId='e' * 64)
        with self.assertRaisesRegex(ContractError, 'application_refresh_mismatch'):
            self.lease.refresh(signed(changed))
        class Later(test_service._Clock):
            @classmethod
            def now(cls, tz=None): return NOW + timedelta(seconds=6)
        patch('identity.application_binding.datetime', Later).start()
        self.binding.update(issuedAt=fresh['issuedAt'], expiresAt=fresh['expiresAt'])
        response = strict_loads(await self.provider.handle(self.binding_request()))
        self.assertEqual(response['claims']['generation'], 1)
        self.service.replace_application_lease(self.lease)
        successor = ApplicationObservationLease(signed(changed), asyncio.Event())
        with self.assertRaisesRegex(ContractError, 'application_generation_mismatch'):
            self.service.replace_application_lease(successor)
        self.done.set()
        self.service.replace_application_lease(successor)
        self.assertEqual(self.service._application_lease.generation, 2)

    async def test_actual_ledger_binding_and_trusted_reply_verification(self):
        request = self.binding_request()
        response = await self.provider.handle(request)
        claims = verify_response(response, request, public_key=self.record['state']['issuers'][0]['publicKey'],
                                 signing_key_ref=ref('issuer'), now=NOW)
        self.assertEqual(claims['callerRef'], ref('human'))
        self.assertEqual(claims['scope'], self.observed['scope'])
        self.assertEqual(claims['authoritySequence'], 1)
        self.assertEqual(len(self.js.messages), 1)
        self.binding['nonce'] = 'c' * 64
        with self.assertRaisesRegex(ContractError, 'application_response_binding'):
            verify_response(response, self.binding_request(), public_key=self.record['state']['issuers'][0]['publicKey'],
                            signing_key_ref=ref('issuer'), now=NOW)

    async def test_exact_runtime_tuple_and_observer_possession(self):
        self.binding['releaseDigest'] = 'sha256:' + 'c' * 64
        with self.assertRaisesRegex(ContractError, 'application_binding_mismatch'):
            await self.provider.handle(self.binding_request())
        self.binding['releaseDigest'] = self.observed['releaseDigest']
        self.make_provider(bytes(reversed(SEED)))
        with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
            await self.provider.handle(self.binding_request())

    async def test_host_attestation_permission_and_membership_are_required(self):
        state = self.record['state']
        state['grants'][2]['decision'] = 'denied'
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await self.provider.handle(self.binding_request())
        state['grants'][2]['decision'] = 'allowed'
        state['memberships'][1]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await self.provider.handle(self.binding_request())

    async def test_current_grant_revocation_and_hard_denial(self):
        deny = copy.deepcopy(self.record['state']['grants'][1])
        deny.update(ref=ref('client-denial'), decision='denied')
        self.record['state']['grants'].append(deny)
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await self.provider.handle(self.binding_request())
        self.record['state']['grants'].pop()
        self.js.messages[0].data = canonical_bytes(self.record)
        self.claims.update(operationId='revoke-app', contractId='identity-revoke',
            payload={'authorityId': 'authority-one', 'targetRef': ref('application-client')})
        await self.service.handle(self.request())
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await self.provider.handle(self.binding_request())

    async def test_lifetime_ends_during_awaited_authority_read(self):
        original = self.js.stream_info
        async def end(*args, **kwargs):
            result = await original(*args, **kwargs)
            self.done.set()
            return result
        self.js.stream_info = end
        with self.assertRaisesRegex(ContractError, 'application_lifetime_ended'):
            await self.provider.handle(self.binding_request())
        with self.assertRaisesRegex(ContractError, 'application_lifetime_ended'):
            await self.provider.handle(self.binding_request())

    async def test_clock_expiry_and_future_denial_bound_response(self):
        deny = copy.deepcopy(self.record['state']['grants'][1])
        boundary = NOW + timedelta(seconds=1)
        deny.update(ref=ref('future-denial'), decision='denied', issuedAt=boundary.isoformat().replace('+00:00', 'Z'))
        self.record['state']['grants'].append(deny)
        self.js.messages[0].data = canonical_bytes(self.record)
        response = strict_loads(await self.provider.handle(self.binding_request()))
        self.assertEqual(response['claims']['validUntil'], boundary.isoformat(timespec='microseconds').replace('+00:00', 'Z'))
        class Later(test_service._Clock):
            @classmethod
            def now(cls, tz=None): return NOW + timedelta(seconds=4)
        patch('identity.application_binding.datetime', Later).start()
        with self.assertRaisesRegex(ContractError, 'application_observation_expired'):
            await self.provider.handle(self.binding_request())

    async def test_direct_plugin_and_unenrolled_observer_are_refused(self):
        self.record['state']['identities'][0]['kind'] = 'plugin'
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await self.provider.handle(self.binding_request())
        self.observed['signingKeyRef'] = ref('unknown-issuer')
        self.make_provider()
        with self.assertRaisesRegex(ContractError, 'application_credential_unavailable'):
            await self.provider.handle(self.binding_request())


class ObservationIntervalTests(unittest.TestCase):
    """Only the owner's runtime observation may live OBSERVATION_SECONDS; requests keep 5 s."""
    def claims(self, seconds):
        stamp = lambda value: value.isoformat().replace('+00:00', 'Z')
        return {'issuedAt': stamp(NOW), 'expiresAt': stamp(NOW + timedelta(seconds=seconds))}

    def test_observation_limit_is_separate_from_the_request_limit(self):
        from identity.application_binding import OBSERVATION_SECONDS, _interval
        self.assertEqual(OBSERVATION_SECONDS, 8)
        _interval(self.claims(7), NOW, OBSERVATION_SECONDS)
        with self.assertRaisesRegex(ContractError, 'application_observation_expired'):
            _interval(self.claims(9), NOW, OBSERVATION_SECONDS)
        _interval(self.claims(5), NOW)
        with self.assertRaisesRegex(ContractError, 'application_observation_expired'):
            _interval(self.claims(6), NOW)
