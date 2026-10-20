"""Signed enrolled recovery route between one client and the retained owner."""
import copy
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import base64
from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.application_client import ApplicationClientKey, provision_application_client
from identity.test_authority import NOW, SEED, ref
from identity.test_service import _Clock
from identity.transitions import transition
from state_owner.authority_switch_service import AuthoritySwitchService
from state_owner.test_authority_switch import AuthoritySwitchTests as _AuthoritySwitchTests


class AuthoritySwitchServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _AuthoritySwitchTests.setUp(self)
        patch('state_owner.authority_switch_service.datetime', _Clock).start()

    def envelope(self, *args, **kwargs):
        return _AuthoritySwitchTests.envelope(self, *args, **kwargs)

    def client(self):
        issuer = self.record['state']['issuers'][0]
        self.switch_seed = b'R' * 32
        switch_public = base64.urlsafe_b64encode(bytes(
            SigningKey(self.switch_seed).verify_key)).decode().rstrip('=')
        interval = {'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
                    'expiresAt': '2026-10-09T12:10:00Z'}
        self.record['state']['identities'].append({'ref': ref('switch-service'),
            'principalId': 'switch-service', 'kind': 'service', 'status': 'active',
            'externalIdentity': None})
        self.record['state']['issuers'].append({'ref': ref('switch-issuer'),
            'identityRef': ref('switch-service'), 'instanceId': 'switch-instance',
            'publicKey': switch_public, **interval})
        selection = {'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'instanceId': 'application-one',
            'callerRef': ref('human'), 'scope': copy.deepcopy(self.scope),
            'transportRef': ref('client-transport'),
            'grantRef': ref('application-grant'),
            'replyIssuerRef': ref('issuer'),
            'replyIssuerPublicKey': issuer['publicKey'],
            'releaseDigest': 'sha256:' + 'a' * 64,
            'policyRef': ref('application-policy'), 'workspaceRef': None,
            'authoritySwitchRecovery': {
                'subject': '.'.join(('amx', 'v1', 'h', 'hub-one', 'o', 'org-one',
                    'authority-switch', self.switch_id, 'command')),
                'grantRef': ref('grant'),
                'replyIssuerRef': ref('switch-issuer'),
                'replyIssuerPublicKey': switch_public,
                'transportRef': ref('switch-transport'),
                'switchId': self.switch_id, 'source': copy.deepcopy(self.source),
                'streamIdentity': {'created': self.ledger._identity.created.isoformat().replace('+00:00', 'Z'),
                                   'minimumSequence': 1},
                'serviceIdentityRef': ref('switch-service'),
                'serviceInstanceId': 'switch-instance'}}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name).resolve() / 'client.key'
        payload = provision_application_client(path, selection=selection,
            identity=self.record['state']['identities'][0],
            issued_at='2026-10-09T11:59:00Z', expires_at='2026-10-09T12:10:00Z')
        self.record['state'] = transition(self.record['state'], 'identity-enroll',
                                           payload, hub_id='hub-one')
        self.js.messages[0].data = canonical_bytes(self.record)
        key = ApplicationClientKey(strict_loads(path.read_bytes()))
        service = AuthoritySwitchService(self.owner, self.service.ingress,
            connection=None, profile_id='profile-one', authority_id='authority-one',
            service_identity_ref=ref('switch-service'), service_instance_id='switch-instance',
            signing_key_ref=ref('switch-issuer'), signing_seed=self.switch_seed)
        return key, service

    def request(self, key):
        selected = key.selection['authoritySwitchRecovery']
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': selected['transportRef'], 'grantRef': selected['grantRef'],
            'operationId': 'recover_source_one', 'expectedVersion': 1,
            'contractId': 'authority-switch', 'approvalRefs': [],
            'payload': {'action': 'request-recovery', 'switchId': self.switch_id,
                        'source': copy.deepcopy(self.source)},
            'replySubject': '_INBOX.abcdefghijklmnop.reply',
            'issuedAt': '2026-10-09T12:00:00Z',
            'expiresAt': '2026-10-09T12:00:30Z'}
        subject = key.command_subject('authority-switch')
        return subject, key.sign_command(claims, subject=subject, now=NOW)

    async def response(self):
        await _AuthoritySwitchTests.source_fenced(self)
        key, service = self.client()
        subject, request = self.request(key)
        response = await service.handle(request,
            received_reply_subject='_INBOX.abcdefghijklmnop.reply')
        return key, service, subject, request, response

    async def test_current_enrolled_request_returns_one_exact_verified_authorization(self):
        key, service, subject, request, response = await self.response()
        result = key.verify_command_response(response, request, subject=subject, now=NOW)
        self.assertIs(result._seal, key._authority_switch_seal)
        self.assertEqual(strict_loads(result._response)['claims']['switchRef']['revision'], 2)
        replay = await service.handle(request,
            received_reply_subject='_INBOX.abcdefghijklmnop.reply')
        renewed = key.verify_command_response(replay, request, subject=subject, now=NOW)
        self.assertIs(renewed._seal, key._authority_switch_seal)
        claims = strict_loads(request)['claims']
        claims['replySubject'] = '_INBOX.abcdefghijklmnop.retry'
        retry_request = key.sign_command(claims, subject=subject, now=NOW)
        retry_response = await service.handle(retry_request,
            received_reply_subject='_INBOX.abcdefghijklmnop.retry')
        retried = key.verify_command_response(
            retry_response, retry_request, subject=subject, now=NOW)
        self.assertIs(retried._seal, key._authority_switch_seal)
        self.assertEqual(len(self.switch_js.messages), 2)

    async def test_revoked_grant_and_expired_reply_are_refused(self):
        await _AuthoritySwitchTests.source_fenced(self)
        key, service = self.client()
        subject, request = self.request(key)
        self.record['state']['grants'][0]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaises(ContractError):
            await service.handle(request,
                received_reply_subject='_INBOX.abcdefghijklmnop.reply')

        self.record['state']['grants'][0]['status'] = 'active'
        self.js.messages[0].data = canonical_bytes(self.record)
        response = await service.handle(request,
            received_reply_subject='_INBOX.abcdefghijklmnop.reply')
        with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_unconfirmed$'):
            key.verify_command_response(response, request, subject=subject,
                now=NOW + timedelta(seconds=31))

    async def test_signed_mismatched_source_reply_is_refused(self):
        key, _, subject, request, response = await self.response()
        changed = strict_loads(response)
        changed['claims']['source']['applicationVersion'] = 'other-version'
        changed['signature'] = sign_claims(changed['claims'], self.switch_seed)
        with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_unconfirmed$'):
            key.verify_command_response(canonical_bytes(changed), request,
                                        subject=subject, now=NOW)

        for mutate in (
                lambda claims: claims.update(profileId='other-profile'),
                lambda claims: claims['operation'].update(effectiveActorRef=ref('other-human')),
                lambda claims: claims['operation']['caller'].update(
                    authenticatedIdentityRef=ref('other-human'))):
            changed = strict_loads(response)
            mutate(changed['claims'])
            changed['signature'] = sign_claims(changed['claims'], self.switch_seed)
            with self.assertRaisesRegex(ContractError,
                    '^authority_switch_recovery_unconfirmed$'):
                key.verify_command_response(canonical_bytes(changed), request,
                                            subject=subject, now=NOW)

