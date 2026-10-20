"""Pinned Keycloak device identity through the protected link owner path.

Importing this module starts no provider or broker. Root runs the one test only
after granting the shared Keycloak and task-live slots.
"""
import asyncio
import copy
import json
import os
from pathlib import Path

from agentmux_contracts import payload_digest, strict_loads
from identity.oidc_adapter import OIDCProvider, external_account_link_payload
from identity.oidc_device_authorization import (
    OIDCDeviceAuthorizationFlow, OIDCDeviceAuthorizationProvider,
    OIDCDeviceAuthorizationRequest)
from identity.test_authority import ref
from identity.test_external_account_link_live import LiveExternalAccountLinkTests


class LiveKeycloakExternalAccountLinkTests(LiveExternalAccountLinkTests):
    """One approved Keycloak identity, then one explicit administrator link."""

    test_tls_current_administrator_links_and_revocation_refuses = None

    def provider(self):
        provider = OIDCProvider(os.environ['AMX_OIDC_LIVE_ISSUER'], 'agentmux',
            os.environ['AMX_OIDC_LIVE_KEY_ID'], os.environ['AMX_OIDC_LIVE_PUBLIC_KEY'],
            roots_pem=Path(os.environ['AMX_OIDC_LIVE_ROOTS']).read_text())
        return OIDCDeviceAuthorizationProvider(provider,
            os.environ['AMX_OIDC_LIVE_DEVICE_ENDPOINT'],
            os.environ['AMX_OIDC_LIVE_TOKEN_ENDPOINT'])

    async def authenticate(self):
        flow = OIDCDeviceAuthorizationFlow(self.provider())
        started = asyncio.create_task(asyncio.to_thread(flow.begin),
                                      name='oidc-account-link-device-begin')
        try:
            request = await asyncio.shield(started)
        except BaseException:
            outcome = (await asyncio.gather(
                asyncio.shield(started), return_exceptions=True))[0]
            if type(outcome) is OIDCDeviceAuthorizationRequest:
                outcome.cancel()
            raise
        print('AMX_OIDC_DEVICE:' + json.dumps({'label': 'account-link',
            'verificationUri': request.verification_uri,
            'userCode': request.user_code}), flush=True)
        completion = asyncio.create_task(asyncio.to_thread(flow.complete, request),
                                         name='oidc-account-link-device-poll')
        try:
            return await asyncio.shield(completion)
        finally:
            if not completion.done():
                request.cancel()
            await asyncio.gather(asyncio.shield(completion), return_exceptions=True)

    async def test_keycloak_verified_pair_links_through_current_administrator(self):
        verified = await self.authenticate()
        payload = external_account_link_payload(authority_id='authority-one',
            identity_ref=ref('linked-target'), verified_identity=verified)
        self.assertEqual(payload['externalIdentity'], {
            'issuer': os.environ['AMX_OIDC_LIVE_ISSUER'],
            'subject': os.environ.get('AMX_OIDC_LIVE_SUBJECT', 'keycloak-user-184')})
        self.assertEqual(set(payload['externalIdentity']), {'issuer', 'subject'})

        current = await self.current_record()
        allowed = next(row for row in current['state']['grants']
                       if row['ref']['id'] == 'external-link-grant')
        denied = copy.deepcopy(allowed)
        denied.update(ref=ref('keycloak-external-link-denial'), decision='denied')
        await self.command('identity-grant-set', ref('external-link-grant-set'), {
            'authorityId': 'authority-one', 'record': denied, 'previousRef': None})
        denied_request = await self.link_request(
            'linked-target', operation='keycloak-external-link-denied', payload=payload)
        denied_receipt = self.receipt(
            await self.owner_exchange(denied_request), denied_request)
        self.assertEqual((denied_receipt['decision'], denied_receipt['reason']),
                         ('denied', 'hard_denial'))
        self.assertIsNone(await self.external_identity('linked-target'))
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': denied['ref']})

        linked_request = await self.link_request(
            'linked-target', operation='keycloak-external-link-stable', payload=payload)
        linked_receipt = self.receipt(
            await self.owner_exchange(linked_request), linked_request)
        self.assertEqual((linked_receipt['decision'], linked_receipt['replayed']),
                         ('allowed', False))
        retained = await self.current_record()
        target = next(row for row in retained['state']['identities']
                      if row['ref']['id'] == 'linked-target')
        self.assertEqual(target['externalIdentity'], payload['externalIdentity'])
        self.assertEqual(retained['authorizationDecision']['actorRef'], ref('human'))
        request_payload = strict_loads(linked_request)['claims']['payload']
        self.assertEqual(set(request_payload),
                         {'authorityId', 'identityRef', 'externalIdentity'})
        self.assertEqual(set(request_payload['externalIdentity']),
                         {'issuer', 'subject'})
        self.assertEqual(retained['operation']['payloadDigest'],
                         payload_digest(request_payload))

        replay = self.receipt(await self.owner_exchange(linked_request), linked_request)
        self.assertEqual((replay['decision'], replay['replayed'], replay['sequence']),
                         ('allowed', True, linked_receipt['sequence']))
        final = await self.identity.ledger.current()
        self.assertEqual(final.sequence, linked_receipt['sequence'])
        self.assertEqual(strict_loads(final.latest.record)['state'], retained['state'])
        self.assertFalse(self.errors['identity'])
        self.success = True

