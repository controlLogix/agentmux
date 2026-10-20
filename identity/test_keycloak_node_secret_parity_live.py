"""Keycloak-bound self-hosted node revocation and secret rotation parity."""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import os
import secrets

from nacl.signing import SigningKey
from agentmux_contracts import strict_loads

from capability_owner.test_live import packet, stamp
from identity.native_bridge import verify_response
from identity.service import verify_receipt
from identity.test_authority import SEED, ref
from identity.test_native_bridge import HOST_SEED, native_row
from state_owner.test_task_live import (
    LiveApplicationAccountCustodyTests,
    LiveOIDCTerminalApplicationTests,
)


class LiveKeycloakNodeSecretParityTests(
        LiveOIDCTerminalApplicationTests, LiveApplicationAccountCustodyTests):
    """Use one real provider session for both self-hosted parity outcomes."""

    test_keycloak_terminal_injected_expiry_and_membership_revocation = None
    test_keycloak_terminal_natural_session_expiry = None
    test_real_enrolled_hub_cli_socket_start_routes_and_cleans_up = None
    test_tls_application_account_custody_rotation_and_revocation = None
    test_tls_local_browser_current_identity_revocation_refuses = None
    test_tls_local_browser_current_membership_revocation_refuses = None
    test_tls_local_browser_pairing_returns_real_http_cookie = None

    async def asyncSetUp(self):
        self.row = native_row()
        self.keycloak_session_id = None
        await super().asyncSetUp()

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        now = datetime.now(timezone.utc)
        interval = {'issuedAt': stamp(now-timedelta(seconds=30)),
                    'expiresAt': stamp(now+timedelta(minutes=20))}
        for value in (self.row['facts']['grant'], self.row['facts']['policy']):
            value.update(interval)
        host = {'ref': ref('host'), 'principalId': 'native-host', 'kind': 'service',
                'status': 'active', 'externalIdentity': None}
        plugin = {'ref': ref('plugin'), 'principalId': 'native-plugin', 'kind': 'plugin',
                  'status': 'active', 'externalIdentity': None}
        state['identities'].extend((host, plugin))
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('host-transport'), identityRef=host['ref'],
            publicKey=base64.urlsafe_b64encode(
                bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        membership = copy.deepcopy(state['memberships'][0])
        membership.update(ref=ref('host-member'), identityRef=host['ref'])
        state['memberships'].append(membership)
        base = copy.deepcopy(state['grants'][0])
        for name, contract, resource, caller in (
                ('native-admin', 'identity-native-instance-set', 'authority-one', ref('human')),
                ('host-bind-instance', 'native-authority-bind-instance', 'plugin-one', host['ref'])):
            grant = copy.deepcopy(base)
            grant.update(ref=ref(name), contractId=contract, resourceId=resource,
                         callerRef=caller, actorRef=caller)
            state['grants'].append(grant)
        return initial

    async def identity_request(self, *args, **kwargs):
        raw = await super().identity_request(*args, **kwargs)
        if self.keycloak_session_id is None:
            return raw
        claims = strict_loads(raw)['claims']
        claims['terminalSessionId'] = self.keycloak_session_id
        return packet(claims, bytes(reversed(SEED)))

    async def keycloak_command(self, contract, grant, payload):
        context = await self.identity.authorize_oidc_terminal(
            self.keycloak_session_id, ref('human'), self.project_scope)
        self.assertEqual((context.caller_ref, context.scope),
                         (ref('human'), self.project_scope))
        snapshot = await self.identity.ledger.current()
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': grant,
            'operationId': 'keycloak-parity-' + secrets.token_hex(16),
            'expectedVersion': strict_loads(snapshot.latest.record)['entityVersion'],
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=20)),
            'replySubject': self.host.new_inbox(),
            'terminalSessionId': self.keycloak_session_id}
        raw = packet(claims, bytes(reversed(SEED)))
        response = await self.owner_exchange(raw)
        receipt = verify_receipt(response, raw, public_key=self.issuer_public,
                                 issuer_ref=ref('issuer'))
        self.assertEqual(receipt['decision'], 'allowed')
        retained = strict_loads((await self.identity.ledger.current()).latest.record)
        self.assertEqual(retained['operation']['terminalSessionId'],
                         self.keycloak_session_id)
        self.assertEqual(retained['authorizationDecision']['actorRef'], ref('human'))
        return receipt

    async def command(self, contract, grant, payload):
        if self.keycloak_session_id is None:
            return await super().command(contract, grant, payload)
        return await self.keycloak_command(contract, grant, payload)

    async def native_raw(self, method, inputs):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-native-authority-request-v1',
            'requestId': 'native-'+secrets.token_hex(16), 'method': method,
            'profileId': 'profile-one', 'hubId': 'hub-one',
            'authorityId': 'authority-one', 'owner': self.row['owner'],
            'signingKeyRef': ref('host-transport'), 'issuedAt': stamp(now),
            'expiresAt': stamp(now+timedelta(seconds=4)),
            'replySubject': self.host.new_inbox(), 'input': inputs}
        raw = packet(claims, HOST_SEED, native=True)
        response = await self.exchange(self.host, self.identity_subject, raw,
            claims['replySubject'], timeout=2)
        return raw, response

    async def test_keycloak_bound_node_revocation_and_secret_rotation(self):
        owner = await self.open_application()
        self.keycloak_session_id = await self._approve_terminal(
            owner, 'node-secret-parity')
        context = await self.identity.authorize_oidc_terminal(
            self.keycloak_session_id, ref('human'), self.project_scope)
        self.assertEqual((context.caller_ref, context.scope),
                         (ref('human'), self.project_scope))

        current = strict_loads((await self.identity.ledger.current()).latest.record)
        human = next(row for row in current['state']['identities']
                     if row['ref'] == ref('human'))
        self.assertEqual(human['externalIdentity'], {
            'issuer': os.environ['AMX_OIDC_LIVE_ISSUER'],
            'subject': os.environ.get(
                'AMX_OIDC_LIVE_SUBJECT', 'keycloak-user-184')})

        rotation_check = (LiveApplicationAccountCustodyTests
            .test_tls_application_account_custody_rotation_and_revocation)
        await rotation_check(self)

        declaration = {key: self.row[key] for key in
                       ('manifestDigest', 'relationship', 'parentOwner',
                        'configurationChecksum')}
        await self.keycloak_command('identity-native-instance-set', ref('native-admin'), {
            'authorityId': 'authority-one', 'record': self.row, 'previousRef': None})
        raw, response = await self.native_raw('bind-instance', declaration)
        bound = verify_response(response, raw, public_key=self.issuer_public,
            signing_key_ref=ref('issuer'), now=datetime.now(timezone.utc))['result']
        self.assertEqual(bound, self.row['facts'])
        await self.keycloak_command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': self.row['ref']})
        _raw, refusal = await self.native_raw('bind-instance', declaration)
        self.assertEqual(strict_loads(refusal), {
            'schemaVersion': '1.0.0', 'error': 'identity_outcome_unconfirmed'})
        self.success = True


if __name__ == '__main__':
    import unittest
    unittest.main()
