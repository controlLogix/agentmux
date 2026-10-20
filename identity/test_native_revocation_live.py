"""Real TLS/JWT broker check for enrolled native-instance revocation."""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import secrets

from nacl.signing import SigningKey
from agentmux_contracts import strict_loads

from capability_owner.test_live import packet, stamp
from identity.native_bridge import verify_response
from identity.test_authority import ref
from identity.test_native_bridge import HOST_SEED, native_row
from state_owner.test_task_live import LiveTaskTests


class LiveNativeRevocationTests(LiveTaskTests):
    """A signed revocation removes native authority on the real broker path."""

    test_tls_task_inspect_reserve_restart_replay_and_refusals = None
    seed_ready_task = False
    create_task_host = False

    async def asyncSetUp(self):
        self.row = native_row()
        await super().asyncSetUp()

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        now = datetime.now(timezone.utc)
        interval = {'issuedAt': stamp(now-timedelta(seconds=30)),
                    'expiresAt': stamp(now+timedelta(minutes=5))}
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

    async def native(self, method, inputs, *, timeout=2):
        raw, response = await self.native_raw(method, inputs, timeout=timeout)
        return verify_response(response, raw, public_key=self.issuer_public,
            signing_key_ref=ref('issuer'), now=datetime.now(timezone.utc))['result']

    async def native_raw(self, method, inputs, *, timeout=2):
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
            claims['replySubject'], timeout=timeout)
        return raw, response

    async def test_tls_signed_native_revocation_refuses_later_binding(self):
        declaration = {key: self.row[key] for key in
                       ('manifestDigest', 'relationship', 'parentOwner',
                        'configurationChecksum')}
        await self.command('identity-native-instance-set', ref('native-admin'), {
            'authorityId': 'authority-one', 'record': self.row, 'previousRef': None})
        bound = await self.native('bind-instance', declaration)
        self.assertEqual(bound, self.row['facts'])

        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': self.row['ref']})
        _raw, refusal = await self.native_raw('bind-instance', declaration, timeout=.4)
        self.assertEqual(strict_loads(refusal),
                         {'schemaVersion': '1.0.0',
                          'error': 'identity_outcome_unconfirmed'})
        snapshot = await self.identity.reader.current()
        retained = next(row for row in strict_loads(snapshot.record)['state']['nativeInstances']
                        if row['ref']['id'] == self.row['ref']['id'])
        self.assertEqual(retained['status'], 'revoked')
        self.assertEqual(retained['ref']['revision'], self.row['ref']['revision'] + 1)
        self.success = True


if __name__ == '__main__':
    import unittest
    unittest.main()
