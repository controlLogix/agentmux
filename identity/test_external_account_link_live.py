"""Real TLS/JWT identity-owner qualification for explicit account linking.

Importing this module starts no broker. Root runs the one test only after the
shared live slot is released.
"""
import base64
import copy
from datetime import datetime, timedelta, timezone
import secrets

from nacl.signing import SigningKey
from agentmux_contracts import strict_loads
from capability_owner.test_live import packet, stamp
from identity.service import verify_receipt
from identity.test_authority import SEED, ref
from state_owner import test_task_live as tls_fixture


ADMIN_TWO_SEED = bytes([37]) * 32
APPLICATION_SEED = bytes([53]) * 32


class LiveExternalAccountLinkTests(tls_fixture.LiveTaskTests):
    """One actual broker and owner lifecycle for the D04 linking boundary."""

    seed_ready_task = False
    create_task_host = False
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None

    @property
    def project_scope(self):
        return {'organizationId': 'org-one', 'projectId': 'project-one',
                'workspaceId': None}

    @staticmethod
    def public_key(seed):
        return base64.urlsafe_b64encode(
            bytes(SigningKey(seed).verify_key)).decode().rstrip('=')

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        base_identity = copy.deepcopy(state['identities'][0])
        base_transport = copy.deepcopy(state['transports'][0])
        base_membership = copy.deepcopy(state['memberships'][0])
        base_grant = copy.deepcopy(state['grants'][0])

        for name in ('linked-target', 'application-target', 'hard-denial-target',
                     'revoked-grant-target', 'revoked-member-target'):
            identity = copy.deepcopy(base_identity)
            identity.update(ref=ref(name), principalId=name, externalIdentity=None)
            state['identities'].append(identity)

        administrator = copy.deepcopy(base_identity)
        administrator.update(ref=ref('link-admin-two'), principalId='link-admin-two',
                             externalIdentity=None)
        application = copy.deepcopy(base_identity)
        application.update(ref=ref('link-application'), principalId='link-application',
                           kind='service', externalIdentity=None)
        state['identities'].extend((administrator, application))

        for name, identity_ref, seed in (
                ('link-admin-two-transport', administrator['ref'], ADMIN_TWO_SEED),
                ('link-application-transport', application['ref'], APPLICATION_SEED)):
            transport = copy.deepcopy(base_transport)
            transport.update(ref=ref(name), identityRef=identity_ref,
                             publicKey=self.public_key(seed))
            state['transports'].append(transport)

        for name, identity_ref, scope in (
                ('link-admin-two-member', administrator['ref'], self.scope),
                ('link-application-member', application['ref'], self.project_scope)):
            membership = copy.deepcopy(base_membership)
            membership.update(ref=ref(name), identityRef=identity_ref,
                              scope=copy.deepcopy(scope))
            state['memberships'].append(membership)

        grants = (
            ('external-link-grant', ref('human'), self.scope),
            ('external-link-admin-two-grant', administrator['ref'], self.scope),
            ('external-link-application-grant', application['ref'], self.project_scope),
            ('external-link-grant-set', ref('human'), self.scope),
        )
        for name, identity_ref, scope in grants:
            grant = copy.deepcopy(base_grant)
            grant.update(ref=ref(name), callerRef=identity_ref, actorRef=identity_ref,
                         scope=copy.deepcopy(scope), resourceId='authority-one',
                         contractId=('identity-grant-set' if name == 'external-link-grant-set'
                                     else 'identity-external-account-link'))
            state['grants'].append(grant)
        return initial

    async def current_record(self):
        return strict_loads((await self.identity.ledger.current()).latest.record)

    async def link_request(self, target, *, caller='human', operation=None,
                           payload=None):
        record = await self.current_record()
        choices = {
            'human': (ref('transport'), ref('external-link-grant'),
                      self.scope, bytes(reversed(SEED))),
            'admin-two': (ref('link-admin-two-transport'),
                          ref('external-link-admin-two-grant'),
                          self.scope, ADMIN_TWO_SEED),
            'application': (ref('link-application-transport'),
                            ref('external-link-application-grant'),
                            self.project_scope, APPLICATION_SEED),
        }
        transport, grant, scope, seed = choices[caller]
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': transport, 'grantRef': grant,
            'operationId': operation or 'external-link-' + secrets.token_hex(16),
            'expectedVersion': record['entityVersion'],
            'contractId': 'identity-external-account-link',
            'payload': payload or {'authorityId': 'authority-one',
                'identityRef': ref(target),
                'externalIdentity': {'issuer': 'https://identity.example/realms/team',
                                     'subject': target + '-subject'}},
            'approvalRefs': [], 'issuedAt': stamp(now),
            'expiresAt': stamp(now + timedelta(seconds=20)),
            'replySubject': self.host.new_inbox()}
        return packet(claims, seed)

    async def owner_exchange(self, raw):
        claims = strict_loads(raw)['claims']
        return await self.exchange(self.host, self.identity_subject, raw,
                                   claims['replySubject'], timeout=2)

    def receipt(self, response, request):
        return verify_receipt(response, request, public_key=self.issuer_public,
                              issuer_ref=ref('issuer'))

    async def external_identity(self, target):
        state = (await self.current_record())['state']
        matches = [row['externalIdentity'] for row in state['identities']
                   if row['ref']['id'] == target]
        self.assertEqual(len(matches), 1)
        return matches[0]

    async def test_tls_current_administrator_links_and_revocation_refuses(self):
        linked = await self.link_request('linked-target', operation='external-link-stable')
        first = self.receipt(await self.owner_exchange(linked), linked)
        self.assertEqual((first['decision'], first['replayed']), ('allowed', False))
        self.assertEqual(await self.external_identity('linked-target'), {
            'issuer': 'https://identity.example/realms/team',
            'subject': 'linked-target-subject'})

        replay = self.receipt(await self.owner_exchange(linked), linked)
        self.assertEqual((replay['decision'], replay['replayed'], replay['sequence']),
                         ('allowed', True, first['sequence']))

        application = await self.link_request('application-target', caller='application')
        before_application = await self.identity.ledger.current()
        self.assertEqual(strict_loads(await self.owner_exchange(application)),
                         {'schemaVersion': '1.0.0',
                          'error': 'identity_outcome_unconfirmed'})
        after_application = await self.identity.ledger.current()
        self.assertEqual((after_application.sequence, after_application.latest.record),
                         (before_application.sequence, before_application.latest.record))
        self.assertIsNone(await self.external_identity('application-target'))

        current = await self.current_record()
        allowed = next(row for row in current['state']['grants']
                       if row['ref']['id'] == 'external-link-grant')
        denied = copy.deepcopy(allowed)
        denied.update(ref=ref('external-link-denial'), decision='denied')
        await self.command('identity-grant-set', ref('external-link-grant-set'), {
            'authorityId': 'authority-one', 'record': denied, 'previousRef': None})
        hard_denied = await self.link_request('hard-denial-target')
        refused = self.receipt(await self.owner_exchange(hard_denied), hard_denied)
        self.assertEqual((refused['decision'], refused['reason']),
                         ('denied', 'hard_denial'))
        self.assertIsNone(await self.external_identity('hard-denial-target'))
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': denied['ref']})

        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('external-link-grant')})
        revoked_grant = await self.link_request('revoked-grant-target')
        self.assertEqual(strict_loads(await self.owner_exchange(revoked_grant)),
                         {'schemaVersion': '1.0.0',
                          'error': 'identity_outcome_unconfirmed'})
        self.assertIsNone(await self.external_identity('revoked-grant-target'))

        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('link-admin-two-member')})
        revoked_member = await self.link_request(
            'revoked-member-target', caller='admin-two')
        refused = self.receipt(await self.owner_exchange(revoked_member), revoked_member)
        self.assertEqual((refused['decision'], refused['reason']),
                         ('denied', 'membership_unavailable'))
        self.assertIsNone(await self.external_identity('revoked-member-target'))

        self.assertFalse(self.errors['identity'])
        self.success = True

