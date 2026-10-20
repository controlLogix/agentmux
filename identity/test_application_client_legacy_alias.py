"""Enrolled client signing and verification for legacy alias resolution."""
import copy
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.application_client import ApplicationClientKey, provision_application_client
from identity.ingress import verify_possession
from identity.legacy_identity import LegacyIdentityAdapter
from identity.test_authority import NOW, SEED, ref
from identity import test_service as support
from identity.transitions import transition


class LegacyAliasClientCommandTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.ServiceTests.setUp

    def enrolled_resolver(self):
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        state = self.record['state']
        state['memberships'][0]['scope'] = copy.deepcopy(scope)
        state['grants'][0].update(scope=copy.deepcopy(scope),
            contractId='identity-legacy-alias-resolve', resourceId='authority-one')
        sessions = ('repo_2-worker_3-agent_4', 'repo_2-worker_3-agent_5')
        state['legacyAliases'] = [{
            'ref': ref('legacy-' + str(index)), 'status': 'active', 'identityRef': ref('human'),
            'sourceHubId': 'hub-one', 'scope': copy.deepcopy(scope), 'instanceOwner': None,
            'registrationGeneration': index + 2, 'canonicalSession': session,
            'alias': 'old-agent-' + str(index + 4)}
            for index, session in enumerate(sessions)]
        self.service.configure_legacy_identity(LegacyIdentityAdapter(self.service.reader,
            local_source_hub_id='hub-one', scope=scope))
        issuer = state['issuers'][0]
        selection = {'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'instanceId': 'application-one',
            'callerRef': ref('human'), 'scope': copy.deepcopy(scope),
            'transportRef': ref('client-transport'), 'grantRef': ref('application-grant'),
            'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': issuer['publicKey'],
            'releaseDigest': 'sha256:' + 'a' * 64, 'policyRef': ref('application-policy'),
            'workspaceRef': None,
            'legacyAliasResolve': {'subject': self.service.subject, 'grantRef': ref('grant'),
                'transportRef': ref('legacy-command-transport'),
                'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': issuer['publicKey']}}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name).resolve() / 'client.key'
        payload = provision_application_client(path, selection=selection,
            identity=state['identities'][0], issued_at='2026-10-09T11:59:00Z',
            expires_at='2026-10-09T12:10:00Z')
        self.record['state'] = transition(state, 'identity-enroll', payload, hub_id='hub-one')
        self.js.messages[0].data = canonical_bytes(self.record)
        registrations = [{
            'requestedAddress': 'old-agent-' + str(index + 4),
            'canonicalSession': session, 'registrationGeneration': index + 2,
            'repository': 'repo_2', 'role': 'worker_3', 'agent': 'agent_' + str(index + 4),
            'state': 'ready', 'legacyAlias': 'old-agent-' + str(index + 4)}
            for index, session in enumerate(sessions)]
        return ApplicationClientKey(strict_loads(path.read_bytes())), registrations

    def resolver_claims(self, registrations):
        return {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('legacy-command-transport'), 'grantRef': ref('grant'),
            'operationId': 'resolve-client-one', 'expectedVersion': 0,
            'contractId': 'identity-legacy-alias-resolve',
            'payload': {'authorityId': 'authority-one', 'registrations': registrations},
            'approvalRefs': [], 'issuedAt': '2026-10-09T12:00:00Z',
            'expiresAt': '2026-10-09T12:00:30Z',
            'replySubject': '_INBOX.abcdefghijklmnop'}

    async def response(self):
        key, registrations = self.enrolled_resolver()
        subject = key.command_subject('identity-legacy-alias-resolve')
        request = key.sign_command(self.resolver_claims(registrations), subject=subject, now=NOW)
        response = await self.service.handle(request)
        return key, registrations, subject, request, response

    async def remote_response(self):
        key, registrations = self.enrolled_resolver()
        self.record['state']['legacyAliases'][0]['sourceHubId'] = 'remote-hub'
        self.js.messages[0].data = canonical_bytes(self.record)
        subject = key.command_subject('identity-legacy-alias-resolve')
        claims = self.resolver_claims(registrations)
        claims['operationId'] = 'resolve-remote-one'
        claims['payload'] = {'authorityId': 'authority-one',
                             'remoteAddress': 'agent:repo_2-worker_3-agent_4'}
        request = key.sign_command(claims, subject=subject, now=NOW)
        response = await self.service.handle(request)
        return key, subject, request, response

    async def test_selected_resolver_verifies_exact_signed_bindings(self):
        key, registrations, subject, request, response = await self.response()
        resolution = key.verify_command_response(response, request, subject=subject, now=NOW)
        bindings = resolution.bindings
        self.assertEqual([binding.alias for binding in bindings], ['old-agent-4', 'old-agent-5'])
        self.assertEqual([binding.registration_generation for binding in bindings], [2, 3])
        self.assertTrue(all(binding.local for binding in bindings))
        self.assertEqual(resolution.valid_until.isoformat(), '2026-10-09T12:00:30+00:00')
        verify_possession(strict_loads(request)['claims'], strict_loads(request)['signature'],
                          key.public_key)
        self.assertEqual(strict_loads(response)['claims']['registrations'], registrations)
        self.assertEqual(len(self.js.messages), 1)

    async def test_selected_remote_resolver_returns_one_nonlocal_binding(self):
        key, subject, request, response = await self.remote_response()
        resolution = key.verify_command_response(response, request, subject=subject, now=NOW)
        bindings = resolution.bindings
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0].canonical_session, 'repo_2-worker_3-agent_4')
        self.assertEqual(bindings[0].source_hub_id, 'remote-hub')
        self.assertEqual(bindings[0].registration_generation, 2)
        self.assertFalse(bindings[0].local)
        self.assertEqual(resolution.valid_until.isoformat(), '2026-10-09T12:00:30+00:00')
        claims = strict_loads(response)['claims']
        self.assertEqual(claims['remoteAddress'], 'agent:repo_2-worker_3-agent_4')
        self.assertNotIn('registrations', claims)
        self.assertEqual(len(self.js.messages), 1)

    async def test_remote_request_shape_and_signed_selector_are_exact(self):
        key, subject, request, response = await self.remote_response()
        original = strict_loads(response)

        def resigned(mutate):
            changed = copy.deepcopy(original)
            mutate(changed['claims'])
            changed['signature'] = sign_claims(changed['claims'], SEED)
            return canonical_bytes(changed)

        mutations = (
            lambda claims: claims.update(remoteAddress='agent:repo_2-worker_3-agent_5'),
            lambda claims: claims['bindings'][0].update(
                canonicalSession='repo_2-worker_3-agent_5'),
            lambda claims: claims['bindings'][0].update(scope={
                'organizationId': 'org-one', 'projectId': 'other-project', 'workspaceId': None}),
            lambda claims: claims['bindings'][0].update(authoritySequence=2),
            lambda claims: claims['bindings'][0].update(instanceOwner={
                'pluginId': 'plugin-one', 'installationId': 'install-one',
                'publisherId': 'publisher-one'}),
        )
        for mutate in mutations:
            with self.assertRaises(ContractError):
                key.verify_command_response(resigned(mutate), request, subject=subject, now=NOW)
        claims = strict_loads(request)['claims']
        for payload in ({'authorityId': 'authority-one'}, {
                'authorityId': 'authority-one', 'remoteAddress': 'agent:repo_2-worker_3-agent_4',
                'registrations': []}):
            changed = copy.deepcopy(claims)
            changed['payload'] = payload
            with self.assertRaises(ContractError):
                key.sign_command(changed, subject=subject, now=NOW)

    async def test_signing_refuses_unselected_or_substituted_route(self):
        key, registrations = self.enrolled_resolver()
        subject = key.command_subject('identity-legacy-alias-resolve')
        claims = self.resolver_claims(registrations)
        mutations = (
            lambda value: value.update(contractId='identity-revoke'),
            lambda value: value.update(grantRef=ref('application-grant')),
            lambda value: value.update(transportRef=ref('client-transport')),
            lambda value: value.update(expectedVersion=1),
            lambda value: value.update(approvalRefs=[ref('approval')]),
            lambda value: value['payload'].update(authorityId='other-authority'),
            lambda value: value.pop('replySubject'),
        )
        for mutate in mutations:
            changed = copy.deepcopy(claims)
            mutate(changed)
            with self.subTest(changed=changed):
                with self.assertRaises(ContractError):
                    key.sign_command(changed, subject=subject, now=NOW)
        with self.assertRaises(ContractError):
            key.sign_command(claims, subject=subject + '.other', now=NOW)
        with self.assertRaises(ContractError):
            key.sign_command(claims, subject=subject, now=NOW + timedelta(seconds=31))
        material = strict_loads(key._material)
        material.pop('legacyAliasResolve')
        with self.assertRaises(ContractError):
            ApplicationClientKey(material).sign_command(claims, subject=subject, now=NOW)
        for field in ('subject', 'grantRef', 'transportRef', 'replyIssuerRef',
                      'replyIssuerPublicKey'):
            changed = strict_loads(key._material)
            if field == 'subject':
                changed['legacyAliasResolve'][field] += '.other'
            elif field == 'replyIssuerPublicKey':
                changed['legacyAliasResolve'][field] = 'A' * 43
            elif field == 'replyIssuerRef':
                changed['legacyAliasResolve'][field] = ref('other-issuer')
            else:
                changed['legacyAliasResolve'][field] = changed[field]
            with self.subTest(field=field):
                with self.assertRaises(ContractError):
                    ApplicationClientKey(changed)

    async def test_reply_substitutions_order_count_and_time_refuse(self):
        key, registrations, subject, request, response = await self.response()
        original = strict_loads(response)

        def resign(mutate):
            changed = copy.deepcopy(original)
            mutate(changed['claims'])
            changed['signature'] = sign_claims(changed['claims'], SEED)
            return canonical_bytes(changed)

        mutations = (
            ('digest', lambda claims: claims.update(requestDigest='sha256:' + 'f' * 64)),
            ('operation', lambda claims: claims.update(operationId='other-operation')),
            ('caller', lambda claims: claims.update(callerRef=ref('service'))),
            ('scope', lambda claims: claims['scope'].update(projectId='other-project')),
            ('registrations', lambda claims: claims['registrations'].reverse()),
            ('order', lambda claims: claims['bindings'].reverse()),
            ('count', lambda claims: claims['bindings'].pop()),
            ('source', lambda claims: claims['bindings'][0].update(sourceHubId='other-hub')),
            ('generation', lambda claims: claims['bindings'][0].update(registrationGeneration=9)),
            ('session', lambda claims: claims['bindings'][0].update(canonicalSession='repo_2-worker_3-agent_9')),
            ('alias', lambda claims: claims['bindings'][0].update(alias='other-alias')),
            ('identity owner', lambda claims: claims['bindings'][0].update(identityRef={
                **claims['bindings'][0]['identityRef'], 'ownerHubId': 'other-hub'})),
            ('alias owner', lambda claims: claims['bindings'][0].update(aliasRef={
                **claims['bindings'][0]['aliasRef'], 'ownerHubId': 'other-hub'})),
            ('instance owner', lambda claims: claims['bindings'][0].update(instanceOwner={
                'pluginId': 'plugin-one', 'installationId': 'install-one',
                'publisherId': 'publisher-one'})),
            ('sequence', lambda claims: claims['bindings'][0].update(authoritySequence=2)),
            ('validity', lambda claims: claims.update(validUntil='2026-10-09T12:00:31Z')),
            ('issuance', lambda claims: claims.update(issuedAt='2026-10-09T12:00:03Z')),
        )
        for case, mutate in mutations:
            with self.subTest(case=case):
                with self.assertRaises(ContractError):
                    key.verify_command_response(resign(mutate), request,
                                                subject=subject, now=NOW)
        with self.assertRaises(ContractError):
            key.verify_command_response(response, request, subject=subject,
                                        now=NOW + timedelta(seconds=31))


if __name__ == '__main__':
    unittest.main()
