"""Explicit client enrollment and signed discovery/binding through actual authority."""
import copy
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.application_client import provision_application_client, load_application_client
from identity.application_enrollment import load_application_attestor
from identity import test_application_binding as support
from identity.test_authority import ref, NOW, SEED
from identity.transitions import transition


class ApplicationClientTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.ApplicationBindingTests.setUp
    make_provider = support.ApplicationBindingTests.make_provider

    async def test_knowledge_transport_enrollment_uses_current_ingress_issuer_and_distinct_transport(self):
        from identity.test_knowledge_client import material
        selection = material()
        del selection['purpose']; del selection['seed']
        selection['knowledgeCommands']['replyIssuerRef'] = ref('knowledge-reply-issuer')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'knowledge.key'
            payload = provision_application_client(path, selection=selection,
                identity=self.record['state']['identities'][0],
                issued_at='2026-10-09T12:00:00Z', expires_at='2026-10-09T12:10:00Z')
            key = load_application_client(path)
            self.assertEqual(len(payload['transports']), 2)
            base, knowledge = [row['record'] for row in payload['transports']]
            self.assertNotEqual(base['ref'], knowledge['ref'])
            self.assertEqual(knowledge['issuerRef'], selection['replyIssuerRef'])
            self.assertEqual(knowledge['publicKey'], key.public_key)
            enrolled = transition(self.record['state'], 'identity-enroll', payload, hub_id='hub-one')
            self.assertIn(knowledge, enrolled['transports'])
            self.assertEqual(enrolled['grants'], self.record['state']['grants'])

    async def test_provision_discover_bind_and_pin_current_caller_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'client.key'
            selection = {key: self.binding[key] for key in ('hubId', 'profileId', 'authorityId',
                'instanceId', 'releaseDigest', 'policyRef', 'workspaceRef', 'grantRef')}
            selection.update(callerRef=ref('human'), transportRef=ref('client-transport'),
                scope=self.record['state']['grants'][1]['scope'], replyIssuerRef=ref('issuer'),
                replyIssuerPublicKey=self.record['state']['issuers'][0]['publicKey'])
            payload = provision_application_client(path, selection=selection,
                identity=self.record['state']['identities'][0],
                issued_at='2026-10-09T12:00:00Z', expires_at='2026-10-09T12:10:00Z')
            key = load_application_client(path)
            self.assertNotIn('seed', key.selection)
            with self.assertRaisesRegex(ContractError, 'application_key_store_invalid'):
                load_application_attestor(path)
            self.record['state'] = transition(self.record['state'], 'identity-enroll', payload, hub_id='hub-one')
            self.js.messages[0].data = canonical_bytes(self.record)
            self.service.replace_application_lease(self.lease)
            claims = copy.deepcopy(self.binding)
            claims.update(purpose='agentmux-application-discovery-request-v1', transportRef=ref('client-transport'))
            del claims['generation']; del claims['lifetimeId']
            request = key.sign_discovery(claims, now=NOW)
            raw = await self.service.handle(request)
            discovered = key.verify_response(raw, request, now=NOW)
            self.assertEqual((discovered['generation'], discovered['lifetimeId']), (1, 'd' * 64))
            claims.update(purpose='agentmux-application-binding-request-v1',
                generation=discovered['generation'], lifetimeId=discovered['lifetimeId'], nonce='e' * 64)
            request = key.sign_binding(claims, now=NOW)
            raw = await self.service.handle(request)
            self.assertEqual(key.verify_response(raw, request, now=NOW)['callerRef'], ref('human'))
            wrong = strict_loads(raw)
            wrong['claims']['scope']['projectId'] = 'other-project'
            wrong['signature'] = sign_claims(wrong['claims'], SEED)
            with self.assertRaisesRegex(ContractError, 'application_client_binding'):
                key.verify_response(canonical_bytes(wrong), request, now=NOW)
            with self.assertRaises(ContractError):
                key.verify_response(raw, request, now=NOW + timedelta(seconds=5))
            self.done.set()
            with self.assertRaisesRegex(ContractError, 'application_lifetime_ended'):
                await self.service.handle(request)

    async def test_terminal_capability_pins_three_distinct_contract_grants(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'terminal.key'
            scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                     'workspaceId': None}
            subject = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
            grants = {name: ref(name + '-grant') for name in (
                'oidc-terminal-session-open', 'oidc-terminal-session-status',
                'oidc-terminal-session-close')}
            selection = {key: self.binding[key] for key in ('hubId', 'profileId',
                'authorityId', 'instanceId', 'releaseDigest', 'policyRef',
                'workspaceRef', 'grantRef')}
            selection.update(callerRef=ref('human'), transportRef=ref('client-transport'),
                scope=scope, replyIssuerRef=ref('issuer'),
                replyIssuerPublicKey=self.record['state']['issuers'][0]['publicKey'],
                oidcTerminalSession={'subject': subject, 'grantRefs': grants,
                    'transportRef': ref('terminal-transport'),
                    'replyIssuerRef': ref('issuer'),
                    'replyIssuerPublicKey': self.record['state']['issuers'][0]['publicKey']})
            payload = provision_application_client(path, selection=selection,
                identity=self.record['state']['identities'][0],
                issued_at='2026-10-09T12:00:00Z',
                expires_at='2026-10-09T12:10:00Z')
            self.assertEqual(len(payload['transports']), 2)
            key = load_application_client(path)
            for contract, body in (
                    ('oidc-terminal-session-open', {}),
                    ('oidc-terminal-session-status', {'attemptId': 'oidc_attempt_' + 'a' * 32}),
                    ('oidc-terminal-session-close', {'sessionId': 'oidc_session_' + 'b' * 32})):
                claims = {'purpose': 'agentmux-client-possession-v1',
                    'hubId': 'hub-one', 'profileId': 'profile-one',
                    'authorityId': 'authority-one',
                    'transportRef': ref('terminal-transport'),
                    'grantRef': grants[contract], 'operationId': 'operation-' + contract,
                    'expectedVersion': 0, 'contractId': contract, 'payload': body,
                    'approvalRefs': [], 'replySubject': '_INBOX.terminal_client_01.reply',
                    'issuedAt': '2026-10-09T12:00:00Z',
                    'expiresAt': '2026-10-09T12:00:30Z'}
                raw = key.sign_command(claims, subject=subject, now=NOW)
                parsed, selected = key.verify_command_request(raw, subject=subject)
                self.assertEqual(parsed['claims']['contractId'], contract)
                self.assertEqual(selected['grantRefs'][contract], grants[contract])
