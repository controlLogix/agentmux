"""Source expectations bind the signed Work request without changing its intent."""
import copy
from datetime import datetime, timezone
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.tests.test_work_client_transport import claims, material
from identity.application_client import ApplicationClientKey
from identity.test_knowledge_client import material as knowledge_material
from identity import test_ingress as ingress_support


SOURCE = {'formatVersion': 1, 'sourceDigest': 'sha256:' + 'b' * 64,
    'schemaDigest': 'sha256:' + 'c' * 64, 'applicationId': 123, 'userVersion': 6, 'schemaVersion': 12,
    'localNode': 'mac', 'repository': 'falcon'}


class WorkSourceClaimTests(unittest.TestCase):
    def test_source_is_signed_without_changing_original_work_payload_or_operation(self):
        key = ApplicationClientKey(material())
        original = claims(key, action='create')
        selected = {**original, 'workSource': copy.deepcopy(SOURCE)}
        subject = key.command_subject(selected['contractId'])
        raw = key.sign_command(selected, subject=subject)
        verified, _ = key.verify_command_request(raw, subject=subject)
        self.assertEqual(verified['claims']['workSource'], SOURCE)
        self.assertEqual(verified['claims']['operationId'], original['operationId'])
        self.assertEqual(payload_digest(verified['claims']['payload']), payload_digest(original['payload']))
        changed = strict_loads(raw)
        changed['claims']['workSource']['sourceDigest'] = 'sha256:' + 'd' * 64
        with self.assertRaises(ContractError):
            key.verify_command_request(canonical_bytes(changed), subject=subject)

    def test_source_expectation_has_a_closed_shape(self):
        key = ApplicationClientKey(material())
        subject = key.command_subject('federation-work-read')
        for field, value in (('sourceDigest', 'not-a-digest'), ('schemaVersion', -1),
                ('localNode', 'wrong-node'), ('repository', {'localName': 'falcon'}),
                ('privatePath', '/private/not-a-wire-field')):
            with self.subTest(field=field):
                selected = {**claims(key), 'workSource': {**SOURCE, field: value}}
                with self.assertRaises(ContractError):
                    key.sign_command(selected, subject=subject)
        for field in ('localNode', 'repository'):
            with self.subTest(missing=field):
                source = copy.deepcopy(SOURCE)
                del source[field]
                with self.assertRaises(ContractError):
                    key.sign_command({**claims(key), 'workSource': source}, subject=subject)

    def test_non_work_command_cannot_use_work_source_metadata(self):
        key = ApplicationClientKey(knowledge_material())
        route = key.selection['knowledgeCommands']
        selected = claims(ApplicationClientKey(material()), now=datetime.now(timezone.utc))
        selected.update(contractId='federation-knowledge-inspect',
            transportRef=route['transportRef'], grantRef=route['grantRefs']['federation-knowledge-inspect'],
            payload={'resourceRef': route['resourceRef'], 'input': {}}, workSource=SOURCE)
        with self.assertRaisesRegex(ContractError, 'application_client_command_binding'):
            key.sign_command(selected, subject=route['subject'])


class WorkSourceIngressTests(unittest.IsolatedAsyncioTestCase):
    setUp = ingress_support.IngressTests.setUp
    admit = ingress_support.IngressTests.admit

    async def test_other_domain_ingress_rejects_signed_work_source_metadata(self):
        self.claims['workSource'] = copy.deepcopy(SOURCE)
        with self.assertRaisesRegex(ContractError, 'credential_source_binding_invalid'):
            await self.admit()
