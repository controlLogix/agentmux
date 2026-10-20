"""Closed knowledge enrollment, caller families and actual possession signing."""
import base64
import copy
from datetime import timedelta
import unittest

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, payload_digest, strict_loads
from hub.fed import envelope
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, SEED, ref
from identity import test_authority as support


class KnowledgeAuthorityTests(unittest.TestCase):
    setUp = support.AuthorityTests.setUp
    check = support.AuthorityTests.check
    resign = support.AuthorityTests.resign

    def select(self, action, value, *, kind='human'):
        contract = 'federation-knowledge-' + action
        self.env.update(contractId=contract, destinationServiceId='storage-owner',
            payload={'resourceRef': ref('task-one'), 'input': value})
        if action not in ('read', 'inspect', 'outcome'):
            self.env['payload']['attribution'] = 'operator' if action == 'share' else 'federation'
        self.env['operation'].update(expectedVersion=1, payloadDigest=payload_digest(self.env['payload']))
        self.record['state']['identities'][0]['kind'] = kind
        self.env['operation']['caller']['kind'] = kind
        self.record['state']['grants'][0]['contractId'] = contract
        self.audience = {'hubId': 'hub-one', 'serviceId': 'storage-owner'}
        self.resign()

    def test_human_share_and_service_index_have_separate_authority(self):
        item = envelope.make('knowledge', 'nick', 'mac', 'r000000000000', '*', {})
        self.select('share', {'envelope': item})
        self.assertEqual(self.check().outcome, 'allowed')
        self.select('share', {'envelope': item}, kind='plugin')
        self.assertEqual(self.check().reason, 'native_capability_admission_required')
        self.select('index', {'envelope': item, 'subject': 'am.know.alice.r000000000000', 'localNode': 'mac'})
        self.assertEqual(self.check().reason, 'knowledge_scope_or_actor_mismatch')
        self.select('index', {'envelope': item, 'subject': 'am.know.alice.r000000000000', 'localNode': 'mac'},
            kind='service')
        self.assertEqual(self.check().outcome, 'allowed')

    def test_recovery_needs_current_original_permission_and_exact_version(self):
        self.select('outcome', {'contractId': 'federation-knowledge-share',
            'operationId': 'original', 'payloadDigest': 'sha256:' + 'a' * 64})
        self.assertEqual(self.check().reason, 'knowledge_original_authority_unavailable')
        original = copy.deepcopy(self.record['state']['grants'][0])
        original.update(ref=ref('original-share'), contractId='federation-knowledge-share')
        self.record['state']['grants'].append(original)
        self.assertEqual(self.check().outcome, 'allowed')
        self.env['operation']['expectedVersion'] = 2
        self.resign()
        self.assertEqual(self.check().reason, 'knowledge_scope_or_actor_mismatch')


def material():
    public = base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
    return {'purpose': 'agentmux-application-client-key-v1',
        'seed': base64.b64encode(bytes(reversed(SEED))).decode(),
        'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
        'instanceId': 'application-one', 'callerRef': ref('human'),
        'scope': {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None},
        'transportRef': ref('application-transport'), 'grantRef': ref('application-grant'),
        'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': public,
        'releaseDigest': 'sha256:' + 'a' * 64, 'policyRef': ref('application-policy'), 'workspaceRef': None,
        'knowledgeCommands': {'authenticatedCaller': 'operator',
            'subject': 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.storage-owner.command',
            'transportRef': ref('knowledge-transport'),
            'grantRefs': {'federation-knowledge-' + action: ref('knowledge-' + action)
                for action in ('share', 'read', 'inspect', 'outcome')},
            'resourceRef': ref('task-one'), 'localPeer': 'nick', 'localNode': 'mac',
            'repository': {'localName': 'falcon', 'repositoryId': 'r000000000000'},
            'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': public,
            'serviceIdentityRef': ref('service'), 'serviceInstanceId': 'ingress-one'}}


class KnowledgeKeyTests(unittest.TestCase):
    def test_signs_only_the_exact_protected_route_and_payload(self):
        key = ApplicationClientKey(material())
        route = key.selection['knowledgeCommands']
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': route['transportRef'], 'grantRef': route['grantRefs']['federation-knowledge-share'],
            'operationId': 'knowledge-share', 'expectedVersion': 1, 'contractId': 'federation-knowledge-share',
            'payload': {'resourceRef': route['resourceRef'], 'attribution': 'operator', 'input': {'envelope':
                envelope.make('knowledge', 'nick', 'mac', route['repository']['repositoryId'], '*', {})}},
            'approvalRefs': [], 'replySubject': '_INBOX.knowledge_client_0001',
            'issuedAt': NOW.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (NOW + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}
        raw = key.sign_command(claims, subject=key.command_subject(claims['contractId']), now=NOW)
        self.assertEqual(key.verify_command_request(raw, subject=route['subject'])[0], strict_loads(raw))
        for field in ('transportRef', 'grantRef'):
            changed = copy.deepcopy(claims)
            changed[field] = ref('foreign')
            with self.assertRaises(ContractError):
                key.sign_command(changed, subject=route['subject'], now=NOW)
        with self.assertRaises(ContractError):
            key.sign_command(claims, subject=route['subject'] + '.other', now=NOW)

    def test_enrollment_refuses_shared_transport_and_wrong_actor_family(self):
        for change in ('transport', 'service-family', 'scope'):
            value = material()
            route = value['knowledgeCommands']
            if change == 'transport':
                route['transportRef'] = value['transportRef']
            elif change == 'service-family':
                route['grantRefs']['federation-knowledge-index'] = ref('index')
            else:
                value['scope']['projectId'] = None
            with self.assertRaises(ContractError):
                ApplicationClientKey(value)
