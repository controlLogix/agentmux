"""Policy enrollment binds one separate human command transport and target."""
import base64
import copy
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_client import ApplicationClientKey, provision_application_client, load_application_client
from identity.test_authority import NOW, ref
from identity.test_knowledge_client import material as knowledge_material
from identity.test_native_bridge import native_row
from state_owner.federation_policy import SCHEMA_REF


def material(base=None):
    value = knowledge_material() if base is None else copy.deepcopy(base)
    value.pop('knowledgeCommands', None)
    value['federationPolicyCommands'] = {
        'transportRef': ref('policy-command-transport'),
        'grantRefs': {c: ref('policy-' + c) for c in ('configuration-read', 'configuration-set')},
        'subject': 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.configuration.policy-one.command',
        'configurationRef': dict(ref('policy-one'), revision=0),
        'replyIssuerRef': ref('policy-reply-issuer'),
        'replyIssuerPublicKey': value['replyIssuerPublicKey'],
        'serviceIdentityRef': ref('policy-service'),
        'owner': native_row()['owner'],
        'target': {'sourceRef': ref('policy-source'), 'selectionDigest': 'sha256:' + 'a' * 64,
            'repositoryId': 'r000000000000'},
        'keyRef': ref('policy-key'), 'originDigest': 'sha256:' + 'b' * 64,
        'repository': {'localName': 'falcon', 'repositoryId': 'r000000000000',
            'normalizedRemote': 'example.invalid/falcon'},
        'authenticatedCaller': 'operator', 'policyPath': '/private/federation.toml', 'localPeer': 'nick'}
    return value


def read_claims(value, *, now=NOW):
    route = value['federationPolicyCommands']
    return {'purpose': 'agentmux-client-possession-v1',
        **{k: value[k] for k in ('hubId', 'profileId', 'authorityId')},
        'transportRef': route['transportRef'], 'grantRef': route['grantRefs']['configuration-read'],
        'contractId': 'configuration-read', 'operationId': 'policy-read', 'expectedVersion': 0,
        'payload': {'configurationRef': route['configurationRef'], 'owner': route['owner']},
        'approvalRefs': [], 'replySubject': '_INBOX.abcdefghijklmnop.request_one',
        'issuedAt': now.isoformat().replace('+00:00', 'Z'),
        'expiresAt': (now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}


class PolicyCommandEnrollmentTests(unittest.TestCase):
    def test_policy_preparation_signs_only_the_exact_target_and_key(self):
        value = material()
        route = value['federationPolicyCommands']
        key = ApplicationClientKey(value)
        claims = read_claims(value)
        proposal = {'format': 'amx-federation-policy-preparation-v1',
            'target': route['target'], 'originDigest': route['originDigest'], 'previousRevision': 0,
            'oldPolicy': {'digest': route['originDigest'], 'bytes': 40},
            'desiredPolicy': {'digest': 'sha256:' + 'c' * 64, 'bytes': 42},
            'change': {'verb': 'trust', 'arguments': {'peer': 'alice', 'level': 'flag'}}}
        claims.update(contractId='configuration-set', grantRef=route['grantRefs']['configuration-set'])
        claims['payload'].update(schemaRef=SCHEMA_REF, secretReferences=[route['keyRef']],
            configurationBytes=base64.b64encode(canonical_bytes(proposal)).decode())
        raw = key.sign_command(claims, subject=route['subject'], now=NOW)
        self.assertEqual(key.verify_command_request(raw, subject=route['subject'])[0], strict_loads(raw))
        for field, replacement in (('target', {**route['target'], 'selectionDigest': 'sha256:' + 'd' * 64}),
                ('originDigest', 'sha256:' + 'e' * 64), ('previousRevision', 1), ('format', 'other')):
            changed = copy.deepcopy(claims)
            document = dict(proposal, **{field: replacement})
            changed['payload']['configurationBytes'] = base64.b64encode(canonical_bytes(document)).decode()
            with self.assertRaises(ContractError):
                key.sign_command(changed, subject=route['subject'], now=NOW)
        changed = copy.deepcopy(claims)
        changed['payload']['secretReferences'] = [ref('other-key')]
        with self.assertRaises(ContractError):
            key.sign_command(changed, subject=route['subject'], now=NOW)

    def test_actual_key_signs_only_its_exact_policy_read(self):
        value = material()
        key = ApplicationClientKey(value)
        claims = read_claims(value)
        subject = key.command_subject('configuration-read')
        raw = key.sign_command(claims, subject=subject, now=NOW)
        self.assertEqual(key.verify_command_request(raw, subject=subject)[0], strict_loads(raw))
        for mutate in (lambda c: c.update(transportRef=ref('other')),
                lambda c: c.update(grantRef=ref('other')),
                lambda c: c.update(expectedVersion=1),
                lambda c: c['payload']['configurationRef'].update(id='other'),
                lambda c: c['payload']['owner'].update(instanceId='other'),
                lambda c: c.update(expiresAt=(NOW + timedelta(seconds=6)).isoformat().replace('+00:00', 'Z'))):
            changed = copy.deepcopy(claims)
            mutate(changed)
            with self.assertRaises(ContractError):
                key.sign_command(changed, subject=subject, now=NOW)

    def test_shared_transport_foreign_target_and_extra_authority_refuse(self):
        for mutate in (lambda v: v['federationPolicyCommands'].update(transportRef=v['transportRef']),
                lambda v: v['federationPolicyCommands']['target'].update(repositoryId='r111111111111'),
                lambda v: v['federationPolicyCommands']['grantRefs'].update(
                    **{'configuration-set': v['federationPolicyCommands']['grantRefs']['configuration-read']}),
                lambda v: v['federationPolicyCommands'].update(policyPath='relative/federation.toml'),
                lambda v: v['federationPolicyCommands'].update(credentials='private')):
            value = material()
            mutate(value)
            with self.assertRaises(ContractError):
                ApplicationClientKey(value)

    def test_provision_uses_current_ingress_issuer_for_distinct_policy_transport(self):
        value = material()
        value.pop('purpose'); value.pop('seed')
        identity = {'ref': value['callerRef'], 'kind': 'human', 'status': 'active',
            'principalId': 'human-one', 'externalIdentity': None}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'client.key'
            payload = provision_application_client(path, selection=value, identity=identity,
                issued_at=NOW.isoformat().replace('+00:00', 'Z'),
                expires_at=(NOW + timedelta(minutes=5)).isoformat().replace('+00:00', 'Z'))
            key = load_application_client(path)
        records = [t['record'] for t in payload['transports']]
        self.assertEqual(len(records), 2)
        policy = next(t for t in records if t['ref'] == value['federationPolicyCommands']['transportRef'])
        self.assertEqual(policy['issuerRef'], value['replyIssuerRef'])
        self.assertNotEqual(policy['issuerRef'], value['federationPolicyCommands']['replyIssuerRef'])
        self.assertEqual(policy['publicKey'], key.public_key)
