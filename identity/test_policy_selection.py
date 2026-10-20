"""Closed policy service enrollment and its exact broker credential policy."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

import nkeys
from agentmux_contracts import ContractError, canonical_bytes
from identity.application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from identity import test_application_service_selection as support
from identity.test_authority import ref
from native_security.nats_credentials import service_policy, validate_service


def add_policy(test):
    directory = test.root / 'policy'
    directory.mkdir(mode=0o700)
    payload, receipt = provision_application_service_issuer(directory / 'issuer.key', service_id='policy-owner',
        profile_id='profile-one', authority_id='authority-one', instance_id='policy-instance',
        identity={'ref': ref('policy-service'), 'kind': 'service', 'status': 'active',
            'principalId': 'policy-service', 'externalIdentity': None}, issuer_ref=ref('policy-issuer'),
        issued_at=test.issuer_start, expires_at=test.issuer_end)
    selected = {key: copy.deepcopy(test.value['definitions'][key]) for key in ('connection', 'credentials', 'ledger')}
    selected['ledger'].update(entityId='native-policy', stream='POLICY')
    selected['ledger']['history']['path'] = str(directory / 'history.sqlite')
    selected['ledger']['checkpoint'] = {'path': str(directory / 'checkpoint'), 'commitRef': ref('policy-checkpoint')}
    selected.update(issuer={'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
        'issuerRef': ref('policy-issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']},
        serviceIdentityRef=ref('policy-service'), serviceInstanceId='policy-instance',
        requestSigningKeyRef=ref('identity-issuer'), policyRef=ref('native-policy'),
        pluginIdentityRef=ref('plugin'), instanceId='plugin-one')
    roots = {}
    for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
        path = directory / key
        path.mkdir(mode=0o700)
        roots[key] = str(path)
    selected['backup'] = dict(roots, destinationId='policy-backup', keyId='policy-key')
    credentials = selected['credentials']
    credentials.update(path=str(directory / 'policy.creds'), replyPrefix='_INBOX.policy_service_000001')
    policy = service_policy(role='policy', hub_id='hub-one', entity_id='native-policy',
        scope=selected['ledger']['scope'], stream='POLICY', reply_prefix=credentials['replyPrefix'],
        jetstream_domain=selected['connection']['jetstreamDomain'])
    account = nkeys.from_seed(nkeys.encode_seed(bytes([1]) * 32, nkeys.PREFIX_BYTE_ACCOUNT))
    user = nkeys.from_seed(nkeys.encode_seed(bytes([55]) * 32, nkeys.PREFIX_BYTE_USER))
    try:
        now = int(test.test_now.timestamp())
        claims = {'iss': account.public_key.decode(), 'sub': user.public_key.decode(), 'iat': now, 'exp': now + 3600,
            'nats': {'type': 'user', 'version': 2, 'pub': {'allow': list(policy.publish_subjects)},
                'sub': {'allow': list(policy.subscribe_subjects)}, 'resp': policy.response_permissions}}
        encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
        signed = encode({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encode(claims)
        token = signed + b'.' + base64.urlsafe_b64encode(account.sign(signed)).rstrip(b'=')
        raw = b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n' + \
            b'-----BEGIN USER NKEY SEED-----\n' + user.seed + b'\n------END USER NKEY SEED------\n'
        Path(credentials['path']).write_bytes(raw)
        Path(credentials['path']).chmod(0o600)
        credentials.update(sha256='sha256:' + hashlib.sha256(raw).hexdigest(),
            accountPublicKey=account.public_key.decode(), userPublicKey=user.public_key.decode())
    finally:
        account.wipe()
        user.wipe()
    test.value['policy'] = selected
    return payload


class PolicySelectionTests(unittest.TestCase):
    def setUp(self):
        support.ServiceSelectionTests.setUp(self)
        add_policy(self)

    def selected(self):
        return ApplicationServiceSelection(canonical_bytes(self.value))

    def test_exact_role_credentials_signing_key_and_receipt_binding(self):
        selected = self.selected()
        self.assertEqual(selected.binding('policy').owner_domain, 'policy-evaluations')
        self.assertEqual(len(selected.load_signing_seed('policy')), 32)
        inputs = selected.service_policy_inputs('policy')
        policy = service_policy(**inputs)
        credentials = selected.service('policy')['credentials']
        actual = validate_service(selected.read_credential_bytes('policy'),
            account_public_key=credentials['accountPublicKey'], **inputs)
        self.assertEqual(actual.public_key, credentials['userPublicKey'])
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.policy-owner.command')
        self.assertEqual(policy.response_permissions, {'max': 1, 'ttl': 5000000000})
        self.assertNotIn('>', policy.publish_subjects)

    def test_omission_preserves_existing_services_and_unknown_fields_refuse(self):
        original = self.value.pop('policy')
        self.selected()
        self.value['policy'] = dict(original, arbitraryCallback='unused')
        with self.assertRaises(ContractError):
            self.selected()

    def test_substituted_reference_inbox_or_custody_refuses(self):
        original = copy.deepcopy(self.value)
        for mutate in (
                lambda p: p.update(policyRef=ref('other-policy')),
                lambda p: p.update(requestSigningKeyRef=ref('other-requester')),
                lambda p: p['credentials'].update(replyPrefix=self.value['definitions']['credentials']['replyPrefix']),
                lambda p: p['ledger']['history'].update(path=self.value['definitions']['ledger']['history']['path']),
                lambda p: p['backup'].update(keyDirectory=self.value['identity']['backup']['keyDirectory'])):
            self.value = copy.deepcopy(original)
            mutate(self.value['policy'])
            with self.assertRaises(ContractError):
                self.selected()
