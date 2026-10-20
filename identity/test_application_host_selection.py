"""Explicit host pins, private creation, and byte-exact digest receipts."""
import base64
import binascii
import copy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import tempfile
import ssl
import unittest

from agentmux_contracts import ContractError
from identity.application_host_selection import write_application_attestor_host_selection
from identity.test_authority import ref


def selection():
    def nkey(prefix):
        raw = bytes([prefix]) + bytes(range(32))
        return base64.b32encode(raw + binascii.crc_hqx(raw, 0).to_bytes(2, 'little')).decode()
    digest = 'sha256:' + 'a' * 64
    return {'schemaVersion': '1.0.0', 'hostPolicy': '/private/host.json',
        'ownerUid': os.getuid(), 'workspaces': ['/private/workspace'],
        'kernelScope': {'hubId': 'hub-one', 'instanceId': 'instance-one', 'profileId': 'profile-one',
                        'assemblyDigest': digest, 'releaseManifestDigest': digest, 'releaseVersion': '1.0.0'},
        'keyPath': '/private/attestor.key', 'credentials': {'path': '/private/attestor.creds',
            'sha256': digest, 'accountPublicKey': nkey(0), 'userPublicKey': nkey(160),
            'replyPrefix': '_INBOX.' + 'a' * 16},
        'connection': {'endpoint':'tls://127.0.0.1:4223', 'serverName':'application.agentmux.invalid',
            'rootsPEM':ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0]),
            'leafCertificateSHA256':digest},
        'application': {'authorityId': 'authority-one', 'identityRef': ref('observer'),
            'issuerRef': ref('observer-issuer'), 'transportRef': ref('observer-transport'),
            'policyRef': ref('policy'), 'workspaceRef': None,
            'scope': {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}},
        'receiptTrust': {'issuerRef': ref('ingress'), 'publicKey': base64.urlsafe_b64encode(bytes(32)).decode().rstrip('='),
            'notBefore': '2026-10-16T00:00:00Z', 'expiresAt': '2026-10-17T00:00:00Z', 'minimumAuthorityRevision': 1},
        'initialGeneration': 1}


class HostSelectionTests(unittest.TestCase):
    now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)

    def test_private_create_only_and_exact_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'selection.json'
            receipt = write_application_attestor_host_selection(path, selection(), now=self.now)
            raw = path.read_bytes()
            self.assertEqual(receipt.path, str(path))
            self.assertEqual(receipt.digest, 'sha256:' + hashlib.sha256(raw).hexdigest())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_application_attestor_host_selection(path, selection(), now=self.now)
            self.assertEqual(path.read_bytes(), raw)

    def test_bad_pins_are_refused_before_creation(self):
        mutations = [lambda s: s.update(extra=True),
            lambda s: s.update(keyPath='/private/../key'),
            lambda s: s['application']['issuerRef'].update(ownerHubId='other-hub'),
            lambda s: s['credentials'].update(userPublicKey='U' + 'A' * 55),
            lambda s: s['receiptTrust'].update(expiresAt='2026-10-16T00:00:00Z'),
            lambda s: s.update(initialGeneration=0)]
        mutations += [lambda s: s.pop('connection'), lambda s: s.update(connection=None),
            lambda s: s['connection'].update(endpoint='tls://127.0.0.1:65536'),
            lambda s: s['connection'].update(endpoint='tls://remote.example:4222'),
            lambda s: s['connection'].update(serverName='127.0.0.1'),
            lambda s: s['connection'].update(rootsPEM='not a certificate'),
            lambda s: s['connection'].update(rootsPEM=s['connection']['rootsPEM']*2),
            lambda s: s['connection'].update(leafCertificateSHA256=''),
            lambda s: s['connection'].update(jetstreamDomain=None)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'selection.json'
            for mutate in mutations:
                candidate = copy.deepcopy(selection())
                mutate(candidate)
                with self.subTest(candidate=candidate), self.assertRaises(ContractError):
                    write_application_attestor_host_selection(path, candidate, now=self.now)
                self.assertFalse(path.exists())
