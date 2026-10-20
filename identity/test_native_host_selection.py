"""Native host selection is explicit, private and bound to admitted host inputs."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

from agentmux_contracts import ContractError
from nacl.signing import SigningKey
from identity.native_host_selection import write_native_host_selection, load_native_host_selection
from identity.test_application_host_selection import selection
from identity.test_application_service_selection import protected_host
from identity.test_authority import ref


class NativeHostSelectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        base = selection()
        self.value = {k:base[k] for k in ('schemaVersion','hostPolicy','ownerUid','workspaces',
                                       'kernelScope','connection','credentials')}
        self.value['workspaces'] = [str(self.root/'repo')]
        self.value['hostPolicy'] = str(self.root/'host.json')
        self.value['credentials']['path'] = str(self.root/'native.creds')
        self.key = self.root/'request.key'
        self.seed = bytes([7])*32
        self.key.write_bytes(self.seed)
        self.key.chmod(0o600)
        self.value.update(keys={'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one',
            'organizationId':'org-one','issuerInstanceId':'identity-one','stream':'AUTHORITY','domain':'app',
            'streamCreated':(datetime.now(timezone.utc)-timedelta(days=1)).isoformat().replace('+00:00','Z'),
            'minimumSequence':3,'maxBytes':2097152,'replicas':1,
            'hostTransportRef':ref('host-transport'),'hostIdentityRef':ref('host-service'),
            'issuerRef':ref('identity-issuer'),'issuerIdentityRef':ref('identity-service')},
            requestSigner={'keyFile':{'path':str(self.key),'sha256':'sha256:'+hashlib.sha256(self.key.read_bytes()).hexdigest()},
                           'ref':ref('host-transport'),
                           'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(self.seed).verify_key)).decode().rstrip('=')},
            destinations={'plugin-one':'task-owner'}, capabilityRoutes=[])
        self.path = self.root/'native.json'

    def load(self, receipt, **changes):
        inputs = dict(expected_digest=receipt.digest, host_policy=self.value['hostPolicy'],
            owner_uid=self.value['ownerUid'], workspaces=self.value['workspaces'],
            kernel_scope=self.value['kernelScope'], protected_host_account=protected_host())
        inputs.update(changes)
        return load_native_host_selection(self.path, **inputs)

    def test_activation_declarations_are_owner_free_pinned_and_immutable(self):
        from identity.native_host_selection import NativeHostSelection
        from identity.test_native_bridge import native_row
        from agentmux_contracts import canonical_bytes
        row = native_row()
        declaration = {k:row[k] for k in ('identityRef','manifestDigest','configurationChecksum','facts')}
        declaration.update(recordRef=row['ref'], previousRef=None, pin=row['owner']['pin'])
        self.value['activationDeclarations'] = {'plugin-one':declaration}
        selected = self.load(write_native_host_selection(self.path, self.value))
        self.assertEqual(selected.activation_declarations(), self.value['activationDeclarations'])
        selected.activation_declarations()['plugin-one']['facts']['grant']['actions'].clear()
        self.assertEqual(selected.activation_declarations()['plugin-one']['facts']['grant']['actions'], ['inspect'])
        for mutate in (lambda d:d.update(owner=row['owner']),
                       lambda d:d['recordRef'].update(revision=2),
                       lambda d:d.update(previousRef=ref('other')),
                       lambda d:d['identityRef'].update(ownerHubId='other'),
                       lambda d:d['pin'].update(manifestChecksum='sha256:'+'0'*64),
                       lambda d:d['facts']['grant'].update(subjectInstanceId='other')):
            candidate=copy.deepcopy(self.value)
            mutate(candidate['activationDeclarations']['plugin-one'])
            with self.assertRaises(ContractError): write_native_host_selection(self.root/'invalid.json', candidate)

    def test_create_only_and_current_host_pins(self):
        receipt = write_native_host_selection(self.path, self.value)
        selected = self.load(receipt)
        self.assertEqual(selected.key_options(), self.value['keys'])
        self.assertEqual(selected.read_signer_material(), self.key.read_bytes())
        self.assertEqual(selected.client_options()['requestSigningRef'], self.value['keys']['hostTransportRef'])
        self.assertEqual(selected.client_options()['responseSigningRef'], self.value['keys']['issuerRef'])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        changed = selected.key_options()
        changed['minimumSequence'] = 0
        self.assertEqual(selected.key_options()['minimumSequence'], 3)
        with self.assertRaises(FileExistsError):
            write_native_host_selection(self.path, self.value)
        for change in ({'expected_digest':'sha256:'+'0'*64}, {'host_policy':'/other/host.json'},
                       {'protected_host_account':None}, {'workspaces':[str(self.root/'other')]}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.load(receipt, **change)
        self.key.write_bytes(b'changed')
        with self.assertRaises(ContractError):
            selected.read_signer_material()

    def test_private_storage_activation_pins_require_scope_unique_ids_and_storage_binding(self):
        from identity.test_native_bridge import native_row
        row = native_row()
        row['facts']['domainBindings'].append({'id':'private-read','contractId':'capability-storage-read',
            'action':'read','resourceClass':'storage','resourceIds':['private-one']})
        declaration = {k:row[k] for k in ('identityRef','manifestDigest','configurationChecksum','facts')}
        declaration.update(recordRef=row['ref'],previousRef=None,pin=row['owner']['pin'],
            privateStorageResources=[{'resourceId':'private-one','scope':copy.deepcopy(row['facts']['grant']['scope']),
                                      'bindingDigest':'sha256:'+'a'*64}])
        self.value['activationDeclarations']={'plugin-one':declaration}
        selected=self.load(write_native_host_selection(self.path,self.value))
        self.assertEqual(selected.activation_declarations()['plugin-one']['privateStorageResources'],
                         declaration['privateStorageResources'])
        for mutate in (lambda d:d['privateStorageResources'].append(copy.deepcopy(d['privateStorageResources'][0])),
                       lambda d:d['privateStorageResources'][0]['scope'].update(projectId='other'),
                       lambda d:d['privateStorageResources'][0].update(resourceId='unbound'),
                       lambda d:d['facts']['domainBindings'][-1].update(action='inspect'),
                       lambda d:d['privateStorageResources'][0].update(bindingDigest='sha256:bad')):
            candidate=copy.deepcopy(self.value);mutate(candidate['activationDeclarations']['plugin-one'])
            with self.assertRaises(ContractError):write_native_host_selection(self.root/'invalid.json',candidate)

    def test_closed_pins_paths_and_no_display_authority(self):
        for mutate in (lambda v: v.update(grants=[]), lambda v: v['keys'].update(profileId='other'),
                       lambda v: v['keys'].update(domain='>'), lambda v: v['keys'].update(minimumSequence=-1),
                       lambda v: v['keys']['hostIdentityRef'].update(ownerHubId='other'),
                       lambda v: v['requestSigner'].update(ref=ref('identity-issuer')),
                       lambda v: v['requestSigner'].pop('ref'),
                       lambda v: v['credentials'].update(path=v['workspaces'][0]+'/secret'),
                       lambda v: v.update(destinations={}), lambda v: v.update(project='display'),
                       lambda v: v['connection'].update(endpoint='tls://remote:4222')):
            candidate = copy.deepcopy(self.value)
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(ContractError):
                write_native_host_selection(self.path, candidate)
            self.assertFalse(self.path.exists())

    def test_path_schema_accepts_absolute_names_and_refuses_controls(self):
        from agentmux_contracts import validate
        for path in ('/private/native.json', '/Users/test/Profile Data/native.json'):
            candidate = copy.deepcopy(self.value)
            candidate['hostPolicy'] = path
            validate('native-authority-host-selection', candidate)
        for path in ('relative/path', '/private/\x00key', '/private/\x1fkey', '/private/\x7fkey'):
            candidate = copy.deepcopy(self.value)
            candidate['hostPolicy'] = path
            with self.subTest(path=repr(path)), self.assertRaises(ContractError):
                validate('native-authority-host-selection', candidate)

    def test_raw_signer_rejects_wrong_length_wrapper_digest_and_public_key(self):
        from identity.native_host_selection import NativeHostSelection
        from agentmux_contracts import canonical_bytes
        for raw in (b'', self.seed[:-1], self.seed+b'x', b'{"seed":"wrapped"}'):
            self.key.write_bytes(raw)
            value = copy.deepcopy(self.value)
            value['requestSigner']['keyFile']['sha256'] = 'sha256:'+hashlib.sha256(raw).hexdigest()
            with self.subTest(length=len(raw)), self.assertRaises(ContractError):
                NativeHostSelection(canonical_bytes(value)).read_signer_material()
        self.key.write_bytes(self.seed)
        value = copy.deepcopy(self.value)
        value['requestSigner']['publicKey'] = base64.urlsafe_b64encode(bytes(32)).decode().rstrip('=')
        with self.assertRaises(ContractError):
            NativeHostSelection(canonical_bytes(value)).read_signer_material()

    def test_exact_jwt_policy_and_transport_handoff(self):
        from native_security.test_nats_credentials import credential
        from identity.native_host_selection import NativeHostSelection
        from agentmux_contracts import canonical_bytes
        selected = NativeHostSelection(canonical_bytes(self.value))
        expected = ('amx.v1.h.hub-one.o.org-one.identity.authority-one.command',
            '$JS.API.STREAM.INFO.AUTHORITY', '$JS.API.STREAM.MSG.GET.AUTHORITY',
            '$JS.app.API.STREAM.INFO.AUTHORITY', '$JS.app.API.STREAM.MSG.GET.AUTHORITY')
        self.assertEqual(selected.publish_subjects(), tuple(sorted(expected)))
        def enroll(extra=None, missing=None):
            def permissions(claims):
                pubs = list(expected)
                if extra: pubs.append(extra)
                if missing: pubs.remove(missing)
                claims['nats'].update(pub={'allow':pubs},
                    sub={'allow':[self.value['credentials']['replyPrefix']+'.>']})
            raw, account, user = credential(permissions)
            path = Path(self.value['credentials']['path'])
            path.write_bytes(raw)
            path.chmod(0o600)
            self.value['credentials'].update(accountPublicKey=account, userPublicKey=user,
                sha256='sha256:'+hashlib.sha256(raw).hexdigest())
            return NativeHostSelection(canonical_bytes(self.value))
        selected = enroll()
        options = selected.transport_options()
        self.assertEqual(options['subject'], expected[0])
        self.assertEqual(options['connection'], self.value['connection'])
        self.assertEqual(options['publishSubjects'], list(sorted(expected)))
        for extra in ('>', '$JS.API.STREAM.INFO.OTHER', '$JS.API.STREAM.PURGE.AUTHORITY',
                      '$JS.other.API.STREAM.INFO.AUTHORITY', '_INBOX.>'):
            with self.subTest(extra=extra), self.assertRaises(ContractError):
                enroll(extra=extra).load_credentials()
        with self.assertRaises(ContractError):
            enroll(missing='$JS.API.STREAM.INFO.AUTHORITY').load_credentials()
        selected = enroll()
        self.value['credentials']['userPublicKey'] = selection()['credentials']['userPublicKey']
        with self.assertRaises(ContractError):
            NativeHostSelection(canonical_bytes(self.value)).load_credentials()

    def test_explicit_capability_binding_and_scope(self):
        route = {'bindingId':'storage','requestContractId':'capability-storage-read',
            'replyContractId':'capability-content-reply',
            'scope':{'organizationId':'org-one','projectId':'project-one','workspaceId':None},
            'service':{'profileId':'profile-one','hubId':'hub-one','serviceId':'storage-owner',
                'serviceInstanceId':'storage-one','serviceIdentityRef':ref('storage-service'),
                'signingKeyRef':ref('storage-issuer')}}
        self.value['capabilityRoutes'] = [route]
        receipt = write_native_host_selection(self.path, self.value)
        self.assertEqual(self.load(receipt).capability_routes(), [route])
        selected = self.load(receipt)
        self.assertEqual(selected.capability_subject('storage'),
            'amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.storage-owner.command')
        self.assertIn(selected.capability_subject('storage'), selected.publish_subjects())
        with self.assertRaises(ContractError):
            selected.capability_subject('unknown')
        self.path.unlink()
        for mutate in (lambda r:r.update(replyContractId='other'),
                       lambda r:r['service'].update(serviceId='secret-owner'),
                       lambda r:r['scope'].update(organizationId='other')):
            candidate = copy.deepcopy(self.value)
            mutate(candidate['capabilityRoutes'][0])
            with self.assertRaises(ContractError):
                write_native_host_selection(self.path, candidate)
