"""Explicit service enrollment maps to actual owner constructor inputs."""
import base64
import binascii
import copy
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ssl
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes
from identity.application_service_selection import (write_application_service_selection,
    load_application_service_selection, provision_application_service_issuer, ApplicationServiceSelection)
from identity.test_application_host_selection import selection as host_selection
from identity.test_authority import ref, fixture
from identity.transitions import transition
from identity.service import IdentityService
from identity.authority import LedgerAuthorityReader
from identity.ingress import EnrolledIngress
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerLedger, owner_subject
from state_owner.backup_host import BackupHost
from state_owner.artifacts import OwnerArtifacts


def protected_host():
    return {'kind':'named-password', 'account':'HOST', 'broker':{
        'endpoint':'tls://127.0.0.1:4222', 'serverName':'kernel_server',
        'configSha256':'sha256:'+'c'*64}}

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'dashboard'))
from definition_service import DefinitionScope
from definition_command_service import DefinitionCommandService


class ServiceSelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.test_now = datetime.now(timezone.utc)
        self.issuer_start = (self.test_now - timedelta(minutes=1)).isoformat().replace('+00:00', 'Z')
        self.issuer_end = (self.test_now + timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        base = host_selection()
        self.value = {k: base[k] for k in ('schemaVersion', 'hostPolicy', 'ownerUid', 'workspaces', 'kernelScope')}
        self.value.update(authorityId='authority-one', organizationId='org-one',
                          hostPolicy=str(self.root / 'host.json'), workspaces=[str(self.root / 'project')])
        custody = self.root / 'authority-switch'
        custody.mkdir(mode=0o700)
        self.value['authoritySwitch'] = {'custodyDirectory': str(custody), 'binding': None}
        cert = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
        self.seeds = {}
        self.payloads = []
        for index, role in enumerate(('identity', 'definitions')):
            directory = self.root / role
            directory.mkdir(mode=0o700)
            service_id = 'identity-owner' if role == 'identity' else 'definition-owner'
            payload, receipt = provision_application_service_issuer(directory / 'issuer.key',
                service_id=service_id, profile_id='profile-one', authority_id='authority-one', instance_id='instance-one',
                identity={'ref': ref(role+'-service'), 'kind': 'service', 'status': 'active',
                          'principalId': role+'-service', 'externalIdentity': None},
                issuer_ref=ref(role+'-issuer'), issued_at=self.issuer_start, expires_at=self.issuer_end)
            self.payloads.append(payload)
            credentials = copy.deepcopy(base['credentials'])
            raw = bytes([160]) + bytes([index+1]) * 32
            credentials.update(path=str(directory / 'user.creds'), userPublicKey=base64.b32encode(
                raw + binascii.crc_hqx(raw, 0).to_bytes(2, 'little')).decode())
            scope = {'organizationId': 'org-one', 'projectId': None if role == 'identity' else 'project-one', 'workspaceId': None}
            self.value[role] = {'credentials': credentials,
                'connection': {'endpoint': 'tls://127.0.0.1:4222', 'serverName': 'agentmux.local',
                    'rootsPEM': ssl.DER_cert_to_PEM_cert(cert), 'leafCertificateSHA256': 'sha256:'+'a'*64,
                    'jetstreamDomain': 'enrolled-domain'},
                'issuer': {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
                    'issuerRef': ref(role+'-issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']},
                'ledger': {'entityId': 'authority-one' if role == 'identity' else 'catalog-one', 'scope': scope,
                    'stream': role.upper(), 'streamIdentity': {'created': '2026-10-16T00:00:00Z', 'minimumSequence': 0},
                    'retention': {'maxBytes': 2097152, 'reserveBytes': 262144, 'replicas': 1},
                    'history': {'path': str(directory / 'history.sqlite'), 'maxRecords': 1000000, 'maxBytes': 1073741824},
                    'checkpoint': {'path': str(directory / 'checkpoint'), 'commitRef': ref(role+'-checkpoint')}}}
        backup = {}
        for field in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
            path = self.root / field
            path.mkdir(mode=0o700)
            backup[field] = str(path)
        self.value['identity']['backup'] = dict(backup, destinationId='backup-one', keyId='backup-key')
        self.value['definitions'].update(directories={'projectRoot': str(self.root/'project'),
            'home': str(self.root/'home'), 'globalRoot': str(self.root/'global')},
            artifacts={'bucket': 'definitions', 'storeRef': ref('artifacts'), 'maxBytes': 67108864})
        self.path = self.root / 'services.json'

    def load(self, **changes):
        receipt = write_application_service_selection(self.path, self.value)
        inputs = dict(expected_digest=receipt.digest, host_policy=self.value['hostPolicy'],
            owner_uid=self.value['ownerUid'], workspaces=self.value['workspaces'],
            kernel_scope=self.value['kernelScope'], protected_host_account=protected_host())
        inputs.update(changes)
        return load_application_service_selection(self.path, **inputs)

    def add_integration(self, provider='github'):
        from integration_owner.intent import effect_id
        value = copy.deepcopy(self.value['definitions'])
        value.pop('directories')
        value.update(provider=provider, credentialRef=ref('provider-credential'),
                     originalOperationId='original-operation', credentialEnrollment=None)
        value['ledger']['entityId'] = effect_id(value['ledger']['scope'], value['originalOperationId'])
        value['ledger']['stream'] = 'INTEGRATION'
        value['ledger']['history']['path'] = str(self.root / 'integration.sqlite')
        raw = bytes([160]) + bytes([3]) * 32
        value['credentials']['path'] = str(self.root / 'integration.creds')
        value['credentials']['userPublicKey'] = base64.b32encode(raw + binascii.crc_hqx(raw, 0).to_bytes(2, 'little')).decode()
        payload, receipt = provision_application_service_issuer(self.root / 'integration.key',
            service_id='integration-owner', profile_id='profile-one', authority_id='authority-one', instance_id='instance-one',
            identity={'ref': ref('integration-service'), 'kind': 'service', 'status': 'active',
                      'principalId': 'integration-service', 'externalIdentity': None}, issuer_ref=ref('integration-issuer'),
            issued_at='2026-10-16T00:00:00Z', expires_at='2026-10-17T00:00:00Z')
        value['issuer'] = {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
            'issuerRef': ref('integration-issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']}
        self.value['integration'] = value

    def add_orchestration(self):
        directory = self.root / 'orchestration'
        directory.mkdir(mode=0o700, exist_ok=True)
        service = copy.deepcopy(self.value['definitions'])
        service.pop('directories')
        service.pop('artifacts')
        payload, receipt = provision_application_service_issuer(
            directory / 'issuer.key', service_id='orchestration-owner',
            profile_id='profile-one', authority_id='authority-one',
            instance_id='instance-one', identity={'ref': ref('orchestration-service'),
                'kind': 'service', 'status': 'active',
                'principalId': 'orchestration-service', 'externalIdentity': None},
            issuer_ref=ref('orchestration-issuer'), issued_at=self.issuer_start,
            expires_at=self.issuer_end)
        service['issuer'] = {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
            'issuerRef': ref('orchestration-issuer'),
            'publicKey': payload['issuers'][0]['record']['publicKey']}
        raw = bytes([160]) + bytes([7]) * 32
        service['credentials'].update(path=str(directory / 'user.creds'),
            userPublicKey=base64.b32encode(
                raw + binascii.crc_hqx(raw, 0).to_bytes(2, 'little')).decode(),
            replyPrefix='_INBOX.orchestration_service_01')
        service['ledger'].update(entityId='orchestration-one',
                                 stream='ORCHESTRATION')
        service['ledger']['history']['path'] = str(directory / 'history.sqlite')
        service['ledger']['checkpoint'] = {'path': str(directory / 'checkpoint'),
            'commitRef': ref('orchestration-checkpoint')}
        phase_seed = bytes([29]) * 32
        phase_path = directory / 'phase.key'
        phase_path.write_bytes(phase_seed)
        phase_path.chmod(0o600)
        service.update(scope=copy.deepcopy(service['ledger']['scope']),
            resourceRef=ref('orchestration-one'),
            repository=self.value['workspaces'][0],
            orchestratorAgent='ccc-orchestrator', environmentRef=None,
            serviceIdentityRef=ref('orchestration-service'),
            phaseAuthority={'transportRef': ref('orchestration-transport'),
                'keyFile': {'path': str(phase_path),
                    'sha256': 'sha256:' + hashlib.sha256(phase_seed).hexdigest()},
                'publicKey': base64.urlsafe_b64encode(
                    bytes(SigningKey(phase_seed).verify_key)).decode().rstrip('='),
                'grants': {'orchestration-dispatch': ref('orchestration-dispatch'),
                           'orchestration-complete': ref('orchestration-complete')}})
        self.value['orchestration'] = service

    def add_oidc_browser(self):
        key = SigningKey.generate()
        self.value['oidcBrowser'] = {
            'issuer': 'https://identity.example/realms/team',
            'audience': 'agentmux',
            'keyId': 'key-one',
            'publicKey': base64.urlsafe_b64encode(bytes(key.verify_key)).decode().rstrip('='),
            'maxTokenSeconds': 300,
            'authorizationEndpoint':
                'https://identity.example/realms/team/protocol/openid-connect/auth',
            'deviceAuthorizationEndpoint':
                'https://identity.example/realms/team/protocol/openid-connect/auth/device',
            'tokenEndpoint':
                'https://identity.example/realms/team/protocol/openid-connect/token'}

    async def test_optional_oidc_browser_is_protected_and_closed(self):
        selected = self.load()
        self.assertIsNone(selected.oidc_browser_configuration())
        self.assertIsNone(selected.oidc_device_configuration())
        self.path.unlink()
        self.add_oidc_browser()
        selected = self.load()
        provider, authorization, token = selected.oidc_browser_configuration()
        self.assertEqual(provider.issuer, self.value['oidcBrowser']['issuer'])
        self.assertEqual(provider.audience, 'agentmux')
        self.assertEqual(provider.max_token_seconds, 300)
        self.assertEqual(authorization, self.value['oidcBrowser']['authorizationEndpoint'])
        self.assertEqual(token, self.value['oidcBrowser']['tokenEndpoint'])
        device_provider, device, device_token = selected.oidc_device_configuration()
        self.assertEqual(device_provider.issuer, provider.issuer)
        self.assertEqual(device_provider.audience, provider.audience)
        self.assertEqual(device, self.value['oidcBrowser']['deviceAuthorizationEndpoint'])
        self.assertEqual(device_token, token)
        self.path.unlink()
        for field, invalid in (('issuer', 'http://identity.example/realms/team'),
                ('authorizationEndpoint', 'https://other.example/auth'),
                ('deviceAuthorizationEndpoint', 'https://other.example/device'),
                ('tokenEndpoint', 'https://identity.example/other/token'),
                ('publicKey', 'not-a-key')):
            value = self.value['oidcBrowser'][field]
            self.value['oidcBrowser'][field] = invalid
            with self.assertRaises(ContractError):
                self.load()
            self.value['oidcBrowser'][field] = value

    async def test_integration_requires_derived_effect_and_durable_atlassian_pin(self):
        self.add_integration(provider='jira')
        with self.assertRaises(ContractError):
            write_application_service_selection(self.path, self.value)
        self.value['integration']['credentialEnrollment'] = {'path': str(self.root/'pin.json'), 'sha256': 'sha256:'+'a'*64}
        self.value['integration']['ledger']['entityId'] = 'wrong-effect'
        with self.assertRaises(ContractError):
            write_application_service_selection(self.path, self.value)
        self.assertFalse(self.path.exists())

    async def test_selection_builds_explicit_integration_effect_provisioner(self):
        from integration_owner.provisioning import (IntegrationEffectInventory,
            IntegrationEffectProvisioner)
        self.add_integration()
        roots = []
        for name in ('effect-resources', 'effect-inventory', 'router-credentials',
                     'effect-backup-keys'):
            path = self.root / name
            path.mkdir(mode=0o700)
            roots.append(path)
        self.value['integration']['routing'] = {
            'resourceDirectory': str(roots[0]),
            'inventoryDirectory': str(roots[1]),
            'credentialDirectory': str(roots[2]),
            'backupKeyDirectory': str(roots[3]),
            'backupKeyId': 'backup-key',
            'backupDestinationId': 'integration-backup'}
        selected = self.load()
        owner = selected.integration_effect_provisioner(Mock(),
            resource_directory=roots[0], inventory_directory=roots[1],
            credential_directory=roots[2], backup_key_directory=roots[3],
            backup_key_id='backup-key', backup_destination_id='integration-backup',
            commit_ref=ref('integration-checkpoint'),
            credential_issuer=Mock())
        self.assertIsInstance(owner, IntegrationEffectProvisioner)
        self.assertEqual(owner._scope, self.value['integration']['ledger']['scope'])
        self.assertEqual(owner._base_stream, 'INTEGRATION')
        self.assertEqual(owner._max_history_records,
            self.value['integration']['ledger']['history']['maxRecords'])
        self.assertEqual(owner._max_history_bytes,
            self.value['integration']['ledger']['history']['maxBytes'])
        inventory = selected.integration_effect_inventory()
        self.assertIsInstance(inventory, IntegrationEffectInventory)
        with self.assertRaises(ContractError):
            selected.integration_effect_provisioner(Mock(),
                resource_directory=roots[0], inventory_directory=roots[1],
                credential_directory=roots[2], backup_key_directory=roots[3],
                backup_key_id='different-key',
                backup_destination_id='integration-backup',
                commit_ref=ref('integration-checkpoint'),
                credential_issuer=Mock())

    async def test_actual_services_receive_explicit_resources_and_domain(self):
        self.add_integration()
        selected = self.load()
        histories = {}
        for role in ('identity', 'definitions', 'integration'):
            histories[role] = OwnerHistory(selected.service(role)['ledger']['history']['path'],
                selected.binding(role), stream_identity=selected.stream_identity(role))
            self.addCleanup(histories[role].close)
        backup = self.value['identity']['backup']
        host = BackupHost(*(backup[k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'], binding=selected.binding('identity'),
            stream_identity=selected.stream_identity('identity'))
        async def committed(receipt):
            pass
        connection = SimpleNamespace(jetstream=Mock(return_value=object()))
        identity = IdentityService(connection, **selected.identity_kwargs(history=histories['identity'],
            checkpoint_committed=committed, signing_seed=selected.load_signing_seed('identity'), backup_host=host))
        connection.jetstream.assert_called_once_with(domain='enrolled-domain')
        artifacts = OwnerArtifacts(object(), object(), bucket='definitions', owner_hub_id='hub-one',
            store_ref=ref('artifacts'), max_bytes=67108864)
        scope = DefinitionScope(self.root/'project', self.root/'home', self.root/'global', 'project-one')
        kwargs = selected.definition_kwargs(history=histories['definitions'], checkpoint_committed=committed,
            signing_seed=selected.load_signing_seed('definitions'), authority=identity.reader, artifacts=artifacts, scope=scope)
        receiver = DefinitionCommandService.from_enrolled_host(connection, **kwargs)
        self.assertTrue(receiver.ledger.completion_budget_required)
        self.assertEqual(connection.jetstream.call_count, 2)
        self.assertEqual(receiver._subject, 'amx.v1.h.hub-one.o.org-one.definitions.catalog-one.command')
        from integration_owner.service import IntegrationRouterService, IntegrationService
        integration = IntegrationService.from_enrolled_host(connection, **selected.integration_kwargs(
            history=histories['integration'], checkpoint_committed=committed,
            signing_seed=selected.load_signing_seed('integration'), authority=identity.reader,
            artifacts=artifacts, credentials=None))
        self.assertTrue(integration.ledger.completion_budget_required)
        self.assertEqual(integration._subject, 'amx.v1.h.hub-one.o.org-one.integrations.' +
                         self.value['integration']['ledger']['entityId'] + '.command')
        self.assertEqual(connection.jetstream.call_count, 3)
        factory = lambda binding: None
        router = IntegrationRouterService.from_enrolled_host(connection,
            **selected.integration_router_kwargs(authority=identity.reader,
                signing_seed=selected.load_signing_seed('integration'),
                service_factory=factory, artifacts=artifacts,
                credentials=None))
        self.assertEqual(router.subject,
            'amx.v1.h.hub-one.o.org-one.integrations.*.command')
        self.assertIs(router._factory, factory)
        state = fixture()[0]['state']
        for payload in self.payloads:
            state = transition(state, 'identity-enroll', payload, hub_id='hub-one')
        self.assertEqual(state['issuers'][-1]['ref'], ref('definitions-issuer'))

    async def test_selected_service_credentials_match_exact_role_and_user(self):
        from native_security.test_nats_service_credentials import signed_service
        from native_security.nats_credentials import validate, CredentialError
        self.add_integration()
        for role in ('identity', 'definitions', 'integration'):
            candidate = copy.deepcopy(self.value)
            inputs = ApplicationServiceSelection(canonical_bytes(candidate)).service_policy_inputs(role)
            raw, account, user = signed_service(inputs)
            for service in ('identity', 'definitions'):
                candidate[service]['credentials']['accountPublicKey'] = account
            pin = candidate[role]['credentials']
            pin.update(accountPublicKey=account, userPublicKey=user, sha256='sha256:' + hashlib.sha256(raw).hexdigest())
            path = Path(pin['path'])
            path.write_bytes(raw)
            path.chmod(0o600)
            selected = ApplicationServiceSelection(canonical_bytes(candidate))
            credential = selected.load_service_credentials(role,
                protected_host_account=protected_host())
            self.assertEqual(credential.public_key, user)
            with self.assertRaises(ContractError):
                selected.load_service_credentials(role, protected_host_account=None)
            with self.assertRaises(CredentialError):
                validate(raw, account_public_key=account, publish_subjects=['amx.command'],
                    subscribe_subjects=[pin['replyPrefix']+'.>'], private_inbox=True)
            pin['userPublicKey'] = self.value[role]['credentials']['userPublicKey']
            wrong_user = ApplicationServiceSelection(canonical_bytes(candidate))
            with self.assertRaises(ContractError):
                wrong_user.load_service_credentials(role,
                    protected_host_account=protected_host())
            path.write_bytes(raw + b'changed')
            with self.assertRaises(ContractError):
                selected.load_service_credentials(role,
                    protected_host_account=protected_host())

    async def test_integration_credentials_refuse_artifact_writes_identity_reads_and_other_roles(self):
        from native_security.nats_credentials import service_policy
        from native_security.test_nats_service_credentials import signed_service
        self.add_integration()
        candidate = copy.deepcopy(self.value)
        inputs = ApplicationServiceSelection(canonical_bytes(candidate)).service_policy_inputs('integration')
        policy = service_policy(**inputs)
        binding = ApplicationServiceSelection(canonical_bytes(candidate)).binding('integration')
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.integrations.'+binding.entity_id+'.command')
        prefix = '$JS.' + inputs['jetstream_domain'] + '.API.'
        prohibited = ['$O.'+inputs['artifact_bucket']+'.C.*', '$O.'+inputs['artifact_bucket']+'.M.*',
            prefix+'STREAM.MSG.GET.'+candidate['identity']['ledger']['stream'],
            prefix+'STREAM.PURGE.'+inputs['stream']]
        for extra in prohibited:
            self.assertNotIn(extra, policy.publish_subjects)
            raw, account, user = signed_service(inputs, lambda nats: nats['pub']['allow'].append(extra))
            pin = candidate['integration']['credentials']
            pin.update(accountPublicKey=account, userPublicKey=user,
                       sha256='sha256:' + hashlib.sha256(raw).hexdigest())
            Path(pin['path']).write_bytes(raw)
            Path(pin['path']).chmod(0o600)
            with self.subTest(extra=extra), self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(candidate)).load_service_credentials('integration',
                    protected_host_account=protected_host())
        raw, account, user = signed_service(dict(inputs, role='definitions'))
        pin.update(accountPublicKey=account, userPublicKey=user, sha256='sha256:'+hashlib.sha256(raw).hexdigest())
        Path(pin['path']).write_bytes(raw)
        with self.assertRaises(ContractError):
            ApplicationServiceSelection(canonical_bytes(candidate)).load_service_credentials('integration',
                protected_host_account=protected_host())

    async def test_integration_router_policy_keeps_stream_apis_exact(self):
        from native_security.nats_credentials import service_policy
        self.add_integration()
        selected = ApplicationServiceSelection(canonical_bytes(self.value))
        inputs = selected.integration_routing_policy_inputs(
            additional_streams=('INTEGRATION_TWO',))
        policy = service_policy(**inputs)
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.integrations.*.command')
        self.assertIn('$JS.enrolled-domain.API.STREAM.INFO.INTEGRATION_TWO',
                      policy.publish_subjects)
        self.assertNotIn('$JS.enrolled-domain.API.STREAM.INFO.*',
                         policy.publish_subjects)
        self.assertEqual(selected.service_policy_inputs('integration').get(
            'integration_routing'), None)
        with self.assertRaises(ContractError):
            selected.integration_routing_policy_inputs(
                additional_streams='INTEGRATION_TWO')

    async def test_definition_policy_uses_own_domain_without_identity_stream_reads(self):
        from native_security.nats_credentials import service_policy
        from native_security.test_nats_service_credentials import signed_service
        candidate = copy.deepcopy(self.value)
        candidate['definitions']['connection']['jetstreamDomain'] = 'definition-domain'
        inputs = ApplicationServiceSelection(canonical_bytes(candidate)).service_policy_inputs('definitions')
        self.assertNotIn('authority_stream', inputs)
        self.assertEqual(inputs['jetstream_domain'], 'definition-domain')
        policy = service_policy(**inputs)
        for operation in ('INFO', 'MSG.GET'):
            extra = '$JS.definition-domain.API.STREAM.' + operation + '.' + candidate['identity']['ledger']['stream']
            self.assertNotIn(extra, policy.publish_subjects)
            raw, account, user = signed_service(inputs, lambda nats: nats['pub']['allow'].append(extra))
            pin = candidate['definitions']['credentials']
            pin.update(accountPublicKey=account, userPublicKey=user,
                       sha256='sha256:' + hashlib.sha256(raw).hexdigest())
            Path(pin['path']).write_bytes(raw)
            Path(pin['path']).chmod(0o600)
            selected = ApplicationServiceSelection(canonical_bytes(candidate))
            with self.assertRaises(ContractError):
                selected.load_service_credentials('definitions',
                    protected_host_account=protected_host())

    async def test_broadened_signed_permissions_are_refused_after_digest_match(self):
        from native_security.test_nats_service_credentials import signed_service
        candidate = copy.deepcopy(self.value)
        inputs = ApplicationServiceSelection(canonical_bytes(candidate)).service_policy_inputs('definitions')
        raw, account, user = signed_service(inputs, lambda nats: nats['pub']['allow'].append('>'))
        for role in ('identity', 'definitions'):
            candidate[role]['credentials']['accountPublicKey'] = account
        pin = candidate['definitions']['credentials']
        pin.update(accountPublicKey=account, userPublicKey=user, sha256='sha256:' + hashlib.sha256(raw).hexdigest())
        Path(pin['path']).write_bytes(raw)
        Path(pin['path']).chmod(0o600)
        selected = ApplicationServiceSelection(canonical_bytes(candidate))
        with self.assertRaises(ContractError):
            selected.load_service_credentials('definitions',
                protected_host_account=protected_host())

    async def test_missing_host_admission_and_host_pin_mismatch_refuse(self):
        with self.assertRaises(ContractError):
            self.load(protected_host_account=None)
        self.path.unlink()
        with self.assertRaises(ContractError):
            self.load(host_policy='/other/host.json')

    async def test_host_description_is_closed_and_not_a_selection_override(self):
        from identity.application_service_selection import validate_protected_host_account
        for change in (lambda v: v.update(kind='jwt'), lambda v: v.update(account='APP'),
                       lambda v: v.update(users=[]), lambda v: v.update(nkey='A'+'B'*55),
                       lambda v: v.update(imports=[]), lambda v: v['broker'].update(configSha256=''),
                       lambda v: v['broker'].update(endpoint='tls://remote:4222'),
                       lambda v: v['broker'].pop('serverName')):
            value = protected_host()
            change(value)
            with self.assertRaises(ContractError):
                validate_protected_host_account(value)
        for value in (None, {}, '', {'kind':'named-password','account':'HOST'}):
            with self.assertRaises(ContractError):
                validate_protected_host_account(value)
        for field, value in (('protectedHostAccount', protected_host()), ('hostAccountPublicKey','A'+'B'*55)):
            candidate = copy.deepcopy(self.value)
            candidate[field] = value
            with self.assertRaises(ContractError):
                write_application_service_selection(self.path, candidate)

    async def test_shared_application_account_is_not_named_password_host(self):
        self.assertEqual(self.value['identity']['credentials']['accountPublicKey'],
                         self.value['definitions']['credentials']['accountPublicKey'])
        selected = self.load()
        self.assertEqual(selected.service('identity')['credentials']['accountPublicKey'],
                         host_selection()['credentials']['accountPublicKey'])

    async def test_authority_switch_selection_is_explicit_and_retained_activation_cannot_disappear(self):
        candidate = copy.deepcopy(self.value)
        candidate.pop('authoritySwitch')
        with self.assertRaises(ContractError):
            ApplicationServiceSelection(canonical_bytes(candidate))
        selected = self.load()
        self.assertIsNone(selected.authority_switch_configuration())
        candidate = copy.deepcopy(self.value)
        candidate['authoritySwitch']['custodyDirectory'] = str(self.root / 'other-custody')
        with self.assertRaises(ContractError):
            ApplicationServiceSelection(canonical_bytes(candidate))
        custody = Path(self.value['authoritySwitch']['custodyDirectory'])
        (custody / ('authority-switch-' + 'a' * 64 + '-1-' + 'b' * 64 + '.json')).write_text('{}')
        with self.assertRaises(ContractError):
            selected.authority_switch_configuration()

    async def test_extra_commands_shared_users_and_workspace_secrets_refuse(self):
        for mutate in (lambda v: v.update(command=['python', 'anything']),
                       lambda v: v['definitions']['credentials'].update(userPublicKey=v['identity']['credentials']['userPublicKey']),
                       lambda v: v['identity']['issuer']['keyFile'].update(path=v['workspaces'][0]+'/secret')):
            original = copy.deepcopy(self.value)
            mutate(self.value)
            with self.assertRaises(ContractError):
                write_application_service_selection(self.path, self.value)
            self.assertFalse(self.path.exists())
            self.value = original

    async def test_digest_and_key_binding_are_checked_without_repair(self):
        selected = self.load()
        with self.assertRaises(ContractError):
            load_application_service_selection(self.path, expected_digest='sha256:'+'0'*64,
                host_policy=self.value['hostPolicy'], owner_uid=self.value['ownerUid'],
                workspaces=self.value['workspaces'], kernel_scope=self.value['kernelScope'],
                protected_host_account=protected_host())
        with self.assertRaises(FileExistsError):
            write_application_service_selection(self.path, self.value)
        self.value['identity']['issuer']['keyFile'] = self.value['definitions']['issuer']['keyFile']
        self.path.unlink()
        selected = self.load()
        with self.assertRaises(ContractError):
            selected.load_signing_seed('identity')

    async def test_dashboard_and_orchestration_policies_are_explicit_and_project_scoped(self):
        selected = ApplicationServiceSelection(canonical_bytes(self.value))
        self.assertIsNone(selected.dashboard_policy())
        self.assertIsNone(selected.orchestration_policy())

        scope = copy.deepcopy(self.value['definitions']['ledger']['scope'])
        self.value['dashboard'] = {
            'scope': copy.deepcopy(scope),
            'resourceRef': ref('dashboard-one'),
            'databasePath': str(self.root / 'private/dashboard.db'),
        }
        self.add_orchestration()
        selected = ApplicationServiceSelection(canonical_bytes(self.value))
        self.assertEqual(selected.dashboard_policy(), self.value['dashboard'])
        self.assertEqual(selected.orchestration_policy(), self.value['orchestration'])
        self.assertEqual((selected.binding('orchestration').owner_domain,
                          selected.binding('orchestration').entity_kind),
                         ('orchestration-operations', 'attempt'))
        self.assertEqual(selected.orchestration_policy_binding().repository,
                         self.value['workspaces'][0])
        self.assertEqual(selected.load_orchestration_phase_seed(), bytes([29]) * 32)
        self.assertEqual(selected.service_policy_inputs('orchestration')['role'],
                         'orchestration')

        identity_history = OwnerHistory(
            self.value['identity']['ledger']['history']['path'],
            selected.binding('identity'),
            stream_identity=selected.stream_identity('identity'))
        orchestration_history = OwnerHistory(
            self.value['orchestration']['ledger']['history']['path'],
            selected.binding('orchestration'),
            stream_identity=selected.stream_identity('orchestration'))
        self.addCleanup(identity_history.close)
        self.addCleanup(orchestration_history.close)
        identity_ledger = OwnerLedger(object(),
            stream=self.value['identity']['ledger']['stream'],
            subject=owner_subject(selected.binding('identity')),
            binding=selected.binding('identity'),
            retention=selected.retention('identity'),
            stream_identity=selected.stream_identity('identity'),
            history=identity_history, require_completion_budget=True)
        authority = LedgerAuthorityReader(identity_ledger, hub_id='hub-one',
            entity_id='authority-one', profile_id='profile-one',
            organization_id='org-one')
        kwargs = selected.orchestration_kwargs(authority=authority,
            ingress=EnrolledIngress(authority,
                issuer_ref=selected.service('identity')['issuer']['issuerRef'],
                signing_seed=selected.load_signing_seed('identity')),
            history=orchestration_history,
            signing_seed=selected.load_signing_seed('orchestration'),
            phase_signing_seed=selected.load_orchestration_phase_seed())
        self.assertEqual(kwargs['binding'], selected.binding('orchestration'))
        self.assertEqual(kwargs['owner_transport_ref'],
                         ref('orchestration-transport'))
        self.assertEqual(set(kwargs['phase_grants']), {
            'orchestration-dispatch', 'orchestration-complete'})
        ingress = kwargs['ingress']
        for target, attribute, replacement in (
                (ingress, '_reader', copy.copy(authority)),
                (ingress, '_issuer_ref', canonical_bytes(ref('other-issuer'))),
                (ingress, '_seed', bytes([91]) * 32),
                (identity_ledger, '_stream', 'OTHER'),
                (identity_history, '_path', self.root / 'other-history')):
            original = getattr(target, attribute)
            try:
                setattr(target, attribute, replacement)
                with self.subTest(attribute=attribute), self.assertRaises(ContractError):
                    selected.orchestration_kwargs(authority=authority,
                        ingress=ingress, history=orchestration_history,
                        signing_seed=selected.load_signing_seed('orchestration'),
                        phase_signing_seed=selected.load_orchestration_phase_seed())
            finally:
                setattr(target, attribute, original)

    async def test_domain_policies_refuse_scope_route_and_owner_substitution(self):
        scope = copy.deepcopy(self.value['definitions']['ledger']['scope'])
        self.value['dashboard'] = {'scope': copy.deepcopy(scope),
            'resourceRef': ref('dashboard-one'),
            'databasePath': str(self.root / 'private/dashboard.db')}
        self.add_orchestration()
        changes = (
            lambda value: value['dashboard']['scope'].update(projectId='other-project'),
            lambda value: value['dashboard']['resourceRef'].update(ownerHubId='other-hub'),
            lambda value: value['dashboard'].update(
                databasePath=value['workspaces'][0] + '/dashboard.db'),
            lambda value: value['orchestration']['scope'].update(projectId='other-project'),
            lambda value: value['orchestration'].update(repository=str(self.root / 'other')),
            lambda value: value['orchestration']['resourceRef'].update(ownerHubId='other-hub'),
            lambda value: value['orchestration'].update(environmentRef=dict(
                ref('environment-one'), ownerHubId='other-hub')),
        )
        for change in changes:
            candidate = copy.deepcopy(self.value)
            change(candidate)
            with self.subTest(change=change), self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(candidate))
