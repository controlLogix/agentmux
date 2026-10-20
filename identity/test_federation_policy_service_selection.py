"""Dedicated policy selection remains separate from ordinary configuration."""
import copy
import hashlib
import unittest
from pathlib import Path

from agentmux_contracts import ContractError, canonical_bytes
from identity.application_service_selection import ApplicationServiceSelection
from identity import test_configuration_selection as configuration_support
from identity import test_storage_selection as storage_support
from identity.test_authority import ref
from capability_owner.test_knowledge_host import selected_knowledge
from state_owner.federation_policy import FEDERATION_POLICY_SCHEMA, SCHEMA_REF
from identity.federation_policy_selection import policy_binding, policy_target, policy_inputs


class FederationPolicySelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        configuration_support.ConfigurationSelectionTests.setUp(self)
        other = storage_support.StorageSelectionTests()
        other.setUp()
        self.addCleanup(other.temp.cleanup)
        self.value['storage'] = copy.deepcopy(other.value['storage'])
        self.value['storage']['knowledge'] = selected_knowledge(self.root, scope=other.scope)
        service = self.value.pop('configuration')
        service['ledger']['scope'] = copy.deepcopy(other.scope)
        path = self.root / 'federation-policy.schema.json'
        path.write_bytes(FEDERATION_POLICY_SCHEMA)
        path.chmod(0o600)
        service['schemaRef'] = SCHEMA_REF
        service['schemaResources'] = {SCHEMA_REF:{'path':str(path),
            'sha256':'sha256:'+hashlib.sha256(FEDERATION_POLICY_SCHEMA).hexdigest()}}
        knowledge = self.value['storage']['knowledge']
        self.value['federationPolicy'] = {'service': service,
            'target': {'sourceRef':ref('federation-source'), 'source':knowledge['source'],
                'repository':knowledge['repository'], 'localPeer':knowledge['localPeer']},
            'artifacts': {'bucket':'POLICY', 'storeRef':ref('policy-artifacts'), 'maxBytes':65576},
            'key': {'path':str(self.root/'policy.key'), 'keyRef':ref('policy-key')},
            'backupAuthority': {'transportRef':ref('policy-reader'), 'grantRef':ref('policy-read')},
            'projectionAuthority': {'serviceIdentityRef':ref('configuration-service'),
                'transportRef':ref('policy-projector'), 'grantRef':ref('policy-project')}}

    def selected(self):
        return ApplicationServiceSelection(canonical_bytes(self.value))

    async def test_dedicated_binding_and_finite_artifact_policy(self):
        value = self.selected().policy
        self.assertEqual(policy_binding(value).entity_id, 'configuration-one')
        self.assertEqual(policy_target(value).descriptor['repositoryId'],
            value['storage']['knowledge']['repository']['repositoryId'])
        self.assertEqual(policy_inputs(value)['artifact_bucket'], 'POLICY')
        self.assertNotIn('configuration', value)

    async def test_ordinary_configuration_collision_refuses(self):
        self.value['configuration'] = copy.deepcopy(self.value['federationPolicy']['service'])
        with self.assertRaises(ContractError):
            self.selected()

    async def test_wrong_source_scope_schema_and_key_location_refuse(self):
        original = copy.deepcopy(self.value)
        for mutate in (
            lambda p:p['target']['source']['policy'].update(sha256='sha256:'+'a'*64),
            lambda p:p['target'].update(localPeer='other'),
            lambda p:p['service']['ledger']['scope'].update(projectId='other'),
            lambda p:p['service'].update(schemaRef='different.json'),
            lambda p:p['key'].update(path=self.value['workspaces'][0]+'/private.key'),
            lambda p:p['projectionAuthority'].update(grantRef=p['backupAuthority']['grantRef'])):
            self.value = copy.deepcopy(original)
            # Separate the target pins from the selected source before mutation.
            self.value['federationPolicy']['target'] = copy.deepcopy(self.value['federationPolicy']['target'])
            mutate(self.value['federationPolicy'])
            with self.assertRaises(ContractError):
                self.selected()

    async def test_changed_schema_bytes_refuse(self):
        self.selected()
        Path(self.value['federationPolicy']['service']['schemaResources'][SCHEMA_REF]['path']).write_bytes(b'{}')
        with self.assertRaises(ContractError):
            self.selected()

    async def test_distinct_ordinary_configuration_coexists(self):
        import base64
        import binascii
        other = configuration_support.ConfigurationSelectionTests()
        other.setUp()
        self.addCleanup(other.temp.cleanup)
        ordinary = copy.deepcopy(other.value['configuration'])
        ordinary['owner']['instanceId'] = 'ordinary-config-instance'
        ordinary['ledger'].update(entityId='ordinary-configuration', stream='ORDINARY')
        raw = bytes([160]) + bytes([61])*32
        ordinary['credentials']['userPublicKey'] = base64.b32encode(
            raw+binascii.crc_hqx(raw,0).to_bytes(2,'little')).decode()
        ordinary['issuer']['publicKey'] = base64.urlsafe_b64encode(bytes([62])*32).decode().rstrip('=')
        self.value['configuration'] = ordinary
        selected = self.selected()
        self.assertEqual(selected.service('configuration')['ledger']['entityId'], 'ordinary-configuration')
        self.assertEqual(policy_binding(selected.policy).entity_id, 'configuration-one')
        self.assertNotIn('artifact_bucket', selected.service_policy_inputs('configuration'))

    async def test_factory_constructs_actual_dedicated_owner_and_retains_key_until_close(self):
        from datetime import datetime
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, Mock, patch
        from dashboard.application_service_host import ApplicationServiceHost
        from identity.service import IdentityService
        from state_owner.configuration_host import ConfigurationHost
        from state_owner.federation_policy import FederationPolicyOwner
        from state_owner.backup_host import BackupHost
        from state_owner.ledger import StreamIdentity
        selected = self.selected()
        history, backup = configuration_support.ConfigurationSelectionTests.resources(self, selected, 'identity')
        identity_connection = SimpleNamespace(jetstream=Mock(return_value=object()))
        identity = IdentityService(identity_connection, **selected.identity_kwargs(history=history,
            checkpoint_committed=lambda receipt:None, signing_seed=selected.load_signing_seed('identity'), backup_host=backup))
        service = selected.policy['federationPolicy']['service']
        backup_pin = service['backup']
        stream = service['ledger']['streamIdentity']
        backup = BackupHost(*(backup_pin[k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup_pin['destinationId'], binding=policy_binding(selected.policy),
            stream_identity=StreamIdentity(datetime.fromisoformat(stream['created']),stream['minimumSequence']))
        backup.enroll_key(backup_pin['keyId'])
        key_path = Path(selected.policy['federationPolicy']['key']['path'])
        key_path.write_bytes(bytes(range(32))); key_path.chmod(0o600)
        connection = SimpleNamespace()
        js = SimpleNamespace(_nc=connection, _prefix='$JS.enrolled-domain.API')
        objects = SimpleNamespace(_js=js, _name='POLICY')
        js.object_store = AsyncMock(return_value=objects)
        connection.jetstream = Mock(return_value=js)
        host = ApplicationServiceHost(selected, browser_port=0)
        host._identity = identity
        self.addAsyncCleanup(host.close)
        with patch.object(host, '_connect', AsyncMock(return_value=connection)), \
                patch('identity.federation_policy_selection.check_policy_authority', AsyncMock()), \
                patch.object(ConfigurationHost, 'start', AsyncMock()) as start:
            await host._start_federation_policy()
        actual = host._federation_policy
        self.assertIsInstance(actual.owner, FederationPolicyOwner)
        self.assertIs(actual.owner.custody._artifacts._js._nc, connection)
        self.assertEqual(actual.ledger._binding, policy_binding(selected.policy))
        self.assertIsNone(host._configuration)
        self.assertIn(actual, host._services)
        self.assertIs(actual.owner.custody._key, host._federation_policy_keys[0])
        start.assert_awaited_once()
        await host.close()
        self.assertTrue(actual.done.is_set())
        self.assertIsNone(host._federation_policy_keys[0]._fd)
