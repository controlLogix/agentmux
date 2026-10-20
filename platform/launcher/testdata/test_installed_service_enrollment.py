"""Offline enrollment checks; no broker, child process or service is started."""
from datetime import datetime, timezone
import os
import base64
from pathlib import Path
import tempfile
import ssl
import unittest
import asyncio

import nkeys

from agentmux_contracts import ContractError, canonical_bytes
from identity.application_enrollment import _read_material
from identity.application_client import load_application_client
from identity.bootstrap import BootstrapOwner
from identity.test_bootstrap import MockNATS
from native_security.nats_credentials import validate_service
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.history import OwnerHistory

import installed_service_enrollment as setup
from installed_storage_enrollment import StoragePreparation, STORAGE_RETENTION


class InstalledServiceEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.directory = root / 'enrollment'
        self.directory.mkdir(mode=0o700)
        self.workspace = root / 'workspace'
        self.workspace.mkdir(mode=0o700)
        self.scope = {'hubId': 'fixture_hub', 'instanceId': 'fixture_instance', 'profileId': 'fixture_profile',
            'assemblyDigest': 'sha256:' + 'a'*64, 'releaseManifestDigest': 'sha256:' + 'b'*64, 'releaseVersion': '1.0.0'}
        # This is only the private host-input comparison for the offline check.
        # The installed test independently performs full native host admission.
        self.policy = {'ownerUid': os.getuid(), 'instanceId': self.scope['instanceId'], 'profileId': self.scope['profileId'],
            'owner': {'authenticatedIdentityRef': {'ownerHubId': self.scope['hubId']}, 'scope': {'organizationId': 'fixture_org'}},
            'release': {k: self.scope[k] for k in ('releaseManifestDigest', 'releaseVersion')},
            'publicEndpoint': 'tls://127.0.0.1:4222'}
        path = root / 'host.json'
        raw = canonical_bytes(self.policy)
        path.write_bytes(raw)
        path.chmod(0o600)
        account = nkeys.from_seed(nkeys.encode_seed(os.urandom(32), nkeys.PREFIX_BYTE_ACCOUNT))
        try:
            seed = account.seed.decode()
        finally:
            account.wipe()
        self.plan = {'schemaVersion': '1.0.0', 'directory': str(self.directory),
            'host': {'hostPolicy': str(path), 'hostPolicySHA256': setup.digest(raw),
                'kernelScope': self.scope, 'workspaces': [str(self.workspace)], 'installationId': 'c'*64},
            'broker': {'endpoint': 'tls://127.0.0.1:4223',
                'rootsPEM': ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0]),
                'serverName': 'localhost', 'domain': 'fixture_domain', 'leafPin': 'sha256:'+'d'*64, 'accountSeed': seed}}

    def storage_plan(self):
        pin = {'packageId': 'installed_storage_package', 'version': '1.0.0',
               'manifestChecksum': 'sha256:' + '1'*64, 'packageChecksum': 'sha256:' + '2'*64,
               'provenanceChecksum': 'sha256:' + '3'*64}
        package = {'schemaVersion': '1.0.0', 'owner': {'pin': pin,
            'instanceId': 'installed_storage_plugin', 'epoch': '4'*64, 'generation': 1},
            'manifestDigest': pin['manifestChecksum'], 'configurationChecksum': 'sha256:' + '5'*64,
            'schemaRef': 'schemas/config.json', 'schemaBytes': base64.b64encode(b'{"type":"object"}').decode()}
        return {**self.plan, 'scenario': setup.STORAGE_SCENARIO, 'nativePackage': package}

    def test_real_keys_exact_service_permissions_and_bootstrap_possession(self):
        directory, policy = setup.admit_plan(self.plan)
        owner = setup.Preparation(self.plan, directory, policy)
        self.addCleanup(lambda: owner.account.wipe() if owner.account is not None else None)
        now = datetime.now(timezone.utc)
        owner.materials(now)
        users = set()
        for role in setup.ROLES:
            service = owner.value[role]
            options = dict(role=role, hub_id=self.scope['hubId'], entity_id=service['ledger']['entityId'],
                scope=service['ledger']['scope'], stream=service['ledger']['stream'],
                reply_prefix=service['credentials']['replyPrefix'], jetstream_domain=self.plan['broker']['domain'])
            if role != 'identity':
                options['artifact_bucket'] = 'installed_artifacts'
            raw = _read_material(service['credentials']['path'], max_bytes=65536, return_bytes=True)
            credential = validate_service(raw, account_public_key=owner.account.public_key.decode(), **options)
            self.assertEqual(service['credentials']['sha256'], setup.digest(raw))
            self.assertEqual(service['credentials']['userPublicKey'], credential.public_key)
            users.add(credential.public_key)
            self.assertNotIn('streamIdentity', service['ledger'])
        users.update((owner.client_credentials['userPublicKey'], owner.attestor_credentials['userPublicKey']))
        self.assertEqual(len(users), 5)
        self.assertNotIn('integrationEffectQuery', load_application_client(owner.client_key).selection)
        self.assertEqual(owner.value['integration']['provider'], 'github')
        self.assertIsNone(owner.value['integration']['credentialEnrollment'])
        self.assertEqual({g['contractId'] for g in setup.strict_loads(owner.permit.record)['state']['grants']},
                         {'application-bind', 'application-attest'})
        binding = OwnerBinding(self.scope['hubId'], 'identity', owner.authority, 'identity-authority',
                               canonical_bytes(owner.org_scope))
        # _verify checks possession and permit expiry without using JetStream.
        # This object has no broker implementation and cannot perform enrollment.
        ledger = OwnerLedger(object(), stream='INSTALLED_IDENTITY', subject=owner_subject(binding), binding=binding,
            retention=setup.RETENTION, stream_identity=StreamIdentity(now, 0))
        bootstrap = BootstrapOwner(ledger, owner.permit)
        record, _ = bootstrap._verify(owner.proofs)
        self.assertEqual(record['entityVersion'], 1)
        self.assertEqual(len(owner.proofs), 6)
        changed = [dict(proof) for proof in owner.proofs]
        changed[0]['proof'] = 'A'*86
        with self.assertRaises(ContractError):
            bootstrap._verify(changed)
        with self.assertRaises(ContractError):
            bootstrap._verify(owner.proofs[:-1])

    def test_operator_keeps_current_required_authority_switch_header(self):
        from installed_operator_enrollment import OperatorPreparation
        from identity.application_service_selection import ApplicationServiceSelection
        directory, policy = setup.admit_plan(self.plan)
        owner = OperatorPreparation(self.plan, directory, policy)
        self.addCleanup(lambda: owner.account.wipe() if owner.account is not None else None)
        now = datetime.now(timezone.utc)
        owner.materials(now)
        self.assertIn('authoritySwitch', owner.value)
        for role in setup.ROLES:
            owner.value[role]['ledger']['streamIdentity'] = {
                'created': setup.stamp(now), 'minimumSequence': 0}
        ApplicationServiceSelection(canonical_bytes(owner.value))

    def test_storage_preparation_requires_its_distinct_closed_scenario(self):
        plan = self.storage_plan()
        with self.assertRaises(ContractError):
            setup.admit_plan(plan)
        self.assertEqual(setup.admit_storage_plan(plan), setup.admit_plan(self.plan))
        for changed in (self.plan, {**plan, 'scenario': 'cold-mcp'},
                        {**plan, 'scenario': {'name': setup.STORAGE_SCENARIO}},
                        {**plan, 'credentials': 'ambient'}):
            with self.subTest(fields=set(changed)), self.assertRaises(ContractError):
                setup.admit_storage_plan(changed)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_storage_package_binding_refuses_substitution_and_malformed_schema(self):
        for field, value in (('manifestDigest', 'sha256:'+'9'*64),
                             ('schemaRef', '../schema.json'), ('schemaBytes', 'not-base64'),
                             ('configurationChecksum', 'unpinned')):
            plan = self.storage_plan()
            plan['nativePackage'][field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                setup.admit_storage_plan(plan)
        for field, value in (('generation', 0), ('instanceId', 'other_instance')):
            plan = self.storage_plan()
            plan['nativePackage']['owner'][field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                setup.admit_storage_plan(plan)

    def test_storage_materials_use_separate_credentials_and_proven_phase_key(self):
        from identity.application_service_selection import ApplicationServiceSelection
        directory, policy = setup.admit_storage_plan(self.storage_plan())
        owner = StoragePreparation(self.storage_plan(), directory, policy)
        self.addCleanup(lambda: owner.account.wipe() if owner.account is not None else None)
        now = datetime.now(timezone.utc)
        owner.materials(now)
        binding = OwnerBinding(self.scope['hubId'], 'identity', owner.authority, 'identity-authority',
                               canonical_bytes(owner.org_scope))
        ledger = OwnerLedger(object(), stream='INSTALLED_IDENTITY', subject=owner_subject(binding),
            binding=binding, retention=setup.RETENTION, stream_identity=StreamIdentity(now, 0))
        initial, _ = BootstrapOwner(ledger, owner.permit)._verify(owner.proofs)
        self.assertEqual(len(owner.proofs), 14)
        self.assertEqual(owner.value['configuration']['owner'], self.storage_plan()['nativePackage']['owner'])
        self.assertEqual(initial['state'].get('nativeInstances', []), [])
        plugin = owner.value['storage']['privateStorage']['pluginIdentityRef']
        self.assertTrue(any(identity['ref'] == plugin and identity['kind'] == 'plugin'
                            for identity in initial['state']['identities']))
        phase = owner.value['storage']['board']['phaseAuthority']
        self.assertEqual(sum(grant['callerRef'] == phase['serviceIdentityRef']
                             for grant in initial['state']['grants']), 4)
        users, inboxes = set(), set()
        storage = owner.value['storage']
        descriptors = [*storage['receivers'].values(), storage['privateStorage']['publisher'],
                       storage['board']['cardPublisher'], storage['board']['allocationPublisher']]
        for descriptor in descriptors:
            users.add(descriptor['credentials']['userPublicKey'])
            inboxes.add(descriptor['credentials']['replyPrefix'])
        self.assertEqual(len(users), 5)
        self.assertEqual(len(inboxes), 5)
        self.assertFalse(any(user in users for user in
            (owner.value[role]['credentials']['userPublicKey'] for role in setup.ROLES)))
        self.assertNotIn('bindingDigest', storage['privateStorage'])
        self.assertNotIn('kvStreamIdentity', storage['board'])
        self.assertFalse((directory / 'service-selection.json').exists())
        # No selected source may be emitted before real broker provisioning.
        with self.assertRaises(ContractError):
            ApplicationServiceSelection(canonical_bytes(owner.value))

    def test_storage_provisioning_pins_sources_and_seeds_only_private_namespace(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from identity.application_service_selection import ApplicationServiceSelection
        from capability_owner.private_storage import PrivateStorageResource
        async def check():
            directory, policy = setup.admit_storage_plan(self.storage_plan())
            owner = StoragePreparation(self.storage_plan(), directory, policy)
            self.addCleanup(lambda: owner.account.wipe() if owner.account is not None else None)
            now = datetime.now(timezone.utc)
            owner.materials(now)
            streams = {}
            async def add_stream(config):
                stream = MockNATS(config, now)
                streams[config.name] = stream
                return await stream.stream_info(config.name)
            async def publish(subject, data, **options):
                name = options['headers']['Nats-Expected-Stream']
                self.assertEqual(streams[name].config.subjects, [subject])
                # Reuse the bootstrap mock, whose fixed acknowledgement name
                # is IDENTITY, while checking the selected stream above.
                headers = dict(options['headers'], **{'Nats-Expected-Stream': 'IDENTITY'})
                result = await streams[name].publish(subject, data, headers=headers)
                result.stream = name
                return result
            async def stream_info(name):
                if name == 'KV_am_board':
                    return SimpleNamespace(created=now)
                return await streams[name].stream_info(name)
            async def get_msg(name, **options):
                return await streams[name].get_msg(name, **options)
            kv = SimpleNamespace(create=AsyncMock(side_effect=[1, 2]))
            js = SimpleNamespace(add_stream=add_stream, publish=publish, get_msg=get_msg,
                create_key_value=AsyncMock(return_value=kv),
                stream_info=stream_info)
            await owner.provision_selected_resources(js)
            for role in setup.ROLES:
                owner.value[role]['ledger']['streamIdentity'] = {'created': setup.stamp(now), 'minimumSequence': 0}
            selected = ApplicationServiceSelection(canonical_bytes(owner.value))
            for name in ('storage', 'outcome', 'private', 'card', 'allocation'):
                selected.load_storage_credentials(name)
            validate_service(selected.read_credential_bytes('configuration'),
                account_public_key=owner.account.public_key.decode(),
                **selected.service_policy_inputs('configuration'))
            private = selected.policy['storage']['privateStorage']
            binding = OwnerBinding(self.scope['hubId'], 'plugin-private', private['ledger']['entityId'],
                                   'plugin-storage', canonical_bytes(owner.project_scope))
            ledger = OwnerLedger(streams['INSTALLED_STORAGE_PRIVATE'], stream='INSTALLED_STORAGE_PRIVATE',
                subject=owner_subject(binding), binding=binding, retention=STORAGE_RETENTION,
                stream_identity=StreamIdentity(now, 0), require_completion_budget=True)
            resource = PrivateStorageResource(binding, ledger, canonical_bytes(private['pluginIdentityRef']),
                private['instanceId'], private['packageId'], self.plan['broker']['domain'])
            self.assertEqual(resource.binding_digest, private['bindingDigest'])
            # The seed, first write and conflict precede the required later write.
            # Admission charges full records, even when their JSON is small.
            after_conflict = SimpleNamespace(state=SimpleNamespace(messages=3))
            with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
                setup.RETENTION.admit(after_conflict, 1024, 'bulk', completion_records=0)
            STORAGE_RETENTION.admit(after_conflict, 1024, 'bulk', completion_records=0)
            for name in ('PRIVATE', 'CARD', 'ALLOCATION'):
                self.assertEqual(streams['INSTALLED_STORAGE_' + name].config.max_bytes,
                                 STORAGE_RETENTION.max_bytes)
            self.assertEqual(owner.value['identity']['ledger']['retention']['maxBytes'],
                             setup.RETENTION.max_bytes)
            self.assertEqual(setup.strict_loads(await resource.read(1)), {'retained': True})
            self.assertEqual(len(streams['INSTALLED_STORAGE_PRIVATE'].messages), 1)
            self.assertEqual(len(streams['INSTALLED_STORAGE_CARD'].messages), 0)
            self.assertEqual(len(streams['INSTALLED_STORAGE_ALLOCATION'].messages), 0)
            self.assertEqual(len(streams['INSTALLED_STORAGE_CONFIGURATION'].messages), 0)
            self.assertEqual(selected.policy['storage']['board']['resourceRef']['revision'], 2)
            self.assertFalse((directory / 'service-selection.json').exists())
            result = owner.write_selections(selected, 1)
            contract = result['contractMaterial']
            raw = _read_material(contract['path'], max_bytes=16384, return_bytes=True)
            self.assertEqual(setup.digest(raw), contract['sha256'])
            material = setup.strict_loads(raw)
            self.assertEqual(material['instanceId'], private['instanceId'])
            self.assertEqual(material['packageId'], private['packageId'])
            self.assertEqual(material['serviceSelection']['sha256'], setup.digest(canonical_bytes(selected.policy)))
            self.assertNotIn('owner', material)
            self.assertNotIn('nativeInstances', material)
            for signer in material['nativeSigners'].values():
                seed = _read_material(signer['keyFile']['path'], max_bytes=32, return_bytes=True)
                self.assertEqual(setup.digest(seed), signer['keyFile']['sha256'])
            from unittest.mock import patch
            from dashboard.test_application_service_host import Client
            from installed_storage_operation import OperationAdmission
            identity_binding = selected.binding('identity')
            identity_js = MockNATS(setup.RETENTION.stream_config(stream='INSTALLED_IDENTITY',
                subject=owner_subject(identity_binding)), now)
            identity_js.messages = [SimpleNamespace(subject=owner_subject(identity_binding), seq=1,
                                                    data=owner.permit.record)]
            request = {'contractMaterial': contract, 'provider': 'private',
                'contractId': 'capability-storage-write', 'operationId': 'installed_private_write',
                'expectedVersion': 1, 'resourceRef': {'id': binding.entity_id,
                    'ownerHubId': binding.hub_id, 'revision': 1}, 'input': {'value': {'updated': True}}}
            admission = OperationAdmission(request)
            client = Client(identity_js)
            with patch('installed_storage_operation.new_client', return_value=client):
                try:
                    envelope = setup.strict_loads(await admission.admit())
                finally:
                    client.options['closed_cb'] = AsyncMock()
                    await client.close()
            self.assertEqual(envelope['operation']['operationId'], request['operationId'])
            self.assertEqual(envelope['operation']['caller']['authenticatedIdentityRef'], owner.ref('storage_user'))
            self.assertEqual(envelope['payload'], {'resourceRef': request['resourceRef'], 'input': request['input']})
            self.assertEqual(identity_js.publish_count, 0)
            self.assertEqual(len(streams['INSTALLED_STORAGE_PRIVATE'].messages), 1)
            current = setup.strict_loads(identity_js.messages[0].data)
            for grant in current['state']['grants']:
                if grant['ref'] == material['operationGrants']['private']['capability-storage-write']:
                    grant['decision'] = 'denied'
            identity_js.messages[0].data = canonical_bytes(current)
            refused = OperationAdmission(request)
            client = Client(identity_js)
            with patch('installed_storage_operation.new_client', return_value=client):
                try:
                    with self.assertRaisesRegex(ContractError, '^installed_storage_operation_refused$'):
                        await refused.admit()
                finally:
                    client.options['closed_cb'] = AsyncMock()
                    await client.close()
            self.assertEqual(identity_js.publish_count, 0)
            self.assertEqual(len(streams['INSTALLED_STORAGE_PRIVATE'].messages), 1)
        asyncio.run(check())

    def test_occupied_or_changed_host_inputs_are_refused_before_key_creation(self):
        self.plan['host']['hostPolicySHA256'] = 'sha256:'+'0'*64
        with self.assertRaises(ContractError):
            setup.admit_plan(self.plan)
        self.assertEqual(list(self.directory.iterdir()), [])
        (self.directory / 'occupied').write_text('retained')
        with self.assertRaises(ContractError):
            setup.admit_plan(self.plan)
        self.assertEqual([p.name for p in self.directory.iterdir()], ['occupied'])

    def test_nonlocal_or_unpinned_connection_is_refused_before_creation(self):
        for key, changed in (('endpoint', 'tls://remote.example:4223'), ('endpoint', 'tls://127.0.0.1:65536'),
                ('serverName', '127.0.0.1'), ('leafPin', ''), ('rootsPEM', 'invalid'), ('domain', 'domain.>')):
            original = self.plan['broker'][key]
            self.plan['broker'][key] = changed
            with self.subTest(key=key, changed=changed), self.assertRaises((ContractError, ssl.SSLError)):
                setup.admit_plan(self.plan)
            self.plan['broker'][key] = original
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_reporting_failure_enters_hold_before_unwinding(self):
        retained = object()
        failure = setup.PreparationFailure(retained, ValueError('private cause'))
        events = []
        class StopControlledHold(BaseException):
            pass
        def report():
            events.append('report')
            raise BrokenPipeError('controlled stderr failure')
        async def hold():
            events.append(failure.owner)
            raise StopControlledHold()
        with self.assertRaises(StopControlledHold):
            asyncio.run(setup.hold_before_reporting(report, hold))
        self.assertEqual(events, ['report', retained])

    def test_confirmed_bootstrap_floor_refuses_same_stream_rollback(self):
        async def check():
            directory, policy = setup.admit_plan(self.plan)
            owner = setup.Preparation(self.plan, directory, policy)
            self.addCleanup(lambda: owner.account.wipe())
            now = datetime.now(timezone.utc)
            owner.materials(now)
            binding = OwnerBinding(self.scope['hubId'], 'identity', owner.authority, 'identity-authority',
                                   canonical_bytes(owner.org_scope))
            subject = owner_subject(binding)
            # Reuse the existing offline broker response control. These stream
            # timestamps are test inputs and never installed enrollment evidence.
            js = MockNATS(setup.RETENTION.stream_config(stream='IDENTITY', subject=subject), now)
            ledger = OwnerLedger(js, stream='IDENTITY', subject=subject, binding=binding,
                retention=setup.RETENTION, stream_identity=StreamIdentity(now, 0))
            owner.bootstrap = BootstrapOwner(ledger, owner.permit)
            receipt = await owner.bootstrap.execute(owner.proofs)
            self.assertEqual(receipt.sequence, 1)
            for role in setup.ROLES:
                owner.value[role]['ledger']['streamIdentity'] = {'created': setup.stamp(now), 'minimumSequence': 0}
            selected = owner.confirmed_selection(receipt)
            identity = selected.stream_identity('identity')
            self.assertEqual(identity.minimum_sequence, receipt.sequence)
            js.messages.clear()
            history = OwnerHistory(selected.service('identity')['ledger']['history']['path'],
                                   binding, stream_identity=identity)
            try:
                fresh = OwnerLedger(js, stream='IDENTITY', subject=subject, binding=binding,
                    retention=setup.RETENTION, stream_identity=identity, history=history)
                with self.assertRaisesRegex(ContractError, 'owner_recovery_required'):
                    await fresh.prepare_history()
            finally:
                history.close()
        asyncio.run(check())


if __name__ == '__main__':
    unittest.main()
