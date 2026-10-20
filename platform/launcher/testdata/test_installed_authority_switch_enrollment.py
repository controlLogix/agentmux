"""Offline checks for the distinct installed signed-recovery fixture."""
import copy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.store import Store
from identity.application_client import load_application_client
from identity.application_service_selection import ApplicationServiceSelection
from native_security.nats_credentials import validate_authority_switch_receiver
from state_owner.ledger import OwnerBinding, owner_subject
from state_owner.test_ledger import CREATED
from identity.test_bootstrap import MockNATS

import installed_service_enrollment as base
from installed_authority_switch_enrollment import AuthoritySwitchPreparation
import test_installed_service_enrollment as base_tests


class InstalledAuthoritySwitchEnrollmentTests(unittest.TestCase):
    setUp = base_tests.InstalledServiceEnrollmentTests.setUp

    def recovery_plan(self):
        return {**copy.deepcopy(self.plan),
                'scenario': base.AUTHORITY_SWITCH_SCENARIO}

    def test_recovery_scenario_is_closed_and_baseline_refuses_it(self):
        plan = self.recovery_plan()
        with self.assertRaises(ContractError):
            base.admit_plan(plan)
        self.assertEqual(base.admit_authority_switch_plan(plan),
                         base.admit_plan(self.plan))
        nested = self.directory / 'nested'
        nested.mkdir(mode=0o700)
        for changed in (self.plan,
                {**plan, 'scenario': 'other-recovery'},
                {**plan, 'authoritySwitch': {}},
                {**plan, 'scenario': {'name': base.AUTHORITY_SWITCH_SCENARIO}},
                {**plan, 'directory': str(nested)}):
            with self.subTest(fields=set(changed)), self.assertRaises(ContractError):
                base.admit_authority_switch_plan(changed)

    def test_materials_bind_real_fenced_store_exact_service_and_client_route(self):
        plan = self.recovery_plan()
        directory, policy = base.admit_authority_switch_plan(plan)
        owner = AuthoritySwitchPreparation(plan, directory, policy)
        self.addCleanup(lambda: owner.account.wipe()
                        if owner.account is not None else None)
        custody = Path(plan['host']['hostPolicy']).parent / 'authority-switch'
        self.assertFalse(custody.exists())
        owner.materials(datetime.now(timezone.utc))
        binding = owner.value['authoritySwitch']['binding']
        self.assertEqual(Path(owner.value['authoritySwitch']['custodyDirectory']),
                         custody)
        self.assertTrue(custody.is_dir())
        self.assertEqual(custody.stat().st_mode & 0o777, 0o700)
        self.assertEqual(binding['source'], owner.source)
        self.assertEqual(binding['switchId'], owner.switch_id)
        store = Store(str(owner.legacy_database))
        try:
            fence = store.migration_fence_status()
        finally:
            store.db.close()
        self.assertEqual((fence['fenceId'], fence['generation'], fence['state']),
            (owner.source['fenceId'], owner.source['fenceGeneration'], 'fenced'))
        receiver, ledger = binding['receiver'], binding['ledger']
        raw = Path(receiver['credentials']['path']).read_bytes()
        admitted = validate_authority_switch_receiver(raw,
            account_public_key=owner.account.public_key.decode(),
            hub_id=self.scope['hubId'], entity_id=owner.switch_id,
            scope=owner.org_scope, stream=ledger['stream'],
            reply_prefix=receiver['credentials']['replyPrefix'],
            jetstream_domain=plan['broker']['domain'])
        self.assertEqual(admitted.public_key,
                         receiver['credentials']['userPublicKey'])
        key = load_application_client(owner.client_key)
        route = key.selection['authoritySwitchRecovery']
        self.assertEqual((route['switchId'], route['source']),
                         (owner.switch_id, owner.source))
        self.assertNotEqual(route['replyIssuerRef'], key.selection['replyIssuerRef'])
        state = strict_loads(owner.permit.record)['state']
        grants = [item for item in state['grants']
                  if item['contractId'] == 'authority-switch']
        self.assertEqual(len(grants), 1)
        self.assertEqual((grants[0]['resourceId'], grants[0]['scope']),
                         (owner.switch_id, owner.org_scope))
        self.assertTrue(any(item['ref'] == route['transportRef']
                            for item in state['transports']))
        self.assertTrue(any(item['ref'] == route['serviceIdentityRef']
                            for item in state['identities']))

    def test_switch_stream_provisioning_rewrites_only_the_pinned_creation(self):
        async def check():
            plan = self.recovery_plan()
            directory, policy = base.admit_authority_switch_plan(plan)
            owner = AuthoritySwitchPreparation(plan, directory, policy)
            self.addCleanup(lambda: owner.account.wipe()
                            if owner.account is not None else None)
            owner.materials(datetime.now(timezone.utc))
            before = load_application_client(owner.client_key).selection
            binding = owner.value['authoritySwitch']['binding']
            expected_binding = OwnerBinding(self.scope['hubId'], 'authority-switch',
                owner.switch_id, 'authority-switch', canonical_bytes(owner.org_scope))
            observed = {}

            async def add_stream(config):
                observed['config'] = config
                return SimpleNamespace(created=CREATED,
                    state=SimpleNamespace(messages=0, last_seq=0, first_seq=0,
                                          num_deleted=0, bytes=0), config=config)

            await owner.provision_selected_resources(
                SimpleNamespace(add_stream=add_stream))
            after = load_application_client(owner.client_key).selection
            self.assertEqual(observed['config'].subjects,
                             [owner_subject(expected_binding)])
            self.assertEqual(binding['ledger']['streamIdentity'],
                {'created': base.stamp(CREATED), 'minimumSequence': 0})
            self.assertEqual(after['authoritySwitchRecovery']['streamIdentity'],
                             binding['ledger']['streamIdentity'])
            for role in base.ROLES:
                owner.value[role]['ledger']['streamIdentity'] = {
                    'created': base.stamp(CREATED), 'minimumSequence': 0}
            selected = ApplicationServiceSelection(canonical_bytes(owner.value))
            self.assertEqual(selected.load_authority_switch_signing_seed(),
                __import__('base64').b64decode(
                    strict_loads(Path(binding['receiver']['issuer']['keyFile']['path'])
                                 .read_bytes())['seed']))
            selected.read_authority_switch_credentials()
            changed = copy.deepcopy(after)
            changed['authoritySwitchRecovery']['streamIdentity'] = \
                before['authoritySwitchRecovery']['streamIdentity']
            self.assertEqual(changed, before)

        __import__('asyncio').run(check())

    def test_complete_in_memory_preparation_commits_source_fence_and_closed_material(self):
        async def check():
            plan = self.recovery_plan()
            directory, policy = base.admit_authority_switch_plan(plan)
            owner = AuthoritySwitchPreparation(plan, directory, policy)
            self.addCleanup(lambda: owner.account.wipe()
                            if owner.account is not None else None)
            owner.materials(datetime.now(timezone.utc))

            class Streams:
                def __init__(self):
                    self.values = {}

                async def add_stream(self, config):
                    stream = MockNATS(config, CREATED)
                    self.values[config.name] = stream
                    return await stream.stream_info(config.name)

                async def create_object_store(self, **_options):
                    return SimpleNamespace()

                async def stream_info(self, name):
                    return await self.values[name].stream_info(name)

                async def get_msg(self, name, **options):
                    return await self.values[name].get_msg(name, **options)

                async def publish(self, subject, data, *, headers):
                    name = headers['Nats-Expected-Stream']
                    target = self.values[name]
                    accepted = {'Nats-Expected-Stream': 'IDENTITY',
                        'Nats-Expected-Last-Subject-Sequence':
                            headers['Nats-Expected-Last-Subject-Sequence']}
                    result = await target.publish(subject, data, headers=accepted)
                    result.stream = name
                    return result

            streams = Streams()
            owner.connect = AsyncMock()
            owner.client = SimpleNamespace(
                jetstream=lambda **_options: streams)
            result = await owner.provision()
            self.assertEqual(set(result),
                {'schemaVersion', 'enrollment', 'sha256', 'recoveryMaterial'})
            switch = streams.values['INSTALLED_AUTHORITY_SWITCH']
            self.assertEqual(len(switch.messages), 1)
            record = strict_loads(switch.messages[0].data)
            self.assertEqual((record['entityVersion'], record['state']['phase']),
                             (1, 'source-fenced'))
            selected = ApplicationServiceSelection(
                Path(owner.directory / 'service-selection.json').read_bytes())
            public, guard = selected.authority_switch_configuration()
            self.assertEqual(public['streamIdentity']['minimumSequence'], 1)
            self.assertEqual(public['source'], owner.source)
            self.assertIsNone(guard._owner)
            client = load_application_client(owner.client_key)
            self.assertEqual(
                client.selection['authoritySwitchRecovery']['streamIdentity'],
                public['streamIdentity'])
            material = strict_loads(Path(
                result['recoveryMaterial']['path']).read_bytes())
            self.assertEqual((material['switchId'], material['source']),
                             (owner.switch_id, owner.source))

        __import__('asyncio').run(check())


if __name__ == '__main__':
    unittest.main()
