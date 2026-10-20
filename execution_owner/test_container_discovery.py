"""Recover a retained original when no physical ID reached its owner."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from agentmux_contracts import ContractError, strict_loads

from . import test_container as support
from .container import TaskContainerAdapter


class ContainerDiscoveryTests(support.ContainerTests):
    def recovery_owner(self):
        owner = TaskContainerAdapter(self.plans, self.engine, self.host,
            workspace_ref=self.profile['workspaceRef'], network=self.adapter._network)
        self.addAsyncCleanup(owner.close)
        return owner

    async def lost_create(self):
        admission, intent = await self.authorized()

        async def lose_reply(args, **kwargs):
            result = await self.command(args, **kwargs)
            if args[0] == 'create':
                raise ContractError('execution_engine_command_unknown')
            return result

        self.engine._run.side_effect = lose_reply
        with self.assertRaisesRegex(ContractError, '^execution_engine_command_unknown$'):
            await self.adapter.prepare(admission, task_inspection=self.inspection(), intent=intent)
        self.assertIsNone(next(iter(self.adapter._runs.values()))['id'])
        original = await self.adapter.checkpoint()
        self.assertEqual(len(original), 1)
        self.assertIsNone(original[0].resource_ref)
        await self.adapter.close()
        self.assertFalse(self.adapter._jobs)
        self.assertFalse(self.engine._jobs)
        self.engine._run.side_effect = self.command
        return admission, intent

    async def test_original_id_discovery_after_lost_create_and_expiry(self):
        admission, intent = await self.lost_create()
        owner = self.recovery_owner()
        retained = tuple(message.data for message in self.intent_js.messages)
        expired = admission.valid_until + timedelta(seconds=1)

        class Expired(datetime):
            @classmethod
            def now(cls, tz=None):
                return expired.astimezone(tz or timezone.utc)

        with patch('execution_owner.plans.datetime', Expired):
            with self.assertRaisesRegex(ContractError, '^execution_admission_expired$'):
                await admission.recheck(self.inspection())
            observed = await owner.recover(intent)
        self.assertEqual(observed.status, 'pending')
        self.assertEqual(strict_loads(observed.resource_ref)['containerId'], 'c' * 64)
        self.assertEqual(tuple(message.data for message in self.intent_js.messages), retained)
        self.assertEqual(self.commands, ['create'])
        self.engine.exec_fixed.assert_not_awaited()
        reference = strict_loads(observed.run_ref)
        with self.assertRaisesRegex(ContractError, '^execution_container_unknown$'):
            await owner.start(reference, admission, task_inspection=self.inspection(), intent=intent)
        self.assertEqual((await owner.stop(reference)).status, 'terminal')
        await owner.cleanup(reference)
        self.assertEqual(self.commands, ['create', 'stop', 'rm'])
        self.assertFalse(owner._jobs)

    async def test_original_id_absence_does_not_claim_or_create_resource(self):
        _, intent = await self.authorized()
        await self.adapter.checkpoint()
        owner = self.recovery_owner()
        observed = await owner.recover(intent)
        self.assertEqual(observed.status, 'unknown')
        self.assertIsNone(observed.resource_ref)
        self.assertFalse(owner._runs)
        with self.assertRaisesRegex(ContractError, '^execution_container_unknown$'):
            await owner.stop(strict_loads(observed.run_ref))
        self.assertFalse(self.commands)
        self.engine.exec_fixed.assert_not_awaited()

    async def test_original_id_malformed_or_foreign_projection_is_not_owned(self):
        _, intent = await self.lost_create()
        original = copy.deepcopy(self.observed)
        mutations = (
            lambda x: x.update(Id=None),
            lambda x: x.update(Name='/another-task'),
            lambda x: x.update(Image='sha256:' + 'd' * 64),
            lambda x: x.update(Config=None),
            lambda x: x['Config']['Labels'].update({'agentmux.task.binding': 'foreign'}),
            lambda x: x['HostConfig'].update(Privileged=True),
            lambda x: x['Mounts'].append({'Type': 'bind', 'Source': '/other',
                'Destination': '/other', 'RW': True}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                self.observed = copy.deepcopy(original)
                mutate(self.observed)
                owner = self.recovery_owner()
                with self.assertRaises(ContractError):
                    await owner.recover(intent)
                self.assertFalse(owner._runs)
                self.assertEqual(self.commands, ['create'])
        self.observed = original
        owner = self.recovery_owner()
        observed = await owner.recover(intent)
        reference = strict_loads(observed.run_ref)
        await owner.stop(reference)
        await owner.cleanup(reference)

    async def test_original_id_is_frozen_before_later_observation_and_stop(self):
        _, intent = await self.lost_create()
        owner = self.recovery_owner()
        observed = await owner.recover(intent)
        reference = strict_loads(observed.run_ref)
        original = copy.deepcopy(self.observed)
        self.observed['Id'] = 'd' * 64
        uncertain = await owner.observe(reference)
        self.assertEqual(uncertain.status, 'unknown')
        self.assertEqual(uncertain.resource_ref, observed.resource_ref)
        with self.assertRaises(ContractError):
            await owner.stop(reference)
        with self.assertRaises(ContractError):
            await owner.cleanup(reference)
        self.assertEqual(self.commands, ['create'])
        self.observed = original
        await owner.stop(reference)
        await owner.cleanup(reference)

    async def test_original_id_discovery_does_not_replace_existing_owner(self):
        admission, intent = await self.authorized()
        await self.adapter.prepare(admission, task_inspection=self.inspection(), intent=intent)
        run = next(iter(self.adapter._runs.values()))
        release = asyncio.Event()
        reader = asyncio.create_task(release.wait(), name='original-discovery-reader')
        run['relay_task'] = reader
        try:
            with self.assertRaisesRegex(ContractError, '^execution_recovery_already_owned$'):
                await self.adapter.recover(intent)
            self.assertIs(next(iter(self.adapter._runs.values())), run)
            self.assertIs(run['relay_task'], reader)
            self.assertFalse(reader.done())
        finally:
            release.set()
            await reader
            run['relay_task'] = None


for _name in dir(support.ContainerTests):
    if _name.startswith('test_') and _name not in vars(ContainerDiscoveryTests):
        setattr(ContainerDiscoveryTests, _name, None)
