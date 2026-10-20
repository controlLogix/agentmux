"""Native recovery after create reply loss before a resource ID was retained."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from agentmux_contracts import ContractError, strict_loads

from .container import TaskContainerAdapter
from .docker_engine import DockerEngine, DockerSelection
from .test_container_live import IMAGE, NativeContainerTests


class NativeContainerDiscoveryTests(NativeContainerTests):
    async def test_original_id_native_lost_create_expired_start_and_exact_cleanup(self):
        self.real_engine = DockerEngine(DockerSelection(
            str(Path('/Users/ryan/.docker/bin/docker').resolve()), 'desktop-linux',
            'unix:///Users/ryan/.docker/run/docker.sock',
            'bf61e5bf-20ff-4b43-a588-d6c46ed9e664', '29.8.2',
            str(Path.home() / '.docker'), IMAGE.split('@')[1]))
        host = await self.workspace('projectdiscovery')
        case = await self.case('projectdiscovery', host, None, None,
            b'import time; time.sleep(1)\n')
        old = case['adapter']
        admission, intent = case['admission'], case['intent']
        original = self.real_engine._run
        commands = []
        created_ids = []

        async def lost(args, **kwargs):
            commands.append(args[0])
            result = await original(args, **kwargs)
            if args[0] == 'create':
                created_ids.append(result.decode('ascii').strip())
                raise ContractError('execution_engine_command_unknown')
            return result

        self.real_engine._run = lost
        with self.assertRaisesRegex(ContractError, '^execution_engine_command_unknown$'):
            await old.prepare(admission, task_inspection=await case['inspect'](), intent=intent)
        self.assertEqual(len(created_ids), 1)
        self.assertIsNone(next(iter(old._runs.values()))['id'])
        pending = await old.checkpoint()
        self.assertIsNone(pending[0].resource_ref)
        await old.close()
        self.assertFalse(old._jobs or self.real_engine._jobs)

        async def observe_only(args, **kwargs):
            self.assertNotIn(args[0], ('create', 'start', 'exec'))
            commands.append(args[0])
            return await original(args, **kwargs)

        self.real_engine._run = observe_only
        recovered = TaskContainerAdapter(old._plans, self.real_engine, host,
            workspace_ref=case['profile']['workspaceRef'], network=old._network)
        self.native_adapters.append(recovered)
        self.addAsyncCleanup(recovered.close)
        # Wait for the real original deadline; do not extend or replace authority.
        remaining = (admission.valid_until - datetime.now(timezone.utc)).total_seconds()
        self.assertLessEqual(remaining, 30)
        await asyncio.sleep(max(0, remaining) + .05)
        self.assertGreaterEqual(datetime.now(timezone.utc), admission.valid_until)
        with self.assertRaisesRegex(ContractError, '^execution_admission_expired$'):
            await admission.recheck(b'')
        before = tuple(item.record for item in (await intent._ledger.current()).records)
        observed = await recovered.recover(intent)
        self.assertEqual(observed.status, 'pending')
        resource = strict_loads(observed.resource_ref)
        self.assertEqual(resource['containerId'], created_ids[0])
        self.assertEqual(tuple(item.record for item in (await intent._ledger.current()).records), before)
        run = next(iter(recovered._runs.values()))
        self.assertEqual(run['binding'], intent.binding)
        self.assertEqual(run['spec']['name'], next(iter(old._runs.values()))['spec']['name'])
        # The new verified owner now holds cleanup; the checkpointed owner has
        # joined and no longer owns a physical client or a directory obligation.
        self.native_adapters.remove(old)
        reference = strict_loads(observed.run_ref)
        with self.assertRaisesRegex(ContractError, '^execution_container_unknown$'):
            await recovered.start(reference, admission, task_inspection=b'', intent=intent)
        stopped = await recovered.stop(reference)
        self.assertIn(stopped.status, ('pending', 'terminal'))
        physical = await self.real_engine.inspect(resource['containerId'])
        self.assertIn(physical['State']['Status'], ('created', 'exited', 'dead'))
        self.assertIs(physical['State']['Running'], False)
        self.assertEqual(physical['State']['Pid'], 0)
        await recovered.cleanup(reference)
        self.assertIsNone(await self.real_engine.find(run['spec']['name']))
        self.assertEqual((await recovered.observe(reference)).status, 'terminal')
        self.assertEqual(commands.count('create'), 1)
        self.assertNotIn('start', commands)
        self.assertNotIn('exec', commands)
        self.assertFalse(recovered._jobs or self.real_engine._jobs)
        self.real_engine._run = original


for _name in dir(NativeContainerTests):
    if _name.startswith('test_') and _name not in vars(NativeContainerDiscoveryTests):
        setattr(NativeContainerDiscoveryTests, _name, None)
