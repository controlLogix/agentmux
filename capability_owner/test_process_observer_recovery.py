"""Lost Process observers leave the original owner and generation intact."""
import asyncio
from contextlib import asynccontextmanager

from agentmux_contracts import ContractError, strict_loads
from identity.test_authority import ref
from .test_process_resource import ProcessResourceTests as StableProcessResourceTests


class ProcessObserverRecoveryTests(StableProcessResourceTests):
    @asynccontextmanager
    async def held_start(self):
        case = await self.resource_case()
        entered, release = asyncio.Event(), asyncio.Event()
        prepare = self.credentials.prepare
        calls = []
        task_records = tuple(item.data for item in self.task_js.messages)

        async def held(*args, **kwargs):
            calls.append(args[0])
            result = await prepare(*args, **kwargs)
            entered.set()
            await release.wait()
            return result

        self.credentials.prepare = held
        observer = asyncio.create_task(self.receive(case['raw'], case['wrapper']))
        signal = asyncio.create_task(entered.wait())
        try:
            done, _ = await asyncio.wait((observer, signal), timeout=10,
                return_when=asyncio.FIRST_COMPLETED)
            if signal not in done:
                if observer in done:
                    await observer
                self.fail('The original Start did not reach credential preparation')
            self.assertFalse(observer.done())
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(self.execution_js.messages), 1)
            self.assertEqual(len(self.credential_js.messages), 1)
            owner = self.resource._admission._owner
            self.assertEqual(len(owner._jobs), 1)
            first = self.execution_js.messages[0].data
            generation = self.credential_js.messages[0].data
            state = strict_loads(first)['state']
            self.assertEqual(state['originalEnvelope'], strict_loads(case['raw']))
            self.assertEqual(state['executionBinding'], self.run)
            self.assertEqual(state['step'], 'credential-prepare-intent')
            self.assertEqual(state['executionPhase'], 'start-intent')
            yield {
                'case': case, 'release': release, 'observer': observer,
                'owner': owner, 'calls': calls, 'first': first,
                'generation': generation, 'task_records': task_records,
                'receiver_workers': tuple(self.receiver._workers),
                'resource_workers': tuple(self.resource._workers),
                'owner_jobs': tuple(owner._jobs),
            }
        finally:
            release.set()
            signal.cancel()
            tasks = {observer, signal, *self.receiver._workers, *self.resource._workers}
            owner = self.resource._admission._owner
            if owner is not None:
                tasks.update(owner._jobs)
            await asyncio.gather(*tasks, return_exceptions=True)
            self.credentials.prepare = prepare

    async def join_original(self, held):
        held['release'].set()
        tasks = {*held['receiver_workers'], *held['resource_workers'], *held['owner_jobs']}
        _, pending = await asyncio.wait(tasks, timeout=10)
        self.assertFalse(pending, 'The original owner did not join after release')
        self.assertTrue(all(not task.cancelled() for task in tasks))
        # An expired original observer may be refused after the retained write.
        # The fresh, authorized query below must still recover that exact write.
        await asyncio.gather(*tasks, return_exceptions=True)

    def assert_original_retained(self, held):
        self.assertEqual(len(held['calls']), 1)
        self.assertEqual(len(self.execution_js.messages), 2)
        self.assertEqual(self.execution_js.messages[0].data, held['first'])
        self.assertEqual(len(self.credential_js.messages), 1)
        self.assertEqual(self.credential_js.messages[0].data, held['generation'])
        state = strict_loads(self.execution_js.messages[-1].data)['state']
        self.assertEqual(state['originalEnvelope'], strict_loads(held['case']['raw']))
        self.assertEqual(state['executionBinding'], self.run)
        self.assertEqual(state['executionPhase'], 'start-intent')
        self.assertEqual(state['step'], 'pending-enrollment')
        self.assertEqual(tuple(item.data for item in self.task_js.messages), held['task_records'])
        self.assertEqual(self.commands, [])
        self.assertEqual(self.engine.exec_fixed.await_count, 0)
        self.assertFalse(held['owner']._jobs)
        self.assertFalse(self.resource._workers)
        self.assertFalse(self.receiver._workers)

    async def recover_original(self, held):
        operation = strict_loads(held['case']['raw'])['operation']
        first = strict_loads(held['first'])
        raw, wrapper = await self.packet(held['case'], 'capability-outcome-query', {
            'resourceRef': ref('executor'),
            'input': {'contractId': 'capability-process-start',
                'operationId': operation['operationId'],
                'payloadDigest': operation['payloadDigest']},
        }, 'recover-lost-start')
        recovered = await self.receive(raw, wrapper)
        self.assertEqual(recovered, {
            'operationId': operation['operationId'],
            'payloadDigest': operation['payloadDigest'],
            'recordRef': {'id': first['entityId'],
                'ownerHubId': first['ownerHubId'], 'revision': first['entityVersion']},
            'outcome': 'committed',
        })
        self.assert_original_retained(held)

    async def test_cancelled_observer_recovers_original_without_another_start(self):
        async with self.held_start() as held:
            held['observer'].cancel()
            with self.assertRaises(asyncio.CancelledError):
                await held['observer']
            self.assertTrue(all(not task.done() for task in held['owner_jobs']))
            self.assertEqual(self.execution_js.messages[0].data, held['first'])
            await self.join_original(held)
            await self.recover_original(held)

    async def test_receiver_timeout_recovers_original_without_another_start(self):
        async with self.held_start() as held:
            # Use the receiver's real five-second limit; do not change its clock
            # or the production native delivery proof's five-second lifetime.
            with self.assertRaisesRegex(ContractError, '^capability_owner_unavailable$'):
                await asyncio.wait_for(asyncio.shield(held['observer']), timeout=7)
            self.assertTrue(all(not task.done() for task in held['owner_jobs']))
            self.assertEqual(self.execution_js.messages[0].data, held['first'])
            await self.join_original(held)
            await self.recover_original(held)

    async def test_resource_close_joins_original_without_stopping_or_releasing_task(self):
        async with self.held_start() as held:
            closing = asyncio.create_task(self.resource.close())
            try:
                done, _ = await asyncio.wait((closing,), timeout=0.05)
                self.assertFalse(done, 'Close returned while the original was held')
                self.assertTrue(self.resource._closed)
                self.assertEqual(self.execution_js.messages[0].data, held['first'])
                held['release'].set()
                await asyncio.wait_for(asyncio.shield(closing), timeout=10)
                await asyncio.gather(held['observer'], *held['receiver_workers'],
                    return_exceptions=True)
                self.assert_original_retained(held)
                self.assertTrue(held['owner']._closed)
                self.assertTrue(self.resource._admission._closed)
            finally:
                held['release'].set()
                await asyncio.gather(closing, return_exceptions=True)


for _name in dir(StableProcessResourceTests):
    if _name.startswith('test_') and _name not in vars(ProcessObserverRecoveryTests):
        setattr(ProcessObserverRecoveryTests, _name, None)
