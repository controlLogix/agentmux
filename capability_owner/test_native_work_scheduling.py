"""Native caller checks leave signed Work exchanges on their original deadline."""
import asyncio
from datetime import datetime, timedelta, timezone
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agentmux_contracts import ContractError
from hub import server
from identity.test_authority import ref
from .test_hub_work_maintenance import HubWorkMaintenanceTests


class MaintenanceAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_foreground_bypasses_once_then_background_progresses_in_order(self):
        from .work_maintenance import _MaintenanceLock
        lock = _MaintenanceLock()
        order = []
        await lock.acquire()
        async def enter(name, foreground=False):
            await lock.acquire(foreground=foreground)
            try:
                order.append(name)
            finally:
                lock.release()
        tasks = [asyncio.create_task(enter(name, foreground)) for name, foreground in
                 [('background1', False), ('background2', False),
                  ('spawn1', True), ('spawn2', True), ('spawn3', True)]]
        await asyncio.sleep(0)
        self.assertEqual(order, [])
        lock.release()
        await asyncio.gather(*tasks)
        self.assertEqual(order, ['spawn1', 'background1', 'spawn2', 'background2', 'spawn3'])
        self.assertFalse(lock.locked())

    async def test_cancelled_waiter_and_cancelled_grant_do_not_lose_lock(self):
        from .work_maintenance import _MaintenanceLock
        for foreground in (False, True):
            for granted in (False, True):
                lock = _MaintenanceLock()
                await lock.acquire()
                waiting = asyncio.create_task(lock.acquire(foreground=foreground))
                await asyncio.sleep(0)
                if granted:
                    lock.release()
                waiting.cancel()
                if not granted:
                    # Release before the canceled task gets a cleanup turn.
                    lock.release()
                with self.assertRaises(asyncio.CancelledError):
                    await waiting
                await asyncio.wait_for(lock.acquire(), .2)
                lock.release()
                self.assertFalse(lock.locked())


class SpawnPredispatchRecoveryTests(HubWorkMaintenanceTests):
    async def test_proven_predispatch_expiry_replays_terminal_result_without_launch(self):
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)',
            ('falcon', str(self.database.parent / 'checkout'), 'local'))
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'not_launched', 'cli': 'codex'}
        original_begin = self.maintenance.begin_spawn

        async def expire_original():
            request = self.maintenance._requests[asyncio.current_task()]
            remaining = request['expires'] - server.time.monotonic()
            self.assertGreater(remaining, 0)
            result = await original_begin()
            await asyncio.sleep(max(0, request['expires'] - server.time.monotonic()) + .02)
            return result

        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='controlled result', stderr='')) as launch, \
                patch.object(self.hub.tp, 'handle', return_value=('%43', 23458)):
            with patch.object(self.maintenance, 'begin_spawn', side_effect=expire_original):
                with self.assertRaisesRegex(server.HubError, 'expired'):
                    await self.request('spawn', arguments, 'proven-no-launch')
            self.assertEqual(launch.call_count, 0)
            before = await self.hub.db(self.hub.store.agent, 'falcon-worker-not_launched')
            self.assertEqual((before['generation'], before['handle'], before['pane_pid']), (1, None, None))
            original_rows = await self.hub.db(self.hub.store.q,
                "SELECT k,v FROM fed_state WHERE json_extract(v,'$.identity.operationId')=? ORDER BY k",
                ('proven-no-launch',))
            from pathlib import Path
            token_path = Path(server.ROOT) / 'repos/falcon/agents/worker-not_launched/run/token'
            original_token = token_path.read_bytes()
            result = await self.request('spawn', arguments, 'proven-no-launch')
            replay = await self.request('spawn', arguments, 'proven-no-launch')
            self.assertEqual(replay, result)
            self.assertEqual(launch.call_count, 0)
            self.assertEqual(result, {'session': before['session'], 'generation': 1,
                'operationId': 'proven-no-launch', 'outcome': 'not-started',
                'reason': 'original-caller-expired'})
            self.assertEqual(await self.hub.db(self.hub.store.q,
                "SELECT k,v FROM fed_state WHERE json_extract(v,'$.identity.operationId')=? ORDER BY k",
                ('proven-no-launch',)), original_rows)
            self.assertEqual(token_path.read_bytes(), original_token)
        after = await self.hub.db(self.hub.store.agent, result['session'])
        self.assertEqual((after['generation'], after['handle'], after['pane_pid']), (1, None, None))
        self.assertEqual(after, before)
        with patch.object(server.subprocess, 'run') as launch:
            with patch.object(self.hub._work_source_binding, 'check',
                    side_effect=ContractError('work_source_binding_refused')):
                with self.assertRaises(ContractError):
                    await self.request('spawn', arguments, 'proven-no-launch')
            with self.assertRaisesRegex(server.HubError, 'different original request'):
                await self.request('spawn', {**arguments, 'agent': 'other'}, 'proven-no-launch')
            await self.hub.db(self.hub.store.db.execute,
                'UPDATE agents SET generation=generation+1 WHERE session=?', (before['session'],))
            with self.assertRaises(ContractError):
                await self.request('spawn', arguments, 'proven-no-launch')
            await self.hub.db(self.hub.store.db.execute,
                'UPDATE agents SET generation=generation-1 WHERE session=?', (before['session'],))
            from agentmux_contracts import canonical_bytes, strict_loads
            from identity.authority import AuthoritySnapshot
            record = strict_loads(self.snapshot.record)
            grants = strict_loads(self.resources[0]._legacy_actors[0].grants)
            next(g for g in record['state']['grants']
                if g['ref'] == grants['federation-work-register'])['status'] = 'revoked'
            self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
            with self.assertRaises(ContractError):
                await self.request('spawn', arguments, 'proven-no-launch')
            self.assertEqual(launch.call_count, 0)

    async def test_failed_refusal_save_and_unknown_dispatch_remain_uncertain(self):
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)',
            ('falcon', str(self.database.parent / 'checkout'), 'local'))
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'failed_save', 'cli': 'codex'}
        original_begin = self.maintenance.begin_spawn
        async def expire_original():
            result = await original_begin()
            request = self.maintenance._requests[asyncio.current_task()]
            await asyncio.sleep(max(0, request['expires'] - server.time.monotonic()) + .02)
            return result
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(server.subprocess, 'run') as launch:
            with patch.object(self.maintenance, 'begin_spawn', side_effect=expire_original), \
                    patch.object(self.maintenance, '_retain_spawn_refusal', side_effect=OSError('save failed')):
                with self.assertRaises(OSError):
                    await self.request('spawn', arguments, 'failed-refusal-save')
            with self.assertRaisesRegex(server.HubError, 'unconfirmed'):
                await self.request('spawn', arguments, 'failed-refusal-save')
            self.assertEqual(launch.call_count, 0)
            launch.side_effect = OSError('unknown dispatch')
            arguments = {**arguments, 'agent': 'unknown'}
            with self.assertRaises(OSError):
                await self.request('spawn', arguments, 'unknown-dispatch')
            with self.assertRaisesRegex(server.HubError, 'unconfirmed'):
                await self.request('spawn', arguments, 'unknown-dispatch')
            self.assertEqual(launch.call_count, 1)

    async def test_terminal_cli_human_and_json_forms(self):
        import contextlib
        import io
        import json
        from hub import cli
        result = {'session': 'falcon-worker-one', 'generation': 1, 'operationId': 'original',
            'outcome': 'not-started', 'reason': 'original-caller-expired'}
        for suffix in ([], ['--json']):
            output = io.StringIO()
            with patch.object(cli, 'validate_callback', return_value=False), \
                    patch.object(cli, 'call', return_value={'ok': True, 'result': result}) as call, \
                    contextlib.redirect_stdout(output):
                cli.main(['spawn', 'falcon', 'worker', 'one', '--operation-id', 'original', *suffix])
            self.assertEqual(call.call_args.args[1]['operation_id'], 'original')
            if suffix:
                self.assertEqual(json.loads(output.getvalue()), result)
            else:
                self.assertIn('did not start', output.getvalue())
                self.assertNotIn('spawned', output.getvalue())

    async def test_cancelled_original_joins_refusal_save_before_replay(self):
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)',
            ('falcon', str(self.database.parent / 'checkout'), 'local'))
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'cancelled', 'cli': 'codex'}
        original_begin = self.maintenance.begin_spawn
        original_save = self.maintenance._retain_spawn_refusal
        entered, release = threading.Event(), threading.Event()
        async def expire_original():
            result = await original_begin()
            request = self.maintenance._requests[asyncio.current_task()]
            await asyncio.sleep(max(0, request['expires'] - server.time.monotonic()) + .02)
            return result
        def held_save(request):
            entered.set()
            if not release.wait(5):
                raise AssertionError('save not released')
            return original_save(request)
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(server.subprocess, 'run') as launch, \
                patch.object(self.maintenance, 'begin_spawn', side_effect=expire_original), \
                patch.object(self.maintenance, '_retain_spawn_refusal', side_effect=held_save):
            task = asyncio.create_task(self.request('spawn', arguments, 'cancelled-refusal'))
            try:
                for _ in range(800):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(entered.is_set())
                task.cancel()
                await asyncio.sleep(.01)
                task.cancel()
                self.assertFalse(task.done())
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)
            self.assertTrue(task.cancelled())
            result = await self.request('spawn', arguments, 'cancelled-refusal')
            self.assertEqual(result['outcome'], 'not-started')
            self.assertEqual(launch.call_count, 0)


class SourceReadAdmissionTests(HubWorkMaintenanceTests):
    def configure_channels(self, **kwargs):
        import copy
        from agentmux_contracts import canonical_bytes, strict_loads
        from identity.authority import AuthoritySnapshot
        super().configure_channels(**kwargs)
        third = copy.deepcopy(self.value['storage']['work']['channels'][1])
        third.update(resourceRef=ref('work-three'), repository={'localName': 'third'})
        record = strict_loads(self.snapshot.record)
        for index, grant in enumerate(tuple(record['state']['grants'])):
            if grant.get('resourceId') != 'work-two':
                continue
            new = copy.deepcopy(grant)
            new.update(ref=ref('third-source-' + str(index)), resourceId='work-three')
            record['state']['grants'].append(new)
            for actor in third['legacyActors']:
                for contract, reference in tuple(actor['grants'].items()):
                    if reference == grant['ref']:
                        actor['grants'][contract] = new['ref']
        self.value['storage']['work']['channels'].append(third)
        store = self.reopen()
        try:
            store.repo_add('third')
        finally:
            store.db.close()
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
        self.selection = self.selected()

    async def test_three_routes_wait_before_new_proofs_then_run_concurrently(self):
        source = self.hub._work_source_binding
        self.assertEqual(len(source.routes), 3)
        entered, release = threading.Event(), threading.Event()
        proofs, all_entered = [], asyncio.Event()
        original = source._prove_current
        async def prove(session, raw, expires):
            proofs.append(expires)
            if len(proofs) == 3:
                all_entered.set()
            await asyncio.wait_for(all_entered.wait(), 2)
            self.assertGreater((expires - datetime.now(timezone.utc)).total_seconds(), 3)
            return await original(session, raw, expires)
        def alive(*args):
            entered.set()
            if not release.wait(8):
                raise RuntimeError('observation release missing')
            return True
        observer = reader = None
        try:
            with patch.object(self.hub, '_native_core', object()), \
                    patch.object(self.hub.tp, 'alive', side_effect=alive), \
                    patch.object(source, '_prove_current', side_effect=prove):
                observer = asyncio.create_task(self.hub._observe_terminal_alive({'session': 'original'}))
                for _ in range(200):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(entered.is_set())
                reader = asyncio.create_task(source.verify())
                await asyncio.sleep(4.05)
                self.assertEqual(proofs, [])
                release.set()
                await observer
                await asyncio.wait_for(reader, 4)
                self.assertEqual(len(set(proofs)), 1)
                self.assertFalse(source.pending)
                self.assertFalse(self.maintenance._lock.locked())
        finally:
            release.set()
            for task in (observer, reader):
                if task is not None:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    async def test_cancelled_source_batch_joins_all_original_routes_before_release(self):
        source = self.hub._work_source_binding
        started, release = asyncio.Event(), asyncio.Event()
        entered, completed = set(), set()
        original = source._prove_current
        async def prove(session, raw, expires):
            entered.add(id(session))
            if len(entered) == 3:
                started.set()
            await release.wait()
            try:
                return await original(session, raw, expires)
            finally:
                completed.add(id(session))
        task = None
        try:
            with patch.object(source, '_prove_current', side_effect=prove):
                task = asyncio.create_task(source.verify())
                await asyncio.wait_for(started.wait(), 2)
                task.cancel()
                await asyncio.sleep(.01)
                task.cancel()
                await asyncio.sleep(.01)
                self.assertFalse(task.done())
                self.assertTrue(self.maintenance._lock.locked())
                self.assertEqual(completed, set())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertEqual(completed, entered)
            self.assertFalse(source.pending)
            self.assertFalse(self.maintenance._lock.locked())
        finally:
            release.set()
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_submitted_three_route_batch_keeps_original_expiry(self):
        source = self.hub._work_source_binding
        expiries = []
        original = source._prove_current
        async def expired(session, raw, expires):
            expiries.append(expires)
            await asyncio.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + .02)
            return await original(session, raw, expires)
        with patch.object(source, '_prove_current', side_effect=expired):
            with self.assertRaises(ContractError):
                await source.verify()
        self.assertEqual(len(expiries), 3)
        self.assertEqual(len(set(expiries)), 1)
        self.assertFalse(source.pending)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_queued_child_does_not_inherit_turn_and_sees_revoked_grant(self):
        from agentmux_contracts import canonical_bytes, strict_loads
        from identity.authority import AuthoritySnapshot
        source = self.hub._work_source_binding
        old = self.snapshot
        task = None
        try:
            with patch.object(source, '_prove_current', wraps=source._prove_current) as proved:
                async with self.maintenance.observation_read_turn():
                    task = asyncio.create_task(source.verify())
                    await asyncio.sleep(.05)
                    self.assertEqual(proved.await_count, 0)
                    record = strict_loads(old.record)
                    grant = strict_loads(self.resources[0]._legacy_actors[0].grants)['federation-work-inspect']
                    next(row for row in record['state']['grants'] if row['ref'] == grant)['status'] = 'revoked'
                    self.snapshot = AuthoritySnapshot(canonical_bytes(record), old.sequence)
                with self.assertRaises(ContractError):
                    await task
                self.assertEqual(proved.await_count, 3)
            self.assertFalse(source.pending)
            self.assertFalse(self.maintenance._lock.locked())
        finally:
            self.snapshot = old
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


class NativeWorkSchedulingTests(HubWorkMaintenanceTests):
    async def test_live_observation_waits_for_discovery_and_joins_cancelled_original(self):
        await self.registered()
        entered, release = threading.Event(), threading.Event()
        task = None
        def alive(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('observation was not released')
            return True
        try:
            with patch.object(self.hub, '_native_core', object()), \
                    patch.object(self.hub.tp, 'alive', side_effect=alive) as observed:
                async with self.maintenance.discovery_request_turn(b'original discovery'):
                    task = asyncio.create_task(self.hub.live_loop())
                    await asyncio.sleep(.05)
                    self.assertFalse(entered.is_set())
                for _ in range(200):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(entered.is_set())
                task.cancel()
                await asyncio.sleep(.01)
                task.cancel()
                await asyncio.sleep(.01)
                self.assertFalse(task.done())
                self.assertTrue(self.maintenance._lock.locked())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                observed.assert_called_once()
                self.assertFalse(self.maintenance._lock.locked())
        finally:
            release.set()
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def read_work(self, operation, expires=None):
        return await self.hub._work_storage_commands._call(
            self.sessions[0], 'federation-work-read', operation,
            {'resourceRef': ref(self.resources[0].binding.entity_id),
             'input': {'query': {'kind': 'list', 'state': None}}},
            expires or datetime.now(timezone.utc) + timedelta(seconds=4))

    async def test_native_caller_waits_for_signed_reply_and_joins_on_cancel(self):
        source = self.hub._work_source_binding
        commands = self.hub._work_storage_commands
        original_local = source._local
        original_command = self.sessions[0].work_command
        replied = threading.Event()
        local_entered, local_release = asyncio.Event(), asyncio.Event()
        native_entered, native_release = threading.Event(), threading.Event()
        events = []
        reader = None

        def command(**kwargs):
            result = original_command(**kwargs)
            if kwargs['contract_id'] == 'federation-work-read':
                replied.set()
            return result

        async def local(**kwargs):
            if asyncio.current_task() is reader and replied.is_set():
                local_entered.set()
                await local_release.wait()
                result = await original_local(**kwargs)
                events.append('reply-source-checked')
                return result
            return await original_local(**kwargs)

        def identify(pid):
            events.append('native-entered')
            native_entered.set()
            if not native_release.wait(5):
                raise AssertionError('native check was not released')
            return None, False

        tasks = []
        try:
            with patch.object(self.sessions[0], 'work_command', side_effect=command), \
                    patch.object(source, '_local', side_effect=local), \
                    patch.object(self.hub, '_native_core', object()), \
                    patch.object(self.hub, 'peer', return_value=(123, server.os.getuid())), \
                    patch.object(self.hub, 'identify_qualified', side_effect=identify):
                reader = asyncio.create_task(self.read_work('native-drain-original'))
                tasks.append(reader)
                await asyncio.wait_for(local_entered.wait(), 3)
                writer = SimpleNamespace(get_extra_info=lambda key: object())
                native = asyncio.create_task(self.hub._caller_identity({}, writer, False, qualified=True))
                tasks.append(native)
                await asyncio.sleep(0)
                self.assertFalse(native_entered.is_set())
                local_release.set()
                await reader
                for _ in range(100):
                    if native_entered.is_set():
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(native_entered.is_set())
                self.assertEqual(events[:2], ['reply-source-checked', 'native-entered'])
                waiting = asyncio.create_task(self.read_work('native-drain-next'))
                tasks.append(waiting)
                native.cancel()
                await asyncio.sleep(0)
                native.cancel()
                await asyncio.sleep(.02)
                self.assertFalse(native.done())
                self.assertFalse(waiting.done())
                self.assertTrue(all(lock.locked() for lock in commands._transport_locks.values()))
                native_release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await native
                await waiting
                self.assertFalse(any(lock.locked() for lock in commands._transport_locks.values()))
        finally:
            local_release.set()
            native_release.set()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_partial_lock_wait_cancellation_releases_acquired_locks(self):
        commands = self.hub._work_storage_commands
        locks = list(commands._transport_locks.values())
        self.assertGreaterEqual(len(locks), 2)
        await locks[1].acquire()
        async def turn():
            async with commands.native_check_turn():
                self.fail('second transport is still held')
        task = asyncio.create_task(turn())
        try:
            await asyncio.sleep(0)
            self.assertTrue(locks[0].locked())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(locks[0].locked())
            self.assertTrue(locks[1].locked())
        finally:
            locks[1].release()
            await asyncio.gather(task, return_exceptions=True)

    async def test_queued_read_keeps_original_expiry(self):
        commands = self.hub._work_storage_commands
        expires = datetime.now(timezone.utc) + timedelta(seconds=.05)
        async with commands.native_check_turn():
            task = asyncio.create_task(self.read_work('expired-native-queue', expires))
            await asyncio.sleep(.07)
        with self.assertRaisesRegex(ContractError, 'legacy_work_client_expired'):
            await task
        await self.read_work('after-expired-native-queue')

    async def test_concurrent_activation_proofs_drain_before_native_check(self):
        source = self.hub._work_source_binding
        commands = self.hub._work_storage_commands
        original_local = source._local
        finished = set()
        blocked, release = asyncio.Event(), asyncio.Event()
        loop = asyncio.get_running_loop()
        patches = []
        for session in self.sessions:
            original = session.work_command
            def command(*, original=original, session=session, **kwargs):
                result = original(**kwargs)
                if kwargs['contract_id'] == 'federation-work-inspect':
                    loop.call_soon_threadsafe(finished.add, id(session))
                return result
            patches.append(patch.object(session, 'work_command', side_effect=command))
        async def local(**kwargs):
            if len(finished) == len(self.sessions):
                blocked.set()
                await release.wait()
            return await original_local(**kwargs)
        async def native():
            async with commands.native_check_turn():
                self.assertTrue(release.is_set())
                return await self.hub.db(lambda: 'native completed')
        tasks = []
        try:
            for item in patches:
                item.start()
            source.activation = None
            with patch.object(source, '_local', side_effect=local):
                activation = asyncio.create_task(source.activate())
                tasks.append(activation)
                await asyncio.wait_for(blocked.wait(), 3)
                check = asyncio.create_task(native())
                tasks.append(check)
                await asyncio.sleep(0)
                self.assertFalse(check.done())
                release.set()
                await activation
                self.assertEqual(await check, 'native completed')
                await source.verify()
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            for item in reversed(patches):
                item.stop()

    async def test_failed_classification_fallback_uses_the_same_turn(self):
        commands = self.hub._work_storage_commands
        writer = SimpleNamespace(get_extra_info=lambda key: object())
        with patch.object(self.hub, '_native_core', object()), \
                patch.object(self.hub, 'peer', return_value=(123, server.os.getuid())), \
                patch.object(self.hub, 'identify_qualified',
                    side_effect=[server.CallerClassificationUnavailable('unavailable'), (None, False)]) as identify:
            with self.assertRaises(server.CallerClassificationUnavailable):
                await self.hub.authenticate_caller({'verb': 'whoami', 'args': {}}, writer, False)
            async with commands.native_check_turn():
                fallback = asyncio.create_task(self.hub.caller_of({}, writer, False))
                await asyncio.sleep(0)
                self.assertEqual(identify.call_count, 1)
                self.assertFalse(fallback.done())
            self.assertEqual(await fallback, 'operator')
            self.assertEqual(identify.call_count, 2)

    async def test_final_native_check_keeps_original_deadline_after_wait(self):
        import time
        commands = self.hub._work_storage_commands
        admitted = SimpleNamespace(expires_monotonic=time.monotonic() + .05)
        self.hub._work_reply_identity = {}
        async def final():
            self.hub._work_reply_identity[asyncio.current_task()] = (admitted, False, (123, server.os.getuid()))
            await self.hub._check_work_targets()
        with patch.object(self.hub, '_native_core', object()), \
                patch.object(self.hub, 'identify_qualified') as identify:
            async with commands.native_check_turn():
                task = asyncio.create_task(final())
                await asyncio.sleep(.07)
            with self.assertRaises(server.HubError):
                await task
            identify.assert_not_called()

    async def test_native_check_waits_for_whole_observation_read(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def observation():
            async with self.maintenance.observation_read_turn():
                await self.read_work('observation-first-route')
                entered.set()
                await release.wait()
                await self.read_work('observation-second-route')
        async def native():
            async with self.hub._native_work_check_turn():
                self.assertTrue(release.is_set())
                return await self.hub.db(lambda: 'checked')
        tasks = []
        try:
            with patch.object(self.hub, '_native_core', object()):
                read = asyncio.create_task(observation())
                tasks.append(read)
                await asyncio.wait_for(entered.wait(), 3)
                check = asyncio.create_task(native())
                tasks.append(check)
                await asyncio.sleep(0)
                self.assertFalse(check.done())
                release.set()
                await read
                self.assertEqual(await check, 'checked')
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_native_turn_reuses_only_exact_adoption_owner_and_child(self):
        entered = asyncio.Event()
        async def unrelated():
            async with self.hub._native_work_check_turn():
                entered.set()
        async def child():
            async with self.hub._native_work_check_turn():
                return await self.hub.db(lambda: 'child checked')
        with patch.object(self.hub, '_native_core', object()):
            async with self.maintenance.adoption_request_turn(b'original request'):
                async with self.hub._native_work_check_turn():
                    self.assertFalse(entered.is_set())
                waiting = asyncio.create_task(unrelated())
                original = asyncio.create_task(child())
                # Model only the existing exact child assignment, never authority.
                self.maintenance._request_turn['child'] = original
                self.assertEqual(await asyncio.wait_for(asyncio.shield(original), 2), 'child checked')
                self.assertFalse(waiting.done())
            await waiting
            self.assertTrue(entered.is_set())

    async def test_partial_transport_cancellation_releases_maintenance_turn(self):
        commands = self.hub._work_storage_commands
        locks = list(commands._transport_locks.values())
        await locks[1].acquire()
        async def native():
            async with self.hub._native_work_check_turn():
                self.fail('held transport must block')
        with patch.object(self.hub, '_native_core', object()):
            task = asyncio.create_task(native())
            try:
                await asyncio.sleep(0)
                self.assertTrue(self.maintenance._lock.locked())
                self.assertTrue(locks[0].locked())
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertFalse(self.maintenance._lock.locked())
                self.assertFalse(locks[0].locked())
            finally:
                locks[1].release()
                await asyncio.gather(task, return_exceptions=True)


from . import test_adopt_request_turn as adoption


class NativeAdoptionSchedulingTests(adoption.AdoptRequestTurnTests):
    async def test_native_adoption_original_child_and_replay(self):
        with patch.object(self.hub, '_native_core', object()):
            await self.test_queue_precedes_proof_and_same_id_replay_preserves_registration()

    async def test_native_adoption_unrelated_task_waits_through_reply(self):
        with patch.object(self.hub, '_native_core', object()):
            await self.test_unrelated_inherited_task_waits_through_final_check_and_reply()

    async def test_native_adoption_cancellation_joins_original_child(self):
        with patch.object(self.hub, '_native_core', object()):
            await self.test_cancellation_joins_original_child_before_releasing_turn()


class NativeDiscoverySchedulingTests(adoption.AdoptRequestTurnTests):
    async def test_discovery_keeps_background_read_outside_final_check(self):
        entered = asyncio.Event()
        background = None
        original = self.hub._check_work_targets
        async def read():
            async with self.maintenance.observation_read_turn():
                entered.set()
        async def final():
            nonlocal background
            background = self.task(read())
            await asyncio.sleep(0)
            self.assertFalse(entered.is_set())
            await original()
            self.assertFalse(entered.is_set())
        with patch.object(self.hub, '_native_core', object()), \
                patch.object(self.hub, '_check_work_targets', side_effect=final):
            result = await self.framed_connection({'verb': 'ping', 'args': {}})
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['result']['lifecycleOperationIds'])
        await background
        self.assertTrue(entered.is_set())
        self.assertIsNone(self.maintenance._discovery_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_discovery_expired_in_queue_never_authenticates(self):
        import json
        import socket
        import time
        from contextlib import asynccontextmanager
        from agentmux_contracts import canonical_bytes
        from hub.core_endpoint import CoreEndpoint, _mac, digest
        endpoint = object.__new__(CoreEndpoint)
        endpoint.hub = self.hub
        endpoint.tasks, endpoint.nonces = set(), {}
        endpoint.record = SimpleNamespace(raw=b'private selected fixture record')
        endpoint.value = {'key': '42' * 32}
        endpoint.route = SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}})
        endpoint.check = lambda: None
        self.hub._selected_endpoint = endpoint
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        reader, writer = await asyncio.open_connection(sock=left)
        server_reader, server_writer = await asyncio.open_connection(sock=right)
        queued = asyncio.Event()
        original = self.maintenance.discovery_request_turn
        @asynccontextmanager
        async def turn(request):
            queued.set()
            async with original(request):
                yield
        body = {'binding': digest(endpoint.record.raw), 'nonce': '8' * 64,
            'expires': time.monotonic() + .3, 'repository': '/falcon',
            'request': {'verb': 'ping', 'args': {}}}
        try:
            with patch.object(self.hub, '_native_core', object()), \
                    patch.object(self.maintenance, 'discovery_request_turn', turn), \
                    patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as auth:
                async with self.maintenance._serialized():
                    task = self.task(endpoint.serve(server_reader, server_writer))
                    writer.write(canonical_bytes({'core': body, 'mac': _mac(endpoint.value['key'], body)}) + b'\n')
                    await writer.drain()
                    await asyncio.wait_for(queued.wait(), 2)
                    await asyncio.sleep(max(0, body['expires'] - time.monotonic()) + .02)
                await asyncio.wait_for(task, 2)
                auth.assert_not_awaited()
            self.assertIsNone(self.maintenance._discovery_turn)
            self.assertFalse(self.maintenance._lock.locked())
        finally:
            writer.close(); server_writer.close()
            await asyncio.gather(writer.wait_closed(), server_writer.wait_closed())

    async def test_discovery_cancellation_releases_only_its_original_turn(self):
        entered, release = asyncio.Event(), self.gate()
        original = self.binding.verify
        async def verify():
            await original()
            entered.set()
            await release.wait()
        with patch.object(self.hub, '_native_core', object()), \
                patch.object(self.binding, 'verify', side_effect=verify):
            self.request = {'verb': 'ping', 'args': {}}
            task = self.task(self.adoption_connection())
            await asyncio.wait_for(entered.wait(), 3)
            self.assertTrue(self.maintenance._lock.locked())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertIsNone(self.maintenance._discovery_turn)
        self.assertFalse(self.maintenance._lock.locked())
        await self.binding.verify()


class NativeSpawnPreflightTests(adoption.AdoptRequestTurnTests):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'native_spawn', 'cli': 'codex'}
        self.request = {'verb': 'spawn', 'args': self.arguments,
                        'operationId': 'native-spawn-original', 'as': 'operator'}
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)',
            ('falcon', str(self.database.parent / 'checkout'), 'local'))
        native = SimpleNamespace(recheck=lambda **kwargs: None,
            harness_command=lambda *args, **kwargs: SimpleNamespace(arguments=['owned-harness'], environment={}))
        self.enterContext(patch.object(self.hub, '_native_core', native))

    async def test_framed_spawn_preflights_once_and_replays_original(self):
        events = []
        verify, identity = self.binding.verify, self.hub._caller_identity
        async def verified():
            events.append('source')
            return await verify()
        async def classified(*args, **kwargs):
            events.append('identity')
            return await identity(*args, **kwargs)
        with patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, '_caller_identity', side_effect=classified), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='original spawn', stderr='')) as launch:
            first = await self.framed_connection(self.request)
            self.assertTrue(first['ok'], first)
            self.assertEqual(events, ['source', 'identity'])
            row = await self.hub.db(self.hub.store.agent, first['result']['session'])
            second = await self.framed_connection(self.request)
            self.assertTrue(second['ok'], second)
            self.assertEqual(second['result'], first['result'])
            self.assertEqual(second['operationId'], self.request['operationId'])
            self.assertEqual(events, ['source', 'identity', 'source', 'identity'])
            launch.assert_called_once()
            self.assertEqual(await self.hub.db(self.hub.store.agent, row['session']), row)
            self.assertEqual(row['generation'], 1)

    async def test_spawn_wrong_uid_and_changed_source_refuse_before_effect(self):
        with patch.object(self.hub, 'peer', return_value=(123, server.os.getuid() + 1)), \
                patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
            result = await self.framed_connection(self.request)
            self.assertFalse(result['ok'], result)
            verify.assert_not_awaited()
        old = self.hub.cfg.get('nats_url')
        def changed(pid):
            self.hub.cfg['nats_url'] = 'nats://changed-source.invalid:4222'
            return None, False
        try:
            with patch.object(self.hub, 'identify_qualified', side_effect=changed):
                result = await self.framed_connection(self.request)
                self.assertFalse(result['ok'], result)
        finally:
            self.hub.cfg['nats_url'] = old
        self.assertFalse(any(row['contractId'] == 'federation-work-register' for row in self.submitted))

    async def test_managed_spawn_cannot_reuse_operator_preflight(self):
        request = {key: value for key, value in self.request.items() if key != 'as'}
        with patch.object(self.hub, 'identify_qualified', return_value=('falcon-worker-existing', True)), \
                patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
            result = await self.framed_connection(request)
            self.assertFalse(result['ok'], result)
            self.assertEqual(verify.await_count, 2)
        with patch.object(self.hub, 'identify_qualified', return_value=('falcon-worker-existing', True)):
            result = await self.framed_connection(self.request)
            self.assertFalse(result['ok'], result)
        self.assertFalse(any(row['contractId'] == 'federation-work-register' for row in self.submitted))

    async def test_spawn_expired_original_proof_never_registers(self):
        import time
        from dataclasses import replace
        original = self.hub.authenticate_caller
        async def expired(*args, **kwargs):
            proof = await original(*args, **kwargs)
            self.hub._authenticated_callers[proof] = replace(
                self.hub._authenticated_callers[proof], expires_monotonic=time.monotonic() - .01)
            return proof
        with patch.object(self.hub, 'authenticate_caller', side_effect=expired):
            result = await self.framed_connection(self.request)
        self.assertFalse(result['ok'], result)
        self.assertFalse(any(row['contractId'] == 'federation-work-register' for row in self.submitted))


class SourceReadCallerTests(NativeSpawnPreflightTests):
    async def test_framed_kill_ingress_and_dispatch_keep_both_source_checks(self):
        with patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='original', stderr='')):
            spawned = await self.framed_connection(self.request)
        self.assertTrue(spawned['ok'], spawned)
        request = {'verb': 'kill', 'args': {'session': spawned['result']['session']},
                   'operationId': 'source-gated-kill', 'as': 'operator'}
        with patch.object(self.binding, 'verify', wraps=self.binding.verify) as verified, \
                patch.object(self.binding, '_prove_current', wraps=self.binding._prove_current) as proved, \
                patch.object(self.hub, 'harness', return_value=True) as terminated:
            async with self.hub._native_work_check_turn():
                task = self.task(self.framed_connection(request))
                await asyncio.sleep(.05)
                self.assertEqual(proved.await_count, 0)
            result = await task
            self.assertTrue(result['ok'], result)
            self.assertEqual(verified.await_count, 2)
            replay = await self.framed_connection(request)
            self.assertTrue(replay['ok'], replay)
            self.assertEqual(replay['result'], result['result'])
            self.assertEqual(verified.await_count, 4)
            terminated.assert_called_once()

    async def test_queued_ingress_does_not_renew_original_envelope(self):
        request = {'verb': 'kill', 'args': {'session': 'falcon-worker-original'},
                   'operationId': 'expired-original-kill'}
        with patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as auth:
            async with self.hub._native_work_check_turn():
                task = self.task(self.framed_connection(request, expires=server.time.monotonic() + .04))
                await asyncio.sleep(.08)
            with self.assertRaisesRegex(AssertionError, 'closed without a response'):
                await task
            auth.assert_not_awaited()
        self.assertFalse(self.binding.pending)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_changed_source_after_wait_refuses_without_authentication(self):
        old = self.hub.cfg.get('nats_url')
        request = {'verb': 'kill', 'args': {'session': 'falcon-worker-original'},
                   'operationId': 'changed-source-kill'}
        try:
            with patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as auth:
                async with self.hub._native_work_check_turn():
                    task = self.task(self.framed_connection(request))
                    await asyncio.sleep(.05)
                    self.hub.cfg['nats_url'] = 'nats://changed-source.invalid:4222'
                with self.assertRaisesRegex(AssertionError, 'closed without a response'):
                    await task
                auth.assert_not_awaited()
        finally:
            self.hub.cfg['nats_url'] = old
        self.assertFalse(self.binding.pending)
        self.assertFalse(self.maintenance._lock.locked())


class NativeSpawnPreparationTests(NativeSpawnPreflightTests):
    async def test_saved_replay_keeps_final_classification_ahead_of_background(self):
        entered = asyncio.Event()
        background = None
        async def observe():
            async with self.maintenance.observation_read_turn():
                entered.set()
        original = self.hub._check_work_targets
        async def checked():
            nonlocal background
            reservation = self.maintenance._spawn_request_turn
            self.assertTrue(reservation['disclosure_only'])
            self.assertTrue(reservation['child'].done())
            background = self.task(observe())
            await asyncio.sleep(0)
            self.assertFalse(entered.is_set())
            await original()
            self.assertFalse(entered.is_set())
        with patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='original', stderr='')) as launch:
            first = await self.framed_connection(self.request)
            self.assertTrue(first['ok'], first)
            with patch.object(self.hub, '_check_work_targets', side_effect=checked):
                replay = await self.framed_connection(self.request)
            self.assertTrue(replay['ok'], replay)
            self.assertEqual(replay['result'], first['result'])
            launch.assert_called_once()
        self.assertIsNotNone(background)
        await background
        self.assertTrue(entered.is_set())
        self.assertIsNone(self.maintenance._spawn_request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_original_child_error_and_terminal_replay_release_preparation(self):
        original = self.maintenance.begin_spawn
        async def expire():
            result = await original()
            request = self.maintenance._requests[asyncio.current_task()]
            await asyncio.sleep(max(0, request['expires'] - server.time.monotonic()) + .02)
            return result
        with patch.object(server.subprocess, 'run') as launch:
            with patch.object(self.maintenance, 'begin_spawn', side_effect=RuntimeError('preparation failed')):
                first = await self.adoption_connection()
                self.assertFalse(first['ok'])
                self.assertIsNone(self.maintenance._spawn_request_turn)
                self.assertFalse(self.maintenance._lock.locked())
            with patch.object(self.maintenance, 'begin_spawn', side_effect=expire):
                refused = await self.adoption_connection()
                self.assertFalse(refused['ok'])
            replay = await self.framed_connection(self.request)
            self.assertTrue(replay['ok'], replay)
            self.assertEqual(replay['result']['outcome'], 'not-started')
            self.assertEqual(launch.call_count, 0)
        self.assertIsNone(self.maintenance._spawn_request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_cancel_after_child_assignment_joins_original_preparation(self):
        entered, release = asyncio.Event(), self.gate()
        original = self.maintenance.begin_spawn
        async def begin():
            result = await original()
            entered.set()
            await release.wait()
            return result
        with patch.object(self.maintenance, 'begin_spawn', side_effect=begin), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='original', stderr='')) as launch:
            task = self.task(self.adoption_connection())
            await asyncio.wait_for(entered.wait(), 3)
            reservation = self.maintenance._spawn_request_turn
            self.assertIsNotNone(reservation['child'])
            task.cancel()
            await asyncio.sleep(.01)
            task.cancel()
            self.assertFalse(task.done())
            self.assertIs(self.maintenance._spawn_request_turn, reservation)
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(reservation['child'].done())
            self.assertEqual(launch.call_count, 1)
        self.assertIsNone(self.maintenance._spawn_request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_actual_preparation_releases_before_harness_callback(self):
        entered, release = asyncio.Event(), self.gate()
        callback_entered = asyncio.Event()
        original = self.binding.verify
        first = True
        async def verify():
            nonlocal first
            if first:
                first = False
                entered.set()
                await release.wait()
            return await original()
        async def callback():
            async with self.maintenance.observation_read_turn():
                await original()
                callback_entered.set()
        loop = asyncio.get_running_loop()
        def launch(*args, **kwargs):
            self.assertIsNone(self.maintenance._spawn_request_turn)
            # A real signed source read must progress while the harness waits.
            asyncio.run_coroutine_threadsafe(callback(), loop).result(timeout=3)
            return SimpleNamespace(returncode=0, stdout='controlled', stderr='')
        with patch.object(self.binding, 'verify', side_effect=verify), \
                patch.object(server.subprocess, 'run', side_effect=launch) as harness:
            task = self.task(self.framed_connection(self.request))
            await asyncio.wait_for(entered.wait(), 3)
            self.assertTrue(self.maintenance._lock.locked())
            self.assertFalse(callback_entered.is_set())
            release.set()
            result = await task
            self.assertTrue(result['ok'], result)
            self.assertTrue(callback_entered.is_set())
            self.assertEqual(harness.call_count, 1)
        self.assertIsNone(self.maintenance._spawn_request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_cancel_before_spawn_child_releases_reservation(self):
        entered, release = asyncio.Event(), self.gate()
        async def verify():
            entered.set()
            await release.wait()
        with patch.object(self.binding, 'verify', side_effect=verify):
            task = self.task(self.adoption_connection())
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertIsNone(self.maintenance._spawn_request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_old_parent_cleanup_cannot_release_new_reservation(self):
        child_entered, old_released, newer_entered = asyncio.Event(), asyncio.Event(), asyncio.Event()
        child_release, newer_release = self.gate(), self.gate()
        async def old_child():
            child_entered.set()
            self.maintenance.release_spawn_preparation()
            old_released.set()
            await child_release.wait()
        async def old_parent():
            async with self.maintenance.spawn_request_turn(b'old'):
                child = self.task(old_child())
                self.maintenance._spawn_request_turn['child'] = child
                await child_entered.wait()
        async def newer():
            async with self.maintenance.spawn_request_turn(b'new'):
                newer_entered.set()
                await newer_release.wait()
        parent = self.task(old_parent())
        await old_released.wait()
        next_parent = self.task(newer())
        await newer_entered.wait()
        current = self.maintenance._spawn_request_turn
        parent.cancel()
        await asyncio.sleep(.01)
        self.assertFalse(parent.done())
        child_release.set()
        with self.assertRaises(asyncio.CancelledError):
            await parent
        self.assertIs(self.maintenance._spawn_request_turn, current)
        self.assertTrue(self.maintenance._lock.locked())
        newer_release.set()
        await next_parent
        self.assertFalse(self.maintenance._lock.locked())

    async def test_spawn_expired_in_queue_never_authenticates(self):
        import json
        import socket
        import time
        from contextlib import asynccontextmanager
        from agentmux_contracts import canonical_bytes
        from hub.core_endpoint import CoreEndpoint, _mac, digest
        endpoint = object.__new__(CoreEndpoint)
        endpoint.hub = self.hub
        endpoint.tasks, endpoint.nonces = set(), {}
        endpoint.record = SimpleNamespace(raw=b'private selected fixture record')
        endpoint.value = {'key': '42' * 32}
        endpoint.route = SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}})
        endpoint.check = lambda: None
        self.hub._selected_endpoint = endpoint
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        reader, writer = await asyncio.open_connection(sock=left)
        server_reader, server_writer = await asyncio.open_connection(sock=right)
        queued = asyncio.Event()
        original = self.maintenance.spawn_request_turn
        @asynccontextmanager
        async def turn(request):
            queued.set()
            async with original(request):
                yield
        body = {'binding': digest(endpoint.record.raw), 'nonce': '8' * 64,
            'expires': time.monotonic() + .3, 'repository': '/falcon',
            'request': self.request}
        try:
            with patch.object(self.hub, '_native_core', object()), \
                    patch.object(self.maintenance, 'spawn_request_turn', turn), \
                    patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as auth:
                async with self.maintenance._serialized():
                    task = self.task(endpoint.serve(server_reader, server_writer))
                    writer.write(canonical_bytes({'core': body, 'mac': _mac(endpoint.value['key'], body)}) + b'\n')
                    await writer.drain()
                    await asyncio.wait_for(queued.wait(), 2)
                    await asyncio.sleep(max(0, body['expires'] - time.monotonic()) + .02)
                await asyncio.wait_for(task, 2)
                auth.assert_not_awaited()
            self.assertIsNone(self.maintenance._spawn_request_turn)
            self.assertFalse(self.maintenance._lock.locked())
        finally:
            writer.close(); server_writer.close()
            await asyncio.gather(writer.wait_closed(), server_writer.wait_closed())

