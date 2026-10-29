"""Actual Hub lifecycle callers use the selected original Work source."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import deliver, server
from identity.authority import AuthoritySnapshot
from .test_work_source import SelectedWorkSourceFixture
from identity.test_authority import ref


class HubWorkMaintenanceTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    def configure_channels(self, **kwargs):
        SelectedWorkSourceFixture.configure_channels(self, **kwargs)
        record = strict_loads(self.snapshot.record)
        for index, channel in enumerate(self.value['storage']['work']['channels']):
            grant = ref('hub-service-read-' + str(index))
            channel['legacyActors'][0]['grants']['federation-work-read'] = grant
            record['state']['grants'].append({'ref': grant, 'callerRef': ref('storage-service'),
                'actorRef': ref('storage-service'), 'scope': channel.get('scope', self.scope),
                'contractId': 'federation-work-read', 'resourceId': channel['resourceRef']['id'],
                'decision': 'allowed', 'delegationRef': None, 'definitionTarget': None, 'status': 'active',
                'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
        self.selection = self.selected()

    async def asyncSetUp(self):
        await SelectedWorkSourceFixture.asyncSetUp(self)
        self.hub = await self.setup_source()
        self.enterContext(patch.object(server, 'ROOT', str(self.database.parent / 'application')))
        self.enterContext(patch.object(server, 'HUBDIR', str(self.database.parent)))
        await self.hub._work_source_binding.activate()
        self.maintenance = self.hub._maintenance_for_work()
        self.addAsyncCleanup(self.hub._close_work_maintenance)

    async def request(self, verb, arguments, operation):
        request = {'verb': verb, 'args': arguments, 'operationId': operation}
        writer = SimpleNamespace(get_extra_info=lambda key: object())
        with patch.object(self.hub, 'peer', return_value=(123, server.os.getuid())), \
                patch.object(self.hub, 'identify_qualified', return_value=(None, False)):
            proof = await self.hub.authenticate_caller(request, writer, False)
        token = self.hub._authenticated_caller_context.set(proof)
        try:
            return await self.hub.dispatch(verb, arguments, 'operator')
        finally:
            self.hub._authenticated_caller_context.reset(token)

    async def registered(self, name='one'):
        session, generation = await self.maintenance.register('falcon', 'worker', name, 'codex', {},
            handle='%17', pane_pid=12345)
        agent = await self.hub.db(self.hub.store.agent, session)
        self.assertEqual(agent['generation'], generation)
        self.assertTrue(await self.hub._apply_observed_state(agent, 'ready'))
        return await self.hub.db(self.hub.store.agent, session)

    async def claim_both(self, agent):
        def setup():
            rows = []
            for repository in ('falcon', 'other'):
                row = self.hub.store.work_create('virtual:operator', repository,
                    'agent:' + agent['session'], 'Retained ' + repository)
                claimed = self.hub.store.claim(agent['session'], work_id=row['id'])
                self.assertEqual(claimed['claimed']['id'], row['id'])
                self.hub.store.claim_path(agent['session'], repository, repository + '.txt', row['id'])
                rows.append(self.hub.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)))
            self.assertTrue(all(row['state'] == 'claimed' and row['claimed_by'] == agent['session'] for row in rows))
            return rows
        return await self.hub.db(setup)

    async def test_actual_spawn_registers_through_owner_on_original_hub_source(self):
        checkout = str(self.database.parent / 'checkout')
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)', ('falcon', checkout, 'local'))
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'spawned', 'cli': 'codex'}
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(returncode=0,
                    stdout='original process result', stderr='')) as launch, \
                patch.object(self.hub.tp, 'handle', return_value=('%41', 23456)):
            result = await self.request('spawn', arguments, 'original-spawn')
            original_token = (Path(server.ROOT) / 'repos/falcon/agents/worker-spawned/run/token').read_bytes()
            replay = await self.request('spawn', arguments, 'original-spawn')
            self.assertEqual(replay, result)
            launch.assert_called_once()
            self.assertEqual((Path(server.ROOT) / 'repos/falcon/agents/worker-spawned/run/token').read_bytes(), original_token)
            with self.assertRaisesRegex(server.HubError, 'different original request'):
                await self.request('spawn', {**arguments, 'agent': 'changed'}, 'original-spawn')
        agent = await self.hub.db(self.hub.store.agent, result['session'])
        self.assertEqual((agent['generation'], agent['handle'], agent['pane_pid']), (1, '%41', 23456))
        mutations = [r for r in self.submitted if r['contractId'] == 'federation-work-register']
        self.assertEqual(len(mutations), 2)
        self.assertEqual(len({r['operationId'] for r in mutations}), 1)
        self.assertTrue(all('workSource' in r for r in mutations))
        owner_agent = await self.resources[0]._owner.db(self.resources[0]._store.agent, result['session'])
        self.assertEqual(owner_agent, agent)
        self.assertTrue((Path(server.ROOT) / 'repos/falcon/agents/worker-spawned/run/token').is_file())
        self.assertEqual(len(await self.hub.db(self.hub.store.q,
            "SELECT * FROM events WHERE entity_id=? AND event='registered'", (agent['session'],))), 1)
        self.assertEqual(len(await self.hub.db(self.hub.store.q,
            "SELECT * FROM messages WHERE kind='control' AND target=?", ('agent:' + agent['session'],))), 1)

    async def test_spawn_expiry_during_preparation_refuses_physical_launch(self):
        checkout = str(self.database.parent / 'checkout')
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)', ('falcon', checkout, 'local'))
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'expired', 'cli': 'codex'}
        begin_spawn = self.maintenance.begin_spawn
        entered = False

        async def held_preparation():
            nonlocal entered
            entered = True
            request = self.maintenance._requests[asyncio.current_task()]
            remaining = request['expires'] - server.time.monotonic()
            self.assertGreater(remaining, 0, 'original request expired before the held preparation')
            await asyncio.sleep(remaining + 0.02)
            self.assertGreaterEqual(server.time.monotonic(), request['expires'])
            return await begin_spawn()

        failure = None
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.maintenance, 'begin_spawn', side_effect=held_preparation), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='controlled provider result', stderr='')) as launch, \
                patch.object(self.hub.tp, 'handle', return_value=('%42', 23457)):
            try:
                await self.request('spawn', arguments, 'expiry-during-spawn-preparation')
            except server.HubError as exc:
                failure = exc
            self.assertTrue(entered)
            self.assertEqual(launch.call_count, 0, 'expired request submitted a physical launch')
            self.assertIsInstance(failure, server.HubError)
            self.assertIn('expired', str(failure))

    async def test_first_spawn_success_refuses_revoked_original_permission(self):
        checkout = str(self.database.parent / 'checkout')
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)', ('falcon', checkout, 'local'))
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'revoked', 'cli': 'codex'}
        save_result = self.maintenance.save_result
        revoked = False

        async def revoke_after_saved_result(verb, result):
            nonlocal revoked
            await save_result(verb, result)
            request = self.maintenance._requests[asyncio.current_task()]
            self.assertLess(server.time.monotonic(), request['expires'],
                'disclosure reproduction requires a still-live original request')
            record = strict_loads(self.snapshot.record)
            grants = strict_loads(self.resources[0]._legacy_actors[0].grants)
            original = next(g for g in record['state']['grants']
                if g['ref'] == grants['federation-work-register'])
            self.assertEqual(original['status'], 'active')
            original['status'] = 'revoked'
            self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
            revoked = True

        failure = None
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.maintenance, 'save_result', side_effect=revoke_after_saved_result), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='controlled provider result', stderr='')) as launch, \
                patch.object(self.hub.tp, 'handle', return_value=('%43', 23458)):
            try:
                await self.request('spawn', arguments, 'revoked-first-spawn-disclosure')
            except ContractError as exc:
                failure = exc
            self.assertTrue(revoked)
            self.assertEqual(launch.call_count, 1)
            self.assertIsInstance(failure, ContractError,
                'first success disclosed after original registration permission was revoked')

    async def test_actual_observed_death_returns_both_repository_leases(self):
        agent = await self.registered()
        rows = await self.claim_both(agent)
        self.assertTrue(await self.hub._apply_observed_state(agent, 'dead', 'terminal gone'))
        self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'dead')
        actual = await self.hub.db(self.hub.store.q,
            'SELECT * FROM work_items WHERE id IN (?,?) ORDER BY repo', tuple(row['id'] for row in rows))
        self.assertTrue(all(row['state'] == 'ready' and row['claimed_by'] is None for row in actual))
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM claims'), [])

    async def test_revoked_death_preserves_actual_agent_work_and_claims(self):
        agent = await self.registered()
        await self.claim_both(agent)
        def observed():
            return {table: self.hub.store.q('SELECT * FROM ' + table)
                for table in ('agents', 'work_items', 'claims', 'deliveries', 'team_members')}
        before = await self.hub.db(observed)
        record = strict_loads(self.snapshot.record)
        grant = self.resources[1]._legacy_actors[0].grants
        state_ref = strict_loads(grant)['federation-work-state']
        next(g for g in record['state']['grants'] if g['ref'] == state_ref)['status'] = 'revoked'
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
        with self.assertRaises(ContractError):
            await self.hub._apply_observed_state(agent, 'dead', 'terminal gone')
        self.assertEqual(await self.hub.db(observed), before)

    async def test_actual_global_sweep_keeps_one_batch_across_repositories(self):
        agent = await self.registered()
        rows = await self.claim_both(agent)
        await self.hub.db(self.hub.store.db.execute,
            "UPDATE work_items SET lease_until='2000-01-01T00:00:00.000Z' WHERE claimed_by=?", (agent['session'],))
        await self.hub.db(self.hub.store.db.execute,
            "UPDATE claims SET lease_until='2000-01-01T00:00:00.000Z' WHERE holder=?", (agent['session'],))
        swept = await self.hub._sweep_work_leases()
        self.assertEqual({row['id']: row['state'] for row in swept},
            {row['id']: 'ready' for row in rows})
        self.assertEqual(len(swept), len(rows))
        requests = [r for r in self.submitted if r['contractId'] == 'federation-work-sweep-global']
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0]['payload']['input'], requests[1]['payload']['input'])
        self.assertEqual(len({r['operationId'] for r in requests}), 1)
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM claims'), [])

    async def test_sweep_with_nothing_expired_submits_nothing(self):
        agent = await self.registered()
        await self.claim_both(agent)
        before = len(self.submitted)
        self.assertEqual(await self.hub._sweep_work_leases(), [])
        self.assertEqual([r for r in self.submitted[before:] if r['contractId'] == 'federation-work-sweep-global'], [])

    async def test_unfinished_sweep_is_recovered_even_when_nothing_expired(self):
        maintenance = self.hub._maintenance_for_work()
        identity = {'trigger': 'sweep', 'phase': 'sweep'}
        prepare = maintenance._prepare
        original = await maintenance._commands._owned_db(prepare, identity, 'sweep-global', {}, repeat=True)
        self.assertFalse(original['completed'])
        retained = await maintenance._commands._owned_db(prepare, identity, 'sweep-global', {}, repeat=True,
            skip_unneeded=True)
        self.assertEqual(retained, original)

    async def failed_spawn(self, *, missing_pane=False, replacement=False):
        checkout = str(self.database.parent / 'checkout')
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)', ('falcon', checkout, 'local'))
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'failed', 'cli': 'codex'}
        finish_spawn = self.maintenance.finish_spawn
        original = None
        rows = []
        replacement_rows = None

        async def prepare_obligations(result):
            nonlocal original, rows, replacement_rows
            await finish_spawn(result)
            original = await self.hub.db(self.hub.store.agent, 'falcon-worker-failed')
            rows = await self.claim_both(original)
            if replacement:
                def replace():
                    self.hub.store.set_state(original['session'], 'dead')
                    self.hub.store.register('falcon', 'worker', 'failed', 'codex', {},
                        handle='%81', pane_pid=23801, legacy='replacement-pane', token_sha='b' * 64)
                    self.hub.store.set_state(original['session'], 'ready')
                    for repository in ('falcon', 'other'):
                        self.hub.store.claim(original['session'], work_id=next(
                            row['id'] for row in rows if row['repo'] == repository))
                        self.hub.store.claim_path(original['session'], repository,
                            repository + '.txt', next(row['id'] for row in rows if row['repo'] == repository))
                    return {table: self.hub.store.q('SELECT * FROM ' + table)
                        for table in ('agents', 'work_items', 'claims', 'events', 'legacy_names')}
                replacement_rows = await self.hub.db(replace)

        message = ('registration changed after spawn' if replacement else
            'spawned but no pane found' if missing_pane else 'spawn failed: controlled failure')
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.maintenance, 'finish_spawn', side_effect=prepare_obligations), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0 if missing_pane else 1, stdout='', stderr='controlled failure')) as launch, \
                patch.object(self.hub.tp, 'handle', return_value=None) as handle:
            with self.assertRaisesRegex(server.HubError, message):
                await self.request('spawn', arguments, 'failed-original-spawn')
            self.assertIsNotNone(original, 'actual registration and retained provider result were not reached')
            self.assertEqual(launch.call_count, 1)
            if replacement:
                after = await self.hub.db(lambda: {table: self.hub.store.q('SELECT * FROM ' + table)
                    for table in replacement_rows})
                self.assertEqual(after, replacement_rows)
                self.assertEqual(after['agents'][0]['generation'], original['generation'] + 1)
                self.assertEqual(after['agents'][0]['state'], 'ready')
                return
            current = await self.hub.db(self.hub.store.agent, original['session'])
            self.assertEqual((current['generation'], current['state']), (original['generation'], 'dead'))
            returned = await self.hub.db(self.hub.store.q,
                'SELECT * FROM work_items WHERE id IN (?,?) ORDER BY repo', tuple(row['id'] for row in rows))
            self.assertTrue(all(row['state'] == 'ready' and row['claimed_by'] is None for row in returned))
            self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM claims'), [])
            mutations = [row for row in self.submitted
                if row['contractId'] in ('federation-work-register', 'federation-work-state')]
            with self.assertRaisesRegex(server.HubError, message):
                await self.request('spawn', arguments, 'failed-original-spawn')
            self.assertEqual([row for row in self.submitted
                if row['contractId'] in ('federation-work-register', 'federation-work-state')], mutations)
            self.assertEqual(launch.call_count, 1)
            self.assertEqual(handle.call_count, 2 if missing_pane else 0)

    async def test_failed_provider_returns_original_generation_leases_without_relaunch(self):
        await self.failed_spawn()

    async def test_missing_pane_returns_original_generation_leases_without_relaunch(self):
        await self.failed_spawn(missing_pane=True)

    async def test_failed_provider_preserves_replacement_registration_and_leases(self):
        await self.failed_spawn(replacement=True)

    async def reconstructed_maintenance_recovers_only_submitted_originals(self):
        with patch.object(self.maintenance, '_complete', side_effect=server.HubError('interrupted adapter completion')):
            with self.assertRaisesRegex(server.HubError, 'interrupted adapter completion'):
                await self.maintenance.register('falcon', 'worker', 'pending', 'codex', {},
                    handle='%82', pane_pid=23802)
        agent = await self.hub.db(self.hub.store.agent, 'falcon-worker-pending')
        self.assertEqual(agent['generation'], 1)

        def before_submission(previous, following):
            self.assertEqual((previous['state'], following['state']), ('prepared', 'uncertain'))
            raise server.HubError('interrupted before submission')

        with patch.object(self.maintenance._client, '_transition', side_effect=before_submission):
            with self.assertRaisesRegex(server.HubError, 'interrupted before submission'):
                await self.maintenance.state(agent, 'ready', phase='prepared-before-dispatch')

        async def phase(name):
            rows = await self.hub.db(self.hub.store.q,
                "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.phase')=?",
                (name,))
            self.assertEqual(len(rows), 1)
            return strict_loads(rows[0]['v'])

        submitted = await phase('register')
        prepared = await phase('prepared-before-dispatch')
        self.assertFalse(submitted['completed'])
        self.assertFalse(prepared['completed'])
        prepared_driver = await self.maintenance._commands._owned_db(self.maintenance._client._load,
            prepared['operationId'], prepared['command'], prepared['arguments'])
        self.assertEqual(prepared_driver['state'], 'prepared')
        roster = await self.hub.db(self.hub.store.q, 'SELECT * FROM agents')
        events = await self.hub.db(self.hub.store.q, 'SELECT * FROM events')
        previous, previous_client = self.maintenance, self.maintenance._client
        await previous.close()
        self.hub._work_maintenance = None
        self.maintenance = self.hub._maintenance_for_work()
        self.assertIsNot(self.maintenance, previous)
        self.assertIsNot(self.maintenance._client, previous_client)
        self.assertIs(self.maintenance._commands, previous._commands)
        start = len(self.submitted)
        original_caller = asyncio.current_task()
        pending = self.maintenance._commands._disclosures.get(original_caller)
        self.assertIsNotNone(pending, 'interrupted caller disclosure was not retained')
        await asyncio.sleep(max(0, (pending[1] - datetime.now(timezone.utc)).total_seconds()) + 0.02)
        self.assertGreaterEqual(datetime.now(timezone.utc), pending[1])

        async def poll():
            self.assertTrue(asyncio.current_task() is not original_caller)
            self.assertNotIn(asyncio.current_task(), self.maintenance._commands._disclosures)
            await self.maintenance.recover_pending()
            self.assertNotIn(asyncio.current_task(), self.maintenance._commands._disclosures)

        with patch.object(server.subprocess, 'run', side_effect=AssertionError('physical launch during recovery')):
            poll_task = asyncio.create_task(poll())
            try:
                await poll_task
            finally:
                await asyncio.gather(poll_task, return_exceptions=True)
        self.assertTrue(self.maintenance._commands._disclosures.get(original_caller) is pending,
            'maintenance recovery changed the interrupted caller minimum')
        recovered_calls = self.submitted[start:]
        self.assertTrue(recovered_calls)
        self.assertTrue(all(row['contractId'] in ('federation-work-inspect', 'federation-work-outcome')
            for row in recovered_calls))
        outcomes = [row['payload']['input'] for row in recovered_calls if row['contractId'] == 'federation-work-outcome']
        self.assertEqual(len(outcomes), len(self.resources))
        self.assertTrue(all(row['operationId'] == submitted['operationId'] for row in outcomes))
        self.assertEqual(await phase('register'), {**submitted, 'completed': True})
        self.assertEqual(await phase('prepared-before-dispatch'), prepared)
        self.assertEqual(await self.maintenance._commands._owned_db(self.maintenance._client._load,
            prepared['operationId'], prepared['command'], prepared['arguments']), prepared_driver)
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM agents'), roster)
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM events'), events)

    async def test_kill_preserves_current_state_change_and_one_event(self):
        agent = await self.registered()
        await self.claim_both(agent)
        await self.hub.db(self.hub.store.set_state, agent['session'], 'busy')
        with patch.object(self.hub, 'harness', return_value=True) as terminate:
            self.assertEqual(await self.hub._kill_agent(agent, 'original reason'), {'killed': agent['session']})
            self.assertEqual(await self.hub._kill_agent(agent, 'original reason'), {'killed': agent['session']})
        terminate.assert_called_once()
        self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'dead')
        events = await self.hub.db(self.hub.store.q,
            "SELECT * FROM events WHERE entity_id=? AND event='kill'", (agent['session'],))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['actor'], 'operator')

    async def test_kill_retry_after_termination_before_state_does_not_repeat_stop(self):
        agent = await self.registered()
        await self.claim_both(agent)
        arguments = {'session': agent['session'], 'reason': 'original interrupted kill'}
        apply_kill = self.hub._apply_kill
        interrupted = False

        async def interrupt_after_termination(original, reason):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                self.assertEqual(terminate.call_count, 1)
                raise server.HubError('injected interruption after termination')
            return await apply_kill(original, reason)

        with patch.object(self.hub, 'harness', return_value=True) as terminate, \
                patch.object(self.hub, '_apply_kill', side_effect=interrupt_after_termination):
            with self.assertRaisesRegex(server.HubError, 'injected interruption'):
                await self.request('kill', arguments, 'original-interrupted-kill')
            self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'ready')
            result = await self.request('kill', arguments, 'original-interrupted-kill')
            self.assertEqual(result, {'killed': agent['session']})
            self.assertEqual(terminate.call_count, 1, 'original operation repeated physical termination')

    async def test_ring_dead_uses_owner_and_metadata_receipt_does_not_repeat(self):
        agent = await self.registered()
        await self.claim_both(agent)
        receipt = deliver.Receipt(outcome='dead', reason='terminal gone')
        self.assertEqual(await self.hub._apply_ring(agent, receipt, ('', 0), False, None), {'dead': []})
        key = (await self.hub.db(self.hub.store.q1,
            "SELECT k FROM fed_state WHERE k LIKE 'hub-work-ring:%'"))['k']
        self.assertEqual(await self.hub.db(self.hub._record_ring, agent, receipt, ('', 0), False, None, key), {'dead': []})
        events = await self.hub.db(self.hub.store.q,
            "SELECT * FROM events WHERE entity='bell' AND entity_id=?", (agent['session'],))
        self.assertEqual(len(events), 1)
        self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'dead')

    async def test_notice_start_poll_and_close_hooks_use_existing_component(self):
        self.hub._start_work_maintenance()
        notices = self.hub._legacy_work_notices
        self.assertIs(notices._commands, self.hub._work_storage_commands)
        def completion():
            work = self.hub.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker',
                'Actual retained completion', federate=True, node='mac')
            self.hub.store.ingest_result({'origin_id': work['id'], 'state': 'done',
                'node': 'remote', 'by': 'original:worker\nnext', 'result': 'Original result'})
            return work
        work = await self.hub.db(completion)
        original = notices.poll
        async def stop_after_poll():
            self.assertEqual(await original(), {'completed': 1, 'pending': 0})
            self.hub.stop.set()
        with patch.object(notices, 'poll', side_effect=stop_after_poll) as poll, \
                patch.object(server.asyncio, 'sleep', new=AsyncMock()):
            await self.hub.work_notice_loop()
        poll.assert_awaited_once()
        # stop blocks fresh client calls, but the original worker can inspect
        # the already committed post before the normal test cleanup joins it.
        messages = await asyncio.wrap_future(self.hub.dbx.submit(self.hub.store.q,
            "SELECT * FROM messages WHERE kind='result' AND work_id=?", (work['id'],)))
        self.assertEqual(len(messages), 1)
        self.assertIn('(by nats:remote:original:worker\nnext)', messages[0]['body'])
        self.assertEqual(messages[0]['idem_key'], f"result:{work['id']}:done:virtual:operator")
        await self.hub._close_work_maintenance()
        self.assertTrue(notices._closed)
        self.assertTrue(self.maintenance._closed)


class HubMaintenanceRecoveryTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    """Isolate adapter recovery with one declared repository."""
    test_reconstructed_maintenance_recovers_only_submitted_originals = (
        HubWorkMaintenanceTests.reconstructed_maintenance_recovers_only_submitted_originals)

    def configure_channels(self, **kwargs):
        HubWorkMaintenanceTests.configure_channels(self, include_second=False, **kwargs)

    async def asyncSetUp(self):
        await HubWorkMaintenanceTests.asyncSetUp(self)
        self.assertEqual(len(self.resources), 1)


class HubReregistrationTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    """Check a next-generation caller with one declared repository."""
    request = HubWorkMaintenanceTests.request

    def configure_channels(self, **kwargs):
        HubWorkMaintenanceTests.configure_channels(self, include_second=False, **kwargs)

    async def asyncSetUp(self):
        await HubWorkMaintenanceTests.asyncSetUp(self)
        self.assertEqual(len(self.resources), 1)

    async def test_actual_adopt_reregisters_alias_terminal_token_and_obligations(self):
        prior_token = 'A' * 43
        prior_hash = server.hashlib.sha256(prior_token.encode()).hexdigest()
        def legacy_data():
            session = self.hub.store.adopt('prior-pane', 'falcon', 'worker', 'renewed', 'codex', {},
                '%70', 23700, prior_hash)
            self.hub.store.team_add('falcon', 'prior_team', [session])
            posted = self.hub.store.post('virtual:operator', 'agent:' + session, 'note', 'Prior incarnation only')
            work = self.hub.store.work_create('virtual:operator', 'falcon', 'agent:' + session, 'Prior lease')
            self.hub.store.claim(session, work_id=work['id'])
            self.hub.store.claim_path(session, 'falcon', 'prior.txt', work['id'])
            # Retain a legacy dead row whose old obligations need registration cleanup.
            self.hub.store.db.execute("UPDATE agents SET state='dead' WHERE session=?", (session,))
            return session, posted, work
        session, posted, work = await self.hub.db(legacy_data)
        token_path = Path(server.ROOT) / 'repos/falcon/agents/worker-renewed/run/token'
        token_path.parent.mkdir(parents=True)
        server.write_secret(str(token_path), prior_token)
        arguments = {'legacy': 'current-pane', 'repo': 'falcon', 'role': 'worker', 'agent': 'renewed', 'cli': 'codex'}
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.hub.tp, 'handle', return_value=('%71', 23701)) as handle, \
                patch.object(server.subprocess, 'run', side_effect=AssertionError('adoption launched a process')):
            result = await self.request('adopt', arguments, 'next-generation-adoption')
            token = token_path.read_bytes()
            mutations = [row for row in self.submitted
                if row['contractId'] in ('federation-work-register', 'federation-work-state')]
            self.assertEqual(await self.request('adopt', arguments, 'next-generation-adoption'), result)
            self.assertTrue(token_path.read_bytes() == token, 'recovery changed the original private token')
            self.assertEqual(handle.call_count, 1)
            self.assertEqual([row for row in self.submitted
                if row['contractId'] in ('federation-work-register', 'federation-work-state')], mutations)
        current = await self.hub.db(self.hub.store.agent, session)
        self.assertEqual((current['generation'], current['state'], current['term_name'], current['handle'], current['pane_pid']),
            (2, 'ready', 'current-pane', '%71', 23701))
        self.assertEqual(await self.hub.db(self.hub.store.agent, 'current-pane'), current)
        self.assertIsNone(await self.hub.db(self.hub.store.agent, 'prior-pane'))
        self.assertTrue(server.hashlib.sha256(token.strip()).hexdigest() == current['token_sha'],
            'installed private token does not match the new registration')
        self.assertTrue(current['token_sha'] != prior_hash, 'next generation retained the old token')
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM claims'), [])
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM team_members WHERE session=?', (session,)), [])
        delivery = await self.hub.db(self.hub.store.q1,
            'SELECT state,last_error FROM deliveries WHERE message_id=? AND recipient=?', (posted['id'], session))
        self.assertEqual(delivery, {'state': 'dead', 'last_error': 'recipient re-registered'})
        returned = await self.hub.db(self.hub.store.q1,
            'SELECT state,claimed_by,blocked_reason FROM work_items WHERE id=?', (work['id'],))
        self.assertEqual(returned, {'state': 'ready', 'claimed_by': None, 'blocked_reason': 'reregistered'})
        self.assertEqual(len(await self.hub.db(self.hub.store.q,
            "SELECT * FROM events WHERE entity_id=? AND event='registered'", (session,))), 2)
