"""First lifecycle disclosure keeps current authority and original outcomes."""
import asyncio
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import server
from identity.authority import AuthoritySnapshot
from .test_hub_work_maintenance import HubWorkMaintenanceTests
from .test_work_source import SelectedWorkSourceFixture


class HubLifecycleDisclosureTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = HubWorkMaintenanceTests.configure_channels
    asyncSetUp = HubWorkMaintenanceTests.asyncSetUp
    request = HubWorkMaintenanceTests.request

    async def prepare(self):
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)',
            ('falcon', str(self.database.parent / 'checkout'), 'local'))

    @contextmanager
    def provider(self):
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='controlled result', stderr='')) as launch, \
                patch.object(self.hub.tp, 'handle', return_value=('%61', 23601)) as handle:
            yield launch, handle

    def arguments(self, verb):
        value = {'repo': 'falcon', 'role': 'worker', 'agent': verb, 'cli': 'codex'}
        return value if verb == 'spawn' else {**value, 'legacy': 'legacy-pane'}

    def revoke(self, action):
        record = strict_loads(self.snapshot.record)
        grants = strict_loads(self.resources[0]._legacy_actors[0].grants)
        grant = next(g for g in record['state']['grants'] if g['ref'] == grants['federation-work-' + action])
        self.assertEqual(grant['status'], 'active')
        grant['status'] = 'revoked'
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)

    async def retained(self, verb):
        rows = await self.hub.db(self.hub.store.q,
            "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.phase')=?",
            (verb + '-result',))
        self.assertEqual(len(rows), 1)
        value = strict_loads(rows[0]['v'])
        self.assertEqual(value['state'], 'completed')
        return value['result']

    async def revoked_result(self, verb, action):
        await self.prepare()
        original_snapshot = self.snapshot
        original_save = self.maintenance.save_result
        saved = False

        async def revoke_after_save(kind, result):
            nonlocal saved
            await original_save(kind, result)
            saved = True
            self.assertLess(server.time.monotonic(), self.maintenance._requests[asyncio.current_task()]['expires'])
            self.revoke(action)

        arguments = self.arguments(verb)
        with self.provider() as (launch, handle):
            with patch.object(self.maintenance, 'save_result', side_effect=revoke_after_save):
                with self.assertRaises(ContractError) as failure:
                    await self.request(verb, arguments, 'retained-' + verb)
                self.assertTrue(saved, 'post-save revocation was not reached: ' + failure.exception.code)
            original = await self.retained(verb)
            token = Path(server.ROOT) / ('repos/falcon/agents/worker-' + verb + '/run/token')
            original_token = token.read_bytes()
            submitted = len([v for v in self.submitted if v['contractId'] in
                ('federation-work-register', 'federation-work-state')])
            self.snapshot = original_snapshot
            replay = await self.request(verb, arguments, 'retained-' + verb)
            self.assertEqual(replay, original)
            self.assertEqual(token.read_bytes(), original_token)
            self.assertEqual(len([v for v in self.submitted if v['contractId'] in
                ('federation-work-register', 'federation-work-state')]), submitted)
            self.assertEqual(launch.call_count, 1 if verb == 'spawn' else 0)
            self.assertEqual(handle.call_count, 1)

    async def test_spawn_registration_revocation_retains_exact_authorized_recovery(self):
        await self.revoked_result('spawn', 'register')

    async def test_adopt_recovery_refuses_register_revocation_between_original_confirmations(self):
        await self.prepare()
        arguments = self.arguments('adopt')
        initial_code = 'success'
        with self.provider() as (launch, handle):
            try:
                await self.request('adopt', arguments, 'between-original-confirmations')
            except (server.HubError, ContractError) as error:
                initial_code = error.code if isinstance(error, ContractError) else 'hub_refusal'
            retained = await self.retained('adopt')
            rows = await self.hub.db(self.hub.store.q,
                "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.operationId')=? "
                "AND json_extract(v,'$.identity.phase') IN ('register','adopt-ready')",
                ('between-original-confirmations',))
            records = [strict_loads(row['v']) for row in rows]
            self.assertEqual(len(records), 2)
            self.assertTrue(all(record['completed'] for record in records))
            phases = {record['identity']['phase']: record['operationId'] for record in records}
            counts_before = len([v for v in self.submitted if v['contractId'] in
                ('federation-work-register', 'federation-work-state')])
            confirm = self.maintenance._client.confirm_registration
            owner = self.resources[0]._lifecycle_owner
            ready_original = owner._ready_original
            deadline = None
            aggregate_called = False
            revoked = False

            async def aggregate(operation_id, *, ready_operation_id, **kwargs):
                nonlocal deadline, aggregate_called
                self.assertEqual(operation_id, phases['register'])
                self.assertEqual(ready_operation_id, phases['adopt-ready'])
                deadline = self.maintenance._requests[asyncio.current_task()]['expires']
                aggregate_called = True
                return await confirm(operation_id, ready_operation_id=ready_operation_id, **kwargs)

            def revoke_between(resource, registration, query):
                nonlocal revoked
                self.assertEqual(registration['envelope']['operation']['operationId'], phases['register'])
                self.assertEqual(query['operationId'], phases['adopt-ready'])
                self.assertIsNotNone(deadline)
                self.assertLess(server.time.monotonic(), deadline, 'fresh recovery expired at original owner reads')
                if not revoked:
                    self.revoke('register')
                    revoked = True
                return ready_original(resource, registration, query)

            failure = None
            result = None
            with patch.object(self.maintenance._client, 'confirm_registration', side_effect=aggregate), \
                    patch.object(owner, '_ready_original', side_effect=revoke_between):
                try:
                    result = await self.request('adopt', arguments, 'between-original-confirmations')
                except (server.HubError, ContractError) as error:
                    failure = error
            counts_after = len([v for v in self.submitted if v['contractId'] in
                ('federation-work-register', 'federation-work-state')])
            print('Adopt recovery boundary:', {'initial': initial_code, 'reachedAggregate': aggregate_called,
                'reachedOwnerReadHook': revoked, 'failure': None if failure is None else
                    failure.code if isinstance(failure, ContractError) else 'hub_refusal',
                'mutationCountBefore': counts_before, 'mutationCountAfter': counts_after,
                'providerCount': launch.call_count, 'adoptionHandleCount': handle.call_count})
            self.assertEqual(counts_after, counts_before)
            self.assertEqual(launch.call_count, 0)
            self.assertEqual(handle.call_count, 1)
            self.assertTrue(aggregate_called)
            self.assertTrue(revoked)
            if result is not None:
                self.assertEqual(result, retained)
            self.assertIsInstance(failure, ContractError,
                'adoption disclosed after original registration permission was revoked between confirmations')

    async def source_loss(self, verb):
        await self.prepare()
        confirm = self.maintenance.confirm_result
        source = self.hub._work_source_binding
        lost = False

        async def lose_after_confirmation(kind, result):
            nonlocal lost
            await confirm(kind, result)
            source.closed = True
            lost = True

        with self.provider() as (launch, handle):
            try:
                with patch.object(self.maintenance, 'confirm_result', side_effect=lose_after_confirmation):
                    with self.assertRaises(ContractError):
                        await self.request(verb, self.arguments(verb), 'source-' + verb)
            finally:
                source.closed = False
            self.assertTrue(lost, 'source-loss hook was not reached after final confirmation')
            self.assertEqual(launch.call_count, 1 if verb == 'spawn' else 0)
            self.assertEqual(handle.call_count, 1)
        await self.retained(verb)

    async def expire_at(self, boundary):
        await self.prepare()
        original = getattr(self.maintenance, boundary)

        async def held(kind, result):
            await original(kind, result)
            request = self.maintenance._requests[asyncio.current_task()]
            remaining = request['expires'] - server.time.monotonic()
            self.assertGreater(remaining, 0)
            await asyncio.sleep(remaining + 0.02)

        with self.provider() as (launch, _):
            with patch.object(self.maintenance, boundary, side_effect=held):
                with self.assertRaisesRegex(server.HubError, 'expired'):
                    await self.request('spawn', self.arguments('spawn'), 'expiry-' + boundary)
            retained = await self.retained('spawn')
            self.assertEqual(await self.request('spawn', self.arguments('spawn'), 'expiry-' + boundary), retained)
            self.assertEqual(launch.call_count, 1)

    async def cancel_and_close(self, boundary):
        await self.prepare()
        entered, release = asyncio.Event(), asyncio.Event()
        original = getattr(self.maintenance, boundary)

        async def held(kind, result):
            await original(kind, result)
            entered.set()
            await release.wait()

        with self.provider() as (launch, _), patch.object(self.maintenance, boundary, side_effect=held):
            caller = asyncio.create_task(self.request('spawn', self.arguments('spawn'), 'cancel-' + boundary))
            closer = None
            try:
                await asyncio.wait_for(entered.wait(), 8)
                caller.cancel()
                await asyncio.sleep(0)
                caller.cancel()
                closer = asyncio.create_task(self.hub._close_work_maintenance())
                await asyncio.sleep(0.02)
                self.assertFalse(caller.done())
                self.assertFalse(closer.done())
                self.assertFalse(self.maintenance._client._closed)
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await caller
                await closer
                self.assertTrue(self.maintenance._client._closed)
                self.assertEqual(launch.call_count, 1)
                self.assertFalse(self.hub._maintenance_calls)
                await self.retained('spawn')
            finally:
                release.set()
                await asyncio.gather(caller, *(() if closer is None else (closer,)), return_exceptions=True)

class HubInitialDisclosureTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    """Isolate initial lifecycle boundaries with one declared repository."""
    request = HubWorkMaintenanceTests.request
    prepare = HubLifecycleDisclosureTests.prepare
    provider = HubLifecycleDisclosureTests.provider
    arguments = HubLifecycleDisclosureTests.arguments
    revoke = HubLifecycleDisclosureTests.revoke
    retained = HubLifecycleDisclosureTests.retained
    revoked_result = HubLifecycleDisclosureTests.revoked_result
    source_loss = HubLifecycleDisclosureTests.source_loss
    expire_at = HubLifecycleDisclosureTests.expire_at
    cancel_and_close = HubLifecycleDisclosureTests.cancel_and_close

    async def asyncSetUp(self):
        await HubWorkMaintenanceTests.asyncSetUp(self)
        self.assertEqual(len(self.resources), 1)

    def configure_channels(self, **kwargs):
        HubWorkMaintenanceTests.configure_channels(self, include_second=False, **kwargs)

    async def test_initial_adopt_readiness_revocation_retains_exact_authorized_recovery(self):
        await self.revoked_result('adopt', 'state')

    async def test_initial_adopt_source_loss_at_final_synchronous_disclosure_refuses(self):
        await self.source_loss('adopt')

    async def test_spawn_source_loss_at_final_synchronous_disclosure_refuses(self):
        await self.source_loss('spawn')

    async def test_same_id_changed_input_refuses_before_another_physical_effect(self):
        await self.prepare()
        with self.provider() as (launch, _):
            await self.request('spawn', self.arguments('spawn'), 'changed-input')
            with self.assertRaisesRegex(server.HubError, 'different original request'):
                await self.request('spawn', {**self.arguments('spawn'), 'agent': 'changed'}, 'changed-input')
            self.assertEqual(launch.call_count, 1)

    async def test_expiry_after_result_retention_keeps_original_recoverable(self):
        await self.expire_at('save_result')

    async def test_expiry_after_final_confirmation_refuses_without_renewal(self):
        await self.expire_at('confirm_result')

    async def test_repeated_cancel_during_retention_joins_before_close(self):
        await self.cancel_and_close('save_result')

    async def test_repeated_cancel_during_final_confirmation_joins_before_close(self):
        await self.cancel_and_close('confirm_result')
