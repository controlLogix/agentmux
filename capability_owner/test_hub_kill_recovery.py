"""The original Hub kill effect survives interrupted lifecycle completion."""
import asyncio
import threading
import unittest
from unittest.mock import Mock, patch

from agentmux_contracts import ContractError, strict_loads
from hub import server
from identity.authority import AuthoritySnapshot
from agentmux_contracts import canonical_bytes
from .test_hub_work_maintenance import HubWorkMaintenanceTests
from .test_work_source import SelectedWorkSourceFixture
from .work_maintenance import HubWorkMaintenance


class HubKillRecoveryTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = HubWorkMaintenanceTests.configure_channels
    asyncSetUp = HubWorkMaintenanceTests.asyncSetUp
    request = HubWorkMaintenanceTests.request
    registered = HubWorkMaintenanceTests.registered
    claim_both = HubWorkMaintenanceTests.claim_both

    async def records(self):
        rows = await self.hub.db(self.hub.store.q,
            "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.phase')='kill-process'")
        return [strict_loads(row['v']) for row in rows]

    def reconstruct_adapter(self):
        # Reconstruct only the caller adapter over the same original durable DB.
        self.maintenance._closed = True
        self.maintenance = HubWorkMaintenance(self.hub, self.hub._work_storage_commands)
        self.hub._work_maintenance = self.maintenance

    async def reconstruct_hub(self):
        original = self.hub
        await original._close_work_maintenance()
        await self.close_hub()
        with patch.object(server, 'load_toml', return_value={'node': 'mac'}):
            self.hub = server.Hub(work_sessions=self.sessions)
        self.assertIsNot(self.hub, original)
        self.assertIsNot(self.hub.store, original.store)
        self.assertIsNot(self.hub.store.db, original.store.db)
        self.assertIsNot(self.hub.dbx, original.dbx)
        self.assertIsNot(self.hub.io, original.io)
        await self.hub._work_source_binding.activate()
        self.maintenance = self.hub._maintenance_for_work()
        self.addAsyncCleanup(self.hub._close_work_maintenance)

    async def test_confirmed_original_recovers_after_hub_store_and_worker_reconstruction(self):
        agent = await self.registered()
        args = {'session': agent['session'], 'reason': 'confirmed across Hub lifetimes'}
        terminate = Mock(return_value=True)
        with patch.object(self.hub, 'harness', terminate), \
                patch.object(self.hub, '_apply_kill', side_effect=server.HubError('injected application failure')):
            with self.assertRaisesRegex(server.HubError, 'injected application'):
                await self.request('kill', args, 'hub-reconstructed-kill')
        record = (await self.records())[0]
        self.assertEqual(record['state'], 'confirmed')
        await self.reconstruct_hub()
        self.assertEqual((await self.records())[0], record)
        with patch.object(self.hub, 'harness', terminate):
            self.assertEqual(await self.request('kill', args, 'hub-reconstructed-kill'), {'killed': agent['session']})
        terminate.assert_called_once()
        events = await self.hub.db(self.hub.store.q,
            "SELECT * FROM events WHERE entity_id=? AND event='kill'", (agent['session'],))
        self.assertEqual(len(events), 1)

    async def test_uncertain_original_refuses_after_hub_store_and_worker_reconstruction(self):
        agent = await self.registered()
        args = {'session': agent['session']}
        terminate = Mock(return_value=False)
        with patch.object(self.hub, 'harness', terminate):
            with self.assertRaisesRegex(server.HubError, 'termination unconfirmed'):
                await self.request('kill', args, 'hub-uncertain-kill')
        record = (await self.records())[0]
        self.assertEqual(record['state'], 'uncertain')
        await self.reconstruct_hub()
        self.assertEqual((await self.records())[0], record)
        with patch.object(self.hub, 'harness', terminate):
            with self.assertRaisesRegex(server.HubError, 'will not be repeated'):
                await self.request('kill', args, 'hub-uncertain-kill')
        terminate.assert_called_once()
        self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'ready')

    async def test_confirmed_original_survives_adapter_reconstruction_and_changed_request_refuses(self):
        agent = await self.registered()
        args = {'session': agent['session'], 'reason': 'retained original'}
        with patch.object(self.hub, 'harness', return_value=True) as terminate:
            with patch.object(self.hub, '_apply_kill', side_effect=server.HubError('injected application failure')):
                with self.assertRaisesRegex(server.HubError, 'injected application'):
                    await self.request('kill', args, 'reconstructed-kill')
            self.assertEqual((await self.records())[0]['state'], 'confirmed')
            self.reconstruct_adapter()
            self.assertEqual(await self.request('kill', args, 'reconstructed-kill'), {'killed': agent['session']})
            with self.assertRaisesRegex(server.HubError, 'different original request'):
                await self.request('kill', {**args, 'reason': 'changed'}, 'reconstructed-kill')
            terminate.assert_called_once()

    async def test_uncertain_physical_result_never_repeats_or_marks_dead_after_reconstruction(self):
        agent = await self.registered()
        args = {'session': agent['session']}
        with patch.object(self.hub, 'harness', return_value=False) as terminate:
            with self.assertRaisesRegex(server.HubError, 'termination unconfirmed'):
                await self.request('kill', args, 'uncertain-kill')
            self.reconstruct_adapter()
            with self.assertRaisesRegex(server.HubError, 'will not be repeated'):
                await self.request('kill', args, 'uncertain-kill')
            terminate.assert_called_once()
        self.assertEqual((await self.records())[0]['state'], 'uncertain')
        self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'ready')

    async def test_failed_confirmation_write_retains_uncertainty_and_no_second_effect(self):
        agent = await self.registered()
        args = {'session': agent['session']}
        with patch.object(self.hub, 'harness', return_value=True) as terminate:
            with patch.object(self.maintenance, 'confirm_kill', side_effect=OSError('injected persistence failure')):
                with self.assertRaises(OSError):
                    await self.request('kill', args, 'write-failed-kill')
            with self.assertRaisesRegex(server.HubError, 'will not be repeated'):
                await self.request('kill', args, 'write-failed-kill')
            terminate.assert_called_once()
        self.assertEqual((await self.records())[0]['state'], 'uncertain')
        self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'ready')

    async def test_replacement_after_marker_refuses_at_original_dispatch_boundary(self):
        agent = await self.registered()
        begin = self.maintenance.begin_kill

        async def replace_after_marker(original, reason):
            record = await begin(original, reason)
            await self.hub.db(self.hub.store.db.execute,
                'UPDATE agents SET generation=generation+1 WHERE session=?', (agent['session'],))
            return record

        with patch.object(self.maintenance, 'begin_kill', side_effect=replace_after_marker), \
                patch.object(self.hub, 'harness', return_value=True) as terminate:
            with self.assertRaisesRegex(server.HubError, 'original termination target'):
                await self.request('kill', {'session': agent['session']}, 'replaced-kill')
            terminate.assert_not_called()
        self.assertEqual((await self.records())[0]['state'], 'uncertain')

    async def test_expiry_after_marker_refuses_before_harness(self):
        agent = await self.registered()
        begin = self.maintenance.begin_kill

        async def expire_after_marker(original, reason):
            record, physical, expires = await begin(original, reason)
            self.assertIsNotNone(expires)
            return record, physical, server.time.monotonic() - 1

        with patch.object(self.maintenance, 'begin_kill', side_effect=expire_after_marker), \
                patch.object(self.hub, 'harness', return_value=True) as terminate:
            with self.assertRaisesRegex(server.HubError, 'request expired'):
                await self.request('kill', {'session': agent['session']}, 'expired-kill')
            terminate.assert_not_called()
        self.assertEqual((await self.records())[0]['state'], 'uncertain')

    async def test_confirmed_stop_does_not_bypass_current_state_authority(self):
        agent = await self.registered()
        await self.claim_both(agent)
        args = {'session': agent['session']}
        with patch.object(self.hub, 'harness', return_value=True) as terminate:
            with patch.object(self.hub, '_apply_kill', side_effect=server.HubError('injected application failure')):
                with self.assertRaises(server.HubError):
                    await self.request('kill', args, 'revoked-kill')
            record = strict_loads(self.snapshot.record)
            grants = strict_loads(self.resources[0]._legacy_actors[0].grants)
            next(g for g in record['state']['grants'] if g['ref'] == grants['federation-work-state'])['status'] = 'revoked'
            self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
            with self.assertRaises(ContractError):
                await self.request('kill', args, 'revoked-kill')
            terminate.assert_called_once()
        self.assertEqual((await self.hub.db(self.hub.store.agent, agent['session']))['state'], 'ready')
        self.assertEqual(len(await self.hub.db(self.hub.store.q, 'SELECT * FROM claims')), 2)

    async def test_repeated_cancellation_and_close_join_confirmation_and_state(self):
        agent = await self.registered()
        entered, release = threading.Event(), threading.Event()
        confirmed = asyncio.Event()
        original_confirm = self.maintenance.confirm_kill

        def terminate(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise AssertionError('original termination was not released')
            return True

        async def confirm(record):
            await original_confirm(record)
            confirmed.set()

        with patch.object(self.hub, 'harness', side_effect=terminate) as physical, \
                patch.object(self.maintenance, 'confirm_kill', side_effect=confirm):
            request = asyncio.create_task(self.request('kill', {'session': agent['session']}, 'cancelled-kill'))
            close = None
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 10))
                request.cancel()
                request.cancel()
                close = asyncio.create_task(self.maintenance.close())
                await asyncio.sleep(0)
                self.assertFalse(close.done())
                self.assertFalse(self.maintenance._closed)
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await request
                if close is not None:
                    await close
            physical.assert_called_once()
        self.assertTrue(confirmed.is_set())
        self.assertTrue(self.maintenance._closed)
        self.assertFalse(self.hub.kills)
        # Maintenance is closed only after the original state/event work joins.
        current = await asyncio.wrap_future(self.hub.dbx.submit(self.hub.store.agent, agent['session']))
        self.assertEqual(current['state'], 'dead')
