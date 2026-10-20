"""Selected adoption publishes its original terminal before live observation."""
import asyncio
from contextvars import Context
from unittest.mock import AsyncMock, patch

from hub import server
from .test_hub_work_maintenance import HubReregistrationTests


class AdoptPublicationTests(HubReregistrationTests):
    async def observe_once(self, alive):
        original_sleep = asyncio.sleep
        observer = None
        async def sleep(seconds, *args, **kwargs):
            if asyncio.current_task() is observer and seconds == 3:
                raise asyncio.CancelledError()
            return await original_sleep(seconds, *args, **kwargs)
        with patch.object(self.hub.tp, 'alive', side_effect=alive), \
                patch.object(self.hub.tp, 'output_mark', return_value=None), \
                patch.object(self.hub, 'harness', return_value=True), \
                patch.object(self.hub, '_tell_operator', new=AsyncMock()), \
                patch.object(server.asyncio, 'sleep', side_effect=sleep):
            observer = asyncio.create_task(self.hub.live_loop(), context=Context())
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(asyncio.shield(observer), 4)
            finally:
                if not observer.done():
                    observer.cancel()
                await asyncio.gather(observer, return_exceptions=True)

    async def test_adopt_publication_precedes_live_observation_and_replays_original(self):
        arguments = {'legacy': 'original-adopted-pane', 'repo': 'falcon',
            'role': 'worker', 'agent': 'published', 'cli': 'shell'}
        original_register = self.maintenance.register
        published, observed = [], []
        observers = []
        loop = asyncio.get_running_loop()
        async def register(*args, **kwargs):
            result = await original_register(*args, **kwargs)
            # The selected owner has committed, but Hub.adopt has not received
            # the result or reached its separate ready/metadata steps.
            published.append(await self.hub.db(self.hub.store.agent, result[0]))
            self.assertEqual(published[-1]['term_name'], arguments['legacy'])
            inspected = asyncio.Event()
            def alive(terminal):
                observed.append(terminal)
                loop.call_soon_threadsafe(inspected.set)
                return terminal == arguments['legacy']
            # Liveness reads the published terminal while adoption owns its
            # turn; its state mutation may finish only after that turn releases.
            observers.append(asyncio.create_task(self.observe_once(alive), context=Context()))
            await asyncio.wait_for(inspected.wait(), 3)
            return result
        failure = None
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.hub.tp, 'handle', return_value=('%71', 23701)) as handle, \
                patch.object(self.maintenance, 'register', side_effect=register):
            try:
                result = await self.request('adopt', arguments, 'publication-original')
            except Exception as error:
                failure = error
            finally:
                if observers:
                    await asyncio.wait_for(asyncio.gather(*observers), 5)
            self.assertEqual(len(published), 1)
            self.assertEqual(published[0]['term_name'], arguments['legacy'],
                f'published terminal was absent; adoption outcome: {failure!r}')
            self.assertEqual(observed, [arguments['legacy']])
            if failure is not None:
                raise failure
            mutations = [row for row in self.submitted if row['contractId'] in
                ('federation-work-register', 'federation-work-state')]
            self.assertEqual(await self.request('adopt', arguments, 'publication-original'), result)
            self.assertEqual([row for row in self.submitted if row['contractId'] in
                ('federation-work-register', 'federation-work-state')], mutations)
            handle.assert_called_once()
        row = await self.hub.db(self.hub.store.agent, result['session'])
        self.assertEqual((row['generation'], row['state'], row['term_name'], row['handle'], row['pane_pid']),
            (1, 'ready', arguments['legacy'], '%71', 23701))
        events = await self.hub.db(self.hub.store.q,
            "SELECT event FROM events WHERE entity_id=? AND event IN ('registered','dead')",
            (row['session'],))
        self.assertEqual(events, [{'event': 'registered'}])

    async def test_real_missing_terminal_marks_dead_but_stale_observation_cannot(self):
        arguments = {'legacy': 'original-live-pane', 'repo': 'falcon',
            'role': 'worker', 'agent': 'observed', 'cli': 'shell'}
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.hub.tp, 'handle', return_value=('%72', 23702)):
            result = await self.request('adopt', arguments, 'observation-original')
        original = await self.hub.db(self.hub.store.agent, result['session'])
        await self.hub.db(self.hub.store.set_handle, original['session'], '%73', 23703)
        self.assertFalse(await self.hub._apply_observed_state(original, 'dead', 'stale terminal'))
        current = await self.hub.db(self.hub.store.agent, original['session'])
        self.assertEqual(current['state'], 'ready')
        terminals = []
        def gone(terminal):
            terminals.append(terminal)
            return False
        await self.observe_once(gone)
        self.assertEqual(terminals, [arguments['legacy']])
        final = await self.hub.db(self.hub.store.agent, original['session'])
        self.assertEqual((final['state'], final['handle'], final['pane_pid']), ('dead', '%73', 23703))
        events = await self.hub.db(self.hub.store.q,
            "SELECT event FROM events WHERE entity_id=? AND event='dead'", (original['session'],))
        self.assertEqual(events, [{'event': 'dead'}])
