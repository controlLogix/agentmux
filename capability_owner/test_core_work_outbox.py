"""SQLite drain scheduling checks; native tests qualify transport authority."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.store import Store
from identity.test_core_work_transport import original_work, route_fixture
from .core_work_client import CoreWorkOutbox


class CoreWorkOutboxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(str(Path(directory.name) / 'work.db'))
        self.addCleanup(self.store.db.close)
        self.route, _ = route_fixture()
        self.route['publisher'] = {'identityRef': {'id': 'publisher'}}
        source = SimpleNamespace(_pins={'database': {'path': str(Path(directory.name) / 'work.db')}})
        self.resource = SimpleNamespace(_store=self.store, repository='falcon',
            _journal=SimpleNamespace(binding=canonical_bytes({'id': 'work-one'})),
            _owner=SimpleNamespace(_source=source), _current=lambda: None)
        async def db(resource, function, *args):
            return function(*args)
        self.publisher = SimpleNamespace(publish=AsyncMock())
        selection = SimpleNamespace(policy={'coreWorkTransport': {'routes': [self.route]}})
        owner = SimpleNamespace(check=lambda: None, _selection=selection, _identity=object(),
            _routes={self.route['routeId']: (self.resource, object())},
            _publishers={self.route['routeId']: self.publisher}, _dispatcher=SimpleNamespace(_db=db))
        self.outbox = CoreWorkOutbox(owner)
        # Scheduling is isolated from credential admission here. The production
        # route parser, SQLite retention and atomic sent transition remain real.
        authority = patch('capability_owner.core_work_client.check_authority',
            new=AsyncMock(side_effect=lambda *a, **k: (object(), datetime.now(timezone.utc) + timedelta(seconds=5))))
        authority.start()
        self.addCleanup(authority.stop)

    def insert(self, number, *, repository='falcon'):
        item = copy.deepcopy(original_work())
        item.update(origin_node='mac', origin_id='outgoing-' + str(number), origin='mac:outgoing-' + str(number))
        item['work'].update(repo=repository, target='role:' + repository + '/worker')
        self.store.db.execute('INSERT INTO nats_outbox(subject,payload,created) VALUES (?,?,?)',
            ('am.work.' + repository + '.worker', canonical_bytes(item).decode(), 'original-created'))
        return self.store.q1('SELECT * FROM nats_outbox ORDER BY seq DESC LIMIT 1')

    async def test_unmatched_window_does_not_starve_later_selected_publication(self):
        unrelated = [self.insert(i, repository='other') for i in range(32)]
        selected = self.insert(32)
        await self.outbox.drain()
        await self.outbox.drain()
        self.publisher.publish.assert_awaited_once()
        call = self.publisher.publish.await_args
        self.assertEqual(call.args, (selected['subject'], selected['payload'].encode()))
        self.assertEqual(self.store.q('SELECT * FROM nats_outbox WHERE seq<? ORDER BY seq', (selected['seq'],)), unrelated)
        completed = self.store.q1('SELECT * FROM nats_outbox WHERE seq=?', (selected['seq'],))
        self.assertIsNotNone(completed['sent'])
        self.assertEqual({k: v for k, v in completed.items() if k != 'sent'},
            {k: v for k, v in selected.items() if k != 'sent'})
        await self.outbox.drain()
        await self.outbox.drain()
        self.publisher.publish.assert_awaited_once()

    async def test_expired_original_stays_unresolved_without_blocking_later_publication(self):
        expired = self.insert(0)
        row = {k: expired[k] for k in ('seq', 'subject', 'payload', 'created')}
        key, retained = self.outbox._retain(self.resource, row, self.route,
            datetime.now(timezone.utc) + timedelta(seconds=5))
        retained.update(state='uncertain', deadline=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
        saved = canonical_bytes(retained).decode()
        self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (saved, key))
        selected = self.insert(1)
        await self.outbox.drain()
        self.publisher.publish.assert_awaited_once()
        self.assertEqual(self.publisher.publish.await_args.args,
            (selected['subject'], selected['payload'].encode()))
        self.assertEqual(self.store.q1('SELECT * FROM nats_outbox WHERE seq=?', (expired['seq'],)), expired)
        self.assertEqual(self.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))['v'], saved)
        self.assertIsNotNone(self.store.q1('SELECT sent FROM nats_outbox WHERE seq=?', (selected['seq'],))['sent'])
        records = self.store.q("SELECT v FROM fed_state WHERE k LIKE 'core-work-outbox:%'")
        self.assertEqual(len(records), 2)
        self.assertEqual(sum(strict_loads(record['v'])['state'] == 'confirmed' for record in records), 1)
        self.assertEqual(self.outbox._last_error, 'core_work_publication_unconfirmed')

    async def test_new_arrivals_do_not_prevent_revisiting_the_original_uncertain_event(self):
        original = self.insert(0)
        for i in range(1, 33):
            self.insert(i, repository='other')
        later = self.insert(33)
        self.publisher.publish.side_effect = [TimeoutError(), None, None]
        with self.assertRaises(TimeoutError):
            await self.outbox.drain()
        retained = strict_loads(self.store.q1("SELECT v FROM fed_state WHERE k LIKE 'core-work-outbox:%'")['v'])
        self.assertEqual(retained['state'], 'uncertain')
        for i in range(34, 66):
            self.insert(i, repository='other')
        await self.outbox.drain()
        await self.outbox.drain()
        self.assertEqual([call.args for call in self.publisher.publish.await_args_list], [
            (original['subject'], original['payload'].encode()),
            (later['subject'], later['payload'].encode()),
            (original['subject'], original['payload'].encode())])
        recovered = [strict_loads(row['v']) for row in self.store.q(
            "SELECT v FROM fed_state WHERE k LIKE 'core-work-outbox:%'")
            if strict_loads(row['v'])['row']['seq'] == original['seq']][0]
        self.assertEqual(recovered, {**retained, 'state': 'confirmed'})
        self.assertEqual(self.publisher.publish.await_args_list[0].kwargs['expires'],
            self.publisher.publish.await_args_list[2].kwargs['expires'])

    async def test_join_finishes_after_this_drain_without_waiting_for_its_parent_loop(self):
        self.insert(0)
        entered, release, keep_parent = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def publish(*args, **kwargs):
            entered.set()
            await release.wait()
        self.publisher.publish.side_effect = publish
        async def parent():
            await self.outbox.drain()
            await keep_parent.wait()
        original = asyncio.create_task(parent())
        joining = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            joining = asyncio.create_task(self.outbox.join())
            await asyncio.sleep(0)
            self.assertFalse(joining.done())
            release.set()
            done, pending = await asyncio.wait({joining}, timeout=1)
            self.assertEqual(done, {joining}, 'Drain join must not retain the long-lived caller task')
            self.assertEqual(pending, set())
            joining.result()
            self.assertFalse(original.done())
        finally:
            release.set()
            keep_parent.set()
            await asyncio.gather(original, *(() if joining is None else (joining,)), return_exceptions=True)

    async def test_cancelled_join_observer_cannot_release_an_unfinished_drain(self):
        self.insert(0)
        entered, release = asyncio.Event(), asyncio.Event()
        async def publish(*args, **kwargs):
            entered.set()
            await release.wait()
        self.publisher.publish.side_effect = publish
        original = asyncio.create_task(self.outbox.drain())
        joining = repeated = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            joining = asyncio.create_task(self.outbox.join())
            await asyncio.sleep(0)
            joining.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await joining
            self.assertFalse(original.done())
            self.assertTrue(self.outbox._active)
            self.assertTrue(all(not marker.done() for marker in self.outbox._active))
            repeated = asyncio.create_task(self.outbox.join())
            await asyncio.sleep(0)
            self.assertFalse(repeated.done())
            release.set()
            await asyncio.wait_for(asyncio.shield(repeated), 1)
            await original
            self.assertEqual(self.outbox._active, set())
        finally:
            release.set()
            await asyncio.gather(original, *(() if repeated is None else (repeated,)), return_exceptions=True)
