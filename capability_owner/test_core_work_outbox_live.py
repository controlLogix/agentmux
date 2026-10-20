"""Real owner outbox delivery, original publication recovery and result routing."""
import asyncio
import copy
from datetime import datetime, timezone
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.core_work_transport import CoreWorkPublisher
from hub.fed.session import FederationSession
from identity.application_service_selection import ApplicationServiceSelection
from state_owner.ledger import OwnerBinding
from .core_work import CoreWorkOwner
from .messages import MessageActor
from .selected_storage import SelectedStorageHost
from .test_core_work_live import LiveCoreWorkTests
from .work import WorkStorageResource
from .work_host import SelectedWorkDomain
from .work_legacy import LegacyWorkActor


class LiveCoreWorkOutboxTests(LiveCoreWorkTests):
    async def sender(self):
        host = SelectedStorageHost(self.core_publisher._selection, identity=self.identity)
        self.addAsyncCleanup(host.close, timeout=None)
        await host._work(host._selection.policy['storage']['work'])
        resource, = host._resources
        owner = CoreWorkOwner(host._selection, self.identity, (resource,))
        host._core_work_owners.append(owner)
        await owner.start()
        return host, owner, resource

    async def rows(self, resource, query, args=(), *, predicate):
        async with asyncio.timeout(5):
            while True:
                rows = await resource._owner.db(resource._store.q, query, args)
                if predicate(rows):
                    return rows
                await asyncio.sleep(.025)

    async def test_actual_outbox_flush_loss_restarts_with_original_wire_event_and_deadline(self):
        calls, wire, active = [], [], []
        original_publish = CoreWorkPublisher.publish
        async def observe(publisher, subject, body, *, expires=None):
            calls.append((subject, body, expires))
            send, flush = publisher._connection.publish, publisher._connection.flush
            async def actual_send(subject, body, **kwargs):
                wire.append((subject, body, copy.deepcopy(kwargs)))
                return await send(subject, body, **kwargs)
            async def lose_confirmed_flush(**kwargs):
                await flush(**kwargs)
                active[0].begin_policy_pause()
                raise TimeoutError('Controlled loss after the actual broker flush')
            with patch.object(publisher._connection, 'publish', side_effect=actual_send):
                if len(calls) == 1:
                    with patch.object(publisher._connection, 'flush', side_effect=lose_confirmed_flush):
                        return await original_publish(publisher, subject, body, expires=expires)
                return await original_publish(publisher, subject, body, expires=expires)
        with patch.object(CoreWorkPublisher, 'publish', new=observe):
            host, owner, resource = await self.sender()
            active.append(owner)
            original = await resource._owner.db(resource._store.work_create, 'operator', 'falcon',
                'role:falcon/worker', 'Original owner outbox', federate=True, node='mac_alice')
            saved_rows = await self.rows(resource,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-outbox:%'",
                predicate=lambda rows: len(rows) == 1 and strict_loads(rows[0]['v'])['state'] == 'uncertain')
            retained = strict_loads(saved_rows[0]['v'])
            self.assertIsNone((await resource._owner.db(resource._store.q1,
                'SELECT sent FROM nats_outbox WHERE seq=?', (retained['row']['seq'],)))['sent'])
            first = (await self.wait_rows('SELECT * FROM work_items WHERE origin=?',
                ('mac_alice:' + original['id'],)))[0]
            self.assertEqual(first['title'], 'Original owner outbox')
            await host.close(timeout=None)
            self.assertTrue(owner._closing.done())
            self.assertTrue(owner._outbox_task.done())
            self.assertIsNone(resource._owner._source._store)
            replacement_host, replacement, fresh = await self.sender()
            active[0] = replacement
            completed_rows = await self.rows(fresh,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-outbox:%'",
                predicate=lambda rows: len(rows) == 1 and strict_loads(rows[0]['v'])['state'] == 'confirmed')
            self.assertEqual(strict_loads(completed_rows[0]['v']), {**retained, 'state': 'confirmed'})
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0], calls[1])
            self.assertLess(datetime.now(timezone.utc), calls[0][2])
            self.assertEqual(wire[0], wire[1])
            await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-proof:%' AND k NOT LIKE '%event:%'", count=2)
            records = await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
            self.assertEqual(len(strict_loads(records[0]['v'])['attempts']), 1)
            self.assertEqual(await self.resource._owner.db(self.resource._store.q,
                'SELECT * FROM work_items WHERE origin=?', ('mac_alice:' + original['id'],)), [first])
            self.assertEqual(await fresh._owner.db(fresh._store.q, 'SELECT * FROM work_items'), [original])
            await replacement_host.close(timeout=None)
            self.assertTrue(replacement._closing.done())
        self.success = True

    async def test_actual_owner_outboxes_deliver_work_and_return_the_original_result(self):
        await self.core_owner.close(timeout=None)
        value = copy.deepcopy(self.core_owner._selection.policy)
        value['coreWorkTransport']['routes'][0]['publisher'] = self.core_publisher_pin('core-nick')
        selection = ApplicationServiceSelection(canonical_bytes(value))
        work = value['storage']['work']
        channel = work['channels'][0]
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        domain = SelectedWorkDomain(self.control_source, session, identity=self.identity,
            scope=self.scope, local_node='mac', selection=selection, channel_ref=channel['resourceRef'])
        self.addAsyncCleanup(domain.close)
        self.resource = WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'work-one',
            'work-channel', canonical_bytes(self.scope)), domain, repository=work['repository']['localName'],
            actors=tuple(MessageActor(canonical_bytes(a['identityRef']), canonical_bytes(a['transportRef']), a['caller'])
                for a in channel['actors']), plugin_identity_ref=channel['pluginIdentityRef'],
            instance_id=channel['instanceId'], initial_source=None,
            legacy_actors=tuple(LegacyWorkActor(canonical_bytes(a['identityRef']), canonical_bytes(a['transportRef']),
                a['caller'], canonical_bytes(a['grants'])) for a in channel['legacyActors']))
        self.core_owner = CoreWorkOwner(selection, self.identity, (self.resource,))
        await self.core_owner.start()
        await self.core_owner.set_work_subjects({'am.work.falcon.worker'})
        sender, _, outgoing_resource = await self.sender()
        original = await outgoing_resource._owner.db(outgoing_resource._store.work_create, 'operator', 'falcon',
            'role:falcon/worker', 'Original two-owner work', federate=True, node='mac_alice')
        incoming = (await self.wait_rows('SELECT * FROM work_items WHERE origin=?',
            ('mac_alice:' + original['id'],)))[0]
        def finish():
            store = self.resource._store
            agent = store.register('falcon', 'worker', 'core_worker', 'claude', {'max_active': 1})
            store.set_state(agent, 'ready')
            self.assertEqual(store.claim(agent, work_id=incoming['id'])['claimed']['id'], incoming['id'])
            store.release(agent, incoming['id'], 'done', 'Exact owner-outbox result', node='mac')
        await self.resource._owner.db(finish)
        completed = (await self.rows(outgoing_resource,
            "SELECT * FROM work_items WHERE id=? AND state='done'", (original['id'],),
            predicate=lambda rows: len(rows) == 1))[0]
        self.assertEqual(completed['result'], 'Exact owner-outbox result')
        self.assertEqual(completed['claimed_by'], 'nats:mac:falcon-worker-core_worker')
        for resource in (self.resource, outgoing_resource):
            records = await self.rows(resource,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-outbox:%'",
                predicate=lambda rows: len(rows) == 1 and strict_loads(rows[0]['v'])['state'] == 'confirmed')
            self.assertEqual(len(records), 1)
            dispatch = await resource._owner.db(resource._store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
            self.assertEqual(len(dispatch), 1)
            self.assertEqual(len(strict_loads(dispatch[0]['v'])['attempts']), 1)
        await sender.close(timeout=None)
        self.success = True
