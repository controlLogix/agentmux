"""Live selected-owner role changes over the prepared authenticated broker."""
import asyncio

from agentmux_contracts import canonical_bytes
from .test_core_work_live import LiveCoreWorkTests


class LiveCoreWorkRoleTests(LiveCoreWorkTests):
    async def test_actual_role_watcher_subscribes_on_registration_and_releases_on_death(self):
        owner, resource = self.core_owner, self.resource
        ingress = owner._ingresses[id(resource)]
        for agent in await resource._owner.db(resource._store.agents, True):
            await resource._owner.db(resource._store.set_state, agent['session'], 'dead')
        await owner._roles.sync()
        self.assertNotIn('am.work.falcon.worker', ingress._subscriptions)
        owner._roles_task = asyncio.create_task(owner._roles.run(), name='core-work:test-roles')
        session = await resource._owner.db(resource._store.register,
            'falcon', 'worker', 'role_watcher', 'codex', {'capabilities': ['python']})
        async def wait_interest(present):
            async with asyncio.timeout(5):
                while ('am.work.falcon.worker' in ingress._subscriptions) != present:
                    await asyncio.sleep(.02)
        await wait_interest(True)
        subscription = ingress._subscriptions['am.work.falcon.worker']
        self.assertEqual(subscription.queue, 'am_work_falcon_worker')
        item = {'type': 'work', 'origin': 'mac_alice:role-watcher', 'origin_node': 'mac_alice',
            'origin_id': 'role-watcher', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Work delivered through actual role interest', 'created_by': 'virtual:operator'}}
        await self.core_publisher.publish('am.work.falcon.worker', canonical_bytes(item))
        rows = await self.wait_rows('SELECT * FROM work_items WHERE origin=?', ('mac_alice:role-watcher',))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['title'], item['work']['title'])
        await resource._owner.db(resource._store.set_state, session, 'dead')
        await wait_interest(False)
        self.assertTrue(subscription._closed)
        owner.begin_policy_pause()
        await asyncio.wait_for(owner.join_policy_pause(), 2)
        self.assertFalse(owner._roles_task.done())
        owner.end_policy_pause()
        self.success = True
