"""Signed work reads and actual Hub posts retain legacy result recipients."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.runtime import Federation
from hub.store import HubError
from hub.tests.test_hub_offline import reg
from identity.test_authority import NOW
from identity.test_service import _Clock
from .federated_work_client import FederatedWorkCommandClient
from .legacy_work_client import LegacyWorkCommandClient
from .legacy_work_notifications import LegacyWorkNotifications
from . import test_federated_work_client as federation_support
from .test_work_bridge_owner import WorkBridgeFixture
from . import test_work_lifecycle_client as lifecycle_support
from . import test_core_work_owner as core_support
from .messages import MessageActor
from .work import WorkStorageResource
from .work_bridge_service import WorkBridgeService
from .work_legacy import LegacyWorkActor
from identity.test_authority import SEED, ref
from state_owner.ledger import OwnerBinding
from . import test_hub_work_maintenance as maintenance_support
from .test_work_source import SelectedWorkSourceFixture


class NotificationReadSchedulingTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = maintenance_support.HubWorkMaintenanceTests.configure_channels
    asyncSetUp = maintenance_support.HubWorkMaintenanceTests.asyncSetUp

    async def queued_read(self, *, fixed_expiry):
        from contextlib import asynccontextmanager
        commands = self.hub._work_storage_commands
        source = self.hub._work_source_binding
        notices = LegacyWorkNotifications(self.hub, commands)
        self.addAsyncCleanup(notices.close)
        routes = commands._select('federation', 'read', 'falcon')
        session = routes[0][0]
        entered = asyncio.Event()
        observed = {}
        original_turn, original_before = commands._read_turn, source.before_call
        original_read = commands._read_current
        original_command = session.work_command

        @asynccontextmanager
        async def turn(selected):
            entered.set()
            async with original_turn(selected):
                observed['admitted_at'] = datetime.now(timezone.utc)
                yield

        async def read(routes, query, expires, **kwargs):
            observed['expires'] = expires
            observed['read_remaining'] = (expires - datetime.now(timezone.utc)).total_seconds()
            return await original_read(routes, query, expires, **kwargs)

        async def before(current_session, expires):
            observed['before_expires'] = expires
            observed['before_remaining'] = (expires - datetime.now(timezone.utc)).total_seconds()
            return await original_before(current_session, expires)

        def command(**kwargs):
            observed['command_expires'] = datetime.fromisoformat(kwargs['expires_at'])
            observed['command_remaining'] = (observed['command_expires'] - datetime.now(timezone.utc)).total_seconds()
            return original_command(**kwargs)

        task = None
        try:
            with patch.object(commands, '_read_turn', turn), \
                    patch.object(commands, '_read_current', side_effect=read), \
                    patch.object(source, 'before_call', side_effect=before), \
                    patch.object(session, 'work_command', side_effect=command) as submitted:
                async with self.maintenance.observation_read_turn():
                    expires = datetime.now(timezone.utc) + timedelta(seconds=.2)
                    task = asyncio.create_task(commands._read(routes, {'kind': 'list', 'state': None}, expires)
                        if fixed_expiry else notices._read('falcon'))
                    await asyncio.wait_for(entered.wait(), 2)
                    self.assertNotIn('expires', observed)
                    self.assertNotIn('before_expires', observed)
                    self.assertIn(task, commands._active)
                    submitted.assert_not_called()
                    await asyncio.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + .02)
                if fixed_expiry:
                    with self.assertRaisesRegex(ContractError, '^legacy_work_client_expired$'):
                        await asyncio.wait_for(task, 3)
                    submitted.assert_not_called()
                    self.assertLessEqual(observed['before_remaining'], 0)
                    self.assertEqual(observed['expires'], expires)
                else:
                    await asyncio.wait_for(task, 4)
                    submitted.assert_called_once()
                    self.assertEqual(observed['command_expires'], observed['expires'])
                    self.assertLess(observed['command_remaining'], observed['before_remaining'])
                    self.assertGreater(observed['read_remaining'], 4.5)
                    self.assertLessEqual(observed['read_remaining'], 5)
                    self.assertGreaterEqual(observed['expires'], observed['admitted_at'] + timedelta(seconds=4.5))
                self.assertEqual(observed['before_expires'], observed['expires'])
                self.assertNotIn(task, commands._active)
        finally:
            if task is not None:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_notification_read_creates_budget_after_maintenance_wait(self):
        await self.queued_read(fixed_expiry=False)

    async def test_explicit_read_expired_in_queue_submits_no_command(self):
        await self.queued_read(fixed_expiry=True)

    async def test_cancelled_queued_notification_read_joins_without_releasing_holder(self):
        from contextlib import asynccontextmanager
        commands = self.hub._work_storage_commands
        notices = LegacyWorkNotifications(self.hub, commands)
        self.addAsyncCleanup(notices.close)
        entered = asyncio.Event()
        original = commands._read_turn
        @asynccontextmanager
        async def turn(routes):
            entered.set()
            async with original(routes):
                yield
        task = None
        try:
            with patch.object(commands, '_read_turn', turn), \
                    patch.object(commands, '_call', wraps=commands._call) as call:
                async with self.maintenance.observation_read_turn():
                    task = asyncio.create_task(notices._read('falcon'))
                    await asyncio.wait_for(entered.wait(), 2)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    self.assertTrue(self.maintenance._lock.locked())
                    self.assertNotIn(task, commands._active)
                    call.assert_not_awaited()
                self.assertFalse(self.maintenance._lock.locked())
        finally:
            if task is not None:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_previous_disclosure_expiring_while_queued_is_not_renewed(self):
        from contextlib import asynccontextmanager
        commands = self.hub._work_storage_commands
        notices = LegacyWorkNotifications(self.hub, commands)
        self.addAsyncCleanup(notices.close)
        entered = asyncio.Event()
        original = commands._read_turn
        expires = datetime.now(timezone.utc) + timedelta(seconds=.3)
        @asynccontextmanager
        async def turn(routes):
            entered.set()
            async with original(routes):
                yield
        async def read():
            commands._remember((), expires)
            return await notices._read('falcon')
        task = None
        try:
            with patch.object(commands, '_read_turn', turn), \
                    patch.object(commands, '_call', wraps=commands._call) as call:
                async with self.maintenance.observation_read_turn():
                    task = asyncio.create_task(read())
                    await asyncio.wait_for(entered.wait(), 2)
                    await asyncio.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + .02)
                with self.assertRaises(ContractError):
                    await asyncio.wait_for(task, 2)
                call.assert_not_awaited()
                self.assertEqual(commands._disclosures[task][1], expires)
                self.assertNotIn(task, commands._active)
        finally:
            if task is not None:
                if not task.done(): task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_unrelated_task_inherits_neither_turn_nor_disclosure(self):
        from contextlib import asynccontextmanager
        commands = self.hub._work_storage_commands
        notices = LegacyWorkNotifications(self.hub, commands)
        self.addAsyncCleanup(notices.close)
        routes = commands._select('federation', 'read', 'falcon')
        entered = asyncio.Event()
        original = commands._read_turn
        parent = asyncio.current_task()
        expires = datetime.now(timezone.utc) + timedelta(seconds=.3)
        task = None
        @asynccontextmanager
        async def turn(selected):
            if asyncio.current_task() is not parent:
                entered.set()
            async with original(selected):
                yield
        try:
            commands._remember((), expires)
            with patch.object(commands, '_read_turn', turn), \
                    patch.object(commands, '_read_current', wraps=commands._read_current) as read:
                async with commands._read_turn(routes):
                    task = asyncio.create_task(notices._read('falcon'))
                    await asyncio.wait_for(entered.wait(), 2)
                    read.assert_not_awaited()
                    self.assertNotIn(task, commands._disclosures)
                    await asyncio.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + .02)
                await asyncio.wait_for(task, 4)
                read.assert_awaited_once()
                self.assertGreater(read.call_args.args[2], expires)
                self.assertEqual(commands._disclosures[parent][1], expires)
                self.assertNotIn(task, commands._active)
        finally:
            commands._disclosures.pop(parent, None)
            if task is not None:
                if not task.done(): task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_still_valid_previous_disclosure_caps_new_notification_read(self):
        from contextlib import asynccontextmanager
        commands = self.hub._work_storage_commands
        notices = LegacyWorkNotifications(self.hub, commands)
        self.addAsyncCleanup(notices.close)
        entered = asyncio.Event()
        original = commands._read_turn
        expires = datetime.now(timezone.utc) + timedelta(seconds=3)
        @asynccontextmanager
        async def turn(routes):
            entered.set()
            async with original(routes):
                yield
        async def read():
            commands._remember((), expires)
            return await notices._read('falcon')
        task = None
        try:
            with patch.object(commands, '_read_turn', turn), \
                    patch.object(commands, '_read_current', wraps=commands._read_current) as submitted:
                async with self.maintenance.observation_read_turn():
                    task = asyncio.create_task(read())
                    await asyncio.wait_for(entered.wait(), 2)
                    submitted.assert_not_awaited()
                    await asyncio.sleep(.05)
                await asyncio.wait_for(task, 3)
                submitted.assert_awaited_once()
                self.assertEqual(submitted.call_args.args[2], expires)
                self.assertLessEqual(commands._disclosures[task][1], expires)
                self.assertNotIn(task, commands._active)
        finally:
            if task is not None:
                if not task.done(): task.cancel()
                await asyncio.gather(task, return_exceptions=True)


class LegacyWorkNotificationTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    session_for = federation_support.FederatedWorkTests.session_for

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_work_client', 'capability_owner.legacy_work_notifications'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.cfg, self.fed.policy = self.owner.policy.cfg, self.owner.policy
        self.fed.session = self.owner.session
        self.addAsyncCleanup(self.fed.session.close)
        self.hub.fed = self.fed
        self.hub._legacy_identity, self.hub._work_rpc = None, None
        await self.replace(owner=self.fed)
        self.submitted, self.drop_after = [], None
        self.commands = LegacyWorkCommandClient(self.hub, (self.session_for('service'),))
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.federated = FederatedWorkCommandClient(self.fed, self.commands)
        self.hub._work_storage_commands = self.commands
        self.notices = LegacyWorkNotifications(self.hub, self.commands)
        self.addAsyncCleanup(self.notices.close)

    def completion(self, *, title='Original completion', creator='virtual:operator', parent=None, state='done'):
        row = self.store.work_create(creator, 'falcon', 'role:falcon/worker', title,
            parent_id=parent, federate=True, node='mac')
        self.store.db.execute('UPDATE work_items SET state=?,claimed_by=?,result=? WHERE id=?',
            (state, 'nats:remote:original_worker', 'Exact result evidence', row['id']))
        return self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))

    def records(self):
        return [strict_loads(row['v']) for row in self.store.q(
            'SELECT v FROM fed_state WHERE k LIKE ? ORDER BY k', (self.notices._prefix + '%',))]

    async def test_poll_reads_as_service_and_posts_exact_original_body_once(self):
        row = self.completion()
        self.assertEqual(await self.notices.poll(), {'completed': 1, 'pending': 0})
        self.assertEqual(await self.notices.poll(), {'completed': 1, 'pending': 0})
        messages = self.store.q("SELECT * FROM messages WHERE kind='result'")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]['body'], f"work {row['id']} \"Original completion\" is done "
            '(by nats:remote:original_worker)\nresult: Exact result evidence')
        self.assertEqual(messages[0]['idem_key'], f"result:{row['id']}:done:virtual:operator")
        self.assertTrue(all(request['grantRef'] == self.work_grants['service']['federation-work-read']
            for request in self.submitted))
        self.assertEqual(self.records()[0]['targets'][0]['state'], 'completed')

    async def test_pending_notice_keeps_first_parent_holder_after_restart(self):
        original = reg(self.store, 'falcon', 'worker', 'original')
        replacement = reg(self.store, 'falcon', 'worker', 'replacement')
        parent = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Parent')
        self.store.claim(original, work_id=parent['id'])
        row = self.completion(parent=parent['id'])
        post = self.hub._post_current
        async def unavailable(sender, target, *args, **kwargs):
            if target == 'agent:' + original:
                raise HubError('controlled recipient unavailable')
            return await post(sender, target, *args, **kwargs)
        with patch.object(self.hub, '_post_current', side_effect=unavailable):
            self.assertFalse(await self.notices.notify(row['id'], 'falcon'))
        self.assertEqual(len(self.store.q("SELECT * FROM messages WHERE kind='result'")), 1)
        await self.notices.close()
        self.store.db.execute('UPDATE work_items SET claimed_by=? WHERE id=?', (replacement, parent['id']))
        self.notices = LegacyWorkNotifications(self.hub, self.commands)
        self.addAsyncCleanup(self.notices.close)
        self.assertTrue(await self.notices.notify(row['id'], 'falcon'))
        targets = {message['target'] for message in self.store.q("SELECT * FROM messages WHERE kind='result'")}
        self.assertEqual(targets, {'agent:' + original, 'virtual:operator'})
        self.assertNotIn('agent:' + replacement, targets)

    async def test_lost_post_reply_reconciles_durable_message_without_reposting(self):
        row = self.completion()
        original = self.hub._post_current
        async def lost(*args, **kwargs):
            await original(*args, **kwargs)
            raise TimeoutError('controlled lost post response')
        with patch.object(self.hub, '_post_current', side_effect=lost):
            self.assertFalse(await self.notices.notify(row['id'], 'falcon'))
        self.assertEqual(self.records()[0]['targets'][0]['state'], 'pending')
        self.assertEqual(len(self.store.q("SELECT * FROM messages WHERE kind='result'")), 1)
        with patch.object(self.hub, '_post_current', side_effect=AssertionError('must reconcile the original post')):
            self.assertTrue(await self.notices.notify(row['id'], 'falcon'))
        self.assertEqual(len(self.store.q("SELECT * FROM messages WHERE kind='result'")), 1)

    async def test_revoked_service_read_cannot_post_or_complete_retained_notice(self):
        row = self.completion()
        with patch.object(self.hub, '_post_current', side_effect=HubError('controlled failure')):
            self.assertFalse(await self.notices.notify(row['id'], 'falcon'))
        before = canonical_bytes(self.records())
        state = strict_loads(self.js.messages[-1].data)
        grant = self.work_grants['service']['federation-work-read']
        next(item for item in state['state']['grants'] if item['ref'] == grant)['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(state)
        with self.assertRaises(ContractError):
            await self.notices.notify(row['id'], 'falcon')
        self.assertEqual(canonical_bytes(self.records()), before)
        self.assertEqual(self.store.q("SELECT * FROM messages WHERE kind='result'"), [])

    async def test_failed_old_notice_does_not_starve_new_completion(self):
        old = self.completion(title='Unavailable old result', creator='agent:falcon-worker-absent')
        new = self.completion(title='Available new result')
        self.assertEqual(await self.notices.poll(), {'completed': 1, 'pending': 1})
        messages = self.store.q("SELECT * FROM messages WHERE kind='result'")
        self.assertEqual([message['work_id'] for message in messages], [new['id']])
        self.assertNotEqual(messages[0]['work_id'], old['id'])

    async def test_expired_first_read_is_not_renewed_by_parent_reply(self):
        holder = reg(self.store, 'falcon', 'worker', 'holder')
        parent = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Parent')
        self.store.claim(holder, work_id=parent['id'])
        row = self.completion(parent=parent['id'])
        state = strict_loads(self.js.messages[-1].data)
        grant = self.work_grants['service']['federation-work-read']
        next(item for item in state['state']['grants'] if item['ref'] == grant)['expiresAt'] = (
            NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(state)
        original = self.notices._read
        calls = 0
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        async def expired(*args, **kwargs):
            nonlocal calls
            value = await original(*args, **kwargs)
            calls += 1
            if calls == 2:
                timer = patch('capability_owner.legacy_work_client.datetime', Later)
                timer.start()
                self.addCleanup(timer.stop)
            return value
        with patch.object(self.notices, '_read', side_effect=expired):
            with self.assertRaises(ContractError):
                await self.notices.notify(row['id'], 'falcon')
        self.assertEqual(self.store.q("SELECT * FROM messages WHERE kind='result'"), [])

    async def test_replaced_recipient_generation_does_not_receive_old_notice(self):
        creator = reg(self.store, 'falcon', 'worker', 'creator')
        row = self.completion(creator='agent:' + creator)
        with patch.object(self.hub, '_post_current', side_effect=HubError('controlled failure')):
            self.assertFalse(await self.notices.notify(row['id'], 'falcon'))
        self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (creator,))
        self.assertFalse(await self.notices.notify(row['id'], 'falcon'))
        self.assertEqual(self.store.q("SELECT * FROM messages WHERE kind='result'"), [])
        self.assertEqual(self.records()[0]['targets'][0]['generation'], 1)

    async def test_unknown_first_recipient_does_not_bind_a_future_registration(self):
        holder = reg(self.store, 'falcon', 'worker', 'holder')
        parent = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Parent')
        self.store.claim(holder, work_id=parent['id'])
        row = self.completion(creator='agent:falcon-worker-future', parent=parent['id'])
        self.assertFalse(await self.notices.notify(row['id'], 'falcon'))
        self.assertEqual([message['target'] for message in self.store.q("SELECT target FROM messages WHERE kind='result'")],
            ['agent:' + holder])
        reg(self.store, 'falcon', 'worker', 'future')
        self.assertFalse(await self.notices.notify(row['id'], 'falcon'))
        self.assertEqual([message['target'] for message in self.store.q("SELECT target FROM messages WHERE kind='result'")],
            ['agent:' + holder])

    async def test_accepted_display_attributions_keep_exact_body_and_idempotency(self):
        for index, by in enumerate(('', ':', 'worker:part', 'line one\nline two', 'None')):
            with self.subTest(by=by):
                row = self.completion(title='Display variant ' + str(index))
                self.store.db.execute('UPDATE work_items SET claimed_by=? WHERE id=?',
                    ('nats:remote:' + by, row['id']))
                self.assertTrue(await self.notices.notify(row['id'], 'falcon'))
                self.assertTrue(await self.notices.notify(row['id'], 'falcon'))
                messages = self.store.q('SELECT * FROM messages WHERE work_id=?', (row['id'],))
                self.assertEqual(len(messages), 1)
                self.assertEqual(messages[0]['body'], f"work {row['id']} \"Display variant {index}\" is done "
                    f'(by nats:remote:{by})\nresult: Exact result evidence')
                self.assertEqual(messages[0]['idem_key'], f"result:{row['id']}:done:virtual:operator")

    async def test_cancelled_poll_joins_the_exact_original_post_before_return(self):
        row = self.completion()
        started, release = asyncio.Event(), asyncio.Event()
        original = self.hub._post_current
        async def held(*args, **kwargs):
            started.set()
            await release.wait()
            return await original(*args, **kwargs)
        with patch.object(self.hub, '_post_current', side_effect=held):
            operation = asyncio.create_task(self.notices.poll())
            try:
                await started.wait()
                operation.cancel()
                await asyncio.sleep(0)
                self.assertFalse(operation.done())
                operation.cancel()
                await asyncio.sleep(0)
                self.assertFalse(operation.done())
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await operation
        self.assertEqual([message['work_id'] for message in self.store.q("SELECT * FROM messages WHERE kind='result'")],
            [row['id']])
        self.assertEqual(self.notices._pending, set())

    async def test_placeholder_and_cancelled_rows_are_not_completion_notices(self):
        self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Not finished',
            federate=True, node='mac')
        self.completion(state='cancelled')
        self.assertEqual(await self.notices.poll(), {'completed': 0, 'pending': 0})
        self.assertEqual(self.store.q("SELECT * FROM messages WHERE kind='result'"), [])

    async def test_parent_notice_selects_the_correct_named_route_among_two_scopes(self):
        holder = reg(self.store, 'falcon', 'worker', 'holder')
        parent = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Parent')
        self.store.claim(holder, work_id=parent['id'])
        row = self.completion(parent=parent['id'])
        await self.notices.close()
        await self.commands.close(timeout=None)
        await self.replace()
        state = strict_loads(self.js.messages[-1].data)
        other_scope = {**self.scope, 'projectId': 'project-other'}
        for membership in tuple(state['state']['memberships']):
            if membership['identityRef'] == ref('service'):
                state['state']['memberships'].append({**copy.deepcopy(membership),
                    'ref': ref('other-' + membership['ref']['id']), 'scope': other_scope})
        self.other_grants = {}
        for contract, reference in self.work_grants['service'].items():
            grant = copy.deepcopy(next(item for item in state['state']['grants'] if item['ref'] == reference))
            grant.update(ref=ref('other-' + reference['id']), resourceId='task-two', scope=other_scope)
            state['state']['grants'].append(grant)
            self.other_grants[contract] = grant['ref']
        self.js.messages[-1].data = canonical_bytes(state)
        actor = next(actor for actor in self.work_actors if actor.caller == 'federation')
        other_actor = LegacyWorkActor(actor.identity_ref, actor.transport_ref, actor.caller,
            canonical_bytes(self.other_grants))
        self.other = WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'task-two', 'work-channel',
            canonical_bytes(other_scope)), self.local, repository='other',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-two', legacy_actors=(other_actor,),
            legacy_authority=self.service.reader)
        self.other_endpoint = WorkBridgeService(self.service.ingress, resources=(self.other,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(self.other_endpoint.close, timeout=None)
        self.drop_before = None
        self.commands = LegacyWorkCommandClient(self.hub,
            tuple(lifecycle_support.WorkLifecycleClientTests.session_for(self, resource)
                for resource in (self.resource, self.other)))
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.hub._work_storage_commands = self.commands
        self.notices = LegacyWorkNotifications(self.hub, self.commands)
        self.addAsyncCleanup(self.notices.close)
        self.submitted.clear()
        self.assertTrue(await self.notices.notify(row['id'], 'falcon'))
        targets = {message['target'] for message in self.store.q("SELECT * FROM messages WHERE kind='result'")}
        self.assertEqual(targets, {'virtual:operator', 'agent:' + holder})
        self.assertTrue(any(request['payload']['input']['query']['kind'] == 'list'
            and request['payload']['resourceRef']['id'] == 'task-two' for request in self.submitted))
        self.assertTrue(all(request['payload']['resourceRef']['id'] == 'task-one'
            for request in self.submitted if request['payload']['input']['query']['kind'] == 'show'))
        # The retained Store also permits legacy parent links across repositories.
        other_parent = self.store.work_create('virtual:operator', 'other', 'agent:' + holder, 'Other parent')
        self.store.claim(holder, work_id=other_parent['id'])
        other_child = self.completion(title='Legacy linked completion', parent=other_parent['id'])
        self.assertTrue(await self.notices.notify(other_child['id'], 'falcon'))
        self.assertEqual({message['target'] for message in self.store.q(
            'SELECT target FROM messages WHERE work_id=?', (other_child['id'],))},
            {'virtual:operator', 'agent:' + holder})


class CoreWorkNotificationAttributionTests(unittest.IsolatedAsyncioTestCase):
    setUp = core_support.CoreWorkOwnerTests.setUp
    asyncSetUp = core_support.CoreWorkOwnerTests.asyncSetUp
    connection = core_support.CoreWorkOwnerTests.connection
    custody = core_support.CoreWorkOwnerTests.custody
    selected = core_support.CoreWorkOwnerTests.selected
    add_board = core_support.CoreWorkOwnerTests.add_board
    identity_inputs = core_support.CoreWorkOwnerTests.identity_inputs
    authority_record = core_support.CoreWorkOwnerTests.authority_record
    reopen = core_support.CoreWorkOwnerTests.reopen
    start_host = core_support.CoreWorkOwnerTests.start_host
    core = core_support.CoreWorkOwnerTests.core
    deliver = core_support.CoreWorkOwnerTests.deliver

    async def test_actual_signed_accepted_completion_is_a_notice_candidate(self):
        owner, resource, ingress, route = await self.core()
        omitted = object()
        for index, by in enumerate(('', ':', 'line one\nline two', None, omitted)):
            with self.subTest(variant=index), patch.object(self.identity.reader, 'current',
                    AsyncMock(return_value=self.core_snapshot)):
                outgoing = await resource._owner.db(resource._store.work_create, 'virtual:operator', 'falcon',
                    'role:falcon/worker', 'Accepted display ' + str(index), federate=True, node='mac')
                result = {'type': 'result', 'origin_id': outgoing['id'], 'state': 'done',
                    'result': 'Accepted original evidence', 'node': 'remote'}
                if by is not omitted:
                    result['by'] = by
                completed = await self.deliver(owner, resource, ingress, route, result)
                self.assertEqual(completed['claimed_by'], 'nats:remote:' + str(result.get('by')))
                self.assertTrue(LegacyWorkNotifications._candidate(completed))

