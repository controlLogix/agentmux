"""Signed exact lifecycle confirmation covers both original action batches."""
import asyncio
import copy
from datetime import timedelta
import hashlib
import threading
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from identity.test_authority import NOW
from . import test_work_lifecycle_client as fixtures


class LifecycleAggregateTests(fixtures.WorkLifecycleClientTests):
    async def originals(self, suffix='one'):
        arguments = {'generation': None, 'repo': 'falcon', 'role': 'worker', 'agent': suffix,
            'cli': 'codex', 'roleSnapshot': {'max_active': 1}, 'transport': 'tmux',
            'handle': None, 'panePid': None, 'legacy': None, 'tokenSha': 'b' * 64}
        session = await self.client.register(arguments, operation_id='register-' + suffix, expires=self.expires)
        await self.client.set_state({'session': session, 'generation': 1, 'state': 'ready', 'note': None},
            operation_id='ready-' + suffix, expires=self.expires)
        return session

    async def observed_originals(self, *, stale=False):
        arguments = {'generation': None, 'repo': 'falcon', 'role': 'worker', 'agent': 'observed',
            'cli': 'codex', 'roleSnapshot': {'max_active': 1}, 'transport': 'tmux',
            'handle': '%61', 'panePid': 23601, 'legacy': 'legacy-pane', 'tokenSha': 'b' * 64}
        session = await self.client.register(arguments, operation_id='register-observed', expires=self.expires)
        agent = self.store.agent(session)
        observation = {'handle': agent['handle'], 'panePid': agent['pane_pid'],
            'created': agent['created'], 'state': agent['state']}
        if stale:
            observation['handle'] = '%different'
        ready = await self.client.set_state({'purpose': 'hub-observation', 'session': session,
            'generation': agent['generation'], 'state': 'ready', 'note': None, 'observation': observation},
            operation_id='ready-observed', expires=self.expires)
        return session, ready

    async def test_observed_ready_exact_signed_pair_and_recovery_do_not_submit_effects(self):
        session, ready = await self.observed_originals()
        self.assertIs(ready, True)
        effects, events = self.effects(), self.store.q('SELECT * FROM events')
        self.assertEqual(await self.client.confirm_registration('register-observed',
            ready_operation_id='ready-observed', expires=self.expires, finish=True), session)
        await self.restart()
        self.assertEqual(await self.client.confirm_registration('register-observed',
            ready_operation_id='ready-observed', expires=self.expires, finish=True), session)
        self.assertEqual(self.effects(), effects)
        self.assertEqual(self.store.q('SELECT * FROM events'), events)

    async def test_observed_ready_revocation_between_reads_requires_restored_authority(self):
        session, ready = await self.observed_originals()
        self.assertIs(ready, True)
        effects, authority = self.effects(), self.js.messages[-1].data
        original = self.lifecycle._ready_original
        for action in ('register', 'state'):
            with self.subTest(action=action):
                changed = False
                def revoke_between(resource, registration, query):
                    nonlocal changed
                    if not changed:
                        changed = True
                        self.revoke(action, other=True)
                    return original(resource, registration, query)
                try:
                    with patch.object(self.lifecycle, '_ready_original', revoke_between):
                        with self.assertRaises(ContractError):
                            await self.client.confirm_registration('register-observed',
                                ready_operation_id='ready-observed', expires=self.expires, finish=True)
                    self.assertTrue(changed)
                finally:
                    self.js.messages[-1].data = authority
                self.assertEqual(await self.client.confirm_registration('register-observed',
                    ready_operation_id='ready-observed', expires=self.expires, finish=True), session)
        self.assertEqual(self.effects(), effects)

    async def test_false_observation_does_not_qualify_as_ready_original(self):
        session, ready = await self.observed_originals(stale=True)
        self.assertIs(ready, False)
        self.assertEqual(self.store.agent(session)['state'], 'starting')
        effects = self.effects()
        with self.assertRaises(ContractError):
            await self.client.confirm_registration('register-observed',
                ready_operation_id='ready-observed', expires=self.expires)
        self.assertEqual(self.effects(), effects)

    async def test_observed_ready_changed_physical_target_refuses(self):
        session, ready = await self.observed_originals()
        self.assertIs(ready, True)
        current, effects = self.store.agent(session), self.effects()
        for field, replacement in (('handle', '%different'), ('pane_pid', 23602), ('created', 'changed-original')):
            with self.subTest(field=field):
                try:
                    self.store.db.execute('UPDATE agents SET ' + field + '=? WHERE session=?', (replacement, session))
                    with self.assertRaises(ContractError):
                        await self.client.confirm_registration('register-observed',
                            ready_operation_id='ready-observed', expires=self.expires)
                finally:
                    self.store.db.execute('UPDATE agents SET ' + field + '=? WHERE session=?', (current[field], session))
        self.assertEqual(await self.client.confirm_registration('register-observed',
            ready_operation_id='ready-observed', expires=self.expires, finish=True), session)
        self.assertEqual(self.effects(), effects)

    def effects(self):
        return [copy.deepcopy(item) for item in self.submitted
            if item['contractId'] in ('federation-work-register', 'federation-work-state')]

    def revoke(self, action, *, other=False):
        record = strict_loads(self.js.messages[-1].data)
        grants = self.other_grants if other else self.work_grants['service']
        next(item for item in record['state']['grants']
            if item['ref'] == grants['federation-work-' + action])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(record)

    async def test_exact_signed_pair_and_fresh_recovery_do_not_submit_effects(self):
        session = await self.originals()
        effects, events = self.effects(), self.store.q('SELECT * FROM events')
        self.assertEqual(await self.client.confirm_registration('register-one', ready_operation_id='ready-one',
            expires=self.expires, finish=True), session)
        aggregate = [item for item in self.submitted if 'readyState' in item['payload']['input']]
        self.assertEqual(len(aggregate), 2)
        self.assertTrue(all(item['contractId'] == 'federation-work-outcome' for item in aggregate))
        await self.restart()
        self.assertEqual(await self.client.confirm_registration('register-one', ready_operation_id='ready-one',
            expires=self.expires, finish=True), session)
        self.assertEqual(await self.client.confirm_registration('register-one', expires=self.expires, finish=True), session)
        self.assertEqual(self.effects(), effects)
        self.assertEqual(self.store.q('SELECT * FROM events'), events)

    async def test_either_original_action_and_other_repository_revocation_refuse(self):
        await self.originals()
        effects, original = self.effects(), self.js.messages[-1].data
        for action, other in (('register', False), ('state', False), ('register', True), ('state', True)):
            with self.subTest(action=action, other=other):
                self.js.messages[-1].data = original
                self.revoke(action, other=other)
                with self.assertRaises(ContractError):
                    await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
        self.assertEqual(self.effects(), effects)

    async def test_revocation_between_original_reads_is_rechecked_at_final_snapshot(self):
        await self.originals()
        original, changed = self.lifecycle._ready_original, False
        def revoke_between(resource, registration, query):
            nonlocal changed
            if not changed:
                changed = True
                self.revoke('register', other=True)
            return original(resource, registration, query)
        with patch.object(self.lifecycle, '_ready_original', revoke_between):
            with self.assertRaises(ContractError):
                await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
        self.assertTrue(changed)
        self.assertEqual(len(self.effects()), 4)

    async def test_unrelated_original_and_replaced_generation_refuse(self):
        session = await self.originals()
        await self.originals('two')
        effects = self.effects()
        with self.assertRaises(ContractError):
            await self.client.confirm_registration('register-one', ready_operation_id='ready-two', expires=self.expires)
        self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (session,))
        with self.assertRaises(ContractError):
            await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
        self.assertEqual(self.effects(), effects)

    async def test_changed_source_refuses_the_pair(self):
        await self.originals()
        worker = self.other._source_worker
        self.other._source_worker = object()
        try:
            with self.assertRaises(ContractError):
                await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
        finally:
            self.other._source_worker = worker
        self.assertEqual(len(self.effects()), 4)

    async def test_original_grant_and_pending_caller_minima_are_preserved(self):
        await self.originals()
        record = strict_loads(self.js.messages[-1].data)
        end = NOW + timedelta(seconds=1)
        next(item for item in record['state']['grants']
            if item['ref'] == self.other_grants['federation-work-register'])['expiresAt'] = end.isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(record)
        await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
        task = asyncio.current_task()
        self.assertEqual(self.commands._disclosures[task][1], end)
        routes, _ = self.commands._disclosures[task]
        self.commands._disclosures[task] = (routes, NOW)
        before = len(self.submitted)
        with self.assertRaises(ContractError):
            await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
        self.assertEqual(len(self.submitted), before)

    async def test_repeated_cancellation_and_close_join_confirmation_calls(self):
        await self.originals()
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.commands._call
        async def held(session, contract, operation, payload, expires, **kwargs):
            if 'readyState' in payload['input']:
                entered.set()
                await release.wait()
            return await original(session, contract, operation, payload, expires, **kwargs)
        with patch.object(self.commands, '_call', held):
            task = asyncio.create_task(self.client.confirm_registration('register-one',
                ready_operation_id='ready-one', expires=self.expires))
            closing = None
            try:
                await asyncio.wait_for(entered.wait(), 3)
                task.cancel()
                task.cancel()
                closing = asyncio.create_task(self.client.close())
                await asyncio.sleep(0)
                closing.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertFalse(closing.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await closing
            finally:
                release.set()
                await asyncio.gather(*(item for item in (task, closing) if item is not None), return_exceptions=True)
        self.assertEqual(self.client._active, set())
        self.assertEqual(self.commands._workers, set())
        self.assertEqual(len(self.effects()), 4)

    async def test_closed_optional_schema_preserves_single_original_queries(self):
        query = {'resourceRef': {'id': 'task-one', 'ownerHubId': 'hub-one', 'revision': 1},
            'input': {'contractId': 'federation-work-register', 'operationId': 'original', 'payloadDigest': 'sha256:' + 'a' * 64}}
        validate('federation-work-outcome', query)
        query['input']['readyState'] = {'operationId': 'ready', 'payloadDigest': 'sha256:' + 'b' * 64}
        validate('federation-work-outcome', query)
        query['input']['contractId'] = 'federation-work-state'
        with self.assertRaises(ContractError):
            validate('federation-work-outcome', query)

        query['input']['contractId'] = 'federation-work-register'
        query['input']['readyState']['extra'] = True
        with self.assertRaises(ContractError):
            validate('federation-work-outcome', query)

    async def test_exact_companion_digest_and_damaged_retained_records_refuse(self):
        await self.originals()
        effects = self.effects()
        original_call = self.commands._call
        altered = False
        async def wrong_digest(session, contract, operation, payload, expires, **kwargs):
            nonlocal altered
            if 'readyState' in payload['input']:
                altered = True
                payload = copy.deepcopy(payload)
                payload['input']['readyState']['payloadDigest'] = 'sha256:' + '0' * 64
            return await original_call(session, contract, operation, payload, expires, **kwargs)
        with patch.object(self.commands, '_call', wrong_digest):
            with self.assertRaises(ContractError):
                await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
        self.assertTrue(altered)
        key = hashlib.sha256(b'ready-one').hexdigest()
        original_key = self.other._journal._base + 'original:' + key
        receipt_key = self.other._journal._base + 'operation:' + key
        original_row = self.store.q1('SELECT v FROM fed_state WHERE k=?', (original_key,))['v']
        receipt_row = self.store.q1('SELECT v FROM fed_state WHERE k=?', (receipt_key,))['v']
        for damage in ('missing-original', 'missing-receipt', 'actor', 'repository', 'scope', 'unapplied'):
            with self.subTest(damage=damage):
                try:
                    if damage in ('missing-original', 'missing-receipt'):
                        self.store.db.execute('DELETE FROM fed_state WHERE k=?',
                            (original_key if damage == 'missing-original' else receipt_key,))
                    elif damage == 'unapplied':
                        value = strict_loads(receipt_row)
                        value['reply']['outcome'] = 'conflict'
                        self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                            (canonical_bytes(value).decode(), receipt_key))
                    else:
                        # Damage actual retained records; this does not represent
                        # a newly authorized command from a different actor.
                        value = strict_loads(original_row)
                        if damage == 'actor':
                            value['operation']['effectiveActorRef']['id'] = 'foreign-actor'
                        elif damage == 'repository':
                            value['payload']['input']['repositories'][0]['repository'] = 'foreign'
                        else:
                            value['operation']['scope']['projectId'] = 'foreign-project'
                        self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                            (canonical_bytes(value).decode(), original_key))
                    with self.assertRaises(ContractError):
                        await self.client.confirm_registration('register-one', ready_operation_id='ready-one', expires=self.expires)
                finally:
                    for selected_key, raw in ((original_key, original_row), (receipt_key, receipt_row)):
                        self.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) '
                            'ON CONFLICT(k) DO UPDATE SET v=excluded.v', (selected_key, raw))
        self.assertEqual(self.effects(), effects)

    async def test_initial_record_load_is_owned_through_repeated_cancel_and_close(self):
        await self.originals()
        entered, release = threading.Event(), threading.Event()
        original = self.client._load
        def held(*args):
            entered.set()
            if not release.wait(4):
                raise RuntimeError('controlled original load was not released')
            return original(*args)
        submitted = len(self.submitted)
        with patch.object(self.client, '_load', held):
            task = asyncio.create_task(self.client.confirm_registration('register-one',
                ready_operation_id='ready-one', expires=self.expires))
            closing = None
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                self.assertIn(task, self.client._active)
                self.assertTrue(self.commands._workers)
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                closing = asyncio.create_task(self.client.close())
                await asyncio.sleep(0)
                closing.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertFalse(closing.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await closing
            finally:
                release.set()
                await asyncio.gather(*(item for item in (task, closing) if item is not None), return_exceptions=True)
        self.assertEqual(self.client._active, set())
        self.assertEqual(self.commands._workers, set())
        self.assertEqual(len(self.submitted), submitted)
