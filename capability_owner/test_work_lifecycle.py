"""Signed fixed lifecycle commands retain one source and transaction."""
import asyncio
import copy
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.tests.test_hub_offline import reg
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .messages import MessageActor
from .test_work_bridge_owner import WorkBridgeFixture
from .work import WorkStorageResource
from .work_bridge_service import WorkBridgeService
from .work_legacy import LegacyWorkActor
from .work_lifecycle import WorkLifecycleOwner


class WorkLifecycleTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        timer = patch('capability_owner.work_lifecycle.datetime', _Clock)
        timer.start()
        self.addCleanup(timer.stop)
        record = strict_loads(self.js.messages[-1].data)
        self.other_scope = {**self.scope, 'projectId': 'project-other'}
        for membership in tuple(record['state']['memberships']):
            if membership['identityRef'] == ref('service'):
                record['state']['memberships'].append({**copy.deepcopy(membership),
                    'ref': ref('other-' + membership['ref']['id']), 'scope': self.other_scope})
        grants = {}
        for contract, grant_ref in self.work_grants['service'].items():
            grant = copy.deepcopy(next(item for item in record['state']['grants'] if item['ref'] == grant_ref))
            grant.update(ref=ref('other-' + grant_ref['id']), resourceId='task-two', scope=self.other_scope)
            record['state']['grants'].append(grant)
            grants[contract] = grant['ref']
        self.other_grants = grants
        self.js.messages[-1].data = canonical_bytes(record)
        actor = next(item for item in self.work_actors if item.caller == 'federation')
        other_actor = LegacyWorkActor(actor.identity_ref, actor.transport_ref, actor.caller, canonical_bytes(grants))
        self.other = WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'task-two', 'work-channel',
            canonical_bytes(self.other_scope)), self.local, repository='other',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-two',
            legacy_actors=(other_actor,), legacy_authority=self.service.reader)
        self.lifecycle = WorkLifecycleOwner((self.resource, self.other))
        self.addAsyncCleanup(self.lifecycle.close)
        self.other_endpoint = WorkBridgeService(self.service.ingress, resources=(self.other,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(self.other_endpoint.close, timeout=None)

    def descriptor(self, action, *, batch='lifecycle-one', resources=None, **fields):
        selected = resources or (self.resource, self.other)
        entries = [{'repository': resource.repository, 'resourceRef': {
            'id': resource.binding.entity_id, 'ownerHubId': 'hub-one', 'revision': resource._journal.current()['revision']}}
            for resource in sorted(selected, key=lambda resource: resource.repository)]
        purpose = {'register': 'hub-registration', 'state': 'hub-state', 'sweep-global': 'hub-lease-sweep'}[action]
        return {'batchId': batch, 'purpose': purpose, 'localNode': 'mac', 'repositories': entries, **fields}

    def requests(self, action, value):
        packets = []
        for entry in value['repositories']:
            resource = self.lifecycle._resources[entry['resourceRef']['id']]
            self.work_request(action, value, operation=value['batchId'], identity='service')
            self.claims['payload']['resourceRef'] = entry['resourceRef']
            self.claims['expectedVersion'] = entry['resourceRef']['revision']
            if resource is self.other:
                self.claims['grantRef'] = self.other_grants['federation-work-' + action]
            packets.append((resource, self.request()))
        return packets

    async def call(self, action, value):
        async def one(resource, packet):
            endpoint = self.endpoint if resource is self.resource else self.other_endpoint
            response = await endpoint.handle(packet,
                received_reply_subject=strict_loads(packet)['claims']['replySubject'])
            return self.verify_reply(response, packet)
        results = await asyncio.gather(*(one(resource, packet) for resource, packet in self.requests(action, value)),
            return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                raise result
        return results

    def claimed(self):
        session = reg(self.store, 'falcon', 'worker', 'one')
        self.store.db.execute("INSERT INTO groups(grp,repo) VALUES ('shared','falcon'),('shared','other')")
        rows = []
        for repository in ('falcon', 'other'):
            row = self.store.work_create('operator', repository, 'role:group:shared/worker', 'Retained ' + repository)
            self.store.claim(session, work_id=row['id'])
            self.store.claim_path(session, repository, 'one.py', row['id'])
            rows.append(self.store.work(row['id']))
        return self.store.agent(session), rows

    async def test_death_returns_every_repository_and_keeps_original_result(self):
        agent, rows = self.claimed()
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note='terminal gone')
        replies = await self.call('state', value)
        self.assertTrue(all(reply['outcome'] == 'applied' and reply['result'] is None for reply in replies))
        self.assertEqual(self.store.agent(agent['session'])['state'], 'dead')
        self.assertEqual([self.store.work(row['id'])['state'] for row in rows], ['ready', 'ready'])
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])
        self.assertEqual(await self.call('state', value), replies)

    async def test_receipt_failure_rolls_back_agent_work_claims_and_all_receipts(self):
        agent, rows = self.claimed()
        before_events = self.store.q('SELECT * FROM events')
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note='terminal gone')
        with patch.object(self.other._journal, '_set', side_effect=RuntimeError('controlled receipt failure')):
            with self.assertRaises(ContractError):
                await self.call('state', value)
        self.assertEqual(self.store.agent(agent['session']), agent)
        self.assertEqual([self.store.work(row['id']) for row in rows], rows)
        self.assertEqual(len(self.store.q('SELECT * FROM claims')), 2)
        self.assertEqual(self.store.q('SELECT * FROM events'), before_events)
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_missing_repository_refuses_before_any_lifecycle_mutation(self):
        agent, rows = self.claimed()
        value = self.descriptor('state', resources=(self.resource,), session=agent['session'],
            generation=agent['generation'], state='dead', note=None)
        with self.assertRaises(ContractError):
            await self.call('state', value)
        self.assertEqual(self.store.agent(agent['session']), agent)
        self.assertEqual([self.store.work(row['id']) for row in rows], rows)

    async def test_revoked_second_repository_grant_prevents_whole_batch(self):
        agent, rows = self.claimed()
        record = strict_loads(self.js.messages[-1].data)
        grant_ref = self.other_grants['federation-work-state']
        next(item for item in record['state']['grants'] if item['ref'] == grant_ref)['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(record)
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note=None)
        with self.assertRaises(ContractError):
            await self.call('state', value)
        self.assertEqual(self.store.agent(agent['session']), agent)
        self.assertEqual([self.store.work(row['id']) for row in rows], rows)

    async def test_global_sweep_rollback_is_not_a_series_of_commits(self):
        _, rows = self.claimed()
        self.store.db.execute("UPDATE work_items SET lease_until='2000-01-01T00:00:00Z'")
        self.store.db.execute("UPDATE claims SET lease_until='2000-01-01T00:00:00Z'")
        value = self.descriptor('sweep-global')
        with patch.object(self.other._journal, '_set', side_effect=RuntimeError('controlled receipt failure')):
            with self.assertRaises(ContractError):
                await self.call('sweep-global', value)
        self.assertEqual([self.store.work(row['id'])['state'] for row in rows], ['claimed', 'claimed'])
        self.assertEqual(len(self.store.q('SELECT * FROM claims')), 2)
        replies = await self.call('sweep-global', value)
        self.assertEqual(len(replies[0]['result']), 2)
        self.assertEqual(replies[0]['result'], replies[1]['result'])
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])

    async def test_registration_preserves_generation_private_token_and_relationship_cleanup(self):
        agent, rows = self.claimed()
        message = self.store.post('virtual:operator', 'agent:' + agent['session'], 'request', 'Earlier incarnation')
        self.store.db.execute("INSERT INTO teams(repo,team,lead_role,created) VALUES ('falcon','one','worker','earlier')")
        self.store.db.execute("INSERT INTO team_members(repo,team,session) VALUES ('falcon','one',?)", (agent['session'],))
        self.store.db.execute("INSERT INTO legacy_names(legacy,session) VALUES ('old-alias',?)", (agent['session'],))
        self.store.db.execute("UPDATE agents SET state='dead' WHERE session=?", (agent['session'],))
        value = self.descriptor('register', generation=agent['generation'], repo='falcon', role='worker', agent='one',
            cli='codex', roleSnapshot={'max_active': 3}, transport='tmux', handle='actual-handle', panePid=123,
            legacy='legacy-one', tokenSha='a' * 64)
        replies = await self.call('register', value)
        self.assertEqual(replies[0]['result'], agent['session'])
        current = self.store.agent(agent['session'])
        self.assertEqual((current['generation'], current['token_sha'], current['handle']), (agent['generation'] + 1, 'a' * 64, 'actual-handle'))
        self.assertEqual(await self.call('register', value), replies)
        self.assertEqual([self.store.work(row['id'])['state'] for row in rows], ['ready', 'ready'])
        self.assertEqual(self.store.q1('SELECT state FROM deliveries WHERE message_id=?', (message['id'],))['state'], 'dead')
        self.assertEqual(self.store.q('SELECT * FROM team_members'), [])
        self.assertEqual(self.store.q('SELECT * FROM legacy_names'), [{'legacy': 'legacy-one', 'session': agent['session']}])
        self.assertNotIn('a' * 64, str(replies))

    async def test_old_generation_and_changed_observation_cannot_mutate_replacement(self):
        agent, rows = self.claimed()
        wrong = self.descriptor('state', session=agent['session'], generation=agent['generation'] + 1, state='dead', note=None)
        with self.assertRaises(ContractError):
            await self.call('state', wrong)
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note=None,
            observation={'handle':'replaced-handle','panePid':agent['pane_pid'],'created':agent['created'],'state':agent['state']})
        value['purpose'] = 'hub-observation'
        replies = await self.call('state', value)
        self.assertEqual([reply['result'] for reply in replies], [False, False])
        self.assertEqual(self.store.agent(agent['session']), agent)
        self.assertEqual([self.store.work(row['id']) for row in rows], rows)

    async def test_changed_source_refuses_without_running_effect(self):
        agent, rows = self.claimed()
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note=None)
        original = self.other._source_worker
        self.other._source_worker = object()
        try:
            with self.assertRaises(ContractError):
                await self.call('state', value)
        finally:
            self.other._source_worker = original
        self.assertEqual(self.store.agent(agent['session']), agent)
        self.assertEqual([self.store.work(row['id']) for row in rows], rows)

    async def test_fresh_original_outcome_after_owner_restart_does_not_repeat_registration(self):
        value = self.descriptor('register', generation=None, repo='falcon', role='worker', agent='new',
            cli='codex', roleSnapshot={'max_active': 1}, transport='tmux', handle=None, panePid=None,
            legacy=None, tokenSha='b' * 64)
        originals = self.requests('register', value)
        result = await self.call('register', value)
        before = self.store.agent(result[0]['result'])
        await self.lifecycle.close()
        self.lifecycle = WorkLifecycleOwner((self.resource, self.other))
        self.addAsyncCleanup(self.lifecycle.close)
        for index, (resource, packet) in enumerate(originals):
            claims = strict_loads(packet)['claims']
            query = {'contractId': claims['contractId'], 'operationId': claims['operationId'],
                'payloadDigest': payload_digest(claims['payload'])}
            self.work_request('outcome', query, operation='fresh-outcome-' + str(index), identity='service')
            self.claims['payload']['resourceRef'] = {**ref(resource.binding.entity_id),
                'revision': resource._journal.current()['revision']}
            self.claims['expectedVersion'] = self.claims['payload']['resourceRef']['revision']
            if resource is self.other:
                self.claims['grantRef'] = self.other_grants['federation-work-outcome']
            raw = self.request()
            endpoint = self.endpoint if resource is self.resource else self.other_endpoint
            response = await endpoint.handle(raw, received_reply_subject=strict_loads(raw)['claims']['replySubject'])
            recovered = self.verify_reply(response, raw)
            self.assertEqual({key: recovered[key] for key in result[index]}, result[index])
        self.assertEqual(self.store.agent(before['session']), before)

    async def test_cancelled_batch_waiter_joins_the_original_transaction(self):
        agent, rows = self.claimed()
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note=None)
        admitted = []
        for resource, packet in self.requests('state', value):
            endpoint = self.endpoint if resource is self.resource else self.other_endpoint
            _, _, inner, _ = await endpoint._admit(packet, strict_loads(packet)['claims']['replySubject'])
            admitted.append((resource, inner))
        entered, release = threading.Event(), threading.Event()
        original = self.store.set_state
        def held(*args):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('controlled transaction was not released')
            return original(*args)
        with patch.object(self.store, 'set_state', held):
            tasks = [asyncio.create_task(self.lifecycle.apply(resource, self.service.reader, raw))
                for resource, raw in admitted]
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                tasks[0].cancel()
                await asyncio.sleep(0)
                self.assertFalse(tasks[0].done())
                release.set()
                results = await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                release.set()
                await asyncio.gather(*tasks, return_exceptions=True)
        self.assertIsInstance(results[0], asyncio.CancelledError)
        self.assertEqual(results[1]['outcome'], 'applied')
        self.assertEqual(self.store.agent(agent['session'])['state'], 'dead')
        self.assertEqual([self.store.work(row['id'])['state'] for row in rows], ['ready', 'ready'])
        self.assertEqual(self.lifecycle._workers, set())

    async def test_single_repository_outcome_cannot_disclose_a_batch_after_other_grant_revocation(self):
        agent, _ = self.claimed()
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note=None)
        originals = self.requests('state', value)
        await self.call('state', value)
        record = strict_loads(self.js.messages[-1].data)
        grant_ref = self.other_grants['federation-work-state']
        next(item for item in record['state']['grants'] if item['ref'] == grant_ref)['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(record)
        resource, packet = originals[0]
        raw = self.work_request('outcome', self.query(packet), operation='fresh-outcome', identity='service')
        with self.assertRaises(ContractError):
            await self.endpoint.handle(raw, received_reply_subject=strict_loads(raw)['claims']['replySubject'])

    async def test_last_batch_snapshot_rechecks_an_earlier_repository_grant(self):
        from . import work_legacy
        agent, rows = self.claimed()
        value = self.descriptor('state', session=agent['session'], generation=agent['generation'], state='dead', note=None)
        admitted = []
        for resource, packet in self.requests('state', value):
            endpoint = self.endpoint if resource is self.resource else self.other_endpoint
            _, _, inner, _ = await endpoint._admit(packet, strict_loads(packet)['claims']['replySubject'])
            admitted.append((resource, inner))
        original, count = work_legacy.authorize, 0
        async def revoke_during_last_admission(resource, authority, raw, *, source_expectation=None):
            nonlocal count
            if resource is self.other:
                count += 1
                if count == 2:
                    record = strict_loads(self.js.messages[-1].data)
                    grant_ref = self.work_grants['service']['federation-work-state']
                    next(item for item in record['state']['grants'] if item['ref'] == grant_ref)['status'] = 'revoked'
                    self.js.messages[-1].data = canonical_bytes(record)
            return await original(resource, authority, raw, source_expectation=source_expectation)
        with patch.object(work_legacy, 'authorize', revoke_during_last_admission):
            replies = await asyncio.gather(*(self.lifecycle.apply(resource, self.service.reader, raw)
                for resource, raw in admitted), return_exceptions=True)
        self.assertTrue(all(isinstance(reply, ContractError) for reply in replies))
        self.assertEqual(self.store.agent(agent['session']), agent)
        self.assertEqual([self.store.work(row['id']) for row in rows], rows)

    async def test_fixed_sweep_cutoff_cannot_expire_an_unselected_repository_mid_operation(self):
        _, rows = self.claimed()
        self.store.db.execute("UPDATE work_items SET lease_until=CASE WHEN repo='falcon' THEN "
            "'2019-01-01T00:00:00.000Z' ELSE '2020-01-01T00:00:00.001Z' END")
        self.store.db.execute("UPDATE claims SET lease_until=CASE WHEN repo='falcon' THEN "
            "'2019-01-01T00:00:00.000Z' ELSE '2020-01-01T00:00:00.001Z' END")
        value = self.descriptor('sweep-global', resources=(self.resource,))
        calls = 0
        def clock(*args):
            nonlocal calls
            calls += 1
            return '2020-01-01T00:00:00.000Z' if calls == 1 else '2020-01-01T00:00:00.002Z'
        self.store.db.create_function('strftime', -1, clock)
        try:
            replies = await self.call('sweep-global', value)
        finally:
            self.store.db.create_function('strftime', -1, None)
        self.assertEqual(replies[0]['result'], [{'id': rows[0]['id'], 'state': 'ready'}])
        self.assertEqual([self.store.work(row['id'])['state'] for row in rows], ['ready', 'claimed'])
        self.assertEqual(len(self.store.q('SELECT * FROM claims')), 1)

    async def test_nonterminal_state_change_does_not_need_unaffected_work_repository_grants(self):
        agent, rows = self.claimed()
        value = self.descriptor('state', resources=(self.resource,), session=agent['session'],
            generation=agent['generation'], state='busy', note='working')
        reply = (await self.call('state', value))[0]
        self.assertEqual(reply['outcome'], 'applied')
        self.assertEqual(self.store.agent(agent['session'])['state'], 'busy')
        self.assertEqual([self.store.work(row['id']) for row in rows], rows)
        self.assertEqual(len(self.store.q('SELECT * FROM claims')), 2)
