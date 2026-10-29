"""Local adapter behavior against the actual signed owner and real Hub Store."""
import asyncio
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.store import HubError
from hub.tests.test_hub_offline import reg
from hub.tests.test_work_client_transport import material
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from .legacy_work_client import LegacyWorkCommandClient
from .local_work_client import LocalWorkClient
from .test_work_bridge_owner import WorkBridgeFixture
from .work_legacy import LegacyWorkActor
from .work_bridge_service import WorkBridgeService
from .work import WorkStorageResource
from .messages import MessageActor
from state_owner.ledger import OwnerBinding
from identity.test_authority import SEED
from identity.work_client import WORK_COMMAND_SECONDS


class LocalWorkClientTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_work_client', 'capability_owner.local_work_client'):
            patch(module + '.datetime', _Clock).start()
        self.submitted, self.drop_after, self.drop_before = [], None, None
        self.caller = 'operator'
        await self.open_client()

    async def open_client(self, *, identity='human', routes=None):
        prior = getattr(self, 'commands', None)
        if prior is not None:
            await prior.close(timeout=None)
        sessions = tuple(self.session_for(identity, repository, endpoint)
            for repository, endpoint in (routes or [('falcon', self.endpoint)]))
        self.session = sessions[0]
        self.commands = LegacyWorkCommandClient(self.hub, sessions)
        self.client = LocalWorkClient(self.hub, self.commands)
        self.addAsyncCleanup(self.commands.close, timeout=None)

    def session_for(self, identity, repository, endpoint):
        loop = asyncio.get_running_loop()
        value = material()
        value['callerRef'] = ref(identity)
        selected = value['workCommands']
        resource = next(iter(endpoint._resources.values()))
        actor = next(actor for actor in resource._legacy_actors
            if actor.identity_ref == canonical_bytes(ref(identity)) and actor.caller == self.caller)
        grants = strict_loads(actor.grants)
        actions = ('read', 'inspect', 'outcome') if identity == 'service' else (
            ('create', 'cancel', 'read', 'inspect', 'outcome') if self.caller == 'operator' else (
            'create', 'claim', 'heartbeat', 'release', 'claim-path', 'read', 'inspect', 'outcome'))
        selected.update(transportRef=ref('transport' if identity == 'human' else 'legacy-service-transport'),
            resourceRef=ref(resource.binding.entity_id),
            authenticatedCaller=self.caller,
            repository={'localName': repository, 'repositoryId': None},
            grantRefs={'federation-work-' + action: grants['federation-work-' + action]
                for action in actions})
        key = ApplicationClientKey(value)
        session = object.__new__(ApplicationClientSession)
        session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = None
        session._work_enrollment = canonical_bytes({
            **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
            'workCommands': key.selection['workCommands']})
        def command(*, contract_id, operation_id, payload, expires_at, deadline, include_valid_until=False):
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId')},
                'transportRef': selected['transportRef'], 'grantRef': selected['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': payload['resourceRef']['revision'],
                'contractId': contract_id, 'payload': payload, 'approvalRefs': [],
                'issuedAt': NOW.isoformat().replace('+00:00', 'Z'), 'expiresAt': expires_at,
                'replySubject': '_INBOX.local_work_actual_01'}
            self.submitted.append(copy.deepcopy(claims))
            raw = key.sign_command(claims, subject=selected['subject'], now=NOW)
            if self.drop_before == contract_id:
                self.drop_before = None
                raise TimeoutError('controlled request loss')
            response = asyncio.run_coroutine_threadsafe(endpoint.handle(raw,
                received_reply_subject=claims['replySubject']), loop).result(timeout=6)
            if self.drop_after == contract_id:
                self.drop_after = None
                raise TimeoutError('controlled reply loss')
            return key.verify_command_response(response, raw, subject=selected['subject'], now=NOW,
                include_valid_until=include_valid_until)
        session.work_command = command
        return session

    async def agent(self, *, maximum=1, home='falcon'):
        self.caller = reg(self.store, home, 'worker', 'local',
            snap={'capabilities': ['python'], 'max_active': maximum})
        self.work_actors = (LegacyWorkActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')),
            self.caller, canonical_bytes(self.work_grants['human'])), self.work_actors[1])
        await self.replace()
        await self.open_client()

    async def finish(self, value=None):
        await self.client.confirm_completion()
        return self.client.finish_disclosure(value)

    async def open_both_repositories(self):
        state = strict_loads(self.js.messages[-1].data)
        foreign_actors = []
        for actor in self.work_actors:
            grants = {}
            for contract, original_ref in strict_loads(actor.grants).items():
                grant = copy.deepcopy(next(grant for grant in state['state']['grants'] if grant['ref'] == original_ref))
                grant.update(ref=ref(original_ref['id'] + '-other'), resourceId='task-other')
                if not any(existing['ref'] == grant['ref'] for existing in state['state']['grants']):
                    state['state']['grants'].append(grant)
                grants[contract] = grant['ref']
            foreign_actors.append(LegacyWorkActor(actor.identity_ref, actor.transport_ref,
                actor.caller, canonical_bytes(grants)))
        self.js.messages[-1].data = canonical_bytes(state)
        resource = WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'task-other',
            'work-channel', canonical_bytes(self.scope)), self.local, repository='other',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one',
            legacy_actors=tuple(foreign_actors), legacy_authority=self.service.reader)
        endpoint = WorkBridgeService(self.service.ingress, resources=(resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(endpoint.close, timeout=None)
        await self.open_client(routes=[('falcon', self.endpoint), ('other', endpoint)])

    async def test_selected_automatic_claim_preserves_cross_home_group_eligibility(self):
        self.store.repo_add('falcon', groups=['shared'])
        self.store.repo_add('other', groups=['shared'])
        await self.agent(home='other', maximum=3)
        await self.open_both_repositories()
        selected = self.store.work_create('operator', 'falcon', 'role:group:shared/worker', 'Selected', priority=20)
        foreign = self.store.work_create('operator', 'other', 'role:group:shared/worker', 'Foreign', priority=1)
        result = await self.client.claim(self.caller, {}, repository='falcon',
            intent_digest=payload_digest({'selected_claim': 1}))
        self.assertEqual(result['claimed']['id'], selected['id'])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        await self.finish(result)
        # The same shared client remains usable by its original aggregate callers.
        result = await self.client.claim(self.caller, {}, intent_digest=payload_digest({'unscoped_claim': 1}))
        self.assertEqual(result['claimed']['id'], foreign['id'])
        await self.finish(result)

    async def test_selected_empty_claim_never_falls_back_to_foreign_work(self):
        await self.agent(maximum=3)
        await self.open_both_repositories()
        foreign = self.store.work_create('operator', 'other', 'role:*/worker', 'Foreign')
        result = await self.client.claim(self.caller, {}, repository='falcon',
            intent_digest=payload_digest({'empty_selected': 1}))
        self.assertIsNone(result['claimed'])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        await self.finish(result)

    async def test_selected_claim_still_counts_foreign_active_capacity(self):
        await self.agent(maximum=1)
        await self.open_both_repositories()
        foreign = self.store.work_create('operator', 'other', 'role:*/worker', 'Active')
        self.store.claim(self.caller, work_id=foreign['id'], repository='other')
        selected = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Ready')
        result = await self.client.claim(self.caller, {}, repository='falcon',
            intent_digest=payload_digest({'capacity_selected': 1}))
        self.assertIsNone(result['claimed'])
        self.assertIn('max_active', result['reason'])
        self.assertEqual(self.store.work(selected['id'])['state'], 'ready')
        await self.finish(result)

    async def test_selected_heartbeat_leaves_foreign_lease_unchanged(self):
        await self.agent(maximum=3)
        await self.open_both_repositories()
        rows = [self.store.work_create('operator', repo, 'role:*/worker', repo)
            for repo in ('falcon', 'other')]
        for row in rows:
            self.store.claim(self.caller, lease_s=60, work_id=row['id'], repository=row['repo'])
        foreign = self.store.work(rows[1]['id'])
        result = await self.client.heartbeat(self.caller, {'lease_s': 900}, repository='falcon',
            intent_digest=payload_digest({'heartbeat_selected': 1}))
        self.assertEqual(result, {'renewed': 1})
        self.assertEqual(self.store.work(rows[1]['id']), foreign)
        self.assertGreater(self.store.work(rows[0]['id'])['lease_until'], foreign['lease_until'])
        await self.finish(result)

    async def test_selected_claim_retains_foreign_pending_and_recovers_original_once(self):
        await self.agent(maximum=3)
        await self.open_both_repositories()
        original = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Original', priority=20)
        intent = payload_digest({'selected_original': 1})
        self.drop_after = 'federation-work-claim'
        with self.assertRaises(TimeoutError):
            await self.client.claim(self.caller, {}, repository='falcon', intent_digest=intent)
        retained = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-client:%'")
        await self.open_both_repositories()
        with self.assertRaisesRegex(ContractError, 'recovery_invalid'):
            await self.client.claim(self.caller, {}, repository='other', intent_digest=intent)
        self.assertEqual(self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), retained)
        later = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Later', priority=1)
        result = await self.client.claim(self.caller, {}, repository='falcon', intent_digest=intent)
        self.assertEqual(result['claimed']['id'], original['id'])
        self.assertEqual(self.store.work(later['id'])['state'], 'ready')
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-work-claim']), 1)
        await self.finish(result)

    async def test_selected_explicit_foreign_id_refuses_authorized_row_lookup(self):
        await self.agent(maximum=3)
        await self.open_both_repositories()
        foreign = self.store.work_create('operator', 'other', 'role:*/worker', 'Foreign')
        self.assertIsNone(await self.client.show(self.caller, foreign['id'], repository='falcon'))
        self.client.finish_disclosure()
        with self.assertRaisesRegex(HubError, 'unavailable'):
            await self.client.claim(self.caller, {'work_id': foreign['id']}, repository='falcon',
                intent_digest=payload_digest({'foreign_explicit': 1}))
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        self.assertFalse(any(c['contractId'] == 'federation-work-claim' for c in self.submitted))

    async def test_selected_foreign_conflicted_original_refuses_without_replacement(self):
        from .legacy_messages_client import LegacyStorageConflict
        await self.agent(maximum=3)
        await self.open_both_repositories()
        first = self.store.work_create('operator', 'falcon', 'role:*/worker', 'First', priority=1)
        competing = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Competing', priority=2)
        original, interfere = self.session.work_command, True
        def command(**kwargs):
            nonlocal interfere
            if kwargs['contract_id'] == 'federation-work-claim' and interfere:
                interfere = False
                payload = {**kwargs['payload'], 'input': {'workId': competing['id'], 'leaseSeconds': None}}
                original(**{**kwargs, 'operation_id': 'competing-claim', 'payload': payload})
            return original(**kwargs)
        self.session.work_command = command
        intent = payload_digest({'conflicted_selected': 1})
        with self.assertRaises(LegacyStorageConflict):
            await self.client.claim(self.caller, {}, repository='falcon', intent_digest=intent)
        retained = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-client:%'")
        self.assertIsNotNone(strict_loads(retained[0]['v'])['conflictReceipt'])
        submitted = len(self.submitted)
        with self.assertRaisesRegex(ContractError, 'recovery_invalid'):
            await self.client.claim(self.caller, {}, repository='other', intent_digest=intent)
        self.assertEqual(len(self.submitted), submitted)
        self.assertEqual(self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), retained)
        result = await self.client.claim(self.caller, {}, repository='falcon', intent_digest=intent)
        self.assertEqual(result['claimed']['id'], first['id'])
        await self.finish(result)

    async def test_selected_repository_constraint_requires_immutable_plain_text(self):
        await self.agent(maximum=3)
        class MutableRepository(str):
            pass
        for repository in ('', True, ['falcon'], MutableRepository('falcon')):
            for method, arguments in ((self.client.claim, {}), (self.client.heartbeat, {}),
                    (self.client.add, {'to': 'role:falcon/worker', 'title': 'Refused'}),
                    (self.client.claim_path, {'path': 'src/refused.py'})):
                with self.subTest(repository=repr(repository), method=method.__name__):
                    with self.assertRaises(ContractError):
                        await method(self.caller, arguments, repository=repository,
                            intent_digest=payload_digest({'invalid_selected': 1}))
        self.assertEqual(self.submitted, [])
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_local_unshared_add_retains_exact_raw_row_until_follow_on(self):
        self.store.db.execute('ALTER TABLE work_items ADD COLUMN future_field TEXT')
        args = {'to': 'role:falcon/worker', 'title': 'Original'}
        row = await self.client.add('operator', args, intent_digest=payload_digest(args))
        self.assertEqual(row, self.store.q1('SELECT * FROM work_items'))
        self.assertIn('future_field', row)
        self.assertNotIn('children', row)
        with self.assertRaisesRegex(ContractError, 'completion_pending'):
            self.client.finish_disclosure(row)
        self.assertIn(asyncio.current_task(), self.commands._disclosures)
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 1)
        self.assertEqual(await self.finish(row), row)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        self.assertIsNone(self.resource.repository_id)

    async def test_show_preserves_children_projection_and_list_repository_scope(self):
        parent = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Parent')
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Child', parent_id=parent['id'])
        foreign = self.store.work_create('operator', 'other', 'role:other/worker', 'Foreign')
        shown = await self.client.show('operator', parent['id'])
        self.assertEqual(shown, self.store.work(parent['id']))
        self.client.finish_disclosure(shown)
        self.assertEqual(await self.client.list('operator'), self.store.work(repo='falcon'))
        self.client.finish_disclosure()
        self.assertIsNone(await self.client.show('operator', foreign['id']))
        self.client.finish_disclosure()
        self.assertNotIn('other', str(self.client))

    async def test_claim_capacity_path_heartbeat_and_exact_release_row(self):
        await self.agent()
        row = self.store.work_create('operator', 'falcon', 'role:*/worker', 'First')
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Second')
        claimed = await self.client.claim(self.caller, {}, intent_digest=payload_digest({'claim': 1}))
        self.assertEqual(claimed['claimed']['id'], row['id'])
        await self.finish(claimed)
        limited = await self.client.claim(self.caller, {}, intent_digest=payload_digest({'claim': 2}))
        self.assertIsNone(limited['claimed'])
        self.assertIn('max_active', limited['reason'])
        await self.finish(limited)
        path = await self.client.claim_path(self.caller, {'path': 'src/a.py', 'work_id': row['id']},
            intent_digest=payload_digest({'path': 1}))
        await self.finish(path)
        claims = await self.client.claims(self.caller)
        self.assertEqual(claims, self.store.q('SELECT * FROM claims'))
        self.client.finish_disclosure(claims)
        renewed = await self.client.heartbeat(self.caller, {}, intent_digest=payload_digest({'heartbeat': 1}))
        self.assertEqual(renewed, {'renewed': 1})
        await self.finish(renewed)
        released = await self.client.release(self.caller,
            {'work_id': row['id'], 'outcome': 'done', 'result': 'Exact result'},
            intent_digest=payload_digest({'release': 1}))
        self.assertEqual(released, self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)))
        self.assertNotIn('children', released)
        await asyncio.sleep(0)
        self.assertEqual(self.client.confirm_disclosure(released), released)
        await self.finish(released)

    async def test_lost_add_reply_recovers_original_after_client_replacement(self):
        args = {'to': 'role:falcon/worker', 'title': 'Original', 'federate': True}
        intent = payload_digest(args)
        self.drop_after = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.client.add('operator', args, intent_digest=intent)
        original = self.store.q1('SELECT * FROM work_items')
        await self.open_client()
        recovered = await self.client.add('operator', args, intent_digest=intent)
        self.assertEqual(recovered, original)
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-work-create']), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)
        await self.finish(recovered)

    async def test_expired_follow_on_refuses_final_disclosure_and_retains_original(self):
        args = {'to': 'role:falcon/worker', 'title': 'Original'}
        row = await self.client.add('operator', args, intent_digest=payload_digest(args))
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=WORK_COMMAND_SECONDS + 1)
        with patch('capability_owner.legacy_work_client.datetime', Later):
            with self.assertRaisesRegex(ContractError, 'expired'):
                await self.client.confirm_completion()
            with self.assertRaises(ContractError):
                self.client.finish_disclosure(row)
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 1)

    async def test_readiness_uses_signed_claimable_and_active_and_stale_generation_refuses(self):
        await self.agent()
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Ready')
        result = await self.client.readiness(self.caller)
        self.assertEqual(result, {'claimable': self.store.claimable(self.caller), 'active': [],
            'capacity': {'atCapacity': False, 'available': 1}})
        self.client.finish_disclosure(result)
        self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (self.caller,))
        with self.assertRaises(ContractError):
            await self.client.readiness(self.caller)

    async def test_changed_session_binding_refuses_final_disclosure(self):
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Ready')
        rows = await self.client.list('operator')
        changed = strict_loads(self.session._work_enrollment)
        changed['workCommands']['localNode'] = 'changed'
        self.session._work_enrollment = canonical_bytes(changed)
        with self.assertRaises(ContractError):
            self.client.finish_disclosure(rows)

    async def test_lost_automatic_claim_recovers_original_after_candidates_change(self):
        await self.agent(maximum=3)
        first = self.store.work_create('operator', 'falcon', 'role:*/worker', 'First', priority=10)
        second = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Second', priority=20)
        intent = payload_digest({'original_claim': 1})
        self.drop_after = 'federation-work-claim'
        with self.assertRaises(TimeoutError):
            await self.client.claim(self.caller, {}, intent_digest=intent)
        self.assertEqual(self.store.work(first['id'])['state'], 'claimed')
        await self.open_client()
        recovered = await self.client.claim(self.caller, {}, intent_digest=intent)
        self.assertEqual(recovered['claimed']['id'], first['id'])
        self.assertEqual(self.store.work(second['id'])['state'], 'ready')
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-work-claim']), 1)
        await self.finish(recovered)

    async def test_uncertain_absent_claim_never_resends_original(self):
        await self.agent(maximum=3)
        row = self.store.work_create('operator', 'falcon', 'role:*/worker', 'First')
        intent = payload_digest({'original_claim': 2})
        self.drop_before = 'federation-work-claim'
        with self.assertRaises(TimeoutError):
            await self.client.claim(self.caller, {}, intent_digest=intent)
        await self.open_client()
        with self.assertRaisesRegex(HubError, 'original recovery is retained'):
            await self.client.claim(self.caller, {}, intent_digest=intent)
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-work-claim']), 1)

    async def test_cancel_preserves_parent_child_relationship_and_exact_result(self):
        parent = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Parent')
        child = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Child', parent_id=parent['id'])
        result = await self.client.cancel('operator', {'work_id': parent['id']},
            intent_digest=payload_digest({'cancel': parent['id']}))
        self.assertEqual(set(result['cancelled']), {parent['id'], child['id']})
        await self.finish(result)
        self.assertEqual(self.store.work(child['id'])['state'], 'cancelled')

    async def test_cross_home_repository_group_eligibility_stays_inside_exact_grant(self):
        self.store.repo_add('falcon', groups=('shared',))
        self.store.repo_add('other', groups=('shared',))
        await self.agent(home='other')
        permitted = self.store.work_create('operator', 'falcon', 'role:group:shared/worker', 'Permitted', priority=20)
        foreign = self.store.work_create('operator', 'other', 'role:group:shared/worker', 'Not granted', priority=1)
        readiness = await self.client.readiness(self.caller)
        self.assertEqual([row['id'] for row in readiness['claimable']], [permitted['id']])
        self.client.finish_disclosure(readiness)
        claimed = await self.client.claim(self.caller, {}, intent_digest=payload_digest({'cross_home': 1}))
        self.assertEqual(claimed['claimed']['id'], permitted['id'])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        await self.finish(claimed)

    async def test_operator_and_service_readiness_use_their_own_signed_target_permission(self):
        target = reg(self.store, 'falcon', 'worker', 'target', snap={'max_active': 2})
        ready = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Ready')
        active = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Active')
        self.store.claim(target, work_id=active['id'])
        for identity, caller in (('human', 'operator'), ('service', 'federation')):
            self.caller = caller
            await self.open_client(identity=identity)
            value = await self.client.readiness(caller, target, 'falcon')
            self.assertEqual(value, {'claimable': self.store.claimable(target, repository='falcon'),
                'active': [{'id': active['id'], 'title': 'Active',
                    'lease_until': self.store.work(active['id'])['lease_until']}],
                'capacity': {'atCapacity': False, 'available': 1}})
            self.assertEqual(value['claimable'][0]['id'], ready['id'])
            self.assertEqual(self.submitted[-1]['payload']['input']['query'],
                {'kind': 'readiness', 'session': target})
            self.assertEqual(self.submitted[-1]['transportRef'],
                ref('transport' if identity == 'human' else 'legacy-service-transport'))
            self.client.finish_disclosure(value)

    async def test_agent_readiness_cannot_target_another_agent_or_borrow_operator_route(self):
        await self.agent()
        other = reg(self.store, 'falcon', 'worker', 'other')
        with self.assertRaises(ContractError):
            await self.client.readiness(self.caller, other)
        with self.assertRaisesRegex(ContractError, 'route_unavailable'):
            await self.client.readiness('operator', self.caller)
        value = await self.client.readiness(self.caller)
        self.assertEqual(value['capacity']['available'], 1)
        self.client.finish_disclosure(value)

    async def test_target_readiness_hides_foreign_claim_but_keeps_global_capacity(self):
        self.store.repo_add('falcon', groups=['shared'])
        self.store.repo_add('other', groups=['shared'])
        target = reg(self.store, 'other', 'worker', 'target', snap={'max_active': 1})
        ready = self.store.work_create('operator', 'falcon', 'role:group:shared/worker', 'Allowed')
        hidden = self.store.work_create('operator', 'other', 'role:other/worker', 'Private work')
        self.store.claim(target, work_id=hidden['id'], repository='other')
        self.caller = 'federation'
        await self.open_client(identity='service')
        value = await self.client.readiness('federation', target)
        self.assertEqual([row['id'] for row in value['claimable']], [ready['id']])
        self.assertEqual(value['active'], [])
        self.assertEqual(value['capacity'], {'atCapacity': True, 'available': 0})
        self.assertNotIn(hidden['id'], canonical_bytes(value).decode())
        self.assertNotIn(hidden['title'], canonical_bytes(value).decode())
        self.client.finish_disclosure(value)
        with self.assertRaisesRegex(ContractError, 'route_unavailable'):
            await self.client.readiness('federation', target, 'other')

    async def test_readiness_final_disclosure_keeps_minimum_deadline_and_pending_mutation(self):
        target = reg(self.store, 'falcon', 'worker', 'target')
        row = await self.client.add('operator', {'to': 'role:falcon/worker', 'title': 'Pending'},
            intent_digest=payload_digest({'pending': 1}))
        state = strict_loads(self.js.messages[-1].data)
        grant = next(x for x in state['state']['grants'] if
            x['ref'] == self.work_grants['human']['federation-work-read'])
        grant['expiresAt'] = (NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(state)
        value = await self.client.readiness('operator', target)
        with self.assertRaisesRegex(ContractError, 'completion_pending'):
            self.client.finish_disclosure(value)
        self.assertEqual(len(self.client._completions[asyncio.current_task()]), 1)
        await self.client.confirm_completion()
        self.assertEqual(self.store.work(row['id'])['title'], 'Pending')
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        with patch('capability_owner.legacy_work_client.datetime', Later):
            with self.assertRaisesRegex(ContractError, 'expired'):
                self.client.finish_disclosure(value)
        self.assertIn(asyncio.current_task(), self.commands._disclosures)

    async def test_readiness_revocation_and_target_replacement_during_owner_load_refuse(self):
        target = reg(self.store, 'falcon', 'worker', 'target')
        select = self.resource._select
        def changed(*args, **kwargs):
            value = select(*args, **kwargs)
            self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (target,))
            return value
        with patch.object(self.resource, '_select', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.client.readiness('operator', target)
        state = strict_loads(self.js.messages[-1].data)
        next(x for x in state['state']['grants'] if
            x['ref'] == self.work_grants['human']['federation-work-read'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(state)
        with self.assertRaises(ContractError):
            await self.client.readiness('operator', target)

    async def test_readiness_aggregate_uses_only_named_routes_and_store_order(self):
        self.store.repo_add('falcon', groups=['shared'])
        self.store.repo_add('other', groups=['shared'])
        target = reg(self.store, 'falcon', 'worker', 'target', snap={'max_active': 2})
        old = self.store.work_create('operator', 'other', 'role:group:shared/worker', 'Older', priority=5)
        self.store.db.execute('UPDATE work_items SET created=created-10 WHERE id=?', (old['id'],))
        newer = self.store.work_create('operator', 'falcon', 'role:group:shared/worker', 'Newer', priority=5)
        first = self.store.work_create('operator', 'falcon', 'role:group:shared/worker', 'Priority', priority=1)
        resource = self.open_work(repository='other')
        endpoint = WorkBridgeService(self.service.ingress, resources=(resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(endpoint.close, timeout=None)
        await self.open_client(routes=[('falcon', self.endpoint), ('other', endpoint)])
        value = await self.client.readiness('operator', target)
        self.assertEqual([row['id'] for row in value['claimable']], [first['id'], old['id'], newer['id']])
        self.assertEqual(value['claimable'], self.store.claimable(target))
        self.assertEqual(value['capacity']['available'], 2)
        self.assertTrue(all(set(row) == {'id', 'target', 'title', 'priority'} for row in value['claimable']))
        self.client.finish_disclosure(value)
        scoped = await self.client.readiness('operator', target, 'falcon')
        self.assertEqual(scoped['claimable'], self.store.claimable(target, repository='falcon'))
        self.client.finish_disclosure(scoped)
