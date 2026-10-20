"""Production legacy address migration through current identity authority and Hub delivery."""
import asyncio
import copy
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes
from hub.store import HubError, Store
from identity.authority import AuthorityReader, AuthoritySnapshot, _indexes
from identity.legacy_identity import LegacyIdentityAdapter
from identity.test_authority import fixture, ref
from identity.transitions import transition


def alias_record(session='alpha-worker-w1', alias='old-w1', *, source='hub-one', generation=1,
                 identity=None, scope=None, owner=None, name='legacy-one'):
    state = fixture()[0]['state']
    return {
        'ref': ref(name), 'status': 'active', 'identityRef': identity or ref('human'),
        'sourceHubId': source, 'scope': copy.deepcopy(scope or state['memberships'][0]['scope']),
        'instanceOwner': copy.deepcopy(owner), 'registrationGeneration': generation,
        'canonicalSession': session, 'alias': alias,
    }


def native_record():
    """Complete independent native instance, including retained authority facts."""
    digest = 'sha256:' + 'a' * 64
    scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
    times = {'issuedAt': '2026-10-09T12:00:00Z', 'expiresAt': '2026-10-09T12:10:00Z'}
    access = {'action': 'inspect', 'resourceClass': 'task', 'resourceId': 'task-one'}
    return {'ref': ref('native-instance'), 'status': 'active',
        'owner': {'pin': {'packageId': 'test-plugin', 'version': '1.0.0',
                          'manifestChecksum': digest, 'packageChecksum': digest,
                          'provenanceChecksum': digest},
                  'instanceId': 'plugin-one', 'epoch': 'b' * 64, 'generation': 1},
        'identityRef': ref('plugin'), 'hostIdentityRef': ref('host'),
        'manifestDigest': digest, 'relationship': 'independent', 'parentOwner': None,
        'configurationChecksum': digest,
        'facts': {'grant': {'grantId': 'native-grant', 'issuerHubId': 'hub-one',
                    'subjectInstanceId': 'plugin-one', 'scope': scope, 'actions': ['inspect'],
                    'resourceIds': ['task-one'], **times, 'policyRef': ref('native-policy'),
                    'parentGrantRef': None, 'revision': 1},
                  'policy': {'reference': ref('native-policy'), 'subjectInstanceId': 'plugin-one',
                    'scope': copy.deepcopy(scope), **times,
                    'decisions': [{'access': access, 'outcome': 'allow'}]},
                  'parentGrant': None, 'parentAccess': [], 'scopeRef': ref('native-scope'),
                  'configurationRevision': 1, 'secretReferences': [],
                  'domainBindings': [{'id': 'inspect-binding', 'contractId': 'task-inspect',
                    'action': 'inspect', 'resourceClass': 'task', 'resourceIds': ['task-one']}]}}


class LegacyIdentityCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.record = fixture()[0]
        self.scope = copy.deepcopy(self.record['state']['memberships'][0]['scope'])
        self.record['state']['legacyAliases'] = [alias_record(scope=self.scope)]
        self.reader = AuthorityReader(SimpleNamespace(), stream='IDENTITY', subject='identity.profile-one',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        self.reader.current = AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(self.record), 9))
        self.adapter = LegacyIdentityAdapter(self.reader, local_source_hub_id='hub-one', scope=self.scope)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(os.path.join(self.directory.name, 'hub.db'))
        self.addCleanup(self.store.db.close)
        self.store.repo_add('alpha')
        self.session = self.store.register('alpha', 'worker', 'w1', 'codex', {}, legacy='old-w1')
        self.store.set_state(self.session, 'ready')
        self.store.configure_identity_fencing('hub-one')

    async def binding(self, address='old-w1'):
        registration = self.store.registration(address)
        return (await self.adapter.bind((registration,)))[0]

    async def test_production_store_preserves_alias_scope_source_and_generation(self):
        binding = await self.binding()
        self.assertEqual((binding.alias, binding.source_hub_id, binding.registration_generation),
                         ('old-w1', 'hub-one', 1))
        self.assertEqual(binding.canonical_session, self.session)
        self.assertEqual(binding.wire()['scope'], self.scope)
        result = self.store.post('virtual:operator', f'agent:{self.session}', 'note', 'hello',
                                 identity_bindings=(binding,))
        self.assertEqual(result['recipients'], [self.session])

    async def test_same_alias_is_scoped_and_exact_namespace_collision_refuses(self):
        other_scope = copy.deepcopy(self.scope)
        other_scope['projectId'] = 'other-project'
        other = alias_record(scope=other_scope, identity=ref('service'), name='legacy-other')
        self.record['state']['legacyAliases'].append(other)
        binding = await self.binding()
        self.assertEqual(binding.identity_ref, canonical_bytes(ref('human')))
        collision = alias_record(scope=self.scope, identity=ref('service'), name='legacy-collision')
        self.record['state']['legacyAliases'].append(collision)
        with self.assertRaisesRegex(ContractError, 'legacy_identity_collision'):
            _indexes(self.record['state'], 'hub-one')

    async def test_reregistration_fences_old_binding_and_does_not_inherit_alias(self):
        old = await self.binding()
        self.store.set_state(self.session, 'dead')
        self.store.register('alpha', 'worker', 'w1', 'codex', {})
        self.store.set_state(self.session, 'ready')
        self.assertEqual(self.store.agent(self.session)['generation'], 2)
        self.assertIsNone(self.store.agent('old-w1'))
        with self.assertRaisesRegex(HubError, 'recipient changed'):
            self.store.post('virtual:operator', f'agent:{self.session}', 'note', 'stale',
                            identity_bindings=(old,))

    async def test_revoked_identity_membership_and_instance_are_refused(self):
        original = copy.deepcopy(self.record)
        for collection in ('identities', 'memberships'):
            with self.subTest(collection=collection):
                self.record = copy.deepcopy(original)
                self.record['state'][collection][0]['status'] = 'revoked'
                self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 10)
                with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
                    await self.binding()

        self.record = copy.deepcopy(original)
        row = native_record()
        owner = row['owner']
        self.record['state']['identities'].extend([
            {'ref': ref('plugin'), 'principalId': 'plugin-one', 'kind': 'plugin',
             'status': 'active', 'externalIdentity': None},
            {'ref': ref('host'), 'principalId': 'host-one', 'kind': 'service',
             'status': 'active', 'externalIdentity': None},
        ])
        member = copy.deepcopy(self.record['state']['memberships'][0])
        member.update(ref=ref('plugin-member'), identityRef=ref('plugin'))
        self.record['state']['memberships'].append(member)
        self.record['state']['nativeInstances'] = [row]
        self.record['state']['legacyAliases'] = [alias_record(scope=self.scope, identity=ref('plugin'),
            owner=row['owner'])]
        self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 10)
        native_adapter = LegacyIdentityAdapter(self.reader, local_source_hub_id='hub-one', scope=self.scope,
                                               instance_owner=row['owner'])
        binding = (await native_adapter.bind((self.store.registration('old-w1'),)))[0]
        self.assertEqual(binding.identity_ref, canonical_bytes(ref('plugin')))
        self.record['state']['nativeInstances'][0]['status'] = 'revoked'
        self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 11)
        with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
            await native_adapter.bind((self.store.registration('old-w1'),))

        self.record = copy.deepcopy(original)
        self.record['state']['identities'].extend([
            {'ref': ref('plugin'), 'principalId': 'plugin-one', 'kind': 'plugin',
             'status': 'active', 'externalIdentity': None},
            {'ref': ref('host'), 'principalId': 'host-one', 'kind': 'service',
             'status': 'active', 'externalIdentity': None},
        ])
        member = copy.deepcopy(self.record['state']['memberships'][0])
        member.update(ref=ref('plugin-member'), identityRef=ref('plugin'))
        self.record['state']['memberships'].append(member)
        self.record['state']['nativeInstances'] = [native_record()]
        self.record['state']['legacyAliases'] = [alias_record(scope=self.scope, identity=ref('plugin'),
            owner=owner)]
        self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 12)
        binding = (await native_adapter.bind((self.store.registration('old-w1'),)))[0]
        self.record['state'] = transition(self.record['state'], 'identity-revoke',
            {'authorityId': 'authority-one', 'targetRef': ref('host')}, hub_id='hub-one')
        self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 13)
        with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
            await native_adapter.bind((self.store.registration('old-w1'),))
        with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
            await native_adapter.admit_remote(self.store.registration('old-w1'), binding.wire())

    async def test_source_generation_session_and_identity_substitution_are_refused(self):
        original = copy.deepcopy(self.record)
        changes = (
            lambda row: row.update(sourceHubId='other-hub'),
            lambda row: row.update(registrationGeneration=2),
            lambda row: row.update(canonicalSession='alpha-worker-w2'),
            lambda row: row.update(identityRef=ref('service')),
        )
        for change in changes:
            with self.subTest(change=change):
                self.record = copy.deepcopy(original)
                change(self.record['state']['legacyAliases'][0])
                self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 11)
                with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
                    await self.binding()

    async def test_remote_selection_carries_provenance_and_destination_fences_generation(self):
        remote = alias_record(session='beta-worker-w2', alias='beta-worker-w2', source='hub-two', name='remote')
        self.record['state']['legacyAliases'] = [remote]
        self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 12)
        binding = (await self.adapter.bind((), remote_address='agent:beta-worker-w2'))[0]
        sent = self.store.post('virtual:operator', 'agent:beta-worker-w2', 'note', 'remote', remote_ok=True,
                               node='node-one', identity_bindings=(binding,))
        self.assertTrue(sent['remote'])
        envelope = __import__('json').loads(self.store.outbox_pending()[0]['payload'])
        self.assertEqual(envelope['legacyIdentity']['sourceHubId'], 'hub-two')

        destination_dir = tempfile.TemporaryDirectory()
        self.addCleanup(destination_dir.cleanup)
        destination = Store(os.path.join(destination_dir.name, 'hub.db'))
        self.addCleanup(destination.db.close)
        destination.repo_add('beta')
        remote_session = destination.register('beta', 'worker', 'w2', 'codex', {})
        destination.set_state(remote_session, 'ready')
        destination.configure_identity_fencing('hub-two')
        destination_adapter = LegacyIdentityAdapter(self.reader, local_source_hub_id='hub-two', scope=self.scope)
        admitted = await destination_adapter.admit_remote(
            destination.registration(f'agent:{remote_session}'), envelope['legacyIdentity'])
        self.assertIsNotNone(destination.ingest_message(envelope, (admitted,)))
        substituted = copy.deepcopy(envelope['legacyIdentity'])
        substituted['identityRef'] = ref('service')
        with self.assertRaisesRegex(ContractError, 'legacy_identity_provenance_invalid'):
            await destination_adapter.admit_remote(destination.registration(f'agent:{remote_session}'), substituted)
        destination.set_state(remote_session, 'dead')
        destination.register('beta', 'worker', 'w2', 'codex', {})
        destination.set_state(remote_session, 'ready')
        envelope['id'] = 'later-message'
        with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
            await destination_adapter.admit_remote(
                destination.registration(f'agent:{remote_session}'), envelope['legacyIdentity'])

    async def test_remote_short_session_is_refused_when_source_hubs_collide(self):
        first = alias_record(session='beta-worker-w2', alias='beta-worker-w2', source='hub-two', name='remote-one')
        second = alias_record(session='beta-worker-w2', alias='beta-worker-w2', source='hub-three', name='remote-two')
        self.record['state']['legacyAliases'] = [first, second]
        self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 12)
        with self.assertRaisesRegex(ContractError, 'legacy_identity_ambiguous'):
            await self.adapter.bind((), remote_address='agent:beta-worker-w2')

    def test_alias_transition_requires_current_identity_membership_and_instance(self):
        state = self.record['state']
        state['legacyAliases'] = []
        payload = {'authorityId': 'authority-one', 'record': alias_record(scope=self.scope), 'previousRef': None}
        result = transition(state, 'identity-legacy-alias-set', payload, hub_id='hub-one')
        self.assertEqual(result['legacyAliases'], [payload['record']])
        state['memberships'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'legacy_identity_membership_unavailable'):
            transition(state, 'identity-legacy-alias-set', payload, hub_id='hub-one')


class HubLegacyIdentityCase(unittest.IsolatedAsyncioTestCase):
    async def test_dispatch_resolve_and_post_use_enrolled_adapter(self):
        from hub import server
        record = fixture()[0]
        scope = copy.deepcopy(record['state']['memberships'][0]['scope'])
        record['state']['legacyAliases'] = [alias_record(scope=scope)]
        reader = AuthorityReader(SimpleNamespace(), stream='IDENTITY', subject='identity.profile-one',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        reader.current = AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 13))
        adapter = LegacyIdentityAdapter(reader, local_source_hub_id='hub-one', scope=scope)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(server, 'ROOT', directory), patch.object(server, 'HUBDIR', os.path.join(directory, 'hub')):
            hub = server.Hub(legacy_identity=adapter)
            try:
                await hub.db(hub.store.repo_add, 'alpha')
                session = await hub.db(hub.store.register, 'alpha', 'worker', 'w1', 'codex', {},
                                       'tmux', None, None, 'old-w1')
                await hub.db(hub.store.set_state, session, 'ready')
                resolved = await hub.dispatch('resolve', {'address': 'old-w1'}, 'operator')
                posted = await hub.dispatch('post', {'to': 'old-w1', 'kind': 'note', 'body': 'hello'}, 'operator')
                self.assertEqual(resolved['recipients'], [session])
                self.assertEqual(posted['recipients'], [session])
                # Canonicalization must not replace the caller's exact legacy
                # alias with another active mapping for the same session.
                record['state']['legacyAliases'][0]['alias'] = 'other-w1'
                reader.current.return_value = AuthoritySnapshot(canonical_bytes(record), 14)
                with self.assertRaisesRegex(HubError, 'legacy_identity_unavailable'):
                    await hub.dispatch('post', {'to': 'old-w1', 'kind': 'note', 'body': 'refuse'}, 'operator')
                record['state']['legacyAliases'][0]['alias'] = 'old-w1'
                reader.current.return_value = AuthoritySnapshot(canonical_bytes(record), 15)
                await hub._notify_work_owner({'id': 'W-NOTICE', 'title': 'notice', 'state': 'done',
                    'created_by': f'agent:{session}', 'parent_id': None, 'result': 'complete'}, 'other-worker')
                self.assertEqual((await hub.db(hub.store.q1,
                    "SELECT kind FROM messages WHERE ref='W-NOTICE'"))['kind'], 'result')
                self.assertIsNotNone(await hub.fed.post_local(
                    'peer:other', 'old-w1', 'note', 'federated local notice', idem='fed-local'))

                from hub.fed.message_services import LocalMessages
                hub.fed.policy = SimpleNamespace(known_peer=lambda _peer: True, trust=lambda _peer: 'auto',
                    may_receive=lambda _rid, _peer: True, local_of=lambda _rid: 'alpha')
                delivered = await LocalMessages(hub.fed).post('peer:other', f'agent:{session}', 'note',
                    'incoming message', None, 'incoming-one', {},
                    incoming={'from': 'other', 'rid': None}, decision=SimpleNamespace(local_repo='alpha'))
                self.assertEqual(delivered['recipients'], [session])

                record['state']['legacyAliases'].extend([
                    alias_record(session='alpha-worker-w2', alias='adopted-w2', scope=scope,
                                 name='legacy-adopted'),
                    alias_record(session='alpha-worker-w3', alias='alpha-worker-w3', scope=scope,
                                 name='legacy-spawned'),
                ])
                reader.current.return_value = AuthoritySnapshot(canonical_bytes(record), 16)
                await hub.db(hub.store.repo_add, 'alpha', paths=(directory,))
                with patch.object(hub.tp, 'handle', return_value=('%2', 2222)):
                    adopted = await hub.adopt({'legacy': 'adopted-w2', 'repo': 'alpha', 'role': 'worker',
                        'agent': 'w2', 'cli': 'codex'})
                self.assertEqual(adopted['session'], 'alpha-worker-w2')
                with patch('hub.server.subprocess.run', return_value=SimpleNamespace(
                        returncode=0, stdout='started', stderr='')), \
                        patch.object(hub.tp, 'handle', return_value=('%3', 3333)):
                    spawned = await hub.spawn({'repo': 'alpha', 'role': 'worker', 'agent': 'w3',
                                               'cli': 'codex'})
                self.assertEqual(spawned['session'], 'alpha-worker-w3')
                welcome_rows = await hub.db(hub.store.q,
                    "SELECT target FROM messages WHERE kind='control' ORDER BY target")
                self.assertEqual({row['target'] for row in welcome_rows},
                                 {'agent:alpha-worker-w2', 'agent:alpha-worker-w3'})
                courier = os.path.join(directory, 'courier')
                os.makedirs(courier)
                with open(os.path.join(courier, 'pending.jsonl'), 'w') as pending:
                    pending.write(__import__('json').dumps({'sender': 'retired-worker',
                        'recipient': 'old-w1', 'kind': 'note', 'body': 'pending'}) + '\n')
                with patch.object(hub, 'harness', return_value=True):
                    imported = await hub.retire_courier()
                    repeated = await hub.retire_courier()
                self.assertEqual((imported['imported'], imported['duplicate']), (1, 0))
                self.assertEqual((repeated['imported'], repeated['duplicate']), (0, 1))
                binding = (await adapter.bind((await hub.db(hub.store.registration, 'old-w1'),)))[0]
                inbound = {'id': 'remote-one', 'target': f'agent:{session}', 'sender': 'virtual:remote',
                           'kind': 'note', 'body': 'inbound', 'origin': 'other-node',
                           'legacyIdentity': binding.wire()}
                self.assertIsNotNone(await hub.ingest_message(inbound))
                inbound['id'] = 'remote-substitution'
                inbound['legacyIdentity']['identityRef'] = ref('service')
                self.assertIsNone(await hub.ingest_message(inbound))
                record['state']['identities'][0]['status'] = 'revoked'
                reader.current.return_value = AuthoritySnapshot(canonical_bytes(record), 17)
                inbound['id'] = 'remote-after-revoke'
                inbound['legacyIdentity'] = binding.wire()
                self.assertIsNone(await hub.ingest_message(inbound))
            finally:
                await hub.db(hub.store.db.close)
                hub.dbx.shutdown(wait=True)
                hub.io.shutdown(wait=True)


if __name__ == '__main__':
    unittest.main()
