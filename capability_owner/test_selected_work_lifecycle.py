"""Protected work channels share custody without sharing project authority."""
import asyncio
import base64
import copy
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from hub.store import Store
from hub.tests.test_hub_offline import reg
from nacl.signing import SigningKey
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from native_security.nats_credentials import storage_receiver_policy
from native_security.test_nats_credentials import credential
from . import test_selected_work as work_support
from .work import WorkStorageResource


class SelectedWorkLifecycleTests(unittest.IsolatedAsyncioTestCase):
    setUp = work_support.SelectedWorkCompositionTests.setUp
    asyncSetUp = work_support.SelectedWorkCompositionTests.asyncSetUp
    connection = work_support.SelectedWorkCompositionTests.connection
    custody = work_support.SelectedWorkCompositionTests.custody
    selected = work_support.SelectedWorkCompositionTests.selected
    add_board = work_support.SelectedWorkCompositionTests.add_board
    identity_inputs = work_support.SelectedWorkCompositionTests.identity_inputs
    authority_record = work_support.SelectedWorkCompositionTests.authority_record
    reopen = work_support.SelectedWorkCompositionTests.reopen

    def configure_channels(self, *, aggregate=False, same_scope=False, include_second=True):
        work = self.value['storage']['work']
        self.other_scope = copy.deepcopy(self.scope) if same_scope else {**self.scope, 'projectId': 'project-other'}
        first = work['channels'][0]
        channels = [first]
        if include_second:
            second = copy.deepcopy(first)
            second.update(resourceRef=ref('work-two'), repository={'localName': 'other'},
                scope=self.other_scope, initialSource=None)
            work['channels'].append(second)
            channels.append(second)
        if aggregate:
            self.value['storage'].pop('privateStorage')
            self.value['storage']['scope'] = {**self.scope, 'projectId': None, 'workspaceId': None}
            work['repository'] = None
            first.update(repository={'localName': 'falcon'}, scope=copy.deepcopy(self.scope))
            reader = copy.deepcopy(first)
            reader.update(resourceRef=ref('work-reader'), repository=None,
                scope=copy.deepcopy(self.value['storage']['scope']), initialSource=None)
            reader.pop('legacyActors', None)
            work['channels'].append(reader)
        if include_second:
            store = self.reopen()
            try:
                store.repo_add('other')
            finally:
                store.db.close()
        record = strict_loads(self.snapshot.record)
        state = record['state']
        service = ref('storage-service')
        state['transports'].append({'ref': ref('maintenance-transport'), 'identityRef': service,
            'issuerRef': self.value['identity']['issuer']['issuerRef'], 'method': 'nats-credential-mapping',
            'publicKey': base64.urlsafe_b64encode(bytes(SigningKey(bytes([51]) * 32).verify_key)).decode().rstrip('='),
            'status': 'active', 'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        for index, channel in enumerate(channels):
            scope = channel.get('scope', self.scope)
            grants = {'federation-work-' + action: ref('lifecycle-' + str(index) + '-' + action)
                for action in ('register', 'state', 'sweep-global')}
            channel['legacyActors'] = [{'identityRef': service, 'transportRef': ref('maintenance-transport'),
                'caller': 'federation', 'grants': grants}]
            for principal, suffix in ((service, 'service'), (ref('human'), 'human')):
                state['memberships'].append({'ref': ref('lifecycle-' + str(index) + '-' + suffix),
                    'identityRef': principal, 'scope': copy.deepcopy(scope), 'status': 'active'})
            for contract, reference in grants.items():
                state['grants'].append({'ref': reference, 'callerRef': service, 'actorRef': service,
                    'scope': copy.deepcopy(scope), 'contractId': contract, 'resourceId': channel['resourceRef']['id'],
                    'decision': 'allowed', 'delegationRef': None, 'definitionTarget': None,
                    'status': 'active', 'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        if aggregate:
            state['memberships'].append({'ref': ref('global-work-human'), 'identityRef': ref('human'),
                'scope': copy.deepcopy(self.value['storage']['scope']), 'status': 'active'})
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
        self.selection = self.selected()
        for seed_number, name in enumerate(('storage', 'outcome'), 41):
            policy = storage_receiver_policy(**self.selection.storage_policy_inputs(name))
            def permissions(claims):
                claims['nats'].update(pub={'allow': list(policy.publish_subjects)},
                    sub={'allow': list(policy.subscribe_subjects)}, resp=policy.response_permissions)
            import nkeys
            encode_seed = nkeys.encode_seed
            def distinct_user(seed, prefix):
                return encode_seed(bytes([seed_number]) * 32 if prefix == nkeys.PREFIX_BYTE_USER else seed, prefix)
            with patch('native_security.test_nats_credentials.nkeys.encode_seed', side_effect=distinct_user):
                raw, account, user = credential(permissions)
            pin = self.value['storage']['receivers'][name]['credentials']
            Path(pin['path']).write_bytes(raw)
            pin.update(sha256='sha256:' + hashlib.sha256(raw).hexdigest(), accountPublicKey=account, userPublicKey=user)
        self.selection = self.selected()

    async def configured_host(self, *, aggregate=False, same_scope=False):
        await self.host.close(timeout=None)
        self.configure_channels(aggregate=aggregate, same_scope=same_scope)
        from .selected_storage import SelectedStorageHost
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        for client in self.clients:
            client.max_payload = 1048576
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients[1:] if aggregate else self.clients):
            await self.host.start()
        return self.host

    async def test_two_named_scopes_share_exact_custody_and_have_distinct_receivers(self):
        host = await self.configured_host()
        resources = [r for r in host._resources if type(r) is WorkStorageResource]
        self.assertEqual(len(resources), 2)
        first, second = resources
        self.assertIs(first._source, second._source)
        self.assertIs(first._store, second._store)
        self.assertIs(first._connection, second._connection)
        self.assertIs(first._source_worker, second._source_worker)
        self.assertIsNot(first._owner, second._owner)
        self.assertEqual(len(host._work_lifecycle_owners), 1)
        host._work_lifecycle_owners[0]._current()
        self.assertEqual(len(host._receivers), 4)
        self.assertEqual({r._scope for r in host._receivers}, {first.binding.scope, second.binding.scope})
        for receiver in host._receivers:
            self.assertTrue(all(r.binding.scope == receiver._scope for r in receiver._receiver._resources.values()))
        host.check_health()
        await host.close(timeout=None)
        self.assertTrue(host._work_lifecycle_owners[0]._closed)
        self.assertIsNone(first._source._store)

    async def test_global_read_handle_does_not_supply_named_mutation_authority(self):
        host = await self.configured_host(aggregate=True)
        resources = [r for r in host._resources if type(r) is WorkStorageResource]
        reader = next(r for r in resources if r.repository is None)
        self.assertEqual(reader._legacy_actors, ())
        self.assertNotIn(reader.binding.entity_id, host._work_lifecycle_owners[0]._resources)
        self.assertEqual(len(host._receivers), 6)
        self.assertEqual(len({id(r._store) for r in resources}), 1)
        host.check_health()

    async def test_second_scope_requires_its_own_current_membership_and_grant(self):
        await self.host.close(timeout=None)
        self.configure_channels()
        original = strict_loads(self.snapshot.record)
        for collection, reference in (('memberships', ref('lifecycle-1-service')),
                ('grants', ref('lifecycle-1-state'))):
            changed = copy.deepcopy(original)
            next(row for row in changed['state'][collection] if row['ref'] == reference)['status'] = 'revoked'
            with self.subTest(collection=collection), \
                    patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                        canonical_bytes(changed), self.snapshot.sequence))):
                with self.assertRaises(ContractError):
                    await self.selection.check_storage_authority(self.identity)

    async def signed_death(self, *, rollback=False, serial_callback=False, cancel_early=False):
        host = await self.configured_host(same_scope=serial_callback or cancel_early)
        resources = sorted((r for r in host._resources if type(r) is WorkStorageResource), key=lambda r: r.repository)
        source = resources[0]._source
        def claimed():
            store = source._store
            session = reg(store, 'falcon', 'worker', 'one')
            store.db.execute("INSERT INTO groups(grp,repo) VALUES ('shared','falcon'),('shared','other')")
            rows = []
            for repository in ('falcon', 'other'):
                row = store.work_create('operator', repository, 'role:group:shared/worker', 'Retained ' + repository)
                store.claim(session, work_id=row['id'])
                store.claim_path(session, repository, 'one.py', row['id'])
                rows.append(store.work(row['id']))
            return store.agent(session), rows
        agent, rows = await source.db(claimed)
        entries = [{'repository': r.repository, 'resourceRef': {**ref(r.binding.entity_id),
            'revision': (await r._owner.db(r._journal.current))['revision']}} for r in resources]
        value = {'batchId': 'selected-lifecycle-death', 'purpose': 'hub-state', 'localNode': 'mac',
            'repositories': entries, 'session': agent['session'], 'generation': agent['generation'],
            'state': 'dead', 'note': None}
        now = datetime.now(timezone.utc)
        packets = []
        for resource, entry in zip(resources, entries):
            actor = resource._legacy_actors[0]
            claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
                'profileId': self.value['kernelScope']['profileId'], 'authorityId': self.value['authorityId'],
                'transportRef': ref('maintenance-transport'),
                'grantRef': strict_loads(actor.grants)['federation-work-state'], 'operationId': value['batchId'],
                'expectedVersion': entry['resourceRef']['revision'], 'contractId': 'federation-work-state',
                'payload': {'resourceRef': entry['resourceRef'], 'input': value, 'attribution': 'federation'},
                'approvalRefs': [], 'issuedAt': now.isoformat().replace('+00:00', 'Z'),
                'expiresAt': (now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'),
                'replySubject': '_INBOX.selected_lifecycle_000001'}
            packet = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
                'signature': sign_claims(claims, bytes([51]) * 32)})
            endpoint = next(endpoint for endpoint in host._receivers if endpoint._service == 'storage-owner'
                and endpoint._scope == resource.binding.scope)
            packets.append((endpoint, packet))
        async def call():
            return await asyncio.gather(*(endpoint.handle(packet,
                received_reply_subject='_INBOX.selected_lifecycle_000001') for endpoint, packet in packets),
                return_exceptions=True)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)):
            if cancel_early:
                endpoint, packet = packets[0]
                await endpoint._receive(SimpleNamespace(data=packet, reply='_INBOX.selected_lifecycle_000001'))
                await asyncio.sleep(0)
                self.assertTrue(endpoint._callbacks)
                await host.close(timeout=None)
                self.assertEqual(endpoint._callbacks, set())
                self.assertEqual(endpoint._active, set())
                retained = self.reopen()
                try:
                    self.assertEqual(retained.agent(agent['session']), agent)
                    self.assertEqual([retained.work(row['id']) for row in rows], rows)
                finally:
                    retained.db.close()
                return
            if rollback:
                with patch.object(resources[1]._journal, '_set', side_effect=RuntimeError('controlled receipt failure')):
                    replies = await call()
                self.assertTrue(all(isinstance(reply, ContractError) for reply in replies))
                self.assertEqual(await source.db(source._store.agent, agent['session']), agent)
                self.assertEqual([await source.db(source._store.work, row['id']) for row in rows], rows)
                self.assertEqual(len(await source.db(source._store.q, 'SELECT * FROM claims')), 2)
            else:
                if serial_callback:
                    endpoint = packets[0][0]
                    for owner, packet in packets:
                        self.assertIs(owner, endpoint)
                        await owner._receive(SimpleNamespace(data=packet, reply='_INBOX.selected_lifecycle_000001'))
                    pending = tuple(endpoint._callbacks)
                    if pending:
                        await asyncio.wait_for(asyncio.gather(*pending), 5)
                    replies = [entry.args[1] for entry in endpoint._connection.publish.await_args_list]
                    self.assertEqual(len(replies), 2, 'The serial subscription must admit every lifecycle participant')
                else:
                    replies = await call()
                from .work_bridge_service import verify_work_bridge_reply
                pin = self.value['storage']['receivers']['storage']
                verified = []
                for reply, (_, packet) in zip(replies, packets):
                    if isinstance(reply, BaseException):
                        raise reply
                    checked = verify_work_bridge_reply(reply, packet, public_key=pin['issuer']['publicKey'],
                        service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                        signing_key_ref=pin['issuer']['issuerRef'], now=datetime.now(timezone.utc))
                    self.assertEqual(checked['outcome'], 'applied')
                    verified.append(checked)
                self.assertEqual((await source.db(source._store.agent, agent['session']))['state'], 'dead')
                self.assertEqual([((await source.db(source._store.work, row['id']))['state']) for row in rows],
                    ['ready', 'ready'])
                if not serial_callback:
                    replay = await call()
                    for repeated, original, (_, packet) in zip(replay, verified, packets):
                        checked = verify_work_bridge_reply(repeated, packet, public_key=pin['issuer']['publicKey'],
                            service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                            signing_key_ref=pin['issuer']['issuerRef'], now=datetime.now(timezone.utc))
                        self.assertEqual(checked, original)

    async def test_actual_selected_signed_batch_returns_both_repositories_once(self):
        await self.signed_death()

    async def test_serial_subscription_admits_same_scope_lifecycle_participants(self):
        await self.signed_death(serial_callback=True)

    async def test_close_joins_incomplete_serial_batch_without_lifecycle_effect(self):
        await self.signed_death(cancel_early=True)

    async def test_actual_selected_signed_batch_rolls_back_agent_and_both_repositories(self):
        await self.signed_death(rollback=True)

    async def test_projection_fields_must_be_paired_and_global_channel_stays_read_only(self):
        await self.host.close(timeout=None)
        self.configure_channels()
        original = copy.deepcopy(self.value)
        channel = self.value['storage']['work']['channels'][1]
        channel.pop('scope')
        with self.assertRaises(ContractError):
            self.selected()
        self.value = copy.deepcopy(original)
        channel = self.value['storage']['work']['channels'][1]
        channel.update(repository=None, scope={**self.other_scope, 'projectId': None})
        with self.assertRaises(ContractError):
            self.selected()
