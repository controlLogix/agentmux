"""Persistent selected board audit/mirror ownership and cancellation."""
import asyncio
import base64
import hashlib
import json
from datetime import datetime
import os
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import nkeys
from agentmux_contracts import canonical_bytes
from agentmux_contracts import strict_loads

from hub.fed.plugins.board import Board
from hub.fed.policy import rid_for_remote
from hub.store import APP_ID, MIGRATIONS, Store
from .selected_storage import BoardAuditMirrorHost, SelectedStorageFailure
from .selected_storage import SelectedStorageHost
from identity import test_storage_selection as selection_support
from dashboard import test_application_service_host as host_support
from identity.application_service_selection import provision_application_service_issuer
from identity.authority import AuthoritySnapshot
from state_owner.backup_host import BackupHost
from state_owner.ledger import OwnerBinding, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import FakeJetStream, record




class BoardAuditMirrorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name).resolve()
        self.database = root / 'hub.db'
        store = Store(str(self.database))
        store.repo_add('falcon')
        for statement in Board.tables:
            store.db.execute(statement)
        store.db.close()
        self.database.chmod(0o600)
        self.policy = root / 'federation.toml'
        policy = b'[federation]\npeer="nick"\n[repos.falcon]\nremote="example.invalid/falcon"\nboard_prefix="SH"\n'
        self.policy.write_bytes(policy)
        self.policy.chmod(0o600)
        pins = {'database': {'path': str(self.database), 'applicationId': APP_ID,
                'userVersion': len(MIGRATIONS)},
            'policy': {'path': str(self.policy), 'sha256': 'sha256:' + hashlib.sha256(policy).hexdigest()}}
        repository = {'localName': 'falcon', 'repositoryId': rid_for_remote('example.invalid/falcon'),
            'normalizedRemote': 'example.invalid/falcon', 'counterPrefix': 'SH'}
        self.owner = BoardAuditMirrorHost(pins, repository=repository, local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.owner.close)
        await self.owner.start()

    def reopen(self):
        return Store.open_existing(str(self.database), application_id=APP_ID,
            user_version=len(MIGRATIONS), owner_uid=os.getuid())

    async def test_real_store_uses_one_executor_and_keeps_unknown_records_after_close(self):
        def write():
            with self.owner._store.tx():
                self.owner._store.event('board', 'SH-1', 'written', 'peer:nick')
            return threading.get_ident()
        first = await self.owner.db(write)
        second = await self.owner.db(threading.get_ident)
        self.assertEqual(first, second)
        self.assertNotEqual(first, threading.get_ident())
        await self.owner.close()
        store = self.reopen()
        try:
            self.assertEqual(store.q1('SELECT entity_id, actor FROM events'),
                {'entity_id': 'SH-1', 'actor': 'peer:nick'})
            self.assertEqual(store.q('SELECT * FROM fed_audit'), [])
        finally:
            store.db.close()

    async def test_cancelled_transaction_and_close_keep_original_worker_until_joined(self):
        entered, release = threading.Event(), threading.Event()
        def transaction():
            with self.owner._store.tx():
                self.owner._store.event('board', 'SH-1', 'begin', 'peer:nick')
                entered.set()
                release.wait()
                self.owner._store.event('board', 'SH-1', 'end', 'peer:nick')
        task = asyncio.create_task(self.owner.db(transaction))
        try:
            async with asyncio.timeout(3):
                while not entered.is_set():
                    await asyncio.sleep(.001)
            task.cancel()
            with self.assertRaisesRegex(SelectedStorageFailure, '^selected_board_projection_cleanup_incomplete$'):
                await self.owner.close(timeout=.001)
            original = self.owner._closing
            self.assertFalse(task.done())
            self.assertTrue(self.owner._pending)
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await self.owner.close()
        self.assertIs(self.owner._closing, original)
        self.assertTrue(original.done())
        store = self.reopen()
        try:
            self.assertEqual([row['event'] for row in store.q('SELECT event FROM events ORDER BY seq')],
                ['begin', 'end'])
        finally:
            store.db.close()

    async def test_changed_selected_policy_fences_projection_without_migrating_database(self):
        self.policy.write_text(self.policy.read_text() + '\n# changed after admission\n')
        with self.assertRaisesRegex(Exception, '^selected_board_projection_unavailable$'):
            self.owner.check_health()
        self.assertTrue(self.owner._closed)
        await self.owner.close()
        store = self.reopen()
        try:
            self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], len(MIGRATIONS))
            self.assertEqual(store.q('SELECT * FROM fed_audit'), [])
        finally:
            store.db.close()

    async def test_failed_policy_and_consumed_close_keep_provisional_store_and_same_custody(self):
        import copy
        pins = copy.deepcopy(self.owner._pins)
        repository = self.owner._repository
        await self.owner.close()
        pins['policy']['sha256'] = 'sha256:' + '0' * 64
        provisional = BoardAuditMirrorHost(pins, repository=repository, local_peer='nick', owner_uid=os.getuid())
        try:
            with self.assertRaisesRegex(SelectedStorageFailure, '^selected_board_projection_unavailable$'):
                await provisional.start()
            store = provisional._store
            self.assertIsNotNone(store)
            custody = store._selected_custody
            descriptor = custody.rows[-1][1]
            real_close = os.close
            attempts = []
            def consumed(fd):
                real_close(fd)
                if fd == descriptor:
                    attempts.append(fd)
                    raise OSError('consumed close fault')
            with patch('hub.store.os.close', side_effect=consumed):
                with self.assertRaisesRegex(SelectedStorageFailure, '^selected_board_projection_cleanup_incomplete$') as failure:
                    await provisional.close()
            self.assertIs(provisional._store, store)
            self.assertIs(failure.exception._cause.owner, custody)
            self.assertEqual(custody.uncertain, [descriptor])
            with patch('hub.store.os.close', side_effect=AssertionError('must not retry consumed descriptor')):
                with self.assertRaises(SelectedStorageFailure):
                    await provisional.close()
            self.assertEqual(attempts, [descriptor])
            self.assertEqual(custody.rows, [])
        finally:
            # All closes were consumed and original futures joined. Preserve the
            # uncertainty record while joining the test-owned executor itself.
            await asyncio.to_thread(provisional._executor.shutdown, wait=True)


class SelectedStorageCompositionTests(unittest.IsolatedAsyncioTestCase):
    connection = selection_support.StorageSelectionTests.connection
    custody = selection_support.StorageSelectionTests.custody
    selected = selection_support.StorageSelectionTests.selected
    add_board = selection_support.StorageSelectionTests.add_board
    identity_inputs = selection_support.StorageSelectionTests.identity_inputs
    authority_record = selection_support.StorageSelectionTests.authority_record

    def setUp(self):
        selection_support.StorageSelectionTests.setUp(self)
        self.publisher_clients = []
        if getattr(self, 'include_board', False):
            self.add_board()
            board = self.value['storage']['board']
            from nacl.signing import SigningKey
            seed = bytes([23]) * 32
            key = self.root / 'board-phase.key'
            key.write_bytes(seed)
            key.chmod(0o600)
            board['phaseAuthority'].update(keyFile={'path': str(key),
                'sha256': 'sha256:' + hashlib.sha256(seed).hexdigest()},
                publicKey=base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('='))
            database = Path(board['auditMirror']['database']['path'])
            store = Store(str(database))
            store.repo_add('falcon')
            for statement in Board.tables:
                store.db.execute(statement)
            store.db.close()
            database.chmod(0o600)
            board['auditMirror']['database'].update(applicationId=APP_ID, userVersion=len(MIGRATIONS))
            raw = b'[federation]\npeer="local"\n[repos.falcon]\nremote="example.com/falcon"\nboard_prefix="SH"\n'
            policy_path = Path(board['auditMirror']['policy']['path'])
            policy_path.write_bytes(raw)
            policy_path.chmod(0o600)
            board['auditMirror']['policy']['sha256'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
        names = ('private', 'storage', 'outcome', 'card', 'allocation') if getattr(self, 'include_board', False) else ('private', 'storage', 'outcome')
        for name in names:
            (self.root / name).mkdir(mode=0o700)
        for name, entry in self.value['storage']['receivers'].items():
            payload, receipt = provision_application_service_issuer(entry['issuer']['keyFile']['path'],
                service_id=name + '-owner', profile_id='profile-one', authority_id='authority-one',
                instance_id=entry['serviceInstanceId'], identity={'ref': entry['serviceIdentityRef'],
                    'kind': 'service', 'status': 'active', 'principalId': name + '-service', 'externalIdentity': None},
                issuer_ref=entry['issuer']['issuerRef'], issued_at=self.issuer_start, expires_at=self.issuer_end)
            entry['issuer'].update(keyFile={'path': receipt.path, 'sha256': receipt.digest},
                publicKey=payload['issuers'][0]['record']['publicKey'])
        selected = self.selected()
        from native_security.nats_credentials import storage_receiver_policy, private_storage_publisher_policy, board_publisher_policy
        for index, name in enumerate(names):
            entry = selected.storage_descriptor(name)
            policy = (private_storage_publisher_policy if name == 'private' else
                storage_receiver_policy if name in ('storage', 'outcome') else board_publisher_policy)(
                **selected.storage_policy_inputs(name))
            account = nkeys.from_seed(nkeys.encode_seed(bytes([1]) * 32, nkeys.PREFIX_BYTE_ACCOUNT))
            user = nkeys.from_seed(nkeys.encode_seed(bytes([40 + index]) * 32, nkeys.PREFIX_BYTE_USER))
            try:
                now = int(self.test_now.timestamp())
                permissions = {'type': 'user', 'version': 2, 'pub': {'allow': list(policy.publish_subjects)},
                    'sub': {'allow': list(policy.subscribe_subjects)}}
                if getattr(policy, 'response_permissions', None) is not None:
                    permissions['resp'] = policy.response_permissions
                claims = {'iss': account.public_key.decode(), 'sub': user.public_key.decode(),
                    'iat': now, 'exp': now + 3600, 'nats': permissions}
                encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
                signed = encode({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encode(claims)
                token = signed + b'.' + base64.urlsafe_b64encode(account.sign(signed)).rstrip(b'=')
                raw = b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n' + \
                    b'-----BEGIN USER NKEY SEED-----\n' + user.seed + b'\n------END USER NKEY SEED------\n'
                pin = (self.value['storage']['privateStorage']['publisher'] if name == 'private' else
                    self.value['storage']['receivers'][name] if name in ('storage', 'outcome') else
                    self.value['storage']['board'][name + 'Publisher'])['credentials']
                Path(pin['path']).write_bytes(raw)
                Path(pin['path']).chmod(0o600)
                pin.update(sha256='sha256:' + hashlib.sha256(raw).hexdigest(),
                    accountPublicKey=account.public_key.decode(), userPublicKey=user.public_key.decode())
            finally:
                account.wipe()
                user.wipe()
        private = self.value['storage']['privateStorage']
        for field in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
            Path(private['backup'][field]).mkdir(mode=0o700)
        self.selection = self.selected()
        pins = private['ledger']
        binding = OwnerBinding('hub-one', 'plugin-private', pins['entityId'], 'plugin-storage', canonical_bytes(self.scope))
        source = StreamIdentity(datetime.fromisoformat(pins['streamIdentity']['created']), 0)
        backup = private['backup']
        backup_host = BackupHost(*(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=binding, stream_identity=source)
        backup_host.enroll_key(backup['keyId'])
        limits = pins['retention']
        policy = Retention(limits['maxBytes'], limits['reserveBytes'], limits['replicas'])
        js = host_support.JetStream(policy)
        js.config = policy.stream_config(stream=pins['stream'], subject=owner_subject(binding))
        js._prefix = '$JS.enrolled-domain.API'
        initial = record()
        initial.update(entityId=binding.entity_id, entityKind=binding.entity_kind,
            ownerDomain=binding.owner_domain, effects=[], state={'formatVersion': 1, 'owner': {
                'pluginIdentityRef': private['pluginIdentityRef'], 'instanceId': private['instanceId'],
                'packageId': private['packageId']}, 'value': {'retained': True}})
        js.messages = [SimpleNamespace(subject=owner_subject(binding), seq=1, data=canonical_bytes(initial))]
        self.clients = [host_support.Client(js), host_support.Client(object()), host_support.Client(object())]
        for client in self.clients:
            client.max_payload = 98304
        if getattr(self, 'include_board', False):
            from .test_board_storage_route import BoardJetStream, PublisherConnection
            board = self.value['storage']['board']
            source = StreamIdentity(datetime.fromisoformat(board['kvStreamIdentity']['created']), 0)
            card = {'key': board['cardKey'], 'rid': board['repository']['repositoryId'], 'title': 'Existing',
                'status': 'todo', 'comments': [], 'history': [], 'unknownFutureField': {'retained': True}}
            entry = SimpleNamespace(bucket='am_board', key=card['rid'] + '.card.' + card['key'],
                revision=board['resourceRef']['revision'], value=canonical_bytes(card))
            info = SimpleNamespace(config=SimpleNamespace(name='KV_am_board', subjects=['$KV.am_board.>']),
                created=source.created, state=SimpleNamespace(last_seq=entry.revision))
            board_js = SimpleNamespace(stream_info=AsyncMock(return_value=info))
            kv = SimpleNamespace(get=AsyncMock(return_value=entry))
            for name in ('allocation', 'card'):
                pin = board[name + 'Publisher']
                for field in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
                    Path(pin['backup'][field]).mkdir(mode=0o700)
                limits = pin['ledger']['retention']
                retention = Retention(limits['maxBytes'], limits['reserveBytes'], limits['replicas'])
                binding = OwnerBinding('hub-one', 'federation-board-operations', pin['ledger']['entityId'], 'attempt',
                    canonical_bytes(self.scope))
                backup = pin['backup']
                backup_host = BackupHost(*(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
                    destination_id=backup['destinationId'], binding=binding, stream_identity=source)
                backup_host.enroll_key(backup['keyId'])
                journal = FakeJetStream(retention)
                journal.config = retention.stream_config(stream=pin['ledger']['stream'], subject=owner_subject(binding))
                jetstream = BoardJetStream(journal, board_js, kv)
                jetstream._prefix = '$JS.enrolled-domain.API'
                self.publisher_clients.append(PublisherConnection(jetstream))
        # Use the existing source fixture's real IdentityService and reader.
        self.identity = self.identity_inputs(self.selection)
        if not getattr(self, 'include_board', False):
            self.add_board()
        current = self.authority_record()
        if not getattr(self, 'include_board', False):
            self.value['storage'].pop('board')
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), 1)

    async def asyncSetUp(self):
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)

    async def test_private_composition_uses_real_owners_and_retained_custody(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            self.host.check_health()
            self.assertEqual(await self.host._resources[0].read(1), canonical_bytes({'retained': True}))
            self.assertEqual(len(self.host._receivers), 2)
            self.assertEqual(len({id(client) for client in self.host._clients}), 3)
            for client in self.clients:
                self.assertTrue(client.options['user_jwt_cb']())
                self.assertTrue(client.options['signature_cb']('broker-nonce'))
                self.assertFalse(client.options['allow_reconnect'])
            custody = self.host._custody[0]
            self.assertEqual(custody.backup._host.latest().receipt.cursor, 1)
            await self.host.close(timeout=None)
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.clients))
        self.assertFalse(self.identity._closed)

    async def test_failed_checkpoint_retains_failure_but_cleanup_joins_all_owners(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch('capability_owner.board_publisher.new_client', side_effect=self.publisher_clients):
            await self.host.start()
            custody = self.host._custody[0]
            custody._cadence._dirty_since = 0
            with patch.object(custody.checkpoint, 'committed', AsyncMock(side_effect=OSError('private write fault'))):
                custody.check()
                failed = custody._export
                with self.assertRaises(OSError):
                    await failed
            with self.assertRaisesRegex(SelectedStorageFailure, '^selected_storage_unavailable$'):
                self.host.check_health()
            await self.host.close(timeout=None)
        self.assertIs(custody._export, failed)
        self.assertIsInstance(failed.exception(), OSError)
        self.assertTrue(custody.backup._closing.done())
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.host._clients))

    async def test_failed_initial_backup_preserves_original_and_closes_partial_startup(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch.object(BackupHost, 'commit', side_effect=OSError('private inventory fault')):
            with self.assertRaisesRegex(SelectedStorageFailure, '^selected_storage_start_unconfirmed$'):
                await self.host.start()
            custody = self.host._custody[0]
            failed = custody.backup._startup
            await self.host.close(timeout=None)
        self.assertIs(custody.backup._startup, failed)
        self.assertIsNotNone(failed.exception())
        self.assertIsNone(custody.backup._host.latest())
        self.assertEqual(self.host._receivers, [])
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.host._clients))

    async def test_due_backup_refreshes_lost_ack_without_another_client_operation(self):
        import copy
        from agentmux_contracts import ContractError, strict_loads, payload_digest
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch('capability_owner.board_publisher.new_client', side_effect=self.publisher_clients):
            await self.host.start()
            custody = self.host._custody[0]
            js = self.clients[0].js
            later = copy.deepcopy(strict_loads(js.messages[0].data))
            later.update(recordId='record-lost-reply', entityVersion=2, previousRevision=1)
            later['state']['value'] = {'retained': True, 'lostReply': True}
            later['operation'].update(operationId='lost-reply', expectedVersion=1,
                payloadDigest=payload_digest(later['state']['value']))
            js.lose_ack = True
            with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
                await custody.ledger.append(later, expected_sequence=1, completion_records=0)
            self.assertEqual(custody.history.verified_cursor, 1)
            custody.backup._clock = lambda: custody.backup._last_clock + 3601
            await custody.backup.run_due()
            self.assertEqual(custody.history.verified_cursor, 2)
            self.assertEqual(custody.backup._host.latest().receipt.cursor, 2)
            self.assertEqual(len(js.messages), 2)
            await self.host.close(timeout=None)


class BothSelectedStorageCompositionTests(SelectedStorageCompositionTests):
    include_board = True

    async def test_private_composition_uses_real_owners_and_retained_custody(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch('capability_owner.board_publisher.new_client', side_effect=self.publisher_clients):
            await self.host.start()
            self.host.check_health()
            self.assertEqual(len(self.host._resources), 2)
            self.assertEqual(len(self.host._board_owners), 2)
            self.assertEqual(len(self.host._routes), 1)
            self.assertEqual(len(self.host._custody), 3)
            for publisher in self.host._publishers:
                self.assertEqual(publisher._connection.options['tls_hostname'], 'agentmux.local')
            card = await self.host._resources[1].read(1)
            from agentmux_contracts import strict_loads
            self.assertEqual(strict_loads(card)['unknownFutureField'], {'retained': True})
            await self.host.close(timeout=None)
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(self.host._audit._closing.done())
        self.assertTrue(all(not client.is_connected for client in [*self.clients, *self.publisher_clients]))
        self.assertFalse(self.identity._closed)

    async def test_same_selection_restart_accepts_newer_card_and_keeps_original_bytes(self):
        from .test_board_storage_route import PublisherConnection
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch('capability_owner.board_publisher.new_client', side_effect=self.publisher_clients):
            await self.host.start()
            await self.host.close(timeout=None)
        card_js = self.publisher_clients[1].js
        original = card_js.kv.get.return_value
        # Model two later source writes at the controlled broker boundary. The
        # installed fixture must separately qualify actual writes and recovery.
        original.revision += 2
        card_js.board.stream_info.return_value.state.last_seq = original.revision
        new_clients = [host_support.Client(client.js) for client in self.clients]
        for client in new_clients:
            client.max_payload = 98304
        new_publishers = [PublisherConnection(client.js) for client in self.publisher_clients]
        restarted = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(restarted.close, timeout=None)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=new_clients), \
                patch('capability_owner.board_publisher.new_client', side_effect=new_publishers):
            await restarted.start()
            self.assertIs(restarted._selection, self.selection)
            self.assertEqual(await restarted._resources[1].read(original.revision), original.value)
            await restarted.close(timeout=None)


class ApplicationStorageCompositionTests(unittest.IsolatedAsyncioTestCase):
    include_board = True
    connection = SelectedStorageCompositionTests.connection
    custody = SelectedStorageCompositionTests.custody
    selected = SelectedStorageCompositionTests.selected
    add_board = SelectedStorageCompositionTests.add_board
    identity_inputs = SelectedStorageCompositionTests.identity_inputs
    authority_record = SelectedStorageCompositionTests.authority_record

    def setUp(self):
        SelectedStorageCompositionTests.setUp(self)
        self.identity.ledger._history.close()
        self.storage_clients = self.clients
        storage_state = strict_loads(self.snapshot.record)['state']
        host_support.HostComposition.prepare_services(self)
        initial = strict_loads(self.clients[0].js.messages[0].data)
        # Extend the real baseline ledger with the selected storage principals.
        # Its reader and ingress are created by ApplicationServiceHost below.
        for collection in ('identities', 'issuers', 'transports', 'memberships', 'grants'):
            existing = {canonical_bytes(item['ref']) for item in initial['state'][collection]}
            initial['state'][collection].extend(item for item in storage_state[collection]
                if canonical_bytes(item['ref']) not in existing)
        self.clients[0].js.messages[0].data = canonical_bytes(initial)

    async def asyncSetUp(self):
        self.host = host_support.ApplicationServiceHost(self.selection)
        self.addAsyncCleanup(self.host.close)

    async def test_storage_borrows_actual_application_identity_and_closes_first(self):
        with patch('application_service_host.new_client', side_effect=self.clients), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.storage_clients), \
                patch('capability_owner.board_publisher.new_client', side_effect=self.publisher_clients):
            await self.host.start()
        self.host.check_health()
        storage = self.host._storage
        self.assertIs(storage._identity, self.host._identity)
        self.assertEqual(len(storage._resources), 2)
        entered, release = asyncio.Event(), asyncio.Event()
        original = storage._cleanup
        async def held_cleanup():
            entered.set()
            await release.wait()
            await original()
        with patch.object(storage, '_cleanup', held_cleanup):
            closing = asyncio.create_task(self.host.close())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                self.assertFalse(closing.done())
                self.assertTrue(all(receiver._closed for receiver in storage._receivers))
                self.assertTrue(self.clients[0].is_connected)
                self.assertFalse(self.host._histories[0]._closed)
            finally:
                release.set()
                await closing
        self.assertTrue(all(not client.is_connected for client in
            self.clients + self.storage_clients + self.publisher_clients))
        self.assertTrue(all(history._closed for history in self.host._histories))

    async def test_selected_missing_credentials_refuse_application_readiness(self):
        selected = self.value['storage']['privateStorage']['publisher']['credentials']
        Path(selected['path']).unlink()
        with patch('application_service_host.new_client', side_effect=self.clients), \
                patch('capability_owner.selected_storage.new_client') as create, \
                patch('capability_owner.board_publisher.new_client') as publishers:
            with self.assertRaises(host_support.ApplicationServiceFailure):
                await self.host.start()
        self.assertFalse(self.host._ready)
        self.assertIsNotNone(self.host._storage)
        self.assertIs(self.host._services[-1], self.host._storage)
        create.assert_not_called()
        publishers.assert_not_called()
        await self.host.close()
        self.assertTrue(all(not client.is_connected for client in self.clients))
        self.assertTrue(all(history._closed for history in self.host._histories))

    async def test_storage_connection_loss_ends_application_health(self):
        with patch('application_service_host.new_client', side_effect=self.clients), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.storage_clients), \
                patch('capability_owner.board_publisher.new_client', side_effect=self.publisher_clients):
            await self.host.start()
        await self.storage_clients[0].options['disconnected_cb']()
        with self.assertRaises(SelectedStorageFailure):
            self.host.check_health()
        self.assertTrue(all(receiver._closed for receiver in self.host._storage._receivers))
        await self.host.close()
        self.assertTrue(all(not client.is_connected for client in
            self.clients + self.storage_clients + self.publisher_clients))
