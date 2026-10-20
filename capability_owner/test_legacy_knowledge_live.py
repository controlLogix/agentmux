"""Legacy knowledge over TLS/JWT, real application binding and Hub sockets."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, AsyncMock, Mock
from types import SimpleNamespace

from agentmux_contracts import canonical_bytes, payload_digest, strict_loads
from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner, MessageOutcomeUnconfirmed
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from hub.client_launch_selection import load_selection
from hub.fed import envelope
from hub.fed.plugins.knowledge import Knowledge
from hub.fed.message_services import LocalMessages, FederationPublisher
from hub.fed.session import FederationSession
from hub.fed import ledger
from hub.tests.test_fed_unit import policy
from hub.server import Hub
from identity.application_client import ApplicationClientKey
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .knowledge_legacy import LegacyKnowledgeActor
from .knowledge_bridge_service import KnowledgeBridgeService
from .messages import MessageStorageResource
from .message_bridge_service import MessageBridgeService
from .reply_service import CapabilityReplyService
from .test_legacy_messages_live import LegacyMessageLiveFixture, stamp


class LiveLegacyKnowledgeTests(LegacyMessageLiveFixture, unittest.IsolatedAsyncioTestCase):
    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        policies['federation']['subscribe']['allow'].append('am.know.alice.' + policy().rid_of('falcon'))

    def initial_authority(self):
        record = super().initial_authority()
        for grant in record['state']['grants']:
            if grant['contractId'].startswith('federation-message-'):
                grant['resourceId'] = 'messages-one'
        template = copy.deepcopy(next(g for g in record['state']['grants'] if g['ref'] == ref('legacy-send')))
        self.knowledge_grants = {}
        for command in ('share', 'approve', 'read', 'inspect', 'outcome'):
            contract = 'federation-knowledge-' + command
            grant = {**template, 'ref': ref('knowledge-' + command), 'contractId': contract, 'resourceId': 'task-one'}
            record['state']['grants'].append(grant)
            self.knowledge_grants[contract] = grant['ref']
        self.knowledge_service_grants = {}
        for command in ('index', 'capture', 'withdraw', 'read', 'inspect', 'outcome'):
            contract = 'federation-knowledge-' + command
            grant = {**template, 'ref': ref('knowledge-service-' + command), 'contractId': contract,
                'resourceId': 'task-one', 'callerRef': ref('service'), 'actorRef': ref('service')}
            record['state']['grants'].append(grant)
            self.knowledge_service_grants[contract] = grant['ref']
        finding = {**template, 'ref': ref('service-finding'), 'contractId': 'federation-message-finding',
            'callerRef': ref('service'), 'actorRef': ref('service')}
        record['state']['grants'].append(finding)
        self.service_grants['federation-message-finding'] = finding['ref']
        for old, new in (('transport', 'knowledge-human-transport'),
                ('message-service-transport', 'knowledge-service-transport')):
            original = next(row for row in record['state']['transports'] if row['ref'] == ref(old))
            record['state']['transports'].append({**original, 'ref': ref(new)})
        return record

    async def start_receiver(self):
        await super().start_receiver()
        await self.receiver.close()
        old = self.resource
        messages = MessageStorageResource(OwnerBinding('hub-one', 'federation-messages', 'messages-one',
            'message-channel', canonical_bytes(self.scope)), LocalMessages(self.domain), FederationPublisher(self.domain),
            repository='falcon', peer='alice', actors=old.actors, legacy_actors=old._legacy_actors,
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        self.resource = KnowledgeStorageResource(OwnerBinding('hub-one', 'federation-knowledge', 'task-one',
            'knowledge-channel', canonical_bytes(self.scope)), self.domain, repository='falcon',
            actors=messages.actors, plugin_identity_ref=ref('plugin'), instance_id='plugin-one',
            legacy_actors=(LegacyKnowledgeActor(canonical_bytes(ref('human')), canonical_bytes(ref('knowledge-human-transport')),
                'operator', canonical_bytes(self.knowledge_grants)),
                LegacyKnowledgeActor(canonical_bytes(ref('service')), canonical_bytes(ref('knowledge-service-transport')),
                    'federation', canonical_bytes(self.knowledge_service_grants))), message_sources=(messages,))
        bridge = KnowledgeBridgeService(self.identity.ingress, resources=(self.resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        message_bridge = MessageBridgeService(self.identity.ingress, resources=(messages,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.receiver = CapabilityReplyService(self.identity.reader, resources=[messages, self.resource],
            hub_id='hub-one', profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage,
            knowledge_bridge=bridge, message_bridge=message_bridge)
        await self.receiver.start()

    def knowledge_key(self, *, service=False):
        material = strict_loads(self.application_key(service=service)._material)
        selected = material.pop('messageCommands')
        selected.pop('peer')
        selected['grantRefs'] = self.knowledge_service_grants if service else self.knowledge_grants
        selected['transportRef'] = ref('knowledge-service-transport' if service else 'knowledge-human-transport')
        material['knowledgeCommands'] = selected
        return ApplicationClientKey(material)

    async def cleanup(self):
        interrupted = await self._join_selected_session()
        try:
            if hasattr(self, 'knowledge_client'):
                await self.knowledge_client.close(timeout=None)
            if hasattr(self, 'actual_hub'):
                await self.message_client.close(timeout=None)
                await self.federation_session.close()
                await self.actual_hub.db(self.actual_hub.store.db.close)
                self.actual_hub.dbx.shutdown(wait=True)
                self.actual_hub.io.shutdown(wait=True)
        finally:
            observation = getattr(self, '_observation_task', None)
            if observation is not None:
                observation.cancel()
                await asyncio.gather(observation, return_exceptions=True)
            await super().cleanup()
        private_launch = getattr(self, 'private_launch', None)
        if private_launch is not None:
            shutil.rmtree(private_launch)
        if interrupted:
            raise asyncio.CancelledError()

    async def _join_selected_session(self):
        session = getattr(self, 'selected_session', None)
        if session is None:
            return False
        if getattr(self, '_selected_cleanup', None) is None:
            def finish():
                session.close(deadline=time.monotonic() + 5)
                return session.join_final()
            self._selected_cleanup = asyncio.create_task(asyncio.to_thread(finish))
        interrupted = False
        while True:
            try:
                complete = await asyncio.shield(self._selected_cleanup)
                break
            except asyncio.CancelledError:
                if self._selected_cleanup.cancelled():
                    raise
                interrupted = True
        self.assertTrue(complete)
        self.assertFalse(session._thread.is_alive())
        if session._owner is not None:
            self.assertFalse(session._owner._subscriptions)
            self.assertIsNone(session._owner._exchange_task)
        return interrupted

    async def selected_knowledge_session(self, key):
        from hub.client_launch_connection import selected_publish_subjects
        from native_security.nats_credentials import validate
        self.private_launch = private = Path(tempfile.mkdtemp(prefix='amux-knowledge-client-', dir=Path.home())).resolve()
        def write(name, raw):
            path = private / name
            path.write_bytes(raw)
            path.chmod(0o600)
            return str(path)
        role = 'caller-application'
        credentials = self.credentials[role].read_bytes()
        credential = validate(credentials, account_public_key=self.account_public_key,
            publish_subjects=selected_publish_subjects(key),
            subscribe_subjects=[self.inbox_prefixes[role] + '.>'],
            private_inbox=True, application_publish=True)
        connection = write('connection.json', canonical_bytes({'schemaVersion': '1.0.0',
            'endpoint': self.broker.url, 'serverName': self.server_name, 'rootsPEM': self.ca_file.read_text(),
            'leafCertificateSHA256': self.leaf_digest, 'credentialsFile': write('client.creds', credentials),
            'accountPublicKey': self.account_public_key, 'userPublicKey': credential.public_key,
            'replyPrefix': self.inbox_prefixes[role]}))
        workspace = self.directory / 'selected-workspace'
        workspace.mkdir(mode=0o700)
        selection = write('selection.json', canonical_bytes({'schemaVersion': '1.0.0',
            'hostPolicy': str(self.directory / 'host-policy.json'), 'workspaces': [str(workspace)],
            'instanceId': 'application-one', 'profileId': 'profile-one', 'hubId': 'hub-one',
            'application': {'clientKey': write('client-key.json', key._material), 'connection': connection}}))
        selected = load_selection(selection, deadline=time.monotonic() + 3)
        self.selected_session = ApplicationClientSession(selected)
        await asyncio.to_thread(self.selected_session.start, deadline=time.monotonic() + 4)
        return self.selected_session

    async def test_actual_broker_index_finding_held_approval_and_handoff_capture(self):
        loop = asyncio.get_running_loop()
        async def maintain_observation():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        # This fixture is the existing trusted observer. Keep its short lease
        # live while the actual application and its four owned clients run.
        self._observation_task = asyncio.create_task(maintain_observation())
        self.application_owners = []
        sessions = {'knowledge': [], 'message': []}
        for family in sessions:
            for service in (False, True):
                if family == 'knowledge':
                    key = self.knowledge_key(service=service)
                else:
                    material = strict_loads(self.application_key(service=service)._material)
                    material['messageCommands']['resourceRef'] = ref('messages-one')
                    key = ApplicationClientKey(material)
                role = 'federation-application' if service else 'caller-application'
                connection = await self.connect(role)
                binding = ClientBindingState(connection, public_key=self.issuer_public,
                    signing_key_ref=ref('issuer'), caller_ref=key.selection['callerRef'], scope=self.scope)
                owner = ClientConnectionOwner(connection, binding, command_subject=self.identity_subject,
                    reply_prefix=self.inbox_prefixes[role], signer=key)
                self.application_owners.append(owner)
                owner._connected = True  # This exact scoped TLS/JWT connection was admitted above.
                self.refresh_observation()
                await owner.authenticate(key, deadline=loop.time() + 3, cleanup_deadline=loop.time() + 4)
                session = object.__new__(ApplicationClientSession)
                pins = {name: key.selection[name] for name in
                    ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', family + 'Commands')}
                setattr(session, family + '_enrollment', lambda value=pins: strict_loads(canonical_bytes(value)))
                # Control only the session's thread handoff. The real owner
                # binds, signs and joins its original TLS request and inbox.
                def submit(*, contract_id, operation_id, payload, expires_at, deadline,
                        selected_owner=owner, selected_family=family):
                    return asyncio.run_coroutine_threadsafe(getattr(selected_owner, selected_family + '_command')(
                        contract_id=contract_id, operation_id=operation_id, payload=payload,
                        expires_at=expires_at, deadline=deadline, cleanup_deadline=deadline + 1), loop).result(timeout=6)
                setattr(session, family + '_command', submit)
                sessions[family].append(session)
        (self.directory / 'config.toml').write_text('node="mac"\nbackup_every_s=9007199254740991\n'
            'prune_every_s=9007199254740991\n')
        (self.directory / 'federation.toml').write_text('[federation]\npeer="nick"\nplugins=["messages","knowledge"]\n'
            '[repos.falcon]\nremote="github.com/adag/falcon"\n[peers.alice]\ntrust="auto"\n')
        from hub import server as hub_server
        with patch.object(hub_server, 'ROOT', str(self.directory / 'root')), \
                patch.object(hub_server, 'HUBDIR', str(self.directory)), \
                patch.object(hub_server, 'SOCK', str(self.directory / 'hub.sock')):
            hub = self.actual_hub = Hub(message_sessions=tuple(sessions['message']),
                knowledge_sessions=tuple(sessions['knowledge']))
        token = (self.directory / 'operator.token').read_text().strip()
        fed = hub.fed
        fed.session = self.federation_session = FederationSession()
        fed.nc = await self.connect('federation')
        self.message_client, self.knowledge_client = hub._message_commands, hub._knowledge_commands
        self.store.repo_add('falcon')
        agent = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(agent, 'ready')
        received = loop.create_future()
        async def on_knowledge(message):
            try:
                received.set_result(await fed.receive(message.subject, message.data, message))
            except BaseException as error:
                received.set_exception(error)
        subject = 'am.know.alice.' + self.resource.repository_id
        await fed.nc.subscribe_owned(fed.session, subject, cb=on_knowledge)
        await fed.nc.flush(timeout=2)
        incoming = envelope.make('knowledge', 'alice', 'remote', self.resource.repository_id, '*',
            {'title': 'Actual broker finding', 'body': 'Original remote body', 'author': 'remote/worker'})
        self.refresh_observation()
        await self.admin.publish(subject, canonical_bytes(incoming))
        await self.admin.flush(timeout=2)
        self.assertEqual(await asyncio.wait_for(received, 4), 'delivered')
        self.assertTrue(ledger.seen(self.store, incoming['id']))
        self.assertIsNotNone(self.store.q1('SELECT id FROM messages WHERE idem_key=?',
            (f"know:{incoming['id']}:{agent}",)))
        async def request(verb, args):
            self.refresh_observation()
            reader = SimpleNamespace(readline=AsyncMock(return_value=canonical_bytes({
                'token': token, 'verb': verb, 'args': args})), at_eof=lambda: False)
            writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
            await hub.handle_conn(reader, writer, tcp=True)
            reply = json.loads(writer.write.call_args.args[0])
            self.assertTrue(reply['ok'], reply)
            return reply['result']
        held = envelope.make('knowledge', 'alice', 'remote', self.resource.repository_id, '*',
            {'title': 'Original held finding', 'body': 'Original held body'})
        qid = ledger.quarantine_add(self.store, held, subject, 'know', 'alice', 'original held policy')
        await request('fed_approve', {'id': qid})
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertEqual(self.store.q1('SELECT untrusted FROM p_knowledge_items WHERE id=?', (held['id'],))['untrusted'], 1)
        await request('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff', 'body': 'Actual captured handoff'})
        captured = self.store.q1("SELECT * FROM p_knowledge_items WHERE source='auto:handoff'")
        self.assertIsNotNone(captured)
        self.assertEqual(captured['body'], 'Actual captured handoff')
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 2)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        for prefix in ('legacy-message-client:', 'legacy-knowledge-client:'):
            self.assertEqual(self.store.q('SELECT k FROM fed_state WHERE k LIKE ?', (prefix + '%',)), [])
        self.success = True

    async def test_tls_unknown_outcome_large_read_actual_hub_socket_and_revocation(self):
        key = self.knowledge_key()
        async def maintain_observation():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task = asyncio.create_task(maintain_observation())
        session = await self.selected_knowledge_session(key)
        owner = session._owner
        item = envelope.make('knowledge', 'nick', 'mac', self.resource.repository_id, '*',
            {'title': 'Original TLS finding', 'body': 'Original body ' + 'x' * 81000,
             'tags': [], 'ref': None, 'author': 'operator', 'source': 'explicit'})
        payload = {'resourceRef': ref('task-one'), 'attribution': 'operator', 'input': {'envelope': item}}
        original_publish, dropped = self.storage.publish, False
        async def lose_reply(subject, raw, **kwargs):
            nonlocal dropped
            if (not dropped and subject.startswith(self.inbox_prefixes['caller-application'] + '.')
                    and strict_loads(raw)['claims'].get('requestContractId') == 'federation-knowledge-share'):
                dropped = True
                return
            return await original_publish(subject, raw, **kwargs)
        with patch.object(self.storage, 'publish', side_effect=lose_reply):
            with self.assertRaises(ApplicationSessionFailure):
                await asyncio.to_thread(session.knowledge_command,
                    contract_id='federation-knowledge-share', operation_id='lost-knowledge',
                    payload=payload, expires_at=stamp(datetime.now(timezone.utc) + timedelta(seconds=4)),
                    deadline=time.monotonic() + 2)
        original = session._command_future
        if original is not None:
            with self.assertRaises(MessageOutcomeUnconfirmed):
                await asyncio.shield(asyncio.wrap_future(original))
        self.assertTrue(dropped)
        self.assertFalse(owner._subscriptions)
        self.assertIsNone(owner._exchange_task)
        self.refresh_observation()
        query = {'resourceRef': {**ref('task-one'), 'revision': 2}, 'input': {
            'contractId': 'federation-knowledge-share', 'operationId': 'lost-knowledge',
            'payloadDigest': payload_digest(payload)}}
        recovered = await asyncio.to_thread(session.knowledge_command,
            contract_id='federation-knowledge-outcome', operation_id='recover',
            payload=query, expires_at=stamp(datetime.now(timezone.utc) + timedelta(seconds=4)),
            deadline=time.monotonic() + 3)
        self.assertEqual(recovered['result']['id'], item['id'])
        read = await asyncio.to_thread(session.knowledge_command,
            contract_id='federation-knowledge-read', operation_id='large-read',
            payload={'resourceRef': ref('task-one'), 'input': {'command': 'show', 'id': item['id']}},
            expires_at=stamp(datetime.now(timezone.utc) + timedelta(seconds=4)),
            deadline=time.monotonic() + 3)
        self.assertEqual(read['row']['body'], item['data']['body'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        with socket.socket() as free_port:
            free_port.bind(('127.0.0.1', 0))
            port = free_port.getsockname()[1]
        (self.directory / 'config.toml').write_text(f'node="mac"\ntcp_port={port}\n'
            'backup_every_s=9007199254740991\nprune_every_s=9007199254740991\n')
        (self.directory / 'federation.toml').write_text('[federation]\npeer="nick"\nplugins=["knowledge"]\n'
            'capture=false\nnotify_findings=false\n[repos.falcon]\nremote="github.com/adag/falcon"\n'
            '[peers.alice]\ntrust="auto"\n')
        from hub import server as hub_server
        with patch.object(hub_server, 'ROOT', str(self.directory / 'root')), \
                patch.object(hub_server, 'HUBDIR', str(self.directory)), \
                patch.object(hub_server, 'SOCK', str(self.directory / 'hub.sock')):
            full_hub = Hub(knowledge_sessions=(session,))
            running = asyncio.create_task(full_hub.main())
            try:
                async with asyncio.timeout(3):
                    while not (self.directory / 'hub.sock').exists():
                        await asyncio.sleep(.01)
                self.refresh_observation()
                reader, writer = await asyncio.open_connection('127.0.0.1', port)
                try:
                    token = (self.directory / 'operator.token').read_text().strip()
                    writer.write(canonical_bytes({'token': token, 'verb': 'fed_knowledge_share', 'args': {
                        'repo': 'falcon', 'title': 'Actual socket finding', 'body': 'Actual socket body'}}) + b'\n')
                    await writer.drain()
                    reply = json.loads(await asyncio.wait_for(reader.readline(), 4))
                    self.assertTrue(reply['ok'], reply)
                finally:
                    writer.close()
                    await writer.wait_closed()
            finally:
                full_hub.stop.set()
                await asyncio.wait_for(running, 5)
                await full_hub.db(full_hub.store.db.close)
                full_hub.dbx.shutdown(wait=True)
                full_hub.io.shutdown(wait=True)
        self.assertTrue(full_hub._knowledge_commands._closed)
        self.assertFalse(full_hub._knowledge_commands._workers)
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 2)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        management = await self.connect('host')
        with patch.object(self, 'host', management):
            await self.command('identity-revoke', ref('grant'),
                {'authorityId': 'authority-one', 'targetRef': self.knowledge_grants['federation-knowledge-share']})
        with self.assertRaises(Exception):
            await asyncio.to_thread(session.knowledge_command,
                contract_id='federation-knowledge-outcome', operation_id='revoked',
                payload=query, expires_at=stamp(datetime.now(timezone.utc) + timedelta(seconds=4)),
                deadline=time.monotonic() + 2)
        self.assertFalse(owner._subscriptions)
        entered, release = threading.Event(), threading.Event()
        original_close = session.close
        def held_close(*, deadline):
            entered.set()
            release.wait()
            return original_close(deadline=deadline)
        with patch.object(session, 'close', side_effect=held_close):
            joining = asyncio.create_task(self._join_selected_session())
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                for _ in range(2):
                    joining.cancel()
                    await asyncio.sleep(0)
                    self.assertFalse(joining.done())
                self.assertTrue(session._thread.is_alive())
                self.assertTrue(self.storage.is_connected)
                self.assertTrue(self.private_launch.is_dir())
            finally:
                release.set()
                interrupted = await joining
        self.assertTrue(interrupted)
        self.assertFalse(session._thread.is_alive())
        self.success = True
