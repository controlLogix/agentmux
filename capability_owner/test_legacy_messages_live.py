"""TLS/JWT message exchange, actual application binding and lost-reply recovery."""
import asyncio
import base64
import copy
import hashlib
import json
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
import secrets
import shutil
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import patch, AsyncMock, Mock
import weakref
from nacl.signing import SigningKey

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads
from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner, MessageOutcomeUnconfirmed
from hub.client_launch_session import ApplicationClientSession
from hub.fed import envelope
from hub.fed.message_bridge import MessageBridgeIntents
from hub.fed.message_services import LocalMessages, FederationPublisher
from hub.fed.runtime import Federation
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.plugins.messages import Messages
from hub.fed.session import FederationSession
from hub.store import Store
from hub.server import Hub
from hub.tests.test_fed_unit import policy
from identity.application_binding import ApplicationBindingProvider, ApplicationObservationLease
from identity.application_client import ApplicationClientKey
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding
from .message_bridge_service import MessageBridgeService
from .legacy_messages_client import LegacyMessageCommandClient
from .messages import MessageActor, LegacyMessageActor, MessageStorageResource
from .reply_service import CapabilityReplyService
from .test_policy_live import PolicyLiveFixture


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


class LegacyMessageLiveFixture(PolicyLiveFixture):
    service_id = 'storage-owner'
    enroll_native_instances = False

    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        for role in ('caller-application', 'federation-application', 'federation'):
            self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
        for role in ('caller-application', 'federation-application'):
            policies[role] = {'publish': {'allow': [self.identity_subject, self.read_subject]},
                'subscribe': {'allow': []}}
        policies['federation'] = {'publish': {'allow': ['am.msg.nick.alice']},
            'subscribe': {'allow': ['am.msg.alice.nick']}}

    def initial_authority(self):
        record = super().initial_authority()
        state = record['state']
        base = copy.deepcopy(next(g for g in state['grants'] if g['ref'] == ref('capability-policy-evaluate')))
        self.message_grants = {}
        for command in ('send', 'approve', 'inspect', 'outcome'):
            contract = 'federation-message-' + command
            grant = copy.deepcopy(base)
            grant.update(ref=ref('legacy-' + command), contractId=contract, resourceId='task-one')
            state['grants'].append(grant)
            self.message_grants[contract] = grant['ref']
        self.service_grants = {}
        for command in ('deliver', 'inspect', 'outcome'):
            contract = 'federation-message-' + command
            grant = copy.deepcopy(base)
            grant.update(ref=ref('service-' + command), contractId=contract, resourceId='task-one',
                callerRef=ref('service'), actorRef=ref('service'))
            state['grants'].append(grant)
            self.service_grants[contract] = grant['ref']
        for name, actor, contract in (('application-bind', 'human', 'application-bind'),
                ('application-attest', 'service', 'application-attest'),
                ('application-service-bind', 'service', 'application-bind')):
            grant = copy.deepcopy(base)
            grant.update(ref=ref(name), contractId=contract, resourceId='application-one',
                callerRef=ref(actor), actorRef=ref(actor))
            state['grants'].append(grant)
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('message-observer-member'), identityRef=ref('service'), scope=copy.deepcopy(self.scope))
        state['memberships'].append(member)
        transport = copy.deepcopy(next(t for t in state['transports'] if t['ref'] == ref('transport')))
        transport['ref'] = ref('application-transport')
        state['transports'].append(transport)
        for name in ('message-service-transport', 'application-service-transport'):
            service_transport = copy.deepcopy(transport)
            service_transport.update(ref=ref(name), identityRef=ref('service'),
                publicKey=base64.urlsafe_b64encode(bytes(SigningKey(bytes([23]) * 32).verify_key)).decode().rstrip('='))
            state['transports'].append(service_transport)
        return record

    async def start_receiver(self):
        self.store = Store(str(self.directory / 'hub.db'))
        async def db(function, *args, **kwargs):
            return function(*args, **kwargs)
        self.domain = SimpleNamespace(me='nick', node='mac', store=self.store, db=db, policy=policy(),
            session=FederationSession(), presence={}, fcfg={'primary': True}, kick=lambda: None)
        for name in ('sender_of', 'resolve_repo', 'address_of', 'stage', 'publish'):
            setattr(self.domain, name, getattr(Federation, name).__get__(self.domain))
        resource = MessageStorageResource(OwnerBinding('hub-one', 'federation-messages', 'task-one',
            'message-channel', canonical_bytes(self.scope)), LocalMessages(self.domain), FederationPublisher(self.domain),
            repository='falcon', peer='alice',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            legacy_actors=(LegacyMessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')),
                'operator', canonical_bytes(self.message_grants)),
                LegacyMessageActor(canonical_bytes(ref('service')), canonical_bytes(ref('message-service-transport')),
                    'federation', canonical_bytes(self.service_grants))),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')
        self.resource = resource
        bridge = MessageBridgeService(self.identity.ingress, resources=(resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.receiver = CapabilityReplyService(self.identity.reader, resources=[resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage, message_bridge=bridge)
        await self.receiver.start()
        self.refresh_observation()
        self.identity.application = ApplicationBindingProvider(self.identity.reader,
            observation_lease=self.lease, issuer_ref=ref('issuer'), signing_seed=SEED)

    def refresh_observation(self):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-application-runtime-observation-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'instanceId': 'application-one', 'generation': 1,
            'lifetimeId': 'd' * 64, 'releaseDigest': 'sha256:' + 'a' * 64,
            'policyRef': ref('application-policy'), 'workspaceRef': None, 'scope': self.scope,
            'signingKeyRef': ref('issuer'), 'issuedAt': stamp(now), 'expiresAt': stamp(now + timedelta(seconds=4))}
        raw = canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims, 'signature': sign_claims(claims, SEED)})
        if hasattr(self, 'lease'):
            self.lease.refresh(raw)
        else:
            self.lease = ApplicationObservationLease(raw, asyncio.Event())

    def application_key(self, *, service=False):
        return ApplicationClientKey({'purpose': 'agentmux-application-client-key-v1',
            'seed': base64.b64encode(bytes([23]) * 32 if service else bytes(reversed(SEED))).decode(),
            'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
            'instanceId': 'application-one', 'callerRef': ref('service' if service else 'human'), 'scope': self.scope,
            'transportRef': ref('application-service-transport' if service else 'application-transport'),
            'grantRef': ref('application-service-bind' if service else 'application-bind'),
            'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': self.issuer_public,
            'releaseDigest': 'sha256:' + 'a' * 64, 'policyRef': ref('application-policy'), 'workspaceRef': None,
            'messageCommands': {'authenticatedCaller': 'federation' if service else 'operator', 'subject': self.read_subject,
                'transportRef': ref('message-service-transport' if service else 'transport'),
                'grantRefs': self.service_grants if service else self.message_grants, 'resourceRef': ref('task-one'),
                'peer': 'alice', 'localPeer': 'nick', 'localNode': 'mac',
                'repository': {'localName': 'falcon', 'repositoryId': self.resource.repository_id},
                'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': self.issuer_public,
                'serviceIdentityRef': ref('service'), 'serviceInstanceId': 'ingress-one'}})

    async def cleanup(self):
        success = self.success
        self.success = False
        try:
            if hasattr(self, 'message_client'):
                await self.message_client.close(timeout=None)
            if hasattr(self, 'federation_session'):
                await self.federation_session.close()
            for owner in getattr(self, 'application_owners', []):
                await owner.close(deadline=asyncio.get_running_loop().time() + 5)
            if hasattr(self, 'client_owner'):
                await self.client_owner.close(deadline=asyncio.get_running_loop().time() + 5)
        finally:
            try:
                await super().cleanup()
            finally:
                if hasattr(self, 'domain'):
                    await self.domain.session.close()
                    self.store.db.close()
        if success and not self.keep_directory:
            shutil.rmtree(self.directory)

class LiveLegacyMessagesTests(LegacyMessageLiveFixture, unittest.IsolatedAsyncioTestCase):
    async def test_tls_bound_client_recovers_lost_original_reply_and_refuses_revoked_grant(self):
        key = self.application_key()
        binding = ClientBindingState(self.host, public_key=self.issuer_public,
            signing_key_ref=ref('issuer'), caller_ref=ref('human'), scope=self.scope)
        owner = self.client_owner = ClientConnectionOwner(self.host, binding,
            command_subject=self.identity_subject, reply_prefix=self.inbox_prefixes['host'], signer=key)
        owner._connected = True  # The existing fixture already admitted this exact TLS/JWT connection.
        self.refresh_observation()
        await owner.authenticate(key, deadline=asyncio.get_running_loop().time() + 3,
            cleanup_deadline=asyncio.get_running_loop().time() + 4)
        self.assertEqual(binding.current(self.host, now=datetime.now(timezone.utc))['callerRef'], ref('human'))
        snapshot = await self.identity.reader.current()
        self.assertEqual(strict_loads(snapshot.record)['state'].get('nativeInstances', []), [])
        env = envelope.make('message', 'nick', 'mac', self.resource.repository_id, 'alice',
            {'kind': 'note', 'body': 'Original TLS legacy message', 'sender': {'operator': True}, 'target': None})
        payload = {'resourceRef': ref('task-one'), 'attribution': 'operator',
            'input': {'envelope': env, 'subject': 'am.msg.nick.alice', 'localNode': 'mac'}}
        original_publish, dropped = self.storage.publish, False
        async def drop_first(subject, raw, **kwargs):
            nonlocal dropped
            if (not dropped and subject.startswith(self.inbox_prefixes['host'] + '.')
                    and strict_loads(raw)['claims'].get('requestContractId') == 'federation-message-send'):
                dropped = True
                return
            return await original_publish(subject, raw, **kwargs)
        expiry = stamp(datetime.now(timezone.utc) + timedelta(seconds=4))
        with patch.object(self.storage, 'publish', side_effect=drop_first):
            with self.assertRaises(MessageOutcomeUnconfirmed):
                await owner.message_command(contract_id='federation-message-send', operation_id='live-lost-message',
                    payload=payload, expires_at=expiry, deadline=asyncio.get_running_loop().time() + 2,
                    cleanup_deadline=asyncio.get_running_loop().time() + 3)
        self.assertTrue(dropped)
        self.assertFalse(owner._subscriptions)
        self.assertIsNone(owner._exchange_task)
        original = owner.command_request
        self.assertIsNotNone(original)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.refresh_observation()
        query = {'resourceRef': {**ref('task-one'), 'revision': 2}, 'input': {
            'contractId': 'federation-message-send', 'operationId': 'live-lost-message', 'payloadDigest': payload_digest(payload)}}
        result = await owner.message_command(contract_id='federation-message-outcome', operation_id='live-recovery',
            payload=query, expires_at=stamp(datetime.now(timezone.utc) + timedelta(seconds=4)),
            deadline=asyncio.get_running_loop().time() + 3, cleanup_deadline=asyncio.get_running_loop().time() + 4)
        self.assertEqual(result['result']['id'], env['id'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        # Administration uses a separate owned connection. Once attached to a
        # ClientConnectionOwner, its client cannot be borrowed for raw requests.
        management = await self.connect('host')
        with patch.object(self, 'host', management):
            await self.command('identity-revoke', ref('grant'),
                {'authorityId': 'authority-one', 'targetRef': self.message_grants['federation-message-send']})
        with self.assertRaises(Exception):
            await owner.message_command(contract_id='federation-message-outcome', operation_id='revoked-recovery',
                payload=query, expires_at=stamp(datetime.now(timezone.utc) + timedelta(seconds=4)),
                deadline=asyncio.get_running_loop().time() + .5, cleanup_deadline=asyncio.get_running_loop().time() + 2)
        self.assertFalse(owner._subscriptions)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.success = True

    async def test_actual_broker_receive_and_authenticated_approval_use_separate_bound_service_actor(self):
        self.application_owners = []
        loop = asyncio.get_running_loop()
        sessions = []
        for role, service in (('caller-application', False), ('federation-application', True)):
            key = self.application_key(service=service)
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
            public = {k: key.selection[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'messageCommands')}
            session.message_enrollment = lambda pins=public: strict_loads(canonical_bytes(pins))
            # The thread handoff is controlled; each real connection owner
            # performs application binding, signing and TLS message exchange.
            def submit(*, contract_id, operation_id, payload, expires_at, deadline, selected_owner=owner):
                return asyncio.run_coroutine_threadsafe(selected_owner.message_command(
                    contract_id=contract_id, operation_id=operation_id, payload=payload,
                    expires_at=expires_at, deadline=deadline, cleanup_deadline=deadline + 1), loop).result(timeout=6)
            session.message_command = submit
            sessions.append(session)
        hub = object.__new__(Hub)
        hub.store, hub.db = self.store, self.domain.db
        hub._authenticated_callers = weakref.WeakKeyDictionary()
        hub._authenticated_caller_context = ContextVar('live-message-caller', default=None)
        hub.operator_sha = hashlib.sha256(b'live-operator-secret').hexdigest()
        fed = object.__new__(Federation)
        fed.hub, fed.node = hub, 'mac'
        hub.fed = fed
        fed.cfg, fed.policy, fed.presence = self.domain.policy.cfg, self.domain.policy, {}
        fed.stats = dict.fromkeys(('received', 'duplicates', 'dropped', 'quarantined', 'delivered', 'errors'), 0)
        fed.log = lambda *_args: None
        fed._qualified_messages = True
        fed.session = self.federation_session = FederationSession()
        fed.nc = await self.connect('federation')
        self.message_client = LegacyMessageCommandClient(hub, tuple(sessions))
        self.message_client.bind(fed)
        fed._message_commands = self.message_client
        fed._message_intents = MessageBridgeIntents(fed, self.message_client)
        adapter = TrustedPluginAdapter(Messages(), builtin_context_factory('messages'))
        fed.routes = {'message': adapter, 'handoff': adapter}
        fed.plugin_adapters, fed.plugins = {'messages': adapter}, {'messages': adapter.original}
        fed.verbs, fed.plugin_verbs = fed._core_verbs(), {}
        received = loop.create_future()
        async def on_message(message):
            try:
                received.set_result(await fed.receive(message.subject, message.data, message))
            except BaseException as error:
                received.set_exception(error)
        await fed.nc.subscribe_owned(fed.session, 'am.msg.alice.nick', cb=on_message)
        await fed.nc.flush(timeout=2)
        incoming = envelope.make('message', 'alice', 'other', self.resource.repository_id, 'nick',
            {'kind': 'note', 'body': 'Original broker message', 'sender': {'operator': True}, 'target': None})
        await self.admin.publish('am.msg.alice.nick', canonical_bytes(incoming))
        await self.admin.flush(timeout=2)
        self.assertEqual(await asyncio.wait_for(received, 4), 'delivered')
        row = self.store.q1('SELECT * FROM messages WHERE idem_key=?', ('fed:' + incoming['id'],))
        self.assertIsNotNone(row)
        self.assertIn('Original broker message', row['body'])
        from hub.fed import ledger
        self.assertTrue(ledger.seen(self.store, incoming['id']))
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])
        fed.policy = self.domain.policy = policy(peers={'alice': {'trust': 'approve'}})
        held_env = envelope.make('message', 'alice', 'other', self.resource.repository_id, 'nick',
            {'kind': 'note', 'body': 'Original held broker data', 'sender': {'operator': True}, 'target': None})
        qid = ledger.quarantine_add(self.store, held_env, 'am.msg.alice.nick', 'msg', 'alice', 'approve')
        self.refresh_observation()
        request = {'token': 'live-operator-secret', 'verb': 'fed_approve', 'args': {'id': qid}}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()))
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock())
        await hub.handle_conn(reader, writer, tcp=True)
        reply = json.loads(writer.write.call_args.args[0])
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['result']['outcome'], 'delivered')
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        row = self.store.q1('SELECT * FROM messages WHERE idem_key=?', ('fed:' + held_env['id'],))
        self.assertIn('REMOTE DATA', row['body'])
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 2)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])
        # A long code operation expires both its first local proof and initial
        # application binding. The existing trusted observer refreshes its lease;
        # the same real connection must authenticate again before the handoff.
        from hub.fed.code_services import GitOperations, RepositoryDirectory
        from hub.fed.plugins.code import Code
        for statement in Code.tables:
            self.store.db.execute(statement)
        fed.loop = fed.wake = None
        code = TrustedPluginAdapter(Code(), builtin_context_factory('code'))
        fed.plugin_adapters['code'], fed.plugins['code'] = code, code.original
        fed.verbs['fed_code_share'], fed.plugin_verbs['fed_code_share'] = code.verbs()['share'], (code, 'share')
        request = {'token': 'live-operator-secret', 'verb': 'fed_code_share', 'args': {
            'repo': 'falcon', 'note': 'live code handoff', 'to': 'peer:alice/falcon/worker'}}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        async def slow_git(*_args):
            await asyncio.sleep(5.05)
            self.refresh_observation()
        checkout = SimpleNamespace(repo='falcon', rid=self.resource.repository_id, remote='origin',
            url='git@github.com:Adag/Falcon.git', path='/not-used')
        with patch.object(RepositoryDirectory, 'checkout', AsyncMock(return_value=checkout)), \
                patch.object(GitOperations, 'revision', AsyncMock(return_value='a' * 40)), \
                patch.object(GitOperations, 'branch', AsyncMock(return_value='live')), \
                patch.object(GitOperations, 'push', AsyncMock(side_effect=slow_git)), \
                patch.object(GitOperations, 'summary', AsyncMock(return_value=(None, ['one.py'], 'one.py | 1 +', 'log'))):
            await hub.handle_conn(reader, writer, tcp=True)
        reply = json.loads(writer.write.call_args.args[0])
        self.assertTrue(reply['ok'], reply)
        code_result = reply['result']
        handoff = strict_loads(self.store.q1('SELECT payload FROM fed_outbox WHERE msg_id=?',
            (code_result['handoff']['id'],))['payload'])
        self.assertEqual(handoff['data']['code'], code_result['id'])
        self.assertFalse(hub._code_share_invocations)
        self.assertFalse(hub._authenticated_callers)
        # Exercise the real Hub constructor, server socket, normal stop and
        # message-client close around the same original SQLite source.
        from hub import server as hub_server
        old_client = self.message_client
        await old_client.close(timeout=None)
        with socket.socket() as port_socket:
            port_socket.bind(('127.0.0.1', 0))
            port = port_socket.getsockname()[1]
        (self.directory / 'config.toml').write_text(f'node="mac"\ntcp_port={port}\nbackup_every_s=9007199254740991\nprune_every_s=9007199254740991\n')
        (self.directory / 'federation.toml').write_text('[federation]\npeer="nick"\nplugins=["messages"]\n'
            '[repos.falcon]\nremote="github.com/adag/falcon"\n[peers.alice]\ntrust="auto"\n')
        hub_socket = str(self.directory / 'hub.sock')
        full_hub = None
        with patch.object(hub_server, 'ROOT', str(self.directory / 'root')), \
                patch.object(hub_server, 'HUBDIR', str(self.directory)), patch.object(hub_server, 'SOCK', hub_socket):
            full_hub = Hub(message_sessions=tuple(sessions))
            self.message_client = full_hub._message_commands
            running = asyncio.create_task(full_hub.main())
            try:
                async with asyncio.timeout(3):
                    while not (self.directory / 'hub.sock').exists():
                        await asyncio.sleep(.01)
                self.refresh_observation()
                # Keep transport identity separate from the source fixture's
                # controlled caller; the real server authenticates this token.
                proof_reader, proof_writer = await asyncio.open_connection('127.0.0.1', port)
                token = (self.directory / 'operator.token').read_text().strip()
                proof_writer.write(json.dumps({'token': token, 'verb': 'post', 'args': {
                    'to': 'peer:alice/falcon/worker', 'body': 'Original socket message'}}).encode() + b'\n')
                await proof_writer.drain()
                socket_reply = json.loads(await asyncio.wait_for(proof_reader.readline(), 3))
                self.assertTrue(socket_reply['ok'], socket_reply)
                proof_writer.close()
                await proof_writer.wait_closed()
            finally:
                full_hub.stop.set()
                await asyncio.wait_for(running, 5)
                await full_hub.db(full_hub.store.db.close)
                full_hub.dbx.shutdown(wait=True)
                full_hub.io.shutdown(wait=True)
        self.assertTrue(full_hub._message_commands._closed)
        self.assertFalse(full_hub._message_commands._workers)
        self.success = True
