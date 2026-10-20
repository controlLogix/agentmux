"""AMUX-628 owner authorization and retained effects; broker I/O is controlled."""
import asyncio
import base64
import copy
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import weakref
import unittest
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

import nkeys
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import envelope, guard
from hub.fed.peer_control import HEADER_REPOSITORY
from hub.fed.session import FederationSession
from identity.application_client import ApplicationClientKey
from identity.authority import AuthoritySnapshot
from identity.peer_control import control_claims
from identity.test_authority import ref
from identity import test_peer_control as peer_support
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .knowledge_control import KnowledgeControlOwner
from .knowledge_host import SelectedKnowledgeDomain
from .knowledge_legacy import LegacyKnowledgeActor
from .knowledge_bridge_service import KnowledgeBridgeService
from .messages import MessageActor
from .legacy_knowledge_client import LegacyKnowledgeCommandClient
from . import test_peer_control_command as command_support


class KnowledgeControlTests(command_support.PeerControlCommandFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.knowledge_grants = {contract: ref('control-knowledge-' + contract) for contract in (
            'index', 'withdraw', 'inspect', 'outcome')}
        self.knowledge_grants = {'federation-knowledge-' + k: v for k, v in self.knowledge_grants.items()}
        channel = self.value['storage']['knowledge']['channels'][0]
        channel['legacyActors'] = [{'identityRef': self.signer['identityRef'],
            'transportRef': ref('knowledge-control-service-transport'), 'caller': 'federation',
            'grants': self.knowledge_grants}]
        self.selection = self.selected()
        record = strict_loads(self.snapshot.record)
        state = record['state']
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('knowledge-control-service-transport'), identityRef=self.signer['identityRef'],
            issuerRef=self.signer['ref'], publicKey=self.signer['publicKey'],
            issuedAt=self.issuer_start, expiresAt=self.issuer_end)
        state['transports'].append(transport)
        state['memberships'].append({'ref': ref('knowledge-control-service-member'),
            'identityRef': self.signer['identityRef'], 'scope': copy.deepcopy(self.scope), 'status': 'active'})
        for contract, reference in self.knowledge_grants.items():
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=reference, callerRef=self.signer['identityRef'], actorRef=self.signer['identityRef'],
                scope=copy.deepcopy(self.scope), resourceId='knowledge-one', contractId=contract,
                decision='allowed', delegationRef=None, issuedAt=self.issuer_start, expiresAt=self.issuer_end)
            state['grants'].append(grant)
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)

    async def asyncSetUp(self):
        await peer_support.PeerControlFixture.asyncSetUp(self)
        self.current = patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot))
        self.current.start()
        self.addCleanup(self.current.stop)
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        self.domain = SelectedKnowledgeDomain(self.source, session, identity=self.identity,
            scope=self.scope, local_node='mac')
        self.resource = KnowledgeStorageResource(OwnerBinding('hub-one', 'federation-knowledge',
            'knowledge-one', 'knowledge-channel', canonical_bytes(self.scope)), self.domain, repository='falcon',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            legacy_actors=(LegacyKnowledgeActor(canonical_bytes(self.signer['identityRef']),
                canonical_bytes(ref('knowledge-control-service-transport')), 'federation',
                canonical_bytes(self.knowledge_grants)),), plugin_identity_ref=ref('plugin-one'), instance_id='plugin-one')
        self.controller = KnowledgeControlOwner(self.selection, self.identity, (self.resource,))
        self.addAsyncCleanup(self.controller.close, timeout=None)
        self.ingress = next(iter(self.controller._routes.values()))
        # Only connection observation is controlled here. Actual callback and
        # broker publisher identity remain a separate required live check.
        self.connected = patch.object(type(self.ingress._connection), 'is_connected', PropertyMock(return_value=True))
        self.connected.start()
        self.addCleanup(self.connected.stop)
        self.ingress._started = asyncio.create_task(asyncio.sleep(0))
        await self.ingress._started
        self.controller._ready = True
        selected = strict_loads(self.key._material)
        commands = selected.pop('peerControlCommands')
        commands.pop('routeId')
        commands.update(authenticatedCaller='federation', transportRef=ref('knowledge-control-service-transport'),
            grantRefs=self.knowledge_grants)
        selected.update(seed=base64.b64encode(self.identity.ingress._seed).decode(), callerRef=self.signer['identityRef'])
        selected['knowledgeCommands'] = commands
        self.service_key = ApplicationClientKey(selected)
        self.endpoint = KnowledgeBridgeService(self.identity.ingress, resources=(self.resource,),
            service_identity_ref=self.signer['identityRef'], service_instance_id=self.signer['instanceId'],
            signing_key_ref=self.signer['ref'], signing_seed=self.identity.ingress._seed)
        self.addAsyncCleanup(self.endpoint.close, timeout=None)

    def request_knowledge(self, action, value, *, operation='control-effect', revision=1):
        now = datetime.now(timezone.utc)
        contract = 'federation-knowledge-' + action
        payload = {'resourceRef': {**ref('knowledge-one'), 'revision': revision}, 'input': value}
        if action not in ('inspect', 'outcome'):
            payload['attribution'] = 'federation'
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('knowledge-control-service-transport'),
            'grantRef': self.knowledge_grants[contract], 'operationId': operation, 'expectedVersion': revision,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'replySubject': '_INBOX.knowledge_control_00000001', 'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}
        return self.service_key.sign_command(claims, subject=self.commands['subject'], now=now)

    async def call_knowledge(self, raw):
        reply = await self.endpoint.handle(raw, received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        return self.service_key.verify_command_response(reply, raw, subject=self.commands['subject'],
            now=datetime.now(timezone.utc))

    async def retain_control(self, item):
        key = nkeys.from_seed(nkeys.encode_seed(bytes([2]) * 32, nkeys.PREFIX_BYTE_USER))
        try:
            signature = base64.b64encode(key.sign(canonical_bytes(control_claims(
                self.ingress._pin, item, 'am.ctl.alice')))).decode()
        finally:
            key.wipe()
        await self.source.db(self.ingress._retain, item, signature, self.snapshot.sequence)
        return {'eventId': item['id'], 'eventDigest': payload_digest(item), 'subject': 'am.ctl.alice',
            'signature': signature, 'repositoryId': self.resource.repository_id}

    def knowledge_session(self, *, lose_applied=False, lose_rejected=False):
        with patch.object(self, 'key', self.service_key), \
                patch.object(self, 'commands', self.service_key.selection['knowledgeCommands']):
            session, owner, client, wire = self.open_session()
        session._knowledge_enrollment = canonical_bytes({key: self.service_key.selection[key] for key in
            ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'knowledgeCommands')})
        original_subscribe = client.subscribe
        lost = []
        async def subscribe(*args, **kwargs):
            subscription = await original_subscribe(*args, **kwargs)
            original_next = subscription.next_msg
            async def next_message(**options):
                claims = strict_loads(wire.responses[-1])['claims']
                if (not lost and claims['requestContractId'] == 'federation-knowledge-withdraw'
                        and (lose_applied and claims['result']['outcome'] == 'applied'
                            or lose_rejected and claims['result']['outcome'] == 'rejected')):
                    lost.append(wire.responses[-1])
                    raise TimeoutError()
                return await original_next(**options)
            subscription.next_msg = next_message
            return subscription
        client.subscribe = subscribe
        return session, owner, wire

    def knowledge_client(self, session):
        from hub.server import Hub
        from hub.fed.runtime import Federation
        from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
        from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
        from hub.fed.plugins.knowledge import Knowledge
        hub = object.__new__(Hub)
        hub.store, hub.db = self.source._store, self.source.db
        hub._authenticated_callers = weakref.WeakKeyDictionary()
        hub._authenticated_caller_context = ContextVar('knowledge-control-caller', default=None)
        fed = object.__new__(Federation)
        fed.hub, fed.node = hub, 'mac'
        hub.fed = fed
        fed.cfg, fed.policy = self.domain.policy.cfg, self.domain.policy
        fed.nc, fed.session = SimpleNamespace(_subs={}), FederationSession()
        self.addAsyncCleanup(fed.session.close)
        fed.log, fed.notify_operator = Mock(), AsyncMock()
        fed._qualified_knowledge = True
        client = LegacyKnowledgeCommandClient(hub, (session,)).bind(fed)
        self.addAsyncCleanup(client.close, timeout=None)
        fed._knowledge_commands = client
        fed._knowledge_intents = KnowledgeBridgeIntents(fed, client)
        plugin = TrustedPluginAdapter(Knowledge(), builtin_context_factory('knowledge'))
        fed.plugin_adapters = {'knowledge': plugin}
        return hub, fed, client

    def control_message(self, fed, item, selector):
        from nats.aio.msg import Msg
        from identity.peer_control import HEADER
        subscription = SimpleNamespace(_closed=False, unsubscribe=AsyncMock(),
            _wait_for_msgs_task=asyncio.current_task())
        fed.nc._subs[1] = subscription
        fed.session.own_subscription(subscription)
        return Msg(_client=fed.nc, subject=selector['subject'], data=canonical_bytes(item), _sid=1,
            headers={HEADER: selector['signature'], HEADER_REPOSITORY: selector['repositoryId']})

    async def index_original(self):
        item = envelope.make('knowledge', 'alice', 'mac', self.resource.repository_id, '*',
            {'title': 'Original finding', 'body': 'Original retained content', 'author': 'alice/worker'})
        result = await self.call_knowledge(self.request_knowledge('index', {'envelope': item,
            'subject': 'am.know.alice.' + item['rid'], 'localNode': 'mac'}, operation='index-original'))
        self.assertEqual(result['outcome'], 'applied')
        return item

    async def test_actual_owner_withdraws_trusted_peer_and_preserves_content_fts_and_provenance(self):
        item = await self.index_original()
        other_peer = envelope.make('knowledge', 'bob', 'mac', self.resource.repository_id, '*',
            {'title': 'Other peer', 'body': 'Untouched other peer'})
        other_repo = envelope.make('knowledge', 'alice', 'mac', 'r000000000000', '*',
            {'title': 'Other repository', 'body': 'Untouched other repository'})
        def retained_others():
            with self.source._store.tx():
                self.resource._knowledge._index(other_peer, 'falcon', 'auto', False)
                self.resource._knowledge._index(other_repo, 'other-repo', 'auto', False)
        await self.source.db(retained_others)
        original = await self.source.db(self.source._store.q1, 'SELECT * FROM p_knowledge_items WHERE id=?', (item['id'],))
        self.assertNotEqual(self.domain.policy.trust('alice'), 'deny')
        event = envelope.make('revoke', 'alice', 'mac', data={'reason': 'original revoke'})
        selector = await self.retain_control(event)
        value = {'peer': 'alice', 'control': selector}
        raw = self.request_knowledge('withdraw', value, revision=2)
        result = await self.call_knowledge(raw)
        self.assertEqual(result['result'], {'withdrawn': 1})
        row = await self.source.db(self.source._store.q1, 'SELECT * FROM p_knowledge_items WHERE id=?', (item['id'],))
        self.assertIsNotNone(row['withdrawn'])
        self.assertEqual({k: v for k, v in row.items() if k != 'withdrawn'},
            {k: v for k, v in original.items() if k != 'withdrawn'})
        fts = await self.source.db(self.source._store.q,
            "SELECT rowid FROM p_knowledge_fts WHERE p_knowledge_fts MATCH 'retained'")
        self.assertEqual(len(fts), 1)
        audit = await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'")
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['msg_id'], event['id'])
        self.assertEqual(await self.call_knowledge(raw), result)
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'")), 1)

        for other in (other_peer, other_repo):
            row = await self.source.db(self.source._store.q1,
                'SELECT withdrawn FROM p_knowledge_items WHERE id=?', (other['id'],))
            self.assertIsNone(row['withdrawn'])

    async def test_raw_unadmitted_substituted_and_disconnected_control_refuse(self):
        item = await self.index_original()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        with self.assertRaises(ContractError):
            await self.call_knowledge(self.request_knowledge('withdraw', {'peer': 'alice'}, revision=2))
        for field, changed in (('eventId', 'unknown-event'), ('eventDigest', 'sha256:' + 'a' * 64),
                ('subject', 'am.ctl.bob'), ('signature', base64.b64encode(bytes(64)).decode()),
                ('repositoryId', 'r000000000000')):
            altered = {**selector, field: changed}
            with self.subTest(field=field):
                rejected = await self.call_knowledge(self.request_knowledge('withdraw', {'peer': 'alice', 'control': altered},
                    operation='changed-' + field.lower(), revision=2))
                self.assertEqual(rejected['outcome'], 'rejected')
                self.assertEqual(rejected['result'], {'withdrawn': 0})
        with patch.object(type(self.ingress._connection), 'is_connected', PropertyMock(return_value=False)), \
                self.assertRaises(ContractError):
            await self.call_knowledge(self.request_knowledge('withdraw', {'peer': 'alice', 'control': selector},
                operation='disconnected-control', revision=2))
        self.ingress._session.closing = True
        with self.assertRaises(ContractError):
            await self.call_knowledge(self.request_knowledge('withdraw', {'peer': 'alice', 'control': selector},
                operation='closed-session-control', revision=2))
        self.ingress._session.closing = False
        self.assertIsNone((await self.source.db(self.source._store.q1,
            'SELECT withdrawn FROM p_knowledge_items WHERE id=?', (item['id'],)))['withdrawn'])
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'"), [])

    async def test_committed_original_recovers_without_authorizing_new_effect_from_revoked_peer(self):
        await self.index_original()
        event = envelope.make('revoke', 'alice', 'mac')
        value = {'peer': 'alice', 'control': await self.retain_control(event)}
        original = self.request_knowledge('withdraw', value, revision=2)
        result = await self.call_knowledge(original)
        record = strict_loads(self.snapshot.record)
        next(g for g in record['state']['grants'] if g['ref'] == ref('control-grant'))['status'] = 'revoked'
        changed = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=changed)):
            self.assertEqual(await self.call_knowledge(original), result)
            query = {'contractId': 'federation-knowledge-withdraw', 'operationId': 'control-effect',
                'payloadDigest': payload_digest(strict_loads(original)['claims']['payload'])}
            recovered = await self.call_knowledge(self.request_knowledge('outcome', query,
                operation='recover-original', revision=3))
            self.assertEqual(recovered['result'], result['result'])
            self.assertEqual((await self.call_knowledge(self.request_knowledge('withdraw', value,
                operation='new-effect-with-old-proof', revision=3)))['outcome'], 'rejected')
        expired = copy.deepcopy(record)
        peer = next(g for g in expired['state']['grants'] if g['ref'] == ref('control-grant'))
        peer.update(status='active', expiresAt=(datetime.now(timezone.utc) - timedelta(seconds=1))
            .isoformat().replace('+00:00', 'Z'))
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(expired), changed.sequence + 1))):
            self.assertEqual(await self.call_knowledge(original), result)
            self.assertEqual((await self.call_knowledge(self.request_knowledge('withdraw', value,
                operation='new-effect-with-expired-proof', revision=3)))['outcome'], 'rejected')
        next(g for g in record['state']['grants'] if
            g['ref'] == self.knowledge_grants['federation-knowledge-withdraw'])['status'] = 'revoked'
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(record), changed.sequence + 1))), self.assertRaises(ContractError):
            await self.call_knowledge(self.request_knowledge('outcome', query,
                operation='revoked-service-outcome', revision=3))
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'")), 1)

    async def test_repeated_control_through_plugin_client_keeps_original_operation_and_version(self):
        await self.index_original()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        session, _, wire = self.knowledge_session()
        _, fed, _ = self.knowledge_client(session)
        await fed._on_ctl(self.control_message(fed, event, selector))
        applied = [strict_loads(raw)['claims'] for raw in wire.responses if
            strict_loads(raw)['claims']['requestContractId'] == 'federation-knowledge-withdraw'
            and strict_loads(raw)['claims']['result']['outcome'] == 'applied']
        self.assertEqual(len(applied), 1, fed.log.call_args_list)
        original = next(strict_loads(raw)['claims'] for raw in wire.requests if
            strict_loads(raw)['claims']['operationId'] == applied[0]['operationId']
            and strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-withdraw')
        before = len([raw for raw in wire.requests if
            strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-withdraw'])
        await fed._on_ctl(self.control_message(fed, event, selector))
        self.assertEqual(len([raw for raw in wire.requests if
            strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-withdraw']), before)
        query = [strict_loads(raw)['claims'] for raw in wire.requests if
            strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-outcome'][-1]
        self.assertEqual(query['payload']['input']['operationId'], original['operationId'])
        self.assertEqual(query['payload']['input']['payloadDigest'], payload_digest(original['payload']))
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'")), 1)

    async def test_restart_after_lost_control_reply_queries_original_without_republication(self):
        await self.index_original()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        session, _, wire = self.knowledge_session(lose_applied=True)
        hub, fed, client = self.knowledge_client(session)
        await fed._on_ctl(self.control_message(fed, event, selector))
        pending = await hub.db(hub.store.q, "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")
        self.assertEqual(len(pending), 1, fed.log.call_args_list)
        original = strict_loads(pending[0]['v'])
        await client.close(timeout=None)
        replacement, _, fresh = self.knowledge_session()
        current = LegacyKnowledgeCommandClient(hub, (replacement,)).bind(fed)
        self.addAsyncCleanup(current.close, timeout=None)
        fed._knowledge_commands = current
        from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
        fed._knowledge_intents = KnowledgeBridgeIntents(fed, current)
        await fed.plugin_adapters['knowledge'].on_tick(fed)
        self.assertEqual(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
        self.assertFalse(any(strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-withdraw'
            for raw in fresh.requests))
        query = [strict_loads(raw)['claims'] for raw in fresh.requests if
            strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-outcome'][-1]
        self.assertEqual(query['payload']['input']['operationId'], original['operationId'])
        self.assertEqual(query['payload']['input']['payloadDigest'], payload_digest(original['payload']))
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'")), 1)

    async def test_pending_recovery_waiting_for_callback_cannot_create_another_operation(self):
        await self.index_original()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        session, _, _ = self.knowledge_session(lose_applied=True)
        hub, fed, client = self.knowledge_client(session)
        await fed._on_ctl(self.control_message(fed, event, selector))
        original = strict_loads((await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"))[0]['v'])
        await client.close(timeout=None)
        replacement, _, wire = self.knowledge_session()
        current = LegacyKnowledgeCommandClient(hub, (replacement,)).bind(fed)
        self.addAsyncCleanup(current.close, timeout=None)
        enrollment = replacement.knowledge_enrollment()
        lock = current._locks[id(replacement)]
        await lock.acquire()
        recovery = asyncio.create_task(current._execute(replacement, enrollment, 'withdraw',
            original['intentDigest'], original['payload']['input'], 'federation',
            datetime.now(timezone.utc) + timedelta(seconds=5), recover_only=True))
        try:
            await asyncio.sleep(0)
            self.assertFalse(recovery.done())
            # The original callback commits cleanup after startup took its
            # pending snapshot, while startup still waits for the route lock.
            def complete():
                row = hub.store.q1("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")
                current._forget(row['k'], original)
            await hub.db(complete)
        finally:
            lock.release()
        self.assertIsNone(await recovery)
        self.assertEqual(wire.requests, [])
        self.assertEqual(len(await hub.db(hub.store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'")), 1)

    async def test_close_joins_original_admission_and_caller_can_join_same_cleanup(self):
        event = envelope.make('revoke', 'alice', 'mac')
        value = {'peer': 'alice', 'control': await self.retain_control(event)}
        original = strict_loads(self.request_knowledge('withdraw', value))
        # The actual owner admission consumes its normalized signed envelope.
        admitted = await self.identity.ingress.admit(canonical_bytes(original),
            cancellation_ref=ref('control-cleanup-cancellation'))
        entered, release = asyncio.Event(), asyncio.Event()
        async def authority(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.snapshot
        async def caller():
            with self.assertRaises(ContractError):
                await self.controller.admit(self.resource, admitted.envelope,
                    datetime.now(timezone.utc) + timedelta(seconds=5))
            await self.controller.close(timeout=None)
        with patch('hub.fed.peer_control.check_authority', authority):
            original_call = asyncio.create_task(caller())
            await asyncio.wait_for(entered.wait(), 1)
            with self.assertRaises(ContractError):
                await self.controller.close(timeout=.001)
            cleanup = self.controller._closing
            self.assertFalse(cleanup.done())
            release.set()
            await asyncio.wait_for(original_call, 2)
            self.assertTrue(cleanup.done())
            self.assertIs(self.controller._closing, cleanup)
        self.assertEqual(await self.source.db(lambda: 1), 1)

    async def test_policy_pause_joins_original_admission_before_source_replacement(self):
        event = envelope.make('revoke', 'alice', 'mac')
        value = {'peer': 'alice', 'control': await self.retain_control(event)}
        admitted = await self.identity.ingress.admit(self.request_knowledge('withdraw', value),
            cancellation_ref=ref('control-pause-cancellation'))
        entered, release = asyncio.Event(), asyncio.Event()
        async def authority(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.snapshot
        with patch('hub.fed.peer_control.check_authority', authority):
            original = asyncio.create_task(self.controller.admit(self.resource, admitted.envelope,
                datetime.now(timezone.utc) + timedelta(seconds=5)))
            await asyncio.wait_for(entered.wait(), 1)
            self.controller.begin_policy_pause()
            joined = asyncio.create_task(self.controller.join_policy_pause())
            await asyncio.sleep(0)
            self.assertFalse(joined.done())
            with self.assertRaises(ContractError):
                self.controller.check()
            self.controller.check_health()
            self.ingress.check_health()
            release.set()
            with self.assertRaises(ContractError):
                await original
            await asyncio.wait_for(joined, 1)
        self.controller.end_policy_pause()
        self.controller.check()
        self.assertFalse(self.ingress._policy_paused)

    async def test_repository_lookup_header_does_not_admit_missing_or_other_repository(self):
        from nats.aio.msg import Msg
        from identity.peer_control import HEADER
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        subscription = SimpleNamespace(_closed=False, _wait_for_msgs_task=asyncio.current_task(),
            unsubscribe=AsyncMock())
        self.ingress._subscription = subscription
        self.ingress._connection._subs[7] = subscription
        self.addCleanup(self.ingress._connection._subs.pop, 7, None)
        self.ingress._session.own_subscription(subscription)
        for repository in (None, 'r000000000000', selector['repositoryId'] + '.other'):
            headers = {HEADER: selector['signature']}
            if repository is not None:
                headers[HEADER_REPOSITORY] = repository
            message = Msg(_client=self.ingress._connection, subject=selector['subject'],
                _sid=7, data=canonical_bytes(event), headers=headers)
            with self.subTest(repository=repository), self.assertRaises(ContractError):
                self.ingress._message(message)
        headers[HEADER_REPOSITORY] = selector['repositoryId']
        self.assertEqual(self.ingress._message(message), (event, selector['signature']))

    async def test_invalid_candidates_reject_without_capacity_or_session_poisoning(self):
        await self.index_original()
        session, owner, wire = self.knowledge_session()
        owner._current_command_binding.side_effect = lambda *a, **k: {'validUntil':
            (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()}
        owner._require_query_binding.side_effect = owner._current_command_binding.side_effect
        hub, fed, _ = self.knowledge_client(session)
        for _ in range(33):
            event = envelope.make('revoke', 'alice', 'mac')
            selector = await self.retain_control(event)
            malformed = {**selector, 'signature': base64.b64encode(bytes(64)).decode()}
            await fed._on_ctl(self.control_message(fed, event, malformed))
            self.assertEqual(await hub.db(hub.store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
            self.assertIsNone(owner._close_task)
        rejected = [strict_loads(raw)['claims']['result'] for raw in wire.responses if
            strict_loads(raw)['claims']['requestContractId'] == 'federation-knowledge-withdraw']
        self.assertEqual(len(rejected), 33)
        self.assertTrue(all(r['outcome'] == 'rejected' and r['result'] == {'withdrawn': 0} for r in rejected))
        self.assertEqual((await self.source.db(self.resource._journal.current))['revision'], 2)
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'"), [])
        # A forged signature for this same event cannot reserve its real
        # operation ID and prevent its later authenticated admission.
        await fed._on_ctl(self.control_message(fed, event, selector))
        self.assertIsNone(owner._close_task)
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'")), 1)
        await owner.close(deadline=asyncio.get_running_loop().time() + 2)

    async def test_lost_rejected_reply_recovers_exact_terminal_original(self):
        await self.index_original()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        malformed = {**selector, 'signature': base64.b64encode(bytes(64)).decode()}
        session, _, wire = self.knowledge_session(lose_rejected=True)
        hub, fed, client = self.knowledge_client(session)
        await fed._on_ctl(self.control_message(fed, event, malformed))
        pending = await hub.db(hub.store.q, "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")
        self.assertEqual(len(pending), 1)
        original = strict_loads(pending[0]['v'])
        await client.close(timeout=None)
        replacement, _, fresh = self.knowledge_session()
        current = LegacyKnowledgeCommandClient(hub, (replacement,)).bind(fed)
        self.addAsyncCleanup(current.close, timeout=None)
        fed._knowledge_commands = current
        from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
        fed._knowledge_intents = KnowledgeBridgeIntents(fed, current)
        await fed.plugin_adapters['knowledge'].on_tick(fed)
        self.assertEqual(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
        self.assertFalse(any(strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-withdraw'
            for raw in fresh.requests))
        response = strict_loads(fresh.responses[-1])['claims']['result']
        self.assertEqual(response['outcome'], 'rejected')
        self.assertEqual(response['operationId'], original['operationId'])
        self.assertEqual(response['payloadDigest'], payload_digest(original['payload']))
        self.assertEqual(response['result'], {'withdrawn': 0})
        self.assertEqual((await self.source.db(self.resource._journal.current))['revision'], 2)
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='knowledge-revoke'"), [])

    async def test_valid_missing_receipt_and_unavailable_owner_remain_uncertain(self):
        await self.index_original()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        key = self.ingress._key(event['id'])
        await self.source.db(self.source._store.db.execute, 'DELETE FROM fed_state WHERE k=?', (key,))
        raw = self.request_knowledge('withdraw', {'peer': 'alice', 'control': selector},
            operation='valid-original-arriving', revision=2)
        with self.assertRaises(ContractError):
            await self.call_knowledge(raw)
        original = strict_loads(raw)['claims']
        def absent():
            return self.resource._journal.outcome(original['operationId'], payload_digest(original['payload']))
        self.assertIsNone(await self.source.db(absent))
        await self.retain_control(event)
        for mode in ('paused', 'disconnected', 'authority-outage'):
            if mode == 'paused':
                self.controller.begin_policy_pause()
                context = patch.object(self.controller, '_policy_paused', True)
            elif mode == 'disconnected':
                context = patch.object(type(self.ingress._connection), 'is_connected', PropertyMock(return_value=False))
            else:
                context = patch.object(self.identity.reader, 'current', AsyncMock(
                    side_effect=ContractError('authority_unavailable')))
            try:
                with context, self.subTest(mode=mode), self.assertRaises(ContractError):
                    await self.call_knowledge(raw)
            finally:
                if mode == 'paused':
                    await self.controller.join_policy_pause()
                    self.controller.end_policy_pause()
            self.assertIsNone(await self.source.db(absent))
        result = await self.call_knowledge(raw)
        self.assertEqual(result['outcome'], 'applied')
        self.assertEqual(result['result'], {'withdrawn': 1})

    async def test_forged_rejected_reply_cannot_clear_original_pending(self):
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        selector['signature'] = base64.b64encode(bytes(64)).decode()
        session, _, _ = self.knowledge_session()
        hub, fed, _ = self.knowledge_client(session)
        original_handle = self.endpoint.handle
        async def forged(raw, **kwargs):
            response = await original_handle(raw, **kwargs)
            item = strict_loads(response)
            if item['claims']['requestContractId'] == 'federation-knowledge-withdraw':
                item['claims']['result']['result']['withdrawn'] = 1
                return canonical_bytes(item)
            return response
        with patch.object(self.endpoint, 'handle', forged):
            await fed._on_ctl(self.control_message(fed, event, selector))
        pending = await hub.db(hub.store.q, "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")
        self.assertEqual(len(pending), 1)
        self.assertEqual(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-control:%'"), [])
        retained = strict_loads(pending[0]['v'])
        stored = await self.source.db(self.resource._journal.outcome, retained['operationId'],
            payload_digest(retained['payload']))
        self.assertEqual(stored['reply']['outcome'], 'rejected')
        self.assertEqual(stored['result'], {'withdrawn': 0})
