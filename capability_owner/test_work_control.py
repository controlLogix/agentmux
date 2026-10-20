"""AMUX-669 owner authorization and retained effects; broker I/O is controlled."""
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
from .work import WorkStorageResource
from .work_control import WorkControlOwner
from .work_host import SelectedWorkDomain, WorkStoreHost
from .work_legacy import LegacyWorkActor
from .work_bridge_service import WorkBridgeService
from .messages import MessageActor
from .legacy_work_client import LegacyWorkCommandClient
from .federated_work_client import FederatedWorkCommandClient, WorkBridgeIntents
from . import test_peer_control_command as command_support


class WorkControlFixture(command_support.PeerControlCommandFixture):
    def setUp(self):
        super().setUp()
        self.work_grants = {contract: ref('control-work-' + contract) for contract in (
            'ingest', 'revoke', 'inspect', 'outcome')}
        self.work_grants = {'federation-work-' + k: v for k, v in self.work_grants.items()}
        self.value['storage']['work'] = copy.deepcopy(self.value['storage']['knowledge'])
        channel = self.value['storage']['work']['channels'][0]
        channel['resourceRef'] = ref('work-one')
        channel['initialSource'] = None
        route = self.value['peerControl']['routes'][0]
        route['resourceRef'] = ref('work-one')
        channel['legacyActors'] = [{'identityRef': self.signer['identityRef'],
            'transportRef': ref('work-control-service-transport'), 'caller': 'federation',
            'grants': self.work_grants}]
        self.selection = self.selected()
        record = strict_loads(self.snapshot.record)
        state = record['state']
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('work-control-service-transport'), identityRef=self.signer['identityRef'],
            issuerRef=self.signer['ref'], publicKey=self.signer['publicKey'],
            issuedAt=self.issuer_start, expiresAt=self.issuer_end)
        state['transports'].append(transport)
        state['memberships'].append({'ref': ref('work-control-service-member'),
            'identityRef': self.signer['identityRef'], 'scope': copy.deepcopy(self.scope), 'status': 'active'})
        for contract, reference in self.work_grants.items():
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=reference, callerRef=self.signer['identityRef'], actorRef=self.signer['identityRef'],
                scope=copy.deepcopy(self.scope), resourceId='work-one', contractId=contract,
                decision='allowed', delegationRef=None, issuedAt=self.issuer_start, expiresAt=self.issuer_end)
            state['grants'].append(grant)
        next(g for g in state['grants'] if g['ref'] == ref('control-grant'))['resourceId'] = 'work-one'
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)

    async def asyncSetUp(self):
        await peer_support.PeerControlFixture.asyncSetUp(self)
        await self.source.close()
        pin = self.value['storage']['work']
        self.source = WorkStoreHost(pin['source'], repository=pin['repository'],
            local_peer='nick', owner_uid=__import__('os').getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        self.current = patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot))
        self.current.start()
        self.addCleanup(self.current.stop)
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        self.domain = SelectedWorkDomain(self.source, session, identity=self.identity,
            scope=self.scope, local_node='mac')
        self.resource = WorkStorageResource(OwnerBinding('hub-one', 'federation-work',
            'work-one', 'work-channel', canonical_bytes(self.scope)), self.domain, repository='falcon',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            legacy_actors=(LegacyWorkActor(canonical_bytes(self.signer['identityRef']),
                canonical_bytes(ref('work-control-service-transport')), 'federation',
                canonical_bytes(self.work_grants)),), plugin_identity_ref=ref('plugin-one'), instance_id='plugin-one')
        self.controller = WorkControlOwner(self.selection, self.identity, (self.resource,))
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
        commands.update(resourceRef=ref('work-one'), authenticatedCaller='federation', transportRef=ref('work-control-service-transport'),
            grantRefs=self.work_grants)
        selected.update(seed=base64.b64encode(self.identity.ingress._seed).decode(), callerRef=self.signer['identityRef'])
        selected['workCommands'] = commands
        self.service_key = ApplicationClientKey(selected)
        self.endpoint = WorkBridgeService(self.identity.ingress, resources=(self.resource,),
            service_identity_ref=self.signer['identityRef'], service_instance_id=self.signer['instanceId'],
            signing_key_ref=self.signer['ref'], signing_seed=self.identity.ingress._seed)
        self.addAsyncCleanup(self.endpoint.close, timeout=None)

    def request_work(self, action, value, *, operation='control-effect', revision=1):
        now = datetime.now(timezone.utc)
        contract = 'federation-work-' + action
        payload = {'resourceRef': {**ref('work-one'), 'revision': revision}, 'input': value}
        if action not in ('inspect', 'outcome'):
            payload['attribution'] = 'federation'
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('work-control-service-transport'),
            'grantRef': self.work_grants[contract], 'operationId': operation, 'expectedVersion': revision,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'replySubject': '_INBOX.work_control_00000001', 'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}
        return self.service_key.sign_command(claims, subject=self.commands['subject'], now=now)

    async def call_work(self, raw):
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

    def work_session(self, *, lose_applied=False, lose_rejected=False):
        with patch.object(self, 'key', self.service_key), \
                patch.object(self, 'commands', self.service_key.selection['workCommands']):
            session, owner, client, wire = self.open_session()
        session._work_enrollment = canonical_bytes({key: self.service_key.selection[key] for key in
            ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'workCommands')})
        original_subscribe = client.subscribe
        lost = []
        async def subscribe(*args, **kwargs):
            subscription = await original_subscribe(*args, **kwargs)
            original_next = subscription.next_msg
            async def next_message(**options):
                claims = strict_loads(wire.responses[-1])['claims']
                if (not lost and claims['requestContractId'] == 'federation-work-revoke'
                        and (lose_applied and claims['result']['outcome'] == 'applied'
                            or lose_rejected and claims['result']['outcome'] == 'rejected')):
                    lost.append(wire.responses[-1])
                    raise TimeoutError()
                return await original_next(**options)
            subscription.next_msg = next_message
            return subscription
        client.subscribe = subscribe
        return session, owner, wire

    def work_client(self, session):
        from hub.server import Hub
        from hub.fed.runtime import Federation
        from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
        hub = object.__new__(Hub)
        hub.store, hub.db = self.source._store, self.source.db
        hub._authenticated_callers = weakref.WeakKeyDictionary()
        hub._authenticated_caller_context = ContextVar('work-control-caller', default=None)
        fed = object.__new__(Federation)
        fed.hub, fed.node = hub, 'mac'
        hub.fed = fed
        fed.cfg, fed.policy = self.domain.policy.cfg, self.domain.policy
        fed.nc, fed.session = SimpleNamespace(_subs={}), FederationSession()
        self.addAsyncCleanup(fed.session.close)
        fed.log, fed.notify_operator = Mock(), AsyncMock()
        fed._qualified_work = True
        hub.cfg = {'node': 'mac'}
        hub.dbx, hub.stop = self.source._executor, asyncio.Event()
        base = LegacyWorkCommandClient(hub, (session,))
        self.addAsyncCleanup(base.close, timeout=None)
        client = FederatedWorkCommandClient(fed, base)
        fed._work_commands = client
        fed._work_intents = WorkBridgeIntents(fed, client)
        from hub.fed.plugins.work import Work
        plugin = TrustedPluginAdapter(Work(), builtin_context_factory('work'))
        fed.plugin_adapters = {'work': plugin}
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


class WorkControlTests(WorkControlFixture, unittest.IsolatedAsyncioTestCase):
    async def seed_work(self):
        def seed():
            store = self.source._store
            store.repo_add('other')
            rows = []
            for peer, repo, state, reason in (
                    ('alice', 'falcon', 'ready', None),
                    ('alice', 'falcon', 'blocked', 'awaiting origin grant'),
                    ('alice', 'falcon', 'claimed', None),
                    ('alice', 'falcon', 'waiting_children', None),
                    ('alice', 'falcon', 'done', None),
                    ('alice', 'falcon', 'blocked', 'operator hold'),
                    ('bob', 'falcon', 'ready', None),
                    ('alice', 'other', 'ready', None)):
                row = store.work_create('operator', repo, 'role:' + repo + '/worker', 'Retained original work')
                store.db.execute('UPDATE work_items SET origin_peer=?, state=?, blocked_reason=?, result=? WHERE id=?',
                    (peer, state, reason, 'Original result', row['id']))
                rows.append(store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)))
            return rows
        return await self.source.db(seed)

    async def version(self):
        return (await self.source.db(self.resource._journal.current))['revision']

    async def test_signed_owner_withdraws_only_unclaimed_selected_work_and_preserves_trust(self):
        rows = await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac', data={'reason': 'Original self-revoke'})
        value = {'peer': 'alice', 'control': await self.retain_control(event)}
        raw = self.request_work('revoke', value)
        first = await self.call_work(raw)
        self.assertEqual(first['result'], {'cancelled': 2})
        self.assertEqual(await self.call_work(raw), first)
        after = await self.source.db(self.source._store.q, 'SELECT * FROM work_items ORDER BY rowid')
        for index, original in enumerate(rows):
            if index < 2:
                self.assertEqual(after[index]['state'], 'cancelled')
                self.assertEqual(after[index]['result'], 'withdrawn by alice')
                self.assertEqual({k: v for k, v in after[index].items() if k not in ('state', 'result', 'updated')},
                    {k: v for k, v in original.items() if k not in ('state', 'result', 'updated')})
            else:
                self.assertEqual(after[index], original)
        self.assertEqual(self.domain.policy.trust('alice'), 'auto')
        audit = await self.source.db(self.source._store.q, "SELECT * FROM fed_audit WHERE decision='work-revoke'")
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['msg_id'], event['id'])
        self.assertEqual((await self.version()), 2)

    async def test_service_key_without_control_and_wrong_proof_never_withdraw(self):
        rows = await self.seed_work()
        with self.assertRaises(ContractError):
            await self.call_work(self.request_work('revoke', {'peer': 'alice'}, operation='unproved'))
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        for field, wrong in (('signature', 'A' * 86 + '=='), ('subject', 'am.ctl.bob'),
                ('repositoryId', 'r000000000000')):
            with self.subTest(field=field):
                altered = {**selector, field: wrong}
                result = await self.call_work(self.request_work('revoke', {'peer': 'alice', 'control': altered},
                    operation='wrong-' + field.lower(), revision=await self.version()))
                self.assertEqual(result['outcome'], 'rejected')
        result = await self.call_work(self.request_work('revoke', {'peer': 'bob', 'control': selector},
            operation='wrong-peer', revision=await self.version()))
        self.assertEqual(result['outcome'], 'rejected')
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM work_items ORDER BY rowid'), rows)

    async def test_committed_outcome_recovers_after_peer_revoke_but_not_service_grant_revoke(self):
        await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac')
        value = {'peer': 'alice', 'control': await self.retain_control(event)}
        original = self.request_work('revoke', value)
        first = await self.call_work(original)
        record = strict_loads(self.snapshot.record)
        next(g for g in record['state']['grants'] if g['ref'] == ref('control-grant'))['status'] = 'revoked'
        current = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)
        query = {'contractId': 'federation-work-revoke', 'operationId': 'control-effect',
            'payloadDigest': payload_digest(strict_loads(original)['claims']['payload'])}
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=current)):
            recovered = await self.call_work(self.request_work('outcome', query, operation='current-query', revision=2))
            self.assertEqual({k: recovered[k] for k in first}, first)
            new_event = envelope.make('revoke', 'alice', 'mac')
            rejected = await self.call_work(self.request_work('revoke',
                {'peer': 'alice', 'control': await self.retain_control(new_event)},
                operation='new-denied', revision=2))
            self.assertEqual((rejected['outcome'], rejected['result']), ('rejected', {'cancelled': 0}))
        next(g for g in record['state']['grants'] if g['ref'] == self.work_grants['federation-work-revoke'])['status'] = 'revoked'
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(record), self.snapshot.sequence + 2))), self.assertRaises(ContractError):
            await self.call_work(self.request_work('outcome', query, operation='service-denied', revision=2))

    async def test_client_replay_archives_original_and_uses_only_outcome_after_lost_reply(self):
        await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        session, owner, wire = self.work_session(lose_applied=True)
        hub, fed, client = self.work_client(session)
        message = self.control_message(fed, event, selector)
        async with fed._work_intents.control(message.subject, event, message):
            with self.assertRaises(Exception):
                await client.revoke('alice')
        pending = await hub.db(hub.store.q, "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'")
        self.assertEqual(len(pending), 1)
        original = strict_loads(pending[0]['v'])
        self.assertEqual(original['payload']['input']['control']['eventId'], event['id'])
        await client._client.close(timeout=None)
        replacement, _, fresh = self.work_session()
        hub, fed, client = self.work_client(replacement)
        await client.recover_controls()
        self.assertEqual([strict_loads(raw)['claims']['contractId'] for raw in fresh.requests],
            ['federation-work-inspect', 'federation-work-outcome'])
        self.assertEqual(await hub.db(hub.store.q, "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        completed = await hub.db(hub.store.q, "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-control:%'")
        self.assertEqual(len(completed), 1)
        self.assertEqual(strict_loads(completed[0]['v'])['operationId'], original['operationId'])
        message = self.control_message(fed, event, selector)
        async with fed._work_intents.control(message.subject, event, message):
            self.assertEqual(await client.revoke('alice'), {'cancelled': 2})
        self.assertEqual(sum(strict_loads(raw)['claims']['contractId'] == 'federation-work-revoke'
            for raw in wire.requests + fresh.requests), 1)
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='work-revoke'")), 1)

    async def test_close_joins_original_admission_and_caller_can_join_same_cleanup(self):
        event = envelope.make('revoke', 'alice', 'mac')
        value = {'peer': 'alice', 'control': await self.retain_control(event)}
        original = strict_loads(self.request_work('revoke', value))
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
        admitted = await self.identity.ingress.admit(self.request_work('revoke', value),
            cancellation_ref=ref('control-pause-cancellation'))
        entered, release = asyncio.Event(), asyncio.Event()
        source, store = self.source, self.source._store
        async def authority(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.snapshot
        joined = None
        with patch('hub.fed.peer_control.check_authority', authority):
            original = asyncio.create_task(self.controller.admit(self.resource, admitted.envelope,
                datetime.now(timezone.utc) + timedelta(seconds=5)))
            try:
                await asyncio.wait_for(entered.wait(), 1)
                self.assertTrue(self.controller._active)
                self.assertTrue(self.ingress._active)
                self.controller.begin_policy_pause()
                joined = asyncio.create_task(self.controller.join_policy_pause())
                await asyncio.sleep(0)
                self.assertFalse(joined.done())
                with self.assertRaises(ContractError):
                    self.controller.check()
                self.controller.check_health()
                self.ingress.check_health()
                self.assertIs(self.ingress._store_owner, source)
                self.assertIs(source._store, store)
                release.set()
                with self.assertRaises(ContractError):
                    await original
                await asyncio.wait_for(joined, 1)
                self.assertFalse(self.controller._active)
                self.assertFalse(self.ingress._active)
                self.assertFalse(self.ingress._workers)
            finally:
                release.set()
                await asyncio.gather(original, return_exceptions=True)
                if joined is not None:
                    await asyncio.gather(joined, return_exceptions=True)
        self.controller.end_policy_pause()
        self.controller.check()
        self.assertFalse(self.ingress._policy_paused)
        self.assertIs(source._store, store)
        self.assertEqual(await source.db(lambda: 1), 1)

    async def test_authenticated_owner_rejection_retires_only_the_exact_no_effect_control(self):
        rows = await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        selector['signature'] = base64.b64encode(bytes(64)).decode()
        session, _, wire = self.work_session()
        hub, fed, client = self.work_client(session)
        message = self.control_message(fed, event, selector)
        async with fed._work_intents.control(message.subject, event, message):
            result = await client.revoke('alice')
        self.assertEqual(result, {'cancelled': 0})
        self.assertEqual(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        completed = await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-control:%'")
        self.assertEqual(len(completed), 1)
        self.assertEqual(strict_loads(completed[0]['v'])['confirmedReply']['outcome'], 'rejected')
        message = self.control_message(fed, event, selector)
        async with fed._work_intents.control(message.subject, event, message):
            self.assertEqual(await client.revoke('alice'), result)
        self.assertEqual(sum(strict_loads(raw)['claims']['contractId'] == 'federation-work-revoke'
            for raw in wire.requests), 1)
        self.assertEqual(await self.source.db(self.source._store.q,
            'SELECT * FROM work_items ORDER BY rowid'), rows)

    async def test_policy_pause_at_commit_fences_the_original_control_without_effect(self):
        rows = await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac')
        value = {'peer': 'alice', 'control': await self.retain_control(event)}
        raw = self.request_work('revoke', value)
        original_commit = self.resource._journal.commit
        def pause(*args, **kwargs):
            self.controller.begin_policy_pause()
            return original_commit(*args, **kwargs)
        with patch.object(self.resource._journal, 'commit', side_effect=pause), self.assertRaises(ContractError):
            await self.call_work(raw)
        await self.controller.join_policy_pause()
        self.controller.end_policy_pause()
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM work_items ORDER BY rowid'), rows)
        claims = strict_loads(raw)['claims']
        self.assertIsNone(await self.source.db(self.resource._journal.outcome,
            claims['operationId'], payload_digest(claims['payload'])))

    async def test_independent_subscription_order_waits_only_for_original_protected_receipt(self):
        await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        await self.source.db(self.source._store.db.execute, 'DELETE FROM fed_state WHERE k=?',
            (self.ingress._key(event['id']),))
        entered = asyncio.Event()
        recover = self.ingress.recover
        async def observe(*args, **kwargs):
            try:
                return await recover(*args, **kwargs)
            except ContractError as error:
                if error.code == 'peer_control_event_unadmitted':
                    entered.set()
                raise
        with patch.object(self.ingress, 'recover', side_effect=observe):
            original = asyncio.create_task(self.call_work(self.request_work('revoke',
                {'peer': 'alice', 'control': selector})))
            try:
                await asyncio.wait_for(entered.wait(), 1)
                self.assertFalse(original.done())
                self.assertEqual(await self.retain_control(event), selector)
                result = await asyncio.wait_for(original, 3)
                self.assertEqual(result['result'], {'cancelled': 2})
            finally:
                if not original.done():
                    original.cancel()
                await asyncio.gather(original, return_exceptions=True)

    async def test_wrong_zero_effect_reply_cannot_retire_original_control(self):
        rows = await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        selector['signature'] = base64.b64encode(bytes(64)).decode()
        session, _, wire = self.work_session()
        hub, fed, client = self.work_client(session)
        sign = self.endpoint._sign
        def wrong_result(request, resource, result, checked, **options):
            if result.get('outcome') == 'rejected':
                result = {**result, 'result': {'cancelled': 1}}
            return sign(request, resource, result, checked, **options)
        message = self.control_message(fed, event, selector)
        with patch.object(self.endpoint, '_sign', side_effect=wrong_result), self.assertRaises(ContractError):
            async with fed._work_intents.control(message.subject, event, message):
                await client.revoke('alice')
        self.assertEqual(len(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 1)
        self.assertEqual(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-control:%'"), [])
        await client.recover_controls()
        self.assertEqual(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        self.assertEqual(sum(strict_loads(raw)['claims']['contractId'] == 'federation-work-revoke'
            for raw in wire.requests), 1)
        self.assertEqual(await self.source.db(self.source._store.q,
            'SELECT * FROM work_items ORDER BY rowid'), rows)

    async def test_local_policy_deny_still_withdraws_without_a_peer_control(self):
        await self.seed_work()
        with patch.object(self.domain.policy, 'trust', return_value='deny'), \
                patch.object(self.controller, 'admit', side_effect=AssertionError('No peer proof is implied')):
            result = await self.call_work(self.request_work('revoke', {'peer': 'alice'}))
        self.assertEqual(result['result'], {'cancelled': 2})
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='work-revoke'"), [])

    async def test_cancellation_and_close_join_the_original_control_archive(self):
        await self.seed_work()
        event = envelope.make('revoke', 'alice', 'mac')
        selector = await self.retain_control(event)
        session, _, _ = self.work_session()
        hub, fed, client = self.work_client(session)
        entered, release = asyncio.Event(), asyncio.Event()
        owned_db = client._client._owned_db
        async def pause(function, *args, **kwargs):
            if function.__name__ == 'archive':
                entered.set()
                await release.wait()
            return await owned_db(function, *args, **kwargs)
        async def withdraw():
            message = self.control_message(fed, event, selector)
            async with fed._work_intents.control(message.subject, event, message):
                return await client.revoke('alice')
        with patch.object(client._client, '_owned_db', side_effect=pause):
            original = asyncio.create_task(withdraw())
            try:
                await asyncio.wait_for(entered.wait(), 3)
                original.cancel()
                await asyncio.sleep(0)
                self.assertFalse(original.done())
                with self.assertRaises(ContractError):
                    await client._client.close(timeout=.001)
                closing = client._client._closing
                self.assertFalse(closing.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await original
                await client._client.close(timeout=None)
                self.assertIs(client._client._closing, closing)
                self.assertTrue(closing.done())
                self.assertFalse(client._client._workers)
            finally:
                release.set()
                if not original.done():
                    original.cancel()
                await asyncio.gather(original, return_exceptions=True)
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_audit WHERE decision='work-revoke'")), 1)
        self.assertEqual(await self.source.db(lambda: 1), 1)
