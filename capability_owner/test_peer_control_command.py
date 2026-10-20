"""Real enrolled operator frames and retained self-revoke owner outcomes."""
import asyncio
import base64
import copy
import hashlib
import threading
import weakref
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import nkeys

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import envelope
from hub.fed.peer_control import PeerControlPublisher
from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from identity.application_client import ApplicationClientKey
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref, SEED
from identity.test_knowledge_client import material
from identity import test_peer_control as peer_support
from identity.test_peer_control import control_credentials
from .peer_control_command import PeerControlCommandOwner
from .peer_control_service import PeerControlCommandService
from .peer_control_client import PeerControlCommandClient


class PeerControlCommandFixture(peer_support.PeerControlFixture):
    def setUp(self):
        super().setUp()
        self.grants = {name: ref('operator-' + name) for name in ('federation-peer-revoke', 'federation-peer-revoke-outcome')}
        route = self.value['peerControl']['routes'][0]
        route['operators'] = [{'identityRef': ref('human'), 'transportRef': ref('control-operator-transport'),
            'grants': self.grants}]
        raw, _, _ = control_credentials(peer='nick')
        token = raw.splitlines()[1]
        first, second, _ = token.split(b'.')
        claims = strict_loads(base64.urlsafe_b64decode(second + b'=' * (-len(second) % 4)))
        key = nkeys.from_seed(nkeys.encode_seed(bytes([33]) * 32, nkeys.PREFIX_BYTE_USER))
        account = nkeys.from_seed(nkeys.encode_seed(bytes([1]) * 32, nkeys.PREFIX_BYTE_ACCOUNT))
        try:
            publisher_user = key.public_key.decode()
            claims['sub'] = publisher_user
            second = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
            updated = first + b'.' + second
            updated += b'.' + base64.urlsafe_b64encode(account.sign(updated)).rstrip(b'=')
            raw = raw.replace(token, updated).replace(raw.split(b'BEGIN USER NKEY SEED-----\n')[1].splitlines()[0], key.seed)
        finally:
            account.wipe()
            key.wipe()
        path = self.root / 'control-command-publisher.creds'
        path.write_bytes(raw)
        path.chmod(0o600)
        route['publisher'] = {'identityRef': ref('control-local-publisher'),
            'transportRef': ref('control-local-publisher-transport'), 'grantRef': ref('control-local-publisher-grant'),
            'credentials': {'path': str(path), 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(),
                'userPublicKey': publisher_user}}
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        state = current['state']
        state['identities'].append({'ref': ref('control-local-publisher'), 'kind': 'service', 'status': 'active',
            'principalId': 'control-local-publisher', 'externalIdentity': None})
        state['memberships'].append({'ref': ref('control-local-publisher-member'), 'identityRef': ref('control-local-publisher'),
            'scope': copy.deepcopy(self.scope), 'status': 'active'})
        publisher_transport = copy.deepcopy(state['transports'][0])
        publisher_transport.update(ref=ref('control-local-publisher-transport'), identityRef=ref('control-local-publisher'),
            issuerRef=self.value['identity']['issuer']['issuerRef'], issuedAt=self.issuer_start,
            expiresAt=self.issuer_end, publicKey=base64.urlsafe_b64encode(base64.b32decode(publisher_user)[1:-2]).decode().rstrip('='))
        state['transports'].append(publisher_transport)
        publisher_grant = copy.deepcopy(state['grants'][0])
        publisher_grant.update(ref=ref('control-local-publisher-grant'), callerRef=ref('control-local-publisher'),
            actorRef=ref('control-local-publisher'), scope=copy.deepcopy(self.scope), resourceId='knowledge-one',
            contractId='peer-control-revoke', decision='allowed', delegationRef=None,
            issuedAt=self.issuer_start, expiresAt=self.issuer_end)
        state['grants'].append(publisher_grant)
        template = copy.deepcopy(state['transports'][0])
        template.update(ref=ref('control-operator-transport'), identityRef=ref('human'),
            issuerRef=self.value['identity']['issuer']['issuerRef'], issuedAt=self.issuer_start,
            expiresAt=self.issuer_end, publicKey=base64.urlsafe_b64encode(bytes(
                SigningKey(bytes(reversed(SEED))).verify_key)).decode().rstrip('='))
        state['transports'].append(template)
        state['memberships'].append({'ref': ref('control-operator-member'), 'identityRef': ref('human'),
            'scope': copy.deepcopy(self.scope), 'status': 'active'})
        for contract, grant_ref in self.grants.items():
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=grant_ref, callerRef=ref('human'), actorRef=ref('human'), scope=copy.deepcopy(self.scope),
                resourceId='knowledge-one', contractId=contract, decision='allowed', delegationRef=None,
                issuedAt=self.issuer_start, expiresAt=self.issuer_end)
            state['grants'].append(grant)
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence + 1)
        selected = material()
        commands = selected.pop('knowledgeCommands')
        commands.update(routeId=route['routeId'], resourceRef=route['resourceRef'],
            repository={k: route['repository'][k] for k in ('localName', 'repositoryId')},
            localPeer=route['localPeer'], localNode=route['localNode'], transportRef=ref('control-operator-transport'),
            grantRefs=self.grants, replyIssuerRef=self.value['identity']['issuer']['issuerRef'],
            replyIssuerPublicKey=self.value['identity']['issuer']['publicKey'])
        signer = next(s for s in state['issuers'] if s['ref'] == commands['replyIssuerRef'])
        commands.update(serviceIdentityRef=signer['identityRef'], serviceInstanceId=signer['instanceId'])
        selected['peerControlCommands'] = commands
        self.key = ApplicationClientKey(selected)
        self.commands, self.signer = commands, signer

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.publisher = PeerControlPublisher(self.selection, self.identity, route_id='knowledge-alice')
        self.addAsyncCleanup(self.publisher.close, timeout=None)
        self.owner = PeerControlCommandOwner(self.selection, self.identity, self.source, (self.publisher,))
        self.addAsyncCleanup(self.owner.close, timeout=None)
        self.endpoint = PeerControlCommandService(self.identity.ingress, self.owner,
            service_identity_ref=self.signer['identityRef'], service_instance_id=self.signer['instanceId'],
            signing_key_ref=self.signer['ref'], signing_seed=self.identity.ingress._seed)
        self.addAsyncCleanup(self.endpoint.close, timeout=None)
        self.current = patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot))
        self.current.start()
        self.addCleanup(self.current.stop)

    def request(self, item, *, operation='original-kill', query=None, approval_refs=()):
        now = datetime.now(timezone.utc)
        contract = 'federation-peer-revoke-outcome' if query else 'federation-peer-revoke'
        value = query or {'routeId': self.commands['routeId'], 'envelope': item}
        payload = {'resourceRef': self.commands['resourceRef'], 'input': value}
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': self.commands['transportRef'],
            'grantRef': self.grants[contract], 'operationId': operation, 'expectedVersion': 1,
            'contractId': contract, 'payload': payload, 'approvalRefs': list(approval_refs),
            'replySubject': '_INBOX.peer_control_command_0001',
            'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}
        return self.key.sign_command(claims, subject=self.commands['subject'], now=now)

    async def call(self, raw):
        response = await self.endpoint.handle(raw,
            received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        return self.key.verify_command_response(response, raw, subject=self.commands['subject'],
            now=datetime.now(timezone.utc))

    def open_session(self, *, lose_reply=False):
        """Use real session/connection methods with only broker I/O controlled."""
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')
        client = SimpleNamespace(is_connected=True, max_payload=65536,
            flush=AsyncMock(), close=AsyncMock())
        binding = ClientBindingState(client, public_key=self.key.selection['replyIssuerPublicKey'],
            signing_key_ref=ref('issuer'), caller_ref=ref('human'), scope=self.scope)
        owner = ClientConnectionOwner(client, binding,
            command_subject='amx.v1.h.hub-one.o.org-one.identity.authority-one.command',
            reply_prefix='_INBOX.peer_control_client_000001', signer=self.key)
        owner._connected = True
        owner._current_command_binding = AsyncMock(return_value={'validUntil': expiry})
        owner._require_query_binding = Mock(return_value={'validUntil': expiry})
        self.addAsyncCleanup(owner.close, deadline=asyncio.get_running_loop().time() + 15)
        wire = SimpleNamespace(requests=[], responses=[], subscriptions=[], limits=[])

        async def subscribe(subject, **options):
            wire.limits.append(options['pending_bytes_limit'])
            async def next_message(**_options):
                if lose_reply:
                    raise TimeoutError()
                return SimpleNamespace(subject=subject, data=wire.responses[-1])
            subscription = SimpleNamespace(unsubscribe=AsyncMock(), next_msg=next_message)
            wire.subscriptions.append(subscription)
            return subscription

        async def publish(subject, raw, *, reply):
            self.assertEqual(subject, self.commands['subject'])
            wire.requests.append(raw)
            wire.responses.append(await self.endpoint.handle(raw, received_reply_subject=reply))
        client.subscribe, client.publish = subscribe, publish
        session = object.__new__(ApplicationClientSession)
        session._owner, session._loop = owner, asyncio.get_running_loop()
        session._thread, session._loop_stopping = threading.current_thread(), False
        session._stopped, session._closing, session._final_closing = False, None, None
        session._terminal_enrolled, session._terminal_active = False, False
        session._peer_control_enrollment = canonical_bytes({
            'scope': self.scope, 'peerControlCommands': self.commands})
        session._command_future = session._command_identity = None
        return session, owner, client, wire

    async def session_call(self, session, payload, *, operation, contract='federation-peer-revoke', approval_refs=()):
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')
        return await asyncio.to_thread(session.peer_control_command,
            contract_id=contract, operation_id=operation, payload=payload, expires_at=expiry,
            approval_refs=approval_refs)

    def hub_client(self, session):
        from hub.server import Hub
        from hub.fed.runtime import Federation
        hub = object.__new__(Hub)
        hub.store, hub.db = self.source._store, self.source.db
        hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        hub._authenticated_callers = weakref.WeakKeyDictionary()
        hub._authenticated_caller_context = ContextVar('peer-control-test-caller', default=None)
        federation = object.__new__(Federation)
        federation.hub, federation.node = hub, 'mac'
        federation.cfg = {'federation': {'peer': 'nick'}}
        adapter = PeerControlCommandClient(hub, (session,)).bind(federation)
        self.addAsyncCleanup(adapter.close, timeout=None)
        return hub, adapter

    async def hub_revoke(self, hub, adapter, item, *, token='operator-secret'):
        request = {'token': token, 'verb': 'fed_kill', 'args': {'revoke': True}}
        proof = await hub.authenticate_caller(request, SimpleNamespace(), True)
        context = hub._authenticated_caller_context.set(proof)
        try:
            return await adapter.revoke('operator', item)
        finally:
            hub._authenticated_caller_context.reset(context)



class PeerControlCommandTests(PeerControlCommandFixture, unittest.IsolatedAsyncioTestCase):
    async def test_real_session_recovers_original_after_lost_reply(self):
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        payload = {'resourceRef': self.commands['resourceRef'],
            'input': {'routeId': self.commands['routeId'], 'envelope': item}}
        session, original, client, wire = self.open_session(lose_reply=True)
        with patch.object(self.publisher, 'publish_revoke', AsyncMock(return_value={
                'eventId': item['id'], 'eventDigest': payload_digest(item)})) as publish:
            with self.assertRaises(ApplicationSessionFailure):
                await self.session_call(session, payload, operation='lost-peer-revoke')
            self.assertEqual(original.command_request, wire.requests[0])
            self.assertFalse(original._subscriptions)
            self.assertTrue(original._exchange_task.done())
            self.assertTrue(original._close_task.done())
            client.close.assert_awaited_once()
            wire.subscriptions[0].unsubscribe.assert_awaited_once()
            retained = strict_loads(wire.requests[0])['claims']
            replacement, fresh_owner, _, fresh = self.open_session()
            query = {'resourceRef': self.commands['resourceRef'], 'input': {
                'routeId': self.commands['routeId'], 'operationId': retained['operationId'],
                'payloadDigest': payload_digest(retained['payload'])}}
            recovered = await self.session_call(replacement, query, operation='recover-peer-revoke',
                contract='federation-peer-revoke-outcome')
            self.assertEqual(recovered, strict_loads(wire.responses[0])['claims']['result'])
            self.assertEqual(recovered['eventId'], item['id'])
            self.assertEqual(recovered['outcome'], 'published')
            self.assertEqual(publish.call_count, 1)
            self.assertEqual(fresh.limits, [65536])
            self.assertFalse(fresh_owner._subscriptions)
            self.assertNotEqual(fresh.requests[0], wire.requests[0])

    async def test_real_session_requires_current_approval_and_hard_denial_wins(self):
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        payload = {'resourceRef': self.commands['resourceRef'],
            'input': {'routeId': self.commands['routeId'], 'envelope': item}}
        record = strict_loads(self.snapshot.record)
        grant = next(g for g in record['state']['grants'] if g['ref'] == self.grants['federation-peer-revoke'])
        grant['decision'] = 'review-required'
        approver = copy.deepcopy(grant)
        approver.update(ref=ref('control-approve'), contractId='identity-approve',
            resourceId=grant['ref']['id'], decision='allowed')
        record['state']['grants'].append(approver)
        record['state']['approvals'].append({'ref': ref('control-approval'), 'grantRef': grant['ref'],
            'approverRef': ref('human'), 'approverGrantRef': approver['ref'],
            'payloadDigest': payload_digest(payload), 'audience': {'hubId': 'hub-one', 'serviceId': 'storage-owner'},
            'operationId': 'approved-peer-kill', 'expectedVersion': 1, 'decision': 'approved', 'status': 'active',
            'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        approved = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=approved)), \
                patch.object(self.publisher, 'publish_revoke', AsyncMock(return_value={
                    'eventId': item['id'], 'eventDigest': payload_digest(item)})) as publish:
            missing, _, _, _ = self.open_session()
            with self.assertRaises(ApplicationSessionFailure):
                await self.session_call(missing, payload, operation='approved-peer-kill')
            publish.assert_not_awaited()
            session, _, _, _ = self.open_session()
            result = await self.session_call(session, payload, operation='approved-peer-kill',
                approval_refs=(ref('control-approval'),))
            self.assertEqual(result['outcome'], 'published')
            denial = copy.deepcopy(grant)
            denial.update(ref=ref('control-hard-denial'), decision='denied')
            record['state']['grants'].append(denial)
            denied = AuthoritySnapshot(canonical_bytes(record), approved.sequence + 1)
            with patch.object(self.identity.reader, 'current', AsyncMock(return_value=denied)):
                session, _, _, _ = self.open_session()
                with self.assertRaises(ApplicationSessionFailure):
                    await self.session_call(session, payload, operation='approved-peer-kill',
                        approval_refs=(ref('control-approval'),))
                query = {'resourceRef': self.commands['resourceRef'], 'input': {
                    'routeId': self.commands['routeId'], 'operationId': result['operationId'],
                    'payloadDigest': result['payloadDigest']}}
                session, _, _, _ = self.open_session()
                with self.assertRaises(ApplicationSessionFailure):
                    await self.session_call(session, query, operation='denied-peer-outcome',
                        contract='federation-peer-revoke-outcome')
            self.assertEqual(publish.call_count, 1)

    async def test_cancelled_waiter_joins_original_publication_before_source_release(self):
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        entered, release = asyncio.Event(), asyncio.Event()
        async def publish(_item):
            entered.set()
            await release.wait()
            return {'eventId': item['id'], 'eventDigest': payload_digest(item)}
        with patch.object(self.publisher, 'publish_revoke', side_effect=publish) as original:
            waiter = asyncio.create_task(self.call(self.request(item)))
            await entered.wait()
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            with self.assertRaises(ContractError):
                await self.endpoint.close(timeout=0.01)
            closing = self.endpoint._closing
            self.assertFalse(closing.done())
            self.assertTrue(self.owner._workers)
            release.set()
            await self.endpoint.close(timeout=2)
            self.assertIs(self.endpoint._closing, closing)
            await self.owner.close(timeout=2)
            self.assertFalse(self.owner._workers)
            self.assertFalse(self.owner._active)
            self.assertEqual(original.call_count, 1)
            self.source.check_health()

    async def test_hub_intent_recovers_original_with_actual_replacement_session(self):
        session, _, _, wire = self.open_session(lose_reply=True)
        hub, adapter = self.hub_client(session)
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        async def sent(original):
            pending = await self.source.db(self.source._store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'peer-control-client:%'")
            self.assertEqual(len(pending), 1)
            self.assertEqual(strict_loads(pending[0]['v'])['payload']['input']['envelope'], original)
            return {'eventId': original['id'], 'eventDigest': payload_digest(original)}
        with patch.object(self.publisher, 'publish_revoke', side_effect=sent) as publish:
            with self.assertRaises(ApplicationSessionFailure):
                await self.hub_revoke(hub, adapter, item)
            await adapter.close(timeout=2)
            replacement, _, _, fresh = self.open_session()
            recovered = PeerControlCommandClient(hub, (replacement,)).bind(adapter._federation)
            self.addAsyncCleanup(recovered.close, timeout=None)
            new_item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
            result = await self.hub_revoke(hub, recovered, new_item)
            self.assertEqual(result[0]['eventId'], item['id'])
            self.assertNotEqual(result[0]['eventId'], new_item['id'])
            self.assertEqual(result[0], strict_loads(wire.responses[0])['claims']['result'])
            self.assertEqual(strict_loads(fresh.requests[0])['claims']['contractId'],
                'federation-peer-revoke-outcome')
            self.assertEqual(publish.call_count, 1)
            with self.assertRaises(Exception):
                await recovered.revoke('operator', new_item)

    async def test_signed_route_subject_actor_and_result_substitution_refuse(self):
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        raw = self.request(item)
        for field, value in (('resourceRef', ref('other-knowledge')), ('routeId', 'other-route'),
                ('from', 'alice'), ('node', 'other-node')):
            packet = strict_loads(raw)
            payload = packet['claims']['payload']
            if field == 'resourceRef':
                payload[field] = value
            elif field == 'routeId':
                payload['input'][field] = value
            else:
                payload['input']['envelope'][field] = value
            with self.assertRaises(ContractError):
                await self.call(canonical_bytes(packet))
        wrong_actor = strict_loads(self.snapshot.record)
        next(i for i in wrong_actor['state']['identities'] if i['ref'] == ref('human'))['kind'] = 'plugin'
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(wrong_actor), self.snapshot.sequence + 1))), self.assertRaises(ContractError):
            await self.call(raw)
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'peer-control-command:%'"), [])
        with patch.object(self.publisher, 'publish_revoke', AsyncMock(return_value={
                'eventId': item['id'], 'eventDigest': payload_digest(item)})):
            reply = await self.endpoint.handle(raw, received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        packet = strict_loads(reply)
        packet['claims']['result']['eventId'] = 'substituted-event'
        with self.assertRaises(ContractError):
            self.key.verify_command_response(canonical_bytes(packet), raw, subject=self.commands['subject'],
                now=datetime.now(timezone.utc))

    async def test_original_retained_before_publish_and_replayed_without_second_send(self):
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        raw = self.request(item)
        async def sent(value):
            rows = await self.source.db(self.source._store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'peer-control-command:%'")
            self.assertEqual(len(rows), 1)
            retained = strict_loads(rows[0]['v'])
            self.assertEqual(retained['original']['payload']['input']['envelope'], item)
            self.assertEqual(retained['result']['outcome'], 'uncertain')
            return {'eventId': item['id'], 'eventDigest': payload_digest(item)}
        with patch.object(self.publisher, 'publish_revoke', side_effect=sent) as publish:
            result = await self.call(raw)
            self.assertEqual(result['outcome'], 'published')
            self.assertEqual(await self.call(self.request(item)), result)
            self.assertEqual(publish.call_count, 1)
            query = {'routeId': self.commands['routeId'], 'operationId': result['operationId'],
                'payloadDigest': result['payloadDigest']}
            self.assertEqual(await self.call(self.request(None, operation='query-original', query=query)), result)

    async def test_unknown_send_is_retained_and_query_cannot_republish(self):
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        raw = self.request(item)
        with patch.object(self.publisher, 'publish_revoke', AsyncMock(side_effect=TimeoutError())) as publish:
            with self.assertRaises(ContractError):
                await self.call(raw)
            result = await self.call(self.request(item))
            self.assertEqual(result['outcome'], 'uncertain')
            self.assertEqual(publish.call_count, 1)
            query = {'routeId': self.commands['routeId'], 'operationId': result['operationId'],
                'payloadDigest': result['payloadDigest']}
            self.assertEqual(await self.call(self.request(None, operation='query-original', query=query)), result)
            self.assertEqual(publish.call_count, 1)

    async def test_revoked_original_grant_prevents_outcome_disclosure(self):
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'kill switch'})
        with patch.object(self.publisher, 'publish_revoke', AsyncMock(return_value={
                'eventId': item['id'], 'eventDigest': payload_digest(item)})):
            result = await self.call(self.request(item))
        record = strict_loads(self.snapshot.record)
        next(g for g in record['state']['grants'] if g['ref'] == self.grants['federation-peer-revoke'])['status'] = 'revoked'
        query = {'routeId': self.commands['routeId'], 'operationId': result['operationId'], 'payloadDigest': result['payloadDigest']}
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(record), self.snapshot.sequence + 1))), self.assertRaises(ContractError):
            await self.call(self.request(None, operation='query-revoked', query=query))

