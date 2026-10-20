"""Actual enrolled legacy admission shares the original message transaction."""
import copy
import asyncio
from datetime import datetime, timedelta
import unittest
from unittest.mock import patch, AsyncMock, Mock
from types import SimpleNamespace

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed import ledger
from hub.tests.test_fed_unit import policy
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from .message_bridge_service import MessageBridgeService, verify_message_bridge_reply
from .messages import LegacyMessageActor
from .test_messages import MessageFixture


class BridgeOwnerFixture(MessageFixture):
    def setUp(self):
        MessageFixture.setUp(self)
        self.claims['expiresAt'] = (datetime.fromisoformat(self.claims['issuedAt'])
            + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')
        state = self.record['state']
        template = next(g for g in state['grants'] if g['ref'] == ref('messages-write'))
        human, service = {}, {}
        for identity, target, commands in (('human', human, ('send', 'approve', 'inspect', 'outcome')),
                ('service', service, ('deliver', 'inspect', 'outcome'))):
            for command in commands:
                contract = 'federation-message-' + command
                grant = copy.deepcopy(template)
                grant.update(ref=ref('legacy-' + identity + '-' + command), callerRef=ref(identity),
                    actorRef=ref(identity), contractId=contract)
                state['grants'].append(grant)
                target[contract] = grant['ref']
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('legacy-service-member'), identityRef=ref('service'), scope=copy.deepcopy(self.scope))
        state['memberships'].append(member)
        transport = copy.deepcopy(next(t for t in state['transports'] if t['ref'] == ref('transport')))
        transport.update(ref=ref('legacy-service-transport'), identityRef=ref('service'))
        state['transports'].append(transport)
        self.legacy_grants = {'human': human, 'service': service}
        self.legacy_actors = (
            LegacyMessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')),
                'operator', canonical_bytes(human)),
            LegacyMessageActor(canonical_bytes(ref('service')), canonical_bytes(ref('legacy-service-transport')),
                'federation', canonical_bytes(service)))
        self.js.messages[0].data = canonical_bytes(self.record)

    def open_resource(self, **changes):
        changes.setdefault('legacy_actors', self.legacy_actors)
        return MessageFixture.open_resource(self, **changes)

    async def bridge_prepare(self, command, *, value=None, operation='legacy-one', revision=1,
                             query=None, identity=None):
        identity = identity or ('service' if command == 'deliver' else 'human')
        contract = 'federation-message-' + command
        if query is not None:
            payload = {'resourceRef': {**ref('task-one'), 'revision': revision}, 'input': query}
        elif command == 'inspect':
            payload = {'resourceRef': {**ref('task-one'), 'revision': revision}, 'input': {}}
        else:
            value = value or self.value(command='publish' if command == 'send' else 'post')
            env = value['envelope']
            payload = {'resourceRef': {**ref('task-one'), 'revision': revision},
                'attribution': 'federation' if identity == 'service' else 'operator',
                'input': {'envelope': env, 'subject': 'am.msg.nick.alice' if command == 'send' else 'am.msg.alice.nick',
                    'localNode': 'mac'}}
            if command == 'approve':
                payload['input'].update(quarantineId=value['quarantineId'], privileged=value.get('privileged', False))
        self.claims.update(operationId=operation, expectedVersion=revision, contractId=contract, payload=payload,
            transportRef=ref('legacy-service-transport' if identity == 'service' else 'transport'),
            grantRef=self.legacy_grants[identity][contract])
        admitted = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return admitted.envelope


class MessageBridgeOwnerTests(BridgeOwnerFixture, unittest.IsolatedAsyncioTestCase):
    async def test_signed_send_replay_and_fresh_outcome_keep_original_outbox(self):
        value = self.value(command='publish')
        raw = await self.bridge_prepare('send', value=value)
        first = await self.resource.legacy(self.service.reader, raw)
        self.assertEqual(first['outcome'], 'applied')
        self.assertEqual(await self.resource.legacy(self.service.reader, raw), first)
        self.assertEqual(self.store.q1('SELECT * FROM fed_outbox')['msg_id'], value['envelope']['id'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')), 1)
        original = strict_loads(raw)['operation']
        query = {'contractId': 'federation-message-send',
            **{k: original[k] for k in ('operationId', 'payloadDigest')}}
        recovered = await self.resource.legacy(self.service.reader,
            await self.bridge_prepare('outcome', operation='recover-one', query=query))
        self.assertEqual(recovered['receiptRef'], first['receiptRef'])
        self.assertEqual(recovered['result'], first['result'])

    async def test_enrolled_federation_service_delivers_with_original_message_id_and_fts(self):
        value = self.value()
        reply = await self.resource.legacy(self.service.reader, await self.bridge_prepare('deliver', value=value))
        self.assertEqual(reply['result']['deliveryOutcome'], 'delivered')
        row = self.store.q1('SELECT * FROM messages')
        self.assertEqual(row['idem_key'], 'fed:' + value['envelope']['id'])
        self.assertEqual(self.store.q1('SELECT * FROM deliveries')['message_id'], row['id'])
        self.assertEqual(self.store.q1('SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?', ('Original',))['rowid'], 1)
        checked = await self.resource.authorize_legacy(self.service.reader,
            await self.bridge_prepare('inspect', operation='inspect-one', identity='service'))
        with self.assertRaises(AttributeError):
            checked.valid_until = None

    async def test_recovery_cannot_replace_the_revoked_selected_original_grant(self):
        raw = await self.bridge_prepare('send')
        await self.resource.legacy(self.service.reader, raw)
        operation = strict_loads(raw)['operation']
        self.claims.update(operationId='revoke-selected-send', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2,
            payload={'authorityId': 'authority-one',
                'targetRef': self.legacy_grants['human']['federation-message-send']})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        current = strict_loads(self.js.messages[-1].data)
        grant = next(g for g in current['state']['grants']
            if g['ref']['id'] == self.legacy_grants['human']['federation-message-send']['id'])
        replacement = copy.deepcopy(grant)
        replacement.update(ref=ref('other-send-grant'), status='active')
        current['state']['grants'].append(replacement)
        self.js.messages[-1].data = canonical_bytes(current)
        query = {'contractId': 'federation-message-send',
            **{k: operation[k] for k in ('operationId', 'payloadDigest')}}
        admitted = await self.bridge_prepare('outcome', operation='recover-revoked', query=query, revision=2)
        with self.assertRaises(ContractError):
            await self.resource.legacy(self.service.reader, admitted)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)

    async def test_operator_approval_delivers_while_exact_item_still_held(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        value = self.value()
        value['quarantineId'] = ledger.quarantine_add(self.store, value['envelope'], 'am.msg.alice.nick',
            'msg', 'alice', 'trust approve for alice')
        raw = await self.bridge_prepare('approve', value=value)
        reply = await self.resource.legacy(self.service.reader, raw)
        self.assertEqual(reply['result']['deliveryOutcome'], 'delivered')
        self.assertEqual(ledger.quarantine_get(self.store, value['quarantineId'])['state'], 'held')
        self.assertIn('REMOTE DATA', self.store.q1('SELECT * FROM messages')['body'])
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)

    async def test_foreign_route_and_sender_refuse_before_any_effect(self):
        for change in (lambda v:v['envelope'].update(to='foreign'),
                lambda v:v['envelope']['data'].update(sender={'operator': False})):
            value = self.value(command='publish')
            change(value)
            raw = await self.bridge_prepare('send', value=value)
            with self.assertRaises(ContractError):
                await self.resource.legacy(self.service.reader, raw)
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_legacy_message_grants_cannot_replace_native_plugin_admission(self):
        raw = await self.bridge_prepare('send')
        current = strict_loads(self.js.messages[-1].data)
        principal = next(i for i in current['state']['identities'] if i['ref'] == ref('human'))
        principal['kind'] = 'plugin'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.resource.legacy(self.service.reader, raw)
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])

    async def test_approval_after_hard_denial_or_changed_held_payload_refuses(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        value = self.value()
        value['quarantineId'] = ledger.quarantine_add(self.store, value['envelope'], 'am.msg.alice.nick',
            'msg', 'alice', 'trust approve for alice')
        raw = await self.bridge_prepare('approve', value=value)
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        with self.assertRaises(ContractError):
            await self.resource.legacy(self.service.reader, raw)
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        changed = copy.deepcopy(value['envelope'])
        changed['data']['body'] = 'changed held message'
        self.store.db.execute('UPDATE fed_quarantine SET envelope=? WHERE id=?',
            (canonical_bytes(changed).decode(), value['quarantineId']))
        with self.assertRaises(ContractError):
            await self.resource.legacy(self.service.reader, raw)
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])

    async def test_outcome_retention_failure_rolls_back_the_original_delivery(self):
        raw = await self.bridge_prepare('deliver')
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('retention failed')):
            with self.assertRaises(RuntimeError):
                await self.resource.legacy(self.service.reader, raw)
        for table in ('messages', 'deliveries', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])

    async def test_large_original_envelopes_keep_full_content_and_replay(self):
        body = 'Original ' + 'z' * 200000
        value = self.value(command='publish')
        value['envelope']['data']['body'] = body
        raw = await self.bridge_prepare('send', value=value, operation='large-send')
        self.assertGreater(len(raw), 65536)
        sent = await self.resource.legacy(self.service.reader, raw)
        self.assertEqual(sent['result']['id'], value['envelope']['id'])
        self.assertEqual(strict_loads(self.store.q1('SELECT payload FROM fed_outbox')['payload'])['data']['body'], body)
        self.assertEqual(await self.resource.legacy(self.service.reader, raw), sent)
        incoming = self.value()
        incoming['envelope']['data']['body'] = body
        admitted = await self.bridge_prepare('deliver', value=incoming, operation='large-deliver', revision=2)
        received = await self.resource.legacy(self.service.reader, admitted)
        self.assertEqual(await self.resource.legacy(self.service.reader, admitted), received)
        self.assertIn(body, self.store.q1('SELECT body FROM messages')['body'])
        self.assertEqual(len(self.store.q('SELECT * FROM deliveries')), 1)
        records = [strict_loads(r['v']) for r in self.store.q("SELECT v FROM fed_state WHERE k LIKE '%:operation:%'")]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r['formatVersion'] == 2 and 'envelope' not in r for r in records))

    async def test_large_original_retention_failure_rolls_back_publication(self):
        value = self.value(command='publish')
        value['envelope']['data']['body'] = 'z' * 100000
        raw = await self.bridge_prepare('send', value=value)
        original = self.resource._journal._set
        def fail_metadata(key, value, **kwargs):
            if key.startswith('operation:'):
                raise RuntimeError('metadata failed after original')
            return original(key, value, **kwargs)
        with patch.object(self.resource._journal, '_set', side_effect=fail_metadata):
            with self.assertRaises(RuntimeError):
                await self.resource.legacy(self.service.reader, raw)
        for table in ('fed_outbox', 'fed_audit', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])


class MessageBridgeServiceTests(BridgeOwnerFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        patch('capability_owner.message_bridge_service.datetime', _Clock).start()
        self.endpoint = MessageBridgeService(self.service.ingress, resources=(self.resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(self.endpoint.close)
        self.claims['replySubject'] = '_INBOX.legacy_messages_000001'

    def verified(self, response, raw):
        from nacl.signing import SigningKey
        import base64
        return verify_message_bridge_reply(response, raw,
            public_key=base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), now=NOW)

    async def dispatch(self, raw):
        return await self.endpoint.handle(raw, received_reply_subject=self.claims['replySubject'])

    async def test_actual_transport_possession_and_signed_reply_bind_original_request(self):
        await self.bridge_prepare('send')
        raw = self.request()
        response = await self.dispatch(raw)
        result = self.verified(response, raw)
        self.assertEqual(result['outcome'], 'applied')
        self.assertEqual(self.verified(await self.dispatch(raw), raw), result)
        changed = strict_loads(raw)
        changed['claims']['payload']['input']['envelope']['data']['body'] = 'changed request'
        with self.assertRaises(ContractError):
            self.verified(response, canonical_bytes(changed))
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertNotIn('hub-one', repr(self.endpoint))

    def application_key(self):
        import base64
        from identity.application_client import ApplicationClientKey
        from nacl.signing import SigningKey
        public = base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
        selected = {'authenticatedCaller': 'operator', 'subject': self.reply_service.subject,
            'transportRef': ref('transport'), 'grantRefs': self.legacy_grants['human'],
            'resourceRef': ref('task-one'), 'peer': 'alice', 'localPeer': 'nick', 'localNode': 'mac',
            'repository': {'localName': 'falcon', 'repositoryId': self.resource.repository_id},
            'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': public,
            'serviceIdentityRef': ref('service'), 'serviceInstanceId': 'ingress-one'}
        material = {'purpose': 'agentmux-application-client-key-v1',
            'seed': base64.b64encode(bytes(reversed(SEED))).decode(),
            'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
            'instanceId': 'application-one', 'callerRef': ref('human'), 'scope': self.scope,
            'transportRef': ref('application-transport'), 'grantRef': ref('application-grant'),
            'replyIssuerRef': ref('issuer'), 'replyIssuerPublicKey': public,
            'releaseDigest': 'sha256:' + 'a' * 64, 'policyRef': ref('application-policy'),
            'workspaceRef': None, 'messageCommands': selected}
        return ApplicationClientKey(material)

    async def test_protected_application_key_signs_only_its_message_route(self):
        key = self.application_key()
        selected = key.selection['messageCommands']
        await self.bridge_prepare('send')
        raw = key.sign_command(self.claims, subject=key.command_subject('federation-message-send'), now=NOW)
        response = await self.dispatch(raw)
        self.assertEqual(key.verify_command_response(response, raw, subject=selected['subject'], now=NOW)['outcome'], 'applied')
        for mutate in (lambda c:c.update(grantRef=ref('application-grant')),
                lambda c:c['payload']['resourceRef'].update(id='other'),
                lambda c:c['payload']['input'].update(subject='am.msg.nick.foreign'),
                lambda c:c['payload']['input']['envelope'].update(to='foreign')):
            claims = copy.deepcopy(self.claims)
            mutate(claims)
            with self.assertRaises(ContractError):
                key.sign_command(claims, subject=selected['subject'], now=NOW)
        with self.assertRaises(ContractError):
            key.sign_command(self.claims, subject=selected['subject'] + '.other', now=NOW)

    async def test_validity_metadata_is_verified_and_only_available_for_outcomes(self):
        from agentmux_contracts import payload_digest
        key = self.application_key()
        selected = key.selection['messageCommands']
        await self.bridge_prepare('send')
        original_payload = copy.deepcopy(self.claims['payload'])
        raw = key.sign_command(self.claims, subject=selected['subject'], now=NOW)
        response = await self.dispatch(raw)
        original = key.verify_command_response(response, raw, subject=selected['subject'], now=NOW)
        with self.assertRaises(ContractError):
            key.verify_command_response(response, raw, subject=selected['subject'], now=NOW,
                include_valid_until=True)
        with self.assertRaises(ContractError):
            verify_message_bridge_reply(response, raw, public_key=selected['replyIssuerPublicKey'],
                service_identity_ref=selected['serviceIdentityRef'], service_instance_id=selected['serviceInstanceId'],
                signing_key_ref=selected['replyIssuerRef'], now=NOW, include_valid_until=True)
        query = {'contractId': 'federation-message-send', 'operationId': self.claims['operationId'],
            'payloadDigest': payload_digest(original_payload)}
        await self.bridge_prepare('outcome', operation='metadata-query', query=query, revision=2)
        raw = key.sign_command(self.claims, subject=selected['subject'], now=NOW)
        response = await self.dispatch(raw)
        ordinary = key.verify_command_response(response, raw, subject=selected['subject'], now=NOW)
        checked = key.verify_command_response(response, raw, subject=selected['subject'], now=NOW,
            include_valid_until=True)
        self.assertEqual(checked, {'result': ordinary, 'validUntil': strict_loads(response)['claims']['validUntil']})
        self.assertEqual(ordinary['result'], original['result'])
        forged = strict_loads(response)
        forged['claims']['validUntil'] = (NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        with self.assertRaises(ContractError):
            key.verify_command_response(canonical_bytes(forged), raw, subject=selected['subject'], now=NOW,
                include_valid_until=True)
        with self.assertRaises(ContractError):
            key.verify_command_response(response, raw, subject=selected['subject'],
                now=datetime.fromisoformat(checked['validUntil']), include_valid_until=True)

    async def test_lost_reply_retires_original_inbox_then_queries_the_same_committed_operation(self):
        from hub.client_launch_connection import ClientConnectionOwner, MessageOutcomeUnconfirmed
        from hub.client_launch_binding import ClientBindingState
        from agentmux_contracts import payload_digest
        key = self.application_key()
        client = SimpleNamespace(is_connected=True, max_payload=1048576,
            flush=AsyncMock(), close=AsyncMock())
        binding = ClientBindingState(client, public_key=key.selection['replyIssuerPublicKey'],
            signing_key_ref=ref('issuer'), caller_ref=ref('human'), scope=self.scope)
        owner = ClientConnectionOwner(client, binding,
            command_subject='amx.v1.h.hub-one.o.org-one.identity.authority-one.command',
            reply_prefix='_INBOX.message_client_000001', signer=key)
        self.addAsyncCleanup(owner.close, deadline=asyncio.get_running_loop().time() + 10)
        owner._connected = True
        expiry = (NOW + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')
        # Connection admission is controlled here; actual key possession and
        # current owner authorization run through the real enrolled endpoint.
        owner._current_command_binding = AsyncMock(return_value={'validUntil': expiry})
        owner._require_query_binding = Mock(return_value={'validUntil': expiry})
        subscriptions, response = [], {}
        async def subscribe(subject, **_options):
            index = len(subscriptions)
            async def next_message(**_options):
                if index == 0:
                    raise TimeoutError()
                return SimpleNamespace(subject=subject, data=response['raw'])
            subscription = SimpleNamespace(unsubscribe=AsyncMock(), next_msg=next_message)
            subscriptions.append(subscription)
            return subscription
        async def publish(subject, raw, *, reply):
            response['raw'] = await self.endpoint.handle(raw, received_reply_subject=reply)
        client.subscribe, client.publish = subscribe, publish
        await self.bridge_prepare('send')
        payload = copy.deepcopy(self.claims['payload'])
        with patch('hub.client_launch_connection.datetime', _Clock), \
                patch('identity.application_client.datetime', _Clock):
            with self.assertRaises(MessageOutcomeUnconfirmed):
                await owner.message_command(contract_id='federation-message-send', operation_id='lost-message',
                    payload=payload, expires_at=expiry, deadline=asyncio.get_running_loop().time() + 3,
                    cleanup_deadline=asyncio.get_running_loop().time() + 4)
            original = owner.command_request
            self.assertIsNotNone(original)
            self.assertFalse(owner._subscriptions)
            self.assertIsNone(owner._exchange_task)
            client.close.assert_not_awaited()
            subscriptions[0].unsubscribe.assert_awaited_once()
            query = {'resourceRef': {**ref('task-one'), 'revision': 2}, 'input': {
                'contractId': 'federation-message-send', 'operationId': 'lost-message',
                'payloadDigest': payload_digest(payload)}}
            recovered = await owner.message_command(contract_id='federation-message-outcome',
                operation_id='recover-message', payload=query, expires_at=expiry,
                deadline=asyncio.get_running_loop().time() + 3,
                cleanup_deadline=asyncio.get_running_loop().time() + 4)
            metadata = await owner.message_command(contract_id='federation-message-outcome',
                operation_id='recover-message-metadata', payload=query, expires_at=expiry,
                deadline=asyncio.get_running_loop().time() + 3,
                cleanup_deadline=asyncio.get_running_loop().time() + 4, include_valid_until=True)
            self.assertEqual(metadata, {'result': recovered,
                'validUntil': strict_loads(response['raw'])['claims']['validUntil']})
        self.assertEqual(recovered['outcome'], 'applied')
        self.assertEqual(recovered['result']['id'], payload['input']['envelope']['id'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertFalse(owner._subscriptions)
        subscriptions[1].unsubscribe.assert_awaited_once()
        subscriptions[2].unsubscribe.assert_awaited_once()

    async def test_selected_storage_route_dispatches_only_explicit_legacy_protocol(self):
        from .reply_service import CapabilityReplyService
        route = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection,
            message_bridge=self.endpoint)
        self.addAsyncCleanup(route.close)
        await self.bridge_prepare('deliver')
        raw = self.request()
        with self.assertRaises(ContractError):
            await self.reply_service.handle(raw, received_reply_subject=self.claims['replySubject'])
        response = await route.handle(raw, received_reply_subject=self.claims['replySubject'])
        self.assertEqual(self.verified(response, raw)['result']['deliveryOutcome'], 'delivered')
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        await route.close()
        self.assertTrue(self.endpoint._closed)
        self.assertFalse(self.endpoint._workers)
        with self.assertRaises(ContractError):
            await route.handle(raw, received_reply_subject=self.claims['replySubject'])

    async def test_forged_transport_or_reply_route_cannot_commit(self):
        await self.bridge_prepare('deliver')
        raw = self.request()
        changed = strict_loads(raw)
        changed['signature'] = 'A' * 86
        with self.assertRaises(ContractError):
            await self.dispatch(canonical_bytes(changed))
        with self.assertRaises(ContractError):
            await self.endpoint.handle(raw, received_reply_subject='_INBOX.other_messages_000001')
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])

    async def test_large_delivery_uses_same_signed_route_and_compact_receipt(self):
        value = self.value()
        body = 'z' * 999000
        value['envelope']['data']['body'] = body
        self.assertLess(len(canonical_bytes(value['envelope'])), 1000000)
        await self.bridge_prepare('deliver', value=value)
        raw = self.request()
        response = await self.dispatch(raw)
        self.assertLess(len(response), 65536)
        result = self.verified(response, raw)
        self.assertEqual(result['result']['deliveryOutcome'], 'delivered')
        self.assertIn(body, self.store.q1('SELECT body FROM messages')['body'])
        self.assertEqual(self.verified(await self.dispatch(raw), raw), result)

    async def test_revocation_after_commit_withholds_reply_and_keeps_original_outcome(self):
        await self.bridge_prepare('send')
        raw = self.request()
        original = self.resource.legacy
        async def revoke_after_commit(authority, inner):
            result = await original(authority, inner)
            self.claims.update(operationId='revoke-after-message', contractId='identity-revoke',
                grantRef=ref('grant'), expectedVersion=2,
                payload={'authorityId': 'authority-one',
                    'targetRef': self.legacy_grants['human']['federation-message-send']})
            revoked = strict_loads(await self.service.handle(self.request()))
            self.assertEqual(revoked['claims']['receipt']['decision'], 'allowed')
            return result
        with patch.object(self.resource, 'legacy', side_effect=revoke_after_commit):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertTrue(self.store.q('SELECT * FROM fed_state'))

    async def test_cancelled_reply_retains_original_worker_until_close_joins_it(self):
        await self.bridge_prepare('deliver')
        raw = self.request()
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.owner.db
        async def delayed(function, *args, **kwargs):
            if function == self.resource._journal.commit:
                entered.set()
                await release.wait()
            return await original(function, *args, **kwargs)
        self.owner.db = delayed
        request = asyncio.create_task(self.dispatch(raw))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request
            with self.assertRaisesRegex(ContractError, 'legacy_message_cleanup_incomplete'):
                await self.endpoint.close(timeout=.01)
            self.assertTrue(self.endpoint._workers)
        finally:
            release.set()
        await self.endpoint.close()
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
