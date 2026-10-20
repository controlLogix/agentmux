"""Focused checks for the enrolled local browser session foundation."""
import asyncio
import copy
from datetime import timedelta
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_client import provision_application_client, load_application_client
from identity.authority import LedgerAuthorityReader
from identity.local_browser_session import LocalBrowserSession, LocalBrowserRequestProof
from identity import test_application_binding as support
from identity.test_authority import ref, NOW
from identity.transitions import transition
from hub.client_launch_connection import ClientConnectionOwner, ConnectionFailure
from hub.client_launch_binding import ClientBindingState


class LocalBrowserSessionTests(unittest.IsolatedAsyncioTestCase):
    make_provider = support.ApplicationBindingTests.make_provider

    def setUp(self):
        support.ApplicationBindingTests.setUp(self)
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        for item in self.record['state']['memberships']:
            item['scope'] = copy.deepcopy(scope)
        for item in self.record['state']['grants'][1:3]:
            item['scope'] = copy.deepcopy(scope)
        self.observed['scope'] = copy.deepcopy(scope)
        self.js.messages[0].data = canonical_bytes(self.record)
        self.make_provider()

    def key(self):
        if hasattr(self, '_client_key'):
            return self._client_key
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        selection = {key: self.binding[key] for key in ('hubId', 'profileId', 'authorityId',
            'instanceId', 'releaseDigest', 'policyRef', 'workspaceRef', 'grantRef')}
        selection.update(callerRef=ref('human'), transportRef=ref('browser-transport'),
            scope=copy.deepcopy(self.record['state']['grants'][1]['scope']), replyIssuerRef=ref('issuer'),
            replyIssuerPublicKey=self.record['state']['issuers'][0]['publicKey'])
        path = Path(directory.name).resolve() / 'browser.key'
        payload = provision_application_client(path, selection=selection,
            identity=self.record['state']['identities'][0], issued_at='2026-10-09T12:00:00Z',
            expires_at='2026-10-09T12:10:00Z')
        self.record['state'] = transition(self.record['state'], 'identity-enroll', payload, hub_id='hub-one')
        self.js.messages[0].data = canonical_bytes(self.record)
        self.service.replace_application_lease(self.lease)
        self._client_key = load_application_client(path)
        return self._client_key

    def command_key(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        command_grant = copy.deepcopy(self.record['state']['grants'][1])
        command_grant.update(ref=ref('local-browser-open-grant'),
            contractId='local-browser-session-open', resourceId='authority-one')
        self.record['state']['grants'].append(command_grant)
        selection = {key: self.binding[key] for key in ('hubId', 'profileId', 'authorityId',
            'instanceId', 'releaseDigest', 'policyRef', 'workspaceRef', 'grantRef')}
        selection.update(callerRef=ref('human'), transportRef=ref('browser-transport'),
            scope=copy.deepcopy(command_grant['scope']), replyIssuerRef=ref('issuer'),
            replyIssuerPublicKey=self.record['state']['issuers'][0]['publicKey'],
            localBrowserSessionOpen={'subject': self.service.subject,
                'grantRef': command_grant['ref'], 'transportRef': ref('browser-command-transport'),
                'replyIssuerRef': ref('issuer'),
                'replyIssuerPublicKey': self.record['state']['issuers'][0]['publicKey']})
        path = Path(directory.name).resolve() / 'browser-command.key'
        payload = provision_application_client(path, selection=selection,
            identity=self.record['state']['identities'][0], issued_at='2026-10-09T12:00:00Z',
            expires_at='2026-10-09T12:10:00Z')
        self.record['state'] = transition(self.record['state'], 'identity-enroll', payload,
                                           hub_id='hub-one')
        self.js.messages[0].data = canonical_bytes(self.record)
        self.service.replace_application_lease(self.lease)
        return load_application_client(path)

    async def session(self, *, clock=None, exchange=None):
        return await LocalBrowserSession.open(self.key(), self.service.reader,
            exchange or self.service.handle, clock=clock or (lambda: NOW))

    async def test_exact_request_has_one_use_verified_human_project_context(self):
        session = await self.session()
        body = {'name': 'writer', 'scope': 'repo', 'description': 'Review changes'}
        proof = await session.authorize('POST', '/api/board/agentdef', body)
        context = session.consume(proof, 'POST', '/api/board/agentdef', body)
        self.assertEqual(context.caller_ref, ref('human'))
        self.assertEqual(context.scope['projectId'], 'project-one')
        changed_scope = context.scope
        changed_scope['projectId'] = 'forged'
        self.assertEqual(context.scope['projectId'], 'project-one')
        self.assertNotIn('seed', repr(session) + repr(proof) + repr(context))
        with self.assertRaisesRegex(ContractError, 'local_browser_proof_unavailable'):
            session.consume(proof, 'POST', '/api/board/agentdef', body)
        with self.assertRaises(TypeError):
            LocalBrowserRequestProof()

    async def test_changed_request_consumes_proof_and_identity_fields_are_refused(self):
        session = await self.session()
        body = {'name': 'writer', 'scope': 'repo'}
        proof = await session.authorize('POST', '/api/board/agentdrop', body)
        with self.assertRaisesRegex(ContractError, 'local_browser_proof_unavailable'):
            session.consume(proof, 'POST', '/api/board/agentdrop', {**body, 'name': 'other'})
        with self.assertRaisesRegex(ContractError, 'local_browser_proof_unavailable'):
            session.consume(proof, 'POST', '/api/board/agentdrop', body)
        for changed in ({**body, 'actor': 'forged'}, {**body, 'projectId': 'other'},
                        {**body, 'user_id': 'other'}, {**body, 'config': {'identity': 'forged'}}):
            with self.assertRaisesRegex(ContractError, 'local_browser_identity_field_refused'):
                await session.authorize('POST', '/api/board/agentdef', changed)
        with self.assertRaisesRegex(ContractError, 'local_browser_request_unavailable'):
            await session.authorize('GET', '/api/board/agents', body)

    async def _changed_authority_refuses(self, change, error):
        session = await self.session()
        change(self.record['state'])
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, error):
            await session.authorize('POST', '/api/board/agentdef',
                {'name': 'writer', 'scope': 'repo'})

    async def test_current_grant_revocation_refuses(self):
        await self._changed_authority_refuses(
            lambda state: state['grants'][1].update(status='revoked'),
            'application_permission_unavailable')

    async def test_current_membership_revocation_refuses(self):
        await self._changed_authority_refuses(
            lambda state: state['memberships'][0].update(status='revoked'),
            'application_permission_unavailable')

    async def test_current_non_human_identity_refuses(self):
        await self._changed_authority_refuses(
            lambda state: state['identities'][0].update(kind='service'),
            'local_browser_human_unavailable')

    async def test_current_hard_denial_refuses(self):
        session = await self.session()
        denied = copy.deepcopy(self.record['state']['grants'][1])
        denied.update(ref=ref('deny-browser'), decision='denied')
        self.record['state']['grants'].append(denied)
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await session.authorize('POST', '/api/board/agentdef',
                {'name': 'writer', 'scope': 'repo'})

    async def test_expiry_runtime_end_and_close_invalidate_session(self):
        session = await self.session()
        body = {'name': 'writer', 'scope': 'repo'}
        proof = await session.authorize('POST', '/api/board/agentdrop', body)
        session.close()
        with self.assertRaisesRegex(ContractError, 'local_browser_proof_unavailable'):
            session.consume(proof, 'POST', '/api/board/agentdrop', body)
        with self.assertRaisesRegex(ContractError, 'local_browser_session_closed'):
            await session.authorize('POST', '/api/board/agentdrop', body)
        current = [NOW]
        expired = await self.session(clock=lambda: current[0])
        current[0] = NOW + timedelta(minutes=15)
        with self.assertRaisesRegex(ContractError, 'local_browser_session_expired'):
            await expired.authorize('POST', '/api/board/agentdrop', body)
        ended = await self.session()
        self.done.set()
        with self.assertRaisesRegex(ContractError, 'application_lifetime_ended'):
            await ended.authorize('POST', '/api/board/agentdrop', body)

    async def test_delayed_exchange_and_authority_cannot_mint_late_proof(self):
        current = [NOW]

        async def delayed_exchange(request):
            response = await self.service.handle(request)
            purpose = strict_loads(request)['claims']['purpose']
            if purpose == 'agentmux-application-binding-request-v1':
                current[0] = NOW + timedelta(seconds=5)
            return response

        session = await self.session(clock=lambda: current[0], exchange=delayed_exchange)
        with self.assertRaisesRegex(ContractError, 'application_observation_expired'):
            await session.authorize('POST', '/api/board/agentdef',
                {'name': 'writer', 'scope': 'repo'})

        current[0] = NOW
        shared = self.service.reader
        reader = LedgerAuthorityReader(shared._ledger, hub_id=shared._hub,
            entity_id=shared._entity, profile_id=shared._profile,
            organization_id=shared._organization)
        session = await LocalBrowserSession.open(self.key(), reader, self.service.handle,
            clock=lambda: current[0])
        original = session._authority.current

        async def delayed_authority():
            snapshot = await original()
            current[0] = NOW + timedelta(seconds=5)
            return snapshot

        session._authority.current = delayed_authority
        with self.assertRaisesRegex(ContractError, 'local_browser_binding_expired'):
            await session.authorize('POST', '/api/board/agentdef',
                {'name': 'writer', 'scope': 'repo'})

    async def test_exchange_latency_is_subtracted_from_proof_lifetime(self):
        monotonic = [100.0]

        async def latent_exchange(request):
            response = await self.service.handle(request)
            if strict_loads(request)['claims']['purpose'] == 'agentmux-application-binding-request-v1':
                monotonic[0] += 6
            return response

        with patch('identity.local_browser_session.time.monotonic',
                   side_effect=lambda: monotonic[0]):
            session = await self.session(exchange=latent_exchange)
            body = {'name': 'writer', 'scope': 'repo'}
            proof = await session.authorize('POST', '/api/board/agentdef', body)
            with self.assertRaisesRegex(ContractError, 'local_browser_proof_unavailable'):
                session.consume(proof, 'POST', '/api/board/agentdef', body)

    async def test_pending_limit_and_close_during_exchange_fail_closed(self):
        gate, full = asyncio.Event(), asyncio.Event()
        blocked = 0

        async def held_exchange(request):
            nonlocal blocked
            purpose = strict_loads(request)['claims']['purpose']
            if purpose == 'agentmux-application-binding-request-v1':
                blocked += 1
                if blocked == 32:
                    full.set()
                await gate.wait()
            return await self.service.handle(request)

        session = await self.session(exchange=held_exchange)
        body = {'name': 'writer', 'scope': 'repo'}
        pending = [asyncio.create_task(
            session.authorize('POST', '/api/board/agentdef', body)) for _ in range(32)]
        await asyncio.wait_for(full.wait(), timeout=1)
        with self.assertRaisesRegex(ContractError, 'local_browser_session_busy'):
            await session.authorize('POST', '/api/board/agentdef', body)
        session.close()
        gate.set()
        results = await asyncio.gather(*pending, return_exceptions=True)
        self.assertTrue(all(isinstance(item, ContractError)
            and 'local_browser_session_closed' in str(item) for item in results))
        self.assertEqual(session._pending, 0)
        self.assertEqual(len(session._proofs), 0)

    async def test_connection_owner_supplies_binding_reply_prefix_and_deadlines(self):
        direct = await self.session()
        owner = object.__new__(ClientConnectionOwner)
        owner.authenticate = AsyncMock(return_value=copy.deepcopy(direct._binding))
        with self.assertRaisesRegex(ContractError, 'local_browser_connection_owner_required'):
            await LocalBrowserSession.open(self.key(), self.service.reader, owner.exchange,
                clock=lambda: NOW)
        session = await LocalBrowserSession.open_connection_owner(self.key(),
            self.service.reader, owner, clock=lambda: NOW)
        body = {'name': 'writer', 'scope': 'repo'}
        proof = await session.authorize('POST', '/api/board/agentdef', body)
        with self.assertRaisesRegex(ContractError, 'local_browser_session_busy'):
            await session.authorize('POST', '/api/board/agentdef', body)
        context = session.consume(proof, 'POST', '/api/board/agentdef', body)
        self.assertEqual(context.scope['projectId'], 'project-one')
        self.assertEqual(owner.authenticate.await_count, 2)
        for call in owner.authenticate.await_args_list:
            self.assertIs(call.args[0], self.key())
            self.assertAlmostEqual(call.kwargs['cleanup_deadline'] - call.kwargs['deadline'], 5)

    async def test_real_connection_owner_composes_prefix_binding_and_one_proof(self):
        key = self.key()
        selected = key.selection
        client = SimpleNamespace(is_connected=False)
        client.requests, client.reply_subjects, client.subscriptions = [], [], []

        async def connect(**_options):
            client.is_connected = True

        async def close():
            client.is_connected = False

        async def publish(subject, raw, *, reply):
            expected = (f"amx.v1.h.{selected['hubId']}.o.{selected['scope']['organizationId']}"
                        f".identity.{selected['authorityId']}.command")
            self.assertEqual(subject, expected)
            self.assertEqual(reply, client.reply_subjects[-1])
            client.requests.append(raw)

        async def subscribe(subject, **_options):
            client.reply_subjects.append(subject)

            async def next_msg(**_):
                response = await self.service.handle(client.requests[-1])
                return SimpleNamespace(subject=subject, data=response)

            subscription = SimpleNamespace(next_msg=AsyncMock(side_effect=next_msg),
                unsubscribe=AsyncMock())
            client.subscriptions.append(subscription)
            return subscription

        client.connect = AsyncMock(side_effect=connect)
        client.close = AsyncMock(side_effect=close)
        client.publish = AsyncMock(side_effect=publish)
        client.subscribe = AsyncMock(side_effect=subscribe)
        client.flush = AsyncMock()
        binding = ClientBindingState(client, public_key=selected['replyIssuerPublicKey'],
            signing_key_ref=selected['replyIssuerRef'], caller_ref=selected['callerRef'],
            scope=selected['scope'])
        command = (f"amx.v1.h.{selected['hubId']}.o.{selected['scope']['organizationId']}"
                   f".identity.{selected['authorityId']}.command")
        prefix = '_INBOX.local_browser_0001'
        owner = ClientConnectionOwner(client, binding, command_subject=command,
            reply_prefix=prefix, signer=key)
        loop = asyncio.get_running_loop()
        await owner._connect({}, deadline=loop.time() + 2, cleanup_deadline=loop.time() + 3)
        session = None
        try:
            with patch('hub.client_launch_connection.datetime', support.test_service._Clock), \
                    patch('identity.application_client.datetime', support.test_service._Clock):
                session = await LocalBrowserSession.open_connection_owner(key,
                    self.service.reader, owner, clock=lambda: NOW)
                body = {'name': 'writer', 'scope': 'repo'}
                proof = await session.authorize('POST', '/api/board/agentdef', body)
                context = session.consume(proof, 'POST', '/api/board/agentdef', body)
                self.assertEqual(context.scope['projectId'], 'project-one')
                self.assertIs(owner.require_connection(), client)
                self.assertEqual(owner.binding.current(client, now=NOW)['callerRef'], ref('human'))
            claims = [strict_loads(raw)['claims'] for raw in client.requests]
            self.assertEqual([item['purpose'] for item in claims], [
                'agentmux-application-discovery-request-v1',
                'agentmux-application-binding-request-v1',
                'agentmux-application-discovery-request-v1',
                'agentmux-application-binding-request-v1'])
            self.assertEqual(len(set(client.reply_subjects)), 4)
            self.assertTrue(all(subject.startswith(prefix + '.')
                for subject in client.reply_subjects))
            self.assertTrue(all(subscription.unsubscribe.await_count == 1
                for subscription in client.subscriptions))
            self.assertFalse(owner._subscriptions)
        finally:
            if session is not None:
                session.close()
            await owner.close(deadline=loop.time() + 2)
        client.connect.assert_awaited_once()
        client.close.assert_awaited_once()

    async def test_fixed_owner_command_creates_private_server_session_and_signed_approval(self):
        from application_service_host import ApplicationServiceHost
        key = self.command_key()
        selected = key.selection
        captured = []
        final_entered, final_release = asyncio.Event(), asyncio.Event()
        host = object.__new__(ApplicationServiceHost)
        host._closed = False
        host._connection_failure = None
        host._loop = asyncio.get_running_loop()
        host._browser_origin = 'http://127.0.0.1:8787'
        async def approve(challenge, session, authority, *, origin=None):
            captured.append((challenge, session, authority, origin))
            context = await session.verify_identity()
            if challenge == '3456-789A-BCDE-FGHJ-KMNP':
                final_entered.set()
                await final_release.wait()
            await authority.recheck(context)
        host.approve_local_browser = approve
        self.service.configure_local_browser_host(host)
        client = SimpleNamespace(is_connected=False)
        client.requests = []
        async def connect(**_): client.is_connected = True
        async def close(): client.is_connected = False
        async def publish(_subject, raw, *, reply): client.requests.append((raw, reply))
        async def subscribe(subject, **_):
            async def next_msg(**_):
                raw, reply = client.requests[-1]
                return SimpleNamespace(subject=reply, data=await self.service.handle(raw))
            return SimpleNamespace(next_msg=AsyncMock(side_effect=next_msg), unsubscribe=AsyncMock())
        client.connect, client.close = AsyncMock(side_effect=connect), AsyncMock(side_effect=close)
        client.publish, client.subscribe = AsyncMock(side_effect=publish), AsyncMock(side_effect=subscribe)
        client.flush = AsyncMock()
        binding = ClientBindingState(client, public_key=selected['replyIssuerPublicKey'],
            signing_key_ref=selected['replyIssuerRef'], caller_ref=selected['callerRef'],
            scope=selected['scope'])
        owner = ClientConnectionOwner(client, binding, command_subject=self.service.subject,
            reply_prefix='_INBOX.local_browser_0002', signer=key)
        loop = asyncio.get_running_loop()
        await owner._connect({}, deadline=loop.time() + 2, cleanup_deadline=loop.time() + 3)
        try:
            with patch('hub.client_launch_connection.datetime', support.test_service._Clock), \
                    patch('identity.application_client.datetime', support.test_service._Clock), \
                    patch('identity.application_binding.datetime', support.test_service._Clock), \
                    patch('identity.local_browser_session.datetime', support.test_service._Clock), \
                    patch('identity.service.datetime', support.test_service._Clock):
                await owner.authenticate(key, deadline=loop.time() + 2,
                                         cleanup_deadline=loop.time() + 3)
                result = await owner.local_browser_session_open(
                    challenge='2345-6789-ABCD-EFGH-JKMP', origin='http://127.0.0.1:8787',
                    operation_id='browser-open-one', deadline=loop.time() + 2,
                    cleanup_deadline=loop.time() + 3)
            self.assertEqual(result['outcome'], 'approved')
            self.assertEqual(result['callerRef'], ref('human'))
            self.assertEqual(result['scope']['projectId'], 'project-one')
            self.assertEqual(len(captured), 1)
            challenge, session, _authority, origin = captured[0]
            self.assertEqual((challenge, origin),
                ('2345-6789-ABCD-EFGH-JKMP', 'http://127.0.0.1:8787'))
            with patch('identity.application_binding.datetime', support.test_service._Clock), \
                    patch('identity.local_browser_session.datetime', support.test_service._Clock):
                context = await session.verify_identity()
            self.assertEqual(context.caller_ref, ref('human'))
            self.assertNotIn('2345-6789', repr(result) + repr(session))
            session.close()

            with patch('hub.client_launch_connection.datetime', support.test_service._Clock), \
                    patch('identity.application_client.datetime', support.test_service._Clock), \
                    patch('identity.application_binding.datetime', support.test_service._Clock), \
                    patch('identity.local_browser_session.datetime', support.test_service._Clock), \
                    patch('identity.service.datetime', support.test_service._Clock):
                refused = asyncio.create_task(owner.local_browser_session_open(
                    challenge='3456-789A-BCDE-FGHJ-KMNP', origin='http://127.0.0.1:8787',
                    operation_id='browser-open-revoked', deadline=loop.time() + 2,
                    cleanup_deadline=loop.time() + 3))
                await asyncio.wait_for(final_entered.wait(), 1)
                grant_ref = key.selection['localBrowserSessionOpen']['grantRef']
                grant = next(item for item in self.record['state']['grants']
                             if item['ref'] == grant_ref)
                grant['status'] = 'revoked'
                self.js.messages[0].data = canonical_bytes(self.record)
                final_release.set()
                with self.assertRaisesRegex(ConnectionFailure, 'application_command_unconfirmed'):
                    await refused
            self.assertEqual(len(captured), 2)
        finally:
            await owner.close(deadline=loop.time() + 2)


if __name__ == '__main__':
    unittest.main()
