"""Actual session, connection owner, signer and receiver over an offline transport."""
import asyncio
from datetime import datetime, timezone
import io
import json
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner
from hub.client_launch_coordinator import result
from hub.client_launch_session import ApplicationClientSession
from hub.fed import mcp
from agentmux_contracts import canonical_bytes, payload_digest, sign_claims
from identity import test_application_client_command as command_support
from identity.test_authority import SEED, ref


class QueryComposition(unittest.TestCase):
    def test_mcp_uses_actual_owner_method_and_verifies_actual_receiver_receipt(self):
        state = {}
        async def open_client(*_args, **_kwargs):
            # Build the existing authority/SQLite fixture on the session's own
            # event loop and thread. Only network I/O is replaced below.
            fixture = command_support.ClientCommandTests('test_selected_query_signs_and_verifies_actual_receiver_receipt')
            fixture.setUp()
            await fixture.asyncSetUp()
            state['fixture'] = fixture
            key, _ = await fixture.enrolled_query()
            selected = key.selection
            client = SimpleNamespace(is_connected=True, connect=AsyncMock(), flush=AsyncMock())
            async def close():
                client.is_connected = False
                await fixture.service.close()
                fixture.tmp.cleanup()
            client.close = close
            binding = ClientBindingState(client, public_key=selected['replyIssuerPublicKey'],
                signing_key_ref=selected['replyIssuerRef'], caller_ref=selected['callerRef'], scope=selected['scope'])
            identity_subject = (f"amx.v1.h.{selected['hubId']}.o.{selected['scope']['organizationId']}"
                                f".identity.{selected['authorityId']}.command")
            owner = ClientConnectionOwner(client, binding, command_subject=identity_subject,
                reply_prefix='_INBOX.abcdefghijklmnop', signer=key)
            state.update(owner=owner, key=key)
            loop = asyncio.get_running_loop()
            await owner._connect({}, deadline=loop.time() + 4, cleanup_deadline=loop.time() + 5)
            claims = owner._claims(selected, 'agentmux-application-binding-request-v1', loop.time() + 4)
            claims.update(generation=1, lifetimeId='a' * 64)
            request = key.sign_binding(claims)
            response_claims = {k: v for k, v in claims.items() if k not in ('purpose', 'replySubject', 'expiresAt')}
            response_claims.update(purpose='agentmux-application-binding-response-v1', requestDigest=payload_digest(claims),
                callerRef=selected['callerRef'], scope=selected['scope'], signingKeyRef=selected['replyIssuerRef'],
                authorityRef=ref('authority-one'), authoritySequence=1, validUntil=claims['expiresAt'])
            response = canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
                'canonicalization': 'RFC8785-JCS-UTF8', 'claims': response_claims,
                'signature': sign_claims(response_claims, SEED)})
            binding.accept(client, binding.begin(client, request), response,
                           now=datetime.now(timezone.utc))
            pending = {}
            async def publish(subject, raw, *, reply):
                self.assertEqual(subject, key.command_subject('integration-effect-query'))
                pending['response'] = await fixture.service.handle(raw)
                pending['reply'] = reply
            async def subscribe(subject, **kwargs):
                async def next_msg(**_):
                    return SimpleNamespace(subject=pending['reply'], data=pending['response'])
                subscription = SimpleNamespace(unsubscribe=AsyncMock(), next_msg=next_msg)
                owner.own_subscription(subscription)
                return subscription
            client.publish, client.subscribe = publish, subscribe
            return owner

        session = ApplicationClientSession(SimpleNamespace(
            application_client='/private/client', application_connection='/private/connection'))
        try:
            with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
                session.start(deadline=time.monotonic() + 5)
            self.assertTrue(session.query_enabled())
            request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
                'name': 'agentmux_integration_effect_query',
                'arguments': {'operationId': 'query-one', 'expectedVersion': 1}}}
            output = io.StringIO()
            with patch.object(mcp.cli, 'call') as legacy:
                mcp.main(io.StringIO(json.dumps(request) + '\n'), output,
                         startup_result=result('ensure', 'observed'), application_session=session)
            legacy.assert_not_called()
            receipt = json.loads(output.getvalue())['result']
            self.assertFalse(receipt['isError'])
            self.assertEqual(receipt['structuredContent']['phase'], 'intent-committed')
            self.assertEqual(receipt['structuredContent']['operationId'], 'query-one')
            self.assertEqual(len(state['fixture'].js.messages), 1)
            self.assertIsNone(state['fixture'].owner._worker)
            self.assertIsNotNone(state['owner'].command_request)
        finally:
            session.join_final()
        self.assertFalse(session._thread.is_alive())
