"""One live code-share refresh supplies two separate, fixed-expiry proofs."""
import asyncio
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from hub.store import HubError
from hub.tests import test_authenticated_caller as support


class CodeShareProofTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        support.AuthenticatedCallerTests.setUp(self)
        self.request = {'token': 'operator-secret', 'verb': 'fed_code_share',
            'args': {'repo': 'falcon', 'to': 'peer:alice/falcon/worker'}}
        self.reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(self.request).encode()),
            at_eof=Mock(return_value=False))
        self.writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(),
            is_closing=Mock(return_value=False))

    async def dispatch(self, callback):
        async def call(verb, args, caller):
            self.assertEqual((verb, caller), ('fed_code_share', 'operator'))
            await callback()
            return {'completed': True}
        self.hub.dispatch = call
        with patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as authentication:
            await self.hub.handle_conn(self.reader, self.writer, tcp=True)
            self.assertEqual(authentication.call_count, 2)
        self.assertTrue(json.loads(self.writer.write.call_args.args[0])['ok'])
        self.assertFalse(self.hub._authenticated_callers)
        self.assertFalse(self.hub._code_share_invocations)

    async def test_two_purposes_share_one_authentication_and_expiry(self):
        async def call():
            storage = await self.hub.code_share_caller('storage')
            with self.assertRaises(HubError):
                self.hub._consume_authenticated_caller(storage)
            with self.assertRaises(HubError):
                self.hub._consume_authenticated_caller(storage, purpose='handoff')
            first = self.hub._consume_authenticated_caller(storage, purpose='storage')
            with self.assertRaises(HubError):
                self.hub._consume_authenticated_caller(storage, purpose='storage')
            handoff = await self.hub.reauthenticate_code_share_caller()
            second = self.hub._consume_authenticated_caller(handoff, purpose='handoff')
            self.assertIs(first, second)
            self.assertNotIn(b'operator-secret', first.request)
            for purpose in ('storage', 'handoff'):
                with self.assertRaises(HubError):
                    await self.hub.code_share_caller(purpose)
        await self.dispatch(call)

    async def test_proof_cannot_be_consumed_by_a_borrowed_task(self):
        async def call():
            storage = await self.hub.code_share_caller('storage')
            async def borrowed():
                with self.assertRaises(HubError):
                    self.hub._consume_authenticated_caller(storage, purpose='storage')
            await asyncio.create_task(borrowed())
            self.hub._consume_authenticated_caller(storage, purpose='storage')
        await self.dispatch(call)

    async def test_slow_storage_cannot_extend_handoff_expiry(self):
        async def call():
            storage = await self.hub.code_share_caller('storage')
            admitted = self.hub._consume_authenticated_caller(storage, purpose='storage')
            with patch('hub.server.time.monotonic', return_value=admitted.expires_monotonic):
                with self.assertRaises(HubError):
                    await self.hub.reauthenticate_code_share_caller()
                with self.assertRaises(HubError):
                    await self.hub.code_share_caller('storage')
        await self.dispatch(call)

    async def test_reserved_proof_refuses_changed_request_and_closed_connection(self):
        async def call():
            storage = await self.hub.code_share_caller('storage')
            self.hub._consume_authenticated_caller(storage, purpose='storage')
            invocation = self.hub._current_code_share_invocation()
            invocation.dispatched_request['args']['repo'] = 'other'
            with self.assertRaises(HubError):
                await self.hub.reauthenticate_code_share_caller()
            invocation.dispatched_request['args']['repo'] = 'falcon'
            handoff = await self.hub.reauthenticate_code_share_caller()
            self.writer.is_closing.return_value = True
            with self.assertRaises(HubError):
                self.hub._consume_authenticated_caller(handoff, purpose='handoff')
        await self.dispatch(call)

    async def test_cancellation_disposes_both_purposes_and_private_request(self):
        entered = asyncio.Event()
        retained = []
        async def call(verb, args, caller):
            await self.hub.code_share_caller('storage')
            retained.append(self.hub._current_code_share_invocation())
            entered.set()
            await asyncio.Event().wait()
        self.hub.dispatch = call
        task = asyncio.create_task(self.hub.handle_conn(self.reader, self.writer, tcp=True))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.hub._authenticated_callers)
        self.assertFalse(self.hub._code_share_invocations)
        self.assertEqual(retained[0].request, b'')
        self.assertIsNone(retained[0].reader)
        self.assertIsNone(retained[0].writer)
        self.assertFalse(retained[0].proofs)
        self.assertFalse(retained[0].purpose_proofs)


if __name__ == '__main__':
    unittest.main()
