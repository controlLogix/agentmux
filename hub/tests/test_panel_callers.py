"""Actual local Hub dispatch with private, domain-bound panel caller proofs.

Owner clients below are controlled local consumers, not broker qualification.
"""
import asyncio
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from hub.store import HubError
from hub.fed import runtime
from hub.tests import test_authenticated_caller as caller_support


class PanelCallerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        caller_support.AuthenticatedCallerTests.setUp(self)

    async def dispatch(self, callback, *, verb='fed_panel'):
        request = {'token': 'operator-secret', 'verb': verb, 'args': {}}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        self.hub.dispatch = callback
        with patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as authenticate:
            await self.hub.handle_conn(reader, writer, tcp=True)
        self.assertFalse(self.hub._authenticated_callers)
        self.assertIsNone(self.hub._authenticated_caller_context.get())
        return json.loads(writer.write.call_args.args[0]), authenticate.await_count

    async def test_one_authentication_original_request_and_expiry_for_all_domains(self):
        async def callback(verb, args, caller):
            original = self.hub.current_authenticated_caller()
            admitted = self.hub._authenticated_callers[original]
            with self.hub._panel_callers(caller) as proofs:
                self.assertEqual(set(proofs), {'knowledge', 'code', 'work'})
                self.assertEqual(len(set(proofs.values())), 3)
                for domain in ('knowledge', 'code', 'work'):
                    child = self.hub._consume_authenticated_caller(proofs[domain], purpose='panel-' + domain)
                    self.assertEqual(child.request, admitted.request)
                    self.assertEqual(child.request_digest, admitted.request_digest)
                    self.assertEqual(child.expires_monotonic, admitted.expires_monotonic)
                    self.assertEqual((child.authenticated_caller, child.caller), ('operator', caller))
                    self.assertNotIn(b'operator-secret', child.request)
                with self.assertRaises(HubError):
                    self.hub._consume_authenticated_caller(original)
            self.assertIs(self.hub._authenticated_caller_context.get(), original)
            return {'accepted': True}
        response, count = await self.dispatch(callback)
        self.assertTrue(response['ok'], response)
        self.assertEqual(count, 1)

    async def test_swapped_missing_and_reused_purposes_refuse(self):
        async def callback(verb, args, caller):
            with self.hub._panel_callers(caller) as proofs:
                for domain, wrong in (('knowledge', 'panel-code'), ('code', 'panel-knowledge'),
                        ('work', 'panel-code')):
                    with self.assertRaises(HubError):
                        self.hub._consume_authenticated_caller(proofs[domain], purpose=wrong)
                    with self.assertRaises(HubError):
                        self.hub._consume_authenticated_caller(proofs[domain])
                    self.hub._consume_authenticated_caller(proofs[domain], purpose='panel-' + domain)
                    with self.assertRaises(HubError):
                        self.hub._consume_authenticated_caller(proofs[domain], purpose='panel-' + domain)
            with self.assertRaises(HubError):
                with self.hub._panel_callers(caller):
                    self.fail('consumed original split twice')
            return {}
        response, count = await self.dispatch(callback)
        self.assertTrue(response['ok'], response)
        self.assertEqual(count, 1)

    async def test_foreign_task_cannot_split_original_or_consume_children(self):
        async def callback(verb, args, caller):
            async def split():
                with self.assertRaises(HubError):
                    with self.hub._panel_callers(caller):
                        self.fail('foreign task split the original')
            await asyncio.create_task(split())
            with self.hub._panel_callers(caller) as proofs:
                async def consume():
                    for domain, proof in proofs.items():
                        with self.assertRaises(HubError):
                            self.hub._consume_authenticated_caller(proof, purpose='panel-' + domain)
                await asyncio.create_task(consume())
                for domain, proof in proofs.items():
                    self.hub._consume_authenticated_caller(proof, purpose='panel-' + domain)
            return {}
        response, _ = await self.dispatch(callback)
        self.assertTrue(response['ok'], response)

    async def test_foreign_task_cannot_consume_initial_panel_proof(self):
        async def callback(verb, args, caller):
            original = self.hub.current_authenticated_caller()
            async def consume():
                with self.assertRaises(HubError):
                    self.hub._consume_authenticated_caller(original)
            await asyncio.create_task(consume())
            with self.hub._panel_callers(caller) as proofs:
                self.hub._consume_authenticated_caller(proofs['code'], purpose='panel-code')
            return {}
        response, _ = await self.dispatch(callback)
        self.assertTrue(response['ok'], response)

    async def test_expired_original_and_child_cannot_gain_time(self):
        async def callback(verb, args, caller):
            original = self.hub.current_authenticated_caller()
            expires = self.hub._authenticated_callers[original].expires_monotonic
            with self.hub._panel_callers(caller) as proofs:
                for proof in proofs.values():
                    self.assertEqual(self.hub._authenticated_callers[proof].expires_monotonic, expires)
                with patch('hub.server.time.monotonic', return_value=expires):
                    for domain, proof in proofs.items():
                        with self.assertRaises(HubError):
                            self.hub._consume_authenticated_caller(proof, purpose='panel-' + domain)
            return {}
        response, count = await self.dispatch(callback)
        self.assertTrue(response['ok'], response)
        self.assertEqual(count, 1)

    async def test_expired_original_cannot_mint_children(self):
        async def callback(verb, args, caller):
            original = self.hub.current_authenticated_caller()
            expires = self.hub._authenticated_callers[original].expires_monotonic
            with patch('hub.server.time.monotonic', return_value=expires):
                with self.assertRaises(HubError):
                    with self.hub._panel_callers(caller):
                        self.fail('expired original minted child proofs')
            return {}
        response, count = await self.dispatch(callback)
        self.assertTrue(response['ok'], response)
        self.assertEqual(count, 1)

    async def test_wrong_caller_non_panel_and_direct_proof_cannot_split(self):
        async def wrong_caller(verb, args, caller):
            with self.assertRaises(HubError):
                with self.hub._panel_callers('other'):
                    self.fail('wrong caller split')
            return {}
        response, _ = await self.dispatch(wrong_caller)
        self.assertTrue(response['ok'], response)
        async def wrong_verb(verb, args, caller):
            with self.assertRaises(HubError):
                with self.hub._panel_callers(caller):
                    self.fail('non-panel request split')
            return {}
        response, _ = await self.dispatch(wrong_verb, verb='ping')
        self.assertTrue(response['ok'], response)
        proof = await self.hub.authenticate_caller(
            {'token': 'operator-secret', 'verb': 'fed_panel', 'args': {}}, self.writer, True)
        token = self.hub._authenticated_caller_context.set(proof)
        try:
            with self.assertRaises(HubError):
                with self.hub._panel_callers('operator'):
                    self.fail('proof outside actual dispatch split')
        finally:
            self.hub._authenticated_caller_context.reset(token)
            self.hub._authenticated_callers.pop(proof, None)

    async def test_storage_proof_cannot_serve_panel(self):
        async def callback(verb, args, caller):
            proof = await self.hub.code_share_caller('storage')
            with self.assertRaises(HubError):
                self.hub._consume_authenticated_caller(proof, purpose='panel-code')
            with self.assertRaises(HubError):
                with self.hub._panel_callers(caller):
                    self.fail('storage request split for panel')
            self.hub._consume_authenticated_caller(proof, purpose='storage')
            return {}
        response, _ = await self.dispatch(callback, verb='fed_code_share')
        self.assertTrue(response['ok'], response)

    async def test_exception_disposes_all_children_and_restores_context(self):
        retained = []
        async def callback(verb, args, caller):
            original = self.hub.current_authenticated_caller()
            try:
                with self.hub._panel_callers(caller) as proofs:
                    retained.extend(proofs.values())
                    raise HubError('controlled panel failure')
            finally:
                self.assertIs(self.hub._authenticated_caller_context.get(), original)
                self.assertTrue(all(proof not in self.hub._authenticated_callers for proof in retained))
        response, count = await self.dispatch(callback)
        self.assertFalse(response['ok'])
        self.assertEqual(count, 1)
        for proof in retained:
            with self.assertRaises(HubError):
                self.hub._consume_authenticated_caller(proof, purpose='panel-code')

    async def test_cancellation_disposes_children_before_dispatch_finishes(self):
        entered, waiting = asyncio.Event(), asyncio.Event()
        retained = []
        async def callback(verb, args, caller):
            original = self.hub.current_authenticated_caller()
            try:
                with self.hub._panel_callers(caller) as proofs:
                    retained.extend(proofs.values())
                    entered.set()
                    await waiting.wait()
            finally:
                self.assertIs(self.hub._authenticated_caller_context.get(), original)
        task = asyncio.create_task(self.dispatch(callback))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.hub._authenticated_callers)
        for proof in retained:
            with self.assertRaises(HubError):
                self.hub._consume_authenticated_caller(proof, purpose='panel-knowledge')

    async def test_actual_runtime_panel_aggregates_two_separate_consumers(self):
        seen = {}
        async def read(domain, caller, command, args):
            self.assertEqual((command, args), ('panel', {}))
            proof = self.hub.current_authenticated_caller()
            seen[domain] = self.hub._consume_authenticated_caller(proof, purpose='panel-' + domain)
            return {'title': domain.title(), 'rows': [[domain]]}
        async def knowledge(caller, command, args):
            return await read('knowledge', caller, command, args)
        async def code(caller, command, args):
            return await read('code', caller, command, args)
        async def db(fn):
            return fn()
        adapters = {name: SimpleNamespace(name=name, panel=Mock(return_value={'title': name.title()}))
            for name in ('knowledge', 'code', 'other')}
        confirm_code = Mock()
        fed = SimpleNamespace(hub=self.hub, connected=False, _qualified_knowledge=True, _qualified_code=True,
            _knowledge_commands=SimpleNamespace(read=knowledge),
            _code_commands=SimpleNamespace(read=code, confirm_panel_disclosure=confirm_code),
            plugin_adapters=adapters, db=db)
        async def callback(verb, args, caller):
            return await runtime._v_panel(fed, args, caller)
        with patch.object(runtime, '_v_status', AsyncMock(return_value={'connected': False})), \
                patch.object(runtime, '_v_quarantine', AsyncMock(return_value=[])), \
                patch.object(runtime, '_v_audit', AsyncMock(return_value=[])):
            response, count = await self.dispatch(callback)
        self.assertTrue(response['ok'], response)
        self.assertEqual(count, 1)
        self.assertEqual(set(seen), {'knowledge', 'code'})
        self.assertEqual(seen['knowledge'].request, seen['code'].request)
        self.assertEqual(seen['knowledge'].expires_monotonic, seen['code'].expires_monotonic)
        panels = {panel['plugin']: panel for panel in response['result']['panels']}
        self.assertEqual(panels['knowledge']['rows'], [['knowledge']])
        self.assertEqual(panels['code']['rows'], [['code']])
        self.assertIn('other', panels)
        confirm_code.assert_called_once_with()
        adapters['knowledge'].panel.assert_not_called()
        adapters['code'].panel.assert_not_called()
