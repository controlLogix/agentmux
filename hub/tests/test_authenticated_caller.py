"""Existing Hub authentication issues private, request-bound, single-use proofs."""
import hashlib
import os
import weakref
from types import SimpleNamespace
from contextvars import ContextVar
import unittest
from unittest.mock import AsyncMock, Mock, patch

from hub.server import Hub, AuthenticatedLocalCaller, CallerClassificationUnavailable
from hub.store import HubError


class AuthenticatedCallerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hub=object.__new__(Hub)
        self.hub._authenticated_callers=weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context=ContextVar('test_hub_caller',default=None)
        self.hub.operator_sha=hashlib.sha256(b'operator-secret').hexdigest()
        self.hub.store=SimpleNamespace(q1=Mock())
        self.hub.db=AsyncMock(return_value=None)
        self.hub.peer=Mock(return_value=(123,os.getuid()))
        self.writer=SimpleNamespace(get_extra_info=lambda key:object())

    async def test_operator_attribution_does_not_change_authenticated_identity(self):
        self.hub.db.return_value=(None,False)
        req={'verb':'fed_board_dispatch','args':{'task':'one'},'as':'worker'}
        proof=await self.hub.authenticate_caller(req,self.writer,False)
        req['args']['task']='changed'
        actual=self.hub._consume_authenticated_caller(proof)
        self.assertEqual((actual.authenticated_caller,actual.caller,actual.requested_attribution),
                         ('operator','worker','worker'))
        self.assertIn(b'"task":"one"',actual.request)
        self.assertNotIn('worker',repr(proof))
        with self.assertRaises(HubError):self.hub._consume_authenticated_caller(proof)
        self.assertEqual(await self.hub.caller_of(req,self.writer,False),'worker')

    async def test_tcp_tokens_preserve_authenticated_actor_and_ignore_attribution(self):
        req={'verb':'ping','token':'operator-secret','as':'worker'}
        proof=await self.hub.authenticate_caller(req,self.writer,True)
        actual=self.hub._consume_authenticated_caller(proof)
        self.assertEqual((actual.authenticated_caller,actual.caller),('operator','operator'))
        self.assertEqual(actual.requested_attribution,'worker')
        self.assertNotIn(b'operator-secret',actual.request)
        self.assertEqual(actual.request_digest,hashlib.sha256(actual.request).hexdigest())
        self.hub.db.return_value={'session':'agent-session'}
        self.assertEqual(await self.hub.caller_of({'token':'agent-secret'},self.writer,True),'agent-session')
        self.hub.db.return_value=None
        with self.assertRaises(HubError):await self.hub.authenticate_caller({'token':'revoked'},self.writer,True)

    async def test_kernel_uid_and_agent_attribution_rules_remain(self):
        self.hub.peer.return_value=(123,os.getuid()+1)
        with self.assertRaises(HubError):await self.hub.authenticate_caller({},self.writer,False)
        self.hub.peer.return_value=(123,os.getuid())
        self.hub.db.return_value=('agent',True)
        with self.assertRaises(HubError):await self.hub.authenticate_caller({'as':'operator'},self.writer,False)
        self.assertEqual(await self.hub.caller_of({},self.writer,False),'agent')
        self.hub.db.return_value=(None,True)
        self.assertEqual(await self.hub.caller_of({},self.writer,False),'unregistered')

    async def test_only_work_verbs_get_the_longer_work_window(self):
        from identity.work_client import WORK_COMMAND_SECONDS
        lifetimes={}
        for verb in ('work_cancel','work_add','status','spawn','kill','ping','adopt','fed_kill','fed_board_dispatch'):
            with patch('hub.server.time.monotonic',return_value=1000.0):
                proof=await self.hub.authenticate_caller({'verb':verb,'token':'operator-secret'},self.writer,True)
            lifetimes[verb]=self.hub._authenticated_callers[proof].expires_monotonic-1000.0
        self.assertEqual(lifetimes,{'work_cancel':WORK_COMMAND_SECONDS,'work_add':WORK_COMMAND_SECONDS,
            'status':WORK_COMMAND_SECONDS,'spawn':WORK_COMMAND_SECONDS,'kill':WORK_COMMAND_SECONDS,
            'ping':5,'adopt':5,'fed_kill':5,'fed_board_dispatch':5})
        # The selected core's envelope still caps the longer window.
        self.hub._selected_core_context=lambda:SimpleNamespace(expires_monotonic=1007.0)
        with patch('hub.server.time.monotonic',return_value=1000.0):
            proof=await self.hub.authenticate_caller({'verb':'kill','token':'operator-secret'},self.writer,True)
        self.assertEqual(self.hub._authenticated_callers[proof].expires_monotonic,1007.0)

    async def test_wrong_hub_forged_and_expired_proofs_refuse(self):
        proof=await self.hub.authenticate_caller({'token':'operator-secret'},self.writer,True)
        other=object.__new__(Hub);other._authenticated_callers=weakref.WeakKeyDictionary()
        with self.assertRaises(HubError):other._consume_authenticated_caller(proof)
        with self.assertRaises(HubError):self.hub._consume_authenticated_caller(object.__new__(AuthenticatedLocalCaller))
        with self.assertRaises(TypeError):AuthenticatedLocalCaller()
        with patch('hub.server.time.monotonic',return_value=10**20):
            with self.assertRaises(HubError):self.hub._consume_authenticated_caller(proof)
        with self.assertRaises(HubError):self.hub._consume_authenticated_caller(proof)

    async def test_actual_connection_dispatch_exposes_only_its_current_proof(self):
        import json
        reader=SimpleNamespace(readline=AsyncMock(return_value=json.dumps(
            {'token':'operator-secret','verb':'fed_board_claim','args':{'key':'SH-1'}}).encode()))
        writer=SimpleNamespace(write=Mock(),drain=AsyncMock(),close=Mock())
        seen=[]
        async def dispatch(verb,args,caller):
            proof=self.hub.current_authenticated_caller();seen.append(proof)
            admitted=self.hub._consume_authenticated_caller(proof)
            self.assertEqual(admitted.authenticated_caller,caller)
            self.assertEqual(verb,'fed_board_claim')
            return {'accepted':True}
        self.hub.dispatch=dispatch
        await self.hub.handle_conn(reader,writer,tcp=True)
        self.assertTrue(json.loads(writer.write.call_args.args[0])['ok'])
        with self.assertRaises(HubError):self.hub.current_authenticated_caller()
        with self.assertRaises(HubError):self.hub._consume_authenticated_caller(seen[0])

    async def test_unknown_unix_classification_refuses_proof_but_keeps_legacy_caller(self):
        import subprocess
        self.hub.store.agents=lambda **kwargs:[]
        self.hub.tp=SimpleNamespace(socket='test-socket')
        async def db(fn,*args):return fn(*args)
        self.hub.db=db
        with patch('hub.server.os.path.isdir',return_value=False),patch('hub.server.subprocess.run',
                return_value=SimpleNamespace(returncode=1,stdout='1\n')):
            with self.assertRaises(CallerClassificationUnavailable):
                await self.hub.authenticate_caller({},self.writer,False)
        with patch('hub.server.parent_pid',return_value=None), patch('hub.server.subprocess.run',
                return_value=SimpleNamespace(returncode=1,stdout='')):
            with self.assertRaises(CallerClassificationUnavailable):
                await self.hub.authenticate_caller({},self.writer,False)
            self.assertEqual(await self.hub.caller_of({},self.writer,False),'operator')
        for result in (SimpleNamespace(returncode=1,stdout=''),
                       SimpleNamespace(returncode=0,stdout='invalid')):
            with patch('hub.server.parent_pid',return_value=1),patch('hub.server.subprocess.run',return_value=result):
                with self.assertRaises(CallerClassificationUnavailable):
                    await self.hub.authenticate_caller({},self.writer,False)
        with patch('hub.server.parent_pid',return_value=1),patch('hub.server.subprocess.run',
                side_effect=subprocess.TimeoutExpired('tmux',5)):
            with self.assertRaises(CallerClassificationUnavailable):
                await self.hub.authenticate_caller({},self.writer,False)
        with patch('hub.server.parent_pid',return_value=1),patch('hub.server.subprocess.run',
                return_value=SimpleNamespace(returncode=0,stdout='456\n')):
            proof=await self.hub.authenticate_caller({},self.writer,False)
            self.assertEqual(self.hub._consume_authenticated_caller(proof).authenticated_caller,'operator')

    async def test_unknown_connection_never_exposes_a_qualified_proof(self):
        import json
        self.hub.store.agents=lambda **kwargs:[]
        self.hub.tp=SimpleNamespace(socket='test-socket')
        async def db(fn,*args):return fn(*args)
        self.hub.db=db
        reader=SimpleNamespace(readline=AsyncMock(return_value=b'{"verb":"ping"}'))
        writer=SimpleNamespace(get_extra_info=lambda key:object(),write=Mock(),drain=AsyncMock(),close=Mock())
        async def dispatch(verb,args,caller):
            self.assertEqual(caller,'operator')
            with self.assertRaises(HubError):self.hub.current_authenticated_caller()
            return {'legacy':True}
        self.hub.dispatch=dispatch
        with patch('hub.server.parent_pid',return_value=None),patch('hub.server.subprocess.run',
                return_value=SimpleNamespace(returncode=1,stdout='')):
            await self.hub.handle_conn(reader,writer)
        self.assertTrue(json.loads(writer.write.call_args.args[0])['ok'])
