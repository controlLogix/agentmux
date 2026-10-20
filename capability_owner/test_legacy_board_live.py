"""Legacy board commands on the existing coordinated native TLS/JWT fixture.

Run the three named legacy tests only after the coordinator grants the live slot.
Collection opens no broker. Inherited publisher tests remain separately selectable.
"""
import asyncio
import base64
import copy
from contextvars import ContextVar
import hashlib
import json
import os
from types import SimpleNamespace
import weakref
from unittest.mock import AsyncMock, Mock, patch

from nacl.signing import SigningKey
from agentmux_contracts import strict_loads
from hub.server import Hub
from hub.fed.board_services import build_board_context
from hub.fed.plugins.board import Board
from hub.fed.session import FederationSession
from identity.legacy_board_ingress import LegacyBoardIngress, LegacyBoardCallerEnrollment, LegacyBoardRoute
from identity.test_authority import ref, SEED
from . import test_board_live as fixture
from .legacy_board_service import LegacyBoardCommandClient, LegacyBoardCommandService


class LiveLegacyBoardTests(fixture.LiveBoardPublisherTests):
    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies,reads)
        self.legacy_subject='amx.v1.h.hub-one.o.org-one.p.project-one.w._.board.owner.command'
        policies['host']['publish']['allow'].append(self.legacy_subject)
        policies['storage']['subscribe']['allow'].append(self.legacy_subject)

    def initial_authority(self):
        initial=super().initial_authority()
        issuer=copy.deepcopy(initial['state']['issuers'][0])
        issuer.update(ref=ref('legacy-board-signer'),identityRef=ref('board-owner'),instanceId='board-command-one',
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(fixture.OWNER_SEED).verify_key)).decode().rstrip('='))
        initial['state']['issuers'].append(issuer)
        return initial

    async def legacy_setup(self):
        self.endpoint=LegacyBoardCommandService(self.identity.reader,
            routes=(self.route,self.card_owner._allocation_gate),connection=self.storage,
            service_identity_ref=ref('board-owner'),service_instance_id='board-command-one',
            signing_key_ref=ref('legacy-board-signer'),signing_seed=fixture.OWNER_SEED)
        self.responders.append(self.endpoint)
        await self.endpoint.start()
        self.hub=object.__new__(Hub)
        self.hub._authenticated_callers=weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context=ContextVar('live_legacy_board_proof',default=None)
        self.hub.operator_sha=hashlib.sha256(b'operator-secret').hexdigest()
        self.hub.peer=Mock(return_value=(1,os.getuid()))
        self.hub.db=AsyncMock(return_value=(None,False))
        routes=(LegacyBoardRoute('falcon','SH-1',ref('task-one'),ref('federation-board-command'),self.scope,
                    ref('capability-outcome-query')),
                LegacyBoardRoute('falcon',None,ref('prefix-one'),ref('allocation-command'),self.scope,ref('allocation-query')))
        enrollment=LegacyBoardCallerEnrollment('operator','profile-one','hub-one','authority-one',ref('human'),
            ref('transport'),bytes(reversed(SEED)),routes)
        self.bridge=LegacyBoardIngress(self.hub,self.identity.ingress,enrollment)
        self.saved=[]
        async def save(raw):self.saved.append(raw)
        self.client_options=dict(ingresses=(self.bridge,),lifetime=FederationSession(),
            service_identity_ref=ref('board-owner'),service_instance_id='board-command-one',
            signing_key_ref=ref('legacy-board-signer'),retain_recovery=save)
        self.client=LegacyBoardCommandClient(self.hub,self.host,**self.client_options)
        self.addAsyncCleanup(self.client.close)
        self.consumer=copy.copy(self.domain)
        self.consumer.hub,self.consumer.session=self.hub,FederationSession()
        self.consumer._qualified_board=True
        self.consumer._board_commands=self.client
        self.consumer.kv=AsyncMock(side_effect=AssertionError('qualified writer cannot use direct KV'))
        async def dispatch(verb,args,caller):
            return await getattr(Board(),'v_'+verb.removeprefix('fed_board_'))(build_board_context(self.consumer),args,caller)
        self.hub.dispatch=dispatch

    async def legacy_invoke(self, command, args):
        reader=SimpleNamespace(readline=AsyncMock(return_value=json.dumps({'verb':'fed_board_'+command,'args':args}).encode()))
        writer=SimpleNamespace(get_extra_info=lambda key:object(),write=Mock(),drain=AsyncMock(),close=Mock())
        await self.hub.handle_conn(reader,writer)
        return json.loads(writer.write.call_args.args[0])

    async def test_tls_legacy_all_five_commands_preserve_results_and_join_subscription(self):
        await self.legacy_setup()
        for command,args in (('comment',{'key':'SH-1','text':'Live original é'}),
                ('move',{'key':'SH-1','status':'review'}),('assign',{'key':'SH-1','to':'peer:nick'}),
                ('claim',{'key':'SH-1'}),('add',{'title':'Live allocation'})):
            result=await self.legacy_invoke(command,{'repo':'falcon',**args})
            self.assertTrue(result['ok'],result)
            value=result['result']
            entry=await self.kv.get(self.rid+'.card.'+value['key'])
            self.assertEqual(value['rev'],entry.revision)
            self.assertNotIn('_agentmuxOperation',value)
            self.assertNotIn('receiptRef',value)
            if command!='add':
                self.assertEqual(value['attempts'],1)
                self.assertEqual(value['unknownFutureField'],self.initial_card['unknownFutureField'])
            else:self.assertEqual(value['key'],'SH-2')
        self.assertEqual(len(self.saved),5)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')),5)
        self.consumer.kv.assert_not_awaited()
        callback=self.endpoint._subscription._wait_for_msgs_task
        await self.client.close()
        await self.endpoint.close()
        self.assertTrue(callback.done())
        self.assertNotIn(self.endpoint._subscription._id,self.storage._subs)
        self.assertTrue(self.storage.is_connected)
        self.success=True

    async def test_tls_legacy_lost_reply_restores_original_after_later_write(self):
        await self.legacy_setup()
        args={'repo':'falcon','key':'SH-1','text':'Original é'}
        publish=self.storage.publish
        async def lost(subject,data,*rest,**kwargs):
            if subject.startswith(self.inbox_prefixes['host']+'.') and strict_loads(data).get('claims',{}).get(
                    'purpose')=='agentmux-legacy-board-response-v1':
                return
            return await publish(subject,data,*rest,**kwargs)
        with patch.object(self.storage,'publish',side_effect=lost):
            self.assertFalse((await self.legacy_invoke('comment',args))['ok'])
        recovery=self.client.pending_recovery()[0].recovery_bytes()
        original=await self.kv.get(self.rid+'.card.SH-1')
        self.assertTrue((await self.legacy_invoke('move',{'repo':'falcon','key':'SH-1','status':'done'}))['ok'])
        later=await self.kv.get(self.rid+'.card.SH-1')
        await self.client.close()
        self.client=LegacyBoardCommandClient(self.hub,self.host,**self.client_options)
        self.addAsyncCleanup(self.client.close)
        self.client.restore_recovery(recovery)
        self.consumer._board_commands=self.client
        recovered=await self.legacy_invoke('comment',args)
        self.assertTrue(recovered['ok'],recovered)
        self.assertEqual(recovered['result']['rev'],original.revision)
        self.assertEqual(recovered['result']['status'],'todo')
        self.assertEqual(recovered['result']['attempts'],1)
        self.assertEqual([c['text'] for c in recovered['result']['comments']],['Original é'])
        self.assertEqual((await self.kv.get(self.rid+'.card.SH-1')).revision,later.revision)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')),2)
        self.success=True

    async def test_tls_legacy_denied_raw_write_and_stopped_route_do_not_fall_back(self):
        await self.legacy_setup()
        await self.denied_publish('host','$KV.am_board.'+self.rid+'.card.SH-1')
        self.assertEqual((await self.kv.get(self.rid+'.card.SH-1')).revision,self.card_revision)
        self.hub.db.return_value=('unenrolled',True)
        self.assertFalse((await self.legacy_invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        self.hub.db.return_value=(None,False)
        await self.card_publisher.close()
        self.assertFalse((await self.legacy_invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        self.assertEqual((await self.kv.get(self.rid+'.card.SH-1')).revision,self.card_revision)
        self.consumer.kv.assert_not_awaited()
        self.assertEqual(self.store.q('SELECT * FROM fed_audit'),[])
        self.success=True
