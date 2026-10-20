"""Actual Hub, ingress, publishers and owners with controlled broker I/O."""
import asyncio
import base64
import copy
import hashlib
import json
import os
import secrets
import unittest
import weakref
from contextvars import ContextVar
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from nacl.signing import SigningKey
from hub.server import Hub
from hub.store import HubError
from hub.fed.board_services import build_board_context, SharedBoardStore
from hub.fed.plugins.board import Board
from hub.fed.session import FederationSession
from identity.legacy_board_ingress import LegacyBoardIngress, LegacyBoardCallerEnrollment, LegacyBoardRoute
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from . import test_board_storage_route as route_tests
from .test_board_allocation_owner import BoardBroker
from .legacy_board_service import LegacyBoardCommandClient, LegacyBoardCommandService, LegacyBoardRecovery


class LegacyBoardRoutingTests(unittest.IsolatedAsyncioTestCase):
    open=route_tests.BoardStorageRouteTests.open
    admit=route_tests.BoardStorageRouteTests.admit
    set_row=route_tests.BoardStorageRouteTests.set_row
    install_board=route_tests.BoardStorageRouteTests.install_board
    wrapper=route_tests.BoardStorageRouteTests.wrapper
    bridge_request=route_tests.BoardStorageRouteTests.bridge_request
    install_prefix_gate=route_tests.BoardStorageRouteTests.install_prefix_gate
    responder=route_tests.BoardStorageRouteTests.responder

    def setUp(self):
        route_tests.BoardStorageRouteTests.setUp(self)
        for module in ('capability_owner.legacy_board_service','identity.legacy_board_ingress',
                       'capability_owner.board_allocation_owner','capability_owner.board_allocation_journal'):
            patch(module+'.datetime',_Clock).start()

    async def asyncSetUp(self):
        await route_tests.BoardStorageRouteTests.asyncSetUp(self)
        self.broker=BoardBroker(self.prefix_data,self.resource.repository_id)
        self.broker.entries[self.broker.counter].seq=6
        self.broker.entries[self.broker.counter].data=b'1'
        subject='$KV.am_board.'+self.entry.key
        self.broker.entries[subject]=SimpleNamespace(subject=subject,seq=7,data=self.entry.value,headers=None)
        card_info=self.publisher.jetstream.stream_info
        async def info(stream):
            return await (self.broker.stream_info(stream) if stream=='KV_am_board' else card_info(stream))
        self.publisher.jetstream.stream_info=info
        self.prefix_publisher.jetstream.stream_info=self.broker.stream_info
        self.prefix_publisher.jetstream.get_msg=self.broker.get_msg
        self.prefix_publisher.jetstream.publish=self.broker.publish
        async def get(key):
            entry=await self.broker.get_msg('KV_am_board',subject='$KV.am_board.'+key,direct=False)
            return SimpleNamespace(bucket='am_board',key=key,value=entry.data,revision=entry.seq)
        async def update(key,value,last):
            ack=await self.broker.publish('$KV.am_board.'+key,value,headers={
                'Nats-Expected-Stream':'KV_am_board','Nats-Expected-Last-Subject-Sequence':str(last)})
            return ack.seq
        self.kv.get.side_effect=get
        self.kv.update.side_effect=update
        self.record=strict_loads(self.js.messages[-1].data)
        state=self.record['state']
        issuer=copy.deepcopy(state['issuers'][0])
        issuer.update(ref=ref('board-response-signer'),identityRef=ref('board-owner'),instanceId='board-command-one',
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(route_tests.owner_tests.journal_tests.OWNER_SEED).verify_key)).decode().rstrip('='))
        state['issuers'].append(issuer)
        query=copy.deepcopy(next(g for g in state['grants'] if g['ref']==ref('capability-outcome-query')))
        query.update(ref=ref('allocation-query'),resourceId='prefix-one')
        state['grants'].append(query)
        self.js.messages[-1].data=canonical_bytes(self.record)
        self.endpoint=LegacyBoardCommandService(self.service.reader,routes=(self.route,self.prefix_route),
            connection=self.receiving_connection,service_identity_ref=ref('board-owner'),
            service_instance_id='board-command-one',signing_key_ref=ref('board-response-signer'),
            signing_seed=route_tests.owner_tests.journal_tests.OWNER_SEED)
        self.addAsyncCleanup(self.endpoint.close)
        self.hub=object.__new__(Hub)
        self.hub._authenticated_callers=weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context=ContextVar('legacy_board_proof',default=None)
        self.hub.operator_sha=hashlib.sha256(b'operator-secret').hexdigest()
        self.hub.peer=Mock(return_value=(1,os.getuid()))
        self.hub.db=AsyncMock(return_value=(None,False))
        routes=(LegacyBoardRoute('falcon','SH-1',self.target,ref('federation-board-command'),self.scope,
                    ref('capability-outcome-query')),
                LegacyBoardRoute('falcon',None,ref('prefix-one'),ref('allocation-command'),self.scope,ref('allocation-query')))
        enrollment=LegacyBoardCallerEnrollment('operator','profile-one','hub-one','authority-one',ref('human'),
            ref('transport'),bytes(reversed(SEED)),routes)
        self.bridge=LegacyBoardIngress(self.hub,self.service.ingress,enrollment)
        self.frames,self.saved=[],[]
        self.mailboxes={}
        self.lose_reply=False
        async def subscribe(subject):
            queue=asyncio.Queue()
            self.mailboxes[subject]=queue
            async def next_msg(*,timeout):
                return await asyncio.wait_for(queue.get(),timeout)
            async def unsubscribe():self.mailboxes.pop(subject,None)
            return SimpleNamespace(next_msg=next_msg,unsubscribe=unsubscribe)
        async def publish(subject,data,*,reply):
            self.assertEqual(subject,self.endpoint.subject)
            self.frames.append(data)
            response=await self.endpoint.handle(data,received_reply_subject=reply)
            if self.lose_reply:
                self.lose_reply=False
                raise TimeoutError('PRIVATE reply lost')
            await self.mailboxes[reply].put(SimpleNamespace(data=response))
        self.wire=SimpleNamespace(is_connected=True,new_inbox=lambda:'_INBOX.'+secrets.token_hex(16),
            subscribe=subscribe,publish=publish,flush=AsyncMock())
        async def subscribe_owned(owner,subject):
            return owner.own_subscription(await self.wire.subscribe(subject))
        self.wire.subscribe_owned=subscribe_owned
        async def save(raw):self.saved.append(raw)
        self.client_options=dict(ingresses=(self.bridge,),lifetime=FederationSession(),
            service_identity_ref=ref('board-owner'),service_instance_id='board-command-one',
            signing_key_ref=ref('board-response-signer'),retain_recovery=save)
        self.client=LegacyBoardCommandClient(self.hub,self.wire,**self.client_options)
        self.addAsyncCleanup(self.client.close)
        self.federation=copy.copy(self.legacy.owner)
        self.federation.hub=self.hub
        self.federation._qualified_board=True
        self.federation._board_commands=self.client
        self.federation.kv=AsyncMock(side_effect=AssertionError('qualified caller cannot access KV'))
        async def dispatch(verb,args,caller):
            return await getattr(Board(),'v_'+verb.removeprefix('fed_board_'))(build_board_context(self.federation),args,caller)
        self.hub.dispatch=dispatch

    async def invoke(self, command, args, *, attribution=None):
        request={'verb':'fed_board_'+command,'args':args}
        if attribution is not None:request['as']=attribution
        reader=SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()))
        writer=SimpleNamespace(get_extra_info=lambda key:object(),write=Mock(),drain=AsyncMock(),close=Mock())
        await self.hub.handle_conn(reader,writer)
        return json.loads(writer.write.call_args.args[0])

    async def test_all_five_legacy_commands_use_publisher_owners_and_preserve_results(self):
        cases=(('comment',{'key':'SH-1','text':'one'}),('move',{'key':'SH-1','status':'review'}),
               ('assign',{'key':'SH-1','to':'peer:nick'}),('claim',{'key':'SH-1'}),
               ('add',{'title':'New','labels':['one']}))
        for command,args in cases:
            with self.subTest(command=command):
                result=await self.invoke(command,{'repo':'falcon',**args})
                self.assertTrue(result['ok'],result)
                self.assertNotIn('_agentmuxOperation',result['result'])
                self.assertNotIn('receiptRef',result['result'])
                if command!='add':
                    self.assertEqual(result['result']['attempts'],1)
                    self.assertEqual(result['result']['unknownFutureField'],self.card['unknownFutureField'])
                else:self.assertEqual(result['result']['key'],'SH-2')
        self.federation.kv.assert_not_awaited()
        self.assertEqual(len(self.frames),5)
        self.assertEqual(len(self.saved),5)
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),5)

    async def test_lost_reply_restores_original_snapshot_and_recovers_after_later_write(self):
        args={'repo':'falcon','key':'SH-1','text':'Original é'}
        self.lose_reply=True
        self.assertFalse((await self.invoke('comment',args))['ok'])
        recovery=self.client.pending_recovery()[0]
        first_card=strict_loads(self.broker.entries['$KV.am_board.'+self.entry.key].data)
        first_revision=self.broker.sequence
        self.assertTrue((await self.invoke('move',{'repo':'falcon','key':'SH-1','status':'done'}))['ok'])
        await self.client.close()
        self.client=LegacyBoardCommandClient(self.hub,self.wire,**self.client_options)
        self.addAsyncCleanup(self.client.close)
        self.client.restore_recovery(LegacyBoardRecovery.from_bytes(recovery.recovery_bytes()))
        self.federation._board_commands=self.client
        before=len(self.broker.calls)
        result=await self.invoke('comment',args)
        self.assertTrue(result['ok'],result)
        expected={k:v for k,v in first_card.items() if k not in ('_agentmuxOperation','_agentmuxRecoveryFence')}
        self.assertEqual(result['result'],{**expected,'rev':first_revision,'attempts':1})
        self.assertEqual(len(self.broker.calls),before)
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),2)
        self.assertEqual(self.client.pending_recovery(),())

    async def test_qualified_missing_stale_and_closed_routes_never_fall_back(self):
        for change in ('missing','session','closed'):
            with self.subTest(change=change):
                if change=='missing':self.federation._board_commands=None
                elif change=='session':
                    self.federation._board_commands=self.client
                    self.client.check(self.federation)
                    self.federation.session=FederationSession()
                else:await self.client.close()
                self.assertFalse((await self.invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        self.assertEqual(self.broker.calls,[])
        self.assertEqual(self.frames,[])
        self.federation.kv.assert_not_awaited()
        self.federation._qualified_board=False
        self.assertIsInstance(build_board_context(self.federation).board,SharedBoardStore)

    async def test_changed_caller_command_or_route_refuses_before_publication(self):
        self.hub.db.return_value=('unregistered',True)
        self.assertFalse((await self.invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        self.hub.db.return_value=(None,False)
        self.assertFalse((await self.invoke('claim',{'repo':'other','key':'SH-1'}))['ok'])
        actual=self.hub.dispatch
        async def changed(verb,args,caller):return await actual(verb,{**args,'key':'OTHER'},caller)
        self.hub.dispatch=changed
        self.assertFalse((await self.invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        self.assertEqual(self.frames,[])
        self.assertEqual(self.broker.calls,[])

    async def test_oversized_legacy_reply_refuses_before_claim_or_business_effect(self):
        entry=self.broker.entries['$KV.am_board.'+self.entry.key]
        card=strict_loads(entry.data);card['padding']='x'*24000
        entry.data=json.dumps(card).encode()
        result=await self.invoke('claim',{'repo':'falcon','key':'SH-1'})
        self.assertFalse(result['ok'])
        self.assertEqual(self.journal._read(await self.journal._ledger.current()),{})
        self.assertEqual(self.broker.calls,[])

    async def test_current_original_grant_denial_prevents_recovery_disclosure(self):
        args={'repo':'falcon','key':'SH-1','text':'one'}
        self.lose_reply=True
        self.assertFalse((await self.invoke('comment',args))['ok'])
        grant=next(g for g in self.record['state']['grants'] if g['ref']==ref('federation-board-command'))
        grant['decision']='denied'
        self.js.messages[-1].data=canonical_bytes(self.record)
        before=len(self.frames)
        self.assertFalse((await self.invoke('comment',args))['ok'])
        self.assertEqual(len(self.frames),before)
        self.assertEqual(len(self.broker.calls),1)
        self.assertEqual(len(self.client.pending_recovery()),1)

    async def test_delivery_reply_substitution_and_stopped_publisher_refuse(self):
        self.assertTrue((await self.invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        packet=strict_loads(self.frames[0])
        packet['claims']['replySubject']='_INBOX.different_reply_0001'
        with self.assertRaisesRegex(ContractError,'legacy_board_service_unavailable'):
            await self.endpoint.handle(canonical_bytes(packet),received_reply_subject=packet['claims']['replySubject'])
        await self.publisher.close()
        self.assertFalse((await self.invoke('move',{'repo':'falcon','key':'SH-1','status':'done'}))['ok'])
        self.assertEqual(len(self.broker.calls),1)

    async def test_cancelled_reply_and_cleanup_keep_original_worker_until_joined(self):
        started,release=asyncio.Event(),asyncio.Event()
        async def block(*args):
            started.set()
            await release.wait()
        self.broker.before_publish=block
        task=asyncio.create_task(self.invoke('claim',{'repo':'falcon','key':'SH-1'}))
        try:
            await asyncio.wait_for(started.wait(),3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
            with self.assertRaisesRegex(ContractError,'legacy_board_cleanup_incomplete'):
                await self.endpoint.close(timeout=.001)
            self.assertTrue(self.publisher_connection.is_connected)
            self.assertTrue(self.endpoint._workers)
        finally:
            release.set()
        await self.endpoint.close()
        self.assertFalse(self.endpoint._workers)
        self.assertEqual(len(self.broker.calls),1)
        self.assertEqual(len(self.client.pending_recovery()),1)

    async def test_concurrent_same_request_retains_one_operation_before_sending(self):
        admitted_ready,release=asyncio.Event(),asyncio.Event()
        actual=self.bridge.admit_local
        async def blocked(*args,**kwargs):
            admitted=await actual(*args,**kwargs)
            admitted_ready.set()
            await release.wait()
            return admitted
        args={'repo':'falcon','key':'SH-1','text':'one original'}
        with patch.object(self.bridge,'admit_local',side_effect=blocked):
            first=asyncio.create_task(self.invoke('comment',args))
            await asyncio.wait_for(admitted_ready.wait(),3)
            second=asyncio.create_task(self.invoke('comment',args))
            try:
                async with asyncio.timeout(3):
                    while len(self.client._workers)<2:await asyncio.sleep(0)
            finally:release.set()
            results=await asyncio.gather(first,second)
        self.assertTrue(results[0]['ok'],results[0])
        contracts=[strict_loads(base64.b64decode(strict_loads(raw)['claims']['envelopeBytes']))['contractId']
            for raw in self.frames]
        self.assertEqual(contracts,['federation-board-command','capability-outcome-query'])
        self.assertEqual(len(self.broker.calls),1)
        self.assertEqual(len(self.saved),1)

    async def test_recovery_save_failure_cannot_publish_or_leak_private_error(self):
        async def failed(_raw):raise RuntimeError('PRIVATE snapshot path and value')
        self.client._retain_recovery=failed
        result=await self.invoke('claim',{'repo':'falcon','key':'SH-1'})
        self.assertFalse(result['ok'])
        self.assertNotIn('PRIVATE',result['error'])
        self.assertEqual(self.frames,[])
        self.assertEqual(self.broker.calls,[])
        self.assertEqual(len(self.client.pending_recovery()),1)

    async def test_cancelled_subscription_acquisition_is_joined_before_client_close(self):
        started,release=asyncio.Event(),asyncio.Event()
        original=self.wire.subscribe
        async def blocked(subject):
            subscription=await original(subject)
            started.set()
            await release.wait()
            return subscription
        self.wire.subscribe=blocked
        task=asyncio.create_task(self.invoke('claim',{'repo':'falcon','key':'SH-1'}))
        try:
            await asyncio.wait_for(started.wait(),3)
            task.cancel()
            with self.assertRaisesRegex(HubError,'cleanup is incomplete'):
                await self.client.close(timeout=.001)
            self.assertTrue(self.mailboxes)
            self.assertEqual(self.frames,[])
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):await task
        await self.client.close()
        self.assertFalse(self.mailboxes)
        self.assertFalse(self.client._reply_sessions)
        self.assertTrue(self.wire.is_connected)

    async def test_service_rechecks_deadline_after_authority_read(self):
        from datetime import timedelta
        from identity.test_authority import NOW
        self.assertTrue((await self.invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        packet=strict_loads(self.frames[0])
        with patch('capability_owner.legacy_board_service.datetime') as clock:
            clock.now.side_effect=[NOW,NOW+timedelta(seconds=6)]
            with self.assertRaisesRegex(ContractError,'legacy_board_delivery_refused'):
                await self.endpoint._admit(self.frames[0],packet['claims']['replySubject'])
        self.assertEqual(len(self.broker.calls),1)

    async def test_client_rechecks_session_after_final_authority_read(self):
        original_publish=self.wire.publish
        current=self.service.reader.current
        async def changed():
            result=await current()
            self.federation.session=FederationSession()
            return result
        async def publish(*args,**kwargs):
            await original_publish(*args,**kwargs)
            self.service.reader.current=changed
        self.wire.publish=publish
        try:
            result=await self.invoke('claim',{'repo':'falcon','key':'SH-1'})
        finally:self.service.reader.current=current
        self.assertFalse(result['ok'])
        self.assertEqual(len(self.broker.calls),1)
        self.assertEqual(len(self.client.pending_recovery()),1)

    async def test_client_rechecks_reply_expiry_after_final_authority_read(self):
        from datetime import timedelta
        from identity.test_authority import NOW
        original_publish=self.wire.publish
        current=self.service.reader.current
        clock=Mock()
        clock.now.return_value=NOW
        async def expired():
            result=await current()
            clock.now.return_value=NOW+timedelta(seconds=6)
            return result
        async def publish(*args,**kwargs):
            await original_publish(*args,**kwargs)
            self.service.reader.current=expired
        self.wire.publish=publish
        try:
            with patch('capability_owner.legacy_board_service.datetime',clock):
                result=await self.invoke('claim',{'repo':'falcon','key':'SH-1'})
        finally:self.service.reader.current=current
        self.assertFalse(result['ok'])
        self.assertEqual(len(self.broker.calls),1)
        self.assertEqual(len(self.client.pending_recovery()),1)

    async def test_failed_drain_joins_callback_even_when_subscription_is_marked_closed(self):
        started,release,joined=asyncio.Event(),asyncio.Event(),asyncio.Event()
        async def callback():
            started.set()
            try:await asyncio.Event().wait()
            finally:
                await release.wait()
                joined.set()
        worker=asyncio.create_task(callback())
        await started.wait()
        subscription=SimpleNamespace(_closed=False,_wait_for_msgs_task=worker)
        async def drain():
            subscription._closed=True
            raise RuntimeError('PRIVATE drain failed')
        subscription.drain=drain
        self.endpoint._subscription=subscription
        try:
            with self.assertRaisesRegex(ContractError,'legacy_board_cleanup_incomplete'):
                await self.endpoint.close(timeout=.001)
            self.assertFalse(worker.done())
        finally:release.set()
        await asyncio.gather(self.endpoint._closing,return_exceptions=True)
        await self.endpoint.close()
        self.assertTrue(joined.is_set())
        self.assertTrue(worker.done())

    async def test_delayed_recovery_cannot_remove_or_replace_a_new_original(self):
        ready=[asyncio.Event() for _ in range(3)]
        release=[asyncio.Event() for _ in range(3)]
        sent=[]
        async def send(bridge,inner):
            number=len(sent)
            sent.append(strict_loads(inner))
            ready[number].set()
            await release[number].wait()
            if number==2:raise TimeoutError('PRIVATE third reply lost')
            return {'key':'SH-1','rid':'falcon','rev':21,'attempts':1}
        self.client._send=send
        args={'repo':'falcon','key':'SH-1','text':'same request'}
        tasks=[]
        try:
            tasks.append(asyncio.create_task(self.invoke('comment',args)))
            await asyncio.wait_for(ready[0].wait(),3)
            tasks.append(asyncio.create_task(self.invoke('comment',args)))
            await asyncio.wait_for(ready[1].wait(),3)
            old=self.client.pending_recovery()[0]
            release[0].set()
            self.assertTrue((await tasks[0])['ok'])
            tasks.append(asyncio.create_task(self.invoke('comment',args)))
            await asyncio.wait_for(ready[2].wait(),3)
            new=self.client.pending_recovery()[0]
            self.assertNotEqual(old.original,new.original)
            with self.assertRaisesRegex(HubError,'recovery is unavailable'):
                self.client.restore_recovery(old)
            release[1].set()
            self.assertTrue((await tasks[1])['ok'])
            self.assertEqual(self.client.pending_recovery(),(new,))
            release[2].set()
            self.assertFalse((await tasks[2])['ok'])
            self.assertEqual(self.client.pending_recovery(),(new,))
            self.assertEqual([e['contractId'] for e in sent],
                ['federation-board-command','capability-outcome-query','federation-board-command'])
        finally:
            for event in release:event.set()
            await asyncio.gather(*tasks,return_exceptions=True)

    async def test_pinned_nats_send_failure_retains_early_subscription_for_cleanup(self):
        from hub.nats_transport import new_client
        connection=new_client(require_tls=False)
        connection._status=connection.CONNECTED
        borrowed=FederationSession()
        connection._agentmux_session=borrowed
        request=FederationSession()
        connection._send_command=AsyncMock(side_effect=RuntimeError('PRIVATE SUB send failed'))
        connection._flush_pending=AsyncMock()
        with self.assertRaisesRegex(RuntimeError,'SUB send failed'):
            await request.acquire(connection.subscribe_owned(request,'_INBOX.owned_failure'),request.own_subscription)
        self.assertEqual(len(connection._subs),1)
        self.assertEqual(len(request._resources),1)
        self.assertFalse(borrowed._resources)
        self.assertIs(connection._agentmux_session,borrowed)
        connection._send_command=AsyncMock()
        await request.close()
        self.assertFalse(connection._subs)
        self.assertFalse(borrowed.closing)
        self.assertTrue(connection.is_connected)

    async def test_runtime_start_and_offline_projection_do_not_require_command_session(self):
        from hub.fed.runtime import Federation
        from hub.fed.plugin_adapter import TrustedPluginAdapter
        from hub.fed.board_services import _BoardOperations
        self.federation.session=None
        self.federation.plugin_adapters={'board':TrustedPluginAdapter(Board(),build_board_context)}
        self.hub.stop=asyncio.Event()
        self.hub.stop.set()
        await Federation.run(self.federation)
        self.assertIsNone(self.federation.session)
        _BoardOperations()._mirror(self.federation,self.card['rid'],'SH-1',self.card,7)
        context=build_board_context(self.federation)
        rows=await Board().v_list(context,{'repo':'falcon'},'operator')
        self.assertEqual([(row['key'],row['rev']) for row in rows],[('SH-1',7)])
        row=await Board().v_show(context,{'repo':'falcon','key':'SH-1'},'operator')
        self.assertEqual((row['key'],row['rev']),('SH-1',7))
        self.assertFalse((await self.invoke('claim',{'repo':'falcon','key':'SH-1'}))['ok'])
        self.assertEqual(self.frames,[])
        self.federation.kv.assert_not_awaited()

    async def pinned_cleanup_connection(self):
        from hub.nats_transport import new_client
        connection=new_client(require_tls=False)
        connection._status=connection.CONNECTED
        connection._send_command=AsyncMock()
        connection._flush_pending=AsyncMock()
        connection._error_cb=AsyncMock()
        transport_tasks=[asyncio.create_task(asyncio.Event().wait()) for _ in range(2)]
        connection._reading_task,connection._flusher_task=transport_tasks
        pongs=[]
        def write(data):
            if data==b'PING\r\n':
                pongs.append(asyncio.create_task(connection._process_pong()))
        connection._transport=SimpleNamespace(write=write)
        async def finish():
            for task in transport_tasks:task.cancel()
            await asyncio.gather(*transport_tasks,*pongs,return_exceptions=True)
        self.addAsyncCleanup(finish)
        return connection,pongs

    async def test_failed_pinned_nats_drain_retains_registry_until_unsubscribe_is_confirmed(self):
        connection,pongs=await self.pinned_cleanup_connection()
        async def callback(message):pass
        subscription=await connection.subscribe_owned(self.endpoint._subscriptions,'_INBOX.failed_drain',cb=callback)
        callback_task=subscription._wait_for_msgs_task
        self.endpoint._connection=connection
        self.endpoint._subscription=subscription
        connection._send_command.side_effect=TimeoutError('PRIVATE unsubscribe send failed')
        with self.assertRaisesRegex(ContractError,'legacy_board_cleanup_incomplete'):
            await self.endpoint.close()
        self.assertTrue(subscription._closed)
        self.assertTrue(callback_task.done())
        self.assertIs(connection._subs.get(subscription._id),subscription)
        self.assertTrue(connection.is_connected)
        connection._send_command.side_effect=None
        await self.endpoint.close()
        self.assertEqual(len(pongs),1)
        self.assertEqual(connection._pongs,[])
        self.assertNotIn(subscription._id,connection._subs)
        self.assertTrue(callback_task.done())
        self.assertTrue(connection.is_connected)

    async def test_actual_flush_without_live_reader_or_flusher_cannot_confirm_cleanup(self):
        connection,pongs=await self.pinned_cleanup_connection()
        subscription=await connection.subscribe_owned(self.endpoint._subscriptions,'_INBOX.dead_reader')
        self.endpoint._connection=connection
        self.endpoint._subscription=subscription
        subscription._closed=True
        reader,flusher=connection._reading_task,connection._flusher_task
        for name,task in (('_reading_task',reader),('_flusher_task',flusher)):
            with self.subTest(loop=name):
                setattr(connection,name,None)
                # Actual pinned flush takes its direct-write fallback: no PONG.
                await connection.flush(timeout=1)
                self.assertEqual(pongs,[])
                with self.assertRaisesRegex(ContractError,'legacy_board_cleanup_incomplete'):
                    await self.endpoint.close()
                self.assertIs(connection._subs.get(subscription._id),subscription)
                self.assertTrue(connection.is_connected)
                setattr(connection,name,task)
        async def stopped_during_flush():
            if pongs:
                flusher.cancel()
                await asyncio.gather(flusher,return_exceptions=True)
        connection._flush_pending.side_effect=stopped_during_flush
        with self.assertRaisesRegex(ContractError,'legacy_board_cleanup_incomplete'):
            await self.endpoint.close()
        self.assertEqual(len(pongs),1)
        self.assertIs(connection._subs.get(subscription._id),subscription)
        replacement=asyncio.create_task(asyncio.Event().wait())
        connection._flusher_task=replacement
        connection._flush_pending.side_effect=None
        try:
            await self.endpoint.close()
            self.assertEqual(len(pongs),2)
            self.assertEqual(connection._pongs,[])
            self.assertNotIn(subscription._id,connection._subs)
        finally:
            replacement.cancel()
            await asyncio.gather(replacement,return_exceptions=True)

    async def test_initially_open_subscription_retains_registry_when_flusher_dies_during_drain(self):
        connection,pongs=await self.pinned_cleanup_connection()
        async def callback(message):pass
        subscription=await connection.subscribe_owned(self.endpoint._subscriptions,'_INBOX.open_drain',cb=callback)
        self.endpoint._connection=connection
        self.endpoint._subscription=subscription
        flusher=connection._flusher_task
        async def stop_during_ping():
            if pongs:
                flusher.cancel()
                await asyncio.gather(flusher,return_exceptions=True)
        connection._flush_pending.side_effect=stop_during_ping
        with self.assertRaisesRegex(ContractError,'legacy_board_cleanup_incomplete'):
            await self.endpoint.close()
        self.assertTrue(subscription._closed)
        self.assertTrue(subscription._wait_for_msgs_task.done())
        self.assertEqual(len(pongs),1)
        self.assertIs(connection._subs.get(subscription._id),subscription)
        replacement=asyncio.create_task(asyncio.Event().wait())
        connection._flusher_task=replacement
        connection._flush_pending.side_effect=None
        try:
            await self.endpoint.close()
            self.assertEqual(len(pongs),2)
            self.assertNotIn(subscription._id,connection._subs)
            self.assertTrue(connection.is_connected)
        finally:
            replacement.cancel()
            await asyncio.gather(replacement,return_exceptions=True)

    async def test_original_client_close_allows_only_completed_local_cleanup(self):
        from hub.nats_transport import new_client
        connection=new_client(require_tls=False)
        connection._status=connection.CONNECTED
        connection._send_command=AsyncMock()
        connection._flush_pending=AsyncMock()
        connection._error_cb=AsyncMock()
        async def callback(message):pass
        subscription=await connection.subscribe_owned(self.endpoint._subscriptions,'_INBOX.original_closed',cb=callback)
        self.endpoint._connection=connection
        self.endpoint._subscription=subscription
        callback_task=subscription._wait_for_msgs_task
        connection._status=connection.DISCONNECTED
        with self.assertRaisesRegex(ContractError,'legacy_board_cleanup_incomplete'):
            await self.endpoint.close()
        self.assertIs(connection._subs.get(subscription._id),subscription)
        # Actual Client.close removes its registry and joins no borrowed service.
        await connection.close()
        self.assertTrue(connection.is_closed)
        self.assertFalse(connection._subs)
        await self.endpoint.close()
        self.assertTrue(callback_task.done())
        self.assertTrue(subscription._closed)
        self.assertTrue(self.endpoint._subscriptions.close_task.done())
        self.assertEqual(connection._pongs,[])
