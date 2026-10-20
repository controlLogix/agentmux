"""Signed storage route with real credentials; only transport I/O is controlled."""
import asyncio
import base64
import copy
from dataclasses import replace
from datetime import timedelta
import hashlib
import os
from pathlib import Path
import ssl
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims,strict_loads
from hub.fed.board_services import _BoardOperations
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from identity import test_native_bridge as native_bridge_tests
from native_security.test_nats_credentials import credential
from state_owner.ledger import OwnerBinding,OwnerLedger,StreamIdentity,owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import CREATED,FakeJetStream
from . import test_board_native_owner as native_tests
from . import test_board_owner as owner_tests
from . import test_reply_service as reply_tests
from .board_owner import BoardMutationOwner
from .board_allocation import BoardAllocationResource,BoardAllocationTarget,prepare_allocation
from .board_allocation_journal import BoardAllocationJournal
from .board_allocation_owner import BoardAllocationOwner
from .board_phase_signer import BoardPhaseSigner
from .board_publisher import BoardPublisher, BoardStorageRoute
from .federation_board import FederationBoardResource
from .reply_service import CapabilityReplyService, verify_capability_response
from .receiver import CapabilityReceiver
from .test_storage_contract import StorageWriteContract


class PublisherConnection:
    """Controlled transport; actual credential validation remains unpatched."""
    def __init__(self,js):
        self.js=js
        self.is_connected=False
        self.closes=0

    def jetstream(self,*,domain):
        self.js._nc=self
        return self.js

    async def connect(self,**options):
        assert options['user_jwt_cb']()
        assert len(options['signature_cb']('broker-nonce'))==88
        assert options['allow_reconnect'] is False
        assert options['tls_handshake_first'] is True
        self.options=options
        self.is_connected=True

    async def flush(self,*,timeout):
        pass

    async def close(self):
        self.closes+=1
        self.is_connected=False


class BoardJetStream:
    def __init__(self,journal,board,kv):
        self.journal,self.board,self.kv=journal,board,kv
        self._prefix='$JS.API'

    def __getattr__(self,name):
        return getattr(self.journal,name)

    async def stream_info(self,stream):
        if stream=='KV_am_board':return await self.board.stream_info(stream)
        return await self.journal.stream_info(stream)

    async def key_value(self,bucket):
        assert bucket=='am_board'
        return self.kv


class AllocationStream(FakeJetStream):
    async def publish(self,subject,data,*,headers):
        assert headers['Nats-Expected-Stream']=='ALLOCATIONS'
        ack=await super().publish(subject,data,headers={**headers,'Nats-Expected-Stream':'OWNER'})
        return SimpleNamespace(stream='ALLOCATIONS',seq=ack.seq,duplicate=ack.duplicate)


class BoardStorageRouteTests(StorageWriteContract,unittest.IsolatedAsyncioTestCase):
    open=native_tests.NativeBoardOwnerTests.open
    admit=native_tests.NativeBoardOwnerTests.admit
    set_row=native_tests.NativeBoardOwnerTests.set_row
    install_board=owner_tests.BoardOwnerTests.install_board
    wrapper=native_tests.NativeBoardOwnerTests.wrapper
    bridge_request=native_bridge_tests.NativeBridgeTests.bridge_request

    def setUp(self):
        native_tests.NativeBoardOwnerTests.setUp(self)
        for name,contract in (('allocation-command','federation-board-command'),
                ('allocation-dispatch','federation-board-dispatch'),('allocation-complete','federation-board-complete')):
            base=next(g for g in self.record['state']['grants'] if g['ref']['id']==contract)
            grant=copy.deepcopy(base);grant.update(ref=ref(name),resourceId='prefix-one')
            self.record['state']['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)
        patch('capability_owner.reply_service.datetime',_Clock).start()
        patch('identity.native_bridge.datetime',_Clock).start()

    async def asyncSetUp(self):
        await native_tests.NativeBoardOwnerTests.asyncSetUp(self)
        from native_security.nats_credentials import board_publisher_policy
        self.selection=dict(hub_id='hub-one',entity_id='task-one',scope=self.scope,
            stream='OWNER',reply_prefix='_INBOX.board_publisher_000001',
            repository_id=self.resource.repository_id,card_key='SH-1',jetstream_domain=None)
        policy=board_publisher_policy(**self.selection)
        def permissions(claims):
            claims['nats'].update(pub={'allow':list(policy.publish_subjects)},
                                  sub={'allow':list(policy.subscribe_subjects)})
        raw,account,user=credential(permissions)
        js=BoardJetStream(self.journal_js,self.legacy.owner.js,self.kv)
        self.publisher_connection=PublisherConnection(js)
        self.publisher_options=dict(credentials=raw,account_public_key=account,user_public_key=user,
            server_url='tls://localhost:4222',tls_context=ssl.create_default_context(),
            leaf_certificate_sha256='sha256:'+'a'*64,**self.selection)
        with patch('capability_owner.board_publisher.new_client',return_value=self.publisher_connection):
            self.publisher=BoardPublisher(**self.publisher_options)
        self.addAsyncCleanup(self.publisher.close)
        await self.publisher.start()
        self.journal_js=js
        self.legacy.owner.js=js
        old=self.resource
        self.resource=FederationBoardResource(old.binding,old.board,old.repository,
            old.repository_id,old.card_key,StreamIdentity(CREATED,0))
        self.journal=self.open(target_binding=self.journal._target)
        self.signer=BoardPhaseSigner(self.journal,self.service.ingress,transport_ref=ref('owner-transport'),
            signing_seed=owner_tests.journal_tests.OWNER_SEED,grants={name:ref(name) for name in
                ('federation-board-dispatch','federation-board-complete')})
        self.owner=BoardMutationOwner(self.resource,self.journal,self.signer,actors=self.owner._actors)
        await self.install_prefix_gate()
        self.route=self.publisher.bind(self.owner,allocation_route=self.prefix_route)
        self.receiving_connection=reply_tests.Connection()
        self.responders={service:self.responder(service) for service in ('storage-owner','outcome-owner')}
        async def update(key,value,last):
            self.assertEqual((key,last),(self.entry.key,self.entry.revision))
            revision=self.info.state.last_seq+16
            self.entry=SimpleNamespace(bucket='am_board',key=key,value=value,revision=revision)
            self.info.state.last_seq=revision
            return revision
        self.kv.update.side_effect=update

    async def install_prefix_gate(self):
        from native_security.nats_credentials import board_publisher_policy
        policy=Retention(4_194_304,1_048_576)
        binding=OwnerBinding('hub-one','federation-board-operations','prefix-one','attempt',self.binding.scope)
        self.prefix_data=AllocationStream(policy)
        self.prefix_data.config=policy.stream_config(stream='ALLOCATIONS',subject=owner_subject(binding))
        prefix_js=BoardJetStream(self.prefix_data,self.legacy.owner.js,self.kv)
        prefix_connection=PublisherConnection(prefix_js)
        selected={**self.selection,'entity_id':'prefix-one','stream':'ALLOCATIONS',
            'reply_prefix':'_INBOX.prefix_publisher_000001','card_key':None,'counter_prefix':'SH'}
        permissions=board_publisher_policy(**selected)
        def claims(value):
            value['nats'].update(pub={'allow':list(permissions.publish_subjects)},sub={'allow':list(permissions.subscribe_subjects)})
        raw,account,user=credential(claims)
        options={**self.publisher_options,**selected,'credentials':raw,'account_public_key':account,'user_public_key':user}
        with patch('capability_owner.board_publisher.new_client',return_value=prefix_connection):
            self.prefix_publisher=BoardPublisher(**options)
        self.addAsyncCleanup(self.prefix_publisher.close)
        self.addAsyncCleanup(self.publisher.close)
        await self.prefix_publisher.start()
        prefix_domain=copy.copy(self.legacy.owner)
        prefix_domain.js=prefix_js
        target=BoardAllocationTarget(self.resource.repository_id,'SH',StreamIdentity(CREATED,0))
        resource=BoardAllocationResource(OwnerBinding('hub-one','federation-board','prefix-one','board-prefix',self.binding.scope),
            self.resource.board.__class__(prefix_domain),'falcon',target)
        ledger=OwnerLedger(prefix_js,stream='ALLOCATIONS',subject=owner_subject(binding),binding=binding,
            retention=policy,stream_identity=StreamIdentity(CREATED,0),require_completion_budget=True)
        journal=BoardAllocationJournal(ledger,self.service.reader,owner_service_identity_ref=ref('board-owner'),target_binding=target)
        signer=BoardPhaseSigner(journal,self.service.ingress,transport_ref=ref('owner-transport'),
            signing_seed=owner_tests.journal_tests.OWNER_SEED,grants={
                'federation-board-dispatch':ref('allocation-dispatch'),'federation-board-complete':ref('allocation-complete')})
        self.prefix_owner=BoardAllocationOwner(resource,journal,signer,actors=self.owner._actors)
        self.prefix_route=self.prefix_publisher.bind_allocation(self.prefix_owner)

    def responder(self,service,**changes):
        args=dict(resources=[self.resource],hub_id='hub-one',profile_id='profile-one',
            authority_id='authority-one',service_id=service,service_identity_ref=ref('service'),
            service_instance_id='ingress-one',signing_key_ref=ref('issuer'),signing_seed=SEED,
            request_signing_key_ref=ref('issuer'),connection=self.receiving_connection,board_routes=[self.route])
        args.update(changes)
        responder=CapabilityReplyService(self.service.reader,**args)
        self.addAsyncCleanup(responder.close)
        return responder

    async def dispatch(self,raw):
        request=strict_loads(raw)
        response=await self.responders[request['claims']['serviceId']].handle(raw,
            received_reply_subject=request['claims']['replySubject'])
        return strict_loads(verify_capability_response(response,raw,
            public_key=self.record['state']['issuers'][0]['publicKey'],signing_key_ref=ref('issuer'),
            service_identity_ref=ref('service'),service_instance_id='ingress-one',now=NOW))

    async def contract_prepare(self,operation,revision=7):
        inner=await self.admit('capability-storage-write',operation,revision,
            {'resourceRef':{**self.target,'revision':revision},
             'input':{'value':{'command':'comment','text':operation}}})
        return await self.prepare_native(inner)

    async def prepare_native(self,inner):
        envelope=strict_loads(inner)
        contract=envelope['contractId']
        request_id='request_'+hashlib.sha256(inner).hexdigest()
        snapshot=await self.service.reader.current()
        inp={'operation':envelope['operation'],'operationAuthorityRef':{
            **ref('authority-one'),'revision':snapshot.sequence},
            'bindingId':'board-write' if contract=='capability-storage-write' else 'board-outcome',
            'contractId':contract,'serviceRequestId':request_id,
            'serviceReplySubject':'_INBOX.abcdefghijklmnop','payload':envelope['payload'],
            'originalEnvelopeBytes':base64.b64encode(inner).decode()}
        response=strict_loads(await self.service.native.handle(self.bridge_request('prepare-domain-call',inp)))
        result=response['claims']['result']
        return base64.b64decode(result['serviceRequestBytes']),base64.b64decode(result['envelopeBytes'])

    contract_dispatch=dispatch

    async def contract_outcome(self,inner):
        operation=strict_loads(inner)['operation']
        query=await self.admit('capability-outcome-query','query-'+operation['operationId'],7,
            {'resourceRef':self.target,'input':{'operationId':operation['operationId'],
                'payloadDigest':operation['payloadDigest'],'contractId':'capability-storage-write'}})
        request,_=await self.prepare_native(query)
        return await self.dispatch(request)

    async def test_unregistered_or_raw_backend_cannot_enable_storage_route(self):
        for route in (BoardStorageRoute(),self.owner):
            with self.subTest(route=type(route).__name__),self.assertRaises(ContractError):
                CapabilityReceiver(self.service.reader,hub_id='hub-one',resources=[self.resource],board_routes=[route])

    async def test_selected_database_finishes_actual_card_audit_and_mirror_on_worker(self):
        from hub.store import APP_ID, MIGRATIONS, Store
        from .selected_storage import BoardAuditMirrorHost
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        database, policy = root / 'hub.db', root / 'federation.toml'
        store = Store(str(database))
        self.legacy.store.db.backup(store.db)
        store.db.close()
        database.chmod(0o600)
        raw = b'[federation]\npeer="nick"\n[repos.falcon]\nremote="github.com/adag/falcon"\nboard_prefix="SH"\n'
        policy.write_bytes(raw)
        policy.chmod(0o600)
        audit = BoardAuditMirrorHost({'database': {'path': str(database), 'applicationId': APP_ID,
            'userVersion': len(MIGRATIONS)}, 'policy': {'path': str(policy),
            'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest()}}, repository={
                'localName': 'falcon', 'repositoryId': self.resource.repository_id,
                'normalizedRemote': 'github.com/adag/falcon', 'counterPrefix': 'SH'},
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(audit.close)
        await audit.start()
        resource = replace(self.resource, board=audit.board_for(self.publisher))
        owner = BoardMutationOwner(resource, self.journal, self.signer, actors=self.owner._actors)
        self.addAsyncCleanup(owner.close)
        self.publisher.bind(owner, allocation_route=self.prefix_route)
        request = await self.admit('federation-board-command', 'selected-worker', 7,
            {'resourceRef': self.target, 'attribution': 'operator',
             'input': {'command': 'comment', 'key': 'SH-1', 'text': 'Retained mirror'}})
        result = await owner.apply(request)
        self.assertEqual(result['outcome'], 'applied')
        self.assertEqual(await owner.apply(request), result)
        audit.check_health()
        rows = await audit.db(audit._store.q, 'SELECT * FROM fed_audit')
        self.assertEqual(len(rows), 1)
        row = await audit.db(audit._store.q1, 'SELECT card,rev FROM p_board_cards')
        self.assertEqual(row['rev'], result['resourceRef']['revision'])
        self.assertEqual(strict_loads(row['card'])['comments'][0]['text'], 'Retained mirror')
        # The allocation publisher uses the same worker-safe policy boundary.
        prefix = audit.board_for(self.prefix_publisher)._owner
        self.assertTrue(await prefix.db(_BoardOperations()._mirror, prefix, resource.repository_id,
            resource.card_key, strict_loads(row['card']), row['rev']))

    async def test_receiving_connection_cannot_reuse_publisher_credentials(self):
        with self.assertRaisesRegex(ContractError,'board_storage_route_invalid'):
            self.responder('storage-owner',connection=self.publisher_connection)

    async def test_owner_must_use_the_enrolled_publisher_for_both_authorities(self):
        original=self.journal._ledger._js
        self.journal._ledger._js=self.service.reader._ledger._js
        try:
            with self.assertRaisesRegex(ContractError,'board_storage_route_invalid'):
                self.publisher.bind(self.owner,allocation_route=self.prefix_route)
        finally:
            self.journal._ledger._js=original

    async def test_replaced_journal_connection_refuses_an_already_registered_route(self):
        raw,_=await self.contract_prepare('replaced-journal')
        original=self.journal._ledger._js
        self.journal._ledger._js=self.service.reader._ledger._js
        try:
            with self.assertRaisesRegex(ContractError,'capability_service_unavailable'):
                await self.dispatch(raw)
            self.kv.update.assert_not_awaited()
        finally:
            self.journal._ledger._js=original

    async def test_changed_credential_pin_refuses_before_connection_allocation(self):
        for change in ({'user_public_key':'wrong-user'},{'leaf_certificate_sha256':None},
                       {'leaf_certificate_sha256':'sha256:'+'A'*64}):
            with self.subTest(change=change),patch('capability_owner.board_publisher.new_client') as allocate:
                with self.assertRaisesRegex(ContractError,'board_publisher_configuration'):
                    BoardPublisher(**{**self.publisher_options,**change})
                allocate.assert_not_called()

    async def test_closed_publisher_refuses_without_card_write(self):
        raw,_=await self.contract_prepare('closed-publisher')
        await self.publisher.close()
        with self.assertRaisesRegex(ContractError,'capability_service_unavailable'):
            await self.dispatch(raw)
        self.kv.update.assert_not_awaited()

    async def test_legacy_kv_cache_is_not_used_by_the_publisher_route(self):
        self.legacy.owner.kv.side_effect=AssertionError('legacy credential must not publish')
        raw,inner=await self.contract_prepare('protected-publisher')
        receipt=await self.dispatch(raw)
        self.assertEqual((receipt['outcome'],receipt['resourceRef']['revision']),('applied',23))
        retained=strict_loads(self.journal_js.messages[0].data)['state']['original']
        self.assertEqual(retained,strict_loads(inner))
        self.assertEqual((await self.contract_outcome(inner))['outcome'],'committed')

    async def test_retained_allocation_gate_blocks_card_writer_until_claim_finishes(self):
        claims=copy.deepcopy(self.claims)
        claims.update(contractId='federation-board-command',operationId='prefix-claim',expectedVersion=0,
            grantRef=ref('allocation-command'),payload={'resourceRef':{**ref('prefix-one'),'revision':0},
                'attribution':'operator','input':{'command':'add','title':'Reserved card'}})
        request=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,bytes(reversed(SEED)))})
        admitted=await self.service.ingress.admit(request,cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome,'allowed')
        original=strict_loads(admitted.envelope)
        plan=prepare_allocation(self.prefix_owner._resource.target,original,
            _BoardOperations().prepare_add_input(original['payload']['input']),counter_revision=0,counter_value=None,
            observed_sequence=7,context=None,by='peer:nick',at='2026-10-09T12:00:01Z')
        await self.prefix_owner._journal.prepare(admitted.envelope,expected_sequence=0,plan=plan)
        raw,_=await self.contract_prepare('card-during-allocation')
        with self.assertRaisesRegex(ContractError,'capability_service_unavailable'):
            await self.dispatch(raw)
        self.kv.update.assert_not_awaited()
        result=await self.prefix_owner.recover_pending()
        self.assertEqual(result['outcome'],'rejected')
        self.assertEqual((await self.dispatch(raw))['outcome'],'applied')

    async def test_closed_prefix_publisher_refuses_existing_card_route(self):
        raw,_=await self.contract_prepare('closed-prefix')
        await self.prefix_publisher.close()
        with self.assertRaisesRegex(ContractError,'capability_service_unavailable'):
            await self.dispatch(raw)
        self.kv.update.assert_not_awaited()

    async def test_live_query_recovers_the_executed_downstream_operation(self):
        from . import test_board_live as live_fixture
        request,executed=await self.contract_prepare('upstream-operation')
        receipt=await self.dispatch(request)
        self.assertNotEqual(strict_loads(executed)['operation']['operationId'],'upstream-operation')
        async def admit_query(contract,payload):
            return await self.admit(contract,'lookup-executed',payload['resourceRef']['revision'],payload)
        async def prepare_query(inner):return (await self.prepare_native(inner))[0]
        query=await live_fixture.LiveBoardPublisherTests.query(
            SimpleNamespace(admit=admit_query,prepare=prepare_query),request)
        outcome=await self.dispatch(query)
        self.assertEqual(outcome['outcome'],'committed')
        self.assertEqual(outcome['resourceRef'],receipt['resourceRef'])
        self.assertEqual(outcome['recordRef'],receipt['receiptRef'])
        self.assertEqual(outcome['operationId'],strict_loads(executed)['operation']['operationId'])

    async def test_prefix_gate_refuses_other_prefix_broker_account_pin_domain_or_stream_epoch(self):
        for resource in (replace(self.resource,card_key='OTHER-1'),
                         replace(self.resource,stream_identity=StreamIdentity(CREATED+timedelta(seconds=1),0))):
            with self.subTest(resource=resource),self.assertRaisesRegex(ContractError,'board_allocation_route_invalid'):
                self.prefix_route.check(self.service.reader,resource,publisher=self.publisher)
        for field,value in (('_server','tls://other:4222'),('_account','other-account'),
                            ('_leaf','sha256:'+'b'*64)):
            publisher=copy.copy(self.publisher)
            setattr(publisher,field,value)
            with self.subTest(field=field),self.assertRaisesRegex(ContractError,'board_allocation_route_invalid'):
                self.prefix_route.check(self.service.reader,self.resource,publisher=publisher)
        publisher=copy.copy(self.publisher)
        publisher._selection={**publisher._selection,'jetstream_domain':'other'}
        with self.assertRaisesRegex(ContractError,'board_allocation_route_invalid'):
            self.prefix_route.check(self.service.reader,self.resource,publisher=publisher)
        self.kv.update.assert_not_awaited()

    async def test_signed_reconcile_recovers_lost_card_ack_without_reapplying(self):
        actual=self.kv.update.side_effect
        async def lost_ack(*args,**kwargs):
            await actual(*args,**kwargs)
            raise TimeoutError('PRIVATE acknowledgment')
        self.kv.update.side_effect=lost_ack
        raw,inner=await self.contract_prepare('lost-card-ack')
        with self.assertRaisesRegex(ContractError,'capability_service_unavailable'):
            await self.dispatch(raw)
        recovered=await self.contract_outcome(inner)
        self.assertEqual((recovered['outcome'],recovered['resourceRef']['revision']),('committed',23))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual([c['text'] for c in strict_loads(self.entry.value)['comments']],['lost-card-ack'])

    async def test_cancelled_signed_reply_keeps_original_worker_until_service_close_joins(self):
        actual=self.kv.update.side_effect
        started,release=asyncio.Event(),asyncio.Event()
        async def blocked(*args,**kwargs):
            started.set()
            await release.wait()
            return await actual(*args,**kwargs)
        self.kv.update.side_effect=blocked
        raw,inner=await self.contract_prepare('cancelled-reply')
        reply=asyncio.create_task(self.dispatch(raw))
        await started.wait()
        reply.cancel()
        with self.assertRaises(asyncio.CancelledError):await reply
        service=self.responders['storage-owner']
        try:
            with self.assertRaisesRegex(ContractError,'capability_cleanup_incomplete'):
                await service.close(timeout=.001)
            self.assertTrue(self.publisher_connection.is_connected)
            self.assertEqual(self.publisher_connection.closes,0)
        finally:
            release.set()
        await service.close()
        recovered=await self.contract_outcome(inner)
        self.assertEqual(recovered['outcome'],'committed')
        self.assertEqual(self.kv.update.await_count,1)
