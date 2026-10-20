"""A retained Hub source expectation cannot follow a substituted Work service."""
import asyncio
import base64
import copy
from datetime import datetime,timedelta,timezone
from pathlib import Path
import sqlite3
import tempfile

from agentmux_contracts import ContractError,canonical_bytes,strict_loads
from hub.tests.test_work_client_transport import material
from identity.application_client import ApplicationClientKey
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref
from .selected_storage import SelectedStorageHost
from . import test_work_source as support
from .work import WorkStorageResource
from .work_bridge_service import WorkBridgeService
from .work_lifecycle_client import WorkLifecycleClient


class WorkSourceBoundaryTests(support.SelectedWorkSourceTests):
    async def test_changed_or_stale_receipts_refuse_before_any_outcome_exchange(self):
        hub=await self.setup_source()
        await hub._work_source_binding.activate()
        client=WorkLifecycleClient(hub._work_storage_commands)
        arguments={'generation':None,'repo':'falcon','role':'worker','agent':'receipt',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%22','panePid':12350,
            'legacy':None,'tokenSha':'f'*64}
        await client.register(arguments,operation_id='receipt-source-register',
            expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        hub._work_storage_commands.finish_disclosure()
        record=await hub._work_storage_commands._owned_db(client._load,
            'receipt-source-register','register',arguments)
        routes=client._routes('register',record)
        receipts=[{**copy.deepcopy(metadata),'result':record['result']} for metadata in record['receipts']]
        changed=copy.deepcopy(receipts)
        changed[0]['result']='substituted-result'
        stale=copy.deepcopy(receipts)
        stale[0]['resourceRef']['revision']-=1
        stale[0]['receiptRef']['revision']-=1
        future=copy.deepcopy(receipts)
        future[0]['resourceRef']['revision']+=1
        future[0]['receiptRef']['revision']+=1
        before=len(self.submitted)
        for candidate in (changed,stale,future,list(reversed(receipts))):
            with self.subTest(candidate=candidate[0]['resourceRef']):
                with self.assertRaises(ContractError):
                    await client._exchange(routes,record,datetime.now(timezone.utc)+timedelta(seconds=4),
                        submit=False,_fresh_receipts=candidate)
        self.assertEqual(len(self.submitted),before)

    async def test_later_owner_revision_does_not_resubmit_or_replace_original_result(self):
        hub=await self.setup_source()
        await hub._work_source_binding.activate()
        client=WorkLifecycleClient(hub._work_storage_commands)
        arguments={'generation':None,'repo':'falcon','role':'worker','agent':'later',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%23','panePid':12351,
            'legacy':None,'tokenSha':'1'*64}
        registered=await client.register(arguments,operation_id='original-before-later-state',
            expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        hub._work_storage_commands.finish_disclosure()
        original=await hub._work_storage_commands._owned_db(client._load,
            'original-before-later-state','register',arguments)
        await client.set_state({'session':registered,'generation':1,'state':'busy','note':'later owner state'},
            operation_id='later-state-change',expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        hub._work_storage_commands.finish_disclosure()
        before=len(self.submitted)
        replay=await client.register(arguments,operation_id='original-before-later-state',
            expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        self.assertEqual(replay,registered)
        queries=self.submitted[before:]
        self.assertFalse(any(p['contractId']=='federation-work-register' for p in queries))
        self.assertEqual(sum(p['contractId']=='federation-work-inspect' for p in queries),2)
        for query in (p for p in queries if p['contractId']=='federation-work-outcome'):
            metadata=next(p for p in original['receipts']
                if p['resourceRef']['id']==query['payload']['resourceRef']['id'])
            self.assertGreater(query['payload']['resourceRef']['revision'],metadata['resourceRef']['revision'])
            self.assertEqual(query['payload']['input']['operationId'],'original-before-later-state')
        self.assertEqual((await hub.db(hub.store.agent,registered))['state'],'busy')
        self.assertEqual(await hub.db(hub.store.q1,
            "SELECT count(*) n FROM events WHERE event='registered' AND entity_id=?",(registered,)),{'n':1})

    async def _replace_service(self,value):
        other=SelectedStorageHost(ApplicationServiceSelection(canonical_bytes(value)),identity=self.identity)
        self.addAsyncCleanup(other.close,timeout=None)
        await other._work(value['storage']['work'])
        original=self.resources[0]
        resource=next(r for r in other._resources if type(r) is WorkStorageResource
            and r.binding.entity_id==original.binding.entity_id)
        previous=next(e for e in self.host._receivers if e._service=='storage-owner'
            and e._scope==original.binding.scope)._work_bridge
        endpoint=WorkBridgeService(self.identity.ingress,resources=(resource,),
            service_identity_ref=strict_loads(previous._identity),service_instance_id=previous._instance,
            signing_key_ref=strict_loads(previous._issuer),signing_seed=previous._seed)
        self.addAsyncCleanup(endpoint.close,timeout=None)
        session=self.sessions[0]
        enrolled=session.work_enrollment()
        credentials=material()
        credentials.update(**enrolled,seed=base64.b64encode(bytes([51])*32).decode())
        key=ApplicationClientKey(credentials)
        loop=asyncio.get_running_loop()
        sent=[]
        def changed_service(*,contract_id,operation_id,payload,expires_at,deadline,
                            include_valid_until=False,source_expectation=None):
            route=enrolled['workCommands']
            now=datetime.now(timezone.utc)
            claims={'purpose':'agentmux-client-possession-v1',
                **{k:enrolled[k] for k in ('hubId','profileId','authorityId')},
                'transportRef':route['transportRef'],'grantRef':route['grantRefs'][contract_id],
                'operationId':operation_id,'expectedVersion':payload['resourceRef']['revision'],
                'contractId':contract_id,'payload':payload,'approvalRefs':[],
                'issuedAt':now.isoformat().replace('+00:00','Z'),'expiresAt':expires_at,
                'replySubject':'_INBOX.source_substituted_service_01'}
            if source_expectation is not None: claims['workSource']=source_expectation
            raw=key.sign_command(claims,subject=route['subject'],now=now)
            sent.append(claims)
            response=asyncio.run_coroutine_threadsafe(endpoint.handle(raw,
                received_reply_subject=claims['replySubject']),loop).result(timeout=6)
            return key.verify_command_response(response,raw,subject=route['subject'],
                now=datetime.now(timezone.utc),include_valid_until=include_valid_until)
        # Only this transport's receiver changes. Identity, key, profile, scope,
        # resource and grants are all still the original accepted enrollment.
        session.work_command=changed_service
        return resource,changed_service,sent

    async def test_service_on_another_physical_source_refuses_original_signed_expectation(self):
        hub=await self.setup_source()
        await hub._work_source_binding.activate()
        directory=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        database=directory/'other.db'
        def copy_original():
            connection=sqlite3.connect(str(database))
            try: hub.store.db.backup(connection)
            finally: connection.close()
        await asyncio.wrap_future(hub.dbx.submit(copy_original))
        database.chmod(0o600)
        value=copy.deepcopy(self.host._selection.policy)
        value['storage']['work']['source']['database']['path']=str(database)
        resource,changed_service,sent=await self._replace_service(value)
        entries=[{'repository':r.repository,'resourceRef':{**ref(r.binding.entity_id),
            'revision':(await r._owner.db(r._journal.current))['revision']}} for r in self.resources]
        value={'purpose':'hub-registration','batchId':'source-switch-register','localNode':'mac',
            'repositories':entries,'generation':None,'repo':'falcon','role':'worker','agent':'refused',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%20','panePid':12348,
            'legacy':None,'tokenSha':'d'*64}
        with self.assertRaises(ContractError):
            await hub._work_storage_commands._call(self.sessions[0],'federation-work-register',value['batchId'],
                {'resourceRef':entries[0]['resourceRef'],'input':value,'attribution':'federation'},
                datetime.now(timezone.utc)+timedelta(seconds=4))
        self.assertEqual(sent[-1]['workSource'],await hub._work_source_binding.expectation(self.sessions[0]))
        self.assertEqual(await hub.db(hub.store.agents),[])
        self.assertEqual(await resource._owner.db(resource._store.agents),[])
        # The other source remains a valid independent selected owner. Its normal
        # authorized inspect works without borrowing the Hub's source expectation.
        reply=await asyncio.to_thread(changed_service,contract_id='federation-work-inspect',
            operation_id='standalone-other-source',payload={'resourceRef':ref(resource.binding.entity_id),'input':{}},
            expires_at=(datetime.now(timezone.utc)+timedelta(seconds=4)).isoformat().replace('+00:00','Z'),
            deadline=asyncio.get_running_loop().time()+4)
        self.assertEqual(reply['resourceRef']['id'],resource.binding.entity_id)

    async def test_same_file_replacement_with_changed_node_refuses_before_lease_effect(self):
        hub=await self.setup_source()
        await hub._work_source_binding.activate()
        def seed():
            agent=hub.store.register('falcon','worker','holder','codex',{},handle='%25',pane_pid=12352)
            hub.store.set_state(agent,'ready')
            row=hub.store.work_create('operator','falcon','agent:'+agent,'Original held work')
            hub.store.claim(agent,work_id=row['id'])
            return agent,hub.store.q1('SELECT * FROM work_items WHERE id=?',(row['id'],))
        agent,before=await hub.db(seed)
        original=self.resources[0]
        self.assertIsNone(await original._owner.db(original._journal._get,'resource'))
        value=copy.deepcopy(self.host._selection.policy)
        value['storage']['work']['localNode']='replacement_node'
        resource,_,sent=await self._replace_service(value)
        self.assertEqual(resource._store.path,hub.store.path)
        with self.assertRaises(ContractError):
            await hub._work_storage_commands._call(self.sessions[0],'federation-work-return-leases',
                'changed-node-source',{'resourceRef':ref(original.binding.entity_id),
                    'input':{'session':agent,'reason':'replaced source route'},'attribution':'federation'},
                datetime.now(timezone.utc)+timedelta(seconds=4))
        after=await hub.db(hub.store.q1,'SELECT * FROM work_items WHERE id=?',(before['id'],))
        self.assertEqual(after,before)
        self.assertEqual(sent[-1]['workSource'],await hub._work_source_binding.expectation(self.sessions[0]))

    async def test_lost_registration_reply_recreated_driver_recovers_only_original_outcome(self):
        hub=await self.setup_source()
        await hub._work_source_binding.activate()
        client=WorkLifecycleClient(hub._work_storage_commands)
        session=self.sessions[0]
        submit=session.work_command
        lost=[]
        def drop(**arguments):
            reply=submit(**arguments)
            if arguments['contract_id']=='federation-work-register' and not lost:
                lost.append(True)
                raise TimeoutError('controlled applied response loss')
            return reply
        session.work_command=drop
        arguments={'generation':None,'repo':'falcon','role':'worker','agent':'recovered',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%21','panePid':12349,
            'legacy':None,'tokenSha':'e'*64}
        with self.assertRaises(TimeoutError):
            await client.register(arguments,operation_id='source-lost-register',
                expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        count=sum(item['contractId']=='federation-work-register' for item in self.submitted)
        self.assertEqual(count,2)
        self.assertEqual(len(lost),1)
        await client.close()
        recovered=WorkLifecycleClient(hub._work_storage_commands)
        before=len(self.submitted)
        result=await recovered.register(arguments,operation_id='source-lost-register',
            expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        self.assertEqual(result,'falcon-worker-recovered')
        recovery=self.submitted[before:]
        self.assertEqual(sum(item['contractId']=='federation-work-inspect' for item in recovery),2)
        outcomes=[item for item in recovery if item['contractId']=='federation-work-outcome']
        self.assertEqual(len(outcomes),4)
        self.assertTrue(all(item['payload']['input']['operationId']=='source-lost-register' for item in outcomes))
        self.assertEqual(sum(item['contractId']=='federation-work-register' for item in self.submitted),count)
        self.assertEqual(await hub.db(hub.store.q1,
            "SELECT count(*) n FROM events WHERE event='registered' AND entity_id=?",(result,)),{'n':1})
        self.assertEqual((await hub.db(hub.store.agent,result))['generation'],1)
        retained=await hub.db(hub.store.q1,"SELECT v FROM fed_state WHERE k LIKE 'work-lifecycle-client:%' "
            "AND json_extract(v,'$.operationId')=?",('source-lost-register',))
        record=strict_loads(retained['v'])
        self.assertEqual(record['state'],'completed')
        self.assertEqual(record['operationId'],'source-lost-register')
        self.assertTrue(all('workSource' not in receipt for receipt in record['receipts']))
