"""Code sharing over native TLS sessions, actual Hub admission and local Git."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.client_launch_selection import load_selection
from hub.fed import envelope, ledger
from hub.fed.code_services import GitOperations
from hub.fed.plugins.code import Code
from hub.fed.policy import rid_for_remote
from hub.fed.session import FederationSession
from hub.server import Hub
from hub.tests.test_fed_unit import policy
from identity.application_client import ApplicationClientKey
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding
from .code import CodeStorageResource
from .code_legacy import LegacyCodeActor
from .code_bridge_service import CodeBridgeService
from .reply_service import CapabilityReplyService
from .test_legacy_messages_live import LegacyMessageLiveFixture


class LegacyCodeLiveFixture(LegacyMessageLiveFixture):
    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        self.git_remote = str(self.directory / 'code-remote.git')
        self.code_rid = rid_for_remote(self.git_remote)
        policies['federation']['publish']['allow'].append('am.code.nick.' + self.code_rid)
        policies['federation']['subscribe']['allow'].append('am.code.alice.' + self.code_rid)

    def initial_authority(self):
        record = super().initial_authority()
        template = copy.deepcopy(next(g for g in record['state']['grants'] if g['ref'] == ref('legacy-send')))
        self.code_grants, self.code_service_grants = {}, {}
        for identity, actions, target in (('human',('publish','fetched','approve','read','inspect','outcome'),self.code_grants),
                ('service',('index','read','inspect','outcome'),self.code_service_grants)):
            for action in actions:
                contract = 'federation-code-' + action
                grant = {**template,'ref':ref('code-'+identity+'-'+action),'contractId':contract,
                    'callerRef':ref(identity),'actorRef':ref(identity)}
                record['state']['grants'].append(grant)
                target[contract] = grant['ref']
        for old,new in (('transport','code-human-transport'),('message-service-transport','code-service-transport')):
            original = next(t for t in record['state']['transports'] if t['ref']==ref(old))
            record['state']['transports'].append({**original,'ref':ref(new)})
        return record

    async def start_receiver(self):
        await super().start_receiver()
        await self.receiver.close()
        old = self.resource
        self.domain.policy = policy(repos={'falcon':{'remote':self.git_remote,'peers':['*']}})
        for statement in Code.tables:self.store.db.execute(statement)
        self.resource = CodeStorageResource(OwnerBinding('hub-one','federation-code','task-one','code-channel',
            canonical_bytes(self.scope)),self.domain,repository='falcon',actors=old.actors,
            plugin_identity_ref=ref('plugin'),instance_id='plugin-one',legacy_actors=(
                LegacyCodeActor(canonical_bytes(ref('human')),canonical_bytes(ref('code-human-transport')),
                    'operator',canonical_bytes(self.code_grants)),
                LegacyCodeActor(canonical_bytes(ref('service')),canonical_bytes(ref('code-service-transport')),
                    'federation',canonical_bytes(self.code_service_grants))))
        bridge = CodeBridgeService(self.identity.ingress,resources=(self.resource,),
            service_identity_ref=ref('service'),service_instance_id='ingress-one',signing_key_ref=ref('issuer'),signing_seed=SEED)
        self.receiver = CapabilityReplyService(self.identity.reader,resources=[self.resource],hub_id='hub-one',
            profile_id='profile-one',authority_id='authority-one',service_id='storage-owner',
            service_identity_ref=ref('service'),service_instance_id='ingress-one',signing_key_ref=ref('issuer'),
            signing_seed=SEED,request_signing_key_ref=ref('issuer'),connection=self.storage,code_bridge=bridge)
        await self.receiver.start()
        self.native_clients, self.private_launches = [], []
        async def observe():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task = asyncio.create_task(observe())

    def code_key(self, *, service=False):
        material = strict_loads(self.application_key(service=service)._material)
        selected = material.pop('messageCommands')
        selected.pop('peer')
        selected.update(grantRefs=self.code_service_grants if service else self.code_grants,
            transportRef=ref('code-service-transport' if service else 'code-human-transport'),
            repository={'localName':'falcon','repositoryId':self.resource.repository_id})
        material['codeCommands'] = selected
        return ApplicationClientKey(material)

    async def native_session(self, *, service=False):
        from hub.client_launch_connection import selected_publish_subjects
        from native_security.nats_credentials import validate
        key = self.code_key(service=service)
        role = 'federation-application' if service else 'caller-application'
        private = Path(tempfile.mkdtemp(prefix='amux-code-client-',dir=Path.home())).resolve()
        self.private_launches.append(private)
        def write(name,raw):
            path=private/name;path.write_bytes(raw);path.chmod(0o600)
            return str(path)
        credentials = self.credentials[role].read_bytes()
        credential = validate(credentials,account_public_key=self.account_public_key,
            publish_subjects=selected_publish_subjects(key),subscribe_subjects=[self.inbox_prefixes[role]+'.>'],
            private_inbox=True,application_publish=True)
        connection = write('connection.json',canonical_bytes({'schemaVersion':'1.0.0','endpoint':self.broker.url,
            'serverName':self.server_name,'rootsPEM':self.ca_file.read_text(),
            'leafCertificateSHA256':self.leaf_digest,'credentialsFile':write('client.creds',credentials),
            'accountPublicKey':self.account_public_key,'userPublicKey':credential.public_key,
            'replyPrefix':self.inbox_prefixes[role]}))
        workspace=private/'workspace';workspace.mkdir(mode=0o700)
        selected=write('selection.json',canonical_bytes({'schemaVersion':'1.0.0',
            'hostPolicy':str(self.directory/'host-policy.json'),'workspaces':[str(workspace)],
            'instanceId':'application-one','profileId':'profile-one','hubId':'hub-one',
            'application':{'clientKey':write('client-key.json',key._material),'connection':connection}}))
        selection=load_selection(selected,deadline=time.monotonic()+3)
        session=ApplicationClientSession(selection)
        self.native_clients.append({'session':session,'join':None})
        await asyncio.to_thread(session.start,deadline=time.monotonic()+4)
        return session

    async def join_native_clients(self):
        interrupted=False
        for owned in getattr(self,'native_clients',()):
            session=owned['session']
            if owned['join'] is None:
                def finish(original=session):
                    original.close(deadline=time.monotonic()+5)
                    return original.join_final()
                owned['join']=asyncio.create_task(asyncio.to_thread(finish))
            while True:
                try:
                    self.assertTrue(await asyncio.shield(owned['join']))
                    break
                except asyncio.CancelledError:
                    if owned['join'].cancelled():raise
                    interrupted=True
            self.assertFalse(session._thread.is_alive())
            if session._owner is not None:
                self.assertFalse(session._owner._subscriptions)
                self.assertIsNone(session._owner._exchange_task)
        return interrupted

    async def cleanup(self):
        success=self.success
        self.success=False
        if hasattr(self,'actual_hub'):
            await self.actual_hub._code_commands.close(timeout=None)
            if hasattr(self,'federation_session'):await self.federation_session.close()
        interrupted=await self.join_native_clients()
        for guard in reversed(getattr(self,'_code_guards',())):guard.stop()
        if hasattr(self,'actual_hub'):
            await self.actual_hub.db(self.actual_hub.store.db.close)
            self.actual_hub.dbx.shutdown(wait=True)
            self.actual_hub.io.shutdown(wait=True)
        observation=getattr(self,'_observation_task',None)
        if observation is not None:
            observation.cancel();await asyncio.gather(observation,return_exceptions=True)
        await super().cleanup()
        for private in getattr(self,'private_launches',()):shutil.rmtree(private)
        if success and not self.keep_directory:shutil.rmtree(self.directory)
        if interrupted:raise asyncio.CancelledError()

    async def make_hub(self,sessions):
        directory=self.directory
        (directory/'config.toml').write_text('node="mac"\nbackup_every_s=9007199254740991\nprune_every_s=9007199254740991\n')
        (directory/'federation.toml').write_text('[federation]\npeer="nick"\nplugins=["code"]\n'
            '[repos.falcon]\nremote='+json.dumps(self.git_remote)+'\n[peers.alice]\ntrust="auto"\n')
        from hub import server as hub_server
        with patch.object(hub_server,'ROOT',str(directory/'root')),patch.object(hub_server,'HUBDIR',str(directory)), \
                patch.object(hub_server,'SOCK',str(directory/'hub.sock')):
            self.actual_hub=Hub(code_sessions=tuple(sessions))
        self.operator_token=(directory/'operator.token').read_text().strip()
        self.actual_hub.fed.session=self.federation_session=FederationSession()
        self.assertIsNot(self.actual_hub.store,self.store)
        self.assertEqual(self.actual_hub.store.db.execute('PRAGMA database_list').fetchone()[2],
            self.store.db.execute('PRAGMA database_list').fetchone()[2])
        self.poison_hub_code_access()
        return self.actual_hub

    def poison_hub_code_access(self):
        # The original file still owns quarantine/audit. Only the retained code
        # owner connection may disclose or mutate its code rows.
        self.raw_code_access=[]
        store=self.actual_hub.store
        connection=store.db
        def check(sql):
            if 'p_code_shares' in str(sql).lower():
                self.raw_code_access.append(str(sql))
                raise AssertionError('Hub code caller bypassed retained owner')
        class CheckedConnection:
            def __getattr__(self,name):return getattr(connection,name)
            def execute(self,sql,*args,**kwargs):
                check(sql);return connection.execute(sql,*args,**kwargs)
            def executemany(self,sql,*args,**kwargs):
                check(sql);return connection.executemany(sql,*args,**kwargs)
            def executescript(self,sql,*args,**kwargs):
                check(sql);return connection.executescript(sql,*args,**kwargs)
        self._code_guards=[patch.object(store,'db',CheckedConnection())]
        for name in ('q','q1'):
            original=getattr(store,name)
            def guarded(sql,*args,_original=original,**kwargs):
                check(sql);return _original(sql,*args,**kwargs)
            self._code_guards.append(patch.object(store,name,side_effect=guarded))
        for guard in self._code_guards:guard.start()

    async def request(self,verb,args):
        self.refresh_observation()
        reader=SimpleNamespace(readline=AsyncMock(return_value=canonical_bytes({
            'token':self.operator_token,'verb':verb,'args':args})),at_eof=lambda:False)
        writer=SimpleNamespace(write=Mock(),drain=AsyncMock(),close=Mock(),is_closing=lambda:False)
        await self.actual_hub.handle_conn(reader,writer,tcp=True)
        return json.loads(writer.write.call_args.args[0])

    async def git(self,*arguments):
        def run():
            result=subprocess.run(['git',*map(str,arguments)],stdin=subprocess.DEVNULL,capture_output=True,text=True,
                timeout=10,env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull})
            if result.returncode:raise RuntimeError('owned local Git fixture command failed: '+str(arguments[0]))
            return result.stdout.strip()
        return await asyncio.to_thread(run)

    async def git_checkout(self):
        remote=Path(self.git_remote)
        await self.git('init','--bare','--initial-branch=main',remote)
        checkout=self.directory/'code-checkout'
        await self.git('init','--initial-branch=main',checkout)
        await self.git('-C',checkout,'config','user.name','Code Fixture')
        await self.git('-C',checkout,'config','user.email','code-fixture@example.invalid')
        (checkout/'original.txt').write_text('original committed code\n')
        await self.git('-C',checkout,'add','original.txt')
        await self.git('-C',checkout,'commit','-m','Original fixture code')
        await self.git('-C',checkout,'remote','add','origin',remote)
        await self.git('-C',checkout,'push','origin','main')
        (checkout/'original.txt').write_text('original committed code\nshared feature change\n')
        await self.git('-C',checkout,'add','original.txt')
        await self.git('-C',checkout,'commit','-m','Shared feature code')
        return checkout,await self.git('-C',checkout,'rev-parse','HEAD')


class LiveLegacyCodeTests(LegacyCodeLiveFixture,unittest.IsolatedAsyncioTestCase):
    async def test_native_hub_git_lost_owner_reply_recovers_once_and_revokes(self):
        session=await self.native_session()
        hub=await self.make_hub((session,))
        checkout,sha=await self.git_checkout()
        args={'repo':'falcon','path':str(checkout),'note':'Original actual Git share'}
        original_publish=self.storage.publish
        dropped=False
        async def lose_reply(subject,raw,**kwargs):
            nonlocal dropped
            if (not dropped and subject.startswith(self.inbox_prefixes['caller-application']+'.')
                    and strict_loads(raw)['claims'].get('requestContractId')=='federation-code-publish'):
                dropped=True
                return
            return await original_publish(subject,raw,**kwargs)
        counts={'push':0,'fetch':0}
        original_run=GitOperations._run
        async def counted(owner,path,*arguments):
            if arguments and arguments[0] in counts:counts[arguments[0]]+=1
            return await original_run(owner,path,*arguments)
        with patch.object(GitOperations,'_run',counted):
            with patch.object(self.storage,'publish',side_effect=lose_reply):
                first=await self.request('fed_code_share',args)
            self.assertTrue(dropped)
            self.assertFalse(first['ok'])
            recovered=await self.request('fed_code_share',args)
            self.assertTrue(recovered['ok'],recovered)
            share=recovered['result']
            self.assertEqual(share['sha'],sha)
            self.assertEqual(counts['push'],1)
            self.assertEqual(await self.git('--git-dir',self.git_remote,'rev-parse',share['ref']),sha)
            self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')),1)
            original_row=self.store.q1('SELECT * FROM p_code_shares')
            self.assertEqual((original_row['id'],original_row['sha'],original_row['files']),
                (share['id'],sha,'original.txt'))
            self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')),1)
            listed=await self.request('fed_code_list',{'repo':'falcon'})
            self.assertTrue(listed['ok'],listed)
            self.assertEqual(listed['result'][0]['id'],share['id'])
            panel=await self.request('fed_panel',{})
            self.assertTrue(panel['ok'],panel)
            code=next(p for p in panel['result']['panels'] if p['plugin']=='code')
            self.assertTrue(code['rows'])
            fetched=await self.request('fed_code_fetch',{'id':share['id'],'path':str(checkout)})
            self.assertTrue(fetched['ok'],fetched)
            self.assertTrue(fetched['result']['verified'])
            self.assertEqual(fetched['result']['sha'],sha)
            self.assertEqual(counts['fetch'],1)
            self.assertIsNotNone(self.store.q1('SELECT * FROM p_code_shares')['fetched'])
            management=await self.connect('host')
            with patch.object(self,'host',management):
                await self.command('identity-revoke',ref('grant'),{'authorityId':'authority-one',
                    'targetRef':self.code_grants['federation-code-publish']})
            before=counts['push']
            refused=await self.request('fed_code_share',{**args,'note':'Revoked actual Git share'})
            self.assertFalse(refused['ok'])
            self.assertEqual(counts['push'],before)
        self.assertEqual(self.raw_code_access,[])
        await self.receiver.close()
        refused=await self.request('fed_code_list',{'repo':'falcon'})
        self.assertFalse(refused['ok'])
        self.assertEqual(self.raw_code_access,[])
        await hub._code_commands.close(timeout=None)
        self.assertFalse(hub._code_commands._workers)
        await self.join_native_clients()
        self.success=True

    async def test_actual_broker_service_index_and_authenticated_held_approval(self):
        human=await self.native_session()
        service=await self.native_session(service=True)
        hub=await self.make_hub((human,service))
        fed=hub.fed
        fed.nc=await self.connect('federation')
        subject='am.code.alice.'+self.resource.repository_id
        received=asyncio.get_running_loop().create_future()
        async def on_code(message):
            try:received.set_result(await fed.receive(message.subject,message.data,message))
            except BaseException as error:received.set_exception(error)
        await fed.nc.subscribe_owned(fed.session,subject,cb=on_code)
        await fed.nc.flush(timeout=2)
        item=envelope.make('code','alice','remote',self.resource.repository_id,'*',{
            'ref':'refs/agentmux/alice/remote_feature','sha':'a'*40,'base':None,'files':['remote.py'],
            'stat':'1 file','log':'remote commit','note':'Original broker code','author':'remote/author'})
        await self.admin.publish(subject,canonical_bytes(item));await self.admin.flush(timeout=2)
        self.assertEqual(await asyncio.wait_for(received,5),'delivered')
        row=self.store.q1('SELECT * FROM p_code_shares WHERE id=?',(item['id'],))
        self.assertEqual((row['author'],row['ref'],row['note']),('remote/author',item['data']['ref'],'Original broker code'))
        self.assertTrue(await hub.db(ledger.seen,hub.store,item['id']))
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'),[])
        held=envelope.make('code','alice','remote',self.resource.repository_id,'*',{
            'ref':'refs/agentmux/alice/held_feature','sha':'b'*40,'files':['held.py'],'note':'Original held code'})
        qid=await hub.db(ledger.quarantine_add,hub.store,held,subject,'code','alice','held for operator')
        approved=await self.request('fed_approve',{'id':qid})
        self.assertTrue(approved['ok'],approved)
        self.assertEqual((await hub.db(ledger.quarantine_get,hub.store,qid))['state'],'approved')
        row=self.store.q1('SELECT * FROM p_code_shares WHERE id=?',(held['id'],))
        self.assertEqual((row['note'],row['untrusted']),('Original held code',1))
        self.assertEqual(self.raw_code_access,[])
        pending=await hub.db(hub.store.q,"SELECT * FROM fed_state WHERE k LIKE 'legacy-code-client:%'")
        self.assertEqual(pending,[])
        self.success=True
