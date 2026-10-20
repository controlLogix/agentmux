"""Signed admission binds actual Hub reads to the selected original source."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import server
from hub.client_launch_session import ApplicationClientSession
from hub.store import Store
from hub.tests.test_work_client_transport import material
from identity.application_client import ApplicationClientKey
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from .test_selected_work_lifecycle import SelectedWorkLifecycleTests
from .work import WorkStorageResource
from .work_lifecycle_client import WorkLifecycleClient
from .work_source import HubWorkSourceBinding


class SelectedWorkSourceFixture:
    def setUp(self):
        SelectedWorkLifecycleTests.setUp(self)
        # This is the existing Hub location selected before either owner opens.
        original = str(self.database)
        self.database = self.database.with_name('hub.db')
        Path(original).rename(self.database)
        def repin(value):
            if type(value) is dict:
                for key,item in value.items():
                    if key=='path' and item==original:
                        value[key]=str(self.database)
                    else:
                        repin(item)
            elif type(value) is list:
                for item in value: repin(item)
        repin(self.value)
        # Prepare the original Hub's existing plugin schema before selected
        # ownership freezes it. Qualified startup may not create missing tables.
        with patch.object(server,'ROOT',str(self.database.parent/'application')), \
                patch.object(server,'HUBDIR',str(self.database.parent)), \
                patch.object(server,'load_toml',return_value={'node':'mac'}):
            hub=server.Hub()
        hub.dbx.submit(hub.store.db.close).result()
        hub.dbx.shutdown(wait=True)
        hub.io.shutdown(wait=True)
        self.selection=self.selected()
    asyncSetUp = SelectedWorkLifecycleTests.asyncSetUp
    connection = SelectedWorkLifecycleTests.connection
    custody = SelectedWorkLifecycleTests.custody
    selected = SelectedWorkLifecycleTests.selected
    add_board = SelectedWorkLifecycleTests.add_board
    identity_inputs = SelectedWorkLifecycleTests.identity_inputs
    authority_record = SelectedWorkLifecycleTests.authority_record
    reopen = SelectedWorkLifecycleTests.reopen
    configured_host = SelectedWorkLifecycleTests.configured_host

    def configure_channels(self, **kwargs):
        SelectedWorkLifecycleTests.configure_channels(self, **kwargs)
        record = strict_loads(self.snapshot.record)
        for index, channel in enumerate(self.value['storage']['work']['channels']):
            actor = channel['legacyActors'][0]
            for action in ('inspect', 'outcome','return-leases'):
                contract = 'federation-work-' + action
                grant = ref('source-' + str(index) + '-' + action)
                actor['grants'][contract] = grant
                record['state']['grants'].append({'ref': grant, 'callerRef': ref('storage-service'),
                    'actorRef': ref('storage-service'), 'scope': copy.deepcopy(channel.get('scope',self.scope)),
                    'contractId': contract, 'resourceId': channel['resourceRef']['id'], 'decision': 'allowed',
                    'delegationRef': None, 'definitionTarget': None, 'status': 'active',
                    'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
        self.selection = self.selected()

    async def setup_source(self, *, same=True):
        host = await self.configured_host()
        async def current():
            return self.snapshot
        self.enterContext(patch.object(self.identity.reader, 'current', side_effect=current))
        self.resources = sorted((r for r in host._resources if type(r) is WorkStorageResource),
            key=lambda r: r.repository)
        self.submitted, self.replies = [], []
        self.before_exchange = None
        self.sessions = self.sessions_for(self.resources)
        if same:
            directory = self.database.parent
        else:
            directory = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
            store = Store(str(directory / 'hub.db'))
            store.repo_add('falcon')
            store.db.close()
            (directory / 'hub.db').chmod(0o600)
        with patch.object(server, 'ROOT', str(directory / 'application')), \
                patch.object(server, 'HUBDIR', str(directory)), \
                patch.object(server, 'load_toml', return_value={'node': 'mac'}):
            if not same:
                prepared=server.Hub()
                prepared.dbx.submit(prepared.store.db.close).result()
                prepared.dbx.shutdown(wait=True)
                prepared.io.shutdown(wait=True)
            self.hub = server.Hub(work_sessions=self.sessions)
        self.addAsyncCleanup(self.close_hub)
        self.assertIsNot(self.hub.store, self.resources[0]._store)
        self.assertIsNot(self.hub.store.db, self.resources[0]._connection)
        self.assertIsNot(self.hub.dbx, self.resources[0]._source_worker)
        return self.hub

    async def close_hub(self):
        if self.hub._work_start_cleanup is not None:
            await self.hub._close_failed_work_start()
            return
        lifecycle = getattr(self.hub, '_work_lifecycle_client', None)
        if lifecycle is not None:
            await lifecycle.close()
        await self.hub._work_rpc.close(timeout=None)
        await self.hub._work_storage_commands.close(timeout=None)
        await self.hub.fed.finish_cleanup()
        await asyncio.wrap_future(self.hub.dbx.submit(self.hub.store.db.close))
        self.hub.dbx.shutdown(wait=True)
        self.hub.io.shutdown(wait=True)

    def sessions_for(self, resources):
        return tuple(self.session_for(resource) for resource in resources)

    def session_for(self, resource, *, actor=None, seed=None):
        actor = resource._legacy_actors[0] if actor is None else actor
        enrollment = material()
        enrollment.update(hubId='hub-one', profileId=self.value['kernelScope']['profileId'],
            authorityId=self.value['authorityId'], callerRef=strict_loads(actor.identity_ref),
            scope=strict_loads(resource.binding.scope),
            seed=base64.b64encode(bytes([51]) * 32 if seed is None else seed).decode())
        scope, pin = enrollment['scope'], self.value['storage']['receivers']['storage']
        enrollment['workCommands'].update(authenticatedCaller=actor.caller, localPeer=None,
            localNode='mac', repository={'localName': resource.repository, 'repositoryId': None},
            transportRef=strict_loads(actor.transport_ref),
            subject='.'.join(('amx','v1','h','hub-one','o',scope['organizationId'],'p',scope['projectId'],
                'w',scope['workspaceId'] or '_','capability','storage-owner','command')),
            serviceIdentityRef=pin['serviceIdentityRef'], serviceInstanceId=pin['serviceInstanceId'],
            replyIssuerRef=pin['issuer']['issuerRef'], replyIssuerPublicKey=pin['issuer']['publicKey'],
            resourceRef=ref(resource.binding.entity_id), grantRefs=strict_loads(actor.grants))
        key = ApplicationClientKey(enrollment)
        selected = key.selection
        session = object.__new__(ApplicationClientSession)
        session._work_enrollment = canonical_bytes({k: selected[k] for k in
            ('hubId','profileId','authorityId','callerRef','scope','workCommands')})
        session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = None
        loop = asyncio.get_running_loop()
        endpoint = next(e for e in self.host._receivers if e._service == 'storage-owner'
            and e._scope == resource.binding.scope)
        def submit(*, contract_id, operation_id, payload, expires_at, deadline, include_valid_until=False,
                   source_expectation=None):
            route = selected['workCommands']
            now = datetime.now(timezone.utc)
            claims = {'purpose':'agentmux-client-possession-v1',
                **{k:selected[k] for k in ('hubId','profileId','authorityId')},
                'transportRef':route['transportRef'], 'grantRef':route['grantRefs'][contract_id],
                'operationId':operation_id, 'expectedVersion':payload['resourceRef']['revision'],
                'contractId':contract_id, 'payload':payload, 'approvalRefs':[],
                'issuedAt':now.isoformat().replace('+00:00','Z'), 'expiresAt':expires_at,
                'replySubject':'_INBOX.work_source_actual_' + resource.repository}
            if source_expectation is not None:
                claims['workSource']=source_expectation
            raw = key.sign_command(claims, subject=route['subject'], now=now)
            self.submitted.append(copy.deepcopy(claims))
            async def exchange():
                if self.before_exchange is not None:
                    await self.before_exchange(claims)
                try:
                    return await endpoint.handle(raw, received_reply_subject=claims['replySubject'])
                except Exception as error:
                    chain=[]
                    current=error
                    while current is not None and len(chain)<8:
                        chain.append(type(current).__name__ + ':' +
                            (current.code if isinstance(current,ContractError) else 'closed'))
                        current=current.__context__
                    error.add_note('Private test cause categories: ' + ','.join(chain))
                    raise
            response = asyncio.run_coroutine_threadsafe(exchange(), loop).result(timeout=6)
            self.replies.append(strict_loads(response))
            return key.verify_command_response(response, raw, subject=route['subject'],
                now=datetime.now(timezone.utc), include_valid_until=include_valid_until)
        session.work_command = submit
        return session


class SelectedWorkSourceTests(SelectedWorkSourceFixture,unittest.IsolatedAsyncioTestCase):
    async def test_same_original_two_owned_connections_show_registration_in_actual_hub(self):
        hub = await self.setup_source()
        client = WorkLifecycleClient(hub._work_storage_commands)
        await hub._work_source_binding.activate()
        session = await client.register({'generation':None,'repo':'falcon','role':'worker','agent':'registered',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%17','panePid':12345,
            'legacy':None,'tokenSha':'a'*64}, operation_id='source-registration',
            expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        roster = await hub.dispatch('agents', {}, 'operator')
        row=await hub.db(hub.store.agent,session)
        self.assertIn(row, roster)
        self.assertEqual(await hub.db(hub.store.registration, row['session']),
            await self.resources[0]._owner.db(self.resources[0]._store.registration,row['session']))
        self.assertEqual((await hub.db(hub.store.agent,row['session']))['generation'],1)
        self.assertNotIn(str(self.database), canonical_bytes(self.replies).decode())
        self.assertTrue(all(p['contractId']=='federation-work-inspect' for p in self.submitted[:2]))
        inspected=[p for p in self.submitted if p['operationId'].startswith('lifecycle_inspect_')]
        self.assertEqual(len(inspected),2)
        receipts={p['claims']['result']['resourceRef']['id']:p['claims']['result']['resourceRef']
            for p in self.replies if p['claims']['requestContractId']=='federation-work-register'}
        outcomes=[p for p in self.submitted if p['contractId']=='federation-work-outcome']
        self.assertEqual(len(outcomes),2)
        for outcome in outcomes:
            self.assertEqual(outcome['payload']['resourceRef'],receipts[outcome['payload']['resourceRef']['id']])

    async def test_different_original_refuses_activation_before_registration_or_roster_effect(self):
        hub = await self.setup_source(same=False)
        before = await self.resources[0]._owner.db(lambda:list(self.resources[0]._store.db.iterdump()))
        with self.assertRaisesRegex(ContractError,'work_source_binding_refused'):
            await hub.dispatch('agents', {}, 'operator')
        self.assertTrue(all(p['contractId']=='federation-work-inspect' for p in self.submitted))
        self.assertEqual(before, await self.resources[0]._owner.db(
            lambda:list(self.resources[0]._store.db.iterdump())))
        self.assertEqual(await hub.db(hub.store.agents), [])

    async def test_physical_replacement_refuses_original_connection(self):
        hub = await self.setup_source()
        await hub._work_source_binding.activate()
        replacement = self.database.with_name('replacement.db')
        store = Store(str(replacement)); store.db.close()
        self.database.rename(self.database.with_name('retained.db'))
        replacement.rename(self.database)
        with self.assertRaises((ContractError, server.HubError)):
            await hub.dispatch('agents', {}, 'operator')

    async def test_revoked_inspect_refuses_current_source_use(self):
        hub = await self.setup_source()
        await hub._work_source_binding.activate()
        record = strict_loads(self.snapshot.record)
        grant = strict_loads(self.resources[0]._legacy_actors[0].grants)['federation-work-inspect']
        next(g for g in record['state']['grants'] if g['ref']==grant)['status']='revoked'
        self.snapshot = AuthoritySnapshot(canonical_bytes(record),self.snapshot.sequence)
        with self.assertRaises(ContractError):
            await hub.dispatch('agents', {}, 'operator')
        self.assertEqual(await hub.db(hub.store.agents), [])

    async def test_enrollment_scope_or_profile_substitution_refuses_before_exchange(self):
        hub = await self.setup_source()
        await hub._work_source_binding.activate()
        for field in ('profileId','scope'):
            original = self.sessions[0]._work_enrollment
            value = strict_loads(original)
            if field=='scope': value[field]['projectId']='substituted'
            else: value[field]='substituted'
            self.sessions[0]._work_enrollment=canonical_bytes(value)
            count = len(self.submitted)
            try:
                with self.assertRaises(ContractError):
                    await hub.dispatch('agents', {}, 'operator')
                self.assertEqual(len(self.submitted),count)
            finally:
                self.sessions[0]._work_enrollment=original

    async def test_cancelled_admission_joins_same_original_exchange(self):
        hub = await self.setup_source()
        entered, release = asyncio.Event(), asyncio.Event()
        async def block(claims):
            entered.set()
            await release.wait()
        self.before_exchange=block
        task=asyncio.create_task(hub._work_source_binding.activate())
        await asyncio.wait_for(entered.wait(),2)
        original=hub._work_source_binding.activation
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertIs(hub._work_source_binding.activation,original)
        release.set()
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertTrue(original.done())
        self.assertEqual(hub._work_source_binding.pending,set())
        self.assertEqual(len(self.submitted),2)

    async def test_schema_generation_change_refuses_without_rebinding(self):
        hub = await self.setup_source()
        await hub._work_source_binding.activate()
        source=self.resources[0]._source
        await source.db(source._store.db.execute,'CREATE TABLE source_generation_changed (id TEXT)')
        with self.assertRaises(ContractError):
            await hub.dispatch('agents', {}, 'operator')

    async def test_main_source_refusal_joins_clients_database_and_executors(self):
        hub=await self.setup_source(same=False)
        with patch('asyncio.start_unix_server',side_effect=AssertionError('listener before admission')):
            with self.assertRaises(ContractError):
                await hub.main()
        self.assertTrue(hub._work_start_cleanup.done())
        self.assertTrue(hub.dbx._shutdown)
        self.assertTrue(hub.io._shutdown)
        self.assertTrue(hub._work_storage_commands._closed)
        self.assertFalse(hub._work_storage_commands._workers)
        self.assertFalse(hub._work_source_binding.pending)
        self.assertTrue(all(p['contractId']=='federation-work-inspect' for p in self.submitted))

    async def test_cancelled_main_startup_joins_original_proof_before_close(self):
        hub=await self.setup_source()
        entered,release=asyncio.Event(),asyncio.Event()
        async def block(claims):
            entered.set()
            await release.wait()
        self.before_exchange=block
        task=asyncio.create_task(hub.main())
        await asyncio.wait_for(entered.wait(),2)
        original=hub._work_source_binding.activation
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertFalse(hub.dbx._shutdown)
        release.set()
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertIs(hub._work_source_binding.activation,original)
        self.assertTrue(original.done())
        self.assertTrue(hub.dbx._shutdown)
        self.assertTrue(hub._work_start_cleanup.done())

    async def test_role_preparation_failure_closes_admitted_startup(self):
        hub=await self.setup_source()
        with patch.object(hub,'_seed_roles',side_effect=PermissionError('controlled role preparation')):
            with self.assertRaises(PermissionError): await hub.main()
        self.assertTrue(hub._work_start_cleanup.done())
        self.assertTrue(hub.dbx._shutdown)
        self.assertTrue(hub.io._shutdown)

    async def test_schema_change_after_signed_proof_refuses_lifecycle_commit(self):
        hub=await self.setup_source()
        client=WorkLifecycleClient(hub._work_storage_commands)
        await hub._work_source_binding.activate()
        original=await hub.db(hub.store.q,'SELECT * FROM work_items')
        changed=False
        async def replace_generation(claims):
            nonlocal changed
            if claims['contractId']=='federation-work-register' and not changed:
                changed=True
                source=self.resources[0]._source
                await source.db(source._store.db.execute,'CREATE TABLE source_changed_before_commit (id TEXT)')
        self.before_exchange=replace_generation
        with self.assertRaises(ContractError):
            await client.register({'generation':None,'repo':'falcon','role':'worker','agent':'refused',
                'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%18','panePid':12346,
                'legacy':None,'tokenSha':'b'*64},operation_id='schema-before-commit',
                expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        self.assertTrue(changed)
        self.assertEqual(await asyncio.wrap_future(hub.dbx.submit(hub.store.agents)),[])
        self.assertEqual(await asyncio.wrap_future(hub.dbx.submit(hub.store.q,'SELECT * FROM work_items')),original)

    async def test_schema_change_between_proof_and_actual_hub_read_is_fenced_on_worker(self):
        hub=await self.setup_source()
        await hub._work_source_binding.verify()
        source=self.resources[0]._source
        await source.db(source._store.db.execute,'CREATE TABLE source_changed_before_read (id TEXT)')
        called=[]
        def read_roster():
            called.append(True)
            return hub.store.agents()
        with self.assertRaises(ContractError): await hub.db(read_roster)
        self.assertEqual(called,[])


class WorkSourceSchedulingTests(unittest.IsolatedAsyncioTestCase):
    def test_source_refusal_site_is_closed_and_logging_cannot_replace_failure(self):
        import json
        from types import SimpleNamespace
        from .work_source import WorkSourcePin, _refuse
        pin = object.__new__(WorkSourcePin)
        pin.store, pin.connection = SimpleNamespace(db=object()), object()
        with patch('hub.server.log') as log:
            with self.assertRaisesRegex(ContractError, '^work_source_binding_refused$'):
                pin.check()
            label, raw = log.call_args.args
            self.assertEqual(label, 'work source refusal site')
            record = json.loads(raw)
            self.assertEqual(set(record), {'file', 'line'})
            self.assertEqual(record['file'], 'work_source.py')
            self.assertIs(type(record['line']), int)
            self.assertGreater(record['line'], 0)
        with patch('hub.server.log') as log:
            with self.assertRaisesRegex(ContractError, '^work_source_binding_refused$'):
                _refuse()
            self.assertEqual(json.loads(log.call_args.args[1]),
                {'file': 'work_source.py', 'line': None})
        with patch('hub.server.log', side_effect=RuntimeError('private logging error')):
            with self.assertRaisesRegex(ContractError, '^work_source_binding_refused$'):
                pin.check()

    async def test_route_refusal_keeps_original_future_and_closed_diagnostic(self):
        from concurrent.futures import Future
        import json
        import time
        class PrivateExceptionName(Exception):
            pass
        future = Future()
        original = PrivateExceptionName('private route and credential details')
        future.set_exception(original)
        session = object.__new__(ApplicationClientSession)
        session._command_future = future
        session._command_identity = ('private original intent',)
        failure = session._command_failure('wait', future, time.monotonic() + 1, original)
        diagnostic = copy.deepcopy(failure._command_diagnostic)
        for logging_fails in (False, True):
            with self.subTest(logging_fails=logging_fails):
                binding = object.__new__(HubWorkSourceBinding)
                binding.routes = ((object(), b'private route'), (object(), b'other route'))
                binding.pending = set()
                finished = []
                async def prove(route, raw, expires):
                    await asyncio.sleep(0)
                    finished.append(route)
                    raise failure if raw == b'private route' else original
                binding._prove = prove
                with patch('hub.server.log',
                           side_effect=RuntimeError('private logging failure') if logging_fails else None) as log:
                    with self.assertRaisesRegex(ContractError, '^work_source_binding_refused$'):
                        await binding._all_routes(datetime.now(timezone.utc) + timedelta(seconds=4))
                self.assertEqual(len(finished), 2)
                self.assertEqual(binding.pending, set())
                self.assertIs(session._command_future, future)
                self.assertIs(future.exception(), original)
                self.assertEqual(session._command_identity, ('private original intent',))
                self.assertEqual(failure._command_diagnostic, diagnostic)
                if not logging_fails:
                    self.assertEqual([(call.args[0], json.loads(call.args[1]))
                        for call in log.call_args_list[:3]], [
                            ('work source route refusal', {'category': 'application-session-failure'}),
                            ('application command diagnostic', diagnostic),
                            ('work source route refusal', {'category': 'other'})])
                    self.assertEqual(log.call_args_list[-1].args[0], 'work source refusal site')
                    self.assertNotIn('private', repr(log.call_args_list))

    async def test_64_original_proofs_are_bounded_and_cancellation_joins_them(self):
        # This isolates dispatch/join scheduling. Actual signatures, sources and
        # mutations are qualified by the selected and native tests above.
        binding=object.__new__(HubWorkSourceBinding)
        binding.routes=tuple((object(),str(index).encode()) for index in range(64))
        binding.pending=set()
        binding._proof_slots=asyncio.Semaphore(8)
        binding.check=lambda:None
        entered,release=asyncio.Event(),asyncio.Event()
        active=maximum=finished=0
        async def held(session,raw,expires):
            nonlocal active,maximum,finished
            active+=1
            maximum=max(maximum,active)
            if active==8: entered.set()
            await release.wait()
            active-=1
            finished+=1
            return expires
        binding._prove_current=held
        original=asyncio.create_task(binding._all_routes(datetime.now(timezone.utc)+timedelta(seconds=4)))
        await asyncio.wait_for(entered.wait(),1)
        self.assertEqual(maximum,8)
        original.cancel()
        await asyncio.sleep(0)
        self.assertFalse(original.done())
        release.set()
        with self.assertRaises(asyncio.CancelledError): await original
        self.assertEqual(finished,64)
        self.assertEqual(binding.pending,set())
