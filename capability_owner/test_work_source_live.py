"""Actual enrolled TLS/JWT source binding before Hub maintenance activation."""
import asyncio
import base64
import copy
from datetime import datetime,timedelta,timezone
from pathlib import Path
import secrets
import unittest
from unittest.mock import patch

import nkeys

from agentmux_contracts import ContractError,canonical_bytes,payload_digest,strict_loads
from hub import server
from hub.client_launch_connection import MessageOutcomeUnconfirmed
from hub.client_launch_session import ApplicationSessionFailure
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref,SEED
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageHost
from .test_work_control_live import LiveWorkControlTests
from .work import WorkStorageResource
from .work_bridge_service import WorkBridgeService
from .work_lifecycle_client import WorkLifecycleClient
from native_security.nats_credentials import _JWT, storage_receiver_policy


class LiveWorkSourceTests(LiveWorkControlTests):
    def initial_authority(self):
        record=super().initial_authority()
        template=copy.deepcopy(record['state']['grants'][0])
        for action in ('register','state','sweep-global'):
            contract='federation-work-'+action
            grant={**copy.deepcopy(template),'ref':ref('source-native-'+action),
                'callerRef':ref('service'),'actorRef':ref('service'),'scope':copy.deepcopy(self.scope),
                'contractId':contract,'resourceId':'work-one','decision':'allowed','delegationRef':None}
            record['state']['grants'].append(grant)
            self.work_grants[contract]=grant['ref']
        return record

    async def asyncSetUp(self):
        await super().asyncSetUp()
        selected=copy.deepcopy(self.control_host._selection.policy)
        await self.receiver.close()
        await self.control_host.close(timeout=None)
        directory=self.directory/'source-hub'
        directory.mkdir(mode=0o700)
        remote=selected['storage']['work']['repository']['normalizedRemote']
        (directory/'config.toml').write_text('node="mac"\n')
        (directory/'federation.toml').write_text('[federation]\npeer="nick"\ncapture=false\n'
            'notify_findings=false\n[repos.falcon]\nremote="'+remote+'"\n[peers.alice]\ntrust="auto"\n')
        with patch.object(server,'ROOT',str(directory/'application')),patch.object(server,'HUBDIR',str(directory)):
            prepared=server.Hub()
        prepared.dbx.submit(prepared.store.repo_add,'falcon').result()
        prepared.dbx.submit(prepared.store.db.close).result()
        prepared.dbx.shutdown(wait=True)
        prepared.io.shutdown(wait=True)
        (directory/'hub.db').chmod(0o600)
        selected['storage']['work']['source']['database']['path']=str((directory/'hub.db').resolve())
        self.control_host=SelectedStorageHost(ApplicationServiceSelection(canonical_bytes(selected)),identity=self.identity)
        await self.control_host._work(selected['storage']['work'])
        self.resource=next(r for r in self.control_host._resources if type(r) is WorkStorageResource)
        bridge=WorkBridgeService(self.identity.ingress,resources=(self.resource,),
            service_identity_ref=ref('service'),service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'),signing_seed=SEED)
        self.receiver=CapabilityReplyService(self.identity.reader,resources=(self.resource,),
            hub_id='hub-one',profile_id='profile-one',authority_id='authority-one',service_id='storage-owner',
            service_identity_ref=ref('service'),service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'),signing_seed=SEED,request_signing_key_ref=ref('issuer'),
            connection=self.storage,work_bridge=bridge)
        await self.receiver.start()
        self.native_hub_directory=directory
        self.lifecycle=None
        self.addAsyncCleanup(self.source_cleanup)

    async def source_cleanup(self):
        if self.lifecycle is not None:
            await self.lifecycle.close()
        if self.actual_hub is not None:
            hub=self.actual_hub
            await hub._work_rpc.close(timeout=None)
            await hub._work_storage_commands.close(timeout=None)
            await hub.fed.finish_cleanup()
            await asyncio.wrap_future(hub.dbx.submit(hub.store.db.close))
            hub.dbx.shutdown(wait=True)
            hub.io.shutdown(wait=True)
            self.actual_hub=None

    async def test_actual_enrolled_source_binding_registration_and_revocation(self):
        async def observe():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task=asyncio.create_task(observe())
        session,owner=await self.actual_work_session()
        directory=self.native_hub_directory
        with patch.object(server,'ROOT',str(directory/'application')),patch.object(server,'HUBDIR',str(directory)):
            hub=self.actual_hub=server.Hub(work_sessions=(session,))
        self.assertIsNot(hub.store,self.resource._store)
        self.assertIsNot(hub.store.db,self.resource._connection)
        self.assertIsNot(hub.dbx,self.resource._source_worker)
        await hub._work_source_binding.activate()
        actual=strict_loads(owner.command_request)['claims']
        self.assertEqual(actual['contractId'],'federation-work-inspect')
        self.assertEqual(actual['payload']['input']['sourceBinding']['purpose'],'agentmux-work-source-binding-v1')
        self.lifecycle=WorkLifecycleClient(hub._work_storage_commands)
        registered=await self.lifecycle.register({'generation':None,'repo':'falcon','role':'worker','agent':'native',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%19','panePid':12347,
            'legacy':None,'tokenSha':'c'*64},operation_id='native-source-register',
            expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        final=strict_loads(owner.command_request)['claims']
        self.assertEqual(final['contractId'],'federation-work-outcome')
        route=session.work_enrollment()['workCommands']
        self.assertEqual(final['workSource'],{**hub._work_source_binding.pin.identity,
            'localNode':route['localNode'],
            'repository':None if route['repository'] is None else route['repository']['localName']})
        row=await hub.db(hub.store.agent,registered)
        self.assertIn(row,await hub.dispatch('agents',{},'operator'))
        self.assertEqual(row['generation'],1)
        self.assertEqual(row['token_sha'],'c'*64)
        self.assertEqual(row,await self.resource._owner.db(self.resource._store.agent,registered))
        await self.command('identity-revoke',ref('grant'),{'authorityId':'authority-one',
            'targetRef':self.work_grants['federation-work-inspect']})
        with self.assertRaises(ContractError): await hub.dispatch('agents',{},'operator')
        self.assertEqual(row,await asyncio.wrap_future(hub.dbx.submit(hub.store.agent,registered)))
        self.success=True


    async def test_lost_final_outcome_joins_original_and_recovers_without_registration(self):
        async def observe():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task=asyncio.create_task(observe())
        session,owner=await self.actual_work_session()
        directory=self.native_hub_directory
        with patch.object(server,'ROOT',str(directory/'application')),patch.object(server,'HUBDIR',str(directory)):
            hub=self.actual_hub=server.Hub(work_sessions=(session,))
        await hub._work_source_binding.activate()
        self.lifecycle=WorkLifecycleClient(hub._work_storage_commands)
        arguments={'generation':None,'repo':'falcon','role':'worker','agent':'finallost',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%26','panePid':12353,
            'legacy':None,'tokenSha':'2'*64}
        requests=[]
        bridge=self.receiver._work_bridge
        original_handle=bridge.handle
        async def received(raw,**kwargs):
            requests.append(strict_loads(raw)['claims'])
            return await original_handle(raw,**kwargs)
        publish=self.storage.publish
        dropped=[]
        async def lose_final(subject,raw,**kwargs):
            claims=strict_loads(raw).get('claims',{})
            if (not dropped and subject.startswith(self.inbox_prefixes['federation-application']+'.')
                    and claims.get('requestContractId')=='federation-work-outcome'
                    and claims.get('result',{}).get('outcome')=='applied'):
                dropped.append((raw,owner._exchange_task,session._command_future,subject))
                return
            return await publish(subject,raw,**kwargs)
        with patch.object(bridge,'handle',side_effect=received),patch.object(self.storage,'publish',side_effect=lose_final):
            with self.assertRaises(ApplicationSessionFailure):
                await self.lifecycle.register(arguments,operation_id='native-source-final-lost',
                    expires=datetime.now(timezone.utc)+timedelta(seconds=4))
            self.assertEqual(len(dropped),1)
            raw,exchange,command,inbox=dropped[0]
            self.assertIsNotNone(exchange)
            self.assertIsNotNone(command)
            # A waiter failure cannot authorize replacing a live native exchange.
            await asyncio.wait({exchange},timeout=1)
            self.assertTrue(exchange.done())
            self.assertIsInstance(exchange.exception(),TimeoutError)
            joined=asyncio.wrap_future(command)
            await asyncio.wait({joined},timeout=1)
            self.assertTrue(joined.done())
            self.assertIs(type(joined.exception()),MessageOutcomeUnconfirmed)
            self.assertIsNone(owner._exchange_task)
            self.assertFalse(any(row[0].subject==inbox for row in owner._subscriptions.values()))
            self.assertEqual(sum(row['contractId']=='federation-work-register' for row in requests),1)
            original=next(row for row in requests if row['contractId']=='federation-work-register')
            failed_query=next(row for row in requests if row['contractId']=='federation-work-outcome')
            expected={'contractId':'federation-work-register','operationId':original['operationId'],
                'payloadDigest':payload_digest(original['payload'])}
            self.assertEqual(failed_query['payload']['input'],expected)
            await self.lifecycle.close()
            self.lifecycle=WorkLifecycleClient(hub._work_storage_commands)
            before=len(requests)
            registered=await self.lifecycle.register(arguments,operation_id='native-source-final-lost',
                expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        recovered=requests[before:]
        self.assertEqual([row['contractId'] for row in recovered],
            ['federation-work-inspect','federation-work-outcome'])
        self.assertEqual(recovered[-1]['payload']['input'],expected)
        route=session.work_enrollment()['workCommands']
        source={**hub._work_source_binding.pin.identity,'localNode':route['localNode'],
            'repository':None if route['repository'] is None else route['repository']['localName']}
        self.assertEqual(failed_query['workSource'],source)
        self.assertTrue(all(row['workSource']==source for row in recovered))
        self.assertIsNone(owner._close_task)
        self.assertEqual(registered,strict_loads(raw)['claims']['result']['result'])
        self.assertEqual(sum(row['contractId']=='federation-work-register' for row in requests),1)
        row=await hub.db(hub.store.agent,registered)
        self.assertEqual(row['generation'],1)
        self.assertEqual(row['token_sha'],'2'*64)
        self.assertEqual(await hub.db(hub.store.q1,
            "SELECT count(*) n FROM events WHERE event='registered' AND entity_id=?",(registered,)),{'n':1})
        self.assertEqual(row,await self.resource._owner.db(self.resource._store.agent,registered))
        self.success=True


class NotificationBindingAdmissionTests(LiveWorkSourceTests):
    def initial_authority(self):
        record = super().initial_authority()
        grant = {**copy.deepcopy(record['state']['grants'][0]),
            'ref': ref('notification-binding-read'), 'callerRef': ref('service'),
            'actorRef': ref('service'), 'scope': copy.deepcopy(self.scope),
            'contractId': 'federation-work-read', 'resourceId': 'work-one',
            'decision': 'allowed', 'delegationRef': None}
        record['state']['grants'].append(grant)
        self.work_grants['federation-work-read'] = grant['ref']
        return record

    async def test_notification_budget_starts_after_maintenance_admission(self):
        import json
        import time
        from contextlib import asynccontextmanager
        from .legacy_work_notifications import LegacyWorkNotifications

        async def observe():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task = asyncio.create_task(observe())
        measurements = []
        for queued in (False, True):
            session, owner = await self.actual_work_session()
            directory = self.native_hub_directory
            with patch.object(server, 'ROOT', str(directory / 'application')), \
                    patch.object(server, 'HUBDIR', str(directory)):
                hub = self.actual_hub = server.Hub(work_sessions=(session,))
            await hub._work_source_binding.activate()
            maintenance = hub._maintenance_for_work()
            commands = hub._work_storage_commands
            notices = LegacyWorkNotifications(hub, commands)
            observed = {'queued': queued, 'replyDelay': 2.0}
            entered, published = asyncio.Event(), asyncio.Event()
            requests, delayed = [], []
            original_read = commands._read_current
            original_turn = commands._read_turn
            original_before = hub._work_source_binding.before_call
            original_binding = owner._current_command_binding
            original_publish = owner._client.publish
            identity_publish = self.identity._connection.publish
            identity_handle = self.identity.handle

            async def handle(raw):
                try:
                    return await identity_handle(raw)
                except ContractError as error:
                    observed['identityRefusal'] = error.code
                    raise

            def remaining():
                return (observed['expires'] - datetime.now(timezone.utc)).total_seconds()

            async def read(routes, query, expires, **kwargs):
                observed.update(expires=expires, creationRemaining=(expires - datetime.now(timezone.utc)).total_seconds())
                return await original_read(routes, query, expires, **kwargs)

            @asynccontextmanager
            async def turn(routes):
                started = time.monotonic()
                entered.set()
                async with original_turn(routes):
                    observed['admissionWait'] = time.monotonic() - started
                    yield

            async def before(current, expires):
                self.assertEqual(expires, observed['expires'])
                observed['admissionRemaining'] = remaining()
                return await original_before(current, expires)

            async def binding(**kwargs):
                observed.update(bindingRemaining=remaining(), bindingDeadline=kwargs['deadline'],
                    bindingDeadlineRemaining=kwargs['deadline'] - time.monotonic())
                return await original_binding(**kwargs)

            async def publish(subject, raw, **kwargs):
                claims = strict_loads(raw).get('claims', {})
                requests.append(claims)
                if claims.get('purpose') == 'agentmux-application-binding-request-v1':
                    observed['bindingRequestRemaining'] = remaining()
                    observed['bindingRequestExpires'] = claims['expiresAt']
                return await original_publish(subject, raw, **kwargs)

            async def reply(subject, raw, **kwargs):
                if not subject.startswith(owner._reply_prefix + '.'):
                    return await identity_publish(subject, raw, **kwargs)
                claims = strict_loads(raw).get('claims', {})
                if (subject.startswith(owner._reply_prefix + '.')
                        and claims.get('purpose') == 'agentmux-application-binding-response-v1'):
                    observed['replyCreatedRemaining'] = remaining()
                    async def original_reply():
                        try:
                            await asyncio.sleep(2)
                            observed['replyPublishedRemaining'] = remaining()
                            return await identity_publish(subject, raw, **kwargs)
                        finally:
                            published.set()
                    original = asyncio.create_task(original_reply())
                    delayed.append(original)
                    return await asyncio.shield(original)
                return await identity_publish(subject, raw, **kwargs)

            task = None
            try:
                with patch.object(commands, '_read_current', side_effect=read), \
                        patch.object(commands, '_read_turn', side_effect=turn), \
                        patch.object(hub._work_source_binding, 'before_call', side_effect=before), \
                        patch.object(owner, '_current_command_binding', side_effect=binding), \
                        patch.object(owner._client, 'publish', side_effect=publish), \
                        patch.object(self.identity._connection, 'publish', side_effect=reply), \
                        patch.object(self.identity, 'handle', side_effect=handle):
                    if queued:
                        async with maintenance.observation_read_turn():
                            task = asyncio.create_task(notices._read('falcon'))
                            await asyncio.wait_for(entered.wait(), 2)
                            self.assertNotIn('expires', observed)
                            await asyncio.sleep(3.5)
                    else:
                        task = asyncio.create_task(notices._read('falcon'))
                    rows, _ = await task
                    self.assertEqual(rows, [])
                    self.assertIsNone(session._command_future)
                    self.assertIsNone(owner._close_task)
                    observed['completionRemaining'] = remaining()
                    await asyncio.wait_for(published.wait(), 3)
                    self.assertEqual(len(delayed), 1)
                    # Join the delayed publication; service teardown owns its surrounding callback.
                    await asyncio.gather(*delayed)
                    reads = [r for r in requests if r.get('contractId') == 'federation-work-read']
                    self.assertEqual(len(reads), 1)
                    self.assertGreater(observed['creationRemaining'], 4.5)
                    self.assertLessEqual(observed['creationRemaining'], 5)
                    self.assertGreater(observed['bindingRemaining'], 4.5)
                    self.assertLessEqual(observed['bindingRemaining'], 5)
                    if queued:self.assertGreaterEqual(observed['admissionWait'], 3.5)
                    # Binding uses the unchanged monotonic transport deadline;
                    # the Work request also takes the exact wall-clock expiry minimum.
                    self.assertLessEqual(observed['bindingDeadlineRemaining'], observed['bindingRemaining'] + .05)
                    if reads:
                        self.assertLessEqual(datetime.fromisoformat(reads[0]['expiresAt']), observed['expires'])
                        route = session.work_enrollment()['workCommands']
                        self.assertEqual(reads[0]['payload']['input'], {'query': {'kind': 'list', 'state': None}})
                        self.assertEqual(reads[0]['workSource'], {**hub._work_source_binding.pin.identity,
                            'localNode': route['localNode'], 'repository': 'falcon'})
                    measurements.append({**observed, 'expires': observed['expires'].isoformat()})
            finally:
                if task is not None and task.done() and not task.cancelled():
                    error = task.exception()
                    if isinstance(error, ApplicationSessionFailure):
                        print('notification-binding-failure', json.dumps({
                            'observed': {**observed, 'expires': observed.get('expires').isoformat()},
                            'diagnostic': getattr(error, '_command_diagnostic', None),
                            'requestPurposes': [r.get('purpose') for r in requests]}), flush=True)
                if task is not None:
                    if not task.done(): task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                if delayed:
                    await asyncio.gather(*delayed, return_exceptions=True)
                try:
                    await notices.close()
                    await hub._close_work_maintenance()
                    await self.source_cleanup()
                finally:
                    await owner.close(deadline=asyncio.get_running_loop().time() + 2)
        print('notification-binding-measurements', json.dumps(measurements), flush=True)
        self.success = True


class LiveSelectedWorkSourceTests(unittest.IsolatedAsyncioTestCase):
    """Compose the native fixture without discovering its manual-receiver tests."""

    class Fixture(LiveWorkSourceTests):
        def configure_broker_policies(self, policies, reads):
            super().configure_broker_policies(policies, reads)
            for name in ('storage', 'outcome'):
                role = 'selected-' + name
                prefix = self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
                policy = storage_receiver_policy(hub_id='hub-one', scope=self.scope,
                    service_id=name + '-owner', reply_prefix=prefix)
                policies[role] = {'publish': {'allow': list(policy.publish_subjects)},
                    'subscribe': {'allow': list(policy.subscribe_subjects)}}

        def _configure_tls_and_users(self):
            super()._configure_tls_and_users()
            paths = list((self.directory / 'nsc-keys').rglob(self.account_public_key + '.nk'))
            if len(paths) != 1:
                raise RuntimeError('selected_work_fixture_account_key_unavailable')
            account = nkeys.from_seed(paths[0].read_bytes().strip())
            try:
                for name in ('storage', 'outcome'):
                    role = 'selected-' + name
                    path = self.credentials[role]
                    raw = path.read_bytes()
                    token = _JWT.findall(raw)[0]
                    header, body, _ = token.split(b'.')
                    claims = strict_loads(base64.urlsafe_b64decode(body + b'=' * (-len(body) % 4)))
                    policy = storage_receiver_policy(hub_id='hub-one', scope=self.scope,
                        service_id=name + '-owner', reply_prefix=self.inbox_prefixes[role])
                    claims['nats'].update(pub={'allow': list(policy.publish_subjects)},
                        sub={'allow': list(policy.subscribe_subjects)}, resp=policy.response_permissions)
                    claims.pop('jti', None)
                    body = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                    updated = header + b'.' + body
                    updated += b'.' + base64.urlsafe_b64encode(account.sign(updated)).rstrip(b'=')
                    path.write_bytes(raw.replace(token, updated, 1))
            finally:
                account.wipe()

        def initial_authority(self):
            record = super().initial_authority()
            state = record['state']
            for name, pin in self.value['storage']['receivers'].items():
                state['identities'].append({'ref': pin['serviceIdentityRef'], 'kind': 'service',
                    'status': 'active', 'principalId': name + '-service', 'externalIdentity': None})
                state['issuers'].append({'ref': pin['issuer']['issuerRef'],
                    'identityRef': pin['serviceIdentityRef'], 'instanceId': pin['serviceInstanceId'],
                    'publicKey': pin['issuer']['publicKey'], 'status': 'active',
                    'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
            return record

        async def asyncSetUp(self):
            await super().asyncSetUp()
            selected = copy.deepcopy(self.control_host._selection.policy)
            await self.receiver.close()
            await self.control_host.close(timeout=None)
            selected['storage'] = {name: selected['storage'][name]
                for name in ('scope', 'receivers', 'work')}
            selected['storage']['work']['channels'][0]['pluginIdentityRef'] = ref('plugin')
            selected.pop('peerControl', None)
            connection = {**selected['identity']['connection']}
            for name, pin in selected['storage']['receivers'].items():
                role = 'selected-' + name
                credential, _ = self._credential(role)
                pin['connection'] = copy.deepcopy(connection)
                pin['credentials'] = {**credential, 'accountPublicKey': self.account_public_key,
                    'replyPrefix': self.inbox_prefixes[role]}
            self.selected_receivers = selected['storage']['receivers']
            self.control_host = SelectedStorageHost(
                ApplicationServiceSelection(canonical_bytes(selected)), identity=self.identity)
            try:
                await self.control_host.start()
            except ContractError as error:
                raise error from getattr(error, '_cause', None)
            self.control_host.check_health()
            self.resource = next(r for r in self.control_host._resources if type(r) is WorkStorageResource)
            self.receiver = next(r for r in self.control_host._receivers if r._work_bridge is not None)

        def application_key(self, *, service=False):
            original = super().application_key(service=service)
            key = strict_loads(original._material)
            pin = self.selected_receivers['storage']
            key['messageCommands'].update(replyIssuerRef=pin['issuer']['issuerRef'],
                replyIssuerPublicKey=pin['issuer']['publicKey'],
                serviceIdentityRef=pin['serviceIdentityRef'], serviceInstanceId=pin['serviceInstanceId'])
            return type(original)(key)

        async def qualify_normal_selected_work(self):
            async def observe():
                while True:
                    self.refresh_observation()
                    await asyncio.sleep(.25)
            self._observation_task = asyncio.create_task(observe())
            session, owner = await self.actual_work_session()
            directory = self.native_hub_directory
            with patch.object(server, 'ROOT', str(directory / 'application')), \
                    patch.object(server, 'HUBDIR', str(directory)):
                hub = self.actual_hub = server.Hub(work_sessions=(session,))
            source = self.resource._source
            self.assertTrue(self.control_host._starting.done())
            self.assertEqual(len(self.control_host._receivers), 2)
            self.assertTrue(all(receiver._subscription is not None
                for receiver in self.control_host._receivers))
            self.assertIsNot(hub.store.db, self.resource._connection)
            self.assertEqual(Path(hub.store.path).resolve(),
                Path(source._pins['database']['path']).resolve())
            await hub._work_source_binding.activate()
            self.lifecycle = WorkLifecycleClient(hub._work_storage_commands)
            registered = await self.lifecycle.register({'generation': None, 'repo': 'falcon',
                'role': 'worker', 'agent': 'selected', 'cli': 'codex', 'roleSnapshot': {},
                'transport': 'tmux', 'handle': '%39', 'panePid': 12359,
                'legacy': None, 'tokenSha': '3' * 64}, operation_id='native-selected-register',
                expires=datetime.now(timezone.utc) + timedelta(seconds=4))
            row = await hub.db(hub.store.agent, registered)
            self.assertIn(row, await hub.dispatch('agents', {}, 'operator'))
            self.assertEqual(row['generation'], 1)
            self.assertEqual(row['token_sha'], '3' * 64)
            self.assertEqual(row, await self.resource._owner.db(self.resource._store.agent, registered))
            self.assertEqual(await hub.db(hub.store.q1,
                "SELECT count(*) n FROM events WHERE event='registered' AND entity_id=?", (registered,)), {'n': 1})
            claims = strict_loads(owner.command_request)['claims']
            route = session.work_enrollment()['workCommands']
            self.assertEqual(claims['workSource'], {**hub._work_source_binding.pin.identity,
                'localNode': route['localNode'], 'repository': route['repository']['localName']})
            await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one',
                'targetRef': self.work_grants['federation-work-inspect']})
            with self.assertRaises(ContractError):
                await hub.dispatch('agents', {}, 'operator')
            self.assertEqual(row, await asyncio.wrap_future(hub.dbx.submit(hub.store.agent, registered)))
            await self.source_cleanup()
            for application_owner in self.application_owners:
                await application_owner.close(deadline=asyncio.get_running_loop().time() + 2)
                self.assertIsNone(application_owner._exchange_task)
            await self.control_host.close(timeout=None)
            self.assertTrue(self.control_host._closing.done())
            self.assertTrue(source._closing.done())
            self.assertIsNone(source._store)
            self.assertTrue(all(not client.is_connected for client in self.control_host._clients))
            self.success = True

    @classmethod
    def setUpClass(cls):
        cls.Fixture.setUpClass()

    async def asyncSetUp(self):
        fixture = self.fixture = self.Fixture()
        # The running case owns every cleanup registered by the borrowed fixture.
        fixture.addCleanup = self.addCleanup
        fixture.addAsyncCleanup = self.addAsyncCleanup
        fixture.setUp()
        await fixture.asyncSetUp()

    async def test_normal_selected_start_serves_original_hub_work_and_revocation(self):
        loader = unittest.defaultTestLoader
        self.assertEqual(loader.getTestCaseNames(type(self)), [self._testMethodName])
        self.assertIn('test_lost_final_outcome_joins_original_and_recovers_without_registration',
            loader.getTestCaseNames(LiveWorkSourceTests))
        await self.fixture.qualify_normal_selected_work()
