"""Configured legacy Work cannot silently lose its selected transport."""
import asyncio
import base64
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import time
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from dashboard.test_application_service_host import Client
from identity.authority import AuthoritySnapshot
from identity.core_work_transport import INGEST, RESULT
from identity.test_authority import ref
from native_security.nats_credentials import _base32
from hub import server
from hub.store import HubError
from hub.tests.test_bridge_selection import Connection
from . import test_work_source as source_support
from .test_core_work_owner import credential
from .test_core_work_selection import add_core_route
from .work_lifecycle_client import WorkLifecycleClient
from .core_work_roles import CoreWorkRoles
from . import work_legacy
from .work_bridge_service import WorkBridgeService


class WorkBridgeCompositionTests(source_support.SelectedWorkSourceFixture,
                                  unittest.IsolatedAsyncioTestCase):
    def configure_channels(self, **kwargs):
        super().configure_channels(**kwargs)
        if not getattr(self, 'protected_mode', False):
            return
        record = strict_loads(self.snapshot.record)
        channel = self.value['storage']['work']['channels'][0]
        route = add_core_route(self.value, self.root, channel, self.scope, record,
            self.issuer_start, self.issuer_end)
        route['resultSubjects'] = ['am.result.mac']
        template = copy.deepcopy(record['state']['grants'][0])
        for name, seed, publishes, subscribes in (
                ('core-receiver',31,(),('am.work.falcon.worker','am.result.mac')),
                ('core-peer',32,('am.work.falcon.worker','am.result.mac'),()),
                ('core-publisher',33,('am.work.falcon.worker','am.result.remote'),())):
            raw, account, user, token = credential(seed, publish=publishes, subscribe=subscribes)
            if getattr(self, 'credential_seconds', None) is not None:
                import nkeys
                parts = token.encode().split(b'.')
                claims = strict_loads(base64.urlsafe_b64decode(parts[1]+b'='*(-len(parts[1])%4)))
                self.core_credential_expiry = int(time.time()) + self.credential_seconds
                claims['exp'] = self.core_credential_expiry
                account_key = nkeys.from_seed(nkeys.encode_seed(bytes([1])*32,nkeys.PREFIX_BYTE_ACCOUNT))
                try:
                    signed = parts[0]+b'.'+base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                    updated = signed+b'.'+base64.urlsafe_b64encode(account_key.sign(signed)).rstrip(b'=')
                finally:
                    account_key.wipe()
                raw = raw.replace(token.encode(),updated)
                token = updated.decode()
            path = self.root / (name + '.creds')
            path.write_bytes(raw)
            path.chmod(0o600)
            pin = {'path':str(path), 'sha256':'sha256:'+hashlib.sha256(raw).hexdigest(),
                'userPublicKey':user}
            grants = {contract:ref(name+'-'+contract.removeprefix('federation-work-'))
                for contract in (INGEST,RESULT)}
            if name == 'core-receiver':
                route['receiver']['credentials'] = pin
                route['receiver']['grantRefs'].update(grants)
                channel['legacyActors'][-1]['grants'].update(grants)
            elif name == 'core-peer':
                route['peer'].update(credentialJWT=token,publishSubjects=list(publishes),grantRefs=grants)
            else:
                route['publisher'] = {'identityRef':ref(name),'transportRef':ref(name+'-transport'),
                    'credentials':pin,'publishSubjects':list(publishes),'grantRefs':grants}
                state = record['state']
                state['identities'].append({'ref':ref(name),'kind':'service','status':'active',
                    'principalId':name,'externalIdentity':None})
                state['memberships'].append({'ref':ref(name+'-member'),'identityRef':ref(name),
                    'scope':copy.deepcopy(self.scope),'status':'active'})
                state['transports'].append({**copy.deepcopy(state['transports'][0]),
                    'ref':ref(name+'-transport'),'identityRef':ref(name),
                    'issuerRef':self.value['identity']['issuer']['issuerRef'],
                    'method':'nats-credential-mapping',
                    'publicKey':base64.urlsafe_b64encode(_base32(user.encode(),35)[1:-2]).decode().rstrip('=')})
            existing = {canonical_bytes(grant['ref']) for grant in record['state']['grants']}
            for contract, grant in grants.items():
                if canonical_bytes(grant) not in existing:
                    record['state']['grants'].append({**copy.deepcopy(template),'ref':grant,
                        'callerRef':ref(name),'actorRef':ref(name),'scope':copy.deepcopy(self.scope),
                        'contractId':contract,'resourceId':channel['resourceRef']['id'],
                        'decision':'allowed','delegationRef':None,
                        'issuedAt':self.issuer_start,'expiresAt':self.issuer_end})
        self.snapshot = AuthoritySnapshot(canonical_bytes(record),self.snapshot.sequence)
        self.selection = self.selected()

    def protected_connection(self, **_options):
        # Reuse the existing controlled connection; retain its real session
        # ownership records just as the native paired client does.
        connection = Client(object())
        connection._subs = {}
        connection.flush = AsyncMock()
        async def connect(**options):
            self.assertTrue(options['tls_handshake_first'])
            self.assertTrue(options['user_jwt_cb']())
            self.assertEqual(len(options['signature_cb']('broker-nonce')),88)
            connection.options, connection.is_connected = options, True
        async def subscribe_owned(session, subject, **options):
            subscription = await connection.subscribe(subject, **options)
            subscription._id = len(connection.subscriptions)
            subscription._closed = False
            async def dispatch():
                await asyncio.Future()
            subscription._wait_for_msgs_task = asyncio.create_task(dispatch(),name='controlled-core:callback')
            connection._subs[subscription._id] = subscription
            async def unsubscribe():
                subscription._closed = True
                connection._subs.pop(subscription._id,None)
                subscription._wait_for_msgs_task.cancel()
                await asyncio.gather(subscription._wait_for_msgs_task,return_exceptions=True)
            subscription.unsubscribe.side_effect = unsubscribe
            return subscription
        async def close():
            connection.is_connected = False
        connection.connect, connection.subscribe_owned, connection.close = connect, subscribe_owned, close
        return connection

    async def protected_hub(self):
        self.protected_mode = True
        self.enterContext(patch('hub.core_work_transport.new_client',side_effect=self.protected_connection))
        with patch.dict(server.DEFAULT_CONFIG,{'nats_url':'nats://ordinary-messages:4222'}):
            hub = await self.setup_source()
        return hub

    async def test_actual_selected_mode_proves_transport_and_keeps_unshared_scope_local(self):
        hub = await self.protected_hub()
        owner, = self.host._core_work_owners
        await hub._work_source_binding.activate()
        pins = [strict_loads(hub._work_source_binding._core_pins[id(session)]) for session in self.sessions]
        self.assertEqual([pin['mode'] for pin in pins],['tm218-core-v1','local-only'])
        self.assertNotEqual(hub.bridge.url,owner._selection.policy['coreWorkTransport']['routes'][0]['connection']['endpoint'])
        self.assertTrue(owner._roles_task is not None and not owner._roles_task.done())
        self.assertTrue(owner._outbox_task is not None and not owner._outbox_task.done())
        self.lifecycle = WorkLifecycleClient(hub._work_storage_commands)
        self.addAsyncCleanup(self.lifecycle.close)
        session = await self.lifecycle.register({'generation':None,'repo':'other','role':'worker','agent':'local',
            'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%31','panePid':12355,
            'legacy':None,'tokenSha':'e'*64},operation_id='core-mode-local-register',
            expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        self.assertEqual((await hub.db(hub.store.agent,session))['repo'],'other')
        await hub._work_source_binding.verify()
        self.assertNotIn(str(self.root),canonical_bytes(self.replies).decode())
        self.assertTrue(all('coreTransport' in row['workSource'] for row in self.submitted
            if row['contractId']=='federation-work-register'))

    async def test_current_transport_loss_refuses_proof_and_retains_original_rows(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        owner, = self.host._core_work_owners
        resource = self.resources[0]
        before = await resource._owner.db(resource._store.q,'SELECT * FROM work_items')
        publisher = next(iter(owner._publishers.values()))
        publisher._connection.is_connected = False
        with self.assertRaises(ContractError):
            await hub._work_source_binding.verify()
        self.assertEqual(await resource._owner.db(resource._store.q,'SELECT * FROM work_items'),before)

    async def test_original_first_role_sync_must_finish_before_mode_proof(self):
        entered, release, completed = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original = CoreWorkRoles.sync
        async def held(roles):
            entered.set()
            await release.wait()
            await original(roles)
            completed.set()
        with patch.object(CoreWorkRoles,'sync',new=held):
            hub = await self.protected_hub()
            await asyncio.wait_for(entered.wait(),1)
            owner, = self.host._core_work_owners
            self.assertIsNone(owner._roles._completed_sync)
            session, raw = hub._work_source_binding.routes[0]
            try:
                with self.assertRaises(ContractError):
                    await hub._work_source_binding._prove_current(session,raw,
                        datetime.now(timezone.utc)+timedelta(seconds=4))
            finally:
                release.set()
            await asyncio.wait_for(completed.wait(),2)
            self.assertIsNotNone(owner._roles._completed_sync)
            await hub._work_source_binding.activate()

    async def test_core_policy_pause_at_original_lifecycle_commit_has_no_effect(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        owner, = self.host._core_work_owners
        lifecycle_owner, = self.host._work_lifecycle_owners
        commit = lifecycle_owner._commit
        attempted = []
        def pause(checked,deadline):
            attempted.append(checked)
            owner.begin_policy_pause()
            return commit(checked,deadline)
        client = WorkLifecycleClient(hub._work_storage_commands)
        self.addAsyncCleanup(client.close)
        before = await hub.db(hub.store.agents)
        with patch.object(lifecycle_owner,'_commit',side_effect=pause),self.assertRaises(ContractError):
            await client.register({'generation':None,'repo':'falcon','role':'worker','agent':'refused',
                'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%32','panePid':12356,
                'legacy':None,'tokenSha':'f'*64},operation_id='core-mode-paused-register',
                expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        self.assertEqual(len(attempted),1)
        self.assertEqual(await hub.db(hub.store.agents),before)
        self.assertTrue(all(admission.source is not None for _,_,admission in attempted[0]))
        await owner.join_policy_pause()
        owner.end_policy_pause()

    async def test_missing_declared_owner_or_result_subscription_cannot_be_local_only(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        resource = self.resources[0]
        owner = resource._core_work_owner
        with patch.object(resource,'_core_work_owner',None),self.assertRaises(ContractError):
            await hub._work_source_binding.verify()
        ingress = owner._ingresses[id(resource)]
        subscription = ingress._subscriptions['am.result.mac']
        with patch.object(subscription,'_closed',True),self.assertRaises(ContractError):
            await hub._work_source_binding.verify()
        await hub._work_source_binding.verify()

    async def test_original_required_callback_loss_refuses_current_mode(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        owner, = self.host._core_work_owners
        ingress = owner._ingresses[id(self.resources[0])]
        original = ingress._dispatch_tasks['am.result.mac']
        original.cancel()
        await asyncio.gather(original,return_exceptions=True)
        self.assertTrue(original.done())
        self.assertFalse(ingress._subscriptions['am.result.mac']._closed)
        with self.assertRaises(ContractError):
            await hub._work_source_binding.verify()

    async def test_receiver_only_grant_revocation_refuses_mode(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        original = self.snapshot
        for contract in (INGEST,RESULT):
            record = strict_loads(original.record)
            grant = next(grant for grant in record['state']['grants']
                if grant['ref'] == ref('core-receiver-'+contract.removeprefix('federation-work-')))
            grant['status'] = 'revoked'
            self.snapshot = AuthoritySnapshot(canonical_bytes(record),original.sequence+1)
            with self.subTest(contract=contract),self.assertRaises(ContractError):
                await hub._work_source_binding.verify()
        self.snapshot = original
        await hub._work_source_binding.verify()

    async def test_final_batch_snapshot_revokes_earlier_core_route_before_effect(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        original_authorize = work_legacy.authorize
        revoked = []
        async def authorize(resource,authority,raw,**kwargs):
            admitted = await original_authorize(resource,authority,raw,**kwargs)
            current = asyncio.current_task()
            if (not revoked and current.get_coro().__qualname__ == 'WorkLifecycleOwner._run'
                    and resource.repository == 'falcon'):
                record = strict_loads(self.snapshot.record)
                next(grant for grant in record['state']['grants']
                    if grant['ref']==ref('core-peer-ingest-legacy'))['status']='revoked'
                self.snapshot = AuthoritySnapshot(canonical_bytes(record),self.snapshot.sequence+1)
                revoked.append(admitted.snapshot.sequence)
            return admitted
        client = WorkLifecycleClient(hub._work_storage_commands)
        self.addAsyncCleanup(client.close)
        before = await hub.db(hub.store.agents)
        with patch.object(work_legacy,'authorize',side_effect=authorize),self.assertRaises(ContractError):
            await client.register({'generation':None,'repo':'falcon','role':'worker','agent':'finalrefused',
                'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%33','panePid':12357,
                'legacy':None,'tokenSha':'1'*64},operation_id='core-mode-final-snapshot-register',
                expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        self.assertEqual(len(revoked),1)
        self.assertEqual(await hub.db(hub.store.agents),before)

    async def test_selected_credential_expiry_bounds_signed_mode_reply(self):
        self.credential_seconds = 4
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        proof = next(reply['claims'] for reply in self.replies
            if reply['claims']['result'].get('sourceBinding',{}).get('coreTransport',{}).get('mode')=='tm218-core-v1')
        self.assertLessEqual(datetime.fromisoformat(proof['validUntil']).timestamp(),self.core_credential_expiry)
        original = next(claims for claims in self.submitted if claims['operationId']==proof['operationId'])
        self.assertLess(datetime.fromisoformat(proof['validUntil']),datetime.fromisoformat(original['expiresAt']))

    async def test_mode_generation_node_repository_and_local_config_substitution_refuse(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        owner, = self.host._core_work_owners
        resource = self.resources[0]
        for obj, field, value in ((owner,'_transport_generation','0'*64),
                (resource,'_node','different'),(resource,'repository','other')):
            with self.subTest(field=field),patch.object(obj,field,value),self.assertRaises(ContractError):
                await hub._work_source_binding.verify()
        with patch.dict(hub.cfg,{'nats_url':'nats://substituted:4222'}),self.assertRaises(ContractError):
            await hub._work_source_binding.verify()
        await hub._work_source_binding.verify()

    async def test_cancelled_configured_startup_joins_exact_original_proof(self):
        hub = await self.protected_hub()
        entered, release = asyncio.Event(),asyncio.Event()
        async def held(claims):
            entered.set()
            await release.wait()
        self.before_exchange = held
        startup = asyncio.create_task(hub.main())
        await asyncio.wait_for(entered.wait(),2)
        original = hub._work_source_binding.activation
        startup.cancel()
        await asyncio.sleep(0)
        self.assertFalse(startup.done())
        self.assertFalse(hub.dbx._shutdown)
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await startup
        self.assertIs(hub._work_source_binding.activation,original)
        self.assertTrue(original.done())
        self.assertTrue(hub.dbx._shutdown)
        self.assertTrue(hub._work_start_cleanup.done())
        owner, = self.host._core_work_owners
        await self.host.close(timeout=None)
        self.assertTrue(owner._closing.done())
        self.assertTrue(all(task.done() for ingress in owner._ingresses.values()
            for task in ingress._dispatch_tasks.values()))

    async def test_transport_loss_at_final_proof_signature_refuses_disclosure(self):
        hub = await self.protected_hub()
        owner, = self.host._core_work_owners
        publisher = next(iter(owner._publishers.values()))
        original = WorkBridgeService._sign
        intercepted = []
        def lose(service,request,resource,result,checked,**kwargs):
            if result.get('sourceBinding',{}).get('coreTransport',{}).get('mode') == 'tm218-core-v1':
                intercepted.append(checked)
                publisher._connection.is_connected = False
            return original(service,request,resource,result,checked,**kwargs)
        with patch.object(WorkBridgeService,'_sign',new=lose),self.assertRaises(ContractError):
            await hub._work_source_binding.activate()
        self.assertEqual(len(intercepted),1)
        self.assertFalse(any(reply['claims']['result'].get('sourceBinding',{}).get('coreTransport',{}).get('mode')
            == 'tm218-core-v1' for reply in self.replies))

    async def test_final_mode_fence_uses_no_work_database_off_original_worker(self):
        hub = await self.protected_hub()
        final, observed = [], []
        original_sign, original_disclose = WorkBridgeService._sign, work_legacy.check_disclosure
        def sign(service,request,resource,result,checked,**kwargs):
            final.append(resource)
            try:
                observed.append(('sign',resource.repository))
                return original_sign(service,request,resource,result,checked,**kwargs)
            finally:
                final.pop()
        def disclose(resource,original,current):
            final.append(resource)
            try:
                observed.append(('disclose',resource.repository))
                return original_disclose(resource,original,current)
            finally:
                final.pop()
        resource = self.resources[0]
        original_q1 = resource._store.q1
        def q1(*args,**kwargs):
            if final and not getattr(resource._source._worker,'active',False):
                self.fail('Final mode disclosure read Work data outside its original worker')
            return original_q1(*args,**kwargs)
        with patch.object(WorkBridgeService,'_sign',new=sign), \
                patch.object(work_legacy,'check_disclosure',side_effect=disclose), \
                patch.object(resource._store,'q1',side_effect=q1):
            await hub._work_source_binding.activate()
            await hub._work_source_binding.verify()
        self.assertIn(('sign','falcon'),observed)
        self.assertIn(('disclose','falcon'),observed)

    async def test_same_scope_local_resource_substitution_at_signing_refuses(self):
        hub = await self.protected_hub()
        original = WorkBridgeService._sign
        intercepted = []
        def substitute(service,request,resource,result,checked,**kwargs):
            if resource.repository == 'other':
                intercepted.append(resource.binding)
                with patch.object(resource,'binding',replace(resource.binding,entity_id='different-local-resource')):
                    return original(service,request,resource,result,checked,**kwargs)
            return original(service,request,resource,result,checked,**kwargs)
        with patch.object(WorkBridgeService,'_sign',new=substitute),self.assertRaises(ContractError):
            await hub._work_source_binding.activate()
        self.assertEqual(len(intercepted),1)
        self.assertFalse(any(reply['claims']['result'].get('sourceBinding',{}).get('repository')=='other'
            for reply in self.replies))

    async def test_first_core_registration_keeps_original_result_before_next_role_poll(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        owner, = self.host._core_work_owners
        resource = self.resources[0]
        original_watcher, original_sync = owner._roles_task, owner._roles.sync
        original_proof = owner.transport_proof
        entered, release, completed = asyncio.Event(),asyncio.Event(),asyncio.Event()
        guards = []
        async def held():
            if asyncio.current_task() is not original_watcher:
                return await original_sync()
            entered.set()
            await release.wait()
            await original_sync()
            completed.set()
        def proof(current,snapshot):
            try:
                return original_proof(current,snapshot)
            except ContractError as error:
                self.assertTrue(getattr(current._source._worker,'active',False))
                row = current._store.agent('falcon-worker-held')
                ingress = owner._ingresses[id(current)]
                trace, line = error.__traceback__, None
                while trace is not None:
                    if trace.tb_frame.f_code.co_name == '_transport_binding':
                        line = trace.tb_lineno
                    trace = trace.tb_next
                guards.append({'code':error.code,'guardLine':line,
                    'generation':None if row is None else row['generation'],
                    'missingRoleSubscription':'am.work.falcon.worker' not in ingress._subscriptions,
                    'originalWatcherLive':owner._roles_task is original_watcher and not original_watcher.done()})
                raise
        client = WorkLifecycleClient(hub._work_storage_commands)
        self.addAsyncCleanup(client.close)
        result, failure, receipt = None,None,None
        with patch.object(owner._roles,'sync',side_effect=held),patch.object(owner,'transport_proof',side_effect=proof):
            try:
                await asyncio.wait_for(entered.wait(),2)
                self.assertIsNotNone(owner._roles._completed_sync)
                self.assertFalse(original_watcher.done())
                result = await client.register({'generation':None,'repo':'falcon','role':'worker','agent':'held',
                    'cli':'codex','roleSnapshot':{},'transport':'tmux','handle':'%34','panePid':12358,
                    'legacy':None,'tokenSha':'3'*64},operation_id='core-mode-first-role-register',
                    expires=datetime.now(timezone.utc)+timedelta(seconds=4))
            except ContractError as error:
                failure = type(error).__name__
            finally:
                try:
                    requests = [row for row in self.submitted if row['contractId']=='federation-work-register'
                        and row['payload']['resourceRef']['id']==resource.binding.entity_id]
                    if requests:
                        request = requests[0]
                        receipt = await resource._owner.db(resource._journal.outcome,request['operationId'],
                            payload_digest(request['payload']))
                finally:
                    release.set()
            await asyncio.wait_for(completed.wait(),2)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['reply']['outcome'],'applied')
        self.assertEqual(await resource._owner.db(resource._store.q1,
            "SELECT count(*) n FROM events WHERE event='registered' AND entity_id=?",('falcon-worker-held',)),{'n':1})
        self.assertIs(owner._roles_task,original_watcher)
        self.assertIsNone(failure,f'Original result failed after one applied registration; guards={guards}')
        self.assertEqual(result,'falcon-worker-held')

    async def test_configured_bridge_refuses_missing_protected_work_transport(self):
        # Construct the actual Hub with legacy core transport configured and a
        # valid selected Work source that does not declare the protected bridge.
        with patch.dict(server.DEFAULT_CONFIG, {'nats_url': 'nats://unused:4222'}):
            hub = await self.setup_source()
        self.assertIsNotNone(hub.bridge)
        self.assertFalse(self.host._core_work_owners)
        await hub.db(hub.store.work_create, 'operator', 'falcon',
            'role:falcon/worker', 'Retained legacy offer', federate=True, node='mac')
        before = await hub.db(hub.store.outbox_pending)
        self.assertEqual(len(before), 1)
        self.assertTrue(before[0]['subject'].startswith('am.work.'))

        connection = Connection()
        connection.finish_reader.set()
        connection.finish_socket.set()
        observed = {'connected': False, 'subscriptions': []}

        async def run_bridge():
            original = asyncio.create_task(hub.bridge.run())
            try:
                await asyncio.wait_for(connection.reading.wait(), 1)
                observed['connected'] = hub.bridge.connected
                observed['subscriptions'] = [row[0] for row in connection.subscriptions.values()]
            finally:
                hub.stop.set()
                if not original.done():
                    original.cancel()
                await asyncio.gather(original, return_exceptions=True)

        refused = False
        with patch.object(server.Hub, '_main', side_effect=run_bridge), \
                patch.object(hub, '_seed_roles'), \
                patch('hub.bridge.NatsClient', return_value=connection):
            try:
                await hub.main()
            except (ContractError, HubError):
                refused = True
        resource = self.resources[0]
        after = await resource._owner.db(resource._store.outbox_pending)
        self.assertEqual(after, before)
        self.assertTrue(refused,
            'Configured Work transport was admitted without its protected owner; '
            f'connected={observed["connected"]}, subscriptions={observed["subscriptions"]}')
        self.assertFalse(observed['connected'])
