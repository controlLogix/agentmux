"""Selected startup recovers retained policy before constructing borrowed owners."""
import asyncio
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import AuthoritySnapshot
from identity.ingress import EnrolledIngress
from identity.test_authority import ref, SEED
from state_owner.configuration_host import ConfigurationHost
from state_owner.federation_policy import FederationPolicyTarget, FederationPolicyCustody, SCHEMA_REF, FEDERATION_POLICY_SCHEMA
from state_owner.history import OwnerHistory
from state_owner.checkpoint_host import CheckpointHost
from state_owner.backup_host import BackupHost
from state_owner.ledger import StreamIdentity
from state_owner.test_ledger import CREATED
from state_owner import test_configuration_activation as events
from . import test_federation_policy_transition as policy_support
from . import test_selected_storage as storage_support
from identity import test_federation_policy_service_selection as selection_support
from .selected_storage import SelectedStorageHost
from hub.store import Store
from hub.fed.plugins.knowledge import Knowledge


class SelectedPolicyRestartTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = policy_support.FederationPolicyTransitionTests.asyncSetUp
    make_owner = policy_support.FederationPolicyTransitionTests.make_owner
    request = policy_support.FederationPolicyTransitionTests.request
    final = policy_support.FederationPolicyTransitionTests.final
    project_request = policy_support.FederationPolicyTransitionTests.project_request

    async def test_committed_unshare_replacement_startup_keeps_all_original_resources(self):
        await self.check_replacement_startup()

    async def test_committed_unshare_with_control_keeps_original_resources_and_route(self):
        await self.check_replacement_startup(peer_control=True)

    async def test_cancelled_control_opening_keeps_original_jobs_until_cleanup(self):
        await self.check_replacement_startup(peer_control=True, cancel_control=True)

    async def test_failed_control_opening_expires_permission_and_joins_original_jobs(self):
        await self.check_replacement_startup(peer_control=True, fail_control=True)

    async def check_replacement_startup(self, *, peer_control=False, cancel_control=False, fail_control=False):
        fixture = storage_support.SelectedStorageCompositionTests()
        fixture.include_board = True
        fixture.setUp()
        for fn,args,kwargs in fixture._cleanups:
            self.addCleanup(fn,*args,**kwargs)
        fixture._cleanups.clear()
        await self.transition.close()
        await self.source.close()
        await self.owner.close(timeout=None)
        board = fixture.value['storage']['board']
        self.pins, self.repository = copy.deepcopy(board['auditMirror']), copy.deepcopy(board['repository'])
        self.path = Path(self.pins['policy']['path'])
        self.old = self.path.read_bytes()
        self.target = FederationPolicyTarget.selected(self.ledger._binding,
            source_ref=ref('selected-federation-policy'), source=self.pins,
            repository=self.repository, local_peer=board['localPeer'])
        store = Store(self.pins['database']['path'])
        try:
            for statement in Knowledge.tables:
                store.db.execute(statement)
            store.event('board', 'SH-1', 'preserved', 'peer:local')
            store.db.execute('INSERT INTO p_knowledge_items(id,rid,repo,from_peer,title,body,at) VALUES (?,?,?,?,?,?,?)',
                ('finding-kept',self.repository['repositoryId'],'falcon','alice','Retained','original finding','2026-10-17'))
            store.db.execute('INSERT INTO messages(id,sender,target,kind,body,body_sha,created) VALUES (?,?,?,?,?,?,?)',
                ('message-kept','operator','operator','note','original message',hashlib.sha256(b'original message').hexdigest(),'2026-10-17'))
        finally:
            store.db.close()
        repository = {k:v for k,v in self.repository.items() if k != 'counterPrefix'}
        channel = {'resourceRef':ref('messages-one'), 'peer':'alice', 'actors':[
            {'identityRef':ref('human'), 'transportRef':ref('storage-human-transport'), 'caller':'operator'}],
            'pluginIdentityRef':fixture.value['storage']['privateStorage']['pluginIdentityRef'], 'instanceId':'plugin-one', 'initialSource':{'kind':'message','id':'message-kept'}}
        message = dict(source=copy.deepcopy(self.pins), repository=repository, localPeer=board['localPeer'],
            localNode='mac', channels=[channel])
        knowledge = copy.deepcopy(message)
        knowledge['channels'][0].pop('peer')
        knowledge['channels'][0]['resourceRef'] = ref('knowledge-one')
        knowledge['channels'][0]['initialSource'] = {'kind':'knowledge','id':'finding-kept'}
        fixture.value['storage'].update(messages=message,knowledge=knowledge)
        control_fixture = None
        if peer_control:
            from identity.test_peer_control import PeerControlTests
            control_fixture = PeerControlTests()
            control_fixture.setUp()
            for fn,args,kwargs in control_fixture._cleanups:
                self.addCleanup(fn,*args,**kwargs)
            control_fixture._cleanups.clear()
            route = copy.deepcopy(control_fixture.value['peerControl']['routes'][0])
            route.update(repository=copy.deepcopy(repository), localPeer=knowledge['localPeer'],
                localNode=knowledge['localNode'], resourceRef=knowledge['channels'][0]['resourceRef'])
            fixture.value['peerControl'] = {'routes':[route]}
        # Reuse the prepared closed selection descriptor, with this original
        # aggregate and source. The actual ConfigurationHost is built below.
        descriptor_fixture = selection_support.FederationPolicySelectionTests()
        descriptor_fixture.setUp()
        for fn,args,kwargs in descriptor_fixture._cleanups:
            self.addCleanup(fn,*args,**kwargs)
        descriptor_fixture._cleanups.clear()
        fp = copy.deepcopy(descriptor_fixture.value['federationPolicy'])
        fp['target'] = {'sourceRef':ref('selected-federation-policy'), 'source':self.pins,
            'repository':self.repository,'localPeer':board['localPeer']}
        fp['service']['ledger'].update(entityId=self.ledger._binding.entity_id,
            scope=strict_loads(self.ledger._binding.scope))
        fp['service']['owner'] = copy.deepcopy(self.fixture.owner)
        fp['projectionAuthority'] = {'serviceIdentityRef':ref('service'),
            'transportRef':ref('policy-reader'),'grantRef':ref('policy-project')}
        fixture.value['federationPolicy'] = fp
        selected = ApplicationServiceSelection(canonical_bytes(fixture.value))
        authority = fixture.identity.reader
        current = strict_loads(fixture.snapshot.record)
        for name, rows in self.record['state'].items():
            if type(rows) is list:
                existing = current['state'].setdefault(name, [])
                for row in rows:
                    if 'ref' in row:
                        existing[:] = [old for old in existing if old.get('ref') != row['ref']]
                    existing.append(copy.deepcopy(row))
        for name in ('transports','grants','memberships'):
            preferred = {canonical_bytes(row['ref']) for row in self.record['state'][name]}
            current['state'][name].sort(key=lambda row: canonical_bytes(row['ref']) not in preferred)
        if control_fixture is not None:
            control_state = strict_loads(control_fixture.snapshot.record)['state']
            for name in ('identities','transports','memberships','grants'):
                for row in control_state[name]:
                    if row['ref']['id'].startswith('control-'):
                        current['state'][name].append(copy.deepcopy(row))
        current['state']['identities'].append({'ref':channel['pluginIdentityRef'], 'kind':'plugin',
            'status':'active','principalId':'selected-plugin','externalIdentity':None})
        transport = copy.deepcopy(next(r for r in current['state']['transports'] if r['ref']==ref('transport')))
        transport.update(ref=ref('storage-human-transport'),issuedAt=fixture.issuer_start,expiresAt=fixture.issuer_end)
        current['state']['transports'].append(transport)
        self.record = current
        self.fixture.authority = authority
        reader = patch.object(authority, 'current', AsyncMock(side_effect=lambda:AuthoritySnapshot(canonical_bytes(self.record),1)))
        reader.start(); self.addCleanup(reader.stop)
        self.ingress = EnrolledIngress(authority,issuer_ref=ref('issuer'),signing_seed=SEED)
        events.enroll_event_producer(self.record['state'], strict_loads(self.ledger._binding.scope))
        history = OwnerHistory(self.root/'restart-history.sqlite', self.ledger._binding,
            stream_identity=StreamIdentity(CREATED,0))
        self.addCleanup(history.close)
        paths = [self.root/name for name in ('restart-backup','restart-inventory','restart-keys','restart-checkpoint')]
        for path in paths:path.mkdir(mode=0o700)
        backup = BackupHost(*paths[:3],destination_id='restart-policy',binding=self.ledger._binding,
            stream_identity=StreamIdentity(CREATED,0))
        backup.enroll_key('key')
        checkpoint = CheckpointHost(paths[3]/'checkpoint',stream='OWNER',commit_ref=ref('checkpoint'),
            binding=self.ledger._binding,stream_identity=StreamIdentity(CREATED,0))
        self.fixture.connection.jetstream = lambda:self.fixture.js
        custody = FederationPolicyCustody(self.target,self.artifacts,self.key,ingress=self.ingress,
            backup_transport_ref=ref('policy-reader'),backup_grant_ref=ref('policy-backup'))
        host = ConfigurationHost.from_enrolled_host(self.fixture.connection, authority=authority,stream='OWNER',
            binding=self.ledger._binding,retention=self.fixture.policy,stream_identity=StreamIdentity(CREATED,0),
            history=history,owner=self.fixture.owner,schema_ref=SCHEMA_REF,schema_resources={SCHEMA_REF:FEDERATION_POLICY_SCHEMA},
            issuer_ref=ref('issuer'),signing_seed=SEED,reply_prefix='_INBOX.configuration',checkpoint_host=checkpoint,
            backup_host=backup,backup_key_id='key',event_producer=events.event_producer(authority,strict_loads(self.ledger._binding.scope)),
            event_account_public_key='A'*56,federation_policy=custody)
        self.addAsyncCleanup(host.close,timeout=None)
        clock = patch('identity.configuration_events.datetime',policy_support.policy_support._Clock)
        clock.start(); self.addCleanup(clock.stop)
        await host.start()
        self.owner,self.ledger = host.owner,host.ledger
        # Commit the original decision while the selected storage host is down.
        from .federation_policy_transition import changed_policy
        desired = changed_policy(self.old, {'verb':'unshare','arguments':{'repo':'falcon'}},repository=self.repository)
        proposal = self.owner.preparation_bytes(previous_revision=0,old_policy=self.old,desired_policy=desired,
            change={'verb':'unshare','arguments':{'repo':'falcon'}})
        request = self.request(proposal)
        descriptor = await self.owner.prepare(request, old_policy=self.old, desired_policy=desired)
        raw = self.request(descriptor)
        await self.owner.handle(raw)
        await self.project_request(raw,desired)
        replacement = SelectedStorageHost(selected,identity=fixture.identity,federation_policy=host)
        self.addAsyncCleanup(replacement.close,timeout=None)
        entered, release = asyncio.Event(), asyncio.Event()
        permits = []
        control_connection = SimpleNamespace(is_connected=False)
        async def connect_control(**options):
            self.assertTrue(options['user_jwt_cb']())
            self.assertTrue(options['signature_cb']('broker-nonce'))
            permits.append(replacement._startup_permits['knowledge'])
            entered.set()
            if cancel_control:
                await release.wait()
            if fail_control:
                raise ContractError('peer_control_unavailable')
            control_connection.is_connected = True
        async def close_control():
            control_connection.is_connected = False
        control_connection.connect = connect_control
        control_connection.subscribe_owned = AsyncMock(return_value=SimpleNamespace(unsubscribe=AsyncMock()))
        control_connection.flush = AsyncMock()
        control_connection.close = close_control
        from hub.fed.peer_control import PeerControlIngress
        original_ingress_start = PeerControlIngress.start
        async def checked_ingress_start(ingress, *, _bootstrap=None):
            source = ingress._store_owner
            ingress._store_owner = object()
            try:
                with self.assertRaisesRegex(ContractError,'^peer_control_configuration$'):
                    await original_ingress_start(ingress,_bootstrap=_bootstrap)
            finally:
                ingress._store_owner = source
            return await original_ingress_start(ingress,_bootstrap=_bootstrap)
        with patch('capability_owner.selected_storage.new_client',side_effect=fixture.clients), \
                patch('capability_owner.board_publisher.new_client',side_effect=fixture.publisher_clients), \
                patch('hub.fed.peer_control.new_client',return_value=control_connection), \
                patch.object(PeerControlIngress,'start',checked_ingress_start), \
                patch('datetime.datetime',policy_support.policy_support._Clock):
            if fail_control:
                with self.assertRaises(ContractError):
                    await replacement.start()
                control = replacement._knowledge_controls[0]
                ingress = next(iter(control._routes.values()))
                original_start, original_control, original_ingress = replacement._starting, control._starting, ingress._started
                await replacement.close(timeout=None)
                self.assertTrue(all(task.done() for task in (original_start,original_control,original_ingress)))
                self.assertTrue(control._closing.done())
                self.assertTrue(ingress._closing.done())
                self.assertEqual(replacement._startup_permits,{})
                self.assertFalse(control_connection.is_connected)
                with self.assertRaisesRegex(ContractError,'^selected_policy_bootstrap_invalid$'):
                    permits[0]._start_owned(asyncio.sleep,0)
                return
            if cancel_control:
                caller = asyncio.create_task(replacement.start())
                closer = None
                try:
                    await asyncio.wait_for(entered.wait(),5)
                    original_start = replacement._starting
                    control = replacement._knowledge_controls[0]
                    original_control = control._starting
                    ingress = next(iter(control._routes.values()))
                    original_ingress = ingress._started
                    caller.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await caller
                    closer = asyncio.create_task(replacement.close(timeout=None))
                    await asyncio.sleep(0)
                    self.assertFalse(closer.done())
                    self.assertFalse(original_start.done())
                    self.assertFalse(original_control.done())
                    self.assertFalse(original_ingress.done())
                    self.assertIsNotNone(replacement._audit._store)
                finally:
                    release.set()
                    await asyncio.gather(caller,return_exceptions=True)
                    await replacement.close(timeout=None)
                if closer is not None:
                    await closer
                self.assertTrue(all(task.done() for task in (original_start,original_control,original_ingress)))
                self.assertEqual(replacement._startup_permits,{})
                self.assertFalse(control_connection.is_connected)
                return
            try:
                await replacement.start()
            except Exception as error:
                raise getattr(error, '_cause', None) or error
            replacement.check_health()
            self.assertEqual(self.path.read_bytes(),desired)
            self.assertEqual(len(replacement._resources),4)
            self.assertEqual(replacement._startup_permits,{})
            if peer_control:
                with self.assertRaisesRegex(ContractError,'^selected_policy_bootstrap_invalid$'):
                    permits[0]._start_owned(asyncio.sleep,0)
            for resource in replacement._resources:
                if resource.binding.owner_domain == 'plugin-private':continue
                with self.assertRaises(ContractError):await resource.read(1)
            self.assertEqual(len(replacement._message_stores),0)
            self.assertIs(replacement._preconstructed_sources['messages'],replacement._audit)
            self.assertIs(replacement._preconstructed_sources['knowledge'],replacement._audit)
            with self.assertRaisesRegex(ContractError, '^selected_policy_not_shared$'):
                await replacement._audit.db(replacement._audit._store.event,'board','SH-1','must-not-write','operator')
            original_resources = tuple(replacement._resources)
            original_store = replacement._audit._store
            if peer_control:
                self.assertEqual(len(replacement._knowledge_controls),1)
                control = replacement._knowledge_controls[0]
                ingress = next(iter(control._routes.values()))
                self.assertIs(ingress._store_owner,replacement._audit)
                with self.assertRaisesRegex(ContractError,'^selected_policy_not_shared$'):
                    await ingress.recover('not-admitted','sha256:'+'a'*64)
            journals = [(r, r._journal.binding, r._journal._base) for r in original_resources if hasattr(r,'_journal')]
            self.transition = host._policy_transition
            shared, _ = await self.final({'verb':'share','arguments':{'repo':'falcon',
                'remote':self.repository['normalizedRemote'],'board_prefix':self.repository['counterPrefix']}},
                revision=1,operation='reshare-original')
            await self.transition.apply(shared)
            self.assertEqual(tuple(replacement._resources),original_resources)
            self.assertIs(replacement._audit._store,original_store)
            if peer_control:
                self.assertIs(next(iter(control._routes.values())),ingress)
                ingress.check()
                self.assertTrue(control_connection.is_connected)
            for resource,binding,base in journals:
                self.assertEqual((resource._journal.binding,resource._journal._base),(binding,base))
                await resource.read(1)
            board_resource = next(r for r in original_resources if r.binding.entity_kind=='board-card')
            self.assertTrue(strict_loads(await board_resource.read(1))['unknownFutureField']['retained'])
            self.assertEqual((await replacement._audit.db(original_store.q1,
                'SELECT body FROM messages WHERE id=?',('message-kept',)))['body'],'original message')
            self.assertEqual((await replacement._audit.db(original_store.q1,
                'SELECT body FROM p_knowledge_items WHERE id=?',('finding-kept',)))['body'],'original finding')
            self.assertEqual(len(await replacement._audit.db(original_store.q,
                "SELECT rowid FROM p_knowledge_fts WHERE p_knowledge_fts MATCH ?",('original',))),1)
            self.assertEqual(await replacement._audit.db(original_store.q,
                "SELECT event FROM events WHERE event='must-not-write'"),[])
            await replacement.close(timeout=None)
            if peer_control:
                self.assertTrue(control._closing.done())
                self.assertTrue(ingress._closing.done())
                self.assertFalse(control_connection.is_connected)
