"""Protected operator enrollment through actual selected services and Hub Unix RPC."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import threading
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub import server
from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner
from hub.client_launch_session import ApplicationClientSession
from identity.application_client import ApplicationClientKey
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref
from .selected_storage import SelectedStorageHost
from .test_work_source_live import LiveSelectedWorkSourceTests
from .work import WorkStorageResource
from .work_lifecycle_client import WorkLifecycleClient


class LiveSelectedOperatorWorkTests(LiveSelectedWorkSourceTests):
    class Fixture(LiveSelectedWorkSourceTests.Fixture):
        def initial_authority(self):
            record = super().initial_authority()
            template = copy.deepcopy(record['state']['grants'][0])
            self.operator_grants = {}
            for action in ('create', 'claim', 'heartbeat', 'release', 'claim-path', 'read', 'inspect', 'outcome', 'cancel'):
                contract = 'federation-work-' + action
                grant = {**copy.deepcopy(template), 'ref':ref('selected-operator-' + action),
                    'callerRef':ref('human'), 'actorRef':ref('human'), 'scope':copy.deepcopy(self.scope),
                    'contractId':contract, 'resourceId':'work-one', 'decision':'allowed', 'delegationRef':None}
                record['state']['grants'].append(grant)
                self.operator_grants[contract] = grant['ref']
            return record

        async def asyncSetUp(self):
            await super().asyncSetUp()
            selected = copy.deepcopy(self.control_host._selection.policy)
            await self.control_host.close(timeout=None)
            actor = {'identityRef':ref('human'), 'transportRef':ref('transport'), 'caller':'operator',
                'grants':copy.deepcopy(self.operator_grants)}
            selected['storage']['work']['channels'][0]['legacyActors'].append(actor)
            self.control_host = SelectedStorageHost(ApplicationServiceSelection(canonical_bytes(selected)), identity=self.identity)
            await self.control_host.start()
            self.control_host.check_health()
            self.resource = next(r for r in self.control_host._resources if type(r) is WorkStorageResource)
            self.receiver = next(r for r in self.control_host._receivers if r._work_bridge is not None)

        async def operator_session(self):
            value = strict_loads(self.application_key(service=False)._material)
            command = value.pop('messageCommands'); command.pop('peer')
            actor = self.control_host._selection.policy['storage']['work']['channels'][0]['legacyActors'][-1]
            command.update(resourceRef=ref('work-one'), grantRefs=actor['grants'],
                authenticatedCaller=actor['caller'], transportRef=actor['transportRef'])
            value['workCommands'] = command
            key = ApplicationClientKey(value)
            connection = await self.connect('host')
            binding = ClientBindingState(connection, public_key=self.issuer_public,
                signing_key_ref=ref('issuer'), caller_ref=actor['identityRef'], scope=self.scope)
            owner = ClientConnectionOwner(connection, binding, command_subject=self.identity_subject,
                reply_prefix=self.inbox_prefixes['host'], signer=key)
            self.application_owners.append(owner); owner._connected = True
            self.refresh_observation()
            loop = asyncio.get_running_loop()
            await owner.authenticate(key, deadline=loop.time()+3, cleanup_deadline=loop.time()+4)
            session = object.__new__(ApplicationClientSession)
            session._owner, session._loop, session._thread = owner, loop, threading.current_thread()
            session._loop_stopping = session._stopped = session._terminal_enrolled = session._terminal_active = False
            session._closing = session._final_closing = session._command_future = session._command_identity = None
            session._work_enrollment = canonical_bytes({k:key.selection[k] for k in
                ('hubId','profileId','authorityId','callerRef','scope','workCommands')})
            return session, owner

    # The parent test qualifies a different selected service-only route.
    test_normal_selected_start_serves_original_hub_work_and_revocation = None

    async def test_selected_operator_hub_target_work_and_original_replay(self):
        fixture = self.fixture
        async def observe():
            while True:
                fixture.refresh_observation()
                await asyncio.sleep(.25)
        fixture._observation_task = asyncio.create_task(observe())
        service, _ = await fixture.actual_work_session()
        operator, _ = await fixture.operator_session()
        directory = fixture.native_hub_directory
        with patch.object(server, 'ROOT', str(directory/'application')), patch.object(server, 'HUBDIR', str(directory)):
            hub = fixture.actual_hub = server.Hub(work_sessions=(service, operator))
        await hub._work_source_binding.activate()
        fixture.lifecycle = WorkLifecycleClient(hub._work_storage_commands)
        target = await fixture.lifecycle.register({'generation':None, 'repo':'falcon', 'role':'worker',
            'agent':'operator_target', 'cli':'codex', 'roleSnapshot':{'capabilities':['python'], 'max_active':2},
            'transport':'tmux', 'handle':'%668', 'panePid':12368, 'legacy':None, 'tokenSha':'6'*64},
            operation_id='selected-operator-register', expires=datetime.now(timezone.utc)+timedelta(seconds=4))
        registered = await hub.db(hub.store.agent, target)
        submitted = []
        bridge = fixture.receiver._work_bridge
        original = bridge.handle
        async def received(raw, **kwargs):
            submitted.append(strict_loads(raw)['claims'])
            return await original(raw, **kwargs)
        self.enterContext(patch.object(bridge, 'handle', side_effect=received))
        self.enterContext(patch.object(server, 'parent_pid', return_value=1))
        pane_listing = SimpleNamespace(returncode=0, stdout='')
        self.enterContext(patch.object(server.subprocess, 'run', return_value=pane_listing))
        tasks = set()
        async def receive(reader, writer, *, tcp=False):
            task = asyncio.current_task(); tasks.add(task)
            try:
                await hub.handle_conn(reader, writer, tcp=tcp)
            finally:
                writer.close(); await writer.wait_closed(); tasks.discard(task)
        socket_directory = tempfile.TemporaryDirectory(prefix='amux668-', dir='/tmp')
        self.addCleanup(socket_directory.cleanup)
        path = str(Path(socket_directory.name)/'operator.sock')
        listener = await asyncio.start_unix_server(receive, path=path)
        tcp_listener = None
        async def close_listener():
            listener.close(); await listener.wait_closed()
            if tcp_listener is not None:
                tcp_listener.close(); await tcp_listener.wait_closed()
            if tasks: await asyncio.gather(*tuple(tasks))
        self.addAsyncCleanup(close_listener)
        async def receive_tcp(reader, writer):
            await receive(reader, writer, tcp=True)
        tcp_listener = await asyncio.start_server(receive_tcp, '127.0.0.1', 0)
        port = tcp_listener.sockets[0].getsockname()[1]
        async def request(verb, args, operation, *, selected=target, tcp=False):
            reader, writer = await asyncio.open_connection('127.0.0.1', port) if tcp else await asyncio.open_unix_connection(path)
            value = {'verb':verb, 'args':args, 'operationId':operation}
            if selected is not None: value['as'] = selected
            if tcp: value['token'] = (directory/'operator.token').read_text().strip()
            try:
                writer.write(json.dumps(value).encode()+b'\n'); await writer.drain()
                response = json.loads(await asyncio.wait_for(reader.readline(), 10))
                return response
            finally:
                writer.close(); await writer.wait_closed()
                if tasks: await asyncio.gather(*tuple(tasks))
        async def allowed(verb, args, operation):
            value = await request(verb, args, operation)
            self.assertTrue(value['ok'], value)
            self.assertEqual(value['caller'], target)
            return value['result']
        created = await allowed('work_add', {'to':'role:*/worker', 'title':'Selected operator target'}, 'selected-create')
        self.assertEqual((created['created_by'], created['repo']), ('agent:'+target, 'falcon'))
        pane_listing.stdout = str(os.getpid())
        try:
            pane = await request('claim', {'work_id':created['id']}, 'pane-override')
            self.assertFalse(pane['ok'], pane)
            self.assertIn('--as is only for the operator', pane['error'])
        finally:
            pane_listing.stdout = ''
        tcp_created = await request('work_add', {'to':'role:falcon/worker', 'title':'TCP operator'}, 'tcp-create', tcp=True)
        self.assertTrue(tcp_created['ok'], tcp_created)
        self.assertEqual(tcp_created['caller'], 'operator')
        self.assertEqual(tcp_created['result']['created_by'], 'virtual:operator')
        tcp_claim = await request('claim', {'work_id':tcp_created['result']['id']}, 'tcp-claim', tcp=True)
        self.assertFalse(tcp_claim['ok'], tcp_claim)
        untargeted = await request('claim', {'work_id':created['id']}, 'untargeted-claim', selected=None)
        self.assertFalse(untargeted['ok'], untargeted)
        claimed = await allowed('claim', {'work_id':created['id']}, 'selected-claim')
        self.assertEqual((claimed['claimed']['id'], claimed['claimed']['claimed_by']), (created['id'], target))
        self.assertEqual(await allowed('heartbeat', {}, 'selected-heartbeat'), {'renewed':1})
        path_claim = await allowed('claim_path', {'path':'src/selected.py', 'work_id':created['id']}, 'selected-path')
        self.assertEqual(path_claim['holder'], target)
        cancelled = await request('work_cancel', {'work_id':created['id'], 'reason':'Cannot escalate'}, 'target-cancel')
        self.assertFalse(cancelled['ok'], cancelled)
        args = {'work_id':created['id'], 'outcome':'done', 'result':'Original selected result'}
        released = await allowed('release', args, 'selected-release')
        self.assertEqual(released, await fixture.resource._owner.db(fixture.resource._store.q1,
            'SELECT * FROM work_items WHERE id=?', (created['id'],)))
        self.assertNotIn('children', released)
        self.assertEqual(await allowed('release', args, 'selected-release'), released)
        for action in ('create', 'claim', 'heartbeat', 'claim-path', 'release'):
            calls = [row for row in submitted if row['contractId']=='federation-work-'+action
                and row['payload']['input'].get('title') != 'TCP operator']
            self.assertEqual(len(calls), 1, action)
            call = calls[0]
            self.assertEqual(call['transportRef'], ref('transport'))
            self.assertEqual(call['grantRef'], fixture.operator_grants['federation-work-'+action])
            self.assertEqual(call['payload']['attribution'], 'operator')
            self.assertEqual(call['payload']['input']['onBehalfOf'],
                {'session':target, 'generation':registered['generation']})
        tcp_call, = [row for row in submitted if row['contractId']=='federation-work-create'
            and row['payload']['input'].get('title')=='TCP operator']
        self.assertEqual(tcp_call['payload']['attribution'], 'operator')
        self.assertNotIn('onBehalfOf', tcp_call['payload']['input'])
        await fixture.command('identity-revoke', ref('grant'), {'authorityId':'authority-one',
            'targetRef':fixture.operator_grants['federation-work-claim']})
        denied = await request('claim', {}, 'revoked-claim')
        self.assertFalse(denied['ok'], denied)
        self.assertEqual(await fixture.resource._owner.db(fixture.resource._store.q1,
            'SELECT * FROM work_items WHERE id=?', (created['id'],)), released)
        fixture.success = True
