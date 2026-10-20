"""AMUX-669 real peer publication through selected ingress and Hub withdrawal."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import threading
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from hub.fed import envelope
from hub.fed.peer_control import HEADER_REPOSITORY
from hub.fed.session import FederationSession
from hub.server import Hub
from identity.application_client import ApplicationClientKey
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref, SEED
from identity.test_peer_control_live import LivePeerControlTests
from identity.peer_control import HEADER
from .work import WorkStorageResource
from .work_bridge_service import WorkBridgeService
from .work_control import WorkControlOwner
from hub.fed.peer_control import PeerControlPublisher
from .legacy_work_client import LegacyWorkCommandClient
from .federated_work_client import FederatedWorkCommandClient, WorkBridgeIntents
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageHost
from .test_peer_control_command_live import LivePeerControlCommandTests


class LiveWorkControlTests(LivePeerControlCommandTests):
    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        policies['federation']['subscribe']['allow'].append('am.ctl.alice')

    def initial_authority(self):
        record = super().initial_authority()
        state = record['state']
        transport = copy.deepcopy(next(t for t in state['transports'] if t['ref'] == ref('message-service-transport')))
        transport['ref'] = ref('work-control-service-transport')
        state['transports'].append(transport)
        grant = copy.deepcopy(state['grants'][0])
        self.work_grants = {}
        for command in ('ingest', 'revoke', 'inspect', 'outcome'):
            contract = 'federation-work-' + command
            row = {**grant, 'ref': ref('work-control-' + command), 'contractId': contract,
                'callerRef': ref('service'), 'actorRef': ref('service'), 'scope': copy.deepcopy(self.scope),
                'resourceId': 'work-one', 'decision': 'allowed', 'delegationRef': None}
            state['grants'].append(row)
            self.work_grants[contract] = row['ref']
        for name in ('control-peer', 'control-nick'):
            original = next(g for g in state['grants'] if g['ref'] == ref(name + '-grant'))
            state['grants'].append({**copy.deepcopy(original), 'ref': ref('work-' + name + '-grant'),
                'resourceId': 'work-one'})
        return record

    async def asyncSetUp(self):
        await LivePeerControlTests.asyncSetUp(self)
        self.application_owners, self.actual_hub, self.control_host = [], None, None
        self._observation_task = None
        self.addAsyncCleanup(self._work_cleanup)
        await self.receiver.close()
        await self.control_ingress.close(timeout=None)
        await self.control_source.close()
        self.control_ingress = self.control_source = None
        selected = copy.deepcopy(self.value)
        selected['storage']['work'] = copy.deepcopy(selected['storage']['knowledge'])
        selected['storage']['work']['channels'][0].update(resourceRef=ref('work-one'), initialSource=None)
        selected['peerControl']['routes'][0]['resourceRef'] = ref('work-one')
        selected['peerControl']['routes'][0]['peer']['grantRef'] = ref('work-control-peer-grant')
        selected['storage']['work']['channels'][0]['legacyActors'] = [{
            'identityRef': ref('service'), 'transportRef': ref('work-control-service-transport'),
            'caller': 'federation', 'grants': self.work_grants}]
        selection = ApplicationServiceSelection(canonical_bytes(selected))
        self.control_host = SelectedStorageHost(selection, identity=self.identity)
        await self.control_host._work(selected['storage']['work'])
        self.resource = next(r for r in self.control_host._resources if type(r) is WorkStorageResource)
        self.controls = WorkControlOwner(selection, self.identity, (self.resource,))
        self.control_host._work_controls.append(self.controls)
        await self.controls.start()
        await self.control_publisher.close(timeout=None)
        sender = copy.deepcopy(self.sender_selection.policy)
        sender['storage']['work'] = copy.deepcopy(sender['storage']['knowledge'])
        sender['storage']['work']['channels'][0].update(resourceRef=ref('work-one'), initialSource=None)
        pin = sender['peerControl']['routes'][0]
        pin['resourceRef'] = ref('work-one')
        pin['peer']['grantRef'] = ref('work-control-nick-grant')
        pin['publisher']['grantRef'] = ref('work-control-peer-grant')
        self.control_publisher = PeerControlPublisher(ApplicationServiceSelection(canonical_bytes(sender)),
            self.identity, route_id=pin['routeId'])
        await self.control_publisher.start()
        self.control_ingress = next(iter(self.controls._routes.values()))
        bridge = WorkBridgeService(self.identity.ingress, resources=(self.resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.receiver = CapabilityReplyService(self.identity.reader, resources=[self.resource],
            hub_id='hub-one', profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage,
            work_bridge=bridge)
        await self.receiver.start()

    async def _work_cleanup(self):
        if self.actual_hub is not None:
            await self.actual_hub._work_storage_commands.close(timeout=None)
            await self.actual_hub.fed.finish_cleanup()
            await self.actual_hub.db(self.actual_hub.store.db.close)
            self.actual_hub.dbx.shutdown(wait=True)
            self.actual_hub.io.shutdown(wait=True)
        for owner in self.application_owners:
            await owner.close(deadline=asyncio.get_running_loop().time() + 2)
        if self.receiver is not None:
            await self.receiver.close()
        if self.control_host is not None:
            await self.control_host.close(timeout=None)
        if self._observation_task is not None:
            self._observation_task.cancel()
            await asyncio.gather(self._observation_task, return_exceptions=True)

    async def actual_work_session(self):
        value = strict_loads(self.application_key(service=True)._material)
        command = value.pop('messageCommands')
        command.pop('peer')
        command.update(resourceRef=ref('work-one'), grantRefs=self.work_grants,
            transportRef=ref('work-control-service-transport'))
        value['workCommands'] = command
        key = ApplicationClientKey(value)
        connection = await self.connect('federation-application')
        binding = ClientBindingState(connection, public_key=self.issuer_public,
            signing_key_ref=ref('issuer'), caller_ref=ref('service'), scope=self.scope)
        owner = ClientConnectionOwner(connection, binding, command_subject=self.identity_subject,
            reply_prefix=self.inbox_prefixes['federation-application'], signer=key)
        self.application_owners.append(owner)
        owner._connected = True  # This exact scoped TLS/JWT connection was admitted above.
        self.refresh_observation()
        loop = asyncio.get_running_loop()
        await owner.authenticate(key, deadline=loop.time() + 3, cleanup_deadline=loop.time() + 4)
        session = object.__new__(ApplicationClientSession)
        session._owner, session._loop, session._thread = owner, loop, threading.current_thread()
        session._loop_stopping = session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = session._command_future = session._command_identity = None
        session._work_enrollment = canonical_bytes({k: key.selection[k] for k in
            ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'workCommands')})
        return session, owner

    async def test_actual_control_plugin_owner_lost_reply_and_original_recovery(self):
        async def observe():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task = asyncio.create_task(observe())
        session, owner = await self.actual_work_session()
        (self.directory / 'config.toml').write_text('node="mac"\nbackup_every_s=9007199254740991\n'
            'prune_every_s=9007199254740991\n')
        (self.directory / 'federation.toml').write_text('[federation]\npeer="nick"\nplugins=["work"]\n'
            'capture=false\nnotify_findings=false\n'
            '[repos.falcon]\nremote="' + self.control_host._selection.policy['storage']['work']['repository']['normalizedRemote']
            + '"\n[peers.alice]\ntrust="auto"\n')
        from hub import server as hub_server
        with patch.object(hub_server, 'ROOT', str(self.directory / 'root')), \
                patch.object(hub_server, 'HUBDIR', str(self.directory)), \
                patch.object(hub_server, 'SOCK', str(self.directory / 'hub.sock')):
            hub = self.actual_hub = Hub(work_sessions=(session,))
        fed = hub.fed
        self.assertEqual(fed.policy.rid_of('falcon'), self.resource.repository_id)
        fed.session, fed.nc = FederationSession(), await self.connect('federation')
        source = self.resource._owner._source
        def seed():
            store = source._store
            row = store.work_create('operator', 'falcon', 'role:falcon/worker', 'Retained remote work',
                body='Original retained body')
            store.db.execute("UPDATE work_items SET origin_peer='alice' WHERE id=?", (row['id'],))
            return store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))
        before = await source.db(seed)
        original = envelope.make('revoke', 'alice', 'mac_alice', data={'reason': 'Owner self-revoke'})
        mallory = await self.connect('control-mallory')
        for role, connection in (('control-mallory', mallory), ('host', self.host)):
            for subject in ('am.ctl.alice', 'am.ctl.*', 'am.ctl.>'):
                previous = len(self.errors[role])
                self.permission_events[role].clear()
                await connection.publish(subject, canonical_bytes(original))
                await connection.flush(timeout=1)
                await self.wait_permissions(role, previous + 1)
        received, admitted = asyncio.Event(), asyncio.Event()
        admission = self.control_ingress._dispatch
        async def retain(message, handle):
            await admission(message, handle)
            admitted.set()
        self.control_ingress._dispatch = retain
        async def callback(message):
            try:
                await fed._on_ctl(message)
            finally:
                received.set()
        await fed.nc.subscribe_owned(fed.session, 'am.ctl.alice', cb=callback)
        await fed.nc.flush(timeout=1)
        publish, dropped = self.storage.publish, []
        async def lose_reply(subject, raw, **kwargs):
            claims = strict_loads(raw).get('claims', {})
            if (not dropped and subject.startswith(self.inbox_prefixes['federation-application'] + '.')
                    and claims.get('requestContractId') == 'federation-work-revoke'
                    and claims['result']['outcome'] == 'applied'):
                dropped.append(raw)
                return
            return await publish(subject, raw, **kwargs)
        with patch.object(self.storage, 'publish', side_effect=lose_reply):
            await self.control_publisher.publish_revoke(original)
            await asyncio.wait_for(admitted.wait(), 3)
            await asyncio.wait_for(received.wait(), 7)
            # The independently owned subscriptions can arrive in either order.
            # The original retained client intent reconciles that same event.
            if not dropped:
                await fed._work_commands.recover_controls()
        self.assertEqual(len(dropped), 1, 'The actual applied owner reply must be lost')
        pending = await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'")
        self.assertEqual(len(pending), 1)
        retained = strict_loads(pending[0]['v'])
        self.assertEqual(retained['payload']['input']['control']['eventId'], original['id'])
        self.assertEqual(retained['payload']['input']['control']['eventDigest'], payload_digest(original))
        await hub._work_storage_commands.close(timeout=None)
        await owner.close(deadline=asyncio.get_running_loop().time() + 2)
        replacement, fresh = await self.actual_work_session()
        hub._work_storage_commands = LegacyWorkCommandClient(hub, (replacement,))
        fed._work_commands = FederatedWorkCommandClient(fed, hub._work_storage_commands)
        fed._work_intents = WorkBridgeIntents(fed, fed._work_commands)
        await fed._work_commands.recover_controls()
        query = strict_loads(fresh.command_request)['claims']
        self.assertEqual(query['contractId'], 'federation-work-outcome')
        self.assertEqual(query['payload']['input']['operationId'], retained['operationId'])
        self.assertEqual(query['payload']['input']['payloadDigest'], payload_digest(retained['payload']))
        self.assertEqual(await hub.db(hub.store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        after = await source.db(source._store.q1, 'SELECT * FROM work_items WHERE id=?', (before['id'],))
        self.assertEqual(after['state'], 'cancelled')
        self.assertEqual(after['result'], 'withdrawn by alice')
        self.assertEqual({k: v for k, v in after.items() if k not in ('state', 'result', 'updated')},
            {k: v for k, v in before.items() if k not in ('state', 'result', 'updated')})
        audit = await source.db(source._store.q, "SELECT * FROM fed_audit WHERE decision='work-revoke'")
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['msg_id'], original['id'])
        self.assertNotEqual(self.resource._owner.policy.trust('alice'), 'deny')
        proof_row = await source.db(source._store.q1, 'SELECT v FROM fed_state WHERE k=?',
            (self.control_ingress._key(original['id']),))
        signature = strict_loads(proof_row['v'])['signature']
        original_callback = self.control_ingress._subscription._cb
        completed, refused = asyncio.Event(), []
        async def observe_refusal(message):
            try:
                await original_callback(message)
            except ContractError:
                refused.append(True)
                raise
            finally:
                completed.set()
        self.control_ingress._subscription._cb = observe_refusal
        for headers in (None, {HEADER: signature},
                {HEADER: signature, HEADER_REPOSITORY: 'r000000000000'},
                {HEADER: 'A' * 86 + '==', HEADER_REPOSITORY: self.resource.repository_id}):
            completed.clear()
            received.clear()
            await self.admin.publish('am.ctl.alice', canonical_bytes(original), headers=headers)
            await self.admin.flush(timeout=1)
            await asyncio.wait_for(completed.wait(), 1)
            await asyncio.wait_for(received.wait(), 5)
            self.assertIsNone(fresh._close_task)
            self.assertEqual(await hub.db(hub.store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        self.assertEqual(refused, [True] * 4)
        self.control_ingress._subscription._cb = original_callback
        # Repeated broker publication reconciles the completed original intent.
        received.clear()
        await self.control_publisher.publish_revoke(original)
        await asyncio.wait_for(received.wait(), 5)
        self.assertEqual(len(await source.db(source._store.q,
            "SELECT * FROM fed_audit WHERE decision='work-revoke'")), 1)
        await self.command('identity-revoke', ref('grant'),
            {'authorityId': 'authority-one', 'targetRef': ref('work-control-peer-grant')})
        # A committed original remains recoverable under current service
        # authority, while the expired/revoked peer proof grants no new effect.
        query_payload = {'resourceRef': retained['payload']['resourceRef'], 'input': {
            'contractId': retained['contractId'], 'operationId': retained['operationId'],
            'payloadDigest': payload_digest(retained['payload'])}}
        recovered = await asyncio.to_thread(replacement.work_command,
            contract_id='federation-work-outcome', operation_id='live-revoked-peer-original-outcome',
            payload=query_payload, expires_at=(datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat())
        self.assertEqual(recovered['operationId'], retained['operationId'])
        self.assertEqual(recovered['outcome'], 'applied')
        await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one',
            'targetRef': self.work_grants['federation-work-revoke']})
        denied, denied_owner = await self.actual_work_session()
        with self.assertRaises(ApplicationSessionFailure):
            await asyncio.to_thread(denied.work_command, contract_id='federation-work-outcome',
                operation_id='live-denied-original-outcome', payload=query_payload,
                expires_at=(datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat())
        await denied_owner.close(deadline=asyncio.get_running_loop().time() + 2)
        self.assertFalse(denied_owner._subscriptions)
        self.assertTrue(denied_owner._close_task.done())
        self.success = True
