"""Actual operator control publication reaches the remote Work owner."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import time
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, payload_digest, strict_loads
from hub.client_launch_session import ApplicationSessionFailure
from hub.fed.session import FederationSession
from hub.server import Hub
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref, SEED

from .peer_control_client import PeerControlCommandClient
from .peer_control_service import PeerControlCommandService
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageHost
from .test_work_control_live import LiveWorkControlTests
from .work_bridge_service import WorkBridgeService


class LiveWorkOperatorControlTests(LiveWorkControlTests):
    def initial_authority(self):
        record = super().initial_authority()
        for grant in record['state']['grants']:
            if grant['ref'] in self.control_grants.values():
                grant['resourceId'] = 'work-one'
        return record

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.operator_hub = self.sender_host = None
        self.addAsyncCleanup(self._operator_cleanup)
        # Reuse Alice's separately owned source. Nick's receiving source has a
        # different local peer and must never lend custody to this publisher.
        selected = copy.deepcopy(self.control_publisher._selection.policy)
        selected['storage'].pop('knowledge')
        route = selected['peerControl']['routes'][0]
        route['operators'] = [{'identityRef': ref('human'),
            'transportRef': ref('control-operator-transport'), 'grants': self.control_grants}]
        self.sender_selection = ApplicationServiceSelection(canonical_bytes(selected))
        await self.control_publisher.close(timeout=None)
        self.sender_host = SelectedStorageHost(self.sender_selection, identity=self.identity)
        # Full selected startup is qualified separately by AMUX-673. This test
        # composes its existing Work and publication slices on the real broker.
        await self.sender_host._work(selected['storage']['work'])
        await self.sender_host._peer_control()
        self.control_publisher = self.sender_host._peer_control_publishers[0]
        self._withdrawal_ready = asyncio.Event()
        await self._receive_phase(publication=True)

    async def _receive_phase(self, *, publication):
        # The reused fixture gives both logical peers one command subject.
        # Serialize real exchanges instead of mixing their source custody or
        # racing two receivers. Simultaneous deployment remains AMUX-286.
        await self.receiver.close()
        work_bridge = control_endpoint = None
        resources = (self.resource,)
        if publication:
            resources = tuple(self.sender_host._resources)
            control_endpoint = PeerControlCommandService(self.identity.ingress,
                self.sender_host._peer_control_owners[0], service_identity_ref=ref('service'),
                service_instance_id='ingress-one', signing_key_ref=ref('issuer'), signing_seed=SEED)
            self.addAsyncCleanup(control_endpoint.close, timeout=None)
        else:
            work_bridge = WorkBridgeService(self.identity.ingress, resources=resources,
                service_identity_ref=ref('service'), service_instance_id='ingress-one',
                signing_key_ref=ref('issuer'), signing_seed=SEED)
            self.addAsyncCleanup(work_bridge.close, timeout=None)
        self.receiver = CapabilityReplyService(self.identity.reader, resources=resources,
            hub_id='hub-one', profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage,
            work_bridge=work_bridge, peer_control=control_endpoint)
        await self.receiver.start()

    async def _operator_cleanup(self):
        if hasattr(self, '_withdrawal_ready'):
            self._withdrawal_ready.set()
        if self.operator_hub is not None:
            await self.operator_hub._peer_control_commands.close(timeout=None)
            await self.operator_hub.fed.finish_cleanup()
            await self.operator_hub.db(self.operator_hub.store.db.close)
            self.operator_hub.dbx.shutdown(wait=True)
            self.operator_hub.io.shutdown(wait=True)
        if self.receiver is not None:
            await self.receiver.close()
        if self.sender_host is not None:
            await self.sender_host.close(timeout=None)

    def _hub(self, directory, *, operator_session=None, work_session=None):
        directory.mkdir(mode=0o700, exist_ok=True)
        operator = operator_session is not None
        peer, node = ('alice', 'mac_alice') if operator else ('nick', 'mac')
        (directory / 'config.toml').write_text('node="' + node + '"\n'
            'backup_every_s=9007199254740991\nprune_every_s=9007199254740991\n')
        (directory / 'federation.toml').write_text('[federation]\npeer="' + peer + '"\n'
            'plugins=' + ('[]' if operator else '["work"]') + '\ncapture=false\nnotify_findings=false\n'
            '[repos.falcon]\nremote="' + self.sender_selection.policy['storage']['work']['repository']['normalizedRemote']
            + '"\n[peers.' + ('nick' if operator else 'alice') + ']\ntrust="auto"\n')
        from hub import server as hub_server
        with patch.object(hub_server, 'ROOT', str(directory / 'root')), \
                patch.object(hub_server, 'HUBDIR', str(directory)), \
                patch.object(hub_server, 'SOCK', str(directory / 'hub.sock')):
            return Hub(peer_control_sessions=(operator_session,) if operator else None,
                work_sessions=(work_session,) if work_session is not None else None)

    async def test_operator_kill_lost_reply_recovery_withdraws_remote_work_once(self):
        async def observe():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task = asyncio.create_task(observe())
        work_session, _ = await self.actual_work_session()
        operator_session, operator_owner = await self.actual_session()
        nick = self.actual_hub = self._hub(self.directory / 'work-receiver-hub', work_session=work_session)
        alice = self.operator_hub = self._hub(self.directory / 'work-operator-hub',
            operator_session=operator_session)
        nick.fed.session, nick.fed.nc = FederationSession(), await self.connect('federation')
        receiving_source = self.resource._owner._source
        publishing_source = self.sender_host._peer_control_owners[0]._source
        self.assertIsNot(receiving_source, publishing_source)
        self.assertEqual((receiving_source._peer, publishing_source._peer), ('nick', 'alice'))
        self.assertIsNot(nick.store, receiving_source._store)
        self.assertIsNot(alice.store, publishing_source._store)
        self.assertNotIn('knowledge', self.sender_selection.policy['storage'])

        def seed():
            store = receiving_source._store
            rows = []
            for peer, state in (('alice', 'ready'), ('alice', 'claimed'), ('bob', 'ready')):
                row = store.work_create('operator', 'falcon', 'role:falcon/worker', 'Original ' + peer + state,
                    body='Original retained body')
                store.db.execute('UPDATE work_items SET origin_peer=?, state=? WHERE id=?',
                    (peer, state, row['id']))
                rows.append(store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)))
            return rows
        before = await receiving_source.db(seed)
        admitted, received = asyncio.Event(), asyncio.Event()
        admission = self.control_ingress._dispatch
        async def retain(message, handle):
            await admission(message, handle)
            admitted.set()
        self.control_ingress._dispatch = retain
        async def callback(message):
            # These independently owned subscriptions can arrive in either
            # order; keep this real callback until protected admission finishes.
            await asyncio.wait_for(admitted.wait(), 3)
            await self._withdrawal_ready.wait()
            try:
                await nick.fed._on_ctl(message)
            finally:
                received.set()
        await nick.fed.nc.subscribe_owned(nick.fed.session, 'am.ctl.alice', cb=callback)
        await nick.fed.nc.flush(timeout=1)
        token = (self.directory / 'work-operator-hub' / 'operator.token').read_text().strip()
        request = {'token': token, 'verb': 'fed_kill', 'args': {'revoke': True}}
        published = []
        send_control = self.control_publisher._connection.publish
        async def observe_publication(subject, raw, **kwargs):
            published.append((subject, raw, copy.deepcopy(kwargs)))
            return await send_control(subject, raw, **kwargs)
        publication = patch.object(self.control_publisher._connection, 'publish', side_effect=observe_publication)
        publication.start()
        self.addCleanup(publication.stop)
        publish, dropped = self.storage.publish, []
        async def lose_reply(subject, raw, **kwargs):
            claims = strict_loads(raw).get('claims', {})
            if (not dropped and subject.startswith(self.inbox_prefixes['caller-application'] + '.')
                    and claims.get('requestContractId') == 'federation-peer-revoke'):
                dropped.append(raw)
                return
            return await publish(subject, raw, **kwargs)
        with patch.object(self.storage, 'publish', side_effect=lose_reply):
            first = await self.hub_request(alice, request)
        self.assertTrue(first['ok'], first)
        self.assertEqual(first['result']['revoke_publication'], 'unconfirmed')
        self.assertEqual(len(dropped), 1)
        # The original publication exchange has joined. Change only the
        # fixture receiver, then run the retained real callback with fresh
        # Work admission; no original request deadline is extended.
        await self._receive_phase(publication=False)
        self._withdrawal_ready.set()
        await asyncio.wait_for(received.wait(), 7)
        original = strict_loads(operator_owner.command_request)['claims']
        item = original['payload']['input']['envelope']
        self.assertEqual((item['from'], item['node'], item['type']), ('alice', 'mac_alice', 'revoke'))
        pending = await alice.db(alice.store.q, "SELECT v FROM fed_state WHERE k LIKE 'peer-control-client:%'")
        self.assertEqual(len(pending), 1)
        retained = strict_loads(pending[0]['v'])
        self.assertEqual(retained['operationId'], original['operationId'])
        self.assertEqual(retained['payload'], original['payload'])
        await self._receive_phase(publication=True)
        await alice._peer_control_commands.close(timeout=None)
        await operator_owner.close(deadline=asyncio.get_running_loop().time() + 2)
        self.assertFalse(operator_owner._subscriptions)
        replacement, fresh_owner = await self.actual_session()
        alice._peer_control_commands = PeerControlCommandClient(alice, (replacement,)).bind(alice.fed)
        recovered = await self.hub_request(alice, request)
        self.assertTrue(recovered['ok'], recovered)
        self.assertEqual(recovered['result']['revoke_publication'], 'published')
        result = recovered['result']['revoke_results'][0]
        self.assertEqual(result, strict_loads(dropped[0])['claims']['result'])
        self.assertEqual(result['eventId'], item['id'])
        query = strict_loads(fresh_owner.command_request)['claims']
        self.assertEqual(query['contractId'], 'federation-peer-revoke-outcome')
        self.assertEqual(query['payload']['input']['operationId'], original['operationId'])
        self.assertEqual(query['payload']['input']['payloadDigest'], payload_digest(original['payload']))
        proof_rows = await receiving_source.db(receiving_source._store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'peer-control:%'")
        self.assertEqual(len(proof_rows), 1)
        proof = strict_loads(proof_rows[0]['v'])
        self.assertEqual(proof['event'], item)
        self.assertEqual(proof['eventDigest'], payload_digest(item))
        self.assertEqual(len(published), 1)
        self.assertEqual((published[0][0], strict_loads(published[0][1])), ('am.ctl.alice', item))
        after = await receiving_source.db(receiving_source._store.q,
            'SELECT * FROM work_items ORDER BY rowid')
        self.assertEqual((after[0]['state'], after[0]['result']), ('cancelled', 'withdrawn by alice'))
        self.assertEqual({k: v for k, v in after[0].items() if k not in ('state', 'result', 'updated')},
            {k: v for k, v in before[0].items() if k not in ('state', 'result', 'updated')})
        self.assertEqual(after[1:], before[1:])
        audit = await receiving_source.db(receiving_source._store.q,
            "SELECT * FROM fed_audit WHERE decision='work-revoke'")
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['msg_id'], item['id'])
        self.assertEqual(self.resource._owner.policy.trust('alice'), 'auto')
        publication_rows = await publishing_source.db(publishing_source._store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'peer-control-command:%'")
        self.assertEqual(len(publication_rows), 1)
        self.assertEqual(strict_loads(publication_rows[0]['v'])['original']['operation']['operationId'],
            original['operationId'])
        await self.command('identity-revoke', ref('grant'),
            {'authorityId': 'authority-one', 'targetRef': self.control_grants['federation-peer-revoke']})
        denied, denied_owner = await self.actual_session()
        with self.assertRaises(ApplicationSessionFailure):
            await asyncio.to_thread(denied.peer_control_command,
                contract_id='federation-peer-revoke-outcome', operation_id='work-revoked-original-outcome',
                payload=query['payload'], expires_at=(datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat(),
                deadline=time.monotonic() + .75)
        await denied_owner.close(deadline=asyncio.get_running_loop().time() + 2)
        self.assertFalse(denied_owner._subscriptions)
        self.assertTrue(denied_owner._close_task.done())
        self.assertEqual(await receiving_source.db(receiving_source._store.q,
            "SELECT * FROM fed_audit WHERE decision='work-revoke'"), audit)
        self.assertEqual(len(published), 1)
        self.success = True
