"""One real Hub operator route through enrolled application and peer control."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import secrets
import threading
import time
from unittest.mock import patch

import nkeys

from agentmux_contracts import canonical_bytes, payload_digest, strict_loads
from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner
from hub.client_launch_session import ApplicationClientSession
from hub.client_launch_session import ApplicationSessionFailure
from hub.server import Hub
from identity.application_client import ApplicationClientKey
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref, SEED
from identity.test_peer_control import PeerControlTests
from identity.test_peer_control_live import LivePeerControlTests
from native_security.nats_credentials import _JWT
from .peer_control_service import PeerControlCommandService
from .peer_control_client import PeerControlCommandClient
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageHost
from .test_legacy_messages_live import LegacyMessageLiveFixture


class LivePeerControlCommandTests(LegacyMessageLiveFixture, PeerControlTests):
    private_inbox_roles = ('identity', 'storage', 'host', 'other-scope',
        'caller-application', 'federation-application')
    setUp = LivePeerControlTests.setUp
    _credential = LivePeerControlTests._credential
    _control_cleanup = LivePeerControlTests._control_cleanup

    def configure_broker_policies(self, policies, reads):
        LegacyMessageLiveFixture.configure_broker_policies(self, policies, reads)
        for role, peer in (('control-alice', 'alice'), ('control-nick', 'nick'), ('control-mallory', 'mallory')):
            self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
            policies[role] = {'publish': {'allow': ['am.ctl.' + peer]}, 'subscribe': {'allow': []}}
        for role, peer in (('control-receiver', 'alice'), ('control-alice-receiver', 'nick')):
            self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
            policies[role] = {'publish': {'allow': []}, 'subscribe': {'allow': ['am.ctl.' + peer]}}

    def _configure_tls_and_users(self):
        LegacyMessageLiveFixture._configure_tls_and_users(self)
        paths = list((self.directory / 'nsc-keys').rglob(self.account_public_key + '.nk'))
        if len(paths) != 1:
            raise RuntimeError('peer_control_fixture_account_key_unavailable')
        account = nkeys.from_seed(paths[0].read_bytes().strip())
        try:
            for role in ('control-alice', 'control-nick', 'control-mallory', 'control-receiver', 'control-alice-receiver'):
                path = self.credentials[role]
                raw = path.read_bytes()
                token = _JWT.findall(raw)[0]
                header, body, _ = token.split(b'.')
                claims = strict_loads(base64.urlsafe_b64decode(body + b'=' * (-len(body) % 4)))
                if role in ('control-receiver', 'control-alice-receiver'):
                    claims['nats']['pub'] = {'allow': [], 'deny': ['>']}
                    claims['nats']['sub'] = {'allow': ['am.ctl.nick' if role == 'control-alice-receiver' else 'am.ctl.alice']}
                else:
                    claims['nats']['pub'] = {'allow': ['am.ctl.' + role.removeprefix('control-')]}
                    claims['nats']['sub'] = {'allow': [], 'deny': ['>']}
                claims.pop('jti', None)
                body = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                updated = header + b'.' + body
                updated += b'.' + base64.urlsafe_b64encode(account.sign(updated)).rstrip(b'=')
                path.write_bytes(raw.replace(token, updated, 1))
        finally:
            account.wipe()

    def initial_authority(self):
        record = LegacyMessageLiveFixture.initial_authority(self)
        state = record['state']
        template = copy.deepcopy(state['transports'][0])
        grant = copy.deepcopy(state['grants'][0])
        for name, role in (('control-receiver', 'control-receiver'), ('control-peer', 'control-alice'),
                ('control-nick', 'control-nick'), ('control-alice-receiver', 'control-alice-receiver')):
            pin, _ = self._credential(role)
            public = base64.b32decode(pin['userPublicKey'] + '=' * (-len(pin['userPublicKey']) % 8))[1:-2]
            state['identities'].append({'ref': ref(name), 'kind': 'service', 'status': 'active',
                'principalId': name, 'externalIdentity': None})
            state['transports'].append({**template, 'ref': ref(name + '-transport'), 'identityRef': ref(name),
                'issuerRef': ref('issuer'), 'publicKey': base64.urlsafe_b64encode(public).decode().rstrip('=')})
            state['memberships'].append({'ref': ref(name + '-member'), 'identityRef': ref(name),
                'scope': copy.deepcopy(self.scope), 'status': 'active'})
            if name in ('control-peer', 'control-nick'):
                state['grants'].append({**grant, 'ref': ref(name + '-grant'), 'callerRef': ref(name),
                    'actorRef': ref(name), 'scope': copy.deepcopy(self.scope), 'contractId': 'peer-control-revoke',
                    'resourceId': 'knowledge-one', 'decision': 'allowed', 'delegationRef': None})
        transport = copy.deepcopy(next(t for t in state['transports'] if t['ref'] == ref('transport')))
        transport['ref'] = ref('control-operator-transport')
        state['transports'].append(transport)
        self.control_grants = {}
        for contract in ('federation-peer-revoke', 'federation-peer-revoke-outcome'):
            row = {**grant, 'ref': ref('operator-' + contract), 'callerRef': ref('human'), 'actorRef': ref('human'),
                'scope': copy.deepcopy(self.scope), 'contractId': contract, 'resourceId': 'knowledge-one',
                'decision': 'allowed', 'delegationRef': None}
            state['grants'].append(row)
            self.control_grants[contract] = row['ref']
        return record

    async def asyncSetUp(self):
        # Reuse the accepted selected control fixture, with this fixture's real
        # application discovery/binding receiver and retained identity service.
        await LivePeerControlTests.asyncSetUp(self)
        self.application_owners = []
        self.control_host = self.actual_hub = None
        self._observation_task = None
        self.addAsyncCleanup(self._command_cleanup)
        await self.control_publisher.close(timeout=None)
        await self.receiver.close()
        selected = copy.deepcopy(self.sender_selection.policy)
        route = selected['peerControl']['routes'][0]
        route['operators'] = [{'identityRef': ref('human'), 'transportRef': ref('control-operator-transport'),
            'grants': self.control_grants}]
        self.sender_selection = ApplicationServiceSelection(canonical_bytes(selected))
        host = self.control_host = SelectedStorageHost(self.sender_selection, identity=self.identity)
        await host._knowledge(selected['storage']['knowledge'])
        await host._peer_control()
        self.control_publisher = host._peer_control_publishers[0]
        self.control_endpoint = PeerControlCommandService(self.identity.ingress, host._peer_control_owners[0],
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.receiver = CapabilityReplyService(self.identity.reader, resources=host._resources,
            hub_id='hub-one', profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage,
            peer_control=self.control_endpoint)
        await self.receiver.start()

    async def _command_cleanup(self):
        if self.actual_hub is not None:
            await self.actual_hub._peer_control_commands.close(timeout=None)
            await self.actual_hub.fed.finish_cleanup()
            await self.actual_hub.db(self.actual_hub.store.db.close)
            self.actual_hub.dbx.shutdown(wait=True)
            self.actual_hub.io.shutdown(wait=True)
        if self.receiver is not None:
            await self.receiver.close()
        if self.control_host is not None:
            await self.control_host.close(timeout=None)
        if self._observation_task is not None:
            self._observation_task.cancel()
            await asyncio.gather(self._observation_task, return_exceptions=True)

    def control_key(self):
        selected = strict_loads(self.application_key()._material)
        route = selected.pop('messageCommands')
        route.pop('peer')
        pin = self.sender_selection.policy['peerControl']['routes'][0]
        route.update(routeId=pin['routeId'], grantRefs=self.control_grants, resourceRef=pin['resourceRef'],
            repository={k: pin['repository'][k] for k in ('localName', 'repositoryId')},
            localPeer='alice', localNode='mac_alice', transportRef=ref('control-operator-transport'))
        selected['peerControlCommands'] = route
        return ApplicationClientKey(selected)

    async def actual_session(self):
        key = self.control_key()
        connection = await self.connect('caller-application')
        binding = ClientBindingState(connection, public_key=self.issuer_public,
            signing_key_ref=ref('issuer'), caller_ref=ref('human'), scope=self.scope)
        owner = ClientConnectionOwner(connection, binding, command_subject=self.identity_subject,
            reply_prefix=self.inbox_prefixes['caller-application'], signer=key)
        self.application_owners.append(owner)
        owner._connected = True  # The fixture just admitted this exact TLS/JWT connection.
        self.refresh_observation()
        loop = asyncio.get_running_loop()
        await owner.authenticate(key, deadline=loop.time() + 3, cleanup_deadline=loop.time() + 4)
        session = object.__new__(ApplicationClientSession)
        session._owner, session._loop, session._thread = owner, loop, threading.current_thread()
        session._loop_stopping = session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = session._command_future = session._command_identity = None
        session._peer_control_enrollment = canonical_bytes({k: key.selection[k] for k in
            ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'peerControlCommands')})
        return session, owner

    async def hub_request(self, hub, request):
        handling = set()
        async def receive(reader, writer):
            original = asyncio.current_task()
            handling.add(original)
            try:
                await hub.handle_conn(reader, writer, tcp=True)
            finally:
                writer.close()
                await writer.wait_closed()
                handling.discard(original)
        server = await asyncio.start_server(receive, '127.0.0.1', 0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            try:
                writer.write(canonical_bytes(request) + b'\n')
                await writer.drain()
                return json.loads(await asyncio.wait_for(reader.readline(), 7))
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
            if handling:
                await asyncio.gather(*tuple(handling))

    async def test_actual_hub_enrolled_owner_publication_and_admitted_peer_receipt(self):
        async def maintain_observation():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task = asyncio.create_task(maintain_observation())
        session, owner = await self.actual_session()
        (self.directory / 'config.toml').write_text('node="mac_alice"\nbackup_every_s=9007199254740991\n'
            'prune_every_s=9007199254740991\n')
        (self.directory / 'federation.toml').write_text('[federation]\npeer="alice"\nplugins=[]\n'
            '[repos.falcon]\nremote="example.invalid/falcon"\n[peers.nick]\ntrust="auto"\n')
        from hub import server as hub_server
        with patch.object(hub_server, 'ROOT', str(self.directory / 'root')), \
                patch.object(hub_server, 'HUBDIR', str(self.directory)), \
                patch.object(hub_server, 'SOCK', str(self.directory / 'hub.sock')):
            hub = self.actual_hub = Hub(peer_control_sessions=(session,))
        token = (self.directory / 'operator.token').read_text().strip()
        request = {'token': token, 'verb': 'fed_kill', 'args': {'revoke': True}}
        original_publish, dropped = self.storage.publish, []
        async def lose_original_reply(subject, raw, **kwargs):
            if (not dropped and subject.startswith(self.inbox_prefixes['caller-application'] + '.')
                    and strict_loads(raw)['claims'].get('requestContractId') == 'federation-peer-revoke'):
                dropped.append(raw)
                return
            return await original_publish(subject, raw, **kwargs)
        with patch.object(self.storage, 'publish', side_effect=lose_original_reply):
            reply = await self.hub_request(hub, request)
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(len(dropped), 1)
        self.assertEqual(reply['result']['revoke_publication'], 'unconfirmed')
        killed = await hub.db(hub.store.q1, 'SELECT v FROM fed_state WHERE k=?', ('killed',))
        self.assertEqual(strict_loads(killed['v']), reply['result'])
        self.assertIsNotNone(reply['result']['withdrawn_outbox'])
        await asyncio.wait_for(self.received.wait(), 3)
        self.assertEqual(len(self.proofs), 1)
        proof = strict_loads(self.proofs[0])
        original = strict_loads(owner.command_request)['claims']
        item = original['payload']['input']['envelope']
        self.assertEqual(proof['event'], item)
        self.assertEqual(item['from'], 'alice')
        self.assertEqual(item['type'], 'revoke')
        self.assertEqual(proof['eventDigest'], payload_digest(item))
        self.assertFalse(hub.fed.connected)
        await hub._peer_control_commands.close(timeout=2)
        await owner.close(deadline=asyncio.get_running_loop().time() + 2)
        self.assertFalse(owner._subscriptions)
        self.assertTrue(owner._close_task.done())
        replacement, fresh_owner = await self.actual_session()
        hub._peer_control_commands = PeerControlCommandClient(hub, (replacement,)).bind(hub.fed)
        recovered_reply = await self.hub_request(hub, request)
        self.assertTrue(recovered_reply['ok'], recovered_reply)
        self.assertEqual(recovered_reply['result']['revoke_publication'], 'published')
        self.assertEqual(recovered_reply['result']['revoke_results'][0], strict_loads(dropped[0])['claims']['result'])
        self.assertEqual(recovered_reply['result']['revoke_results'][0]['eventId'], item['id'])
        self.assertEqual(strict_loads(fresh_owner.command_request)['claims']['contractId'],
            'federation-peer-revoke-outcome')
        self.assertEqual(len(self.proofs), 1)
        self.assertNotIn('credentials', canonical_bytes(reply).decode())
        # Recover the same original effect through its real enrolled route, then
        # revoke current authority and refuse its disclosure on a fresh session.
        query = {'resourceRef': original['payload']['resourceRef'], 'input': {
            'routeId': original['payload']['input']['routeId'], 'operationId': original['operationId'],
            'payloadDigest': payload_digest(original['payload'])}}
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')
        recovered = await asyncio.to_thread(replacement.peer_control_command,
            contract_id='federation-peer-revoke-outcome', operation_id='live-original-outcome',
            payload=query, expires_at=expiry)
        self.assertEqual(recovered['eventId'], item['id'])
        self.assertEqual(recovered['outcome'], 'published')
        self.assertEqual(len(self.proofs), 1)
        await self.command('identity-revoke', ref('grant'),
            {'authorityId': 'authority-one', 'targetRef': self.control_grants['federation-peer-revoke']})
        denied, denied_owner = await self.actual_session()
        with self.assertRaises(ApplicationSessionFailure):
            await asyncio.to_thread(denied.peer_control_command,
                contract_id='federation-peer-revoke-outcome', operation_id='live-revoked-outcome',
                payload=query, expires_at=(datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat(),
                deadline=time.monotonic() + .75)
        # The synchronous wait can finish before its owned cleanup. Join that
        # same connection task before releasing the borrowed identity service.
        await denied_owner.close(deadline=asyncio.get_running_loop().time() + 2)
        self.assertFalse(denied_owner._subscriptions)
        self.assertTrue(denied_owner._close_task.done())
        self.assertEqual(len(self.proofs), 1)
        self.success = True
