"""Native protected core composition over the Hub's original physical source.

The existing source fixture opens the selected Work resource and supplies its
owned receiver. It does not exercise installed or full selected-host startup.
Only the ordinary legacy socket is controlled; source commands and protected
Work/result publication use the actual enrolled TLS/JWT broker connections.
"""
import asyncio
import base64
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import secrets
import tempfile
import time
from unittest.mock import patch

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import server
from hub.core_work_transport import CoreWorkPublisher
from hub.tests.test_bridge_selection import Connection
from identity.application_service_selection import ApplicationServiceSelection
from identity.core_work_transport import INGEST, RESULT
from identity.test_authority import ref, SEED
from native_security.nats_credentials import _JWT, _base32
from .core_work import CoreWorkOwner
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageHost
from .test_core_work_live import LiveCoreWorkTests
from .test_work_source_live import LiveWorkSourceTests
from .work import WorkStorageResource
from .work_bridge_service import WorkBridgeService
from .work_lifecycle_client import WorkLifecycleClient


class LiveWorkBridgeCompositionTests(LiveWorkSourceTests):
    core_receiver = LiveCoreWorkTests.core_receiver
    core_peer = LiveCoreWorkTests.core_peer
    core_publisher_pin = LiveCoreWorkTests.core_publisher_pin
    core_cleanup = LiveCoreWorkTests.core_cleanup
    wait_rows = LiveCoreWorkTests.wait_rows

    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        # The source and core fixtures have different control parents. Add the
        # existing finite core roles without running either parent twice.
        self.core_policies = {
            'core-alice': (['am.work.falcon.worker', 'am.result.mac'], []),
            'core-nick': (['am.work.falcon.worker', 'am.result.mac_alice'], []),
            'core-receiver': ([], ['am.work.falcon.worker', 'am.result.mac']),
            'core-alice-receiver': ([], ['am.work.falcon.worker', 'am.result.mac_alice']),
        }
        for role, (publish, subscribe) in self.core_policies.items():
            self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
            policies[role] = {'publish': {'allow': publish}, 'subscribe': {'allow': subscribe}}

    def _configure_tls_and_users(self):
        super()._configure_tls_and_users()
        paths = list((self.directory/'nsc-keys').rglob(self.account_public_key+'.nk'))
        if len(paths) != 1:
            raise RuntimeError('core_work_fixture_account_key_unavailable')
        account = nkeys.from_seed(paths[0].read_bytes().strip())
        try:
            for role, (publish, subscribe) in self.core_policies.items():
                path = self.credentials[role]
                raw = path.read_bytes()
                token = _JWT.findall(raw)[0]
                header, body, _ = token.split(b'.')
                claims = strict_loads(base64.urlsafe_b64decode(body+b'='*(-len(body)%4)))
                claims['nats']['pub'] = {'allow': publish} if publish else {'allow': [], 'deny': ['>']}
                claims['nats']['sub'] = {'allow': subscribe} if subscribe else {'allow': [], 'deny': ['>']}
                claims.pop('jti', None)
                encoded = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                updated = header+b'.'+encoded
                updated += b'.'+base64.urlsafe_b64encode(account.sign(updated)).rstrip(b'=')
                path.write_bytes(raw.replace(token, updated, 1))
        finally:
            account.wipe()

    def initial_authority(self):
        record = super().initial_authority()
        state = record['state']
        template = copy.deepcopy(state['transports'][0])
        grant = copy.deepcopy(state['grants'][0])
        for role in self.core_policies:
            pin, _ = self._credential(role)
            public = _base32(pin['userPublicKey'].encode(), 35)[1:-2]
            state['identities'].append({'ref': ref(role), 'kind': 'service', 'status': 'active',
                'principalId': role, 'externalIdentity': None})
            state['transports'].append({**template, 'ref': ref(role+'-transport'), 'identityRef': ref(role),
                'issuerRef': ref('issuer'), 'publicKey': base64.urlsafe_b64encode(public).decode().rstrip('=')})
            state['memberships'].append({'ref': ref(role+'-member'), 'identityRef': ref(role),
                'scope': copy.deepcopy(self.scope), 'status': 'active'})
            contracts = [INGEST, RESULT]
            if 'receiver' in role:
                contracts.extend(('federation-work-inspect', 'federation-work-outcome'))
            for contract in contracts:
                state['grants'].append({**copy.deepcopy(grant),
                    'ref': ref(role+'-'+contract.removeprefix('federation-work-')),
                    'callerRef': ref(role), 'actorRef': ref(role), 'scope': copy.deepcopy(self.scope),
                    'contractId': contract, 'resourceId': 'work-one', 'decision': 'allowed', 'delegationRef': None})
        return record

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.core_owner = self.core_publisher = None
        self.addAsyncCleanup(self.core_cleanup)
        value = copy.deepcopy(self.control_host._selection.policy)
        await self.receiver.close()
        await self.control_host.close(timeout=None)
        work = value['storage']['work']
        receiver = self.core_receiver('core-receiver')
        work['channels'][0]['legacyActors'].append({
            'identityRef': receiver['identityRef'], 'transportRef': receiver['transportRef'],
            'caller': 'federation', 'grants': receiver['grantRefs']})
        route = {'routeId': 'core-alice', 'scope': copy.deepcopy(self.scope),
            'resourceRef': ref('work-one'), 'repository': copy.deepcopy(work['repository']),
            'localNode': 'mac', 'accountPublicKey': self.account_public_key,
            'connection': {'endpoint': self.broker.url, 'serverName': self.server_name,
                'rootsPEM': self.ca_file.read_text(), 'leafCertificateSHA256': self.leaf_digest},
            'workSubjects': ['am.work.falcon.worker'], 'resultSubjects': ['am.result.mac'],
            'receiver': receiver, 'peer': self.core_peer('core-alice', 'mac_alice'),
            'publisher': self.core_publisher_pin('core-nick')}
        value['coreWorkTransport'] = {'routes': [route]}
        selection = ApplicationServiceSelection(canonical_bytes(value))
        self.control_host = SelectedStorageHost(selection, identity=self.identity)
        await self.control_host._work(work)
        self.resource, = (r for r in self.control_host._resources if type(r) is WorkStorageResource)
        self.core_owner = CoreWorkOwner(selection, self.identity, (self.resource,))
        self.control_host._core_work_owners.append(self.core_owner)
        await self.core_owner.start(_watch_roles=True)
        bridge = WorkBridgeService(self.identity.ingress, resources=(self.resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.receiver = CapabilityReplyService(self.identity.reader, resources=(self.resource,),
            hub_id='hub-one', profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED, request_signing_key_ref=ref('issuer'),
            connection=self.storage, work_bridge=bridge)
        await self.receiver.start()
        sender = copy.deepcopy(self.sender_selection.policy)
        sender_work = copy.deepcopy(sender['storage']['knowledge'])
        sender['storage']['work'] = sender_work
        sender_work['channels'][0].update(resourceRef=ref('work-one'), initialSource=None)
        sender_receiver = self.core_receiver('core-alice-receiver')
        sender_work['channels'][0]['legacyActors'] = [{
            'identityRef': sender_receiver['identityRef'], 'transportRef': sender_receiver['transportRef'],
            'caller': 'federation', 'grants': sender_receiver['grantRefs']}]
        sender['coreWorkTransport'] = {'routes': [{**copy.deepcopy(route),
            'localNode': 'mac_alice', 'resultSubjects': ['am.result.mac_alice'],
            'receiver': sender_receiver, 'peer': self.core_peer('core-nick', 'mac'),
            'publisher': self.core_publisher_pin('core-alice')}]}
        self.core_publisher = CoreWorkPublisher(ApplicationServiceSelection(canonical_bytes(sender)),
            self.identity, route_id='core-alice')
        await self.core_publisher.start()
        async def observe():
            while True:
                self.refresh_observation()
                await asyncio.sleep(.25)
        self._observation_task = asyncio.create_task(observe())
        self.session, self.session_owner = await self.actual_work_session()
        directory = self.native_hub_directory
        with patch.object(server, 'ROOT', str(directory/'application')), patch.object(server, 'HUBDIR', str(directory)), \
                patch.dict(server.DEFAULT_CONFIG, {'nats_url': 'nats://ordinary-messages:4222'}):
            self.actual_hub = server.Hub(work_sessions=(self.session,))
        self.assertIsNot(self.actual_hub.store, self.resource._store)
        self.assertIsNot(self.actual_hub.store.db, self.resource._connection)
        self.assertIsNot(self.actual_hub.dbx, self.resource._source_worker)
        async with asyncio.timeout(5):
            while self.core_owner._roles._completed_sync is None:
                await asyncio.sleep(.025)

    async def activate_native(self):
        replies = []
        bridge = self.receiver._work_bridge
        actual = bridge.handle
        async def observe(raw, **kwargs):
            reply = await actual(raw, **kwargs)
            replies.append((strict_loads(raw), strict_loads(reply)))
            return reply
        with patch.object(bridge, 'handle', side_effect=observe):
            await self.actual_hub._work_source_binding.activate()
        self.assertEqual(len(replies), 1)
        request, reply = replies[0]
        wanted = request['claims']['payload']['input']['sourceBinding']
        proof = reply['claims']['result']['sourceBinding']
        self.assertEqual(wanted['coreTransport'], {'mode': 'tm218-core-v1'})
        self.assertEqual(proof['nonce'], wanted['nonce'])
        self.assertEqual(proof['coreTransport']['mode'], 'tm218-core-v1')
        self.assertRegex(proof['coreTransport']['bindingDigest'], r'^sha256:[0-9a-f]{64}$')
        self.assertTrue(reply['signature'])
        self.assertEqual(proof['coreTransport'], strict_loads(
            self.actual_hub._work_source_binding._core_pins[id(self.session)]))
        self.assertEqual({k: proof[k] for k in self.actual_hub._work_source_binding.pin.identity},
            self.actual_hub._work_source_binding.pin.identity)
        return proof

    async def register_native(self):
        self.lifecycle = WorkLifecycleClient(self.actual_hub._work_storage_commands)
        expires = datetime.now(timezone.utc)+timedelta(seconds=4)
        with self.registration_stages(expires):
            registered = await self.lifecycle.register({'generation': None, 'repo': 'falcon', 'role': 'worker',
                'agent': 'native_core', 'cli': 'codex', 'roleSnapshot': {}, 'transport': 'tmux',
                'handle': '%41', 'panePid': 12371, 'legacy': None, 'tokenSha': '9'*64},
                operation_id='native-core-mode-register', expires=expires)
        ingress = self.core_owner._ingresses[id(self.resource)]
        async with asyncio.timeout(5):
            while 'am.work.falcon.worker' not in ingress._subscriptions:
                await asyncio.sleep(.025)
        return registered

    @contextmanager
    def registration_stages(self, expires):
        """Keep closed private stage facts without changing the original calls."""
        owner, bridge = self.core_owner, self.receiver._work_bridge
        ingress = owner._ingresses[id(self.resource)]
        records, admissions = [], {}
        allowed = {'core_work_transport_refused', 'legacy_work_service_unavailable',
            'legacy_work_request_refused', 'legacy_work_reply_unconfirmed',
            'core_work_role_sync_unconfirmed', 'capability_resource_stale',
            'capability_access_refused', 'selected_work_source_unavailable',
            'selected_storage_unavailable'}
        guard_sources = {'/capability_owner/core_work_roles.py': 'roles',
            '/capability_owner/core_work.py': 'core-owner',
            '/capability_owner/core_work_client.py': 'core-dispatch',
            '/hub/core_work_transport.py': 'core-transport',
            '/identity/core_work_transport.py': 'core-authority',
            '/capability_owner/work.py': 'work-resource',
            '/capability_owner/work_host.py': 'work-source',
            '/capability_owner/selected_storage.py': 'selected-source',
            '/hub/fed/session.py': 'session'}
        guard_functions = {'sync', '_sync', 'check', 'check_health', '_open', '_interests',
            '_current', 'set_work_subjects', 'check_authority', 'check_snapshot',
            '_transport_binding', 'transport_proof', '_db', 'local_credential',
            'selected_route', 'public_credential', 'check_open'}

        def record(stage, outcome, error=None, elapsed_ms=None):
            if len(records) >= 128:
                return
            row = {'stage': stage, 'outcome': outcome,
                'remainingMs': int((expires-datetime.now(timezone.utc)).total_seconds()*1000),
                'rolesAlive': owner._roles_task is not None and not owner._roles_task.done(),
                'outboxAlive': owner._outbox_task is not None and not owner._outbox_task.done(),
                'firstSyncComplete': owner._roles._completed_sync is not None,
                'roleError': owner._roles._last_error is not None,
                'roleErrorCode': ('none' if owner._roles._last_error is None else
                    owner._roles._last_error if owner._roles._last_error in allowed else 'other_error')}
            for label, subject in (('work', 'am.work.falcon.worker'), ('result', 'am.result.mac')):
                subscription = ingress._subscriptions.get(subject)
                task = ingress._dispatch_tasks.get(subject)
                custody = ingress._session._resources.get(id(subscription))
                row[label+'Subscribed'] = subscription is not None
                row[label+'CallbackAlive'] = isinstance(task, asyncio.Task) and not task.done()
                row[label+'OriginalCallback'] = (subscription is not None
                    and subscription._wait_for_msgs_task is task)
                row[label+'Owned'] = (subscription is not None and custody is not None
                    and custody[1] is subscription
                    and ingress._connection._subs.get(subscription._id) is subscription)
            if error is not None:
                code = getattr(error, 'code', None)
                row['errorCode'] = code if isinstance(error, ContractError) and code in allowed else 'other_error'
                trace = error.__traceback__
                while trace is not None:
                    frame = trace.tb_frame.f_code
                    if frame.co_name in guard_functions:
                        for suffix, label in guard_sources.items():
                            if frame.co_filename.endswith(suffix):
                                row.update(guardSource=label, guardFunction=frame.co_name,
                                    guardLine=trace.tb_lineno)
                    trace = trace.tb_next
            if elapsed_ms is not None:
                row['elapsedMs'] = elapsed_ms
            records.append(row)

        def timed(stage, original):
            async def invoke(*args, **kwargs):
                started = time.monotonic_ns()
                record(stage, 'entered')
                try:
                    result = await original(*args, **kwargs)
                except BaseException as error:
                    record(stage, 'raised', error, (time.monotonic_ns()-started)//1_000_000)
                    raise
                record(stage, 'returned', elapsed_ms=(time.monotonic_ns()-started)//1_000_000)
                return result
            return invoke

        original_admit, original_sign, original_proof = bridge._admit, bridge._sign, owner.transport_proof
        async def admit(raw, reply_subject):
            claims = strict_loads(raw)['claims']
            contract = claims['contractId']
            kind = {'federation-work-inspect': 'inspect', 'federation-work-register': 'register',
                'federation-work-outcome': 'outcome'}.get(contract, 'other')
            key = (contract, claims['operationId'])
            admissions[key] = admissions.get(key, 0)+1
            phase = 'first' if admissions[key] == 1 else 'final' if admissions[key] == 2 else 'repeated'
            stage = kind+'-'+phase+'-admission'
            record(stage, 'entered')
            try:
                result = await original_admit(raw, reply_subject)
            except BaseException as error:
                record(stage, 'raised', error)
                raise
            record(stage, 'returned')
            return result

        def sign(*args, **kwargs):
            record('sign', 'entered')
            try:
                result = original_sign(*args, **kwargs)
            except BaseException as error:
                record('sign', 'raised', error)
                raise
            record('sign', 'returned')
            return result

        def proof(*args, **kwargs):
            record('current-proof', 'entered')
            try:
                result = original_proof(*args, **kwargs)
            except BaseException as error:
                record('current-proof', 'raised', error)
                raise
            record('current-proof', 'returned')
            return result

        try:
            with patch.object(bridge, '_admit', side_effect=admit), \
                    patch.object(bridge, '_sign', side_effect=sign), \
                    patch.object(owner, 'transport_proof', side_effect=proof), \
                    patch.object(bridge._ingress, '_request_authority',
                        side_effect=timed('request-authority', bridge._ingress._request_authority)), \
                    patch.object(bridge._ingress, 'admit',
                        side_effect=timed('ingress-admit', bridge._ingress.admit)), \
                    patch.object(self.resource, 'authorize_legacy',
                        side_effect=timed('resource-authorize', self.resource.authorize_legacy)), \
                    patch.object(owner._roles, '_sync',
                        side_effect=timed('role-sync', owner._roles._sync)):
                yield
        finally:
            # The existing private fixture keeps this bounded diagnostic separate
            # from all credentials, request bodies and arbitrary exception text.
            try:
                descriptor, _ = tempfile.mkstemp(prefix='amux676-native-registration-stages-', suffix='.json')
                output = os.fdopen(descriptor, 'w+b')
                try:
                    output.write(canonical_bytes(records))
                    output.flush()
                except OSError:
                    output.close()
                    raise
                originals = frozenset(bridge._active | bridge._workers)
                finalized = False
                def after_originals(_done=None):
                    nonlocal finalized
                    if finalized or any(not original.done() for original in originals):
                        return
                    finalized = True
                    try:
                        output.seek(0)
                        output.truncate()
                        output.write(canonical_bytes(records))
                        output.flush()
                    except OSError:
                        pass
                    finally:
                        output.close()
                for original in originals:
                    if not original.done():
                        original.add_done_callback(after_originals)
                after_originals()
            except OSError:
                pass

    @contextmanager
    def outbox_stages(self):
        """Attach only closed publication facts if the existing wait fails."""
        owner = self.core_owner
        publisher = owner._publishers['core-alice']
        publish, mark = publisher.publish, owner._outbox._mark
        stages = []
        allowed = {'core_work_transport_refused', 'core_work_publication_unconfirmed',
            'capability_resource_stale', 'capability_access_refused',
            'selected_work_source_unavailable', 'selected_storage_unavailable'}
        sources = {'/capability_owner/core_work_client.py': 'core-outbox',
            '/capability_owner/core_work.py': 'core-owner',
            '/hub/core_work_transport.py': 'core-publisher',
            '/identity/core_work_transport.py': 'core-authority',
            '/capability_owner/work.py': 'work-resource',
            '/capability_owner/work_host.py': 'work-source',
            '/capability_owner/selected_storage.py': 'selected-source',
            '/hub/fed/session.py': 'session'}
        functions = {'publish', 'check', 'check_health', '_mark', '_db', '_current',
            '_open', 'check_authority', 'check_snapshot', 'body_route', 'signed_claims',
            'local_credential', 'public_credential', 'selected_route', 'check_open'}

        def record(stage, outcome, error=None):
            if len(stages) >= 32:
                return
            item = {'stage': stage, 'outcome': outcome}
            if error is not None:
                code = getattr(error, 'code', None)
                item['errorCode'] = (code if isinstance(error, ContractError) and code in allowed else
                    'timeout' if isinstance(error, TimeoutError) else
                    'cancelled' if isinstance(error, asyncio.CancelledError) else 'other_error')
                trace = error.__traceback__
                while trace is not None:
                    frame = trace.tb_frame.f_code
                    if frame.co_name in functions:
                        for suffix, label in sources.items():
                            if frame.co_filename.endswith(suffix):
                                item.update(guardSource=label, guardFunction=frame.co_name,
                                    guardLine=trace.tb_lineno)
                    trace = trace.tb_next
            stages.append(item)

        async def publication(subject, body, *, expires=None):
            record('publish', 'entered')
            try:
                result = await publish(subject, body, expires=expires)
            except BaseException as error:
                record('publish', 'raised', error)
                raise
            record('publish', 'returned')
            return result

        def marking(resource, key, expected, state, deadline):
            stage = 'mark-'+state if state in ('pending', 'uncertain', 'confirmed') else 'mark-other'
            record(stage, 'entered')
            try:
                result = mark(resource, key, expected, state, deadline)
            except BaseException as error:
                record(stage, 'raised', error)
                raise
            record(stage, 'returned')
            return result

        try:
            with patch.object(publisher, 'publish', side_effect=publication), \
                    patch.object(owner._outbox, '_mark', side_effect=marking):
                yield
        except BaseException as error:
            held = owner._transport_sessions['core-alice']
            code = owner._outbox._last_error
            note = {'stages': stages, 'outboxErrorCode': code if code in allowed else
                'none' if code is None else 'other_error',
                'outboxAlive': owner._outbox_task is not None and not owner._outbox_task.done(),
                'rolesAlive': owner._roles_task is not None and not owner._roles_task.done(),
                'publisherConnected': publisher._connection.is_connected,
                'publisherClosed': publisher._closed, 'publisherPaused': publisher._policy_paused,
                'originalPublisher': held[3] is publisher,
                'originalPublisherSession': held[4] is publisher._session,
                'originalPublisherConnection': held[5] is publisher._connection}
            error.add_note('Closed core outbox diagnostic: '+canonical_bytes(note).decode())
            raise

    async def test_actual_configured_native_core_mode_signs_source_proof(self):
        await self.activate_native()
        await self.actual_hub._work_source_binding.verify()
        self.assertFalse(self.core_owner._roles_task.done())
        self.assertFalse(self.core_owner._outbox_task.done())
        self.assertNotEqual(self.actual_hub.bridge.url,
            self.core_owner._selection.policy['coreWorkTransport']['routes'][0]['connection']['endpoint'])
        self.success = True

    async def test_native_core_work_result_and_original_message_compatibility(self):
        await self.activate_native()
        registered = await self.register_native()
        hub = self.actual_hub
        original = {'type': 'work', 'origin': 'mac_alice:native-composition', 'origin_node': 'mac_alice',
            'origin_id': 'native-composition', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Original native composition work', 'created_by': 'agent:original',
                'requirements': '{"capabilities":["python"]}'}}
        await self.core_publisher.publish('am.work.falcon.worker', canonical_bytes(original))
        incoming, = await self.wait_rows('SELECT * FROM work_items WHERE origin=?', (original['origin'],))
        self.assertEqual(incoming['created_by'], original['work']['created_by'])
        self.assertEqual(incoming['title'], original['work']['title'])
        self.assertEqual(incoming, await hub.db(hub.store.q1,
            'SELECT * FROM work_items WHERE id=?', (incoming['id'],)))
        await self.core_publisher.publish('am.work.falcon.worker', canonical_bytes(original))
        await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-proof:%' AND k NOT LIKE '%event:%'", count=2)
        self.assertEqual(await hub.db(hub.store.q, 'SELECT * FROM work_items WHERE origin=?', (original['origin'],)), [incoming])
        with self.outbox_stages():
            outgoing = await self.resource._owner.db(self.resource._store.work_create, 'operator', 'falcon',
                'role:falcon/worker', 'Original native result obligation', federate=True, node='mac')
            async with asyncio.timeout(5):
                while not (await self.resource._owner.db(self.resource._store.q1,
                        'SELECT sent FROM nats_outbox WHERE subject=?', ('am.work.falcon.worker',)))['sent']:
                    await asyncio.sleep(.025)
        result = {'type': 'result', 'origin_id': outgoing['id'], 'state': 'done',
            'result': 'Exact native composition result', 'node': 'mac_alice', 'by': 'falcon-worker-original'}
        await self.core_publisher.publish('am.result.mac', canonical_bytes(result))
        completed, = await self.wait_rows("SELECT * FROM work_items WHERE id=? AND state='done'", (outgoing['id'],))
        self.assertEqual(completed['result'], result['result'])
        self.assertEqual(completed['claimed_by'], 'nats:mac_alice:falcon-worker-original')
        records = await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'", count=2)
        self.assertTrue(all(len(strict_loads(row['v'])['attempts']) == 1 for row in records))

        connection = Connection()
        connection.finish_reader.set()
        connection.finish_socket.set()
        with patch('hub.bridge.NatsClient', return_value=connection):
            running = asyncio.create_task(hub.bridge.run())
            try:
                await asyncio.wait_for(connection.reading.wait(), 1)
                self.assertTrue(hub.bridge.connected)
                self.assertEqual([row[0] for row in connection.subscriptions.values()], ['am.agent.>'])
                self.assertEqual(hub.bridge.role_subs, {})
                envelope = {'id': 'native-ordinary-original', 'origin': 'mac_alice',
                    'sender': 'virtual:remote', 'target': 'agent:'+registered,
                    'kind': 'note', 'body': 'Original ordinary message', 'ref': 'original-reference'}
                handler = next(iter(connection.subscriptions.values()))[1]
                await handler('am.agent.falcon.worker.native_core', canonical_bytes(envelope))
                before, = await hub.db(hub.store.q, 'SELECT * FROM messages WHERE idem_key=?',
                    ('nats:native-ordinary-original',))
                await handler('am.agent.falcon.worker.native_core', canonical_bytes(envelope))
                self.assertEqual(await hub.db(hub.store.q, 'SELECT * FROM messages WHERE idem_key=?',
                    ('nats:native-ordinary-original',)), [before])
                self.assertEqual((before['sender'], before['body'], before['ref']),
                    (envelope['sender'], envelope['body'], envelope['ref']))
                self.assertEqual(strict_loads(before['meta']), {'origin': envelope['origin']})
                self.assertEqual(await hub.db(hub.store.q1,
                    'SELECT count(*) n FROM deliveries WHERE message_id=? AND recipient=?',
                    (before['id'], registered)), {'n': 1})
                rows = await hub.db(hub.store.q, 'SELECT * FROM work_items')
                forged = {**original, 'origin': 'mac_alice:raw-refused', 'origin_id': 'raw-refused'}
                await hub.bridge.on_work('am.work.falcon.worker', canonical_bytes(forged))
                await hub.bridge.on_result('am.result.mac', canonical_bytes({**result, 'result': 'Raw refused'}))
                self.assertEqual(await hub.db(hub.store.q, 'SELECT * FROM work_items'), rows)
            finally:
                hub.stop.set()
                running.cancel()
                await asyncio.gather(running, return_exceptions=True)
        self.assertTrue(connection.closed)
        self.assertFalse(hub.bridge.connected)
        self.success = True

    async def test_native_policy_pause_refuses_proof_and_retains_pending_work(self):
        await self.activate_native()
        owner = self.core_owner
        owner.begin_policy_pause()
        await owner.join_policy_pause()
        pending = await self.resource._owner.db(self.resource._store.work_create, 'operator', 'falcon',
            'role:falcon/worker', 'Keep this original obligation', federate=True, node='mac')
        before = await self.actual_hub.db(self.actual_hub.store.q, 'SELECT * FROM nats_outbox')
        with self.assertRaises(ContractError):
            await self.actual_hub._work_source_binding.verify()
        self.actual_hub.bridge.nc = Connection()
        await self.actual_hub.bridge.drain_outbox()
        self.assertEqual(await self.actual_hub.db(self.actual_hub.store.q, 'SELECT * FROM nats_outbox'), before)
        self.assertTrue(all(row['sent'] is None for row in before))
        self.assertEqual(await self.actual_hub.db(self.actual_hub.store.q1,
            'SELECT * FROM work_items WHERE id=?', (pending['id'],)), pending)
        owner.end_policy_pause()
        await self.actual_hub._work_source_binding.verify()
        self.success = True
