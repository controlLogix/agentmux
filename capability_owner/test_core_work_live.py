"""Actual enrolled TLS/JWT core work publisher, owned receiver and Work owner."""
import asyncio
import base64
import copy
from datetime import datetime, timezone
import hashlib
import secrets
from unittest.mock import patch

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection
from identity.core_work_transport import HEADER, INGEST, RESULT
from identity.test_authority import ref
from identity.test_peer_control_live import LivePeerControlTests
from native_security.nats_credentials import _JWT, _base32
from state_owner.ledger import OwnerBinding
from hub.core_work_transport import CoreWorkPublisher
from hub.fed.session import FederationSession
from .core_work import CoreWorkOwner
from .messages import MessageActor
from .work import WorkStorageResource
from .work_host import SelectedWorkDomain
from .work_legacy import LegacyWorkActor


class LiveCoreWorkTests(LivePeerControlTests):
    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
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
        paths = list((self.directory / 'nsc-keys').rglob(self.account_public_key + '.nk'))
        if len(paths) != 1:
            raise RuntimeError('core_work_fixture_account_key_unavailable')
        account = nkeys.from_seed(paths[0].read_bytes().strip())
        try:
            for role, (publish, subscribe) in self.core_policies.items():
                path = self.credentials[role]
                raw = path.read_bytes()
                token = _JWT.findall(raw)[0]
                header, body, _ = token.split(b'.')
                claims = strict_loads(base64.urlsafe_b64decode(body + b'=' * (-len(body) % 4)))
                claims['nats']['pub'] = {'allow': publish} if publish else {'allow': [], 'deny': ['>']}
                claims['nats']['sub'] = {'allow': subscribe} if subscribe else {'allow': [], 'deny': ['>']}
                claims.pop('jti', None)
                encoded = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                updated = header + b'.' + encoded
                updated += b'.' + base64.urlsafe_b64encode(account.sign(updated)).rstrip(b'=')
                path.write_bytes(raw.replace(token, updated, 1))
        finally:
            account.wipe()

    def initial_authority(self):
        record = super().initial_authority()
        state = record['state']
        template = copy.deepcopy(state['transports'][0])
        grant = copy.deepcopy(state['grants'][0])
        for name, role in (('core-receiver', 'core-receiver'), ('core-alice', 'core-alice'),
                           ('core-nick', 'core-nick'), ('core-alice-receiver', 'core-alice-receiver')):
            pin, _ = self._credential(role)
            public = _base32(pin['userPublicKey'].encode(), 35)[1:-2]
            state['identities'].append({'ref': ref(name), 'kind': 'service', 'status': 'active',
                                       'principalId': name, 'externalIdentity': None})
            state['transports'].append({**template, 'ref': ref(name + '-transport'), 'identityRef': ref(name),
                'issuerRef': ref('issuer'), 'publicKey': base64.urlsafe_b64encode(public).decode().rstrip('=')})
            state['memberships'].append({'ref': ref(name + '-member'), 'identityRef': ref(name),
                                        'scope': copy.deepcopy(self.scope), 'status': 'active'})
            contracts = [INGEST, RESULT]
            if 'receiver' in name:
                contracts.extend(('federation-work-inspect', 'federation-work-outcome'))
            for contract in contracts:
                state['grants'].append({**copy.deepcopy(grant), 'ref': ref(name + '-' + contract.removeprefix('federation-work-')),
                    'callerRef': ref(name), 'actorRef': ref(name), 'scope': copy.deepcopy(self.scope),
                    'contractId': contract, 'resourceId': 'work-one', 'decision': 'allowed', 'delegationRef': None})
        return record

    def core_receiver(self, role):
        pin, _ = self._credential(role)
        return {'identityRef': ref(role), 'transportRef': ref(role + '-transport'), 'credentials': pin,
            'grantRefs': {contract: ref(role + '-' + contract.removeprefix('federation-work-'))
                         for contract in (INGEST, RESULT, 'federation-work-inspect', 'federation-work-outcome')}}

    def core_peer(self, role, node):
        pin, token = self._credential(role)
        return {'nodeId': node, 'identityRef': ref(role), 'transportRef': ref(role + '-transport'),
            'userPublicKey': pin['userPublicKey'], 'credentialJWT': token,
            'publishSubjects': self.core_policies[role][0],
            'grantRefs': {contract: ref(role + '-' + contract.removeprefix('federation-work-'))
                         for contract in (INGEST, RESULT)}}

    def core_publisher_pin(self, role):
        pin, _ = self._credential(role)
        return {'identityRef': ref(role), 'transportRef': ref(role + '-transport'), 'credentials': pin,
            'publishSubjects': self.core_policies[role][0],
            'grantRefs': {contract: ref(role + '-' + contract.removeprefix('federation-work-'))
                         for contract in (INGEST, RESULT)}}

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.core_owner = self.core_publisher = None
        self.addAsyncCleanup(self.core_cleanup)
        value = copy.deepcopy(self.value)
        work = copy.deepcopy(value['storage']['knowledge'])
        channel = work['channels'][0]
        channel.update(resourceRef=ref('work-one'), initialSource=None,
            legacyActors=[{**{k: self.core_receiver('core-receiver')[k] for k in ('identityRef', 'transportRef')},
                'caller': 'federation', 'grants': self.core_receiver('core-receiver')['grantRefs']}])
        value['storage']['work'] = work
        connection = {'endpoint': self.broker.url, 'serverName': self.server_name,
                      'rootsPEM': self.ca_file.read_text(), 'leafCertificateSHA256': self.leaf_digest}
        route = {'routeId': 'core-alice', 'scope': copy.deepcopy(self.scope), 'resourceRef': ref('work-one'),
            'repository': copy.deepcopy(work['repository']), 'localNode': 'mac',
            'accountPublicKey': self.account_public_key, 'connection': connection,
            'workSubjects': ['am.work.falcon.worker'], 'resultSubjects': ['am.result.mac'],
            'receiver': self.core_receiver('core-receiver'), 'peer': self.core_peer('core-alice', 'mac_alice')}
        value['coreWorkTransport'] = {'routes': [route]}
        selection = ApplicationServiceSelection(canonical_bytes(value))
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        domain = SelectedWorkDomain(self.control_source, session, identity=self.identity,
            scope=self.scope, local_node='mac', selection=selection, channel_ref=ref('work-one'))
        self.addAsyncCleanup(domain.close)
        actor = channel['legacyActors'][0]
        self.resource = WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'work-one',
            'work-channel', canonical_bytes(self.scope)), domain, repository=work['repository']['localName'],
            actors=tuple(MessageActor(canonical_bytes(a['identityRef']), canonical_bytes(a['transportRef']), a['caller'])
                         for a in channel['actors']), plugin_identity_ref=channel['pluginIdentityRef'],
            instance_id=channel['instanceId'], initial_source=None,
            legacy_actors=(LegacyWorkActor(canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']),
                                          'federation', canonical_bytes(actor['grants'])),))
        self.core_owner = CoreWorkOwner(selection, self.identity, (self.resource,))
        await self.core_owner.start()
        await self.core_owner.set_work_subjects({'am.work.falcon.worker'})
        # Publisher metadata belongs to a separate protected sender selection;
        # the receiver never receives its private credentials or raw objects.
        sender = copy.deepcopy(self.sender_selection.policy)
        sender_work = copy.deepcopy(sender['storage']['knowledge'])
        sender_channel = sender_work['channels'][0]
        receiver = self.core_receiver('core-alice-receiver')
        sender_channel.update(resourceRef=ref('work-one'), initialSource=None,
            legacyActors=[{'identityRef': receiver['identityRef'], 'transportRef': receiver['transportRef'],
                           'caller': 'federation', 'grants': receiver['grantRefs']}])
        sender['storage']['work'] = sender_work
        sender['coreWorkTransport'] = {'routes': [{**route, 'localNode': 'mac_alice',
            'resultSubjects': ['am.result.mac_alice'], 'receiver': receiver,
            'peer': self.core_peer('core-nick', 'mac'), 'publisher': self.core_publisher_pin('core-alice')}]}
        sender_selection = ApplicationServiceSelection(canonical_bytes(sender))
        self.core_publisher = CoreWorkPublisher(sender_selection, self.identity, route_id='core-alice')
        await self.core_publisher.start()

    async def core_cleanup(self):
        if self.core_publisher is not None:
            await self.core_publisher.close(timeout=None)
        if self.core_owner is not None:
            await self.core_owner.close(timeout=None)

    async def wait_rows(self, query, args=(), *, count=1):
        async with asyncio.timeout(5):
            while True:
                rows = await self.resource._owner.db(self.resource._store.q, query, args)
                if len(rows) == count:
                    return rows
                await asyncio.sleep(.025)

    async def test_actual_enrolled_core_work_result_replay_and_forgery_refusals(self):
        item = {'type': 'work', 'origin': 'mac_alice:remote-one', 'origin_node': 'mac_alice',
            'origin_id': 'remote-one', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Original core work', 'created_by': 'agent:original',
                'requirements': '{"capabilities":["python"]}'}}
        body = canonical_bytes(item)
        await self.core_publisher.publish('am.work.falcon.worker', body)
        rows = await self.wait_rows('SELECT * FROM work_items WHERE origin=?', ('mac_alice:remote-one',))
        first = rows[0]
        self.assertEqual(first['created_by'], 'agent:original')
        await self.core_publisher.publish('am.work.falcon.worker', body)
        await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-proof:%' AND k NOT LIKE '%event:%'", count=2)
        records = await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
        self.assertEqual(len(strict_loads(records[0]['v'])['attempts']), 1)
        outgoing = await self.resource._owner.db(self.resource._store.work_create,
            'operator', 'falcon', 'role:falcon/worker', 'Original placeholder', federate=True, node='mac')
        result = {'type': 'result', 'origin_id': outgoing['id'], 'state': 'done',
                  'result': 'Exact original result', 'node': 'mac_alice', 'by': 'falcon-worker-one'}
        await self.core_publisher.publish('am.result.mac', canonical_bytes(result))
        completed = (await self.wait_rows("SELECT * FROM work_items WHERE id=? AND state='done'", (outgoing['id'],)))[0]
        self.assertEqual(completed['result'], 'Exact original result')
        self.assertEqual(completed['claimed_by'], 'nats:mac_alice:falcon-worker-one')
        await self.core_publisher.publish('am.result.mac', canonical_bytes(result))
        await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-proof:%' AND k NOT LIKE '%event:%'", count=4)
        ingress = self.core_owner._ingresses[id(self.resource)]
        finished = asyncio.Event()
        subscription = ingress._subscriptions['am.work.falcon.worker']
        original_callback = subscription._cb
        async def observed(message):
            try:
                await original_callback(message)
            finally:
                finished.set()
        subscription._cb = observed
        forged = copy.deepcopy(item)
        forged.update(origin='mac_alice:forged-one', origin_id='forged-one')
        for headers in (None, {HEADER: base64.b64encode(bytes(64)).decode()}):
            finished.clear()
            await self.admin.publish('am.work.falcon.worker', canonical_bytes(forged), headers=headers)
            await self.admin.flush(timeout=1)
            await asyncio.wait_for(finished.wait(), 2)
        self.assertEqual(await self.resource._owner.db(self.resource._store.q,
            'SELECT * FROM work_items WHERE origin=?', ('mac_alice:forged-one',)), [])
        # Actual account permissions refuse publishing another literal route and
        # wildcard spoofing, independently of application signature validation.
        publisher_connection = await self.connect('core-alice')
        for subject in ('am.work.other.worker', 'am.work.*.worker', 'am.result.other'):
            before = len(self.errors['core-alice'])
            self.permission_events['core-alice'].clear()
            await publisher_connection.publish(subject, body)
            await publisher_connection.flush(timeout=1)
            await self.wait_permissions('core-alice', before + 1)
        self.success = True

    async def test_actual_lost_effect_reply_restarted_owner_queries_original_only(self):
        item = {'type': 'work', 'origin': 'mac_alice:lost-reply', 'origin_node': 'mac_alice',
            'origin_id': 'lost-reply', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Recover the original receipt', 'created_by': 'agent:original'}}
        body = canonical_bytes(item)
        old_owner, old_resource = self.core_owner, self.resource
        old_ingress = old_owner._ingresses[id(old_resource)]
        submitted, lost = [], asyncio.Event()
        actual = old_resource.legacy
        async def lose_reply(authority, raw):
            original = strict_loads(raw)
            result = await actual(authority, raw)
            if original['contractId'] == INGEST:
                submitted.append(original)
                lost.set()
                raise ContractError('controlled_core_reply_loss_after_commit')
            return result
        with patch.object(old_resource, 'legacy', side_effect=lose_reply):
            await self.core_publisher.publish('am.work.falcon.worker', body)
            await asyncio.wait_for(lost.wait(), 3)
            await old_owner.close(timeout=None)
        before = await old_resource._owner.db(old_resource._store.q,
            "SELECT k,v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
        self.assertEqual(len(before), 1)
        pending = strict_loads(before[0]['v'])
        self.assertEqual(pending['attempts'], [{'original': submitted[0]}])
        receipt = await old_resource._owner.db(old_resource._journal.outcome,
            submitted[0]['operation']['operationId'], submitted[0]['operation']['payloadDigest'])
        self.assertEqual(receipt['reply']['outcome'], 'applied')
        selection = old_owner._selection
        # Reconstruct the selected owner and concrete resource over the same
        # admitted source and journal. The old object cannot authorize recovery.
        resource = WorkStorageResource(old_resource.binding, old_resource._owner,
            repository=old_resource.repository, actors=old_resource.actors,
            plugin_identity_ref=strict_loads(old_resource.plugin_identity),
            instance_id=old_resource.instance_id, initial_source=None,
            legacy_actors=old_resource._legacy_actors)
        self.assertEqual(resource._journal.binding, old_resource._journal.binding)
        self.resource = resource
        self.core_owner = CoreWorkOwner(selection, self.identity, (resource,))
        await self.core_owner.start()
        await self.core_owner.set_work_subjects({'am.work.falcon.worker'})
        ingress = self.core_owner._ingresses[id(resource)]
        self.assertIsNot(ingress._session, old_ingress._session)
        calls, recovered = [], asyncio.Event()
        original = resource.legacy
        async def observe(authority, raw):
            calls.append(strict_loads(raw))
            result = await original(authority, raw)
            if calls[-1]['contractId'] == 'federation-work-outcome':
                recovered.set()
            return result
        with patch.object(resource, 'legacy', side_effect=observe):
            await self.core_publisher.publish('am.work.falcon.worker', body)
            await asyncio.wait_for(recovered.wait(), 3)
            await asyncio.wait_for(self.core_owner._dispatcher.join(), 2)
        self.assertNotIn(INGEST, [call['contractId'] for call in calls])
        after = (await self.wait_rows('SELECT v FROM fed_state WHERE k=?', (before[0]['k'],)))[0]
        completed = strict_loads(after['v'])
        self.assertEqual(len(completed['attempts']), 1)
        self.assertEqual(completed['attempts'][0]['original'], pending['attempts'][0]['original'])
        self.assertEqual(completed['attempts'][0]['reply']['outcome'], 'applied')
        rows = await self.wait_rows('SELECT * FROM work_items WHERE origin=?', (item['origin'],))
        self.assertEqual(rows[0]['created_by'], 'agent:original')
        proofs = await self.wait_rows("SELECT v FROM fed_state WHERE k LIKE 'core-work-proof:%' "
            "AND k NOT LIKE '%event:%'", count=2)
        self.assertEqual(len({strict_loads(row['v'])['sessionNonce'] for row in proofs}), 2)
        self.success = True

    async def test_actual_publisher_policy_join_observes_operation_without_parent(self):
        item = {'type': 'work', 'origin': 'mac_alice:publisher-join', 'origin_node': 'mac_alice',
            'origin_id': 'publisher-join', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Join one publication', 'created_by': 'agent:original'}}
        publisher = self.core_publisher
        entered, release, published, finish = (asyncio.Event() for _ in range(4))
        flush = publisher._connection.flush
        async def blocked_flush(*args, **kwargs):
            await flush(*args, **kwargs)
            entered.set()
            await release.wait()
        async def parent():
            try:
                await publisher.publish('am.work.falcon.worker', canonical_bytes(item))
            except ContractError:
                pass
            finally:
                published.set()
            await finish.wait()
        caller = observer = None
        with patch.object(publisher._connection, 'flush', side_effect=blocked_flush):
            try:
                caller = asyncio.create_task(parent())
                await asyncio.wait_for(entered.wait(), 2)
                publisher.begin_policy_pause()
                marker = next(iter(publisher._active))
                observer = asyncio.create_task(publisher.join_policy_pause())
                await asyncio.sleep(0)
                observer.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await observer
                self.assertFalse(marker.done())
                observer = asyncio.create_task(publisher.join_policy_pause())
                await asyncio.sleep(0)
                self.assertFalse(observer.done())
                release.set()
                await asyncio.wait_for(published.wait(), 2)
                await asyncio.wait_for(observer, 2)
                self.assertTrue(marker.done())
                self.assertFalse(marker.cancelled())
                self.assertFalse(caller.done())
                publisher.end_policy_pause()
            finally:
                release.set()
                finish.set()
                if caller is not None:
                    await asyncio.gather(caller, return_exceptions=True)
                if observer is not None:
                    await asyncio.gather(observer, return_exceptions=True)
        self.success = True
