"""Controlled owner checks; the separate live test proves broker admission."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import AuthoritySnapshot
from identity.core_work_transport import INGEST, RESULT, signed_claims
from identity.test_authority import ref
from native_security.nats_credentials import _base32
from state_owner.ledger import OwnerBinding
from hub.core_work_transport import CoreWorkEvent, _Event
from .core_work import CoreWorkOwner
from .messages import MessageActor
from .test_selected_work import SelectedWorkCompositionTests
from .work import WorkStorageResource
from .work_host import SelectedWorkDomain
from .work_legacy import LegacyWorkActor


def credential(seed_number, *, publish=(), subscribe=()):
    import time
    account = nkeys.from_seed(nkeys.encode_seed(bytes([1])*32, nkeys.PREFIX_BYTE_ACCOUNT))
    user = nkeys.from_seed(nkeys.encode_seed(bytes([seed_number])*32, nkeys.PREFIX_BYTE_USER))
    try:
        claims = {'iss': account.public_key.decode(), 'sub': user.public_key.decode(),
            'iat': int(time.time()) - 1, 'exp': int(time.time()) + 3600, 'nats': {'type': 'user', 'version': 2,
            'pub': {'allow': list(publish)} if publish else {'allow': [], 'deny': ['>']},
            'sub': {'allow': list(subscribe)} if subscribe else {'allow': [], 'deny': ['>']}}}
        encode = lambda value: base64.urlsafe_b64encode(canonical_bytes(value)).rstrip(b'=')
        signed = encode({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encode(claims)
        token = signed + b'.' + base64.urlsafe_b64encode(account.sign(signed)).rstrip(b'=')
        raw = (b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n'
            b'-----BEGIN USER NKEY SEED-----\n' + user.seed + b'\n------END USER NKEY SEED------\n')
        return raw, account.public_key.decode(), user.public_key.decode(), token.decode()
    finally:
        account.wipe()
        user.wipe()


class Connection:
    is_connected = True
    def __init__(self):
        self._subs = {}
    async def close(self):
        self.is_connected = False


class CoreWorkOwnerTests(SelectedWorkCompositionTests):
    async def core(self):
        await self.start_host()
        scope = self.scope
        work = copy.deepcopy(self.value['storage']['work'])
        receiver_raw, account, receiver_user, _ = credential(31,
            subscribe=('am.work.falcon.worker', 'am.result.mac'))
        peer_raw, _, peer_user, peer_jwt = credential(32,
            publish=('am.work.falcon.worker', 'am.result.mac'))
        credential_path = self.root / 'core-receiver.creds'
        credential_path.write_bytes(receiver_raw)
        credential_path.chmod(0o600)
        receiver_grants = {k: ref('core-receiver-' + k.removeprefix('federation-work-'))
            for k in (INGEST, RESULT, 'federation-work-inspect', 'federation-work-outcome')}
        peer_grants = {k: ref('core-peer-' + k.removeprefix('federation-work-')) for k in (INGEST, RESULT)}
        actor = {'identityRef': ref('core-receiver'), 'transportRef': ref('core-receiver-transport'),
                 'caller': 'federation', 'grants': receiver_grants}
        work['channels'][0]['legacyActors'] = [actor]
        route = {'routeId': 'core-remote', 'scope': copy.deepcopy(scope), 'resourceRef': ref('work-one'),
            'repository': {'localName': 'falcon'}, 'localNode': 'mac', 'accountPublicKey': account,
            'connection': copy.deepcopy(self.value['storage']['receivers']['storage']['connection']),
            'workSubjects': ['am.work.falcon.worker'], 'resultSubjects': ['am.result.mac'],
            'receiver': {'identityRef': ref('core-receiver'), 'transportRef': ref('core-receiver-transport'),
                'grantRefs': receiver_grants, 'credentials': {'path': str(credential_path),
                    'sha256': 'sha256:' + hashlib.sha256(receiver_raw).hexdigest(), 'userPublicKey': receiver_user}},
            'peer': {'nodeId': 'remote', 'identityRef': ref('core-peer'), 'transportRef': ref('core-peer-transport'),
                'grantRefs': peer_grants, 'userPublicKey': peer_user, 'credentialJWT': peer_jwt,
                'publishSubjects': ['am.work.falcon.worker', 'am.result.mac']}}
        route['connection'].pop('jetstreamDomain', None)
        current = strict_loads(self.snapshot.record)
        state = current['state']
        template = copy.deepcopy(state['transports'][0])
        grant_template = copy.deepcopy(state['grants'][0])
        for name, user, grants in (('core-receiver', receiver_user, receiver_grants), ('core-peer', peer_user, peer_grants)):
            state['identities'].append({'ref': ref(name), 'kind': 'service', 'status': 'active',
                                       'principalId': name, 'externalIdentity': None})
            state['memberships'].append({'ref': ref(name + '-member'), 'identityRef': ref(name),
                                         'scope': copy.deepcopy(scope), 'status': 'active'})
            state['transports'].append({**template, 'ref': ref(name + '-transport'), 'identityRef': ref(name),
                'issuerRef': self.value['identity']['issuer']['issuerRef'],
                'publicKey': base64.urlsafe_b64encode(_base32(user.encode(), 35)[1:-2]).decode().rstrip('=')})
            for contract, grant in grants.items():
                state['grants'].append({**copy.deepcopy(grant_template), 'ref': grant, 'callerRef': ref(name),
                    'actorRef': ref(name), 'scope': copy.deepcopy(scope), 'resourceId': 'work-one',
                    'contractId': contract, 'decision': 'allowed', 'delegationRef': None,
                    'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        self.core_snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence)
        selected = copy.deepcopy(self.value)
        selected['storage']['work'] = work
        selected['coreWorkTransport'] = {'routes': [route]}
        selection = ApplicationServiceSelection(canonical_bytes(selected))
        source = self.host._message_stores[0]
        domain = SelectedWorkDomain(source, identity=self.identity, scope=scope, local_node='mac',
                                    selection=selection, channel_ref=ref('work-one'))
        self.addAsyncCleanup(domain.close)
        channel = work['channels'][0]
        resource = WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'work-one',
            'work-channel', canonical_bytes(scope)), domain, repository='falcon',
            actors=tuple(MessageActor(canonical_bytes(a['identityRef']), canonical_bytes(a['transportRef']), a['caller'])
                         for a in channel['actors']), plugin_identity_ref=channel['pluginIdentityRef'],
            instance_id=channel['instanceId'], initial_source=None,
            legacy_actors=(LegacyWorkActor(canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']),
                                          'federation', canonical_bytes(receiver_grants)),))
        with patch('hub.core_work_transport.new_client', side_effect=lambda **kwargs: Connection()):
            owner = CoreWorkOwner(selection, self.identity, (resource,))
        self.addAsyncCleanup(owner.close, timeout=None)
        ingress = owner._ingresses[id(resource)]
        completed = asyncio.get_running_loop().create_future()
        completed.set_result(None)
        ingress._started = completed
        owner._started, owner._ready = completed, True
        return owner, resource, ingress, route

    async def deliver(self, owner, resource, ingress, route, item):
        body = canonical_bytes(item)
        subject = 'am.work.falcon.worker' if item['type'] == 'work' else 'am.result.mac'
        key = nkeys.from_seed(nkeys.encode_seed(bytes([32])*32, nkeys.PREFIX_BYTE_USER))
        try:
            signed = base64.b64encode(key.sign(canonical_bytes(signed_claims(route, body, subject)))).decode()
        finally:
            key.wipe()
        deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
        raw = await resource._owner.db(ingress._retain, route['routeId'], body, subject,
                                      signed, self.core_snapshot, deadline)
        event = object.__new__(CoreWorkEvent)
        ingress._handles[event] = _Event(raw, deadline, ingress._session, ingress._connection)
        message = SimpleNamespace(subject=subject, data=body)
        return await owner._dispatcher.receive(resource, message, event)

    async def test_controlled_original_work_and_result_keep_one_owner_effect(self):
        owner, resource, ingress, route = await self.core()
        item = {'type': 'work', 'origin': 'remote:remote-one', 'origin_node': 'remote', 'origin_id': 'remote-one',
            'work': {'repo': 'falcon', 'target': 'role:falcon/worker', 'title': 'Original legacy',
                     'created_by': 'agent:original', 'requirements': '{"capabilities":["python"]}'}}
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)):
            first = await self.deliver(owner, resource, ingress, route, item)
            self.assertEqual(first['origin'], 'remote:remote-one')
            self.assertEqual(first['created_by'], 'agent:original')
            self.assertEqual(await self.deliver(owner, resource, ingress, route, item), first)
            outgoing = await resource._owner.db(resource._store.work_create, 'operator', 'falcon',
                'role:falcon/worker', 'Outgoing', federate=True, node='mac')
            result = {'type': 'result', 'origin_id': outgoing['id'], 'state': 'done',
                      'result': 'Exact original completion', 'node': 'remote', 'by': 'worker'}
            completed = await self.deliver(owner, resource, ingress, route, result)
            self.assertEqual(completed['result'], 'Exact original completion')
            self.assertEqual(completed['claimed_by'], 'nats:remote:worker')
            self.assertEqual(await self.deliver(owner, resource, ingress, route, result), completed)
            records = await resource._owner.db(resource._store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
            self.assertEqual(len(records), 2)
            self.assertTrue(all(len(strict_loads(row['v'])['attempts']) == 1 for row in records))
            rows = await resource._owner.db(resource._store.q, 'SELECT * FROM work_items')
            self.assertEqual(len(rows), 3)  # Existing fixture row plus one incoming and one outgoing.
            self.assertEqual(sum(row['origin'] == 'remote:remote-one' for row in rows), 1)

    async def test_controlled_lost_reply_recovers_only_original_effect(self):
        owner, resource, ingress, route = await self.core()
        item = {'type': 'work', 'origin': 'remote:lost-reply', 'origin_node': 'remote', 'origin_id': 'lost-reply',
            'work': {'repo': 'falcon', 'target': 'role:falcon/worker', 'title': 'Retained original', 'created_by': 'operator'}}
        original = resource.legacy
        submissions = []
        async def lost(authority, raw):
            request = strict_loads(raw)
            result = await original(authority, raw)
            if request['contractId'] == INGEST:
                submissions.append(request)
                raise ConnectionError('controlled original reply loss')
            return result
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)):
            with patch.object(resource, 'legacy', side_effect=lost), self.assertRaises(ConnectionError):
                await self.deliver(owner, resource, ingress, route, item)
            before = await resource._owner.db(resource._store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
            retained = strict_loads(before[0]['v'])['attempts'][0]['original']
            with patch.object(resource, 'legacy', side_effect=lost):
                recovered = await self.deliver(owner, resource, ingress, route, item)
            after = await resource._owner.db(resource._store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
            self.assertEqual(len(submissions), 1)
            self.assertEqual(strict_loads(after[0]['v'])['attempts'][0]['original'], retained)
            self.assertEqual(recovered['origin'], 'remote:lost-reply')
            self.assertEqual(len(await resource._owner.db(resource._store.q,
                'SELECT id FROM work_items WHERE origin=?', ('remote:lost-reply',))), 1)

    async def test_controlled_absent_uncertain_original_never_resubmits(self):
        owner, resource, ingress, route = await self.core()
        item = {'type': 'work', 'origin': 'remote:unknown', 'origin_node': 'remote', 'origin_id': 'unknown',
            'work': {'repo': 'falcon', 'target': 'role:falcon/worker', 'title': 'Unknown original', 'created_by': 'operator'}}
        original = resource.legacy
        submissions = []
        async def interrupted(authority, raw):
            if strict_loads(raw)['contractId'] == INGEST:
                submissions.append(raw)
                raise ConnectionError('controlled interruption before owner outcome')
            return await original(authority, raw)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(resource, 'legacy', side_effect=interrupted):
            with self.assertRaises(ConnectionError):
                await self.deliver(owner, resource, ingress, route, item)
            with self.assertRaisesRegex(ContractError, 'core_work_original_outcome_unconfirmed'):
                await self.deliver(owner, resource, ingress, route, item)
            self.assertEqual(len(submissions), 1)
            self.assertEqual(await resource._owner.db(resource._store.q,
                'SELECT id FROM work_items WHERE origin=?', ('remote:unknown',)), [])

    async def test_controlled_peer_revocation_blocks_completed_disclosure(self):
        owner, resource, ingress, route = await self.core()
        item = {'type': 'work', 'origin': 'remote:revoked', 'origin_node': 'remote', 'origin_id': 'revoked',
            'work': {'repo': 'falcon', 'target': 'role:falcon/worker', 'title': 'Original grant', 'created_by': 'operator'}}
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)):
            await self.deliver(owner, resource, ingress, route, item)
        current = strict_loads(self.core_snapshot.record)
        next(g for g in current['state']['grants'] if g['ref'] == route['peer']['grantRefs'][INGEST])['status'] = 'revoked'
        snapshot = AuthoritySnapshot(canonical_bytes(current), self.core_snapshot.sequence + 1)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=snapshot)), self.assertRaises(ContractError):
            await self.deliver(owner, resource, ingress, route, item)
        rows = await resource._owner.db(resource._store.q, 'SELECT id FROM work_items WHERE origin=?', ('remote:revoked',))
        self.assertEqual(len(rows), 1)

    async def test_controlled_fresh_callback_retries_only_proven_zero_effect_conflict(self):
        owner, resource, ingress, route = await self.core()
        item = {'type': 'work', 'origin': 'remote:conflict', 'origin_node': 'remote', 'origin_id': 'conflict',
            'work': {'repo': 'falcon', 'target': 'role:falcon/worker', 'title': 'Concurrent revision', 'created_by': 'operator'}}
        commit = resource._journal.commit
        changed = False
        def race(original, expected, deadline, effect):
            nonlocal changed
            if original['contractId'] == INGEST and not changed:
                changed = True
                with resource._store.tx():
                    current = resource._journal.current()
                    resource._journal._set('resource', {**current, 'revision': current['revision'] + 1})
            return commit(original, expected, deadline, effect)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)):
            with patch.object(resource._journal, 'commit', side_effect=race), \
                    self.assertRaisesRegex(ContractError, 'core_work_revision_conflict'):
                await self.deliver(owner, resource, ingress, route, item)
            recovered = await self.deliver(owner, resource, ingress, route, item)
            self.assertEqual(recovered['origin'], 'remote:conflict')
            rows = await resource._owner.db(resource._store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'core-work-dispatch:%'")
            attempts = strict_loads(rows[0]['v'])['attempts']
            self.assertEqual(len(attempts), 2)
            self.assertEqual([attempt['reply']['outcome'] for attempt in attempts], ['conflict', 'applied'])
            a, b = [attempt['original'] for attempt in attempts]
            self.assertNotEqual(a['operation']['operationId'], b['operation']['operationId'])
            self.assertNotEqual(a['payload']['input']['coreTransport']['admissionId'],
                                b['payload']['input']['coreTransport']['admissionId'])
            self.assertEqual(a['payload']['input']['envelope'], b['payload']['input']['envelope'])
            self.assertEqual(len(await resource._owner.db(resource._store.q,
                'SELECT id FROM work_items WHERE origin=?', ('remote:conflict',))), 1)

    async def test_controlled_cancellation_close_joins_exact_original_db_effect(self):
        from threading import Event
        owner, resource, ingress, route = await self.core()
        item = {'type': 'work', 'origin': 'remote:cancelled', 'origin_node': 'remote', 'origin_id': 'cancelled',
            'work': {'repo': 'falcon', 'target': 'role:falcon/worker', 'title': 'Owned cancellation', 'created_by': 'operator'}}
        entered, release = Event(), Event()
        ingest = resource._store.ingest_work
        def blocked(value):
            row = ingest(value)
            entered.set()
            if not release.wait(4):
                raise AssertionError('The original DB transaction was not released')
            return row
        caller = None
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(resource._store, 'ingest_work', side_effect=blocked):
            try:
                caller = asyncio.create_task(self.deliver(owner, resource, ingress, route, item))
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                caller.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await caller
                with self.assertRaisesRegex(ContractError, 'core_work_cleanup_incomplete'):
                    await owner.close(timeout=.01)
                self.assertTrue(owner._dispatcher._workers)
            finally:
                release.set()
                await owner.close(timeout=None)
                if caller is not None:
                    await asyncio.gather(caller, return_exceptions=True)
        self.assertFalse(owner._dispatcher._workers)
        rows = await resource._owner.db(resource._store.q, 'SELECT id FROM work_items WHERE origin=?', ('remote:cancelled',))
        self.assertEqual(len(rows), 1)

    async def test_history_replaced_after_final_authority_read_refuses_original_commit(self):
        from threading import Event
        owner, resource, ingress, route = await self.core()
        item = {'type': 'work', 'origin': 'remote:history-replaced', 'origin_node': 'remote',
            'origin_id': 'history-replaced', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Reject changed authority custody', 'created_by': 'operator'}}
        entered, release = Event(), Event()
        commit = owner.check_commit
        pending_state = []
        def blocked(*args):
            pending_state.extend(resource._store.q('SELECT k,v FROM fed_state ORDER BY k'))
            entered.set()
            if not release.wait(4):
                raise AssertionError('The original commit fence was not released')
            return commit(*args)
        history = self.identity.reader._ledger._history
        path, backup = history._path, history._path.with_name('retained-original-history')
        replaced = False
        caller = None
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(owner, 'check_commit', side_effect=blocked):
            try:
                caller = asyncio.create_task(self.deliver(owner, resource, ingress, route, item))
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                path.rename(backup)
                path.write_bytes(b'distinct private replacement')
                path.chmod(0o600)
                replaced = True
                release.set()
                with self.assertRaises(ContractError):
                    await caller
            finally:
                release.set()
                if caller is not None:
                    await asyncio.gather(caller, return_exceptions=True)
                if replaced:
                    path.unlink()
                    backup.rename(path)
        # Inspect the retained physical Store without reauthorizing through the
        # deliberately invalidated identity history. This is test observation.
        rows = await resource._owner._source.db(resource._store.q,
            'SELECT id FROM work_items WHERE origin=?', (item['origin'],))
        self.assertEqual(rows, [])
        self.assertTrue(pending_state)
        retained = await resource._owner._source.db(resource._store.q,
            'SELECT k,v FROM fed_state ORDER BY k')
        self.assertEqual(retained, pending_state)
        dispatch = [strict_loads(row['v']) for row in retained if row['k'].startswith('core-work-dispatch:')]
        self.assertEqual(len(dispatch), 1)
        self.assertEqual(len(dispatch[0]['attempts']), 1)
        self.assertEqual(set(dispatch[0]['attempts'][0]), {'original'})
        original = dispatch[0]['attempts'][0]['original']
        self.assertIsNone(await resource._owner._source.db(resource._journal.outcome,
            original['operation']['operationId'], original['operation']['payloadDigest']))
