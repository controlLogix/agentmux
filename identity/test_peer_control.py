"""Control-only account credentials and retained peer authority boundaries."""
import asyncio
import base64
import copy
import hashlib
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from capability_owner import test_knowledge_host as knowledge_support
from capability_owner.knowledge_host import KnowledgeStoreHost
from hub.fed import envelope
from hub.fed.peer_control import PeerControlEvent, PeerControlIngress
from .authority import AuthoritySnapshot
from .peer_control import HEADER, check_authority, control_claims, public_credential, receiver_credential
from .test_authority import ref
from native_security.test_nats_credentials import credential


def control_credentials(*, peer=None, change=None):
    def update(claims):
        claims['nats'].update(pub={'allow': ['am.ctl.' + peer]} if peer else {'allow': [], 'deny': ['>']},
            sub={'allow': [], 'deny': ['>']} if peer else {'allow': ['am.ctl.alice']})
        if change:
            change(claims)
    return credential(update)


class PeerControlCredentialTests(unittest.TestCase):
    def test_public_peer_credential_has_no_private_seed_and_exact_subject(self):
        raw, account, user = control_credentials(peer='alice')
        token = raw.splitlines()[1].decode()
        claims, public = public_credential(token, account=account, user=user, peer='alice')
        self.assertEqual(claims['nats']['pub']['allow'], ['am.ctl.alice'])
        self.assertEqual(len(public), 32)
        self.assertNotIn('PRIVATE', token)
        for wrong in ('mallory', '*', 'alice.more'):
            with self.subTest(peer=wrong), self.assertRaises(ContractError):
                public_credential(token, account=account, user=user, peer=wrong)

    def test_wildcard_response_and_expired_credentials_refuse(self):
        changes = [lambda c: c['nats']['pub'].update(allow=['am.ctl.*']),
            lambda c: c['nats']['pub'].update(allow=['am.ctl.>']),
            lambda c: c['nats']['pub'].update(allow=['>']),
            lambda c: c['nats'].update(resp={'max': 1, 'ttl': 5000000000}),
            lambda c: c['nats'].update(bearer_token=True),
            lambda c: c.update(exp=int(time.time()) - 1)]
        for change in changes:
            raw, account, user = control_credentials(peer='alice', change=change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                public_credential(raw.splitlines()[1].decode(), account=account, user=user, peer='alice')

    def test_opaque_event_cannot_be_constructed(self):
        with self.assertRaises(TypeError):
            PeerControlEvent()


class PeerControlFixture(knowledge_support.SelectedKnowledgeCompositionFixture):
    def setUp(self):
        super().setUp()
        selected = self.value['storage']['knowledge']
        raw, account, user = control_credentials()
        credentials = self.root / 'control-receiver.creds'
        credentials.write_bytes(raw)
        credentials.chmod(0o600)
        peer_raw, _, peer_user = control_credentials(peer='alice')
        # Give the receiver a different NKey from the peer while retaining the
        # same account signer and the exact deny-all receiving policy.
        key = nkeys.from_seed(nkeys.encode_seed(bytes([31]) * 32, nkeys.PREFIX_BYTE_USER))
        try:
            old = raw.splitlines()[1]
            first, second, _ = old.split(b'.')
            claims = strict_loads(base64.urlsafe_b64decode(second + b'=' * (-len(second) % 4)))
            claims['sub'] = key.public_key.decode()
            second = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
            signer = nkeys.from_seed(nkeys.encode_seed(bytes([1]) * 32, nkeys.PREFIX_BYTE_ACCOUNT))
            try:
                new = first + b'.' + second
                new += b'.' + base64.urlsafe_b64encode(signer.sign(new)).rstrip(b'=')
            finally:
                signer.wipe()
            raw = raw.replace(old, new).replace(raw.split(b'BEGIN USER NKEY SEED-----\n')[1].splitlines()[0], key.seed)
            credentials.write_bytes(raw)
            user = key.public_key.decode()
        finally:
            key.wipe()
        self.value['peerControl'] = {'routes': [{ 'routeId': 'knowledge-alice',
            'scope': self.scope, 'resourceRef': ref('knowledge-one'),
            'repository': copy.deepcopy(selected['repository']), 'localPeer': 'nick', 'localNode': 'mac',
            'accountPublicKey': account, 'connection': copy.deepcopy(self.value['storage']['receivers']['storage']['connection']),
            'receiver': {'identityRef': ref('control-receiver'), 'transportRef': ref('control-receiver-transport'),
                'credentials': {'path': str(credentials), 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(),
                    'userPublicKey': user}},
            'peer': {'peerId': 'alice', 'nodeId': 'mac', 'identityRef': ref('control-peer'), 'transportRef': ref('control-peer-transport'),
                'grantRef': ref('control-grant'), 'userPublicKey': peer_user,
                'credentialJWT': peer_raw.splitlines()[1].decode()}}]}
        self.value['peerControl']['routes'][0]['connection'].pop('jetstreamDomain', None)
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        state = current['state']
        template = copy.deepcopy(state['transports'][0])
        template['issuerRef'] = self.value['identity']['issuer']['issuerRef']
        for role, public_user in (('receiver', user), ('peer', peer_user)):
            name = 'control-' + role
            state['identities'].append({'ref': ref(name), 'kind': 'service', 'status': 'active',
                'principalId': name, 'externalIdentity': None})
            state['memberships'].append({'ref': ref(name + '-member'), 'identityRef': ref(name),
                'scope': copy.deepcopy(self.scope), 'status': 'active'})
            decoded = base64.b32decode(public_user + '=' * (-len(public_user) % 8))[1:-2]
            state['transports'].append({**template, 'ref': ref(name + '-transport'), 'identityRef': ref(name),
                'publicKey': base64.urlsafe_b64encode(decoded).decode().rstrip('='),
                'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        grant = copy.deepcopy(state['grants'][0])
        grant.update(ref=ref('control-grant'), callerRef=ref('control-peer'), actorRef=ref('control-peer'),
            scope=copy.deepcopy(self.scope), resourceId='knowledge-one', contractId='peer-control-revoke',
            decision='allowed', delegationRef=None, issuedAt=self.issuer_start, expiresAt=self.issuer_end)
        state['grants'].append(grant)
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        selected = self.value['storage']['knowledge']
        self.source = KnowledgeStoreHost(selected['source'], repository=selected['repository'],
            local_peer='nick', owner_uid=__import__('os').getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()



class PeerControlTests(PeerControlFixture, unittest.IsolatedAsyncioTestCase):
    async def test_current_peer_and_receiver_membership_transport_and_hard_deny(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)):
            self.assertEqual((await check_authority(self.selection, self.identity, route_id='knowledge-alice')).sequence, self.snapshot.sequence)
        for change in ('identity', 'transport', 'member', 'grant', 'hard-deny'):
            current = strict_loads(self.snapshot.record)
            state = current['state']
            if change == 'identity':
                next(x for x in state['identities'] if x['ref'] == ref('control-peer'))['status'] = 'revoked'
            elif change == 'transport':
                next(x for x in state['transports'] if x['ref'] == ref('control-peer-transport'))['status'] = 'revoked'
            elif change == 'member':
                next(x for x in state['memberships'] if x['ref'] == ref('control-peer-member'))['status'] = 'revoked'
            elif change == 'grant':
                next(x for x in state['grants'] if x['ref'] == ref('control-grant'))['decision'] = 'review-required'
            else:
                denied = copy.deepcopy(next(x for x in state['grants'] if x['ref'] == ref('control-grant')))
                denied.update(ref=ref('control-hard-deny'), decision='denied')
                state['grants'].append(denied)
            snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence + 1)
            with self.subTest(change=change), patch.object(self.identity.reader, 'current', AsyncMock(return_value=snapshot)), \
                    self.assertRaises(ContractError):
                await check_authority(self.selection, self.identity, route_id='knowledge-alice')

    async def test_retained_control_event_conflicts_and_opaque_handle_is_single_use(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)):
            ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='knowledge-alice')
            self.addAsyncCleanup(ingress.close, timeout=None)
            item = envelope.make('revoke', 'alice', 'mac')
            key = nkeys.from_seed(nkeys.encode_seed(bytes([2]) * 32, nkeys.PREFIX_BYTE_USER))
            try:
                signature = base64.b64encode(key.sign(canonical_bytes(control_claims(
                    self.value['peerControl']['routes'][0], item, 'am.ctl.alice')))).decode()
            finally:
                key.wipe()
            raw = await self.source.db(ingress._retain, item, signature, 1)
            self.assertEqual(await self.source.db(ingress._retain, item, signature, 9), raw)
            altered = copy.deepcopy(item)
            altered['data']['changed'] = True
            with self.assertRaises(ContractError):
                await self.source.db(ingress._retain, altered, signature, 2)
            # Controlled checks establish registry/scope behavior only. Actual
            # callback and NKey proof are covered by the separately selected live test.
            with patch.object(ingress, 'check'):
                handle = ingress._handle(raw)
                self.assertEqual(await ingress.consume(handle, peer='alice',
                    repository_id=self.value['peerControl']['routes'][0]['repository']['repositoryId']), raw)
                with self.assertRaises(ContractError):
                    await ingress.consume(handle, peer='alice',
                        repository_id=self.value['peerControl']['routes'][0]['repository']['repositoryId'])
                recovered = await ingress.recover(item['id'], payload_digest(item))
                self.assertEqual(await ingress.consume(recovered, peer='alice',
                    repository_id=self.value['peerControl']['routes'][0]['repository']['repositoryId']), raw)
                for change in ('id', 'event', 'digest', 'signature', 'subject', 'scope', 'sequence', 'shape'):
                    modified = strict_loads(raw)
                    if change == 'id': modified['event']['id'] = 'different-event'
                    elif change == 'event': modified['event']['data']['changed'] = True
                    elif change == 'digest': modified['eventDigest'] = 'sha256:' + 'a' * 64
                    elif change == 'signature': modified['signature'] = base64.b64encode(bytes(64)).decode()
                    elif change == 'subject': modified['subject'] = 'am.ctl.mallory'
                    elif change == 'scope': modified['binding']['scope']['projectId'] = 'another-project'
                    elif change == 'sequence': modified['authoritySequence'] = self.snapshot.sequence + 1
                    else: modified['forged'] = True
                    await self.source.db(self.source._store.db.execute, 'UPDATE fed_state SET v=? WHERE k=?',
                        (canonical_bytes(modified).decode(), ingress._key(item['id'])))
                    with self.subTest(change=change), self.assertRaises((ContractError, ValueError)):
                        await ingress.recover(item['id'], payload_digest(item))
                await self.source.db(self.source._store.db.execute, 'UPDATE fed_state SET v=? WHERE k=?',
                    (raw.decode(), ingress._key(item['id'])))
                revoked = strict_loads(self.snapshot.record)
                next(g for g in revoked['state']['grants'] if g['ref'] == ref('control-grant'))['status'] = 'revoked'
                with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                        canonical_bytes(revoked), self.snapshot.sequence + 1))), self.assertRaises(ContractError):
                    await ingress.recover(item['id'], payload_digest(item))

    async def test_direct_callback_and_unsigned_message_cannot_mint_admission(self):
        from nats.aio.msg import Msg
        ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='knowledge-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        item = envelope.make('revoke', 'alice', 'mac')
        message = Msg(_client=ingress._connection, subject='am.ctl.alice', data=canonical_bytes(item), _sid=1)
        with patch.object(ingress, 'check'), self.assertRaises(ContractError):
            ingress._message(message)
        self.assertEqual(await self.source.db(self.source._store.q, "SELECT * FROM fed_state WHERE k LIKE 'peer-control:%'"), [])

    async def test_route_collection_refuses_duplicate_scope_and_cross_resource_signature(self):
        original = copy.deepcopy(self.value)
        route = copy.deepcopy(self.value['peerControl']['routes'][0])
        route['routeId'] = 'duplicate-alice'
        self.value['peerControl']['routes'].append(route)
        with self.assertRaises(ContractError):
            self.selected()
        self.value = original
        ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='knowledge-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        item = envelope.make('revoke', 'alice', 'mac')
        wrong = copy.deepcopy(self.value['peerControl']['routes'][0])
        wrong['resourceRef'] = ref('other-owner')
        key = nkeys.from_seed(nkeys.encode_seed(bytes([2]) * 32, nkeys.PREFIX_BYTE_USER))
        try:
            signature = base64.b64encode(key.sign(canonical_bytes(control_claims(wrong, item, 'am.ctl.alice')))).decode()
        finally:
            key.wipe()
        with self.assertRaises(ContractError):
            ingress._verify_event(item, 'am.ctl.alice', signature)

    async def test_same_original_event_keeps_each_selected_owner_receipt_and_recovery(self):
        second_channel = copy.deepcopy(self.value['storage']['knowledge']['channels'][0])
        second_channel['resourceRef'] = ref('knowledge-two')
        self.value['storage']['knowledge']['channels'].append(second_channel)
        second = copy.deepcopy(self.value['peerControl']['routes'][0])
        second.update(routeId='knowledge-alice-two', resourceRef=ref('knowledge-two'))
        second['peer']['grantRef'] = ref('control-grant-two')
        self.value['peerControl']['routes'].append(second)
        self.selection = self.selected()
        record = strict_loads(self.snapshot.record)
        grant = copy.deepcopy(next(g for g in record['state']['grants'] if g['ref'] == ref('control-grant')))
        grant.update(ref=ref('control-grant-two'), resourceId='knowledge-two')
        record['state']['grants'].append(grant)
        snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)
        item = envelope.make('revoke', 'alice', 'mac')
        key = nkeys.from_seed(nkeys.encode_seed(bytes([2]) * 32, nkeys.PREFIX_BYTE_USER))
        try:
            with patch.object(self.identity.reader, 'current', AsyncMock(return_value=snapshot)):
                originals = []
                for route in self.value['peerControl']['routes']:
                    ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(),
                        route_id=route['routeId'])
                    self.addAsyncCleanup(ingress.close, timeout=None)
                    signature = base64.b64encode(key.sign(canonical_bytes(control_claims(route, item, 'am.ctl.alice')))).decode()
                    original = await self.source.db(ingress._retain, item, signature, snapshot.sequence)
                    with patch.object(ingress, 'check'):
                        handle = await ingress.recover(item['id'], payload_digest(item))
                        self.assertEqual(await ingress.consume(handle, peer='alice',
                            repository_id=route['repository']['repositoryId']), original)
                    originals.append(strict_loads(original))
                self.assertEqual([p['event']['id'] for p in originals], [item['id'], item['id']])
                self.assertNotEqual(originals[0]['binding']['resourceRef'], originals[1]['binding']['resourceRef'])
                rows = await self.source.db(self.source._store.q,
                    "SELECT * FROM fed_state WHERE k LIKE 'peer-control:%'")
                self.assertEqual(len(rows), 2)
        finally:
            key.wipe()

    async def test_close_joins_recovery_waiting_on_original_authority_before_source_release(self):
        ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='knowledge-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        entered, release = asyncio.Event(), asyncio.Event()
        async def paused(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.snapshot
        original_check = ingress.check
        def controlled_check():
            if ingress._closed:
                raise ContractError('peer_control_unavailable')
            self.source.check_health()
        with patch.object(ingress, 'check', side_effect=controlled_check), \
                patch('hub.fed.peer_control.check_authority', side_effect=paused):
            recovery = asyncio.create_task(ingress.recover('original', 'sha256:' + 'a' * 64))
            await asyncio.wait_for(entered.wait(), 1)
            self.assertEqual(len(ingress._active), 1)
            with self.assertRaises(ContractError):
                await ingress.close(timeout=.001)
            closing = ingress._closing
            self.assertFalse(closing.done())
            self.assertIsNotNone(self.source._store)
            release.set()
            with self.assertRaises(ContractError):
                await recovery
            await ingress.close(timeout=None)
            self.assertIs(ingress._closing, closing)
            self.assertTrue(closing.done())
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_state WHERE k LIKE 'peer-control:%'"), [])

    async def test_selected_message_host_can_lend_exact_knowledge_store_custody(self):
        from capability_owner.messages_host import MessageStoreHost
        await self.source.close()
        selected = self.value['storage']['knowledge']
        source = MessageStoreHost(selected['source'], repository=selected['repository'],
            local_peer='nick', owner_uid=__import__('os').getuid())
        self.addAsyncCleanup(source.close)
        await source.start()
        await source.db(KnowledgeStoreHost.check_knowledge_tables, source._store)
        ingress = PeerControlIngress(self.selection, self.identity, source, AsyncMock(), route_id='knowledge-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        self.assertIs(ingress._store_owner, source)
        with self.assertRaises(ContractError):
            PeerControlIngress(self.selection, self.identity,
                SimpleNamespace(_pins=source._pins, _store=source._store), AsyncMock(), route_id='knowledge-alice')

    async def test_recovery_caller_can_join_same_close_without_waiting_on_its_own_task(self):
        ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='knowledge-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        entered, release = asyncio.Event(), asyncio.Event()
        async def authority(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.snapshot
        def check():
            if ingress._closed:
                raise ContractError('peer_control_unavailable')
        async def caller():
            with self.assertRaises(ContractError):
                await ingress.recover('original', 'sha256:' + 'a' * 64)
            await ingress.close(timeout=None)
        with patch.object(ingress, 'check', side_effect=check), \
                patch('hub.fed.peer_control.check_authority', side_effect=authority):
            original = asyncio.create_task(caller())
            await asyncio.wait_for(entered.wait(), 1)
            with self.assertRaises(ContractError):
                await ingress.close(timeout=.001)
            close = ingress._closing
            release.set()
            await asyncio.wait_for(asyncio.shield(original), 1)
            self.assertTrue(close.done())
            self.assertIs(ingress._closing, close)

