"""Actual selected peer publisher, TLS/JWT ingress and retained control receipt."""
import asyncio
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import unittest

import nkeys
from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from capability_owner.test_policy_live import PolicyLiveFixture
from capability_owner.test_knowledge_host import selected_knowledge
from capability_owner.knowledge_host import KnowledgeStoreHost
from hub.fed import envelope
from hub.fed.peer_control import PeerControlIngress, PeerControlPublisher
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref, SEED
from identity.peer_control import HEADER, control_claims
from hub.fed.peer_control import HEADER_REPOSITORY
from identity.test_peer_control import PeerControlTests
from native_security.nats_credentials import _JWT, _base32


class LivePeerControlTests(PolicyLiveFixture, PeerControlTests):
    enroll_native_instances = False
    private_inbox_roles = ('identity', 'storage', 'host', 'other-scope')

    def setUp(self):
        from capability_owner.test_selected_storage import SelectedStorageCompositionTests
        self.custody = SelectedStorageCompositionTests.custody.__get__(self)
        try:
            PeerControlTests.setUp(self)
        finally:
            del self.custody

    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        for role, peer in (('control-alice', 'alice'), ('control-nick', 'nick'), ('control-mallory', 'mallory')):
            self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
            policies[role] = {'publish': {'allow': ['am.ctl.' + peer]}, 'subscribe': {'allow': []}}
        self.inbox_prefixes['control-receiver'] = '_INBOX.' + secrets.token_hex(16)
        policies['control-receiver'] = {'publish': {'allow': []}, 'subscribe': {'allow': ['am.ctl.alice']}}
        self.inbox_prefixes['control-alice-receiver'] = '_INBOX.' + secrets.token_hex(16)
        policies['control-alice-receiver'] = {'publish': {'allow': []}, 'subscribe': {'allow': ['am.ctl.nick']}}

    def _configure_tls_and_users(self):
        super()._configure_tls_and_users()
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

    def _credential(self, role):
        raw = self.credentials[role].read_bytes()
        token = _JWT.findall(raw)[0]
        body = token.split(b'.')[1]
        claims = strict_loads(base64.urlsafe_b64decode(body + b'=' * (-len(body) % 4)))
        return {'path': str(self.credentials[role]), 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(),
            'userPublicKey': claims['sub']}, token.decode()

    def initial_authority(self):
        record = super().initial_authority()
        state = record['state']
        template = copy.deepcopy(state['transports'][0])
        grant = copy.deepcopy(state['grants'][0])
        state['grants'].append({**copy.deepcopy(grant), 'ref': ref('control-admin-grant'),
            'contractId': 'identity-grant-set', 'resourceId': 'authority-one',
            'scope': {**self.scope, 'projectId': None}, 'decision': 'allowed', 'delegationRef': None})
        for name, role in (('control-receiver', 'control-receiver'), ('control-peer', 'control-alice'),
                ('control-nick', 'control-nick'), ('control-alice-receiver', 'control-alice-receiver')):
            pin, _ = self._credential(role)
            public = _base32(pin['userPublicKey'].encode(), 35)[1:-2]
            state['identities'].append({'ref': ref(name), 'kind': 'service', 'status': 'active',
                'principalId': name, 'externalIdentity': None})
            state['transports'].append({**template, 'ref': ref(name + '-transport'), 'identityRef': ref(name),
                'issuerRef': ref('issuer'), 'publicKey': base64.urlsafe_b64encode(public).decode().rstrip('=')})
            state['memberships'].append({'ref': ref(name + '-member'), 'identityRef': ref(name),
                'scope': copy.deepcopy(self.scope), 'status': 'active'})
            if name in ('control-peer', 'control-nick'):
                state['grants'].append({**grant, 'ref': ref(name + '-grant'),
                    'callerRef': ref(name), 'actorRef': ref(name), 'scope': copy.deepcopy(self.scope),
                    'contractId': 'peer-control-revoke', 'resourceId': 'knowledge-one',
                    'decision': 'allowed', 'delegationRef': None})
        return record

    async def asyncSetUp(self):
        await PolicyLiveFixture.asyncSetUp(self)
        self.control_ingress = self.control_publisher = None
        self.control_source = None
        self.addAsyncCleanup(self._control_cleanup)
        identity = self.value['identity']
        ledger = self.identity.ledger
        history = ledger._history
        identity['ledger'].update(stream='IDENTITY', scope={**self.scope, 'projectId': None},
            streamIdentity={'created': ledger._identity.created.isoformat().replace('+00:00', 'Z'), 'minimumSequence': 0},
            retention={'maxBytes': self.policy.max_bytes, 'reserveBytes': self.policy.reserve_bytes, 'replicas': 1},
            history={'path': str(history._path), 'maxRecords': history._max_records, 'maxBytes': history._max_bytes})
        key_path = self.root / 'control-live-identity.key'
        key_path.write_bytes(canonical_bytes({'schemaVersion': '1.0.0', 'purpose': 'agentmux-application-service-key-v1',
            'serviceId': 'identity-owner', 'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
            'issuerRef': ref('issuer'), 'seed': base64.b64encode(SEED).decode()}))
        key_path.chmod(0o600)
        identity['issuer'].update(issuerRef=ref('issuer'), keyFile={'path': str(key_path),
            'sha256': 'sha256:' + hashlib.sha256(key_path.read_bytes()).hexdigest()},
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='))
        for receiver in self.value['storage']['receivers'].values():
            receiver['requestSigningKeyRef'] = ref('issuer')
        connection = {'endpoint': self.broker.url, 'serverName': self.server_name, 'rootsPEM': self.ca_file.read_text(),
            'leafCertificateSHA256': self.leaf_digest}
        identity['connection'] = {**connection, 'jetstreamDomain': None}
        identity_credentials, _ = self._credential('identity')
        identity['credentials'] = {**identity_credentials, 'accountPublicKey': self.account_public_key,
            'replyPrefix': self.inbox_prefixes['identity']}
        pin = self.value['peerControl']['routes'][0]
        pin.update(scope=copy.deepcopy(self.scope), connection=connection, accountPublicKey=self.account_public_key)
        pin['receiver']['credentials'], _ = self._credential('control-receiver')
        peer, token = self._credential('control-alice')
        pin['peer'].update(nodeId='mac_alice', userPublicKey=peer['userPublicKey'], credentialJWT=token,
            grantRef=ref('control-peer-grant'))
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        self.selection.check_storage_identity_source(self.identity)
        knowledge = self.value['storage']['knowledge']
        self.control_source = KnowledgeStoreHost(knowledge['source'], repository=knowledge['repository'],
            local_peer='nick', owner_uid=os.getuid())
        await self.control_source.start()
        self.received, self.proofs = asyncio.Event(), []
        async def dispatch(message, handle):
            self.proofs.append(await self.control_ingress.consume(handle, peer='alice',
                repository_id=pin['repository']['repositoryId']))
            self.received.set()
        self.control_ingress = PeerControlIngress(self.selection, self.identity, self.control_source, dispatch, route_id='knowledge-alice')
        await self.control_ingress.start()
        sender = copy.deepcopy(self.value)
        sender_directory = self.root / 'control-sender'
        sender_directory.mkdir(mode=0o700)
        sender_knowledge = selected_knowledge(sender_directory, scope=self.scope)
        sender_knowledge.update(localPeer='alice', localNode='mac_alice')
        sender_policy = Path(sender_knowledge['source']['policy']['path'])
        sender_policy.write_bytes(sender_policy.read_bytes().replace(b'peer="nick"', b'peer="alice"')
            .replace(b'[peers.alice]', b'[peers.nick]'))
        sender_knowledge['source']['policy']['sha256'] = 'sha256:' + hashlib.sha256(sender_policy.read_bytes()).hexdigest()
        sender['storage']['knowledge'] = sender_knowledge
        sender_pin = sender['peerControl']['routes'][0]
        sender_pin.update(localPeer='alice', localNode='mac_alice')
        nick, token = self._credential('control-nick')
        sender_pin['peer'].update(peerId='nick', nodeId='mac', identityRef=ref('control-nick'),
            transportRef=ref('control-nick-transport'), grantRef=ref('control-nick-grant'),
            userPublicKey=nick['userPublicKey'], credentialJWT=token)
        sender_receiver, _ = self._credential('control-alice-receiver')
        sender_pin['receiver'].update(identityRef=ref('control-alice-receiver'),
            transportRef=ref('control-alice-receiver-transport'), credentials=sender_receiver)
        sender_pin['publisher'] = {'identityRef': ref('control-peer'), 'transportRef': ref('control-peer-transport'),
            'grantRef': ref('control-peer-grant'), 'credentials': peer}
        from agentmux_contracts.validation import _validators, DEFAULT_SCHEMA_DIR
        errors = list(_validators(DEFAULT_SCHEMA_DIR)['application-service-selection'].iter_errors(sender))
        if errors:
            raise RuntimeError('peer_control_sender_fixture_schema:' + ','.join(
                '/'.join(map(str, e.path)) + ':' + e.validator for e in errors))
        self.sender_selection = ApplicationServiceSelection(canonical_bytes(sender))
        self.control_publisher = PeerControlPublisher(self.sender_selection, self.identity, route_id='knowledge-alice')
        # Check unused inbound pins as well, without starting a second receiver.
        from identity.peer_control import receiver_credential, check_authority
        receiver_credential(sender_pin)
        await check_authority(self.sender_selection, self.identity, route_id='knowledge-alice')
        sender_source = KnowledgeStoreHost(sender_knowledge['source'], repository=sender_knowledge['repository'],
            local_peer='alice', owner_uid=os.getuid())
        self.addAsyncCleanup(sender_source.close)
        await sender_source.start()
        await sender_source.close()
        await self.control_publisher.start()

    async def _control_cleanup(self):
        if self.control_publisher is not None:
            await self.control_publisher.close(timeout=None)
        if self.control_ingress is not None:
            await self.control_ingress.close(timeout=None)
        if self.control_source is not None:
            await self.control_source.close()

    async def test_actual_selected_publisher_admission_recovery_and_broker_spoof_refusals(self):
        item = envelope.make('revoke', 'alice', 'mac_alice', data={'reason': 'kill switch'})
        result = await self.control_publisher.publish_revoke(item)
        await asyncio.wait_for(self.received.wait(), 3)
        self.assertEqual(result, {'eventId': item['id'], 'eventDigest': payload_digest(item)})
        original = self.proofs[0]
        self.assertEqual(strict_loads(original)['event'], item)
        self.received.clear()
        await self.control_publisher.publish_revoke(item)
        await asyncio.wait_for(self.received.wait(), 3)
        self.assertEqual(self.proofs, [original, original])
        recovered = await self.control_ingress.recover(item['id'], payload_digest(item))
        self.assertEqual(await self.control_ingress.consume(recovered, peer='alice',
            repository_id=self.value['peerControl']['routes'][0]['repository']['repositoryId']), original)
        mallory = await self.connect('control-mallory')
        for role, connection in (('control-mallory', mallory), ('host', self.host)):
            for subject in ('am.ctl.alice', 'am.ctl.*', 'am.ctl.>'):
                before = len(self.errors[role])
                self.permission_events[role].clear()
                await connection.publish(subject, canonical_bytes(item))
                await connection.flush(timeout=1)
                await self.wait_permissions(role, before + 1)
        self.assertEqual(len(self.proofs), 2)
        # Even an account administrator able to publish this subject cannot
        # fabricate Alice's possession proof or obtain an admitted handle.
        original_callback = self.control_ingress._subscription._cb
        completed, refused = asyncio.Event(), []
        async def observed(message):
            try:
                await original_callback(message)
            except ContractError:
                refused.append(True)
                raise
            finally:
                completed.set()
        self.control_ingress._subscription._cb = observed
        repository = self.value['peerControl']['routes'][0]['repository']['repositoryId']
        signature = strict_loads(original)['signature']
        for headers in (None, {HEADER: signature},
                {HEADER: base64.b64encode(bytes(64)).decode(), HEADER_REPOSITORY: repository},
                {HEADER: signature, HEADER_REPOSITORY: 'r000000000000'},
                {HEADER: signature, HEADER_REPOSITORY: repository + '.other'}):
            completed.clear()
            await self.admin.publish('am.ctl.alice', canonical_bytes(item), headers=headers)
            await self.admin.flush(timeout=1)
            await asyncio.wait_for(completed.wait(), 1)
        self.assertEqual(refused, [True] * 5)
        self.assertEqual(len(self.proofs), 2)
        # Revoke actual retained authority; an old admitted receipt cannot renew it.
        state = strict_loads((await self.identity.reader.current()).record)['state']
        current = next(g for g in state['grants'] if g['ref'] == ref('control-peer-grant'))
        updated = {**current, 'ref': {**current['ref'], 'revision': 2}, 'status': 'revoked'}
        await self.command('identity-grant-set', ref('control-admin-grant'),
            {'authorityId': 'authority-one', 'record': updated, 'previousRef': current['ref']})
        with self.assertRaises(ContractError):
            await self.control_ingress.recover(item['id'], payload_digest(item))
        self.success = True
