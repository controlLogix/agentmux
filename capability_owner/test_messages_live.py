"""Actual native storage commands against existing message SQLite owners."""
import asyncio
import copy
from datetime import datetime, timezone
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest

from agentmux_contracts import canonical_bytes, strict_loads
from hub.fed import envelope
from hub.fed.message_services import LocalMessages, FederationPublisher
from hub.fed.runtime import Federation
from hub.fed.session import FederationSession
from hub.store import Store
from hub.tests.test_fed_unit import policy
from identity.test_authority import ref, SEED
from identity.test_native_bridge import HOST_SEED
from state_owner.ledger import OwnerBinding
from .messages import MessageActor, MessageStorageResource
from .reply_service import CapabilityReplyService
from .test_policy_live import PolicyLiveFixture


class MessageLiveFixture(PolicyLiveFixture):
    native_go = True
    recovery_checks = True
    service_id = 'storage-owner'
    read_contract, read_class, read_action = 'capability-storage-write', 'storage', 'write'

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        grant = copy.deepcopy(next(g for g in state['grants'] if g['ref'] == ref('capability-policy-evaluate')))
        grant.update(ref=ref('capability-storage-write'), contractId=self.read_contract)
        state['grants'].append(grant)
        query = copy.deepcopy(grant)
        query.update(ref=ref('capability-outcome-query'), contractId='capability-outcome-query')
        state['grants'].append(query)
        for row in (self.parent, self.row):
            facts = row['facts']
            facts['grant'].update(actions=['write', 'inspect'], resourceIds=['task-one'])
            facts['policy']['decisions'] = [{'access': {'action': 'write', 'resourceClass': 'storage',
                'resourceId': 'task-one'}, 'outcome': 'allow'}]
            facts['domainBindings'] = [{'id': 'messages-write', 'contractId': self.read_contract,
                'action': 'write', 'resourceClass': 'storage', 'resourceIds': ['task-one']}]
        for row in (self.parent, self.row):
            row['facts']['policy']['decisions'].append({'access': {'action': 'inspect', 'resourceClass': 'outcome', 'resourceId': 'task-one'}, 'outcome': 'allow'})
            row['facts']['domainBindings'].append({'id': 'messages-outcome', 'contractId': 'capability-outcome-query', 'action': 'inspect', 'resourceClass': 'outcome', 'resourceIds': ['task-one']})
        return initial

    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        self.outcome_subject = 'amx.v1.h.hub-one.o.org-one.p.' + (self.scope['projectId'] or '_') + '.w._.capability.outcome-owner.command'
        policies['storage']['subscribe']['allow'].append(self.outcome_subject)
        policies['host']['publish']['allow'].append(self.outcome_subject)

    async def start_receiver(self):
        if not hasattr(self, 'store'):
            self.store = Store(str(self.directory / 'hub.db'))
            async def db(function, *args, **kwargs):
                return function(*args, **kwargs)
            self.domain = SimpleNamespace(me='nick', node='mac', store=self.store, db=db, policy=policy(),
                session=FederationSession(), presence={}, fcfg={'primary': True}, kick=lambda: None)
            for name in ('sender_of', 'resolve_repo', 'address_of', 'stage', 'publish'):
                setattr(self.domain, name, getattr(Federation, name).__get__(self.domain))
        self.resource = self.storage_resource()
        self.receiver = CapabilityReplyService(self.identity.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id=self.service_id,
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage)
        await self.receiver.start()
        outcome = CapabilityReplyService(self.identity.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='outcome-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.storage)
        self.extra_receivers = [outcome]
        await outcome.start()

    def storage_resource(self):
        binding = OwnerBinding('hub-one', 'federation-messages', 'task-one', 'message-channel', canonical_bytes(self.scope))
        return MessageStorageResource(binding, LocalMessages(self.domain), FederationPublisher(self.domain),
            repository=getattr(self, 'message_repository', 'falcon'), peer='alice',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')

    async def cleanup(self):
        succeeded = self.success
        self.success = False
        await super().cleanup()
        if hasattr(self, 'store'):
            self.store.db.close()
        if succeeded and not self.keep_directory:
            shutil.rmtree(self.directory)

    def storage_value(self, command):
        outgoing = command == 'publish'
        env = envelope.make('message', 'nick' if outgoing else 'alice', 'mac' if outgoing else 'other',
            self.resource.repository_id, 'alice' if outgoing else 'nick',
            {'kind': 'note', 'body': 'Original native message é', 'sender': {'operator': True}, 'target': None})
        return {'formatVersion': 1, 'command': command, 'envelope': env}

    async def native_message(self, command):
        outgoing = command == 'publish'
        value = self.storage_value(command)
        env = value['envelope']
        inner = await self.admit(self.read_contract, {'resourceRef': ref('task-one'), 'input': {'value': value}})
        self.write_private('host-signing.seed', HOST_SEED, raw=True)
        self.write_private('original-envelope.json', inner, raw=True)
        snapshot = await self.identity.ledger.current()
        metadata = await self.admin.request('$JS.API.STREAM.INFO.IDENTITY', b'{}', timeout=2)
        ready = {'serverUrl': self.broker.url, 'authoritySubject': self.identity_subject,
            'capabilitySubject': self.read_subject, 'credentialsFile': str(self.credentials['host']),
            'caFile': str(self.ca_file), 'tlsName': self.server_name, 'leafCertificateSha256': self.leaf_digest,
            'accountPublicKey': self.account_public_key, 'replyPrefix': self.inbox_prefixes['host'],
            'publishSubjects': [self.identity_subject, self.read_subject,
                '$JS.API.STREAM.INFO.IDENTITY', '$JS.API.STREAM.MSG.GET.IDENTITY'],
            'hostSigningSeedFile': str(self.directory / 'host-signing.seed'),
            'originalEnvelopeFile': str(self.directory / 'original-envelope.json'),
            'enrollment': {'profileId': 'profile-one', 'hubId': 'hub-one', 'authorityId': 'authority-one',
                'organizationId': 'org-one', 'stream': 'IDENTITY', 'domain': '',
                'streamCreated': strict_loads(metadata.data)['created'], 'minimumSequence': snapshot.sequence,
                'maxBytes': self.policy.max_bytes, 'replicas': 1, 'hostTransportRef': ref('host-transport'),
                'hostIdentityRef': ref('host'), 'issuerRef': ref('issuer'), 'issuerIdentityRef': ref('service'),
                'issuerInstanceId': 'ingress-one'},
            'service': {'profileId': 'profile-one', 'hubId': 'hub-one', 'serviceId': self.service_id,
                'serviceInstanceId': 'ingress-one', 'serviceIdentityRef': ref('service'), 'signingKeyRef': ref('issuer')},
            'bindingId': 'messages-write', 'resourceRef': ref('task-one'), 'resourceDigest': '',
            'requestContractId': self.read_contract, 'replyContractId': 'capability-storage-write-reply',
            'requestInput': {'value': value}, 'replyPayloadDigest': '', 'revoked': False}
        ready.update(outcomeSubject=self.outcome_subject,
            outcomeService={**ready['service'], 'serviceId': 'outcome-owner'})
        ready['publishSubjects'].append(self.outcome_subject)
        self.write_private('fixture-ready.json', ready)
        self.assertEqual(await self.wait_handoff('go-result.json', lambda v: v.get('phase') == 'read-complete'),
            {'phase': 'read-complete'})
        table = 'fed_outbox' if outgoing else 'messages'
        rows = self.store.q('SELECT * FROM ' + table)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        if outgoing:
            self.assertEqual(row['msg_id'], env['id'])
            self.assertEqual(strict_loads(row['payload']), env)
            self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')), 1)
        else:
            self.assertEqual(row['idem_key'], 'fed:' + env['id'])
            self.assertEqual(self.store.q1('SELECT * FROM deliveries')['message_id'], row['id'])
        self.assertTrue((self.directory / 'storage-mutation.json').is_file())
        await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one', 'targetRef': ref('parent-plugin')})
        ready['revoked'] = True
        self.write_private('fixture-ready.json', ready)
        self.assertEqual(await self.wait_handoff('go-result.json', lambda v: v.get('phase') == 'complete'),
            {'phase': 'complete', 'read': True, 'revocation': True, 'cleanup': True})
        self.assertEqual(await asyncio.wait_for(asyncio.shield(self.go_wait), 3), 0)
        self.assertEqual(len(self.store.q('SELECT * FROM ' + table)), 1)
        self.success = True


class LiveMessagesTests(MessageLiveFixture, unittest.IsolatedAsyncioTestCase):
    async def test_native_post_keeps_original_transaction_and_replay(self):
        await self.native_message('post')

    async def test_native_publish_keeps_original_outbox_and_replay(self):
        await self.native_message('publish')


class LiveOperatorMessagesTests(LiveMessagesTests):
    message_repository = None
    native_scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
