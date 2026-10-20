"""Actual ordinary owner, retained offline broker and fixed real HTTPS consumer.

The separate live case qualifies these same components with real NATS/JWT/TLS.
These tests reuse the existing consumer fixture and actual identity owner reader.
"""
import asyncio
import copy
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from capability_owner import test_secret_consumer as consumer_fixture
from capability_owner.ordinary_secret import OrdinarySecretOwner
from capability_owner.secret_journal import (
    PHASE_CONTRACTS, SecretOperationJournal, SecretPhaseSigner, secret_use_identity)
from identity import test_ordinary_secret_service as ordinary_fixture
from identity import test_service as service_fixture
from identity.test_authority import ref, SEED
from native_security.ordinary_secret_custody import OrdinarySecretCustody
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED


class OrdinarySecretOwnerTests(unittest.IsolatedAsyncioTestCase):
    _authority_state = consumer_fixture.SecretConsumerTests._authority_state
    store = consumer_fixture.SecretConsumerTests.store
    new_consumer = consumer_fixture.SecretConsumerTests.new_consumer
    cleanup_owned = consumer_fixture.SecretConsumerTests.cleanup_owned
    resign = consumer_fixture.SecretConsumerTests.resign
    request = ordinary_fixture.OrdinarySecretServiceTests.request
    received = consumer_fixture.SecretConsumerTests.received

    def setUp(self):
        consumer_fixture.SecretConsumerTests.setUp(self)
        patch('native_security.ordinary_secret_custody.datetime', service_fixture._Clock).start()
        patch('capability_owner.secret_journal.datetime', service_fixture._Clock).start()
        patch('identity.authority._utc_now', return_value=service_fixture.NOW).start()
        state = self.record['state']
        state.pop('ordinarySecretReferences')
        organization = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        state['memberships'].append({'ref': ref('secret-admin-member'),
            'identityRef': ref('human'), 'scope': organization, 'status': 'active'})
        state['grants'][0].update(contractId='identity-ordinary-secret-set',
            resourceId='authority-one', scope=organization)
        grant = next(item for item in state['grants'] if item['ref'] == ref('ordinary-resolve-grant'))
        for name in PHASE_CONTRACTS:
            state['grants'].append({**copy.deepcopy(grant), 'ref': ref(name), 'contractId': name})
        self.store()
        self.root = Path(self.directory.name).resolve()
        self.root.chmod(0o700)
        self.custody = OrdinarySecretCustody(self.root, self.service.reader)
        self.addAsyncCleanup(self.custody.close)
        operation = self.outer['payload']['originalEnvelope']['operation']
        self.binding = OwnerBinding('hub-one', 'ordinary-secret-uses',
            secret_use_identity(operation['scope'], operation['operationId']),
            'effect', canonical_bytes(operation['scope']))
        self.journal_js = FakeJetStream(self.policy)
        self.journal_js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(self.binding))
        self.owners = []
        self.addAsyncCleanup(self.close_owners)

    async def close_owners(self):
        self.server.release.set()
        for owner in self.owners:
            await owner.close()

    def open_journal(self, *, enrollment=None):
        ledger = OwnerLedger(self.journal_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy,
            stream_identity=StreamIdentity(CREATED, 0), require_completion_budget=True)
        journal = SecretOperationJournal(ledger, self.service.reader,
            enrollment=enrollment or self.enrollment, observation_root=self.root)
        self.addAsyncCleanup(journal.close)
        return journal

    def signer(self, journal):
        return SecretPhaseSigner(journal, self.service.ingress,
            transport_ref=ref('custody-transport'),
            grants={name: ref(name) for name in PHASE_CONTRACTS}, signing_seed=bytes(reversed(SEED)))

    def open_owner(self, *, journal=None, custody=None, consumer=None):
        journal = journal or self.open_journal()
        owner = OrdinarySecretOwner(journal, self.signer(journal), custody or self.custody,
                                    consumer or self.consumer)
        self.owners.append(owner)
        return owner

    async def stage(self):
        raw = self.request()
        admitted = await self.service.ingress.admit(raw, cancellation_ref=ref('stage-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        await self.custody.provision(admitted.envelope, secret=consumer_fixture._TOKEN)
        await self.service.handle(raw)
        return canonical_bytes(self.outer)

    def revoke(self, name, *, collection='grants'):
        value = strict_loads(self.js.messages[-1].data)
        next(row for row in value['state'][collection] if row['ref']['id'] == name)['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(value)

    async def test_real_consumer_original_receipt_replay_and_retained_state(self):
        raw = await self.stage()
        owner = self.open_owner()
        result = await owner.use(raw)
        self.assertEqual(result['outcome'], 'accepted')
        self.assertEqual(set(result), {'receiptRef', 'outcome'})
        self.assertEqual(self.server.requests, [('GET', '/rest/api/3/myself', True)])
        self.assertEqual(await owner.use(raw), result)
        self.assertEqual(await owner.recover(raw), result)
        self.assertEqual(len(self.journal_js.messages), 3)
        group = await owner._journal.current()
        self.assertEqual(group['state']['phase'], 'finished')
        self.assertEqual(group['original'], self.outer['payload']['originalEnvelope'])
        public = b''.join(message.data for message in self.journal_js.messages)
        for secret in (consumer_fixture._TOKEN, self.enrollment.email.encode(),
                       self.enrollment.base_url.encode(), self.enrollment.expected_account.encode()):
            self.assertNotIn(secret, public)

    async def test_recovery_of_absent_original_never_creates_claim_or_http(self):
        raw = await self.stage()
        owner = self.open_owner()
        with self.assertRaisesRegex(ContractError, 'ordinary_secret_original_absent'):
            await owner.recover(raw)
        self.assertFalse(self.server.requests)
        self.assertFalse(self.journal_js.messages)

    async def test_fresh_operation_needs_a_different_preprovisioned_ledger(self):
        raw = await self.stage()
        owner = self.open_owner()
        first = await owner._journal.authorize(raw)
        original = strict_loads(first.original_operation)
        self.outer['payload']['originalEnvelope']['operation']['operationId'] = 'fresh-secret-use'
        self.resign()
        fresh = canonical_bytes(self.outer)
        resolution = await owner._journal._authority.resolve(fresh)
        operation = strict_loads(resolution.original_operation)
        self.assertNotEqual(operation['operationId'], original['operationId'])
        with self.assertRaisesRegex(ContractError, '^ordinary_secret_journal_access_refused$'):
            await owner._journal.authorize(fresh)
        binding = OwnerBinding('hub-one', 'ordinary-secret-uses',
            secret_use_identity(operation['scope'], operation['operationId']),
            'effect', canonical_bytes(operation['scope']))
        ledger = OwnerLedger(self.journal_js, stream='OWNER', subject=owner_subject(binding),
            binding=binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        with self.assertRaisesRegex(ContractError, '^owner_retention_unsafe$'):
            await ledger.current()
        self.assertFalse(self.server.requests)
        self.assertFalse(self.journal_js.messages)

    async def test_lost_intent_ack_does_not_dispatch_even_on_restart(self):
        raw = await self.stage()
        owner = self.open_owner()
        self.journal_js.lose_ack = True
        first = await owner.use(raw)
        self.assertEqual(first['outcome'], 'uncertain')
        self.assertEqual(len(self.journal_js.messages), 1)
        self.assertFalse(self.server.requests)
        await owner.close()
        custody = OrdinarySecretCustody(self.root, self.service.reader)
        replacement = self.open_owner(custody=custody, consumer=self.new_consumer())
        self.assertEqual(await replacement.use(raw), first)
        self.assertFalse(self.server.requests)

    async def test_lost_dispatch_ack_never_starts_http(self):
        raw = await self.stage()
        owner = self.open_owner()
        original = self.journal_js.publish
        async def publish(*args, **kwargs):
            if len(self.journal_js.messages) == 1:
                self.journal_js.lose_ack = True
            return await original(*args, **kwargs)
        with patch.object(self.journal_js, 'publish', publish):
            result = await owner.use(raw)
        self.assertEqual(result['outcome'], 'uncertain')
        self.assertEqual(len(self.journal_js.messages), 2)
        self.assertFalse(self.server.requests)
        self.assertEqual(await owner.use(raw), result)

    async def test_lost_completion_ack_recovers_original_without_another_http(self):
        raw = await self.stage()
        owner = self.open_owner()
        original = self.journal_js.publish
        async def publish(*args, **kwargs):
            if len(self.journal_js.messages) == 2:
                self.journal_js.lose_ack = True
            return await original(*args, **kwargs)
        with patch.object(self.journal_js, 'publish', publish):
            result = await owner.use(raw)
        self.assertEqual(result['outcome'], 'accepted')
        self.assertEqual(await owner.recover(raw), result)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(len(self.journal_js.messages), 3)

    async def test_failed_completion_retains_private_observation_across_restart(self):
        raw = await self.stage()
        owner = self.open_owner()
        original = self.journal_js.publish
        async def publish(*args, **kwargs):
            if len(self.journal_js.messages) == 2:
                raise OSError('private write failed')
            return await original(*args, **kwargs)
        with patch.object(self.journal_js, 'publish', publish):
            with self.assertRaises(ContractError): await owner.use(raw)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(len(self.journal_js.messages), 2)
        group = await owner._journal.current()
        self.assertEqual((await owner._journal.load_observation(group)).status, 'accepted')
        await owner.close()
        custody = OrdinarySecretCustody(self.root, self.service.reader)
        replacement = self.open_owner(custody=custody, consumer=self.new_consumer())
        result = await replacement.recover(raw)
        self.assertEqual(result['outcome'], 'accepted')
        self.assertEqual(len(self.journal_js.messages), 3)
        self.assertEqual(len(self.server.requests), 1)

    async def test_cancel_observer_does_not_cancel_private_use_and_close_joins(self):
        raw = await self.stage()
        owner = self.open_owner()
        self.server.hold = True
        caller = asyncio.create_task(owner.use(raw))
        try:
            await self.received()
            caller.cancel()
            with self.assertRaises(asyncio.CancelledError): await caller
            with self.assertRaisesRegex(ContractError, 'ordinary_secret_owner_cleanup_incomplete'):
                await owner.close(timeout=0.02)
            self.assertIsNotNone(self.custody._store._fd)
            self.assertFalse(owner._closing.done())
        finally:
            self.server.release.set()
            await owner.close()
        self.assertIsNone(self.custody._store._fd)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(len(self.journal_js.messages), 3)

    async def test_revocation_after_effect_retains_outcome_but_refuses_receipt(self):
        raw = await self.stage()
        owner = self.open_owner()
        self.server.hold = True
        caller = asyncio.create_task(owner.use(raw))
        try:
            await self.received()
            self.revoke('ordinary-use-grant')
        finally:
            self.server.release.set()
        with self.assertRaises(ContractError): await caller
        self.assertEqual((await owner._journal.current())['state']['outcome'], 'accepted')
        self.assertEqual(len(self.server.requests), 1)
        with self.assertRaises(ContractError): await owner.recover(raw)

    async def test_changed_consumer_selection_cannot_recover_another_enrollment(self):
        raw = await self.stage()
        owner = self.open_owner()
        await owner.use(raw)
        changed = self.open_journal(enrollment=replace(self.enrollment, expected_account='different-account'))
        with self.assertRaises(ContractError): await changed.current()
        self.assertEqual(len(self.server.requests), 1)


if __name__ == '__main__':
    unittest.main()
