"""Offline receiving preflight with real authority and ledger readers."""
import asyncio
import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from identity.authority import AuthorityReader
from identity.test_authority import fixture, NOW, SEED
from nats.js.errors import NotFoundError
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from definition_service import DefinitionScope, DefinitionService
from definition_admission import DefinitionAdmission


class DefinitionAdmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.record, self.env = fixture()
        self.env.update(contractId='definition-save', destinationServiceId='definition-owner')
        self.env['payload'] = {'definitionId': 'definition-one', 'scope': 'repo', 'name': 'worker',
                               'expectedChecksum': None, 'definition': {'description': 'Review changes'}}
        self.env['operation'].update(expectedVersion=0, payloadDigest=payload_digest(self.env['payload']))
        self.record['state']['grants'][0].update(contractId='definition-save', resourceId='definition-one',
                                                definitionTarget={'scope': 'repo', 'name': 'worker'})
        self.resign()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.service = DefinitionService(DefinitionScope(root / 'repo', root / 'home', root / 'global',
                                                        self.env['operation']['scope']['projectId']))
        self.binding = OwnerBinding('hub-one', 'definitions', 'catalog-one', 'definition-catalog',
                                    canonical_bytes(self.env['operation']['scope']))
        self.authority_js = SimpleNamespace(get_msg=AsyncMock(side_effect=self.authority_message))
        self.authority = AuthorityReader(self.authority_js, stream='AUTH', subject='authority.one',
                                         hub_id='hub-one', entity_id='authority-one', profile_id='profile-one',
                                         organization_id=self.env['operation']['scope']['organizationId'])
        self.retention = Retention(1_048_576, 131_072)
        self.stored = None
        self.owner_js = SimpleNamespace(stream_info=AsyncMock(side_effect=self.stream_info),
                                        get_msg=AsyncMock(side_effect=self.owner_message), publish=AsyncMock())
        self.ledger = OwnerLedger(self.owner_js, stream='DEFINITIONS', subject=owner_subject(self.binding),
                                   binding=self.binding, retention=self.retention,
                                   stream_identity=StreamIdentity(NOW, 0))
        self.admission = DefinitionAdmission(self.service, self.authority, self.ledger, self.binding)
        self.clock = patch('identity.authority._utc_now', return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def resign(self):
        claims = self.env['ingressAttestation']['claims']
        claims['operation'] = copy.deepcopy(self.env['operation'])
        claims['contractId'] = self.env['contractId']
        claims['audience']['serviceId'] = self.env['destinationServiceId']
        self.env['ingressAttestation']['signature'] = sign_claims(claims, SEED)

    async def authority_message(self, *args, **kwargs):
        return SimpleNamespace(subject='authority.one', seq=17, data=canonical_bytes(self.record))

    async def stream_info(self, *args):
        count = int(self.stored is not None)
        return SimpleNamespace(config=self.retention.stream_config(stream='DEFINITIONS', subject=owner_subject(self.binding)),
                               created=NOW,
                               state=SimpleNamespace(last_seq=count, messages=count, first_seq=count, num_deleted=0, bytes=count * 4096))

    async def owner_message(self, *args, **kwargs):
        if self.stored is None:
            raise NotFoundError()
        return SimpleNamespace(subject=owner_subject(self.binding), seq=1, data=canonical_bytes(self.stored))

    async def test_real_readers_prepare_without_writes_and_verified_actor(self):
        result = await self.admission.prepare(canonical_bytes(self.env))
        self.assertEqual(result.decision.outcome, 'allowed')
        self.assertEqual(result.audit_actor, 'user-one')
        self.assertEqual(result.preparation.change.candidate.version, 1)
        self.assertIsNotNone(result.authority_ref)
        self.assertFalse(self.service.scope.project_root.exists())
        self.owner_js.publish.assert_not_awaited()
        self.assertEqual(self.authority_js.get_msg.await_count, 2)
        self.assertNotIn('user-one', repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.preparation = None

    async def test_denied_and_review_required_do_not_plan_or_read_catalog(self):
        for decision in ('denied', 'review-required'):
            self.record['state']['grants'][0]['decision'] = decision
            result = await self.admission.prepare(canonical_bytes(self.env))
            self.assertEqual(result.decision.outcome, decision)
            self.assertIsNone(result.preparation)
        self.owner_js.get_msg.assert_not_awaited()
        self.owner_js.publish.assert_not_awaited()

    async def test_revocation_on_second_authority_read_stops_preflight(self):
        calls = 0
        async def read(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.record['state']['grants'][0]['status'] = 'revoked'
            return await self.authority_message()
        self.authority_js.get_msg.side_effect = read
        result = await self.admission.prepare(canonical_bytes(self.env))
        self.assertEqual(result.decision.outcome, 'denied')
        self.assertIsNone(result.preparation)
        self.assertFalse(self.service.scope.project_root.exists())

    async def test_retained_outcome_is_returned_before_file_preflight(self):
        self.stored = {**self.record, 'entityId': 'catalog-one', 'entityKind': 'definition-catalog',
                       'ownerDomain': 'definitions', 'entityVersion': 1, 'previousRevision': 0,
                       'operation': copy.deepcopy(self.env['operation']), 'effects': [], 'artifacts': [],
                       'state': {'schemaVersion': '1.0.0', 'scope': self.env['operation']['scope'], 'definitions': []}}
        with patch('definition_admission.prepare_catalog_change', side_effect=AssertionError('must not prepare')):
            result = await self.admission.prepare(canonical_bytes(self.env))
        self.assertTrue(result.outcome.replayed)
        self.assertIsNone(result.preparation)
        self.owner_js.publish.assert_not_awaited()

    async def test_revocation_during_replay_read_hides_retained_outcome(self):
        self.stored = {**self.record, 'entityId': 'catalog-one', 'entityKind': 'definition-catalog',
                       'ownerDomain': 'definitions', 'entityVersion': 1, 'previousRevision': 0,
                       'operation': copy.deepcopy(self.env['operation']), 'effects': [], 'artifacts': [],
                       'state': {'schemaVersion': '1.0.0', 'scope': self.env['operation']['scope'], 'definitions': []}}
        async def revoke(*args, **kwargs):
            self.record['state']['grants'][0]['status'] = 'revoked'
            return await self.owner_message(*args, **kwargs)
        self.owner_js.get_msg.side_effect = revoke
        result = await self.admission.prepare(canonical_bytes(self.env))
        self.assertEqual(result.decision.outcome, 'denied')
        self.assertIsNone(result.outcome)
        self.assertIsNone(result.preparation)

    async def test_scope_mismatch_and_payload_tampering_fail_closed(self):
        self.env['operation']['scope']['workspaceId'] = 'other-workspace'
        for collection in ('memberships', 'grants'):
            self.record['state'][collection][0]['scope'] = copy.deepcopy(self.env['operation']['scope'])
        self.resign()
        with self.assertRaisesRegex(ContractError, 'definition_admission_scope'):
            await self.admission.prepare(canonical_bytes(self.env))
        self.env['payload']['definition']['description'] = 'Changed after signing'
        with self.assertRaises(ContractError):
            await self.admission.prepare(canonical_bytes(self.env))
        self.owner_js.get_msg.assert_not_awaited()

    async def test_cancelled_preflight_joins_exact_worker_and_consumes_error(self):
        started, release = asyncio.Event(), threading.Event()
        loop = asyncio.get_running_loop()
        def worker(*args):
            loop.call_soon_threadsafe(started.set)
            release.wait()
            raise RuntimeError('private preparation failure')
        try:
            with patch('definition_admission.prepare_catalog_change', side_effect=worker) as prepare:
                caller = asyncio.create_task(self.admission.prepare(canonical_bytes(self.env)))
                began = asyncio.create_task(started.wait())
                await asyncio.wait({caller, began}, return_when=asyncio.FIRST_COMPLETED)
                if caller.done():
                    began.cancel()
                    await asyncio.gather(began, return_exceptions=True)
                    await caller
                    self.fail('preflight ended before worker started')
                await began
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
                self.assertTrue(self.admission._lock.locked())
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await caller
                self.assertFalse(self.admission._lock.locked())
                prepare.assert_called_once()
        finally:
            release.set()

    def test_unbound_readers_and_arbitrary_authority_callbacks_are_rejected(self):
        other = OwnerBinding('hub-one', 'definitions', 'other-catalog', 'definition-catalog', self.binding.scope)
        with self.assertRaisesRegex(ContractError, 'definition_admission_configuration'):
            DefinitionAdmission(self.service, self.authority, self.ledger, other)
        with self.assertRaisesRegex(ContractError, 'definition_admission_configuration'):
            DefinitionAdmission(self.service, SimpleNamespace(evaluate=AsyncMock()), self.ledger, self.binding)

    async def test_operation_id_reuse_with_changed_signed_version_is_rejected(self):
        self.stored = {**self.record, 'entityId': 'catalog-one', 'entityKind': 'definition-catalog',
                       'ownerDomain': 'definitions', 'entityVersion': 1, 'previousRevision': 0,
                       'operation': copy.deepcopy(self.env['operation']), 'effects': [], 'artifacts': [],
                       'state': {'schemaVersion': '1.0.0', 'scope': self.env['operation']['scope'], 'definitions': []}}
        self.env['operation']['expectedVersion'] = 1
        self.resign()
        with self.assertRaisesRegex(ContractError, 'owner_operation_conflict'):
            await self.admission.prepare(canonical_bytes(self.env))
        self.owner_js.publish.assert_not_awaited()

    async def test_replay_rejects_malformed_catalog_state(self):
        self.stored = {**self.record, 'entityId': 'catalog-one', 'entityKind': 'definition-catalog',
                       'ownerDomain': 'definitions', 'entityVersion': 1, 'previousRevision': 0,
                       'operation': copy.deepcopy(self.env['operation']), 'effects': [], 'artifacts': [],
                       'state': {'arbitrary': 'not a catalog'}}
        with self.assertRaises(ContractError):
            await self.admission.prepare(canonical_bytes(self.env))
        self.owner_js.publish.assert_not_awaited()
