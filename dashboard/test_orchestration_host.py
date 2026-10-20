"""Selected orchestration uses the original application host lifetime."""
import asyncio
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, sign_claims
from identity.test_authority import SEED
from orchestration_owner.client import verify_receipt
from application_service_host import ApplicationServiceHost, ApplicationServiceFailure
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_application_service_selection import ServiceSelectionTests, ref
from orchestration_owner.service import OrchestrationCommandService
from state_owner.ledger import owner_subject
from test_application_service_host import HostComposition, Client, JetStream, routed_credential


class OrchestrationHostTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        HostComposition.setUp(self)
        ServiceSelectionTests.add_orchestration(self)
        selected = self.value['orchestration']
        provisional = ApplicationServiceSelection(canonical_bytes(self.value))
        raw = routed_credential(provisional.service_policy_inputs('orchestration'), 7)
        Path(selected['credentials']['path']).write_bytes(raw)
        Path(selected['credentials']['path']).chmod(0o600)
        selected['credentials']['sha256'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
        key = nkeys.from_seed(nkeys.encode_seed(bytes([7]) * 32, nkeys.PREFIX_BYTE_USER))
        try:
            selected['credentials']['userPublicKey'] = key.public_key.decode()
        finally:
            key.wipe()
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        js = JetStream(self.selection.retention('orchestration'))
        js.config = self.selection.retention('orchestration').stream_config(
            stream=selected['ledger']['stream'],
            subject=owner_subject(self.selection.binding('orchestration')))
        self.clients.append(Client(js))
        record = strict_loads(self.clients[0].js.messages[0].data)
        state = record['state']
        actor = selected['serviceIdentityRef']
        state['identities'].append(dict(ref=actor, kind='service', status='active',
            principalId='orchestration-service', externalIdentity=None))
        state['issuers'].append(dict(ref=selected['issuer']['issuerRef'], identityRef=actor,
            status='active', instanceId='instance-one',
            publicKey=selected['issuer']['publicKey'],
            issuedAt=self.issuer_start, expiresAt=self.issuer_end))
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('orchestration-member'), identityRef=actor, scope=selected['scope'])
        state['memberships'].append(member)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=selected['phaseAuthority']['transportRef'], identityRef=actor,
            issuerRef=self.value['identity']['issuer']['issuerRef'],
            publicKey=selected['phaseAuthority']['publicKey'],
            issuedAt=self.issuer_start, expiresAt=self.issuer_end)
        state['transports'].append(transport)
        for contract, reference in selected['phaseAuthority']['grants'].items():
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=reference, callerRef=actor, actorRef=actor,
                contractId=contract, resourceId=selected['resourceRef']['id'],
                scope=selected['scope'], definitionTarget=None,
                issuedAt=self.issuer_start, expiresAt=self.issuer_end)
            state['grants'].append(grant)
        self.record = record
        self.save_authority()

    def save_authority(self):
        self.clients[0].js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        self.host = ApplicationServiceHost(self.selection, browser_port=0)
        self.addAsyncCleanup(self.host.close)

    async def start(self):
        with patch('application_service_host.new_client', side_effect=self.clients):
            await self.host.start()

    async def test_selected_owner_starts_without_unused_checkpoint(self):
        await self.start()
        service = self.host._orchestration
        self.assertIsInstance(service, OrchestrationCommandService)
        self.host.check_health()
        ledger = service.owner._journal._ledger
        self.assertIs(service.owner._journal._authority, self.host._identity.reader)
        self.assertEqual(ledger._binding, self.selection.binding('orchestration'))
        self.assertEqual(ledger._history.source_identity,
                         self.selection.stream_identity('orchestration'))
        self.assertEqual(service._seed, self.selection.load_signing_seed('orchestration'))
        self.assertNotEqual(service._seed, self.selection.load_orchestration_phase_seed())
        self.assertNotIn('orchestration', self.host._checkpoints)
        self.assertFalse(Path(self.value['orchestration']['ledger']['checkpoint']['path']).exists())
        await self.host.close()
        self.assertTrue(ledger._history._closed)
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_absent_selection_keeps_owner_unavailable(self):
        self.value.pop('orchestration')
        await self.host.close()
        self.host = ApplicationServiceHost(
            ApplicationServiceSelection(canonical_bytes(self.value)), browser_port=0)
        self.addAsyncCleanup(self.host.close)
        await self.start()
        self.assertIsNone(self.host._orchestration)
        self.host.check_health()
        self.assertFalse(self.clients[-1].is_connected)

    async def test_selected_factory_accepts_identity_signed_caller_and_signs_receipt(self):
        state = self.record['state']
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('orchestration-query-transport'),
            issuerRef=self.value['identity']['issuer']['issuerRef'])
        state['transports'].append(transport)
        grant = copy.deepcopy(state['grants'][0])
        grant.update(ref=ref('orchestration-query-grant'),
            contractId='orchestration-outcome-query', definitionTarget=None,
            resourceId=self.value['orchestration']['resourceRef']['id'],
            scope=self.value['orchestration']['scope'])
        state['grants'].append(grant)
        self.save_authority()
        await self.start()
        service = self.host._orchestration
        self.assertIs(service.ingress, self.host._identity.ingress)
        claims = strict_loads(HostComposition.request(self))['claims']
        claims.update(transportRef=transport['ref'], grantRef=grant['ref'],
            contractId='orchestration-outcome-query',
            payload={'resourceRef': self.value['orchestration']['resourceRef'],
                'originalOperationId': 'absent-original',
                'originalPayloadDigest': 'sha256:' + '0' * 64})
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        admitted = await service.ingress.admit(request,
            cancellation_ref=ref(claims['operationId']))
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision)
        response = await service.handle(request)
        issuer = self.value['orchestration']['issuer']
        receipt = verify_receipt(response, request, public_key=issuer['publicKey'],
            issuer_ref=issuer['issuerRef'])
        self.assertEqual(receipt['phase'], 'absent')
        self.assertEqual(len(self.clients[-1].js.messages), 0)

    async def test_revoked_phase_grant_refuses_before_construction(self):
        self.record['state']['grants'][-1]['status'] = 'revoked'
        self.save_authority()
        with self.assertRaises(ApplicationServiceFailure):
            await self.start()
        self.assertIsNone(self.host._orchestration)
        self.assertFalse(self.clients[-1].is_connected)

    async def test_expired_phase_transport_refuses_before_construction(self):
        self.record['state']['transports'][-1]['expiresAt'] = self.issuer_start
        self.save_authority()
        with self.assertRaises(ApplicationServiceFailure):
            await self.start()
        self.assertIsNone(self.host._orchestration)

    async def test_changed_phase_key_refuses_before_construction(self):
        Path(self.value['orchestration']['phaseAuthority']['keyFile']['path']).write_bytes(
            bytes([30]) * 32)
        with self.assertRaises(ApplicationServiceFailure):
            await self.start()
        self.assertIsNone(self.host._orchestration)

    async def test_start_failure_retains_constructed_owner_until_cleanup(self):
        async def fail(service):
            raise ContractError('orchestration_service_unavailable')
        with patch.object(OrchestrationCommandService, 'start', fail):
            with self.assertRaises(ApplicationServiceFailure):
                await self.start()
        service = self.host._orchestration
        self.assertIn(service, self.host._services)
        self.assertFalse(self.host._ready)
        self.assertFalse(service.owner._journal._ledger._history._closed)
        await self.host.close()
        self.assertTrue(service.owner._journal._ledger._history._closed)

    async def test_cancelled_start_waiter_keeps_original_start_until_close(self):
        entered = asyncio.Event()
        async def waiting(service):
            entered.set()
            await asyncio.Event().wait()
        with patch.object(OrchestrationCommandService, 'start', waiting):
            starting = asyncio.create_task(self.start())
            await entered.wait()
            service = self.host._orchestration
            starting.cancel()
            with self.assertRaises(ApplicationServiceFailure):
                await starting
            self.assertFalse(self.host._startup.done())
            self.assertIs(self.host._orchestration, service)
            await self.host.close()
        self.assertTrue(self.host._startup.done())
        self.assertTrue(service.owner._journal._ledger._history._closed)

    async def test_authority_rechecked_after_history_preparation(self):
        original = OrchestrationCommandService.start
        async def revoke(service):
            await original(service)
            # The next real current-authority read observes a revoked phase
            # grant; an earlier startup admission cannot publish readiness.
            snapshot = await self.host._identity.reader.current()
            record = strict_loads(snapshot.record)
            record['state']['grants'][-1]['status'] = 'revoked'
            from identity.authority import AuthoritySnapshot
            replacement = AuthoritySnapshot(canonical_bytes(record), snapshot.sequence)
            self.host._identity.reader.current = unittest.mock.AsyncMock(return_value=replacement)
            return service
        with patch.object(OrchestrationCommandService, 'start', revoke):
            with self.assertRaises(ApplicationServiceFailure):
                await self.start()
        self.assertFalse(self.host._ready)
        self.assertIsNotNone(self.host._orchestration)

    async def test_pending_close_retains_original_resources_and_joins_retry(self):
        await self.start()
        service = self.host._orchestration
        history = service.owner._journal._ledger._history
        release = asyncio.Event()
        original = asyncio.create_task(release.wait())
        service._active.add(original)
        try:
            with self.assertRaises(ApplicationServiceFailure):
                await self.host.close()
            self.assertIs(self.host._orchestration, service)
            self.assertIn(original, service._active)
            self.assertFalse(original.done())
            self.assertFalse(history._closed)
            self.assertTrue(all(client.is_connected for client in self.clients))
            with self.assertRaises(ContractError):
                self.host.check_health()
            release.set()
            await original
            await self.host.close()
            self.assertTrue(history._closed)
            self.assertTrue(all(not client.is_connected for client in self.clients))
        finally:
            release.set()
            await original

    async def test_owner_health_is_part_of_application_health(self):
        await self.start()
        self.host._orchestration.owner._worker._closed = True
        with self.assertRaises(ContractError):
            self.host.check_health()
