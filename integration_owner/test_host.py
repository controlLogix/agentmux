"""Actual integration host composition with offline broker and connection controls.

Blocking helpers run inline here. This does not qualify native thread, TLS, NATS
credential traffic or provider-account behavior.
"""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import canonical_bytes, strict_loads
from identity import test_application_service_selection as selection_support
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import LedgerAuthorityReader
from integration_owner import test_admission as admission_support
from integration_owner import test_service as service_support
from integration_owner.credentials import pin_atlassian_config
from integration_owner.enrollment import enrollment_bytes
from integration_owner.service import verify_receipt
from state_owner.ledger import OwnerLedger, owner_subject
from state_owner.test_ledger import FakeJetStream
from taskmgmt.test_atlassian_safety import CLOUD

# The existing selection test adds the approved dashboard module root.
from application_service_host import ApplicationServiceHost
from test_application_service_host import JetStream


class HostTests(unittest.IsolatedAsyncioTestCase):
    request = service_support.ServiceTests.request
    resign = admission_support.AdmissionTests.resign

    def setUp(self):
        admission_support.AdmissionTests.setUp(self)
        selection_support.ServiceSelectionTests.setUp(self)
        selection_support.ServiceSelectionTests.add_integration(self, provider='jira')
        selected = self.value['integration']
        selected['originalOperationId'] = 'operation-one'
        selected['ledger']['entityId'] = self.binding.entity_id
        selected['credentialRef'] = copy.deepcopy(self.envelope['payload']['credentialRef'])
        config = self.root / 'atlassian.json'
        config.write_bytes(canonical_bytes(CLOUD))
        config.chmod(0o600)
        pin = pin_atlassian_config(selected['credentialRef'], provider='jira', config_path=config,
            site_url=CLOUD['base_url'], config_version=selected['credentialRef']['revision'])
        self.enrollment = self.root / 'provider-pin.json'
        raw = enrollment_bytes(pin)
        self.enrollment.write_bytes(raw)
        self.enrollment.chmod(0o600)
        import hashlib
        selected['credentialEnrollment'] = {'path': str(self.enrollment), 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest()}
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        identity_binding = self.selection.binding('identity')
        identity_policy = self.selection.retention('identity')
        identity_js = FakeJetStream(identity_policy)
        identity_js.created = self.selection.stream_identity('identity').created
        identity_js.config = identity_policy.stream_config(stream='OWNER', subject=owner_subject(identity_binding))
        self.record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        self.record['operation'].update(expectedVersion=0, scope=strict_loads(identity_binding.scope))
        issuer = self.record['state']['issuers'][0]
        issuer.update(ref=selected['issuer']['issuerRef'], publicKey=selected['issuer']['publicKey'])
        self.record['state']['transports'][0]['issuerRef'] = issuer['ref']
        identity_js.messages = [SimpleNamespace(subject=owner_subject(identity_binding), seq=1, data=canonical_bytes(self.record))]
        identity_ledger = OwnerLedger(identity_js, stream='OWNER', subject=owner_subject(identity_binding),
            binding=identity_binding, retention=identity_policy, stream_identity=self.selection.stream_identity('identity'))
        self.reader = LedgerAuthorityReader(identity_ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        policy = self.selection.retention('integration')
        self.effect_js = JetStream(policy)
        self.effect_js.created = self.selection.stream_identity('integration').created
        self.effect_js.config = policy.stream_config(stream=selected['ledger']['stream'], subject=owner_subject(self.binding))
        self.effect_js.object_store = AsyncMock(return_value=object())
        self.subscription = SimpleNamespace(drain=AsyncMock())
        self.connection = SimpleNamespace(jetstream=lambda **kwargs: self.effect_js,
            subscribe=AsyncMock(return_value=self.subscription), flush=AsyncMock(), publish=AsyncMock())

    async def asyncSetUp(self):
        async def inline(function, *args):
            return function(*args)
        self.inline_patch = patch('application_service_host._joined', new=inline)
        self.inline_patch.start()
        self.addCleanup(self.inline_patch.stop)
        self.host = ApplicationServiceHost(self.selection)
        self.host._identity = SimpleNamespace(reader=self.reader)
        self.host._connect = AsyncMock(return_value=self.connection)
        # Only the integration branch is under test; no identity service lifetime
        # or connection is created by this fixture.
        self.addAsyncCleanup(self.close_owned)

    async def close_owned(self):
        for service in reversed(self.host._services):
            await service.close()
        for history in self.host._histories:
            history.close()

    async def test_host_composes_real_service_with_restored_credentials_and_signed_intent(self):
        await self.host._start_integration()
        self.host._connect.assert_awaited_once_with('integration')
        service = self.host._integration
        self.assertIs(service.owner._authority, self.reader)
        self.assertIsNotNone(service.owner._worker)
        self.assertTrue(service.ledger.completion_budget_required)
        self.assertEqual(service.subject, 'amx.v1.h.hub-one.o.org-one.integrations.' + self.binding.entity_id + '.command')
        request = self.request()
        response = await service.handle(request)
        selected = self.value['integration']
        receipt = verify_receipt(response, request, public_key=selected['issuer']['publicKey'], issuer_ref=selected['issuer']['issuerRef'])
        self.assertEqual(receipt['phase'], 'intent-committed')
        self.assertEqual(len(self.effect_js.messages), 1)
        self.assertEqual(service.owner._worker._tasks, {})

    async def test_changed_durable_enrollment_refuses_before_opening_connection(self):
        self.enrollment.write_bytes(self.enrollment.read_bytes() + b' ')
        from agentmux_contracts import ContractError
        with self.assertRaises(ContractError):
            await self.host._start_integration()
        self.host._connect.assert_not_awaited()
        self.assertEqual(self.host._services, [])
        self.assertEqual(self.host._histories, [])
