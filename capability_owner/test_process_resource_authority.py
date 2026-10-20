"""Current native authority must survive the public Process receiver boundary."""
import asyncio
from datetime import datetime, timezone
import hashlib

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.test_authority import ref
from .process_resource import ProcessResource
from .receiver import CapabilityReceiver
from .test_process_resource import ProcessResourceTests


class ProcessResourceAuthorityTests(ProcessResourceTests):
    def retained_fingerprint(self):
        # Report digests rather than private original envelopes or credentials.
        digest = lambda data: hashlib.sha256(data).hexdigest()
        ledgers = (self.execution_js, self.credential_js, self.task_js, self.plan_js)
        engine_methods = ('check_transport', 'check', 'find', 'inspect', '_run', 'exec_fixed')
        return (
            tuple(tuple(digest(item.data) for item in ledger.messages) for ledger in ledgers),
            digest(canonical_bytes(self.run)), tuple(self.commands),
            tuple(getattr(self.engine, name).await_count for name in engine_methods),
        )

    async def prepared_revocation(self, target, direct_refusal):
        case = await self.resource_case()
        decision = await self.resource.authorize(self.service.reader, case['raw'], case['wrapper'])
        self.assertEqual(decision.outcome, 'allowed')
        before = self.retained_fingerprint()
        receipt = await self.admin('identity-revoke', {
            'authorityId': 'authority-one', 'targetRef': target(case),
        })
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        with self.assertRaisesRegex(ContractError, '^' + direct_refusal + '$'):
            await self.resource.authorize(self.service.reader, case['raw'], case['wrapper'])
        with self.assertRaisesRegex(ContractError, '^capability_owner_unavailable$'):
            await self.receive(case['raw'], case['wrapper'])
        self.assertEqual(self.retained_fingerprint(), before)
        self.assertEqual(self.execution_js.messages, [])
        self.assertEqual(self.credential_js.messages, [])
        self.assertEqual(self.commands, [])

    async def test_prepared_wrapper_refuses_actual_business_grant_revocation(self):
        await self.prepared_revocation(
            lambda case: strict_loads(case['raw'])['operation']['grantRef'],
            'capability_service_not_authorized',
        )

    async def test_prepared_wrapper_refuses_actual_native_host_grant_revocation(self):
        await self.prepared_revocation(
            lambda case: ref('process-host-prepare'),
            'capability_service_native_unavailable',
        )

    async def test_prepared_wrapper_refuses_actual_native_instance_revocation(self):
        await self.prepared_revocation(
            lambda case: case['row']['ref'],
            'capability_service_native_unavailable',
        )

    async def test_signed_cross_run_cancel_preserves_original_start(self):
        case = await self.resource_case()
        accepted = await self.receive(case['raw'], case['wrapper'])
        self.assertEqual(accepted, {'receiptRef': self.run['runRef'], 'outcome': 'accepted'})
        first = hashlib.sha256(self.execution_js.messages[0].data).hexdigest()
        other_run = {**self.run['runRef'], 'id': self.run['runRef']['id'] + '-other'}
        raw, wrapper = await self.packet(case, 'capability-process-cancel', {
            'resourceRef': ref('executor'), 'input': {'runRef': other_run},
        }, 'cancel-other-run')
        self.assertEqual(strict_loads(raw)['payload']['input']['runRef'], other_run)
        decision = await self.resource.authorize(self.service.reader, raw, wrapper)
        self.assertEqual(decision.outcome, 'allowed')
        before = self.retained_fingerprint()
        with self.assertRaisesRegex(ContractError, '^capability_owner_unavailable$'):
            await self.receive(raw, wrapper)
        self.assertEqual(self.retained_fingerprint(), before)
        self.assertEqual(hashlib.sha256(self.execution_js.messages[0].data).hexdigest(), first)
        self.assertEqual(self.commands, [])

    async def test_wrong_selected_plugin_instance_or_package_refuses_before_owner(self):
        case = await self.resource_case()
        decision = await self.resource.authorize(self.service.reader, case['raw'], case['wrapper'])
        self.assertEqual(decision.outcome, 'allowed')
        before = self.retained_fingerprint()
        pins = {'plugin_identity': ref('plugin'), 'instance_id': 'plugin-one', 'package_id': 'test-plugin'}
        for field, value in (('plugin_identity', ref('another-plugin')),
                             ('instance_id', 'another-instance'), ('package_id', 'another-package')):
            with self.subTest(field=field):
                resource = ProcessResource(self.resource._admission, self.resource._inspection,
                    **{**pins, field: value})
                receiver = CapabilityReceiver(self.service.reader, hub_id='hub-one', resources=(resource,))
                self.addAsyncCleanup(resource.close)
                self.addAsyncCleanup(receiver.close)
                with self.assertRaisesRegex(ContractError, '^capability_access_refused$'):
                    await resource.authorize(self.service.reader, case['raw'], case['wrapper'])
                with self.assertRaisesRegex(ContractError, '^capability_access_refused$'):
                    await receiver.handle(case['raw'], service_request_bytes=case['wrapper'])
                self.assertEqual(self.retained_fingerprint(), before)
        self.assertEqual(self.execution_js.messages, [])
        self.assertEqual(self.credential_js.messages, [])
        self.assertEqual(self.commands, [])

    async def test_actual_default_wrapper_expiry_refuses_before_owner(self):
        case = await self.resource_case()
        claims = strict_loads(case['wrapper'])['claims']
        issued = datetime.fromisoformat(claims['issuedAt'])
        expires = datetime.fromisoformat(claims['validUntil'])
        self.assertGreater((expires - issued).total_seconds(), 0)
        self.assertLessEqual((expires - issued).total_seconds(), 5)
        decision = await self.resource.authorize(self.service.reader, case['raw'], case['wrapper'])
        self.assertEqual(decision.outcome, 'allowed')
        before = self.retained_fingerprint()
        await asyncio.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + 0.1)
        with self.assertRaisesRegex(ContractError, '^capability_service_expired$'):
            await self.resource.authorize(self.service.reader, case['raw'], case['wrapper'])
        with self.assertRaisesRegex(ContractError, '^capability_owner_unavailable$'):
            await self.receive(case['raw'], case['wrapper'])
        self.assertEqual(self.retained_fingerprint(), before)
        self.assertEqual(self.execution_js.messages, [])
        self.assertEqual(self.credential_js.messages, [])
        self.assertEqual(self.commands, [])


for _name in dir(ProcessResourceTests):
    if _name.startswith('test_') and _name not in vars(ProcessResourceAuthorityTests):
        setattr(ProcessResourceAuthorityTests, _name, None)
