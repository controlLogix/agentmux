"""Ordinary configuration ingress preserves current grants and receiver bindings."""
import base64
import copy
import unittest

from agentmux_contracts import ContractError, strict_loads
from identity import test_ingress
from identity.test_authority import ref
from identity.test_native_bridge import native_row


class ConfigurationIngressTests(unittest.IsolatedAsyncioTestCase):
    setUp = test_ingress.IngressTests.setUp
    admit = test_ingress.IngressTests.admit

    def select(self, method):
        contract = 'configuration-' + method
        self.record['state']['grants'][0].update(contractId=contract, resourceId='configuration-one')
        payload = {'configurationRef':ref('configuration-one'), 'owner':native_row()['owner']}
        if method == 'set':
            payload.update(schemaRef='config.json', configurationBytes=base64.b64encode(b'{"private":1}').decode(),
                           secretReferences=[])
        elif method == 'watch':
            payload['afterRevision'] = 0
        self.claims.update(contractId=contract, payload=payload)

    async def test_exact_routes_preserve_operation_payload_and_authorization_scope(self):
        for method in ('read', 'set', 'watch'):
            self.select(method)
            admitted = await self.admit()
            self.assertEqual(admitted.decision.outcome, 'allowed')
            envelope = strict_loads(admitted.envelope)
            self.assertEqual(envelope['destinationServiceId'], 'configuration-owner')
            self.assertEqual(envelope['payload'], self.claims['payload'])
            self.assertEqual(envelope['operation']['operationId'], self.claims['operationId'])
            self.assertEqual(envelope['operation']['scope'], self.record['state']['grants'][0]['scope'])

    async def test_revoked_missing_denied_and_unapproved_authority_never_dispatches(self):
        self.select('set')
        original = copy.deepcopy(self.record)
        for mutate in (lambda s:s['memberships'].clear(),
                       lambda s:s['grants'][0].update(status='revoked'),
                       lambda s:s['grants'][0].update(resourceId='other'),
                       lambda s:s['grants'][0].update(decision='denied'),
                       lambda s:s['grants'][0].update(decision='review-required')):
            self.record = copy.deepcopy(original)
            mutate(self.record['state'])
            try:
                admitted = await self.admit()
            except ContractError:
                continue
            self.assertIsNone(admitted.envelope)
            self.assertNotEqual(admitted.decision.outcome, 'allowed')

    async def test_owner_hub_revision_and_plugin_caller_refuse(self):
        self.select('set')
        for mutate in (lambda p:p['configurationRef'].update(ownerHubId='other'),
                       lambda p:p['configurationRef'].update(revision=2)):
            old = copy.deepcopy(self.claims['payload'])
            mutate(self.claims['payload'])
            result = await self.admit()
            self.assertIsNone(result.envelope)
            self.claims['payload'] = old
        # The identity is still enrolled, but this ordinary path cannot bypass
        # native plugin admission merely by obtaining a configuration grant.
        identity = next(i for i in self.record['state']['identities']
                        if i['ref'] == self.record['state']['transports'][0]['identityRef'])
        identity['kind'] = 'plugin'
        result = await self.admit()
        self.assertIsNone(result.envelope)

    async def test_actual_configuration_owner_checks_exact_owner_after_ingress(self):
        from state_owner.test_configuration import ConfigurationTests
        fixture = ConfigurationTests()
        fixture.setUp()
        self.addAsyncCleanup(fixture.source.close)
        self.record = fixture.record
        self.select('set')
        self.claims['expectedVersion'] = 0
        self.claims['payload']['configurationRef']['revision'] = 0
        admitted = await self.admit()
        response = await fixture.call(admitted.envelope)
        self.assertEqual(response['state']['revision'], 1)
        self.select('read')
        self.claims['payload']['owner']['generation'] += 1
        admitted = await self.admit()
        self.assertEqual(admitted.decision.outcome, 'allowed')
        with self.assertRaisesRegex(ContractError, 'configuration_binding_mismatch'):
            await fixture.source.handle(admitted.envelope)
