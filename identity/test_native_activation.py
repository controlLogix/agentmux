"""Actual initial activation commits full allocated owners before native binding."""
import copy
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity import test_native_bridge as support
from identity.test_authority import ref
from identity.test_service import _Clock


class NativeActivationTests(unittest.IsolatedAsyncioTestCase):
    bridge_request=support.NativeBridgeTests.bridge_request
    request=support.NativeBridgeTests.request

    def setUp(self):
        support.NativeBridgeTests.setUp(self)
        patch('identity.native_activation.datetime',_Clock).start()
        state=self.record['state']
        for name,contract,resource in [('activate','native-authority-activate-instance','plugin-one'),
                                       ('admin','identity-native-instance-set','authority-one')]:
            grant=copy.deepcopy(state['grants'][0])
            grant.update(ref=ref('activation-'+name),callerRef=ref('host'),actorRef=ref('host'),
                         contractId=contract,resourceId=resource)
            state['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)
        self.row['owner'].update(epoch='d'*64,generation=3)

    def activation(self,**changes):
        inp={'record':copy.deepcopy(self.row),'previousRef':None,'cancellationRef':ref('activation-cancel'),'expectedVersion':1}
        inp.update(changes)
        return self.bridge_request('activate-instance',inp)

    async def test_initial_commit_readback_then_bind_and_exact_retry(self):
        raw=self.activation()
        self.assertEqual(self.record['state']['nativeInstances'],[])
        response=strict_loads(await self.service.handle(raw))
        self.assertEqual(response['claims']['owner'],self.row['owner'])
        self.assertEqual(response['claims']['result'],{'enrollmentRef':self.row['ref'],'facts':self.row['facts']})
        self.assertEqual(response['claims']['authoritySequence'],2)
        retained=strict_loads(self.js.messages[-1].data)
        self.assertEqual(retained['state']['nativeInstances'],[self.row])
        self.assertEqual(retained['operation']['cancellationRef'],ref('activation-cancel'))
        self.assertEqual(retained['operation']['expectedVersion'],1)
        self.assertEqual(strict_loads(await self.service.handle(self.bridge_request()))['claims']['result'],self.row['facts'])
        retry=strict_loads(await self.service.handle(raw))
        self.assertEqual(retry['claims']['result'],response['claims']['result'])
        self.assertEqual(len(self.js.messages),2)
        with self.assertRaisesRegex(ContractError,'native_activation_version_mismatch'):
            await self.service.handle(self.bridge_request('activate-instance',strict_loads(raw)['claims']['input'],
                requestId='different-activation-request'))
        self.assertEqual(len(self.js.messages),2)

    async def test_current_method_and_ordinary_authority_required(self):
        for name in ('activation-activate','activation-admin'):
            grant=next(g for g in self.record['state']['grants'] if g['ref']==ref(name))
            grant['decision']='denied'
            self.js.messages[0].data=canonical_bytes(self.record)
            with self.assertRaises(ContractError):await self.service.handle(self.activation())
            self.assertEqual(len(self.js.messages),1)
            grant['decision']='allowed'

    async def test_mismatched_owner_host_expired_facts_and_stale_cas_refuse(self):
        original=copy.deepcopy(self.row)
        for change in (lambda r:r['owner'].update(generation=2), lambda r:r.update(hostIdentityRef=ref('other')),
                       lambda r:r['facts']['grant'].update(expiresAt='2026-10-09T11:00:00Z')):
            row=copy.deepcopy(original);change(row)
            with self.assertRaises(ContractError):await self.service.handle(self.activation(record=row))
            self.assertEqual(len(self.js.messages),1)
        with self.assertRaises(ContractError):await self.service.handle(self.activation(expectedVersion=0))
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['nativeInstances'],[])

    async def test_rebind_requires_explicit_previous_record_revision(self):
        await self.service.handle(self.activation())
        old=copy.deepcopy(self.row['ref'])
        self.row['ref']['revision']=2
        self.row['owner']['generation']=4
        with self.assertRaises(ContractError):await self.service.handle(self.activation(expectedVersion=2))
        response=strict_loads(await self.service.handle(self.activation(previousRef=old,expectedVersion=2)))
        self.assertEqual(response['claims']['result']['enrollmentRef']['revision'],2)
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['nativeInstances'][0]['owner'],self.row['owner'])

    async def test_revocation_after_commit_prevents_activation_success(self):
        execute=self.service.owner.execute
        async def revoke_after_commit(raw):
            receipt=await execute(raw)
            if strict_loads(raw)['contractId']=='identity-native-instance-set':
                self.claims.update(operationId='revoke-activation-host',expectedVersion=2,
                    contractId='identity-revoke',grantRef=ref('grant'),
                    payload={'authorityId':'authority-one','targetRef':ref('host-transport')})
                await self.service.handle(self.request())
            return receipt
        with patch.object(self.service.owner,'execute',side_effect=revoke_after_commit):
            with self.assertRaises(ContractError):await self.service.handle(self.activation())
        retained=strict_loads(self.js.messages[-1].data)
        self.assertEqual(retained['state']['nativeInstances'],[self.row])
        transport=next(t for t in retained['state']['transports'] if t['ref']['id']=='host-transport')
        self.assertEqual(transport['status'],'revoked')

    async def test_future_version_cannot_cross_native_authorization_snapshot(self):
        with patch.object(self.service.owner,'execute',wraps=self.service.owner.execute) as execute:
            with self.assertRaisesRegex(ContractError,'native_activation_version_mismatch'):
                await self.service.handle(self.activation(expectedVersion=2))
            execute.assert_not_called()
        self.assertEqual(len(self.js.messages),1)
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['nativeInstances'],[])

    async def test_method_revocation_between_admission_and_write_cannot_commit_activation(self):
        execute=self.service.owner.execute
        async def revoke_before_commit(raw):
            if strict_loads(raw)['contractId']=='identity-native-instance-set':
                self.claims.update(operationId='revoke-activation-method',expectedVersion=1,
                    contractId='identity-revoke',grantRef=ref('grant'),
                    payload={'authorityId':'authority-one','targetRef':ref('activation-activate')})
                await self.service.handle(self.request())
            return await execute(raw)
        with patch.object(self.service.owner,'execute',side_effect=revoke_before_commit):
            with self.assertRaises(ContractError):await self.service.handle(self.activation())
        records=[strict_loads(message.data) for message in self.js.messages]
        self.assertEqual(records[-1]['state']['nativeInstances'],[])
        grant=next(g for g in records[-1]['state']['grants'] if g['ref']['id']=='activation-activate')
        self.assertEqual(grant['status'],'revoked')
        activations=[r for r in records[1:] if r['authorizationDecision']['contractId']=='identity-native-instance-set']
        self.assertEqual(len(activations),1)
        self.assertEqual(activations[0]['authorizationDecision']['decision'],'denied')
        self.assertNotEqual(activations[0]['outcome'],'committed')
