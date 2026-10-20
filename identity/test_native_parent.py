"""Private-child authority uses current parent records from the actual ledger."""
import copy
import base64
from datetime import timedelta
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, payload_digest
from identity.test_authority import ref, NOW
from identity import test_native_bridge as support
from identity import test_service


class NativeParentTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.NativeBridgeTests.setUp
    request = test_service.ServiceTests.request
    bridge_request = support.NativeBridgeTests.bridge_request
    operation_envelope = support.NativeBridgeTests.operation_envelope

    def install(self):
        self.parent = support.native_row()
        self.parent.update(ref=ref('parent-row'), identityRef=ref('parent-plugin'))
        self.parent['owner']['instanceId'] = 'parent-one'
        self.parent['owner']['epoch'] = 'c' * 64
        self.parent['facts']['grant'].update(grantId='parent-grant', subjectInstanceId='parent-one', policyRef=ref('parent-policy'))
        self.parent['facts']['policy'].update(reference=ref('parent-policy'), subjectInstanceId='parent-one')
        self.row.update(relationship='private', parentOwner=copy.deepcopy(self.parent['owner']))
        self.row['facts']['parentGrant'] = copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['grant']['parentGrantRef'] = ref('parent-grant')
        self.row['facts']['parentAccess'] = [copy.deepcopy(self.parent['facts']['policy']['decisions'][0]['access'])]
        self.record['state']['identities'].append({'ref': ref('parent-plugin'), 'status': 'active',
            'kind': 'plugin', 'principalId': 'parent-plugin', 'externalIdentity': None})
        for original in list(self.record['state']['grants']):
            if original['resourceId'] == 'plugin-one':
                grant = copy.deepcopy(original)
                grant.update(ref=ref('parent-'+original['ref']['id']), resourceId='parent-one')
                self.record['state']['grants'].append(grant)
        self.record['state']['nativeInstances'] = [self.parent, self.row]
        self.persist()

    def persist(self):
        self.js.messages[0].data = canonical_bytes(self.record)

    async def test_parent_and_child_responses_share_current_sequence_and_bound_expiry(self):
        self.install()
        self.parent['facts']['policy']['expiresAt'] = (NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.persist()
        parent_request = self.bridge_request(owner=self.parent['owner'], inp={k:self.parent[k] for k in
            ('manifestDigest','relationship','parentOwner','configurationChecksum')})
        parent = strict_loads(await self.service.native.handle(parent_request))['claims']
        child = strict_loads(await self.service.native.handle(self.bridge_request()))['claims']
        self.assertEqual(parent['authoritySequence'], child['authoritySequence'])
        self.assertEqual(child['result']['parentGrant'], parent['result']['grant'])
        self.assertEqual(child['validUntil'], parent['validUntil'])
        self.assertEqual(child['result']['parentAccess'], self.row['facts']['parentAccess'])

    async def test_private_child_cannot_widen_configuration_source_pins(self):
        self.install()
        source={'configurationRef':ref('configuration-one'),'schemaRef':'config.json',
                'sourceDigest':'sha256:'+'d'*64,'streamCreated':'2026-10-09T12:00:00Z'}
        for row in (self.parent,self.row):
            row['configurationEventSources']=[copy.deepcopy(source)]
            row['facts']['grant']['actions'].append('subscribe')
            row['facts']['grant']['resourceIds'].append('configuration-one')
            row['facts']['domainBindings'].append({'id':'subscription','contractId':'configuration-change-subscribe',
                'action':'subscribe','resourceClass':'configuration','resourceIds':['configuration-one']})
            row['facts']['policy']['decisions'].append({'access':{'action':'subscribe',
                'resourceClass':'configuration','resourceId':'configuration-one'},'outcome':'allow'})
        self.row['facts']['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['parentAccess'].append(copy.deepcopy(self.parent['facts']['policy']['decisions'][-1]['access']))
        self.persist()
        await self.service.native.handle(self.bridge_request())
        for key,value in [('schemaRef','other.json'),('sourceDigest','sha256:'+'e'*64),
                          ('streamCreated','2026-10-09T12:00:01Z')]:
            self.row['configurationEventSources']=[dict(source,**{key:value})];self.persist()
            with self.assertRaisesRegex(ContractError,'native_parent_binding_invalid'):
                await self.service.native.handle(self.bridge_request())
        self.row['configurationEventSources']=[copy.deepcopy(source)]
        self.row['configurationEventSources'][0]['configurationRef']['revision']=0
        self.persist()
        with self.assertRaisesRegex(ContractError,'native_parent_binding_invalid'):
            await self.service.native.handle(self.bridge_request())

    async def test_private_child_prepared_request_reaches_current_receiver(self):
        from identity.capability_service import evaluate_capability_service_request
        self.install()
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('storage-read'), contractId='capability-storage-read', resourceId='task-one')
        self.record['state']['grants'].append(grant)
        for row in (self.parent, self.row):
            binding = copy.deepcopy(row['facts']['domainBindings'][0])
            binding.update(id='storage-binding', contractId='capability-storage-read')
            row['facts']['domainBindings'].append(binding)
        self.persist()
        original = await self.operation_envelope()
        inp = {'operation':strict_loads(original)['operation'], 'operationAuthorityRef':ref('authority-one'),
               'bindingId':'storage-binding', 'contractId':'capability-storage-read',
               'serviceRequestId':'request_'+'c'*64, 'serviceReplySubject':'_INBOX.abcdefghijklmnop',
               'payload':{'resourceRef':ref('task-one'),'input':{}},
               'originalEnvelopeBytes':base64.b64encode(original).decode()}
        response = strict_loads(await self.service.native.handle(self.bridge_request('prepare-domain-call',inp)))
        request = base64.b64decode(response['claims']['result']['serviceRequestBytes'])
        decision = evaluate_capability_service_request(await self.service.reader.current(), request,
            service_id='storage-owner', now=NOW)
        self.assertEqual(decision.outcome, 'allowed')
        self.claims.update(operationId='revoke-parent', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=1, payload={'authorityId':'authority-one','targetRef':ref('parent-plugin')})
        receipt = strict_loads(await self.service.handle(self.request()))['claims']['receipt']
        self.assertEqual(receipt['decision'], 'allowed')
        with self.assertRaises(ContractError):
            evaluate_capability_service_request(await self.service.reader.current(), request,
                service_id='storage-owner', now=NOW)

    async def test_private_child_namespace_is_separate_from_parent_namespace(self):
        self.install()
        for row in (self.parent,self.row):
            row['facts']['grant']['actions'].append('read')
            row['facts']['grant']['resourceIds'] += ['parent-private','child-private']
            row['facts']['domainBindings'].append({'id':'private-storage','contractId':'capability-storage-read',
                'action':'read','resourceClass':'storage','resourceIds':['parent-private','child-private']})
            for resource in ('parent-private','child-private'):
                row['facts']['policy']['decisions'].append({'access':{'action':'read',
                    'resourceClass':'storage','resourceId':resource},'outcome':'allow'})
        self.row['facts']['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['parentAccess'] += [copy.deepcopy(d['access']) for d in self.parent['facts']['policy']['decisions'][1:]]
        self.parent['privateStorageResources']=[{'resourceId':'parent-private',
            'scope':copy.deepcopy(self.parent['facts']['grant']['scope']),'bindingDigest':'sha256:'+'a'*64}]
        self.row['privateStorageResources']=[{'resourceId':'child-private',
            'scope':copy.deepcopy(self.row['facts']['grant']['scope']),'bindingDigest':'sha256:'+'b'*64}]
        self.persist()
        await self.service.native.handle(self.bridge_request())
        original=copy.deepcopy(self.row['privateStorageResources'])
        for field,value in (('resourceId','parent-private'),('bindingDigest','sha256:'+'a'*64)):
            self.row['privateStorageResources']=copy.deepcopy(original)
            self.row['privateStorageResources'][0][field]=value
            self.persist()
            with self.assertRaisesRegex(ContractError,'native_parent_binding_invalid'):
                await self.service.native.handle(self.bridge_request())

    async def test_private_child_admit_and_recheck_keep_original_authority(self):
        self.install()
        original = await self.operation_envelope()
        inp = {'envelopeBytes': base64.b64encode(original).decode(),
               'audience': {'hubId': 'hub-one', 'serviceId': 'task-owner'}}
        admitted = strict_loads(await self.service.native.handle(self.bridge_request('admit-operation', inp)))['claims']['result']
        recheck = {'instanceFactsDigest': payload_digest(self.row['facts']), 'operation': admitted['operation'],
                   'operationAuthorityRef': admitted['authorityRef'], 'originalEnvelopeBytes': inp['envelopeBytes']}
        checked = strict_loads(await self.service.native.handle(self.bridge_request('recheck', recheck)))
        self.assertEqual(checked['claims']['result']['parentGrant'], self.parent['facts']['grant'])
        self.assertEqual(checked['claims']['result']['operationAuthorityRef'], admitted['authorityRef'])

    async def test_parent_recheck_hard_denial_and_policy_denial_win(self):
        self.install()
        deny = copy.deepcopy(next(g for g in self.record['state']['grants']
            if g['resourceId'] == 'parent-one' and g['contractId'] == 'native-authority-recheck'))
        deny.update(ref=ref('parent-denial'), decision='denied')
        self.record['state']['grants'].append(deny)
        self.persist()
        with self.assertRaisesRegex(ContractError, 'native_parent_binding_invalid'):
            await self.service.native.handle(self.bridge_request())
        self.record['state']['grants'].pop()
        self.parent['facts']['policy']['decisions'].append({
            'access': self.row['facts']['parentAccess'][0], 'outcome':'deny'})
        self.persist()
        with self.assertRaisesRegex(ContractError, 'native_parent_binding_invalid'):
            await self.service.native.handle(self.bridge_request())

    async def test_wrong_parent_pin_epoch_generation_and_stale_grant_refuse(self):
        self.install()
        original = copy.deepcopy(self.record)
        for mutate in (lambda: self.row['parentOwner']['pin'].update(packageChecksum='sha256:'+'f'*64),
                       lambda: self.row['parentOwner'].update(epoch='e'*64),
                       lambda: self.row['parentOwner'].update(generation=2),
                       lambda: self.parent['facts']['grant'].update(revision=2),
                       lambda: self.parent.update(status='revoked'),
                       lambda: self.record['state']['identities'][-1].update(status='revoked')):
            mutate()
            self.persist()
            with self.assertRaises(ContractError):
                await self.service.native.handle(self.bridge_request())
            self.record = copy.deepcopy(original)
            self.parent, self.row = self.record['state']['nativeInstances']

    async def test_extra_class_absent_parent_domain_declarations_is_refused(self):
        self.install()
        access = {'action':'inspect', 'resourceClass':'secret', 'resourceId':'task-one'}
        self.parent['facts']['policy']['decisions'].append({'access':access, 'outcome':'allow'})
        self.row['facts']['parentAccess'].append(access)
        self.persist()
        with self.assertRaisesRegex(ContractError, 'native_parent_binding_invalid'):
            await self.service.native.handle(self.bridge_request())

    async def test_parent_revocation_between_reads_refuses_child(self):
        self.install()
        request = self.bridge_request(owner=self.parent['owner'], inp={k:self.parent[k] for k in
            ('manifestDigest','relationship','parentOwner','configurationChecksum')})
        before = strict_loads(await self.service.native.handle(request))['claims']
        self.claims.update(operationId='revoke-parent', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=1, payload={'authorityId':'authority-one','targetRef':ref('parent-plugin')})
        receipt = strict_loads(await self.service.handle(self.request()))['claims']['receipt']
        self.assertEqual(receipt['decision'], 'allowed')
        self.assertGreater(self.js.messages[-1].seq, before['authoritySequence'])
        with self.assertRaisesRegex(ContractError, 'native_parent_binding_invalid'):
            await self.service.native.handle(self.bridge_request())
