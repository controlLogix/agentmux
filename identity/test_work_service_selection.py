"""Protected local/shared work selection and current startup permissions."""
import base64
import copy
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes
from hub import names
from hub.fed.policy import rid_for_remote
from identity import test_application_service_selection as service_support
from identity import test_storage_selection as storage_support
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from identity.test_commands import command_fixture


class WorkServiceSelectionTests(unittest.IsolatedAsyncioTestCase):
    setUp = storage_support.StorageSelectionTests.setUp
    connection = storage_support.StorageSelectionTests.connection
    custody = storage_support.StorageSelectionTests.custody
    selected = storage_support.StorageSelectionTests.selected
    identity_inputs = storage_support.StorageSelectionTests.identity_inputs
    load = service_support.ServiceSelectionTests.load

    def work(self, *, shared=False, aggregate=False, legacy=True):
        if aggregate:
            self.scope = {**self.scope, 'projectId': None}
            self.value['storage'].pop('privateStorage')
            self.value['storage']['scope'] = self.scope
        source = {'database': {'path': str(self.root / 'work.sqlite'), 'applicationId': 0, 'userVersion': 6}}
        repository = None if aggregate else {'localName': 'falcon'}
        if shared:
            source['policy'] = {'path': str(self.root / 'federation.toml'), 'sha256': 'sha256:' + 'e' * 64}
            if repository is not None:
                repository.update(repositoryId=rid_for_remote('example.com/falcon'), normalizedRemote='example.com/falcon')
        actor = {'identityRef': ref('human'), 'transportRef': ref('work-transport'), 'caller': 'operator'}
        channel = {'resourceRef': ref('work-one'), 'actors': [copy.deepcopy(actor)],
            'pluginIdentityRef': ref('plugin-one'), 'instanceId': 'instance-one', 'initialSource': None}
        if legacy:
            commands = ('read', 'inspect', 'outcome') if aggregate else ('create', 'read', 'inspect', 'outcome', 'cancel')
            channel['legacyActors'] = [{**copy.deepcopy(actor),
                'grants': {'federation-work-' + name: ref('work-' + name) for name in commands}}]
        selected = {'source': source, 'repository': repository, 'localPeer': 'local' if shared else None,
            'localNode': 'mac', 'channels': [channel]}
        self.value['storage']['work'] = selected
        return selected

    def record(self):
        record, _ = command_fixture()
        state = record['state']
        interval = dict(status='active', issuedAt=self.issuer_start, expiresAt=self.issuer_end)
        for name, selected in [('identity', self.value['identity']), *self.value['storage']['receivers'].items()]:
            identity = selected.get('serviceIdentityRef', ref('identity-service'))
            state['identities'].append(dict(ref=identity, kind='service', principalId=name + '-service',
                status='active', externalIdentity=None))
            state['issuers'].append(dict(ref=selected['issuer']['issuerRef'], identityRef=identity,
                instanceId=selected.get('serviceInstanceId', 'instance-one'),
                publicKey=selected['issuer']['publicKey'], **interval))
        state['identities'].append(dict(ref=ref('plugin-one'), kind='plugin', principalId='plugin-one',
            status='active', externalIdentity=None))
        state['memberships'].append(dict(ref=ref('work-member'), identityRef=ref('human'),
            scope=copy.deepcopy(self.scope), status='active'))
        state['transports'].append(dict(ref=ref('work-transport'), identityRef=ref('human'),
            issuerRef=ref('identity-issuer'), method='nats-credential-mapping',
            publicKey=base64.urlsafe_b64encode(bytes([51]) * 32).decode().rstrip('='), **interval))
        for actor in self.value['storage']['work']['channels'][0].get('legacyActors', ()):
            for contract, reference in actor['grants'].items():
                state['grants'].append(dict(ref=reference, callerRef=actor['identityRef'], actorRef=actor['identityRef'],
                    scope=copy.deepcopy(self.scope), contractId=contract, resourceId='work-one', decision='allowed',
                    delegationRef=None, definitionTarget=None, **interval))
        return record

    async def test_protected_local_and_shared_work_selection_round_trip(self):
        for shared in (False, True):
            with self.subTest(shared=shared):
                work = self.work(shared=shared)
                self.path = self.root / ('shared-services.json' if shared else 'local-services.json')
                selected = self.load()
                self.assertEqual(selected.policy['storage']['work'], work)
                self.assertEqual(selected.storage_descriptor('storage')['serviceIdentityRef'], ref('storage-service'))

    async def test_work_can_be_the_only_storage_domain_without_legacy_grants(self):
        self.work(legacy=False)
        self.value['storage'].pop('privateStorage')
        self.assertNotIn('legacyActors', self.selected().policy['storage']['work']['channels'][0])

    async def test_operator_target_commands_keep_exact_selected_human_enrollment(self):
        identity = None
        for shared in (False, True):
            with self.subTest(shared=shared):
                work = self.work(shared=shared)
                actor = work['channels'][0]['legacyActors'][0]
                actor['grants'].update({'federation-work-' + name: ref('operator-' + name)
                    for name in ('claim', 'heartbeat', 'release', 'claim-path')})
                selected = self.selected()
                self.assertEqual(selected.policy['storage']['work']['channels'][0]['legacyActors'][0], actor)
                if identity is None:
                    identity = self.identity_inputs(selected)
                    self.addAsyncCleanup(identity.close)
                record = self.record()
                with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
                    await selected.check_storage_authority(identity)

    async def test_aggregate_selection_is_read_only_and_cannot_select_a_work_row(self):
        work = self.work(aggregate=True)
        self.selected()
        actor = work['channels'][0]['legacyActors'][0]
        actor['grants']['federation-work-create'] = ref('work-create')
        with self.assertRaises(ContractError):
            self.selected()
        actor['grants'].pop('federation-work-create')
        work['channels'][0]['initialSource'] = {'kind': 'work', 'id': 'W-one'}
        with self.assertRaises(ContractError):
            self.selected()

    async def test_invalid_local_shared_scope_source_and_actor_shapes_refuse(self):
        self.work()
        original = copy.deepcopy(self.value)
        mutations = (
            lambda w: w.update(localPeer='fake'),
            lambda w: w['repository'].update(repositoryId='r000000000000', normalizedRemote='example.com/falcon'),
            lambda w: w.update(repository=None),
            lambda w: w['source']['database'].update(path=str(self.root / 'project' / 'work.sqlite')),
            lambda w: w['channels'][0]['resourceRef'].update(ownerHubId='foreign'),
            lambda w: w['channels'][0]['actors'].append(copy.deepcopy(w['channels'][0]['actors'][0])),
            lambda w: w['channels'][0]['actors'][0].update(caller='bad:session'),
            lambda w: w['channels'][0]['legacyActors'][0]['grants'].update({'federation-work-offer': ref('offer')}),
            lambda w: w['channels'][0]['legacyActors'][0]['grants'].update({'federation-work-register': ref('register')}),
            lambda w: w['channels'][0]['legacyActors'][0]['grants'].update({'federation-work-sweep-leases': ref('sweep')}),
        )
        for index, mutate in enumerate(mutations):
            self.value = copy.deepcopy(original)
            mutate(self.value['storage']['work'])
            with self.subTest(case=index), self.assertRaises(ContractError):
                self.selected()
        self.value = copy.deepcopy(original)
        work = self.work(shared=True)
        work['repository']['repositoryId'] = 'r000000000000'
        with self.assertRaises(ContractError):
            self.selected()

    async def test_resource_and_source_custody_collisions_refuse(self):
        work = self.work(shared=True)
        original = copy.deepcopy(self.value)
        for mutate in (
                lambda w: w['channels'][0]['resourceRef'].update(id='private-one'),
                lambda w: w['source']['policy'].update(path=w['source']['database']['path']),
                lambda w: w['source']['database'].update(path=self.value['identity']['ledger']['history']['path'])):
            self.value = copy.deepcopy(original)
            mutate(self.value['storage']['work'])
            with self.assertRaises(ContractError):
                self.selected()
        self.value = copy.deepcopy(original)
        work = self.value['storage']['work']
        code = copy.deepcopy(work)
        code['channels'][0].update(resourceRef=ref('code-one'), legacyActors=[])
        code['channels'][0].pop('legacyActors')
        self.value['storage']['code'] = code
        self.selected()
        code['source']['database']['userVersion'] += 1
        with self.assertRaises(ContractError):
            self.selected()

    async def test_local_service_maintenance_and_agent_permissions_are_separate(self):
        work = self.work()
        actor = work['channels'][0]['legacyActors'][0]
        actor.update(caller='federation', grants={'federation-work-sweep-leases': ref('work-sweep')})
        self.selected()
        actor['grants']['federation-work-create'] = ref('work-create')
        with self.assertRaises(ContractError):
            self.selected()
        actor.update(caller=names.session_name('falcon', 'worker', 'one'), grants={'federation-work-claim': ref('work-claim')})
        self.selected()
        actor['grants']['federation-work-cancel'] = ref('work-cancel')
        with self.assertRaises(ContractError):
            self.selected()

    async def test_current_work_actor_transport_membership_grant_and_hard_denial(self):
        self.work()
        selected = self.selected()
        identity = self.identity_inputs(selected)
        self.addAsyncCleanup(identity.close)
        original = self.record()
        async def check(record):
            with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
                return await selected.check_storage_authority(identity)
        await check(original)
        def row(state, collection, name):
            return next(v for v in state[collection] if v['ref']['id'] == name)
        mutations = (
            lambda s: row(s, 'identities', 'human').update(status='revoked'),
            lambda s: row(s, 'identities', 'plugin-one').update(kind='human'),
            lambda s: row(s, 'transports', 'work-transport').update(status='revoked'),
            lambda s: row(s, 'transports', 'work-transport').update(identityRef=ref('plugin-one')),
            lambda s: row(s, 'transports', 'work-transport').update(issuerRef=ref('storage-issuer')),
            lambda s: row(s, 'memberships', 'work-member').update(status='revoked'),
            lambda s: row(s, 'memberships', 'work-member')['scope'].update(projectId='foreign'),
            lambda s: row(s, 'grants', 'work-create').update(status='revoked'),
            lambda s: row(s, 'grants', 'work-create').update(decision='review-required'),
            lambda s: row(s, 'grants', 'work-create').update(resourceId='foreign'),
            lambda s: row(s, 'grants', 'work-create').update(delegationRef=ref('delegation')),
            lambda s: s['grants'].append(dict(row(s, 'grants', 'work-create'), ref=ref('hard-denial'), decision='denied')),
        )
        for index, mutate in enumerate(mutations):
            record = copy.deepcopy(original)
            mutate(record['state'])
            with self.subTest(case=index), self.assertRaises(ContractError):
                await check(record)

    async def test_native_only_selection_still_requires_current_actor_authority(self):
        self.work(legacy=False)
        selected = self.selected()
        identity = self.identity_inputs(selected)
        self.addAsyncCleanup(identity.close)
        record = self.record()
        with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
            await selected.check_storage_authority(identity)
        next(m for m in record['state']['memberships'] if m['ref'] == ref('work-member'))['status'] = 'revoked'
        with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
            with self.assertRaises(ContractError):
                await selected.check_storage_authority(identity)

    async def test_service_maintenance_requires_its_current_service_identity(self):
        work = self.work()
        actor = work['channels'][0]['legacyActors'][0]
        actor.update(identityRef=ref('work-service'), transportRef=ref('work-service-transport'),
            caller='federation', grants={'federation-work-sweep-leases': ref('work-sweep')})
        selected = self.selected()
        identity = self.identity_inputs(selected)
        self.addAsyncCleanup(identity.close)
        record = self.record()
        state = record['state']
        state['identities'].append(dict(ref=ref('work-service'), kind='service', principalId='work-service',
            status='active', externalIdentity=None))
        state['memberships'].append(dict(ref=ref('work-service-member'), identityRef=ref('work-service'),
            scope=copy.deepcopy(self.scope), status='active'))
        transport = copy.deepcopy(next(t for t in state['transports'] if t['ref'] == ref('work-transport')))
        transport.update(ref=ref('work-service-transport'), identityRef=ref('work-service'))
        state['transports'].append(transport)
        with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
            await selected.check_storage_authority(identity)
        next(p for p in state['identities'] if p['ref'] == ref('work-service'))['kind'] = 'device'
        with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
            with self.assertRaises(ContractError):
                await selected.check_storage_authority(identity)

    async def test_cross_home_agent_uses_selected_project_permission(self):
        work = self.work()
        work['repository']['localName'] = 'other'
        caller = names.session_name('falcon', 'worker', 'one')
        channel = work['channels'][0]
        channel['actors'][0]['caller'] = caller
        channel['legacyActors'][0].update(caller=caller,
            grants={'federation-work-claim': ref('work-claim')})
        selected = self.selected()
        identity = self.identity_inputs(selected)
        self.addAsyncCleanup(identity.close)
        record = self.record()
        with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
            await selected.check_storage_authority(identity)
        next(g for g in record['state']['grants'] if g['ref'] == ref('work-claim'))['scope']['projectId'] = 'foreign'
        with patch.object(identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record), 1))):
            with self.assertRaises(ContractError):
                await selected.check_storage_authority(identity)


if __name__ == '__main__':
    unittest.main()
