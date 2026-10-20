"""Protected storage selection preserves exact provider and authority inputs."""
import base64
import binascii
import copy
import unittest

from agentmux_contracts import ContractError, canonical_bytes
from capability_owner.private_storage import private_storage_binding_digest
from hub.fed.policy import rid_for_remote
from identity.application_service_selection import ApplicationServiceSelection
from identity import test_application_service_selection as support
from identity.test_authority import ref
from state_owner.ledger import OwnerBinding, StreamIdentity
from state_owner.retention import Retention
from datetime import datetime


class StorageSelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        support.ServiceSelectionTests.setUp(self)
        self.scope = copy.deepcopy(self.value['definitions']['ledger']['scope'])
        self.serial = 5
        receivers = {}
        for name in ('storage','outcome'):
            descriptor = self.connection(name)
            issuer = copy.deepcopy(self.value['identity']['issuer'])
            issuer.update(issuerRef=ref(name+'-issuer'),publicKey=base64.urlsafe_b64encode(bytes([self.serial])*32).decode().rstrip('='))
            issuer['keyFile']['path'] = str(self.root/name/'issuer.key')
            receivers[name] = dict(descriptor,issuer=issuer,serviceIdentityRef=ref(name+'-service'),
                serviceInstanceId=name+'-instance',requestSigningKeyRef=ref('identity-issuer'))
        private = dict(publisher=self.connection('private'),**self.custody('private'),
            pluginIdentityRef=ref('plugin-one'),instanceId='instance-one',packageId='package-one')
        ledger = private['ledger']; src = ledger['streamIdentity']; policy = ledger['retention']
        private['bindingDigest'] = private_storage_binding_digest(
            binding=OwnerBinding('hub-one','plugin-private','private-one','plugin-storage',canonical_bytes(self.scope)),
            plugin_identity_ref=private['pluginIdentityRef'],instance_id=private['instanceId'],package_id=private['packageId'],
            stream=ledger['stream'],stream_identity=StreamIdentity(datetime.fromisoformat(src['created']),src['minimumSequence']),
            retention=Retention(policy['maxBytes'],policy['reserveBytes'],policy['replicas']),domain='enrolled-domain')
        self.value['storage'] = dict(scope=self.scope,receivers=receivers,privateStorage=private)

    def connection(self,name):
        self.serial += 1
        descriptor = {k:copy.deepcopy(self.value['identity'][k]) for k in ('connection','credentials')}
        raw = bytes([160])+bytes([self.serial])*32
        descriptor['credentials'].update(path=str(self.root/name/'user.creds'),
            userPublicKey=base64.b32encode(raw+binascii.crc_hqx(raw,0).to_bytes(2,'little')).decode(),
            replyPrefix='_INBOX.'+name+'_storage_00000001')
        return descriptor

    def custody(self,name):
        ledger = copy.deepcopy(self.value['definitions']['ledger'])
        ledger.update(entityId=name+'-one',scope=copy.deepcopy(self.scope),stream=name.upper())
        ledger['history']['path'] = str(self.root/name/'history.sqlite')
        ledger['checkpoint'] = dict(path=str(self.root/name/'checkpoint'),commitRef=ref(name+'-checkpoint'))
        backup = {k:str(self.root/name/k) for k in ('backupDirectory','inventoryDirectory','keyDirectory')}
        backup.update(destinationId=name+'-backup',keyId=name+'-key')
        return dict(ledger=ledger,backup=backup)

    def add_board(self):
        card = dict(self.connection('card'),**self.custody('card'))
        allocation = dict(self.connection('allocation'),**self.custody('allocation'))
        phase = dict(serviceIdentityRef=ref('board-service'),transportRef=ref('board-transport'),
            keyFile={'path':str(self.root/'board-phase.key'),'sha256':'sha256:'+'d'*64},
            publicKey=base64.urlsafe_b64encode(bytes([23])*32).decode().rstrip('='),
            cardGrants={k:ref('card-'+k) for k in ('federation-board-dispatch','federation-board-complete')},
            allocationGrants={k:ref('allocation-'+k) for k in ('federation-board-dispatch','federation-board-complete')})
        self.value['storage']['board'] = dict(resourceRef=ref('card-one'),
            repository={'localName':'falcon','repositoryId':rid_for_remote('example.com/falcon'),
                'normalizedRemote':'example.com/falcon','counterPrefix':'SH'},cardKey='SH-1',
            kvStreamIdentity=copy.deepcopy(card['ledger']['streamIdentity']),cardPublisher=card,
            allocationPublisher=allocation,phaseAuthority=phase,localPeer='local',
            actors=[{'identityRef':ref('human'),'transportRef':ref('transport'),'address':'peer:local'}],
            auditMirror={'database':{'path':str(self.root/'board.sqlite'),'applicationId':0,'userVersion':5},
                'policy':{'path':str(self.root/'federation.toml'),'sha256':'sha256:'+'e'*64}})

    def selected(self):
        return ApplicationServiceSelection(canonical_bytes(self.value))

    async def test_private_and_both_provider_selection_and_separate_policies(self):
        selected = self.selected()
        self.assertEqual(selected.storage_policy_inputs('storage')['service_id'],'storage-owner')
        self.assertEqual(selected.storage_policy_inputs('private')['entity_id'],'private-one')
        self.add_board()
        selected = self.selected()
        self.assertEqual(selected.storage_policy_inputs('card')['card_key'],'SH-1')
        self.assertEqual(selected.storage_policy_inputs('allocation')['counter_prefix'],'SH')
        self.assertNotEqual(selected.storage_descriptor('card')['credentials']['userPublicKey'],
            selected.storage_descriptor('storage')['credentials']['userPublicKey'])

    async def test_omission_preserves_existing_selection_and_no_provider_default(self):
        self.value.pop('storage')
        self.selected()
        self.value['storage'] = dict(scope=self.scope,receivers={})
        with self.assertRaises(ContractError):self.selected()

    async def test_private_namespace_changes_cannot_reuse_digest(self):
        original = copy.deepcopy(self.value)
        for field in ('instanceId','packageId'):
            self.value = copy.deepcopy(original)
            self.value['storage']['privateStorage'][field] = 'another'
            with self.assertRaises(ContractError):self.selected()
        for field,value in (('stream','OTHER'),('entityId','other-private')):
            self.value = copy.deepcopy(original)
            self.value['storage']['privateStorage']['ledger'][field] = value
            with self.assertRaises(ContractError):self.selected()

    async def test_shared_credentials_workspace_material_and_scope_substitution_refuse(self):
        original = copy.deepcopy(self.value)
        for mutate in (
            lambda s:s['receivers']['outcome']['credentials'].update(userPublicKey=s['receivers']['storage']['credentials']['userPublicKey']),
            lambda s:s['privateStorage']['publisher']['credentials'].update(path=str(self.root/'project'/'secret')),
            lambda s:s['privateStorage']['ledger']['history'].update(path=self.value['identity']['ledger']['history']['path']),
            lambda s:s['scope'].update(organizationId='other-org'),
            lambda s:s['receivers']['storage'].update(requestSigningKeyRef=ref('other-issuer')),
            lambda s:s['receivers']['storage']['connection'].update(endpoint='tls://127.0.0.1:4222\n')):
            self.value=copy.deepcopy(original);mutate(self.value['storage'])
            with self.assertRaises(ContractError):self.selected()

    async def test_board_source_gate_and_custody_substitution_refuse(self):
        self.add_board(); original=copy.deepcopy(self.value)
        for mutate in (
            lambda b:b.update(cardKey='OTHER-1'),
            lambda b:b['repository'].update(repositoryId='r000000000000'),
            lambda b:b['allocationPublisher']['connection'].update(jetstreamDomain='OTHER'),
            lambda b:b['allocationPublisher']['ledger'].update(entityId='card-one'),
            lambda b:b['cardPublisher']['ledger'].update(scope=dict(self.scope,projectId='other-project')),
            lambda b:b['cardPublisher']['ledger']['history'].update(path=str(self.root/'project'/'history.sqlite')),
            lambda b:b['phaseAuthority'].update(allocationGrants=b['phaseAuthority']['cardGrants'])):
            self.value=copy.deepcopy(original);mutate(self.value['storage']['board'])
            with self.assertRaises(ContractError):self.selected()

    async def test_new_connections_cannot_subscribe_to_existing_service_inboxes(self):
        self.add_board()
        original = copy.deepcopy(self.value)
        for role in ('identity','definitions'):
            for name in ('storage','outcome','private','card','allocation'):
                self.value = copy.deepcopy(original)
                storage = self.value['storage']
                entry = (storage['receivers'][name] if name in ('storage','outcome') else
                    storage['privateStorage']['publisher'] if name == 'private' else
                    storage['board'][name+'Publisher'])
                entry['credentials']['replyPrefix'] = self.value[role]['credentials']['replyPrefix']
                with self.subTest(role=role,name=name),self.assertRaises(ContractError):self.selected()

    async def test_selected_requester_inbox_is_reserved_from_new_receivers(self):
        task = dict(self.connection('task'),**self.custody('task'))
        task.update(issuer=copy.deepcopy(self.value['identity']['issuer']),
            serviceIdentityRef=ref('task-service'),serviceInstanceId='task-instance',
            requesterReplyPrefix='_INBOX.task_requester_000001')
        task['issuer'].update(issuerRef=ref('task-issuer'),publicKey=base64.urlsafe_b64encode(bytes([42])*32).decode().rstrip('='))
        self.value['task'] = task
        self.selected()
        self.value['storage']['receivers']['storage']['credentials']['replyPrefix'] = task['requesterReplyPrefix']
        with self.assertRaises(ContractError):self.selected()

    def identity_inputs(self, selected):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from identity.service import IdentityService
        from state_owner.history import OwnerHistory
        from state_owner.backup_host import BackupHost
        history = OwnerHistory(selected.service('identity')['ledger']['history']['path'],
            selected.binding('identity'),stream_identity=selected.stream_identity('identity'))
        self.addCleanup(history.close)
        backup = self.value['identity']['backup']
        host = BackupHost(*(backup[k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'],binding=selected.binding('identity'),
            stream_identity=selected.stream_identity('identity'))
        connection = SimpleNamespace(jetstream=Mock(return_value=object()))
        return IdentityService(connection,**selected.identity_kwargs(history=history,
            checkpoint_committed=lambda receipt:None,signing_seed=selected.load_signing_seed('identity'),backup_host=host))

    def authority_record(self):
        from identity.test_commands import command_fixture
        record,_ = command_fixture()
        state = record['state']
        interval = dict(status='active',issuedAt=self.issuer_start,expiresAt=self.issuer_end)
        for name,selected in [('identity',self.value['identity']),*self.value['storage']['receivers'].items()]:
            identity = selected.get('serviceIdentityRef',ref('identity-service'))
            state['identities'].append(dict(ref=identity,kind='service',principalId=name+'-service',status='active',externalIdentity=None))
            state['issuers'].append(dict(ref=selected['issuer']['issuerRef'],identityRef=identity,
                instanceId=selected.get('serviceInstanceId','instance-one'),publicKey=selected['issuer']['publicKey'],**interval))
        board = self.value['storage']['board'];phase = board['phaseAuthority']
        state['identities'].append(dict(ref=phase['serviceIdentityRef'],kind='service',principalId='board-service',status='active',externalIdentity=None))
        state['transports'].append(dict(ref=phase['transportRef'],identityRef=phase['serviceIdentityRef'],
            issuerRef=ref('identity-issuer'),method='nats-credential-mapping',publicKey=phase['publicKey'],**interval))
        state['memberships'].append(dict(ref=ref('board-member'),identityRef=phase['serviceIdentityRef'],scope=copy.deepcopy(self.scope),status='active'))
        for name,publisher in [('cardGrants','cardPublisher'),('allocationGrants','allocationPublisher')]:
            for contract,reference in phase[name].items():
                state['grants'].append(dict(ref=reference,callerRef=phase['serviceIdentityRef'],actorRef=phase['serviceIdentityRef'],
                    scope=copy.deepcopy(self.scope),contractId=contract,resourceId=board[publisher]['ledger']['entityId'],
                    decision='allowed',delegationRef=None,definitionTarget=None,**interval))
        return record

    async def test_current_startup_signers_phase_grants_and_hard_denials(self):
        from unittest.mock import AsyncMock, patch
        from identity.authority import AuthoritySnapshot
        self.add_board(); selected=self.selected(); identity=self.identity_inputs(selected)
        original=self.authority_record()
        async def check(record):
            with patch.object(identity.reader,'current',AsyncMock(return_value=AuthoritySnapshot(canonical_bytes(record),1))):
                return await selected.check_storage_authority(identity)
        await check(original)
        changes = [lambda s:s['issuers'][-1].update(status='revoked'),
            lambda s:s['issuers'][-1].update(instanceId='other-instance'),
            lambda s:s['transports'][-1].update(publicKey=s['issuers'][-1]['publicKey']),
            lambda s:s['memberships'][-1].update(status='revoked'),
            lambda s:s['grants'][-1].update(decision='review-required'),
            lambda s:s['grants'][-1].update(resourceId='other-archive'),
            lambda s:s['grants'][-1].update(delegationRef=ref('delegated')),
            lambda s:s['grants'].append(dict(s['grants'][-1],ref=ref('hard-denial'),decision='denied'))]
        for change in changes:
            record=copy.deepcopy(original);change(record['state'])
            with self.assertRaises(ContractError):await check(record)

    async def test_actual_identity_source_substitution_refuses_before_read(self):
        from unittest.mock import patch
        selected=self.selected();identity=self.identity_inputs(selected)
        self.assertIs(selected.check_storage_identity_source(identity)[0],identity.reader)
        for target,field,value in ((identity.reader._ledger,'_stream','OTHER'),
                                  (identity.ingress,'_reader',object()),
                                  (identity.ingress,'_issuer_ref',canonical_bytes(ref('other')))):
            with patch.object(target,field,value),self.assertRaises(ContractError):
                selected.check_storage_identity_source(identity)
