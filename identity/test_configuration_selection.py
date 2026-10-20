"""Configuration enrollment binds private schemas, signing and exact broker rights."""
import base64
import asyncio
import binascii
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes
from identity.application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from identity import test_application_service_selection as fixtures
from identity.test_authority import ref
from identity.test_native_bridge import native_row
from identity.service import IdentityService
from state_owner.history import OwnerHistory
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.configuration_host import ConfigurationHost
from native_security.nats_credentials import service_policy, validate_service, CredentialError
from native_security.test_nats_service_credentials import signed_service


class ConfigurationSelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixtures.ServiceSelectionTests.setUp(self)
        directory = self.root / 'configuration'
        directory.mkdir(mode=0o700)
        service = copy.deepcopy(self.value['identity'])
        payload, receipt = provision_application_service_issuer(directory / 'issuer.key',
            service_id='configuration-owner', profile_id='profile-one', authority_id='authority-one', instance_id='instance-one',
            identity={'ref':ref('configuration-service'), 'kind':'service', 'status':'active',
                      'principalId':'configuration-service', 'externalIdentity':None},
            issuer_ref=ref('configuration-issuer'), issued_at=self.issuer_start, expires_at=self.issuer_end)
        service['issuer'] = {'keyFile':{'path':receipt.path, 'sha256':receipt.digest},
            'issuerRef':ref('configuration-issuer'), 'publicKey':payload['issuers'][0]['record']['publicKey']}
        producer_seed=bytes([7])*32
        producer_path=directory/'producer.key'
        producer_path.write_bytes(producer_seed); producer_path.chmod(0o600)
        service['producer']={'identityRef':ref('configuration-service'),
            'transportRef':ref('configuration-producer'), 'grantRef':ref('configuration-producer-grant'),
            'keyFile':{'path':str(producer_path),'sha256':'sha256:'+hashlib.sha256(producer_seed).hexdigest()},
            'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(producer_seed).verify_key)).decode().rstrip('=')}
        key = bytes([160]) + bytes([3])*32
        service['credentials'].update(path=str(directory/'user.creds'), userPublicKey=base64.b32encode(
            key+binascii.crc_hqx(key,0).to_bytes(2,'little')).decode())
        service['ledger']['entityId']='configuration-one'
        service['ledger']['stream']='CONFIGURATION'
        service['ledger']['history']['path']=str(directory/'history.sqlite')
        service['ledger']['checkpoint']={'path':str(directory/'checkpoint'), 'commitRef':ref('configuration-checkpoint')}
        for field in ('backupDirectory','inventoryDirectory','keyDirectory'):
            path=directory/field; path.mkdir(mode=0o700); service['backup'][field]=str(path)
        raw=b'{"type":"object"}'
        path=directory/'config.json'; path.write_bytes(raw); path.chmod(0o600)
        service.update(owner=native_row()['owner'], requesterReplyPrefix='_INBOX.native_host_00000001',
            schemaRef='config.json', schemaResources={
            'config.json':{'path':str(path), 'sha256':'sha256:'+hashlib.sha256(raw).hexdigest()}})
        self.value['configuration']=service

    def selected(self):
        return ApplicationServiceSelection(canonical_bytes(self.value))

    def resources(self, selected, role):
        service=selected.service(role)
        history=OwnerHistory(service['ledger']['history']['path'], selected.binding(role), stream_identity=selected.stream_identity(role))
        self.addCleanup(history.close)
        backup=service['backup']
        host=BackupHost(*(backup[k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'], binding=selected.binding(role), stream_identity=selected.stream_identity(role))
        return history,host

    async def test_actual_factory_receives_exact_enrolled_resources(self):
        selected=self.selected()
        history,backup=self.resources(selected,'identity')
        connection=SimpleNamespace(jetstream=Mock(return_value=object()))
        identity=IdentityService(connection, **selected.identity_kwargs(history=history,
            checkpoint_committed=lambda receipt:None, signing_seed=selected.load_signing_seed('identity'), backup_host=backup))
        history,backup=self.resources(selected,'configuration')
        ledger=selected.service('configuration')['ledger']
        checkpoint=CheckpointHost(ledger['checkpoint']['path'], stream=ledger['stream'], commit_ref=ledger['checkpoint']['commitRef'],
            binding=selected.binding('configuration'), stream_identity=selected.stream_identity('configuration'))
        inputs=dict(authority=identity.reader,history=history,signing_seed=selected.load_signing_seed('configuration'),
                    checkpoint_host=checkpoint,backup_host=backup)
        kwargs=selected.configuration_kwargs(**inputs)
        host=ConfigurationHost.from_enrolled_host(connection,**kwargs)
        self.assertEqual(kwargs['reply_prefix'], '_INBOX.native_host_00000001')
        self.assertNotEqual(kwargs['reply_prefix'], selected.service('configuration')['credentials']['replyPrefix'])
        self.assertEqual(host._reply_prefix, '_INBOX.native_host_00000001.')
        self.assertEqual(host.subject,service_policy(**selected.service_policy_inputs('configuration')).command_subject)
        self.assertEqual(kwargs['schema_resources'],{'config.json':b'{"type":"object"}'})
        checkpoint._ref=canonical_bytes(ref('wrong-checkpoint'))
        with self.assertRaises(ContractError): selected.configuration_kwargs(**inputs)

    async def test_schema_pin_path_and_size_refusals(self):
        selected=self.selected()
        pin=self.value['configuration']['schemaResources']['config.json']
        path=Path(pin['path'])
        for raw in (b'changed', b'x'*262145):
            path.write_bytes(raw)
            with self.assertRaises(ContractError): selected.load_configuration_schemas()
        original=copy.deepcopy(self.value)
        for name in ('../config.json','https://other/config.json','/config.json','a//b'):
            self.value=copy.deepcopy(original)
            self.value['configuration']['schemaRef']=name
            self.value['configuration']['schemaResources']={name:pin}
            with self.assertRaises(ContractError): self.selected()
        self.value=copy.deepcopy(original)
        self.value['configuration']['schemaResources']['config.json']['path']=self.value['workspaces'][0]+'/config.json'
        with self.assertRaises(ContractError): self.selected()

    async def test_requester_scope_is_required_exact_and_separate(self):
        original=copy.deepcopy(self.value)
        for prefix in (None, '_INBOX.>', '_INBOX.native_host_00000001.',
                       '_INBOX.native_host_00000001\n', '_INBOX.native_host_00000001\r',
                       original['configuration']['credentials']['replyPrefix']):
            self.value=copy.deepcopy(original)
            self.value['configuration']['requesterReplyPrefix']=prefix
            with self.assertRaises(ContractError): self.selected()
        self.value=copy.deepcopy(original)
        del self.value['configuration']['requesterReplyPrefix']
        with self.assertRaises(ContractError): self.selected()

    async def test_real_receiver_accepts_requester_and_refuses_service_and_unknown_inboxes(self):
        from state_owner.test_configuration import ConfigurationTests
        fixture=ConfigurationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.addAsyncCleanup(fixture.source.close)
        await fixture.call(fixture.request('set'))
        selected=self.selected()
        prefix=selected.service('configuration')['requesterReplyPrefix']
        await fixture.source.start(reply_prefix=prefix+'.')
        raw=fixture.request(revision=1)
        for reply in (selected.service('configuration')['credentials']['replyPrefix']+'.request1',
                      '_INBOX.unknown_caller_0001.request1', prefix+'extra.request1'):
            await fixture.source._receive(SimpleNamespace(data=raw,reply=reply))
        self.assertEqual(fixture.connection.sent, [])
        await fixture.source._receive(SimpleNamespace(data=raw,reply=prefix+'.request1'))
        await asyncio.gather(*fixture.source._requests)
        self.assertEqual(len(fixture.connection.sent), 1)
        self.assertEqual(fixture.connection.sent[0][0],prefix+'.request1')
        from state_owner.configuration import verify_configuration_response
        from identity.test_authority import NOW
        reply=verify_configuration_response(fixture.connection.sent[0][1],raw,
            public_key=fixture.record['state']['issuers'][0]['publicKey'],issuer_ref=ref('issuer'),now=NOW)
        self.assertEqual(reply['state']['revision'],1)

    async def test_exact_configuration_credentials_and_role_specific_response_bound(self):
        options=self.selected().service_policy_inputs('configuration')
        policy=service_policy(**options)
        self.assertEqual(policy.response_permissions,{'max':1,'ttl':12_000_000_000})
        self.assertEqual(set(policy.subscribe_subjects),{policy.command_subject,policy.ledger_subject,options['reply_prefix']+'.>'})
        raw,account,user=signed_service(options)
        self.assertEqual(validate_service(raw,account_public_key=account,**options).public_key,user)
        for change in (lambda n:n['resp'].update(ttl=5_000_000_000),lambda n:n['resp'].update(ttl=12_000_000_001),
                       lambda n:n['sub']['allow'].remove(policy.ledger_subject),
                       lambda n:n['sub']['allow'].append('amx.v1.>'),
                       lambda n:n['pub']['allow'].append('$JS.API.STREAM.MSG.GET.IDENTITY')):
            raw,account,_=signed_service(options,change)
            with self.assertRaises(CredentialError): validate_service(raw,account_public_key=account,**options)
        with self.assertRaises(CredentialError): service_policy(**options,artifact_bucket='OTHER')
