"""Protected transport inputs preserve exact credentials and independent trust."""
import base64
import copy
import hashlib
import json
import time
from pathlib import Path
import unittest

import nkeys
from agentmux_contracts import ContractError, canonical_bytes
from identity import test_native_host_selection as support
from identity.test_native_bridge import native_row
from identity.test_authority import ref
from identity.native_host_selection import NativeHostSelection, write_native_host_selection


def credentials(seed, publish, subscribe):
    account=nkeys.from_seed(nkeys.encode_seed(bytes([1])*32,nkeys.PREFIX_BYTE_ACCOUNT))
    user=nkeys.from_seed(nkeys.encode_seed(bytes([seed])*32,nkeys.PREFIX_BYTE_USER))
    try:
        claims={'iss':account.public_key.decode(),'sub':user.public_key.decode(),'iat':int(time.time()),
            'exp':int(time.time())+3600,'nats':{'type':'user','version':2,'pub':{'allow':publish},'sub':{'allow':subscribe}}}
        enc=lambda value:base64.urlsafe_b64encode(json.dumps(value,separators=(',',':')).encode()).rstrip(b'=')
        signed=enc({'typ':'JWT','alg':'ed25519-nkey'})+b'.'+enc(claims)
        token=signed+b'.'+base64.urlsafe_b64encode(account.sign(signed)).rstrip(b'=')
        return (b'-----BEGIN NATS USER JWT-----\n'+token+b'\n------END NATS USER JWT------\n\n'
            b'-----BEGIN USER NKEY SEED-----\n'+user.seed+b'\n------END USER NKEY SEED------\n'),claims['iss'],claims['sub']
    finally:
        account.wipe();user.wipe()


class NativeTransportSelectionTests(unittest.TestCase):
    load=support.NativeHostSelectionTests.load

    def pin(self,name,raw):
        path=self.root/name;path.write_bytes(raw);path.chmod(0o600)
        return {'path':str(path),'sha256':'sha256:'+hashlib.sha256(raw).hexdigest()}

    def setUp(self):
        support.NativeHostSelectionTests.setUp(self)
        prefix='amx.v1.h.hub-one.plugins.plugin-one.'
        for role,index,server in (('lifecycle',10,'controllerCredentials'),('contextTransport',12,'serverCredentials')):
            connection=copy.deepcopy(self.value['connection'])
            connection.update(endpoint='tls://127.0.0.1:'+str(4300+index),serverName=role.lower()+'.local',
                leafCertificateSHA256='sha256:'+str(index//2)*64)
            ca=self.pin(role+'.pem',connection['rootsPEM'].encode())
            outgoing,incoming=([prefix+'lifecycle.control'],[prefix+'lifecycle.event']) if role=='lifecycle' else (
                [prefix+'context.reply',prefix+'operation.invoke',prefix+'operation.cancel'],
                [prefix+'context.request',prefix+'operation.result'])
            raw,account,user=credentials(index,outgoing,incoming)
            serverpin=dict(self.pin(role+'-server.creds',raw),userPublicKey=user)
            raw,_,user=credentials(index+1,incoming,outgoing)
            clientpin=dict(self.pin(role+'-client.creds',raw),userPublicKey=user)
            binding={'instanceId':'plugin-one','credentials':clientpin}
            selected={'connection':connection,'caFile':ca,'accountPublicKey':account,server:serverpin,'bindings':[binding]}
            if role=='lifecycle':
                selected['stateDirectory']=str(self.root/'lifecycle-state')
                binding.update(pin=native_row()['owner']['pin'],workspace=None)
            self.value[role]=selected
        self.value['configurationRoutes']={'plugin-one':{'configurationRef':ref('configuration-one'),
            'authorityRef':ref('authority-one'),'scope':{'organizationId':'org-one','projectId':'project-one','workspaceId':None},
            'service':{'profileId':'profile-one','hubId':'hub-one','serviceInstanceId':'configuration-service',
                'serviceIdentityRef':ref('configuration-service'),'signingKeyRef':ref('configuration-issuer')},
            'resources':[{'ref':'config.json','file':'schemas/config.json'}]}}

    def selected(self):
        return self.load(write_native_host_selection(self.path,self.value))

    def subscription(self):
        row=native_row()
        source={'configurationRef':ref('subscription-configuration'),'schemaRef':'a'*4096,
                'sourceDigest':'sha256:'+'c'*64,'streamCreated':'2026-10-09T12:00:00Z'}
        row['facts']['domainBindings'].append({'id':'subscription','contractId':'configuration-change-subscribe',
            'action':'subscribe','resourceClass':'configuration','resourceIds':['subscription-configuration']})
        declaration={k:row[k] for k in ('identityRef','manifestDigest','configurationChecksum','facts')}
        declaration.update(recordRef=row['ref'],previousRef=None,pin=row['owner']['pin'],configurationEventSources=[source])
        self.value['activationDeclarations']={'plugin-one':declaration}
        self.value['subscriptionRoutes']=[{'bindingId':'subscription','source':copy.deepcopy(source),
            'service':copy.deepcopy(self.value['configurationRoutes']['plugin-one']['service']),
            'scope':copy.deepcopy(row['facts']['grant']['scope'])}]

    def test_explicit_subscription_routes_admit_exact_credential_subject_and_transport(self):
        self.subscription()
        preliminary=NativeHostSelection(canonical_bytes(self.value))
        raw,account,user=credentials(2,list(preliminary.publish_subjects()),[self.value['credentials']['replyPrefix']+'.>'])
        self.value['credentials'].update(self.pin('authority.creds',raw),accountPublicKey=account,userPublicKey=user)
        selected=self.selected()
        transport=selected.subscription_transport_options('subscription','subscription-configuration')
        self.assertEqual(transport['subject'],
            'amx.v1.h.hub-one.o.org-one.p._.w._.configuration.subscription-configuration.command')
        self.assertEqual(transport['credentialsFile'],self.value['credentials']['path'])
        self.assertEqual(transport['connection'],self.value['connection'])
        self.assertEqual(transport['replyPrefix'],self.value['credentials']['replyPrefix'])
        routes=selected.subscription_routes();routes[0]['source']['schemaRef']='changed'
        self.assertEqual(len(selected.subscription_routes()[0]['source']['schemaRef']),4096)
        with self.assertRaises(ContractError):selected.subscription_transport_options('wrong','subscription-configuration')

    def test_subscription_source_scope_signer_and_declaration_mismatches_refuse(self):
        self.subscription()
        for mutate in (lambda v:v.pop('activationDeclarations'),
                       lambda v:v['subscriptionRoutes'].append(copy.deepcopy(v['subscriptionRoutes'][0])),
                       lambda v:v['subscriptionRoutes'][0]['source'].update(sourceDigest='sha256:'+'d'*64),
                       lambda v:v['subscriptionRoutes'][0]['source'].update(streamCreated='2026-10-09T12:00:01Z'),
                       lambda v:v['subscriptionRoutes'][0]['source'].update(schemaRef='other.json'),
                       lambda v:v['subscriptionRoutes'][0]['scope'].update(projectId='other'),
                       lambda v:v['subscriptionRoutes'][0]['service']['signingKeyRef'].update(ownerHubId='other'),
                       lambda v:v['subscriptionRoutes'][0]['service'].update(profileId='other'),
                       lambda v:v['activationDeclarations']['plugin-one']['facts']['domainBindings'][-1].update(action='read')):
            candidate=copy.deepcopy(self.value);mutate(candidate)
            with self.assertRaises(ContractError):write_native_host_selection(self.root/'invalid.json',candidate)
        absent=copy.deepcopy(self.value);del absent['subscriptionRoutes']
        with self.assertRaises(ContractError):NativeHostSelection(canonical_bytes(absent)).subscription_routes()

    def test_subscription_subjects_cannot_exceed_existing_credential_limit(self):
        self.subscription()
        declaration=self.value['activationDeclarations']['plugin-one']
        route=self.value['subscriptionRoutes'][0]
        route['source']['schemaRef']='config.json'
        declaration['configurationEventSources'][0]['schemaRef']='config.json'
        for i in range(20):
            extra=copy.deepcopy(route);extra['source']['configurationRef']['id']='config-'+str(i)
            self.value['subscriptionRoutes'].append(extra)
            declaration['configurationEventSources'].append(copy.deepcopy(extra['source']))
            declaration['facts']['domainBindings'][-1]['resourceIds'].append('config-'+str(i))
        self.assertLessEqual(len(canonical_bytes(self.value)),65536)
        with self.assertRaises(ContractError):write_native_host_selection(self.path,self.value)

    def test_subscription_route_requires_exactly_one_matching_declaration(self):
        from types import SimpleNamespace
        self.subscription()
        for field in ('lifecycle','contextTransport','configurationRoutes'):
            del self.value[field]
        other=copy.deepcopy(self.value['activationDeclarations']['plugin-one'])
        other.update(recordRef=ref('other-native'),identityRef=ref('other-plugin'))
        other['facts']['grant']['subjectInstanceId']='plugin-two'
        other['facts']['policy']['subjectInstanceId']='plugin-two'
        self.value['activationDeclarations']['plugin-two']=other
        self.value['destinations']['plugin-two']='task-owner'
        routes=self.value.pop('subscriptionRoutes')
        self.load(write_native_host_selection(self.path,self.value))
        self.value['subscriptionRoutes']=routes
        with self.assertRaisesRegex(ContractError,'native_host_selection_invalid'):
            write_native_host_selection(self.root/'ambiguous.json',self.value)
        raw=canonical_bytes(self.value)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ContractError,'native_host_selection_invalid'):
            self.load(SimpleNamespace(digest='sha256:'+hashlib.sha256(raw).hexdigest()))

    def test_real_credentials_and_independent_trust_map_to_go_inputs(self):
        preliminary=NativeHostSelection(canonical_bytes(self.value))
        raw,account,user=credentials(2,list(preliminary.publish_subjects()),[self.value['credentials']['replyPrefix']+'.>'])
        self.value['credentials'].update(self.pin('authority.creds',raw),accountPublicKey=account,userPublicKey=user)
        selected=self.selected()
        driver,context=selected.driver_options(),selected.context_options()
        self.assertEqual(driver['serverURL'],'tls://127.0.0.1:4310')
        self.assertEqual(context['serverURL'],'tls://127.0.0.1:4312')
        self.assertEqual(driver['bindings'][0]['pin'],native_row()['owner']['pin'])
        self.assertNotIn('workspace',driver['bindings'][0])
        self.assertEqual(selected.lifecycle_trust_options(),self.value['lifecycle']['connection'])
        self.assertEqual(selected.context_trust_options(),self.value['contextTransport']['connection'])
        self.assertIn('amx.v1.h.hub-one.o.org-one.p.project-one.w._.configuration.configuration-one.command',selected.publish_subjects())
        self.assertNotIn('amx.v1.h.hub-one.o.org-one.p._.w._.configuration.configuration-one.command',selected.publish_subjects())
        route=selected.configuration_routes();route['plugin-one']['service']['hubId']='other'
        self.assertEqual(selected.configuration_routes()['plugin-one']['service']['hubId'],'hub-one')
        transport=selected.configuration_transport_options('plugin-one')
        self.assertEqual(transport['subject'],'amx.v1.h.hub-one.o.org-one.p.project-one.w._.configuration.configuration-one.command')
        self.assertEqual(transport['replyPrefix'],self.value['credentials']['replyPrefix'])
        with self.assertRaises(ContractError):selected.configuration_transport_options('other')

    def test_material_digest_ca_and_exact_permissions_refuse_changes(self):
        selected=self.selected()
        pin=self.value['lifecycle']['controllerCredentials']
        Path(pin['path']).write_bytes(b'changed')
        with self.assertRaises(ContractError):selected.driver_options()
        candidate=copy.deepcopy(self.value)
        prefix='amx.v1.h.hub-one.plugins.plugin-one.'
        raw,_,_=credentials(10,[prefix+'lifecycle.control','amx.v1.>'],[prefix+'lifecycle.event'])
        candidate['lifecycle']['controllerCredentials'].update(self.pin('expanded.creds',raw))
        with self.assertRaises(ContractError):NativeHostSelection(canonical_bytes(candidate)).driver_options()
        ca=self.value['contextTransport']['caFile']
        Path(ca['path']).write_bytes(b'changed')
        with self.assertRaises(ContractError):selected.context_options()

    def test_wrong_binding_reused_users_paths_routes_and_trust_refuse_admission(self):
        for mutate in (lambda v:v['lifecycle']['bindings'][0].update(instanceId='other'),
                       lambda v:v['contextTransport'].update(serverCredentials=v['lifecycle']['controllerCredentials']),
                       lambda v:v['contextTransport']['connection'].update(endpoint='tls://remote:4222'),
                       lambda v:v['contextTransport']['connection'].update(endpoint='tls://127.0.0.1:4312\n'),
                       lambda v:v['contextTransport']['connection'].update(leafCertificateSHA256='sha256:'+'a'*64+'\n'),
                       lambda v:v['lifecycle'].update(stateDirectory=v['workspaces'][0]+'/state'),
                       lambda v:v['lifecycle']['bindings'][0].update(workspace='/unadmitted'),
                       lambda v:v['configurationRoutes']['plugin-one']['authorityRef'].update(id='other'),
                       lambda v:v['configurationRoutes']['plugin-one']['service'].update(hubId='other'),
                       lambda v:v['configurationRoutes']['plugin-one']['service'].update(serviceInstanceId='configuration-service\n'),
                       lambda v:v['configurationRoutes']['plugin-one']['resources'][0].update(file='../outside'),
                       lambda v:v['configurationRoutes']['plugin-one']['scope'].update(organizationId='other')):
            candidate=copy.deepcopy(self.value);mutate(candidate)
            with self.assertRaises(ContractError):write_native_host_selection(self.root/'invalid.json',candidate)

    def test_no_fallback_for_missing_production_inputs(self):
        for field,method in (('lifecycle','driver_options'),('contextTransport','context_options'),('configurationRoutes','configuration_routes')):
            candidate=copy.deepcopy(self.value);del candidate[field]
            with self.assertRaises(ContractError):getattr(NativeHostSelection(canonical_bytes(candidate)),method)()
