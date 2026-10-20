"""Coordinated selected policy factory, enrolled client and original source check.

The controlled restart suite covers all shared source families. This live case
uses one knowledge source and the existing native TLS/JWT broker fixture.
"""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import secrets
import unittest
from unittest.mock import patch

import nkeys
from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import ref, SEED
from identity.application_client import load_application_client, provision_application_client
from identity.application_service_selection import ApplicationServiceSelection
from identity.federation_policy_selection import federation_policy_service_policy, policy_target
from identity.transitions import transition
from identity.peer_control import HEADER, control_claims
from identity import test_federation_policy_service_selection as selection_fixture
from state_owner import test_task_live as live_fixture
from state_owner import test_configuration_activation as events
from state_owner.ledger import OwnerBinding, owner_subject
from state_owner.backup_host import BackupHost
from state_owner.federation_policy import _digest
from native_security.nats_credentials import storage_receiver_policy, _JWT, _SEED, _base32
from dashboard.application_service_host import ApplicationServiceHost
from hub.server import Hub
from hub.store import Store
from hub.fed import envelope
from hub.fed.peer_control import HEADER_REPOSITORY
from .selected_storage import SelectedStorageHost


@unittest.skipUnless(os.environ.get('AMX_SELECTED_POLICY_LIVE') == '1', 'Coordinated selected policy live slot required')
class SelectedPolicyLiveTests(live_fixture.LiveLegacyAliasApplicationTests):
    data_domain = data_kind = 'configuration'
    task_id = 'configuration-one'
    broker_stream_limit = 4
    response_ttls = {'storage': '12s'}
    policy_seed = bytes([53])*32

    def setUp(self):
        fixture = selection_fixture.FederationPolicySelectionTests()
        fixture.setUp()
        for fn, args, kwargs in fixture._cleanups:
            self.addCleanup(fn, *args, **kwargs)
        fixture._cleanups.clear()
        self.value = copy.deepcopy(fixture.value)
        self.value['storage'].pop('privateStorage')
        self.project = copy.deepcopy(self.value['storage']['scope'])
        self.fp = self.value['federationPolicy']
        self.knowledge = self.value['storage']['knowledge']
        self.path = Path(self.knowledge['source']['policy']['path'])
        canonical_path = self.path.with_name('federation.toml')
        self.path.rename(canonical_path)
        self.path = canonical_path
        self.knowledge['source']['policy']['path'] = str(self.path)
        self.fp['target']['source'] = copy.deepcopy(self.knowledge['source'])
        self.old = self.path.read_bytes()
        seed_store = Store(self.knowledge['source']['database']['path'])
        try:
            seed_store.db.execute('INSERT INTO p_knowledge_items(id,rid,repo,from_peer,title,body,at) VALUES (?,?,?,?,?,?,?)',
                ('finding-kept',self.knowledge['repository']['repositoryId'],'falcon','alice','Retained','original searchable finding','2026-10-17'))
        finally:
            seed_store.db.close()
        self.knowledge['channels'][0]['initialSource'] = {'kind':'knowledge','id':'finding-kept'}
        self.fp['service']['owner']['instanceId'] = 'federation-policy-one'
        self.apps, self.storage_hosts = [], []
        self.policy_client = None
        self.hub = None
        self.receiver_seeds = {'storage': bytes([51])*32, 'outcome': bytes([52])*32}

    def configure_broker_policies(self, policies, reads):
        # The inherited identity owner remains organization scoped; only the
        # dedicated configuration aggregate and selected storage are project scoped.
        self.bindings['DATA'] = OwnerBinding('hub-one', 'configuration', self.task_id,
            'configuration', canonical_bytes(self.project))
        self.subjects['DATA'] = owner_subject(self.bindings['DATA'])
        selected = federation_policy_service_policy(hub_id='hub-one', entity_id=self.task_id,
            scope=self.project, stream='DATA', reply_prefix=self.inbox_prefixes['storage'], artifact_bucket='POLICY')
        self.read_subject = selected.command_subject
        policies['storage'] = {'publish': {'allow': list(selected.publish_subjects)},
            'subscribe': {'allow': [s for s in selected.subscribe_subjects if s != self.inbox_prefixes['storage']+'.>']}}
        policies['host']['publish']['allow'] = [self.identity_subject, self.read_subject]
        self.inbox_prefixes['application'] = '_INBOX.'+secrets.token_hex(16)
        policies['application'] = {'publish': {'allow': [self.identity_subject, self.read_subject]}, 'subscribe': {'allow': []}}
        for name in ('storage','outcome'):
            role = 'receiver-'+name
            self.inbox_prefixes[role] = '_INBOX.'+secrets.token_hex(16)
            policy = storage_receiver_policy(hub_id='hub-one', scope=self.project,
                service_id=name+'-owner', reply_prefix=self.inbox_prefixes[role])
            policies[role] = {'publish': {'allow': list(policy.publish_subjects)},
                'subscribe': {'allow': [s for s in policy.subscribe_subjects if s != self.inbox_prefixes[role]+'.>']}}
        for role in ('control-alice', 'control-receiver'):
            self.inbox_prefixes[role] = '_INBOX.'+secrets.token_hex(16)
        policies['control-alice'] = {'publish': {'allow':['am.ctl.alice']}, 'subscribe': {'allow':[]}}
        policies['control-receiver'] = {'publish': {'allow':[]}, 'subscribe': {'allow':['am.ctl.alice']}}

    def _configure_tls_and_users(self):
        super()._configure_tls_and_users()
        paths = list((self.directory/'nsc-keys').rglob(self.account_public_key+'.nk'))
        self.assertEqual(len(paths),1)
        account = nkeys.from_seed(paths[0].read_bytes().strip())
        try:
            for name in ('storage','outcome'):
                path = self.credentials['receiver-'+name]
                raw = path.read_bytes()
                token = _JWT.findall(raw)[0]
                header,body,_ = token.split(b'.')
                claims = strict_loads(base64.urlsafe_b64decode(body+b'='*(-len(body)%4)))
                claims['nats']['pub'] = {'allow':[]}
                claims['nats']['resp'] = {'max':1,'ttl':5_000_000_000}
                claims.pop('jti',None)
                unsigned = header+b'.'+base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                signed = unsigned+b'.'+base64.urlsafe_b64encode(account.sign(unsigned)).rstrip(b'=')
                path.write_bytes(raw.replace(token,signed,1))
            for role in ('control-alice', 'control-receiver'):
                path = self.credentials[role]
                raw = path.read_bytes()
                token = _JWT.findall(raw)[0]
                header,body,_ = token.split(b'.')
                claims = strict_loads(base64.urlsafe_b64decode(body+b'='*(-len(body)%4)))
                if role == 'control-alice':
                    claims['nats']['pub'] = {'allow':['am.ctl.alice']}
                    claims['nats']['sub'] = {'allow':[], 'deny':['>']}
                else:
                    claims['nats']['pub'] = {'allow':[], 'deny':['>']}
                    claims['nats']['sub'] = {'allow':['am.ctl.alice']}
                claims['nats'].pop('resp',None)
                claims.pop('jti',None)
                unsigned = header+b'.'+base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                signed = unsigned+b'.'+base64.urlsafe_b64encode(account.sign(unsigned)).rstrip(b'=')
                path.write_bytes(raw.replace(token,signed,1))
        finally:
            account.wipe()

    def validate_source_credential(self):
        from identity.federation_policy_selection import validate_federation_policy_service
        validate_federation_policy_service(self.credentials['storage'].read_bytes(), account_public_key=self.account_public_key,
            hub_id='hub-one', entity_id=self.task_id, scope=self.project, stream='DATA',
            reply_prefix=self.inbox_prefixes['storage'], artifact_bucket='POLICY')

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        policy_public = base64.urlsafe_b64encode(bytes(SigningKey(self.policy_seed).verify_key)).decode().rstrip('=')
        state['identities'].append({'ref':ref('policy-service'),'kind':'service','status':'active',
            'principalId':'policy-service','externalIdentity':None})
        signer = copy.deepcopy(state['issuers'][0])
        signer.update(ref=ref('policy-issuer'),identityRef=ref('policy-service'),publicKey=policy_public)
        state['issuers'].append(signer)
        state['memberships'].append({**copy.deepcopy(state['memberships'][0]),'ref':ref('policy-member'),
            'identityRef':ref('policy-service'),'scope':copy.deepcopy(self.project)})
        base = copy.deepcopy(state['grants'][0])
        for name, caller, contract in (('policy-read',ref('human'),'configuration-read'),
                ('policy-set',ref('human'),'configuration-set'), ('policy-backup',ref('policy-service'),'configuration-read'),
                ('policy-project',ref('policy-service'),'federation-policy-project')):
            state['grants'].append({**copy.deepcopy(base), 'ref':ref(name), 'callerRef':caller, 'actorRef':caller,
                'scope':copy.deepcopy(self.project), 'contractId':contract, 'resourceId':self.task_id})
        state['transports'].append({**copy.deepcopy(state['transports'][0]), 'ref':ref('policy-reader'),
            'identityRef':ref('policy-service'), 'publicKey':policy_public})
        events.enroll_event_producer(state,self.project)
        for collection in ('transports','memberships','grants'):
            for row in state[collection]:
                if row['ref']['id'].startswith('configuration-event-'):
                    if collection == 'transports':
                        row['issuerRef'] = ref('policy-issuer')
                    for field in ('identityRef','callerRef','actorRef'):
                        if field in row:
                            row[field] = ref('policy-service')
        state['identities'].append({'ref':ref('plugin-one'),'kind':'plugin','status':'active',
            'principalId':'plugin-one','externalIdentity':None})
        for name, seed in self.receiver_seeds.items():
            state['identities'].append({'ref':ref(name+'-service'),'kind':'service','status':'active',
                'principalId':name+'-service','externalIdentity':None})
            signer = copy.deepcopy(state['issuers'][0])
            signer.update(ref=ref(name+'-issuer'), identityRef=ref(name+'-service'), instanceId=name+'-instance',
                publicKey=base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('='))
            state['issuers'].append(signer)
        control_credentials = {}
        for name, role in (('control-peer','control-alice'), ('control-receiver','control-receiver')):
            credential = self.credential(role)
            control_credentials[name] = {k:credential[k] for k in ('path','sha256','userPublicKey')}
            public = _base32(credential['userPublicKey'].encode('ascii'),35)[1:-2]
            state['identities'].append({'ref':ref(name),'kind':'service','status':'active',
                'principalId':name,'externalIdentity':None})
            state['transports'].append({**copy.deepcopy(state['transports'][0]),'ref':ref(name+'-transport'),
                'identityRef':ref(name),'issuerRef':ref('issuer'),
                'publicKey':base64.urlsafe_b64encode(public).decode().rstrip('=')})
            state['memberships'].append({'ref':ref(name+'-member'),'identityRef':ref(name),
                'scope':copy.deepcopy(self.project),'status':'active'})
        state['grants'].append({**copy.deepcopy(base),'ref':ref('control-peer-grant'),
            'callerRef':ref('control-peer'),'actorRef':ref('control-peer'),'scope':copy.deepcopy(self.project),
            'contractId':'peer-control-revoke','resourceId':'knowledge-one','decision':'allowed','delegationRef':None})
        connection = {'endpoint':self.broker.url,'serverName':self.server_name,
            'rootsPEM':self.ca_file.read_text(),'leafCertificateSHA256':self.leaf_digest}
        self.value['peerControl'] = {'routes':[{'routeId':'knowledge-alice','scope':copy.deepcopy(self.project),
            'resourceRef':copy.deepcopy(self.knowledge['channels'][0]['resourceRef']),
            'repository':copy.deepcopy(self.knowledge['repository']),
            'localPeer':self.knowledge['localPeer'],'localNode':self.knowledge['localNode'],
            'accountPublicKey':self.account_public_key,'connection':connection,
            'receiver':{'identityRef':ref('control-receiver'),'transportRef':ref('control-receiver-transport'),
                'credentials':control_credentials['control-receiver']},
            'peer':{'peerId':'alice','nodeId':'mac_alice','identityRef':ref('control-peer'),
                'transportRef':ref('control-peer-transport'),'grantRef':ref('control-peer-grant'),
                'userPublicKey':control_credentials['control-peer']['userPublicKey'],
                'credentialJWT':_JWT.findall(self.credentials['control-alice'].read_bytes())[0].decode('ascii')}}]}
        key_path = self.directory/'application-client.key'
        selection = load_application_client(key_path).selection
        selection['scope'] = copy.deepcopy(self.project)
        selection['transportRef'] = ref('policy-application-transport')
        selection.pop('localBrowserSessionOpen',None)
        selection.pop('legacyAliasResolve',None)
        self.fp['service']['ledger'].update(scope=copy.deepcopy(self.project), entityId=self.task_id)
        selected = ApplicationServiceSelection(canonical_bytes(self.value))
        selection['federationPolicyCommands'] = {
            'transportRef':ref('policy-human-transport'), 'grantRefs':{'configuration-read':ref('policy-read'),'configuration-set':ref('policy-set')},
            'subject':self.read_subject, 'replyIssuerRef':ref('policy-issuer'), 'replyIssuerPublicKey':policy_public,
            'serviceIdentityRef':ref('policy-service'), 'configurationRef':{'id':self.task_id,'ownerHubId':'hub-one','revision':0},
            'owner':copy.deepcopy(self.fp['service']['owner']), 'target':policy_target(selected.policy).descriptor,
            'keyRef':ref('policy-key'), 'originDigest':_digest(self.old),
            'repository':copy.deepcopy(self.knowledge['repository']), 'authenticatedCaller':'operator',
            'policyPath':str(self.path), 'localPeer':'nick'}
        key_path.unlink()
        now = datetime.now(timezone.utc)
        payload = provision_application_client(key_path, selection=selection, identity=state['identities'][0],
            issued_at=live_fixture.stamp(now-timedelta(seconds=30)), expires_at=live_fixture.stamp(now+timedelta(minutes=5)))
        initial['state'] = transition(state,'identity-enroll',payload,hub_id='hub-one')
        return initial

    def credential(self, role):
        raw = self.credentials[role].read_bytes()
        body = _JWT.findall(raw)[0].split(b'.')[1]
        claims = strict_loads(base64.urlsafe_b64decode(body+b'='*(-len(body)%4)))
        return {'path':str(self.credentials[role]), 'sha256':_digest(raw), 'userPublicKey':claims['sub'],
            'accountPublicKey':self.account_public_key, 'replyPrefix':self.inbox_prefixes[role]}

    def signer(self, role, seed, issuer):
        path = self.directory/(role+'.key')
        raw = canonical_bytes({'schemaVersion':'1.0.0','purpose':'agentmux-application-service-key-v1',
            'serviceId':role+'-owner','hubId':'hub-one','profileId':'profile-one','authorityId':'authority-one',
            'issuerRef':ref(issuer),'seed':base64.b64encode(seed).decode()})
        path.write_bytes(raw); path.chmod(0o600)
        return {'keyFile':{'path':str(path),'sha256':_digest(raw)},'issuerRef':ref(issuer),
            'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')}

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.addAsyncCleanup(self.close_selected)
        await self.connections[0].jetstream().create_object_store(bucket='POLICY',max_bytes=1_048_576)
        connection = {'endpoint':self.broker.url,'serverName':self.server_name,'rootsPEM':self.ca_file.read_text(),
            'leafCertificateSHA256':self.leaf_digest,'jetstreamDomain':None}
        identity = self.value['identity']
        identity.update(connection=copy.deepcopy(connection),credentials=self.credential('identity'),issuer=self.signer('identity',SEED,'issuer'))
        ledger = self.identity.ledger
        identity['ledger'].update(stream='IDENTITY',scope=copy.deepcopy(self.scope),
            streamIdentity={'created':ledger._identity.created.isoformat().replace('+00:00','Z'),'minimumSequence':0},
            retention={'maxBytes':self.policy.max_bytes,'reserveBytes':self.policy.reserve_bytes,'replicas':1},
            history={'path':str(ledger._history._path),'maxRecords':ledger._history._max_records,'maxBytes':ledger._history._max_bytes})
        service = self.fp['service']
        service.update(connection=copy.deepcopy(connection),credentials=self.credential('storage'),
            issuer=self.signer('configuration',self.policy_seed,'policy-issuer'),requesterReplyPrefix=self.inbox_prefixes['application'])
        service['ledger'].update(stream='DATA',streamIdentity={'created':self.streams['DATA'].created.isoformat().replace('+00:00','Z'),'minimumSequence':0},
            retention={'maxBytes':self.policy.max_bytes,'reserveBytes':self.policy.reserve_bytes,'replicas':1})
        self.fp['backupAuthority'] = {'transportRef':ref('policy-reader'),'grantRef':ref('policy-backup')}
        self.fp['projectionAuthority'] = {'serviceIdentityRef':ref('policy-service'),'transportRef':ref('policy-reader'),'grantRef':ref('policy-project')}
        producer_path = self.directory/'event.key'
        producer_path.write_bytes(events.PRODUCER_SEED); producer_path.chmod(0o600)
        service['producer'] = {'identityRef':ref('policy-service'),'transportRef':ref('configuration-event-transport'),
            'grantRef':ref('configuration-event-grant'),'keyFile':{'path':str(producer_path),'sha256':_digest(events.PRODUCER_SEED)},
            'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(events.PRODUCER_SEED).verify_key)).decode().rstrip('=')}
        key_path = Path(self.fp['key']['path']); key_path.write_bytes(bytes(range(32))); key_path.chmod(0o600)
        for name, receiver in self.value['storage']['receivers'].items():
            receiver.update(connection=copy.deepcopy(connection),credentials=self.credential('receiver-'+name),
                issuer=self.signer(name,self.receiver_seeds[name],name+'-issuer'),requestSigningKeyRef=ref('issuer'))
        from agentmux_contracts.validation import _validators, DEFAULT_SCHEMA_DIR
        errors = list(_validators(DEFAULT_SCHEMA_DIR)['application-service-selection'].iter_errors(self.value))
        if errors:
            raise AssertionError([(list(e.path),e.message) for e in errors])
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        backup = service['backup']
        owner_backup = BackupHost(*(backup[k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'],binding=self.bindings['DATA'],stream_identity=self.streams['DATA'])
        owner_backup.enroll_key(backup['keyId'])
        await self.start_selected()
        self.session = await self.open_application_session()
        from hub import server as hub_server
        (self.path.parent/'operator.token').write_text('operator-secret')
        (self.path.parent/'operator.token').chmod(0o600)
        with patch.object(hub_server,'ROOT',str(self.path.parent/'root')), \
                patch.object(hub_server,'HUBDIR',str(self.path.parent)), \
                patch.object(hub_server,'SOCK',str(self.path.parent/'hub.sock')):
            self.hub = Hub(policy_sessions=(self.session,))
        await self.hub.db(self.hub.store.repo_add,'falcon')
        self.fed,self.policy_client = self.hub.fed,self.hub._policy_commands

    async def start_selected(self):
        app = ApplicationServiceHost(self.selection,browser_port=0)
        app._identity = self.identity
        self.apps.append(app)
        await app._start_federation_policy()
        self.selected = SelectedStorageHost(self.selection,identity=self.identity,federation_policy=app._federation_policy)
        self.storage_hosts.append(self.selected)
        try:
            await self.selected.start()
        except Exception as error:
            if getattr(error,'_cause',None) is not None:
                raise error._cause
            raise
        self.actual_policy = app._federation_policy

    async def close_selected(self):
        if self.policy_client is not None:
            await self.policy_client.close(timeout=None)
        if self.hub is not None:
            await self.hub.db(self.hub.store.db.close)
            self.hub.dbx.shutdown(wait=True)
            self.hub.io.shutdown(wait=True)
            self.hub = None
        for storage in reversed(self.storage_hosts):
            await storage.close(timeout=None)
        for app in reversed(self.apps):
            # Identity is borrowed from the existing broker fixture.
            app._identity = None
            await app.close()
            self.assertTrue(app._federation_policy.done.is_set())
            self.assertTrue(all(key._fd is None for key in app._federation_policy_keys))
        self.assertTrue(all(host._closing.done() for host in self.storage_hosts))

    async def request_hub(self, verb, arguments):
        self.refresh_application_observation()
        from . import test_peer_control_command_live as socket_fixture
        return await socket_fixture.LivePeerControlCommandTests.hub_request(self,self.hub,
            {'token':'operator-secret','verb':verb,'args':arguments})

    def control_ingress(self):
        self.assertEqual(len(self.selected._knowledge_controls),1)
        controls = self.selected._knowledge_controls[0]
        self.assertEqual(len(controls._routes),1)
        ingress = next(iter(controls._routes.values()))
        self.assertIs(ingress._store_owner,self.selected._preconstructed_sources['knowledge'])
        return ingress

    async def retain_control_receipt(self, ingress, item):
        received = asyncio.Event()
        dispatch = ingress._dispatch
        async def observed(message, handle):
            await dispatch(message,handle)
            received.set()
        ingress._dispatch = observed
        key = nkeys.from_seed(_SEED.findall(self.credentials['control-alice'].read_bytes())[0])
        try:
            signature = base64.b64encode(key.sign(canonical_bytes(control_claims(
                ingress._pin,item,'am.ctl.alice')))).decode('ascii')
        finally:
            key.wipe()
        try:
            publisher = await self.connect('control-alice')
            await publisher.publish('am.ctl.alice',canonical_bytes(item),headers={HEADER:signature,
                HEADER_REPOSITORY:ingress._pin['repository']['repositoryId']})
            await publisher.flush(timeout=1)
            await asyncio.wait_for(received.wait(),3)
        finally:
            ingress._dispatch = dispatch
        handle = await ingress.recover(item['id'],payload_digest(item))
        return await ingress.consume(handle,peer='alice',repository_id=self.knowledge['repository']['repositoryId'])

    async def test_selected_owner_enrolled_hub_policy_changes_preserve_original_source(self):
        source = self.selected._preconstructed_sources['knowledge']
        resource = self.selected._resources[0]
        original_bytes = await resource.read(1)
        original_journal = resource._journal.binding
        control = self.control_ingress()
        original_control_binding = control._route
        event = envelope.make('revoke','alice','mac_alice',data={'reason':'Retained control before unshare'})
        original_receipt = await self.retain_control_receipt(control,event)
        actual_connection = self.session._owner._client
        actual_session_owner = self.session._owner
        # Drop only the actual signed final response after commit/projection.
        # All requests, preparation, owner effects and later reads stay real.
        connection = self.actual_policy.owner._connection
        publish = connection.publish
        dropped = []
        async def lose_final(subject, payload=b'', *args, **kwargs):
            if subject.startswith(self.inbox_prefixes['application']+'.'):
                try:
                    reply = strict_loads(payload)
                except Exception:
                    reply = {}
                if not dropped and reply.get('claims',{}).get('kind') == 'committed':
                    dropped.append(reply)
                    return
            return await publish(subject,payload,*args,**kwargs)
        change = {'peer':'alice','level':'flag','operationId':'live-trust-original'}
        with patch.object(connection,'publish',side_effect=lose_final):
            lost = await self.request_hub('fed_trust',change)
        self.assertFalse(lost['ok'],lost)
        self.assertEqual(len(dropped),1)
        first = await self.actual_policy.ledger.current()
        self.assertEqual(first.sequence,1)
        original_operation = strict_loads(first.latest.record)['operation']
        self.assertEqual(original_operation['operationId'],'live-trust-original')
        recovered = await self.request_hub('fed_trust',change)
        self.assertTrue(recovered['ok'],recovered)
        self.assertIs(self.session._owner,actual_session_owner)
        self.assertIs(self.session._owner._client,actual_connection)
        self.assertFalse(actual_connection.is_closed)
        self.assertEqual((await self.actual_policy.ledger.current()).sequence,1)
        self.assertEqual(await resource.read(1),original_bytes)
        self.assertEqual(source._policy.trust('alice'),'flag')
        result = await self.request_hub('fed_unshare',{'repo':'falcon','operationId':'live-unshare-original'})
        self.assertTrue(result['ok'],result)
        committed = await self.actual_policy.ledger.current()
        self.assertEqual(committed.sequence,2)
        unshared_operation = strict_loads(committed.latest.record)['operation']
        with self.assertRaises(ContractError):
            await resource.read(1)
        # Replace both configuration owner and selected source from the same
        # protected selection while the committed policy remains unshared.
        old_store = source._store
        await self.selected.close(timeout=None)
        self.apps[-1]._identity = None
        await self.apps[-1].close()
        await self.start_selected()
        source = self.selected._preconstructed_sources['knowledge']
        replacement = self.selected._resources[0]
        control = self.control_ingress()
        self.assertEqual(control._route,original_control_binding)
        self.assertEqual(self.selected._startup_permits,{})
        self.assertIsNot(source._store,old_store)
        self.assertEqual(replacement._journal.binding,original_journal)
        self.assertEqual(strict_loads((await self.actual_policy.ledger.current()).latest.record)['operation'],unshared_operation)
        with self.assertRaises(ContractError):
            await replacement.read(1)
        with self.assertRaises(ContractError):
            await control.recover(event['id'],payload_digest(event))
        result = await self.request_hub('fed_share',{'repo':'falcon','remote':'example.invalid/falcon',
            'peers':['*'],'operationId':'live-reshare-original'})
        self.assertTrue(result['ok'],result)
        self.assertEqual((await self.actual_policy.ledger.current()).sequence,3)
        self.assertEqual(await replacement.read(1),original_bytes)
        handle = await control.recover(event['id'],payload_digest(event))
        self.assertEqual(await control.consume(handle,peer='alice',
            repository_id=self.knowledge['repository']['repositoryId']),original_receipt)
        self.assertEqual(len(await source.db(source._store.q,
            "SELECT * FROM p_knowledge_fts WHERE p_knowledge_fts MATCH 'searchable'")),1)
        self.assertEqual(await source.db(source._store.q,'SELECT * FROM fed_outbox'),[])
        await self.command('identity-revoke',ref('grant'),
            {'authorityId':'authority-one','targetRef':ref('control-peer-grant')})
        with self.assertRaises(ContractError):
            await control.recover(event['id'],payload_digest(event))
        await self.command('identity-revoke',ref('grant'),
            {'authorityId':'authority-one','targetRef':ref('policy-set')})
        refused = await self.request_hub('fed_trust',{'peer':'alice','level':'deny','operationId':'revoked-policy-write'})
        self.assertFalse(refused['ok'],refused)
        self.assertEqual((await self.actual_policy.ledger.current()).sequence,3)
        self.assertEqual(await replacement.read(1),original_bytes)
        # An unauthorized file edit cannot be treated as another accepted policy.
        self.path.write_bytes(self.path.read_bytes()+b'\n# unapproved edit\n')
        with self.assertRaises(ContractError):
            await replacement.read(1)
        self.assertEqual((await self.actual_policy.ledger.current()).sequence,3)
        self.success = True


# Borrow fixture lifetimes and enrollment, not its unrelated product exercises.
for _name in dir(live_fixture.LiveLegacyAliasApplicationTests):
    if _name.startswith('test_'):
        setattr(SelectedPolicyLiveTests,_name,None)
