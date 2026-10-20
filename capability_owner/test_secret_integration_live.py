"""Normal selected Secret.Use host through actual native handle, NATS and HTTPS."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import secrets
import unittest

import nkeys
from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from capability_owner.secret_host import SecretUseHost
from capability_owner.secret_journal import PHASE_CONTRACTS
from capability_owner.test_live import LiveCapabilityTests, stamp
from capability_owner.test_secret_journal_admission_live import LiveSecretJournalAdmissionTests
from identity.application_service_selection import ApplicationServiceSelection
from identity.secret_selection import receiver_policy
from identity.test_application_service_selection import ServiceSelectionTests
from identity.test_authority import ref, SEED
from identity.test_native_bridge import native_row, HOST_SEED
from identity.test_ordinary_secret import SCOPE
from native_security.nats_credentials import _JWT


class SecretIntegrationLiveTests(unittest.IsolatedAsyncioTestCase):
    class Fixture(LiveSecretJournalAdmissionTests):
        private_child = True
        recovery_checks = True
        read_class, read_action, read_contract = 'secret', 'use', 'capability-secret-use'
        service_id = 'secret-owner'
        wait_handoff = LiveCapabilityTests.wait_handoff
        start_go_child = LiveCapabilityTests.start_go_child

        def secret_scope(self):
            return copy.deepcopy(SCOPE)

        def configure_broker_policies(self, policies, reads):
            super().configure_broker_policies(policies, reads)
            self.secret_subject = 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.secret-owner.command'
            self.outcome_subject = self.secret_subject.replace('.secret-owner.', '.outcome-owner.')
            policies['host']['publish']['allow'] = [self.identity_subject, self.secret_subject, self.outcome_subject]
            for name in ('secret', 'outcome'):
                role = 'selected-' + name
                prefix = self.inbox_prefixes[role] = '_INBOX.' + secrets.token_hex(16)
                policy = receiver_policy(hub_id='hub-one', scope=self.secret_scope(),
                    service_id=name+'-owner', reply_prefix=prefix)
                policies[role] = {'publish': {'allow': list(policy.publish_subjects)},
                    'subscribe': {'allow': list(policy.subscribe_subjects)}}

        def _configure_tls_and_users(self):
            super()._configure_tls_and_users()
            paths = list((self.directory/'nsc-keys').rglob(self.account_public_key+'.nk'))
            if len(paths) != 1:
                raise RuntimeError('secret_fixture_account_unavailable')
            account = nkeys.from_seed(paths[0].read_bytes().strip())
            try:
                for name in ('secret', 'outcome'):
                    role = 'selected-' + name
                    path = self.credentials[role]
                    raw = path.read_bytes()
                    token = _JWT.findall(raw)[0]
                    header, body, _ = token.split(b'.')
                    claims = strict_loads(base64.urlsafe_b64decode(body+b'='*(-len(body)%4)))
                    policy = receiver_policy(hub_id='hub-one', scope=self.secret_scope(),
                        service_id=name+'-owner', reply_prefix=self.inbox_prefixes[role])
                    claims['nats'].update(pub={'allow': list(policy.publish_subjects)},
                        sub={'allow': list(policy.subscribe_subjects)}, resp=policy.response_permissions)
                    claims.pop('jti', None)
                    body = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                    updated = header+b'.'+body
                    updated += b'.'+base64.urlsafe_b64encode(account.sign(updated)).rstrip(b'=')
                    path.write_bytes(raw.replace(token, updated, 1))
            finally:
                account.wipe()

        def initial_authority(self):
            initial = super().initial_authority()
            state = initial['state']
            now = datetime.now(timezone.utc)
            interval = {'status': 'active', 'issuedAt': stamp(now-timedelta(seconds=30)),
                'expiresAt': stamp(now+timedelta(minutes=5))}
            for name, kind in (('host', 'service'), ('plugin', 'plugin'), ('parent-plugin', 'plugin')):
                state['identities'].append({'ref': ref(name), 'kind': kind, 'status': 'active',
                    'principalId': name+'-one', 'externalIdentity': None})
            for index, name in enumerate(('secret', 'outcome')):
                state['identities'].append({'ref': ref(name+'-service'), 'kind': 'service', 'status': 'active',
                    'principalId': name+'-service', 'externalIdentity': None})
                state['issuers'].append({'ref': ref(name+'-signer'), 'identityRef': ref(name+'-service'),
                    'instanceId': name+'-one', 'publicKey': base64.urlsafe_b64encode(
                        bytes(SigningKey(bytes([61+index])*32).verify_key)).decode().rstrip('='), **interval})
            template = copy.deepcopy(state['transports'][0])
            state['transports'].append({**template, 'ref': ref('host-transport'), 'identityRef': ref('host'),
                'publicKey': base64.urlsafe_b64encode(bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('=')})
            state['memberships'].append({'ref': ref('secret-host-member'), 'identityRef': ref('host'),
                'scope': self.secret_scope(), 'status': 'active'})
            base = copy.deepcopy(state['grants'][0])
            for instance in ('plugin-one', 'parent-one'):
                for method in ('bind-instance', 'admit-operation', 'recheck', 'prepare-domain-call'):
                    state['grants'].append({**copy.deepcopy(base), 'ref': ref('secret-'+instance+'-'+method),
                        'callerRef': ref('host'), 'actorRef': ref('host'), 'scope': self.secret_scope(),
                        'contractId': 'native-authority-'+method, 'resourceId': instance})
            state['grants'].append({**copy.deepcopy(base), 'ref': ref('secret-native-admin'),
                'contractId': 'identity-native-instance-set', 'resourceId': 'authority-one'})
            state['grants'].append({**copy.deepcopy(base), 'ref': ref('secret-account-service-grant'),
                'callerRef': ref('custody'), 'actorRef': ref('custody'), 'scope':copy.deepcopy(SCOPE),
                'contractId': 'identity-application-account-resolve', 'resourceId': 'application-account'})
            self.row = native_row()
            facts = self.row['facts']
            facts['grant'].update(scope=self.secret_scope(), actions=['use', 'inspect'], resourceIds=['ordinary-one'])
            facts['policy'].update(scope=self.secret_scope(), decisions=[{'access': {
                'action': action, 'resourceClass': resource, 'resourceId': 'ordinary-one'}, 'outcome': 'allow'}
                for action, resource in (('use', 'secret'), ('inspect', 'outcome'))])
            facts['secretReferences'] = [ref('ordinary-one')]
            facts['domainBindings'] = [{'id': binding, 'contractId': contract, 'action': action,
                'resourceClass': resource, 'resourceIds': ['ordinary-one']} for binding, contract, action, resource in (
                    ('secret-use', 'capability-secret-use', 'use', 'secret'),
                    ('messages-outcome', 'capability-outcome-query', 'inspect', 'outcome'))]
            for target in (facts['grant'], facts['policy']):
                target.update(issuedAt=interval['issuedAt'], expiresAt=interval['expiresAt'])
            return initial

        async def asyncSetUp(self):
            await super().asyncSetUp()
            self.go_process = self.go_wait = self.go_output = None
            self.secret_host = None
            self.addAsyncCleanup(self.close_secret_fixture)
            await self.stage_administrator()
            await self.stage()
            support = ServiceSelectionTests()
            support.addCleanup = self.addCleanup
            support.setUp()
            value = copy.deepcopy(support.value)
            identity = value['identity']
            ledger, history = self.identity.ledger, self.identity.ledger._history
            identity['ledger'].update(stream='IDENTITY', scope=copy.deepcopy(self.scope),
                streamIdentity={'created': ledger._identity.created.isoformat().replace('+00:00','Z'), 'minimumSequence': 0},
                retention={'maxBytes': self.policy.max_bytes, 'reserveBytes': self.policy.reserve_bytes, 'replicas': 1},
                history={'path': str(history._path), 'maxRecords': history._max_records, 'maxBytes': history._max_bytes})
            connection = {'endpoint': self.broker.url, 'serverName': self.server_name,
                'rootsPEM': self.ca_file.read_text(), 'leafCertificateSHA256': self.leaf_digest, 'jetstreamDomain': None}
            identity['connection'] = copy.deepcopy(connection)
            credential = self.credential_pin('identity')
            identity['credentials'] = credential
            identity['issuer'] = self.issuer_pin('identity', SEED, ref('issuer'))
            receivers = {}
            for index, name in enumerate(('secret', 'outcome')):
                receivers[name] = {'connection': copy.deepcopy(connection),
                    'credentials': self.credential_pin('selected-'+name),
                    'issuer': self.issuer_pin(name, bytes([61+index])*32, ref(name+'-signer')),
                    'serviceIdentityRef': ref(name+'-service'), 'serviceInstanceId': name+'-one',
                    'requestSigningKeyRef': ref('issuer')}
            signer = {'transportRef': ref('custody-transport'), 'keyFile': self.raw_key('custody', bytes(reversed(SEED))),
                'publicKey': base64.urlsafe_b64encode(bytes(SigningKey(bytes(reversed(SEED))).verify_key)).decode().rstrip('='),
                'resolveGrant': ref('ordinary-resolve-grant'), 'phaseGrants': {name: ref(name) for name in PHASE_CONTRACTS}}
            account = {'accountRef': ref('application-account'), 'transportRef': ref('custody-transport'),
                'grantRef': ref('secret-account-service-grant'), 'keyFile': self.raw_key('account', bytes(reversed(SEED))),
                'publicKey': signer['publicKey']}
            value['ordinarySecret'] = {'scope': self.secret_scope(), 'record': copy.deepcopy(self.initial_secret),
                'pluginIdentityRef': ref('plugin'), 'instanceId': 'plugin-one', 'packageId': 'native_tls_capability_test',
                'custodyRoot': str(self.private_root), 'accountCustodyRoot': str(self.account_custody._store._root),
                'consumer': {'baseURL': self.enrollment.base_url, 'deployment': self.enrollment.deployment,
                    'email': self.enrollment.email, 'expectedAccount': self.enrollment.expected_account,
                    'rootsPEM': self.enrollment.trust_pem.decode()},
                'journal': {'namespace': 'INTEGRATION', 'connection': copy.deepcopy(connection),
                    'accountPublicKey': self.account_public_key, 'retention': {'maxBytes': 1048576, 'reserveBytes': 262144, 'replicas': 1},
                    'maxJournals': 2, 'maxTotalBytes': 2097152, 'inventoryRoot': str(self.inventory),
                    'observationRoot': str(self.private_root)}, 'signer': signer, 'account': account, 'receivers': receivers}
            self.selection = ApplicationServiceSelection(canonical_bytes(value))
            self.secret_host = SecretUseHost(self.selection, identity=self.identity)
            try:
                await self.secret_host.start()
            except Exception as error:
                raise error from getattr(error, '_cause', None)
            self.secret_host.check_health()

        def raw_key(self, name, raw):
            path = self.directory/(name+'-secret.key')
            path.write_bytes(raw)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': 'sha256:'+hashlib.sha256(raw).hexdigest()}

        def issuer_pin(self, name, seed, reference):
            body = canonical_bytes({'schemaVersion':'1.0.0','purpose':'agentmux-application-service-key-v1',
                'serviceId': name+'-owner', 'hubId':'hub-one','profileId':'profile-one','authorityId':'authority-one',
                'issuerRef':reference,'seed':base64.b64encode(seed).decode()})
            return {'keyFile':self.raw_key(name+'-issuer', body),'issuerRef':reference,
                'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')}

        def credential_pin(self, role):
            raw = self.credentials[role].read_bytes()
            token = _JWT.findall(raw)[0]
            claims = strict_loads(base64.urlsafe_b64decode(token.split(b'.')[1]+b'=='))
            return {'path':str(self.credentials[role]),'sha256':'sha256:'+hashlib.sha256(raw).hexdigest(),
                'accountPublicKey':self.account_public_key,'userPublicKey':claims['sub'],
                'replyPrefix':self.inbox_prefixes[role]}

        async def close_secret_fixture(self):
            if self.go_wait is not None:
                if not self.go_wait.done():
                    self.go_process.terminate()
                await asyncio.wait_for(asyncio.shield(self.go_wait), 3)
            if self.go_output is not None:
                self.go_output.close()
            if self.secret_host is not None:
                await self.secret_host.close(timeout=None)
                self.assertTrue(self.secret_host._closing.done())
                if self.secret_host._verification is not None:
                    self.assertIsNone(self.secret_host._verification._store._fd)
                self.assertTrue(all(not client.is_connected for client in self.secret_host._clients))

        async def qualify(self):
            refusals = []
            resource_events = []
            began = asyncio.get_running_loop().time()
            resource = self.secret_host._resource
            def observe_step(target, name):
                method = getattr(target, name)
                async def observed(*args, **kwargs):
                    resource_events.append(name+'-started-'+str(round(asyncio.get_running_loop().time()-began, 3)))
                    try:
                        result = await method(*args, **kwargs)
                    except ContractError as error:
                        resource_events.append(name+'-'+str(error))
                        if name == 'current':
                            for _, client, expires in resource._admission._resources.values():
                                resource_events.append('data-connected-'+str(client.is_connected)
                                    +'-remaining-'+str(round((expires-datetime.now(timezone.utc)).total_seconds(), 3)))
                        raise
                    resource_events.append(name+'-finished-'+str(round(asyncio.get_running_loop().time()-began, 3)))
                    if name == 'open':
                        for step in ('authorize', 'prepare', 'current', 'advance'):
                            observe_step(result, step)
                    return result
                setattr(target, name, observed)
            observe_step(resource._signer, 'account')
            observe_step(resource._signer, 'resolve')
            observe_step(resource._admission, 'open')
            original_call = resource.call
            async def observed_call(raw, proof):
                resource_events.append('started')
                try:
                    result = await original_call(raw, proof)
                    resource_events.append('returned-'+result.get('outcome', 'closed'))
                    return result
                except ContractError as error:
                    resource_events.append('refused-'+str(error))
                    raise
            resource.call = observed_call
            original_native = self.identity.native.handle
            async def observed_native(raw):
                try:
                    return await original_native(raw)
                except ContractError as error:
                    refusals.append(str(error))
                    raise
            self.identity.native.handle = observed_native
            await self.start_go_child()
            # The Go declaration fixes actual package/process identity before enrollment.
            self.row['facts']['parentAccess'] = copy.deepcopy(self.row['facts']['policy']['decisions'])
            self.row['facts']['parentAccess'] = [item['access'] for item in self.row['facts']['parentAccess']]
            for row in (self.parent, self.row):
                await self.command('identity-native-instance-set', ref('secret-native-admin'),
                    {'authorityId':'authority-one','record':row,'previousRef':None})
            original = await self.original_request()
            self.write_private('original-envelope.json', original)
            self.write_private('host-signing.seed', HOST_SEED, raw=True)
            metadata = await self.host.request('$JS.API.STREAM.INFO.IDENTITY', b'{}', timeout=2)
            snapshot = await self.identity.ledger.current()
            value = self.selection.policy['ordinarySecret']
            def service(name):
                receiver = value['receivers'][name]
                return {'profileId':'profile-one','hubId':'hub-one','serviceId':name+'-owner',
                    'serviceInstanceId':receiver['serviceInstanceId'],'serviceIdentityRef':receiver['serviceIdentityRef'],
                    'signingKeyRef':receiver['issuer']['issuerRef']}
            ready = {'serverUrl':self.broker.url,'authoritySubject':self.identity_subject,
                'capabilitySubject':self.secret_subject,'credentialsFile':str(self.credentials['host']),
                'caFile':str(self.ca_file),'tlsName':self.server_name,'leafCertificateSha256':self.leaf_digest,
                'accountPublicKey':self.account_public_key,'replyPrefix':self.inbox_prefixes['host'],
                'publishSubjects':[self.identity_subject,self.secret_subject,self.outcome_subject,
                    '$JS.API.STREAM.INFO.IDENTITY','$JS.API.STREAM.MSG.GET.IDENTITY'],
                'hostSigningSeedFile':str(self.directory/'host-signing.seed'),
                'originalEnvelopeFile':str(self.directory/'original-envelope.json'),
                'enrollment':{'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one',
                    'organizationId':'org-one','stream':'IDENTITY','domain':'','streamCreated':strict_loads(metadata.data)['created'],
                    'minimumSequence':snapshot.sequence,'maxBytes':self.policy.max_bytes,'replicas':1,
                    'hostTransportRef':ref('host-transport'),'hostIdentityRef':ref('host'),
                    'issuerRef':ref('issuer'),'issuerIdentityRef':ref('service'),'issuerInstanceId':'ingress-one'},
                'service':service('secret'),'outcomeService':service('outcome'),'outcomeSubject':self.outcome_subject,
                'bindingId':'secret-use','resourceRef':ref('ordinary-one'), 'requestContractId':'capability-secret-use',
                'replyContractId':'capability-secret-use-reply','requestInput':{'consumerRef':ref('consumer'),
                    'purposeRef':ref('purpose-one')},'revoked':False}
            self.write_private('fixture-ready.json', ready)
            try:
                await self.wait_handoff('go-result.json', lambda row:row.get('phase')=='read-complete')
            except RuntimeError as error:
                await self.secret_host.close(timeout=None)
                if refusals:
                    raise AssertionError('native provider refusal: ' + ','.join(refusals)) from error
                raise AssertionError('secret resource events: '+','.join(resource_events)
                    + '; HTTP count='+str(len(self.https_server.requests))) from error
            self.assertEqual(self.https_server.requests, [('GET','/rest/api/3/myself',True)])
            owners = tuple(self.secret_host._resource._owners.values())
            self.assertEqual(len(owners),1)
            retained = await owners[0]._journal.current()
            self.assertEqual(retained['state']['phase'],'finished')
            self.assertEqual(retained['state']['outcome'],'accepted')
            await self.command('identity-revoke',ref('grant'),{'authorityId':'authority-one',
                'targetRef':self.parent['ref']})
            ready['revoked']=True
            self.write_private('fixture-ready.json',ready)
            result=await self.wait_handoff('go-result.json',lambda row:row.get('phase')=='complete')
            self.assertEqual(result,{'phase':'complete','read':True,'revocation':True,'cleanup':True})
            self.assertEqual(await asyncio.wait_for(asyncio.shield(self.go_wait),3),0)
            self.assertEqual(len(self.https_server.requests),1)
            await self.secret_host.close(timeout=None)
            self.success=True

    @classmethod
    def setUpClass(cls):
        cls.Fixture.setUpClass()

    async def asyncSetUp(self):
        # Qualify the production event-loop mode within unchanged authority
        # deadlines; unittest's task stack tracing is not enabled by the host.
        asyncio.get_running_loop().set_debug(False)
        fixture=self.fixture=self.Fixture()
        fixture.addCleanup=self.addCleanup
        fixture.addAsyncCleanup=self.addAsyncCleanup
        await fixture.asyncSetUp()

    async def test_native_selected_secret_handle_receipt_query_and_parent_revocation(self):
        await self.fixture.qualify()
