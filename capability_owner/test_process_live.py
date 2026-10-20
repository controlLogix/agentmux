"""Selected Process host, actual Go caller and one native owned task.

The existing native credential fixture supplies the broker and selected Docker
engine. This case constructs the real selected identity, task and workspace
hosts before releasing the Go caller. It does not qualify installed startup.
"""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import nkeys
from nacl.signing import SigningKey
from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads
from execution_owner.test_native_delivery_live import NativeDeliveryExecutionTests
from execution_owner.retained import SERVICE_COMMANDS
from identity.application_service_selection import ApplicationServiceSelection
from identity.service import IdentityService
from identity.test_authority import ref, SEED
from identity.test_native_bridge import HOST_SEED
from identity.test_workspace_selection import WorkspaceSelectionTests
from identity.test_process_selection import add_process
from identity.process_selection import state_policy, receiver_policy
from identity.workspace_selection import load_workspace_signing_seed
from native_security.nats_credentials import service_policy, workspace_receiver_policy
from native_security.secret_custody import ScopedSecretCustody, _resolved_binding
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.history import OwnerHistory
from state_owner.task_host import TaskHost
from .process_host import ProcessHost
from .workspace_host import WorkspaceReadHost
from . import test_live as tls_support


TASK_SEED = bytes([42])*32


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def public(seed):
    return base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')


class ProcessBrokerFixture(tls_support.LiveCapabilityTests):
    """Keep the existing TLS setup; add only the selected host's exact roles."""
    def configure_broker_policies(self, policies, reads):
        owner = self.process_owner
        pin = owner.value['process']
        task = service_policy(role='task', hub_id='hub-one', entity_id='task-one',
            scope=owner.scope, stream='TASK', reply_prefix=owner.value['task']['credentials']['replyPrefix'])
        workspace = workspace_receiver_policy(hub_id='hub-one', scope=owner.scope,
            reply_prefix=owner.value['workspace']['receiver']['credentials']['replyPrefix'])
        self.selected_policies = {'selected-task': task, 'selected-workspace': workspace,
            'process-state': state_policy(owner.value),
            **{name: receiver_policy(owner.value, name) for name in ('process', 'outcome')}}
        self.inbox_prefixes.update({name: (pin['state'] if name == 'process-state' else
            pin['receivers'][name] if name in ('process', 'outcome') else
            owner.value['task'] if name == 'selected-task' else owner.value['workspace']['receiver'])
            ['credentials']['replyPrefix'] for name in self.selected_policies})
        for name, policy in self.selected_policies.items():
            policies[name] = {'publish': {'allow': list(policy.publish_subjects)},
                'subscribe': {'allow': [s for s in policy.subscribe_subjects
                    if s != self.inbox_prefixes[name]+'.>']}}
        policies['host']['publish']['allow'] = [self.identity_subject,
            *(receiver_policy(owner.value, name).command_subject for name in ('process', 'outcome'))]

    def _configure_tls_and_users(self):
        super()._configure_tls_and_users()
        matches = list((self.directory/'nsc-keys').rglob(self.account_public_key+'.nk'))
        if len(matches) != 1:
            raise RuntimeError('process_fixture_account_key_unavailable')
        key = nkeys.from_seed(matches[0].read_bytes().strip())
        try:
            for name, policy in self.selected_policies.items():
                path = self.credentials[name]
                raw = path.read_bytes(); token = raw.splitlines()[1]
                header, body, _ = token.split(b'.')
                claims = strict_loads(base64.urlsafe_b64decode(body+b'='*(-len(body)%4)))
                claims['nats']['pub'] = {'allow': list(policy.publish_subjects)}
                claims['nats']['sub'] = {'allow': list(policy.subscribe_subjects)}
                if name != 'process-state':
                    claims['nats']['resp'] = policy.response_permissions
                else:
                    claims['nats'].pop('resp', None)
                claims.pop('jti', None)
                body = base64.urlsafe_b64encode(canonical_bytes(claims)).rstrip(b'=')
                signed = header+b'.'+body
                updated = signed+b'.'+base64.urlsafe_b64encode(key.sign(signed)).rstrip(b'=')
                path.write_bytes(raw.replace(token, updated, 1))
        finally:
            key.wipe()


class LiveSelectedProcessTests(NativeDeliveryExecutionTests):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_CAPABILITY_LIVE') != '1' or not Path(os.environ.get('AMX_CAPABILITY_GO_BINARY', '')).is_file():
            raise RuntimeError('A coordinated native Go capability binary is required')
        super().setUpClass()

    def write_private(self, name, value, **kwargs):
        return tls_support.LiveCapabilityTests.write_private(self.handoff, name, value, **kwargs)

    async def wait_handoff(self, name, accept, **kwargs):
        return await tls_support.LiveCapabilityTests.wait_handoff(self.handoff, name, accept, **kwargs)

    def setUp(self):
        super().setUp()
        WorkspaceSelectionTests.setUp(self)
        self.pin = add_process(self)
        Path(self.pin['run']['inventoryRoot']).mkdir(mode=0o700)
        self.selected_process = self.selected_task = self.selected_workspace = None
        self.selected_identity = None
        self.histories = []
        self.go_process = self.go_wait = self.go_output = None
        self.keep_directory = False
        self.effects = []
        self.value['identity']['issuer'] = self.key('identity-live', 'identity-owner', ref('issuer'), SEED)
        self.value['task'].update(serviceIdentityRef=ref('consumer'), serviceInstanceId='consumer-instance')
        self.value['task']['issuer'] = self.key('task-live', 'task-owner', ref('consumer-issuer'), TASK_SEED)
        self.value['task']['requesterReplyPrefix'] = '_INBOX.task_consumer_00000001'
        self.value['task']['ledger']['stream'] = 'TASK'
        self.value['task']['ledger']['scope'] = copy.deepcopy(self.scope)
        self.pin['scope'] = copy.deepcopy(self.scope)
        self.pin['profile']['scope'] = copy.deepcopy(self.scope)
        for name in ('plans', 'credentialsLedger'):
            self.pin[name]['scope'] = copy.deepcopy(self.scope)
        self.value['workspace']['receiver']['requestSigningKeyRef'] = ref('issuer')
        for entry in self.pin['receivers'].values():
            entry['requestSigningKeyRef'] = ref('issuer')
        self.pin['plans'].update(entityId='plan-one', stream='PLAN')
        self.pin['credentialsLedger'].update(entityId='credential', stream='CREDENTIAL')
        signer = self.pin['signer']
        seed = bytes(reversed(SEED)); path = Path(signer['keyFile']['path']); path.write_bytes(seed)
        signer.update(ownerIdentityRef=ref('administrator'), transportRef=ref('administrator-transport'),
            publicKey=public(seed), inspectionGrantRef=ref('task-inspect-grant'),
            taskReadGrantRef=ref('worker-read-grant'), grants={name:ref(name+'-grant')
                if name != 'identity-application-account-resolve' else ref('account-resolve-grant')
                for name in SERVICE_COMMANDS})
        signer['keyFile']['sha256'] = 'sha256:'+hashlib.sha256(seed).hexdigest()
        self.pin['enrollmentIdentityRef'] = ref('administrator')

    def key(self, name, service, issuer, seed):
        path = self.root/(name+'.key')
        raw = canonical_bytes({'schemaVersion':'1.0.0', 'purpose':'agentmux-application-service-key-v1',
            'serviceId':service, 'hubId':'hub-one', 'profileId':'profile-one',
            'authorityId':'authority-one', 'issuerRef':issuer, 'seed':base64.b64encode(seed).decode()})
        path.write_bytes(raw); path.chmod(0o600)
        return {'keyFile':{'path':str(path), 'sha256':'sha256:'+hashlib.sha256(raw).hexdigest()},
            'issuerRef':issuer, 'publicKey':public(seed)}

    def make_credentials(self):
        result = super().make_credentials()
        state = self.record['state']
        # The selected task signer is distinct from public ingress from the
        # first retained record, before any reservation or credential effect.
        next(row for row in state['issuers'] if row['ref']==ref('consumer-issuer'))['publicKey'] = public(TASK_SEED)
        for entry in [self.value['workspace']['receiver'], *self.pin['receivers'].values()]:
            if not any(row['ref']==entry['serviceIdentityRef'] for row in state['identities']):
                state['identities'].append({'ref':entry['serviceIdentityRef'], 'kind':'service',
                    'status':'active', 'principalId':entry['serviceIdentityRef']['id'], 'externalIdentity':None})
                issuer = copy.deepcopy(state['issuers'][0])
                issuer.update(ref=entry['issuer']['issuerRef'], identityRef=entry['serviceIdentityRef'],
                    instanceId=entry['serviceInstanceId'], publicKey=entry['issuer']['publicKey'])
                state['issuers'].append(issuer)
        if not any(row['ref']==ref('parent-plugin') for row in state['identities']):
            state['identities'].append({'ref':ref('parent-plugin'), 'kind':'plugin',
                'status':'active', 'principalId':'parent-one', 'externalIdentity':None})
        template = next(row for row in state['grants'] if row['ref']==ref('task-credential-observe-grant'))
        known = {row['ref']['id'] for row in state['grants']}
        for instance in ('plugin-one', 'parent-one'):
            for method in ('bind-instance', 'admit-operation', 'recheck', 'prepare-domain-call'):
                name = instance+'-'+method
                if name not in known:
                    state['grants'].append({**copy.deepcopy(template), 'ref':ref(name),
                        'callerRef':ref('host'), 'actorRef':ref('host'),
                        'contractId':'native-authority-'+method, 'resourceId':instance})
        if 'process-outcome-grant' not in known:
            state['grants'].append({**copy.deepcopy(template), 'ref':ref('process-outcome-grant'),
                'callerRef':ref('human'), 'actorRef':ref('human'),
                'contractId':'capability-outcome-query', 'resourceId':'executor'})
        # Go allocates the actual downstream ID. The administrator enrolls the
        # exact D grants only after that saved original exists.
        state['grants'][:] = [row for row in state['grants']
            if row['ref'] not in (ref('execution-run-record-grant'), ref('execution-run-observe-grant'))]
        self.profile['limits']['offlineSeconds'] = 60
        record = strict_loads(self.task_js.messages[0].data)
        record['repository'] = {'repositoryId':self.rid, 'revision':'original-revision', 'treeDigest':'sha256:'+'a'*64}
        self.task_js.messages[0].data = canonical_bytes(record)
        self.sync()
        return result

    async def asyncSetUp(self):
        # Configure exact additional users through the existing fixture hook.
        owner = self
        class SelectedBroker(ProcessBrokerFixture):
            process_owner = owner
        with patch.object(tls_support, 'LiveCapabilityTests', SelectedBroker):
            await super().asyncSetUp()
        self.addAsyncCleanup(self.cleanup_process)
        self.go_directory = self.path/'go-process'; self.go_directory.mkdir(mode=0o700)
        await self.credentials.close()
        await self.adapter.checkpoint()
        self.profile['workspaceRef'] = ref('task-one')
        script = b"from pathlib import Path\nimport time\nPath('/workspace/started').write_text('approved')\ntime.sleep(55)\n"
        (self.checkout/'file').write_bytes(script)
        self.profile['recipe']['sha256'] = 'sha256:'+hashlib.sha256(script).hexdigest()
        self.value['workspaces'] = [str(self.checkout)]
        self.value['definitions']['directories']['projectRoot'] = str(self.checkout)
        workspace = self.value['workspace']
        workspace.update(source=copy.deepcopy(self.pins), repository=copy.deepcopy(self.repository),
            checkoutPath=str(self.checkout))
        await self.host.close(timeout=10)
        fixture = self.tls_fixture
        connection = {'endpoint':fixture.broker.url, 'serverName':fixture.server_name,
            'rootsPEM':fixture.ca_file.read_text(), 'leafCertificateSHA256':fixture.leaf_digest, 'jetstreamDomain':None}
        for role, ledger in (('identity', self.service.ledger), ('task', self.owner._ledger)):
            entry = self.value[role]; entry['connection'] = copy.deepcopy(connection)
            entry['credentials'] = self.credential_pin('identity' if role=='identity' else 'selected-task')
            entry['ledger'].update(entityId=ledger._binding.entity_id, scope=strict_loads(ledger._binding.scope),
                stream=ledger._stream, streamIdentity={'created':stamp(ledger._identity.created), 'minimumSequence':0},
                retention=self.retention_pin())
        workspace['receiver'].update(connection=copy.deepcopy(connection), credentials=self.credential_pin('selected-workspace'))
        self.pin['profile'] = copy.deepcopy(self.profile)
        for name, ledger in (('plans', self.plan_ledger), ('credentialsLedger', self.credential_ledger)):
            self.pin[name].update(streamIdentity={'created':stamp(ledger._identity.created), 'minimumSequence':0},
                retention=self.retention_pin())
        self.pin['state'].update(connection=copy.deepcopy(connection), credentials=self.credential_pin('process-state'))
        for name, entry in self.pin['receivers'].items():
            entry.update(connection=copy.deepcopy(connection), credentials=self.credential_pin(name))
        self.pin['run']['retention'] = self.retention_pin()
        self.pin['signer']['accountPayload'] = copy.deepcopy(self.account_payload)
        self.pin['custodyRoot'] = str(self.custody_root)
        self.pin['accountCustodyRoot'] = str(self.path/'live-account-custody')
        from dataclasses import asdict
        self.pin['docker'] = asdict(self.real_engine.selection)
        await self.start_go()
        self.pin['packageId'] = self.row['owner']['pin']['packageId']
        self.selected = ApplicationServiceSelection(canonical_bytes(self.value))
        await self.start_selected_hosts()

    def retention_pin(self):
        return {'maxBytes':self.policy.max_bytes, 'reserveBytes':self.policy.reserve_bytes, 'replicas':self.policy.replicas}

    def credential_pin(self, role):
        raw = self.tls_fixture.credentials[role].read_bytes()
        token = raw.splitlines()[1].split(b'.')[1]
        claims = strict_loads(base64.urlsafe_b64decode(token+b'='*(-len(token)%4)))
        return {'path':str(self.tls_fixture.credentials[role]), 'sha256':'sha256:'+hashlib.sha256(raw).hexdigest(),
            'accountPublicKey':self.account_public, 'userPublicKey':claims['sub'],
            'replyPrefix':self.tls_fixture.inbox_prefixes[role]}

    def retained_resources(self, role):
        selected = self.selected; entry = selected.service(role)
        binding, epoch = selected.binding(role), selected.stream_identity(role)
        history = OwnerHistory(entry['ledger']['history']['path'], binding, stream_identity=epoch)
        self.histories.append(history)
        pin = entry['backup']
        backup = BackupHost(*(pin[key] for key in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=pin['destinationId'], binding=binding, stream_identity=epoch)
        backup.enroll_key(pin['keyId'])
        pin = entry['ledger']['checkpoint']
        checkpoint = CheckpointHost(pin['path'], stream=entry['ledger']['stream'],
            commit_ref=pin['commitRef'], binding=binding, stream_identity=epoch)
        return history, backup, checkpoint

    async def start_selected_hosts(self):
        history, backup, checkpoint = self.retained_resources('identity')
        self.selected_identity = IdentityService(await self.tls_fixture.connect('identity'),
            **self.selected.identity_kwargs(history=history, checkpoint_committed=checkpoint.committed,
                signing_seed=SEED, backup_host=backup))
        await self.selected_identity.start(); self.service = self.selected_identity
        history, backup, checkpoint = self.retained_resources('task')
        self.selected_task = TaskHost.from_enrolled_host(await self.tls_fixture.connect('selected-task'),
            **self.selected.task_kwargs(authority=self.service.reader, ingress=self.service.ingress,
                history=history, signing_seed=TASK_SEED, checkpoint_host=checkpoint, backup_host=backup))
        await self.selected_task.start(); self.owner = self.selected_task.owner
        self.selected_workspace = WorkspaceReadHost(self.selected, identity=self.service, task=self.selected_task,
            connection=await self.tls_fixture.connect('selected-workspace'),
            signing_seed=load_workspace_signing_seed(self.selected))
        await self.selected_workspace.start()
        self.plans = self.make_owner(); self.addAsyncCleanup(self.plans.close)
        self.selected_process = ProcessHost(self.selected, identity=self.service,
            task=self.selected_task, workspace=self.selected_workspace)
        await self.selected_process.start()
        self.count_effects(self.selected_process)

    def count_effects(self, host):
        from execution_owner.container_programs import START, DELIVER
        engine = host._adapter._engine
        command, fixed = engine._run, engine.exec_fixed
        async def counted(args, **kwargs):
            if args[0] == 'create': self.effects.append('create')
            return await command(args, **kwargs)
        async def counted_fixed(container, uid, program, *args, **kwargs):
            if program == DELIVER: self.effects.append('deliver')
            if program == START: self.effects.append('start')
            return await fixed(container, uid, program, *args, **kwargs)
        engine._run, engine.exec_fixed = counted, counted_fixed
        self.live_adapter = host._adapter

    async def observe_owned(self):
        owner = await self.selected_process._admission.existing()
        self.assertIsNotNone(owner)
        snapshot, state = await owner._load()
        raw = await self.selected_process._admission._signer.observe(state['executionBinding'], snapshot.sequence)
        return owner, strict_loads(await owner.query(raw))

    async def joined_calls(self):
        workers = tuple(self.selected_process._resource._workers)
        if workers:
            done, pending = await asyncio.wait(workers, timeout=30)
            self.assertFalse(pending, 'The original Process owner call did not finish')
            for original in done:
                if not original.cancelled(): original.exception()

    async def test_native_selected_original_restart_cancel_and_revocation(self):
        await self.reserve()
        now = datetime.now(timezone.utc)
        self.plan.update(issuedAt=stamp(now-timedelta(seconds=1)), expiresAt=stamp(now+timedelta(seconds=60)))
        await self.enroll()
        for row in (self.parent, self.row):
            result = await self.admin_command('identity-native-instance-set',
                {'authorityId':'authority-one', 'record':row, 'previousRef':None})
            self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        source = strict_loads(self.start())
        source['operation']['deadline'] = stamp(datetime.now(timezone.utc)+timedelta(seconds=60))
        claims = source['ingressAttestation']['claims']
        claims.update(expiresAt=source['operation']['deadline'], operation=copy.deepcopy(source['operation']))
        source['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        self.write_private('host-signing.seed', HOST_SEED, raw=True)
        self.write_private('original-envelope.json', canonical_bytes(source), raw=True)
        fixture = self.tls_fixture
        current = await self.service.ledger.current()
        def service(name):
            entry = self.pin['receivers'][name]
            return {'profileId':'profile-one', 'hubId':'hub-one', 'serviceId':name+'-owner',
                'serviceInstanceId':entry['serviceInstanceId'], 'serviceIdentityRef':entry['serviceIdentityRef'],
                'signingKeyRef':entry['issuer']['issuerRef']}
        process_subject = receiver_policy(self.value, 'process').command_subject
        outcome_subject = receiver_policy(self.value, 'outcome').command_subject
        ready = {'serverUrl':fixture.broker.url, 'authoritySubject':self.service.subject,
            'capabilitySubject':process_subject, 'outcomeSubject':outcome_subject,
            'credentialsFile':str(fixture.credentials['host']), 'caFile':str(fixture.ca_file),
            'tlsName':fixture.server_name, 'leafCertificateSha256':fixture.leaf_digest,
            'accountPublicKey':self.account_public, 'replyPrefix':fixture.inbox_prefixes['host'],
            'publishSubjects':[self.service.subject, process_subject, outcome_subject,
                '$JS.API.STREAM.INFO.IDENTITY', '$JS.API.STREAM.MSG.GET.IDENTITY'],
            'hostSigningSeedFile':str(self.go_directory/'host-signing.seed'),
            'originalEnvelopeFile':str(self.go_directory/'original-envelope.json'),
            'enrollment':{'profileId':'profile-one', 'hubId':'hub-one', 'authorityId':'authority-one',
                'organizationId':'org-one', 'stream':'IDENTITY', 'domain':'',
                'streamCreated':stamp(self.service.ledger._identity.created), 'minimumSequence':current.sequence,
                'maxBytes':self.policy.max_bytes, 'replicas':self.policy.replicas,
                'hostTransportRef':ref('host-transport'), 'hostIdentityRef':ref('host'),
                'issuerRef':ref('issuer'), 'issuerIdentityRef':ref('service'), 'issuerInstanceId':'ingress-one'},
            'service':service('process'), 'outcomeService':service('outcome'),
            'bindingId':'capability-process-start-binding', 'resourceRef':ref('executor'),
            'resourceDigest':'sha256:'+hashlib.sha256(canonical_bytes(source)).hexdigest(),
            'requestContractId':'capability-process-start', 'replyContractId':'capability-process-start-reply',
            'requestInput':{'planRef':ref('plan-one')}, 'replyPayloadDigest':'sha256:'+'0'*64, 'revoked':False}
        self.write_private('fixture-ready.json', ready)
        mutation = await self.wait_handoff('process-mutation.json', lambda value:True)
        identity = {'format':'agentmux-execution-run-reference-v1', 'ownerHubId':'hub-one',
            'scope':self.scope, 'executorId':'executor', 'operationId':mutation['operationId']}
        run_id = 'execution-'+payload_digest(identity).split(':',1)[1]
        authority = strict_loads((await self.service.reader.current()).record)
        template = next(row for row in authority['state']['grants'] if row['ref']==ref('task-credential-observe-grant'))
        for contract in ('execution-run-record', 'execution-run-observe'):
            result = await self.admin_command('identity-grant-set', {'authorityId':'authority-one',
                'record':{**copy.deepcopy(template), 'ref':ref(contract+'-grant'),
                    'contractId':contract, 'resourceId':run_id}, 'previousRef':None})
            self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        self.write_private('process-dispatch-ready.json', {'ready':True})
        accepted = await self.wait_handoff('process-accepted.json', lambda value:True, timeout=15)
        self.assertEqual(accepted['operationId'], mutation['operationId'])
        self.assertEqual(accepted['payloadDigest'], mutation['payloadDigest'])
        self.assertEqual(accepted['receiptRef'], ref(run_id))
        await self.joined_calls()
        owner, view = await self.observe_owned()
        self.assertEqual(view['step'], 'pending-enrollment')
        first = (await owner._ledger.current()).records[0].record
        original = strict_loads(first)
        self.assertEqual(original['operation']['operationId'], mutation['operationId'])
        self.assertEqual(original['operation']['payloadDigest'], mutation['payloadDigest'])
        public_record = strict_loads(await self.selected_process.enrollment())
        expiry = datetime.fromisoformat(original['state']['originalEnvelope']['ingressAttestation']['claims']['expiresAt'])
        self.assertGreater(public_record['record']['expiresUnix'], expiry.timestamp())
        await asyncio.sleep(max(0, (expiry-datetime.now(timezone.utc)).total_seconds())+.1)
        result = await self.admin_command('identity-enroll', public_record['enrollment'])
        self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        self.write_private('process-enrolled.json', {'ready':True})
        await self.wait_handoff('process-dispatched.json', lambda value:value=={'phase':'dispatched'}, timeout=12)
        await self.joined_calls()
        owner, view = await self.observe_owned()
        self.assertEqual(view['status'], 'running')
        marker = self.checkout/'started'
        end = asyncio.get_running_loop().time()+3
        while not marker.exists() and asyncio.get_running_loop().time()<end:
            await asyncio.sleep(.01)
        self.assertEqual(marker.read_text(), 'approved')
        self.assertEqual(self.effects, ['create','deliver','start'])
        old_host = self.selected_process
        engine = old_host._adapter._engine
        physical = next(iter(old_host._adapter._runs.values()))
        name, container = physical['spec']['name'], physical['id']
        generation = public_record['record']['generationRef']
        def private_digests(credentials):
            with credentials._store.access(generation) as directory:
                return tuple(hashlib.sha256(credentials._store.read(directory, file)).hexdigest()
                    for file in ('credential.json','delivery.json'))
        private = private_digests(old_host._credentials)
        await old_host.close(timeout=None)
        self.assertFalse(engine._jobs)
        self.assertTrue((await engine.find(name))['State']['Running'])
        self.selected_process = ProcessHost(self.selected, identity=self.service,
            task=self.selected_task, workspace=self.selected_workspace)
        await self.selected_process.start(); self.count_effects(self.selected_process)
        owner, reopened = await self.observe_owned()
        self.assertEqual(reopened, view)
        self.assertEqual((await owner._ledger.current()).records[0].record, first)
        credentials = self.selected_process._credentials
        self.assertEqual(credentials._history(await credentials._ledger.current())['record'], public_record['record'])
        self.assertEqual(private_digests(credentials), private)
        self.assertEqual((await self.selected_process._adapter._engine.find(name))['Id'], container)
        self.assertEqual(self.effects, ['create','deliver','start'])
        self.write_private('process-observe-ready.json', {'ready':True})
        await self.wait_handoff('process-cancel-dispatched.json', lambda value:value=={'phase':'dispatched'}, timeout=12)
        await self.joined_calls()
        owner, final = await self.observe_owned()
        self.assertEqual(final['status'], 'terminal')
        self.assertFalse((await self.selected_process._adapter._engine.find(name))['State']['Running'])
        result = await self.admin_command('identity-revoke',
            {'authorityId':'authority-one', 'targetRef':public_record['record']['transportRef']})
        self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        snapshot, state = await owner._load()
        await owner.retire(await self.selected_process._admission._signer.observe(state['executionBinding'], snapshot.sequence))
        self.assertIsNone(await self.selected_process._adapter._engine.find(name))
        self.assertFalse(self.selected_process._adapter._engine._jobs)
        self.assertEqual(self.effects, ['create','deliver','start'])
        parent = copy.deepcopy(self.parent); parent['ref']['revision'] += 1; parent['status'] = 'revoked'
        result = await self.admin_command('identity-native-instance-set', {'authorityId':'authority-one',
            'record':parent, 'previousRef':self.parent['ref']})
        self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        ready['revoked'] = True; self.write_private('fixture-ready.json', ready)
        result = await self.wait_handoff('go-result.json', lambda value:value.get('phase')=='complete')
        self.assertEqual(result, {'phase':'complete', 'process':True, 'recovery':True,
            'revocation':True, 'cleanup':True})
        self.assertEqual(await asyncio.wait_for(asyncio.shield(self.go_wait), 3), 0)

    async def start_go(self):
        descriptor = os.open(self.go_directory/'go.private.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        self.go_output = os.fdopen(descriptor, 'wb')
        environment = dict(os.environ, AMX_NATIVE_CAPABILITY_LIVE_DIR=str(self.go_directory),
            AMX_NATIVE_CAPABILITY_CLASS='process', AMX_NATIVE_CAPABILITY_ACTION='start',
            AMX_NATIVE_CAPABILITY_PRIVATE='1', AMX_NATIVE_CAPABILITY_PROCESS='1')
        self.go_process = await asyncio.create_subprocess_exec(os.environ['AMX_CAPABILITY_GO_BINARY'],
            '-test.run=^TestNativeCapabilityTLSIntegration$', '-test.count=1', '-test.timeout=85s',
            env=environment, stdout=self.go_output, stderr=self.go_output)
        self.go_wait = asyncio.create_task(self.go_process.wait())
        self.handoff = SimpleNamespace(directory=self.go_directory, go_output=self.go_output,
            go_wait=self.go_wait, keep_directory=False)
        declaration = await self.wait_handoff('go-declaration.json', lambda value:True)
        self.row = self.install_native_policy('not-an-enrolled-run')
        parent = declaration.pop('parent'); self.row.update(declaration)
        routes = [('start','process','capability-process-start'), ('cancel','process','capability-process-cancel'),
            ('inspect','outcome','capability-outcome-query')]
        facts = self.row['facts']; facts['grant']['actions'] = ['start','cancel','inspect']
        facts['policy']['decisions'] = [{'access':{'action':action,'resourceClass':kind,'resourceId':'executor'},
            'outcome':'allow'} for action,kind,_ in routes]
        facts['domainBindings'] = [{'id':contract+'-binding','contractId':contract,
            'action':action,'resourceClass':kind,'resourceIds':['executor']} for action,kind,contract in routes]
        self.parent = copy.deepcopy(self.row); self.parent.update(parent)
        self.parent.update(ref=ref('native-parent'), identityRef=ref('parent-plugin'))
        self.parent['facts']['grant'].update(grantId='parent-grant', subjectInstanceId='parent-one')
        self.parent['facts']['policy']['subjectInstanceId'] = 'parent-one'
        self.row.update(relationship='private', parentOwner=copy.deepcopy(self.parent['owner']))
        facts['parentGrant'] = copy.deepcopy(self.parent['facts']['grant'])
        facts['grant']['parentGrantRef'] = ref('parent-grant')
        facts['parentAccess'] = [row['access'] for row in facts['policy']['decisions']]

    async def cleanup_process(self):
        if self.go_wait is not None and not self.go_wait.done():
            self.go_process.terminate()
            try: await asyncio.wait_for(asyncio.shield(self.go_wait), 3)
            except TimeoutError:
                self.go_process.kill(); await asyncio.wait_for(asyncio.shield(self.go_wait), 3)
        if self.go_wait is not None:
            code = await self.go_wait
            if code:
                self.go_output.flush()
                descriptor, log = tempfile.mkstemp(prefix='amux288-native-go-failed-', suffix='.log')
                with os.fdopen(descriptor, 'wb') as output:
                    output.write((self.go_directory/'go.private.log').read_bytes())
                print('Native Go failure log: '+log, file=sys.stderr)
        if self.go_output is not None: self.go_output.close()
        if self.selected_process is not None:
            try:
                if not self.selected_process._closed:
                    await self.joined_calls()
                    owner = await self.selected_process._admission.existing()
                    if owner is not None:
                        snapshot, state = await owner._load()
                        if state['step'] != 'retired':
                            self.run = state['executionBinding']
                            if state['executionPhase'] != 'terminal':
                                await owner.cancel(self.native_cancel())
                            credential = self.selected_process._credentials._history(
                                await self.selected_process._credentials._ledger.current())['record']
                            if credential is not None:
                                current = strict_loads((await self.service.reader.current()).record)
                                transport = next((row for row in current['state']['transports']
                                    if row['ref']==credential['transportRef']), None)
                                if transport is not None and transport['status']=='active':
                                    result = await self.admin_command('identity-revoke',
                                        {'authorityId':'authority-one', 'targetRef':transport['ref']})
                                    self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
                            snapshot, state = await owner._load()
                            await owner.retire(await self.selected_process._admission._signer.observe(
                                state['executionBinding'], snapshot.sequence))
            finally:
                await self.selected_process.close(timeout=None)
        if self.selected_workspace is not None: await self.selected_workspace.close(timeout=None)
        if self.selected_task is not None: await self.selected_task.close(timeout=None)
        if self.selected_identity is not None: await self.selected_identity.close()
        for history in self.histories: history.close()


for _name in dir(NativeDeliveryExecutionTests):
    if _name.startswith('test_') and _name not in vars(LiveSelectedProcessTests):
        setattr(LiveSelectedProcessTests, _name, None)
