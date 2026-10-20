"""Explicit storage provisioning for the existing installed-service fixture.

Only the disposable setup owner calls this ceremony. Installed startup consumes
its selection and never creates these namespaces, keys, grants or databases.
"""
import base64
import os

from nacl.signing import SigningKey
from nats.js.api import KeyValueConfig, StorageType

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads
from capability_owner.private_storage import private_storage_binding_digest
from hub.fed.plugins.board import Board
from hub.fed.policy import rid_for_remote
from hub.store import APP_ID, MIGRATIONS, Store
from identity.application_service_selection import provision_application_service_issuer
from identity.application_enrollment import _write_material
from integration_owner.live_broker import user_credential
from native_security.nats_credentials import (
    storage_receiver_policy, private_storage_publisher_policy, board_publisher_policy,
    validate_storage_receiver, validate_private_storage_publisher, validate_board_publisher,
    service_policy, validate_service)
from state_owner.backup_host import BackupHost
from state_owner.configuration_events import ConfigurationEventRoute
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention

from installed_service_enrollment import Preparation, RETENTION, digest, private_bytes, stamp

# Storage qualification retains the seed, writes, conflicts and recovery records.
# The baseline service fixture's three-record bulk capacity cannot hold that flow.
STORAGE_RETENTION = Retention(2 * 1024 * 1024, 131072)


class StoragePreparation(Preparation):
    def write_selections(self, selection, sequence):
        result = super().write_selections(selection, sequence)
        service_path = self.directory / 'service-selection.json'
        identity = selection.service('identity')
        kernel = selection.policy['kernelScope']
        storage = selection.policy['storage']
        configuration = selection.service('configuration')
        material = {'schemaVersion': '1.0.0',
            'serviceSelection': {'path': str(service_path), 'sha256': digest(canonical_bytes(selection.policy))},
            'nativeSigners': self.native_signers,
            'nativeBroker': self.native_broker,
            'nativePackage': self.plan['nativePackage'],
            'configuration': {'reference': {**self.ref('storage_configuration'), 'revision': 0},
                'authorityRef': {**self.ref('authority'), 'id': self.authority, 'revision': 1},
                'service': {'profileId': kernel['profileId'], 'hubId': kernel['hubId'],
                    'serviceInstanceId': kernel['instanceId'], 'serviceIdentityRef': self.ref('configuration'),
                    'signingKeyRef': configuration['issuer']['issuerRef']},
                'commandSubject': service_policy(**selection.service_policy_inputs('configuration')).command_subject,
                'eventSource': self.configuration_source},
            'connection': identity['connection'], 'interval': self.interval,
            'accountPublicKey': identity['credentials']['accountPublicKey'],
            'enrollment': {'profileId': kernel['profileId'], 'hubId': kernel['hubId'],
                'authorityId': self.authority, 'organizationId': self.organization,
                'stream': identity['ledger']['stream'], 'domain': identity['connection']['jetstreamDomain'],
                'streamCreated': identity['ledger']['streamIdentity']['created'], 'minimumSequence': sequence,
                'maxBytes': RETENTION.max_bytes, 'replicas': 1,
                'hostTransportRef': self.native_signers['native_host']['transportRef'],
                'hostIdentityRef': self.native_signers['native_host']['identityRef'],
                'issuerRef': identity['issuer']['issuerRef'], 'issuerIdentityRef': self.ref('identity'),
                'issuerInstanceId': kernel['instanceId']},
            'resources': {'private': {'id': storage['privateStorage']['ledger']['entityId'],
                'ownerHubId': kernel['hubId'], 'revision': 1}, 'card': storage['board']['resourceRef']},
            'privateBindingDigest': storage['privateStorage']['bindingDigest'],
            'services': {name: {'profileId': kernel['profileId'], 'hubId': kernel['hubId'],
                'serviceId': name + '-owner', 'serviceInstanceId': entry['serviceInstanceId'],
                'serviceIdentityRef': entry['serviceIdentityRef'], 'signingKeyRef': entry['issuer']['issuerRef']}
                for name, entry in storage['receivers'].items()},
            'instanceId': self.value['storage']['privateStorage']['instanceId'],
            'packageId': self.value['storage']['privateStorage']['packageId'],
            'projectScope': self.project_scope,
            'operationGrants': {name: {contract: self.ref(name + '_' + contract.replace('-', '_'))
                for contract in ('capability-storage-read', 'capability-storage-write', 'capability-outcome-query')}
                for name in ('private', 'card')}}
        path = self.directory / 'storage-contract.json'
        _write_material(path, material, max_bytes=16384)
        return {**result, 'contractMaterial': {'path': str(path), 'sha256': digest(canonical_bytes(material))}}

    def make_permit(self, now):
        self.storage_store = None
        self.storage_ledgers, self.storage_backup_hosts = [], []
        self.repository = {'localName': 'installed_storage',
            'normalizedRemote': 'example.com/installed-storage', 'counterPrefix': 'IS'}
        self.repository['repositoryId'] = rid_for_remote(self.repository['normalizedRemote'])
        self.storage_dirs = {}
        for name in ('storage', 'outcome', 'private', 'card', 'allocation', 'phase', 'native_host', 'storage_plugin', 'storage_user', 'configuration'):
            path = self.directory / name
            path.mkdir(mode=0o700)
            self.storage_dirs[name] = path
        receivers = {}
        for name in ('storage', 'outcome'):
            identity = {'ref': self.ref(name), 'kind': 'service', 'status': 'active',
                        'principalId': 'fixture_' + name, 'externalIdentity': None}
            payload, receipt = provision_application_service_issuer(
                self.storage_dirs[name] / 'issuer.json', service_id=name + '-owner',
                profile_id=self.plan['host']['kernelScope']['profileId'], authority_id=self.authority,
                instance_id=self.plan['host']['kernelScope']['instanceId'], identity=identity,
                issuer_ref=self.ref(name + '_issuer'), issued_at=self.interval['issuedAt'],
                expires_at=self.interval['expiresAt'])
            self.payloads.append(payload)
            receivers[name] = {**self.connection(name), 'serviceIdentityRef': identity['ref'],
                'serviceInstanceId': self.plan['host']['kernelScope']['instanceId'],
                'requestSigningKeyRef': self.value['identity']['issuer']['issuerRef'],
                'issuer': {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
                    'issuerRef': self.ref(name + '_issuer'),
                    'publicKey': payload['issuers'][0]['record']['publicKey']}}
        private = {'publisher': self.connection('private'), **self.custody('private'),
            'pluginIdentityRef': self.ref('storage_plugin'),
            'instanceId': 'installed_storage_plugin', 'packageId': 'installed_storage_package'}
        phase = self.phase_material()
        policy = b'[federation]\npeer="installed"\n[repos.installed_storage]\nremote="example.com/installed-storage"\nboard_prefix="IS"\n'
        policy_path = self.directory / 'storage-policy.toml'
        private_bytes(policy_path, policy)
        database = self.directory / 'storage-board.sqlite'
        # This is the explicit fixture setup ceremony, not startup migration.
        store = Store(str(database))
        self.storage_store = store
        try:
            store.repo_add(self.repository['localName'])
            for statement in Board.tables:
                store.db.execute(statement)
        finally:
            store.db.close()
            self.storage_store = None
        database.chmod(0o600)
        board = {'resourceRef': self.ref('storage_card'), 'repository': self.repository,
            'cardKey': 'IS-1', 'localPeer': 'installed', 'phaseAuthority': phase,
            'cardPublisher': {**self.connection('card'), **self.custody('card')},
            'allocationPublisher': {**self.connection('allocation'), **self.custody('allocation')},
            'actors': [{'identityRef': self.ref('storage_user'),
                        'transportRef': self.ref('storage_user_transport'), 'address': 'peer:installed'}],
            'auditMirror': {'database': {'path': str(database), 'applicationId': APP_ID,
                                        'userVersion': len(MIGRATIONS)},
                           'policy': {'path': str(policy_path), 'sha256': digest(policy)}}}
        self.value['storage'] = {'scope': self.project_scope, 'receivers': receivers,
                                 'privateStorage': private, 'board': board}
        self.native_signers = {name: self.native_transport(name, kind)
            for name, kind in (('native_host', 'service'), ('storage_plugin', 'plugin'), ('storage_user', 'human'))}
        self.configuration_material()
        self.native_broker = self.native_broker_material()
        super().make_permit(now)

    def configuration_material(self):
        """Enroll the existing configuration owner for the exact prepared slot."""
        package = self.plan['nativePackage']
        root, kernel = self.storage_dirs['configuration'], self.plan['host']['kernelScope']
        identity = {'ref': self.ref('configuration'), 'kind': 'service', 'status': 'active',
                    'principalId': 'fixture_configuration', 'externalIdentity': None}
        payload, receipt = provision_application_service_issuer(root / 'issuer.json',
            service_id='configuration-owner', profile_id=kernel['profileId'], authority_id=self.authority,
            instance_id=kernel['instanceId'], identity=identity, issuer_ref=self.ref('configuration_issuer'),
            issued_at=self.interval['issuedAt'], expires_at=self.interval['expiresAt'])
        seed = os.urandom(32)
        key_path = root / 'producer.key'
        private_bytes(key_path, seed)
        public = base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
        transport = {'ref': self.ref('configuration_transport'), 'identityRef': identity['ref'],
            'issuerRef': self.ref('configuration_issuer'), 'method': 'nats-credential-mapping',
            'publicKey': public, 'status': 'active', **self.interval}
        claims = {'purpose': 'agentmux-enrollment-possession-v1', 'profileId': kernel['profileId'],
                  'authorityId': self.authority, 'credential': transport}
        payload['transports'].append({'record': transport, 'proof': sign_claims(claims, seed)})
        self.payloads.append(payload)
        custody = self.custody('configuration')
        inputs = dict(role='configuration', hub_id=kernel['hubId'], entity_id=custody['ledger']['entityId'],
            scope=self.project_scope, stream=custody['ledger']['stream'],
            reply_prefix='_INBOX.installed_configuration_0001', jetstream_domain=self.plan['broker']['domain'])
        permissions = service_policy(**inputs)
        raw = user_credential(self.account, permissions.publish_subjects, permissions.subscribe_subjects,
                              response=permissions.response_permissions)
        admitted = validate_service(raw, account_public_key=self.account.public_key.decode(), **inputs)
        credentials = root / 'user.creds'
        private_bytes(credentials, raw)
        schema = base64.b64decode(package['schemaBytes'], validate=True)
        schema_path = root / 'config.json'
        private_bytes(schema_path, schema)
        self.value['configuration'] = {**custody, 'connection': dict(self.value['identity']['connection']),
            'credentials': {'path': str(credentials), 'sha256': digest(raw),
                'accountPublicKey': self.account.public_key.decode(), 'userPublicKey': admitted.public_key,
                'replyPrefix': inputs['reply_prefix']},
            'issuer': {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
                'issuerRef': self.ref('configuration_issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']},
            'owner': package['owner'], 'schemaRef': package['schemaRef'],
            'schemaResources': {package['schemaRef']: {'path': str(schema_path), 'sha256': digest(schema)}},
            'requesterReplyPrefix': '_INBOX.installed_native_storage_0001',
            'producer': {'identityRef': identity['ref'], 'transportRef': transport['ref'],
                'grantRef': self.ref('configuration_change'), 'keyFile': {'path': str(key_path), 'sha256': digest(seed)},
                'publicKey': public}}

    def native_broker_material(self):
        from native_security.nats_credentials import validate as validate_credential
        hub = self.plan['host']['kernelScope']['hubId']
        prefix = 'amx.v1.h.' + hub + '.plugins.installed_storage_plugin.'
        policies = {
            'controller': ([prefix + 'lifecycle.control'], [prefix + 'lifecycle.event']),
            'plugin': ([prefix + 'lifecycle.event'], [prefix + 'lifecycle.control']),
            'context': ([prefix + name for name in ('context.reply', 'operation.invoke', 'operation.cancel')],
                        [prefix + name for name in ('context.request', 'operation.result')]),
            'context_client': ([prefix + name for name in ('context.request', 'operation.result')],
                               [prefix + name for name in ('context.reply', 'operation.invoke', 'operation.cancel')])}
        inbox = '_INBOX.installed_native_storage_0001'
        command = 'amx.v1.h.' + hub + '.o.' + self.organization + '.identity.' + self.authority + '.command'
        publish = [command]
        for api in ('$JS.API.', '$JS.' + self.plan['broker']['domain'] + '.API.'):
            publish.extend(api + method + '.INSTALLED_IDENTITY' for method in ('STREAM.INFO', 'STREAM.MSG.GET'))
        for service in ('storage-owner', 'outcome-owner'):
            publish.append(storage_receiver_policy(hub_id=hub, scope=self.project_scope,
                service_id=service, reply_prefix=inbox).command_subject)
        publish.append(service_policy(role='configuration', hub_id=hub, entity_id='fixture_storage_configuration',
            scope=self.project_scope, stream='INSTALLED_STORAGE_CONFIGURATION', reply_prefix=inbox,
            jetstream_domain=self.plan['broker']['domain']).command_subject)
        policies['host'] = (publish, [inbox + '.>'])
        credentials = {}
        for name, (send, receive) in policies.items():
            raw = user_credential(self.account, send, receive)
            admitted = validate_credential(raw, account_public_key=self.account.public_key.decode(),
                publish_subjects=send, subscribe_subjects=receive, private_inbox=name == 'host')
            path = self.storage_dirs['native_host'] / (name + '.creds')
            private_bytes(path, raw)
            credentials[name] = {'path': str(path), 'sha256': digest(raw), 'userPublicKey': admitted.public_key}
        ca_path = self.storage_dirs['native_host'] / 'roots.pem'
        private_bytes(ca_path, self.plan['broker']['rootsPEM'].encode())
        state = self.storage_dirs['native_host'] / 'state'
        state.mkdir(mode=0o700)
        return {'credentials': credentials, 'replyPrefix': inbox, 'publishSubjects': sorted(publish),
            'authoritySubject': command, 'caFile': {'path': str(ca_path),
                'sha256': digest(self.plan['broker']['rootsPEM'].encode())}, 'stateDirectory': str(state)}

    def native_transport(self, name, kind):
        seed = os.urandom(32)
        path = self.storage_dirs[name] / 'signing.key'
        private_bytes(path, seed)
        public = base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
        transport = {'ref': self.ref(name + '_transport'), 'identityRef': self.ref(name),
            'issuerRef': self.value['identity']['issuer']['issuerRef'], 'method': 'nats-credential-mapping',
            'publicKey': public, 'status': 'active', **self.interval}
        proof = {'purpose': 'agentmux-enrollment-possession-v1',
            'profileId': self.plan['host']['kernelScope']['profileId'],
            'authorityId': self.authority, 'credential': transport}
        self.payloads.append({'identity': {'ref': self.ref(name), 'kind': kind,
            'principalId': 'fixture_' + name, 'status': 'active', 'externalIdentity': None},
            'issuers': [], 'transports': [{'record': transport, 'proof': sign_claims(proof, seed)}]})
        return {'identityRef': self.ref(name), 'transportRef': transport['ref'],
                'keyFile': {'path': str(path), 'sha256': digest(seed)}, 'publicKey': public}

    def connection(self, name):
        prefix = '_INBOX.installed_storage_' + name + '_0001'
        inputs = {'hub_id': self.plan['host']['kernelScope']['hubId'],
                  'scope': self.project_scope, 'reply_prefix': prefix}
        if name in ('storage', 'outcome'):
            inputs['service_id'] = name + '-owner'
            policy, validator = storage_receiver_policy, validate_storage_receiver
        else:
            inputs.update(entity_id='fixture_storage_' + name, stream='INSTALLED_STORAGE_' + name.upper(),
                          jetstream_domain=self.plan['broker']['domain'])
            if name == 'private':
                policy, validator = private_storage_publisher_policy, validate_private_storage_publisher
            else:
                inputs['repository_id'] = self.repository['repositoryId']
                inputs['card_key' if name == 'card' else 'counter_prefix'] = 'IS-1' if name == 'card' else 'IS'
                policy, validator = board_publisher_policy, validate_board_publisher
        permissions = policy(**inputs)
        raw = user_credential(self.account, permissions.publish_subjects, permissions.subscribe_subjects,
                              response=getattr(permissions, 'response_permissions', None))
        admitted = validator(raw, account_public_key=self.account.public_key.decode(), **inputs)
        path = self.storage_dirs[name] / 'user.creds'
        private_bytes(path, raw)
        return {'connection': dict(self.value['identity']['connection']),
            'credentials': {'path': str(path), 'sha256': digest(raw),
                'accountPublicKey': self.account.public_key.decode(), 'userPublicKey': admitted.public_key,
                'replyPrefix': prefix}}

    def custody(self, name):
        root = self.storage_dirs[name]
        retention = RETENTION if name == 'configuration' else STORAGE_RETENTION
        backup = {'destinationId': 'fixture_storage_' + name, 'keyId': 'fixture_storage_' + name}
        for field in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
            path = root / field
            path.mkdir(mode=0o700)
            backup[field] = str(path)
        return {'backup': backup, 'ledger': {'entityId': 'fixture_storage_' + name,
            'scope': dict(self.project_scope), 'stream': 'INSTALLED_STORAGE_' + name.upper(),
            'retention': {'maxBytes': retention.max_bytes, 'reserveBytes': retention.reserve_bytes, 'replicas': 1},
            'history': {'path': str(root / 'history.sqlite'), 'maxRecords': 1000000, 'maxBytes': 1073741824},
            'checkpoint': {'path': str(root / 'checkpoint'), 'commitRef': self.ref(name + '_checkpoint')}}}

    def phase_material(self):
        seed = os.urandom(32)
        path = self.storage_dirs['phase'] / 'signing.key'
        private_bytes(path, seed)
        public = base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
        transport = {'ref': self.ref('storage_phase_transport'), 'identityRef': self.ref('storage_phase'),
            'issuerRef': self.value['identity']['issuer']['issuerRef'], 'method': 'nats-credential-mapping',
            'publicKey': public, 'status': 'active', **self.interval}
        claims = {'purpose': 'agentmux-enrollment-possession-v1',
            'profileId': self.plan['host']['kernelScope']['profileId'],
            'authorityId': self.authority, 'credential': transport}
        self.payloads.append({'identity': {'ref': self.ref('storage_phase'), 'kind': 'service',
            'principalId': 'fixture_storage_phase', 'status': 'active', 'externalIdentity': None},
            'issuers': [], 'transports': [{'record': transport, 'proof': sign_claims(claims, seed)}]})
        return {'serviceIdentityRef': self.ref('storage_phase'), 'transportRef': transport['ref'],
            'keyFile': {'path': str(path), 'sha256': digest(seed)}, 'publicKey': public,
            **{name + 'Grants': {contract: self.ref(name + '_' + contract.replace('-', '_'))
                for contract in ('federation-board-dispatch', 'federation-board-complete')}
               for name in ('card', 'allocation')}}

    def extend_initial_authority(self, state):
        phase = self.value['storage']['board']['phaseAuthority']
        state['memberships'].append({'ref': self.ref('storage_phase_membership'),
            'identityRef': phase['serviceIdentityRef'], 'scope': self.project_scope, 'status': 'active'})
        for name in ('card', 'allocation'):
            for contract, reference in phase[name + 'Grants'].items():
                state['grants'].append({'ref': reference, 'callerRef': phase['serviceIdentityRef'],
                    'actorRef': phase['serviceIdentityRef'], 'scope': self.project_scope, 'contractId': contract,
                    'resourceId': 'fixture_storage_' + name, 'decision': 'allowed', 'delegationRef': None,
                    'definitionTarget': None, 'status': 'active', **self.interval})
        # Authorize later activation with the actual process owner. Never put a
        # guessed generation, epoch or package digest in initial enrollment.
        for name in ('native_host', 'storage_plugin', 'storage_user', 'configuration'):
            state['memberships'].append({'ref': self.ref(name + '_project_membership'),
                'identityRef': self.ref(name), 'scope': self.project_scope, 'status': 'active'})
        state['memberships'].append({'ref': self.ref('native_host_org_membership'),
            'identityRef': self.ref('native_host'), 'scope': self.org_scope, 'status': 'active'})
        def grant(name, actor, scope, contract, resource):
            state['grants'].append({'ref': self.ref(name), 'callerRef': self.ref(actor),
                'actorRef': self.ref(actor), 'scope': scope, 'contractId': contract,
                'resourceId': resource, 'decision': 'allowed', 'delegationRef': None,
                'definitionTarget': None, 'status': 'active', **self.interval})
        grant('native_activation', 'native_host', self.org_scope, 'identity-native-instance-set', self.authority)
        for method in ('activate-instance', 'bind-instance', 'admit-operation', 'recheck', 'prepare-domain-call',
                       'prepare-configuration-initialization', 'prepare-configuration-request',
                       'prepare-subscription-call', 'admit-domain-event'):
            grant('native_' + method.replace('-', '_'), 'native_host', self.project_scope,
                  'native-authority-' + method, 'installed_storage_plugin')
        grant('configuration_change', 'configuration', self.project_scope,
              'configuration-change', 'fixture_storage_configuration')
        for contract in ('configuration-set', 'configuration-read', 'configuration-watch'):
            grant(contract.replace('-', '_'), 'native_host', self.project_scope,
                  contract, 'fixture_storage_configuration')
        for name, resource in (('private', 'fixture_storage_private'), ('card', self.ref('storage_card')['id'])):
            for contract in ('capability-storage-read', 'capability-storage-write', 'capability-outcome-query'):
                grant(name + '_' + contract.replace('-', '_'), 'storage_user', self.project_scope,
                      contract, resource)

    async def provision_selected_resources(self, js):
        storage = self.value['storage']
        for name in ('private', 'card', 'allocation', 'configuration'):
            selected = (self.value['configuration'] if name == 'configuration' else
                        storage['privateStorage'] if name == 'private' else storage['board'][name + 'Publisher'])
            ledger = selected['ledger']
            retention = RETENTION if name == 'configuration' else STORAGE_RETENTION
            binding = OwnerBinding(self.plan['host']['kernelScope']['hubId'],
                'configuration' if name == 'configuration' else 'plugin-private' if name == 'private' else 'federation-board-operations', ledger['entityId'],
                'configuration' if name == 'configuration' else 'plugin-storage' if name == 'private' else 'attempt', canonical_bytes(self.project_scope))
            info = await js.add_stream(retention.stream_config(stream=ledger['stream'], subject=owner_subject(binding)))
            retention.validate(info, stream=ledger['stream'], subject=owner_subject(binding))
            if info.state.messages != 0 or info.state.last_seq != 0:
                from agentmux_contracts import ContractError
                raise ContractError('installed_storage_preparation_stream_occupied')
            source = StreamIdentity(info.created, 0)
            ledger['streamIdentity'] = {'created': stamp(info.created), 'minimumSequence': 0}
            if name == 'configuration':
                owner = OwnerLedger(js, stream=ledger['stream'], subject=owner_subject(binding),
                                    binding=binding, retention=retention, stream_identity=source)
                self.storage_ledgers.append(owner)
                route = ConfigurationEventRoute.from_ledger(owner,
                    account_public_key=self.account.public_key.decode(), jetstream_domain=self.plan['broker']['domain'])
                self.configuration_source = {'configurationRef': {**self.ref('storage_configuration'), 'revision': 0},
                    'schemaRef': self.plan['nativePackage']['schemaRef'],
                    'sourceDigest': route.source_digest, 'streamCreated': route.stream_created}
            if name == 'private':
                selected['bindingDigest'] = private_storage_binding_digest(binding=binding,
                    plugin_identity_ref=selected['pluginIdentityRef'], instance_id=selected['instanceId'],
                    package_id=selected['packageId'], stream=ledger['stream'], stream_identity=source,
                    retention=retention, domain=self.plan['broker']['domain'])
                initial = strict_loads(self.permit.record)
                value = {'formatVersion': 1, 'owner': {key: selected[key]
                    for key in ('pluginIdentityRef', 'instanceId', 'packageId')}, 'value': {'retained': True}}
                initial.update(recordId='fixture_storage_seed', entityId=binding.entity_id,
                    entityKind=binding.entity_kind, ownerDomain=binding.owner_domain, state=value)
                initial['operation'].update(operationId='fixture_storage_seed', scope=self.project_scope,
                                            payloadDigest=payload_digest(value))
                initial['authorizationDecision'].update(operationId='fixture_storage_seed',
                                                        contractId='capability-storage-write')
                owner = OwnerLedger(js, stream=ledger['stream'], subject=owner_subject(binding),
                                    binding=binding, retention=retention, stream_identity=source)
                self.storage_ledgers.append(owner)
                await owner.append(initial, expected_sequence=0, completion_records=0)
            backup = selected['backup']
            host = BackupHost(*(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
                destination_id=backup['destinationId'], binding=binding, stream_identity=source)
            self.storage_backup_hosts.append(host)
            host.enroll_key(backup['keyId'])
        kv = await js.create_key_value(config=KeyValueConfig(bucket='am_board', history=10,
            max_bytes=1048576, storage=StorageType.FILE, replicas=1))
        board = storage['board']
        rid = board['repository']['repositoryId']
        await kv.create(rid + '.seq.IS', b'1')
        revision = await kv.create(rid + '.card.IS-1', canonical_bytes({'key': 'IS-1', 'rid': rid,
            'title': 'Installed storage contract', 'status': 'todo', 'comments': [], 'history': [],
            'unknownFutureField': {'retained': True}}))
        info = await js.stream_info('KV_am_board')
        board['kvStreamIdentity'] = {'created': stamp(info.created), 'minimumSequence': 0}
        board['resourceRef']['revision'] = revision
