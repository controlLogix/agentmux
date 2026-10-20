"""Prepare one disposable installed-service enrollment for the owned JWT fixture.

The Go deployment fixture owns the broker and the original process waits. This
module owns only its setup connection and explicit provisioning ceremony. It
starts no service or provider worker and reports no application readiness.
"""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import ssl
import sys

import nkeys
from nats.js.api import ObjectStoreConfig, StorageType

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.application_client import provision_application_client
from identity.application_enrollment import (_admit, _directory, _read_material,
    _write_material, provision_application_attestor)
from identity.application_host_selection import _path, write_application_attestor_host_selection
from identity.application_service_selection import (ApplicationServiceSelection,
    provision_application_service_issuer, write_application_service_selection)
try:
    from identity.application_service_selection import authority_switch_custody_directory
except ImportError:
    authority_switch_custody_directory = None
from identity.bootstrap import BootstrapOwner, BootstrapPermit
from integration_owner.intent import effect_id
from installed_broker_helpers import close_client, user_credential
from hub.nats_transport import new_client
from native_security.descriptor_admission import DescriptorPurpose
from native_security.nats_credentials import service_policy, validate_service, validate as validate_credential
from state_owner.backup_host import BackupHost
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention


ROLES = ('identity', 'definitions', 'integration')
SERVICE_IDS = ('identity-owner', 'definition-owner', 'integration-owner')
RETENTION = Retention(524288, 131072)
ARTIFACT_BYTES = 1048576
STORAGE_SCENARIO = 'storage-contract'
AUTHORITY_SWITCH_SCENARIO = 'authority-switch-recovery'


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ContractError('installed_service_preparation_input_invalid')


def admit_plan(plan):
    """Check explicit setup pins; native host admission still belongs to Go."""
    closed(plan, ('schemaVersion', 'broker', 'host', 'directory'))
    closed(plan['broker'], ('endpoint', 'rootsPEM', 'serverName', 'domain', 'leafPin', 'accountSeed'))
    broker = plan['broker']
    if any(type(v) is not str for v in broker.values()):
        raise ContractError('installed_service_preparation_input_invalid')
    endpoint = re.fullmatch(r'tls://127\.0\.0\.1:([1-9][0-9]{0,4})', broker['endpoint'])
    labels = broker['serverName'].split('.')
    if (endpoint is None or int(endpoint[1]) > 65535 or len(broker['serverName']) > 253
            or all(label.isdigit() for label in labels)
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', broker['domain'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', broker['leafPin'])
            or len(broker['rootsPEM'].encode()) > 16384
            or broker['rootsPEM'].count('-----BEGIN CERTIFICATE-----') != 1
            or broker['rootsPEM'].count('-----END CERTIFICATE-----') != 1):
        raise ContractError('installed_service_preparation_connection_invalid')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_verify_locations(cadata=broker['rootsPEM'])
    host = plan['host']
    closed(host, ('hostPolicy', 'hostPolicySHA256', 'kernelScope', 'workspaces', 'installationId'))
    scope = host['kernelScope']
    closed(scope, ('hubId', 'instanceId', 'profileId', 'assemblyDigest', 'releaseManifestDigest', 'releaseVersion'))
    if (plan['schemaVersion'] != '1.0.0' or not _path(plan['directory'])
            or not _path(host['hostPolicy']) or type(host['workspaces']) is not list
            or len(host['workspaces']) != 1 or not all(_path(p) for p in host['workspaces'])
            or not re.fullmatch(r'[0-9a-f]{64}', host['installationId'])
            or any(not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', scope[k])
                   for k in ('hubId', 'instanceId', 'profileId'))
            or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', scope[k])
                   for k in ('assemblyDigest', 'releaseManifestDigest'))
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', scope['releaseVersion'])):
        raise ContractError('installed_service_preparation_input_invalid')
    directory = Path(plan['directory'])
    fd, _ = _directory(directory / 'admission')
    try:
        if os.listdir(fd):
            raise ContractError('installed_service_preparation_directory_occupied')
    finally:
        os.close(fd)
    if any(directory.resolve().is_relative_to(Path(p).resolve()) for p in host['workspaces']):
        raise ContractError('installed_service_preparation_inside_workspace')
    raw = _read_material(host['hostPolicy'], max_bytes=65536, return_bytes=True)
    policy = strict_loads(raw)
    if (digest(raw) != host['hostPolicySHA256'] or policy['ownerUid'] != os.getuid()
            or policy['instanceId'] != scope['instanceId'] or policy['profileId'] != scope['profileId']
            or policy['owner']['authenticatedIdentityRef']['ownerHubId'] != scope['hubId']
            or policy['release']['releaseManifestDigest'] != scope['releaseManifestDigest']
            or policy['release']['releaseVersion'] != scope['releaseVersion']
            or plan['broker']['endpoint'] == policy['publicEndpoint']):
        raise ContractError('installed_service_preparation_host_mismatch')
    return directory, policy


def admit_storage_plan(plan):
    """Admit the explicit storage ceremony without broadening baseline setup."""
    closed(plan, ('schemaVersion', 'broker', 'host', 'directory', 'scenario', 'nativePackage'))
    if plan['scenario'] != STORAGE_SCENARIO:
        raise ContractError('installed_storage_preparation_scenario_invalid')
    package = plan['nativePackage']
    closed(package, ('schemaVersion', 'owner', 'manifestDigest', 'configurationChecksum', 'schemaRef', 'schemaBytes'))
    validate('configuration-read', {'configurationRef': {'id': 'fixture_storage_configuration',
        'ownerHubId': plan['host']['kernelScope']['hubId'], 'revision': 0}, 'owner': package['owner']})
    owner = package['owner']
    if (package['schemaVersion'] != '1.0.0' or owner['instanceId'] != 'installed_storage_plugin'
            or owner['pin']['packageId'] != 'installed_storage_package' or owner['generation'] != 1
            or package['manifestDigest'] != owner['pin']['manifestChecksum']
            or type(package['configurationChecksum']) is not str
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', package['configurationChecksum'])
            or package['schemaRef'] != 'schemas/config.json' or type(package['schemaBytes']) is not str):
        raise ContractError('installed_storage_package_invalid')
    try:
        schema = base64.b64decode(package['schemaBytes'], validate=True)
        if not 1 <= len(schema) <= 262144 or base64.b64encode(schema).decode() != package['schemaBytes'] or type(strict_loads(schema)) is not dict:
            raise ValueError()
    except Exception:
        raise ContractError('installed_storage_package_invalid') from None
    return admit_plan({key: plan[key] for key in ('schemaVersion', 'broker', 'host', 'directory')})


def admit_authority_switch_plan(plan):
    """Admit the distinct signed-recovery ceremony without changing baseline setup."""
    closed(plan, ('schemaVersion', 'broker', 'host', 'directory', 'scenario'))
    if plan['scenario'] != AUTHORITY_SWITCH_SCENARIO:
        raise ContractError('installed_authority_switch_preparation_scenario_invalid')
    admitted = admit_plan({key: plan[key]
                           for key in ('schemaVersion', 'broker', 'host', 'directory')})
    directory, _policy = admitted
    host_parent = Path(plan['host']['hostPolicy']).parent
    if (authority_switch_custody_directory is None
            or directory.parent != host_parent
            or Path(authority_switch_custody_directory(
                plan['host']['hostPolicy'])).parent != host_parent):
        raise ContractError('installed_authority_switch_preparation_parent_invalid')
    return admitted


def private_bytes(path, raw):
    """Create once through the same native-private descriptor policy as keys."""
    directory, name = _directory(path)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise ContractError('installed_service_preparation_write_uncertain')
            remaining = remaining[count:]
        os.fsync(fd)
        os.fsync(directory)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


class Preparation:
    """Keep the original setup connection, permit and private inputs reachable."""
    def __init__(self, plan, directory, policy):
        self.plan, self.directory, self.policy = plan, directory, policy
        self.account = self.client = self.bootstrap = self.permit = None
        self.failures = []
        self.protocol_error = False

    def __repr__(self):
        return '<InstalledServicePreparation private>'

    async def broker_error(self, _error):
        self.protocol_error = True

    def materials(self, now):
        """Create real private keys and possession proofs before broker I/O."""
        host, broker, directory = self.plan['host'], self.plan['broker'], self.directory
        kernel = host['kernelScope']
        hub = kernel['hubId']
        self.ref = lambda name: {'id': 'fixture_' + name, 'ownerHubId': hub, 'revision': 1}
        ref = self.ref
        self.organization = self.policy['owner']['scope']['organizationId']
        authority = 'fixture_authority'
        self.authority = authority
        self.org_scope = {'organizationId': self.organization, 'projectId': None, 'workspaceId': None}
        self.project_scope = dict(self.org_scope, projectId='fixture_project')
        self.interval = {'issuedAt': stamp(now - timedelta(seconds=5)), 'expiresAt': stamp(now + timedelta(minutes=15))}
        interval_args = {'issued_at': self.interval['issuedAt'], 'expires_at': self.interval['expiresAt']}
        connection = {k: broker[k] for k in ('endpoint', 'serverName', 'rootsPEM')}
        connection.update(leafCertificateSHA256=broker['leafPin'], jetstreamDomain=broker['domain'])
        self.value = {'schemaVersion': '1.0.0', 'hostPolicy': host['hostPolicy'], 'ownerUid': os.getuid(),
            'workspaces': host['workspaces'], 'kernelScope': kernel, 'authorityId': authority,
            'organizationId': self.organization}
        switch_custody = (directory / 'authority-switch'
            if authority_switch_custody_directory is None else
            Path(authority_switch_custody_directory(host['hostPolicy'])))
        self.value['authoritySwitch'] = {
            'custodyDirectory': str(switch_custody), 'binding': None}
        self.payloads = []
        self.account = nkeys.from_seed(broker['accountSeed'].encode())
        if not self.account.public_key.startswith(b'A'):
            raise ContractError('installed_service_preparation_account_invalid')
        for role, service_id in zip(ROLES, SERVICE_IDS):
            selected_dir = directory / role
            selected_dir.mkdir(mode=0o700)
            identity = {'ref': ref(role), 'kind': 'service', 'status': 'active',
                        'principalId': 'fixture_' + role, 'externalIdentity': None}
            payload, receipt = provision_application_service_issuer(selected_dir / 'issuer.json',
                service_id=service_id, profile_id=kernel['profileId'], authority_id=authority,
                instance_id=kernel['instanceId'], identity=identity, issuer_ref=ref(role + '_issuer'), **interval_args)
            self.payloads.append(payload)
            scope = self.org_scope if role == 'identity' else self.project_scope
            entity = (effect_id(scope, 'fixture_original_operation') if role == 'integration'
                      else authority if role == 'identity' else 'fixture_catalog')
            stream = 'INSTALLED_' + role.upper()
            prefix = '_INBOX.installed_' + role + '_0001'
            options = dict(role=role, hub_id=hub, entity_id=entity, scope=scope,
                stream=stream, reply_prefix=prefix, jetstream_domain=broker['domain'])
            if role != 'identity':
                options['artifact_bucket'] = 'installed_artifacts'
            permissions = service_policy(**options)
            raw = user_credential(self.account, permissions.publish_subjects, permissions.subscribe_subjects,
                                  response=permissions.response_permissions)
            admitted = validate_service(raw, account_public_key=self.account.public_key.decode(), **options)
            path = selected_dir / 'user.creds'
            private_bytes(path, raw)
            self.value[role] = {'credentials': {'path': str(path), 'sha256': digest(raw),
                'accountPublicKey': self.account.public_key.decode(), 'userPublicKey': admitted.public_key,
                'replyPrefix': prefix}, 'connection': dict(connection),
                'issuer': {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
                           'issuerRef': ref(role + '_issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']},
                'ledger': {'entityId': entity, 'scope': scope, 'stream': stream,
                    'retention': {'maxBytes': RETENTION.max_bytes, 'reserveBytes': RETENTION.reserve_bytes, 'replicas': 1},
                    'history': {'path': str(selected_dir / 'history.sqlite'), 'maxRecords': 100000, 'maxBytes': 67108864},
                    'checkpoint': {'path': str(selected_dir / 'checkpoint'), 'commitRef': ref(role + '_checkpoint')}}}
        backup = {'destinationId': 'fixture_backup', 'keyId': 'fixture_backup_key'}
        for field in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
            path = directory / field
            path.mkdir(mode=0o700)
            backup[field] = str(path)
        self.value['identity']['backup'] = backup
        roots = {'projectRoot': host['workspaces'][0], 'home': str(directory / 'home'), 'globalRoot': str(directory / 'global')}
        for field in ('home', 'globalRoot'):
            Path(roots[field]).mkdir(mode=0o700)
        artifacts = {'bucket': 'installed_artifacts', 'storeRef': ref('artifacts'), 'maxBytes': ARTIFACT_BYTES}
        self.value['definitions'].update(directories=roots, artifacts=dict(artifacts))
        # No provider credentials means IntegrationOwner creates no worker.
        # No business grant, intent or query route is enrolled by this case.
        self.value['integration'].update(artifacts=dict(artifacts), provider='github',
            credentialRef=ref('unused_provider_credential'), originalOperationId='fixture_original_operation', credentialEnrollment=None)
        self.prepare_selected_materials(now, connection, interval_args)
        identity_issuer = self.value['identity']['issuer']
        self.attestor_path = directory / 'attestor.json'
        observer = {'ref': ref('observer'), 'principalId': 'fixture_observer', 'kind': 'service',
                    'status': 'active', 'externalIdentity': None}
        self.observer = provision_application_attestor(self.attestor_path, profile_id=kernel['profileId'],
            authority_id=authority, instance_id=kernel['instanceId'], identity=observer,
            issuer_ref=ref('observer_issuer'), transport_ref=ref('observer_transport'),
            ingress_issuer_ref=identity_issuer['issuerRef'], **interval_args)
        self.payloads.append(self.observer)
        self.client_key = directory / 'client-key.json'
        caller = {'ref': ref('client'), 'principalId': 'fixture_client', 'kind': 'service',
                  'status': 'active', 'externalIdentity': None}
        client_selection = {**{k: kernel[k] for k in ('hubId', 'profileId', 'instanceId')},
            'authorityId': authority, 'releaseDigest': kernel['releaseManifestDigest'],
            'policyRef': ref('policy'), 'workspaceRef': None, 'grantRef': ref('bind_grant'),
            'transportRef': ref('client_transport'), 'callerRef': caller['ref'], 'scope': self.org_scope,
            'replyIssuerRef': identity_issuer['issuerRef'], 'replyIssuerPublicKey': identity_issuer['publicKey']}
        self.extend_client_selection(client_selection)
        self.payloads.append(provision_application_client(self.client_key, selection=client_selection,
            identity=caller, **interval_args))
        self.identity_command = '.'.join(('amx', 'v1', 'h', hub, 'o', self.organization, 'identity', authority, 'command'))
        self.attestor_credentials = self.request_credentials('attestor')
        self.client_credentials = self.request_credentials('client')
        self.make_permit(now)

    def prepare_selected_materials(self, now, connection, interval_args):
        """Let a distinct fixture scenario add enrolled services before bootstrap."""

    def extend_client_selection(self, selection):
        """Let a distinct fixture scenario add exact client routes before key creation."""

    def client_publish_subjects(self):
        return [self.identity_command]

    def request_credentials(self, role):
        prefix = '_INBOX.installed_' + role + '_0001'
        subjects = self.client_publish_subjects() if role == 'client' else [self.identity_command]
        raw = user_credential(self.account, subjects, [prefix + '.>'])
        credential = validate_credential(raw, account_public_key=self.account.public_key.decode(),
            publish_subjects=subjects, subscribe_subjects=[prefix + '.>'], private_inbox=True)
        path = self.directory / (role + '.creds')
        private_bytes(path, raw)
        return {'path': str(path), 'sha256': digest(raw), 'accountPublicKey': self.account.public_key.decode(),
                'userPublicKey': credential.public_key, 'replyPrefix': prefix}

    def make_permit(self, now):
        ref, kernel = self.ref, self.plan['host']['kernelScope']
        state = {'schemaVersion': '1.0.0', 'profileId': kernel['profileId'], 'organizationId': self.organization,
            'identities': [p['identity'] for p in self.payloads],
            'issuers': [item['record'] for p in self.payloads for item in p['issuers']],
            'transports': [item['record'] for p in self.payloads for item in p['transports']],
            'memberships': [], 'grants': [], 'approvals': []}
        for role, contract in (('client', 'application-bind'), ('observer', 'application-attest')):
            state['memberships'].append({'ref': ref(role + '_membership'), 'identityRef': ref(role),
                                        'scope': self.org_scope, 'status': 'active'})
            state['grants'].append({'ref': ref('bind_grant' if role == 'client' else 'attest_grant'),
                'callerRef': ref(role), 'actorRef': ref(role), 'scope': self.org_scope, 'contractId': contract,
                'resourceId': kernel['instanceId'], 'decision': 'allowed', 'delegationRef': None,
                'definitionTarget': None, **self.interval, 'status': 'active'})
        self.extend_initial_authority(state)
        actor = self.payloads[0]['identity']
        operation = {'schemaVersion': '1.0.0', 'operationId': 'fixture_identity_bootstrap',
            'payloadDigest': payload_digest(state), 'expectedVersion': 0,
            'caller': {'principalId': actor['principalId'], 'kind': actor['kind'], 'authenticatedIdentityRef': actor['ref']},
            'effectiveActorRef': actor['ref'], 'scope': self.org_scope, 'taskId': None, 'runId': None,
            'attemptId': None, 'delegationRef': None, 'grantRef': ref('bootstrap_grant'), 'approvalRefs': [],
            'traceId': 'fixture_bootstrap_trace', 'causationId': 'fixture_setup',
            'deadline': stamp(now + timedelta(minutes=4)), 'cancellationRef': ref('bootstrap_cancel')}
        record = {'schemaVersion': '1.0.0', 'recordId': 'fixture_initial_authority', 'entityId': self.authority,
            'entityKind': 'identity-authority', 'ownerHubId': kernel['hubId'], 'ownerDomain': 'identity',
            'entityVersion': 1, 'previousRevision': 0, 'operation': operation, 'recordedAt': stamp(now),
            'outcome': 'committed', 'state': state, 'effects': [], 'artifacts': [], 'repository': None,
            'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                'reason': 'explicit_enrollment', 'actorRef': actor['ref'], 'contractId': 'identity-bootstrap'}}
        self.permit = BootstrapPermit(canonical_bytes(record), kernel['hubId'], self.authority,
            kernel['profileId'], self.organization, now, now + timedelta(minutes=4))
        self.proofs = [{'ref': item['record']['ref'], 'proof': item['proof']}
                       for p in self.payloads for kind in ('issuers', 'transports') for item in p[kind]]

    def extend_initial_authority(self, state):
        """The baseline ceremony enrolls only binding and observation grants."""

    async def connect(self):
        import base64
        broker = self.plan['broker']
        raw = user_credential(self.account, ['>'], ['>'])
        token, seed = raw.splitlines()[1], raw.splitlines()[-2]
        def sign(nonce):
            signer = nkeys.from_seed(seed)
            try:
                return base64.b64encode(signer.sign(nonce.encode()))
            finally:
                signer.wipe()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_verify_locations(cadata=broker['rootsPEM'])
        self.client = new_client(require_tls=True, leaf_certificate_sha256=broker['leafPin'])
        await self.client.connect(servers=[broker['endpoint']], tls=tls, tls_hostname=broker['serverName'],
            user_jwt_cb=lambda: token, signature_cb=sign, inbox_prefix='_INBOX.installed_setup_0001',
            tls_handshake_first=True, allow_reconnect=False, max_reconnect_attempts=1,
            connect_timeout=3, error_cb=self.broker_error)

    async def provision(self):
        await self.connect()
        broker = self.plan['broker']
        js = self.client.jetstream(domain=broker['domain'], timeout=3)
        for role in ROLES:
            selected = self.value[role]
            domain, kind = {'identity': ('identity', 'identity-authority'),
                            'definitions': ('definitions', 'definition-catalog'), 'integration': ('integrations', 'effect')}[role]
            ledger = selected['ledger']
            binding = OwnerBinding(self.plan['host']['kernelScope']['hubId'], domain, ledger['entityId'], kind, canonical_bytes(ledger['scope']))
            info = await js.add_stream(RETENTION.stream_config(stream=ledger['stream'], subject=owner_subject(binding)))
            RETENTION.validate(info, stream=ledger['stream'], subject=owner_subject(binding))
            if info.state.messages != 0 or info.state.last_seq != 0:
                raise ContractError('installed_service_preparation_stream_occupied')
            ledger['streamIdentity'] = {'created': stamp(info.created), 'minimumSequence': 0}
        await js.create_object_store(bucket='installed_artifacts', config=ObjectStoreConfig(storage=StorageType.FILE,
                                                       max_bytes=ARTIFACT_BYTES, replicas=1))
        await self.provision_selected_resources(js)
        selection = ApplicationServiceSelection(canonical_bytes(self.value))
        identity = selection.service('identity')
        self.bootstrap = BootstrapOwner(OwnerLedger(js, stream=identity['ledger']['stream'],
            subject=owner_subject(selection.binding('identity')), binding=selection.binding('identity'),
            retention=RETENTION, stream_identity=selection.stream_identity('identity')), self.permit)
        receipt = await self.bootstrap.execute(self.proofs)
        await self.provision_confirmed_resources(js, receipt)
        selection = self.confirmed_selection(receipt)
        identity = selection.service('identity')
        backup = identity['backup']
        backup_host = BackupHost(*(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=selection.binding('identity'), stream_identity=selection.stream_identity('identity'))
        backup_host.enroll_key(backup['keyId'])
        backup_host.load_key(backup['keyId'])
        return self.write_selections(selection, receipt.sequence)

    async def provision_selected_resources(self, js):
        """The baseline has no additional selected resources."""

    async def provision_confirmed_resources(self, js, receipt):
        """The baseline has no post-bootstrap owner records to commit."""

    def confirmed_selection(self, receipt):
        if receipt.sequence != 1 or receipt.replayed or self.protocol_error:
            raise ContractError('installed_service_preparation_bootstrap_unconfirmed')
        # The confirmed append raises the admission floor. An empty or rolled
        # back identity stream must not be admitted by the installed services.
        self.value['identity']['ledger']['streamIdentity']['minimumSequence'] = receipt.sequence
        return ApplicationServiceSelection(canonical_bytes(self.value))

    def write_selections(self, selection, sequence):
        host, broker, kernel = self.plan['host'], self.plan['broker'], self.plan['host']['kernelScope']
        identity = selection.service('identity')['issuer']
        attestor = {k: selection.policy[k] for k in ('schemaVersion', 'hostPolicy', 'ownerUid', 'workspaces', 'kernelScope')}
        attestor.update(keyPath=str(self.attestor_path), credentials=self.attestor_credentials,
            application={'authorityId': self.authority, 'identityRef': self.ref('observer'),
                'issuerRef': self.ref('observer_issuer'), 'transportRef': self.ref('observer_transport'),
                'policyRef': self.ref('policy'), 'workspaceRef': None, 'scope': self.org_scope},
            receiptTrust={'issuerRef': identity['issuerRef'], 'publicKey': identity['publicKey'],
                'notBefore': self.interval['issuedAt'], 'expiresAt': self.interval['expiresAt'],
                'minimumAuthorityRevision': sequence}, initialGeneration=1,
            connection={**{k: broker[k] for k in ('endpoint', 'serverName', 'rootsPEM')},
                        'leafCertificateSHA256': broker['leafPin']})
        attestor_receipt = write_application_attestor_host_selection(self.directory / 'attestor-selection.json', attestor)
        service_receipt = write_application_service_selection(self.directory / 'service-selection.json', selection.policy)
        connection = {'schemaVersion': '1.0.0', **attestor['connection'],
            'credentialsFile': self.client_credentials['path'],
            **{k: self.client_credentials[k] for k in ('accountPublicKey', 'userPublicKey', 'replyPrefix')}}
        connection_path = self.directory / 'client-connection.json'
        _write_material(connection_path, connection, max_bytes=32768)
        client = {'schemaVersion': '1.0.0', 'hostPolicy': host['hostPolicy'], 'workspaces': host['workspaces'],
            'instanceId': kernel['instanceId'], 'profileId': kernel['profileId'], 'hubId': kernel['hubId'],
            'application': {'clientKey': str(self.client_key), 'connection': str(connection_path)},
            'applicationAttestor': {'selection': attestor_receipt.path, 'sha256': attestor_receipt.digest},
            'applicationServices': {'installationId': host['installationId'], 'selection': service_receipt.path, 'sha256': service_receipt.digest}}
        path = self.directory / 'client-selection.json'
        _write_material(path, client, max_bytes=16384)
        return {'schemaVersion': '1.0.0', 'enrollment': str(path), 'sha256': digest(canonical_bytes(client))}


class PreparationFailure(RuntimeError):
    def __init__(self, owner, cause):
        super().__init__('installed_service_preparation_held')
        self.owner, self.cause = owner, cause


async def prepare(plan):
    """Return private enrollment pins after real provisioning and setup join."""
    if type(plan) is dict and plan.get('scenario') == STORAGE_SCENARIO:
        directory, policy = admit_storage_plan(plan)
        from installed_storage_enrollment import StoragePreparation
        owner = StoragePreparation(plan, directory, policy)
    elif type(plan) is dict and plan.get('scenario') == AUTHORITY_SWITCH_SCENARIO:
        directory, policy = admit_authority_switch_plan(plan)
        from installed_authority_switch_enrollment import AuthoritySwitchPreparation
        owner = AuthoritySwitchPreparation(plan, directory, policy)
    else:
        directory, policy = admit_plan(plan)
        owner = Preparation(plan, directory, policy)
    try:
        owner.materials(datetime.now(timezone.utc))
        result = await owner.provision()
        await close_client(owner.client)
        if owner.protocol_error:
            raise ContractError('installed_service_preparation_broker_failure')
        owner.account.wipe()
        return result
    except BaseException as error:
        owner.failures.append(error)
        raise PreparationFailure(owner, error) from None


async def main():
    # Bounded stdin carries private fixture authority, never arguments or logs.
    raw = sys.stdin.buffer.read(131073)
    if len(raw) > 131072:
        raise ContractError('installed_service_preparation_input_invalid')
    try:
        result = await prepare(strict_loads(raw))
    except PreparationFailure as failure:
        await hold_before_reporting(
            lambda: print('installed service preparation held; original owner retained', file=sys.stderr, flush=True),
            lambda: keep_owner(failure))
    else:
        sys.stdout.buffer.write(canonical_bytes(result) + b'\n')
        sys.stdout.buffer.flush()


async def hold_before_reporting(report, hold):
    try:
        report()
    finally:
        await hold()


async def keep_owner(failure):
    # The wrapper must preserve its original broker/process owners too.
    # No retry, resource deletion, PID adoption or exit-based recovery occurs.
    while True:
        await asyncio.sleep(1)
        if failure.owner is None:
            raise AssertionError('installed_service_preparation_owner_lost')


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except BaseException:
        print('installed service preparation input refused', file=sys.stderr)
        raise SystemExit(1) from None
