"""Local application enrollment ceremony for one installation (AMUX-728).

This is the trusted provisioning ceremony that ``identity.bootstrap`` expects.
It runs once per installation, before ``prepare-owner-profile``, against the
installation's own application NATS runtime (``agentmux-runtime
application-runtime``). It generates every private key and credential locally,
commits the initial identity authority, and writes the attestor, service and
client selections plus the pinned ``coreHub`` manifest.

The ceremony is staged. Each stage writes create-only private files, so a rerun
resumes after the last complete stage and never regenerates a retained key:

1. ``materials``: keys, credentials, possession proofs and the bootstrap state.
2. ``bootstrap``: streams, the artifact store and the committed authority.
3. ``selections``: Hub files, service/attestor/client selections and coreHub.

It grants nothing from labels, never copies another installation's material and
never contacts the protected infrastructure broker.
"""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time

import nkeys
from nats.js.api import ObjectStoreConfig, StorageType

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed.policy import rid_for_remote
from hub.nats_transport import new_client
from hub.store import APP_ID, MIGRATIONS, Store
from identity.application_client import provision_application_client
from identity.application_enrollment import (_directory, _read_material, _write_material,
                                             provision_application_attestor)
from identity.application_host_selection import write_application_attestor_host_selection
from identity.application_service_selection import (ApplicationServiceSelection, authority_switch_custody_directory,
    provision_application_service_issuer, write_application_service_selection)
from identity.bootstrap import BootstrapOwner, BootstrapPermit
from integration_owner.intent import effect_id
from native_security.nats_credentials import (service_policy, storage_receiver_policy, validate as validate_credential,
    validate_service, validate_storage_receiver)
from state_owner.backup_host import BackupHost
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject
from state_owner.retention import Retention

SCHEMA_VERSION = '1.0.0'
SERVICE_ROLES = (('identity', 'identity-owner'), ('definitions', 'definition-owner'), ('integration', 'integration-owner'))
RECEIVERS = ('storage', 'outcome')
FAMILIES = ('identity', 'messages', 'work')
# One client key per Hub session: the identity route plus operator and
# federation routes for messages and Work (source binding, register, sweep).
SESSIONS = (('identity', 'identity', None), ('messages-operator', 'messages', 'operator'),
            ('messages-federation', 'messages', 'federation'), ('work-operator', 'work', 'operator'),
            ('work-federation', 'work', 'federation'))
RETENTION = Retention(524288, 131072)
ARTIFACT_BYTES = 1048576
LEGACY_BROWSER_PORT = 8787
MESSAGE_OPERATOR = ('send', 'approve', 'inspect', 'outcome')
MESSAGE_SERVICE = ('deliver', 'inspect', 'outcome')
WORK_OPERATOR = ('create', 'claim', 'heartbeat', 'release', 'claim-path', 'read', 'inspect', 'outcome', 'cancel')
WORK_SERVICE = ('ingest', 'revoke', 'inspect', 'outcome', 'register', 'state', 'sweep-global', 'read')
_ID = re.compile(r'[a-z][a-z0-9_-]{0,63}')
# Matches application-message/work-commands localPeer, peer and localNode.
_PEER = re.compile(r'[a-z0-9_]{1,32}')
_REPO = re.compile(r'[a-z0-9_]{1,32}')
_REMOTE = re.compile(r'[a-z0-9][a-z0-9._/-]{0,199}')
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
AGENTMUX = Path.home() / 'Library' / 'Application Support' / 'Agentmux'


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _closed(value, required, optional=()):
    if type(value) is not dict or not set(required) <= set(value) <= set(required) | set(optional):
        raise ContractError('local_enrollment_request_invalid')


def _private_bytes(path, raw):
    """Create once as an owner-private file through the shared native policy."""
    directory, name = _directory(path)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ContractError('local_enrollment_write_uncertain')
            view = view[count:]
        os.fsync(fd)
        os.fsync(directory)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def _private_dir(path):
    path = Path(path)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    meta = os.lstat(path)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise ContractError('local_enrollment_directory_unsafe')
    return path


def _public_json(path):
    """Read installed public metadata: root- or owner-owned, never writable by others."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid not in (0, os.getuid())
                or meta.st_mode & 0o022 or meta.st_size > 65536):
            raise ContractError('local_enrollment_release_invalid')
        return strict_loads(os.read(fd, meta.st_size + 1))
    finally:
        os.close(fd)


def user_credential(account, publish, subscribe, *, name, expires_at, response=None):
    """Issue one least-privilege user under this installation's account key."""
    key = nkeys.from_seed(nkeys.encode_seed(secrets.token_bytes(32), nkeys.PREFIX_BYTE_USER))
    try:
        claims = {'iat': int(time.time()), 'exp': int(expires_at.timestamp()),
                  'iss': account.public_key.decode(), 'sub': key.public_key.decode(), 'name': name}
        claims['jti'] = base64.b32encode(hashlib.new('sha512_256', canonical_bytes(claims)).digest()).decode().rstrip('=')
        permissions = {'type': 'user', 'version': 2, 'pub': {'allow': list(publish)},
                       'sub': {'allow': list(subscribe)}, 'subs': -1, 'data': -1, 'payload': -1}
        if response is not None:
            permissions['resp'] = response
        claims['nats'] = permissions

        def encoded(value):
            return base64.urlsafe_b64encode(canonical_bytes(value)).rstrip(b'=')
        message = encoded({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encoded(claims)
        token = message + b'.' + base64.urlsafe_b64encode(account.sign(message)).rstrip(b'=')
        return (b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n'
                + b'-----BEGIN USER NKEY SEED-----\n' + key.seed + b'\n------END USER NKEY SEED------\n')
    finally:
        key.wipe()


def admit_request(path, expected):
    """Admit the private setup request and the owner request it pins."""
    raw = _read_material(path, max_bytes=65536, return_bytes=True)
    if digest(raw) != expected:
        raise ContractError('local_enrollment_request_changed')
    request = strict_loads(raw)
    _closed(request, ('schemaVersion', 'ownerRequest', 'projectId', 'repositories', 'localPeer',
                      'localNode', 'messagePeer', 'validityDays'), ('applicationRuntime',))
    _closed(request['ownerRequest'], ('path', 'sha256'))
    if (request['schemaVersion'] != SCHEMA_VERSION or not _ID.fullmatch(str(request['projectId']))
            or any(not _PEER.fullmatch(str(request[k])) for k in ('localPeer', 'messagePeer'))
            or request['localPeer'] == request['messagePeer'] or not _PEER.fullmatch(str(request['localNode']))
            or type(request['validityDays']) is not int or not 1 <= request['validityDays'] <= 397
            or not _DIGEST.fullmatch(str(request['ownerRequest']['sha256']))
            or type(request['repositories']) is not list or not 1 <= len(request['repositories']) <= 16):
        raise ContractError('local_enrollment_request_invalid')
    owner_raw = _read_material(request['ownerRequest']['path'], max_bytes=65536, return_bytes=True)
    if digest(owner_raw) != request['ownerRequest']['sha256']:
        raise ContractError('local_enrollment_owner_request_changed')
    owner = strict_loads(owner_raw)
    roots = owner['approvedWorkspaceRoots']
    names = set()
    for repository in request['repositories']:
        _closed(repository, ('root', 'localName', 'normalizedRemote'))
        if (repository['root'] not in roots or not _REPO.fullmatch(str(repository['localName']))
                or not _REMOTE.fullmatch(str(repository['normalizedRemote'])) or repository['localName'] in names):
            raise ContractError('local_enrollment_repository_invalid')
        names.add(repository['localName'])
    if {r['root'] for r in request['repositories']} != set(roots):
        raise ContractError('local_enrollment_repository_coverage')
    return request, owner


class Ceremony:
    """Hold the setup connection and every private input until the run ends."""

    def __init__(self, request, owner, *, root=None, runtime=None):
        self.request, self.owner = request, owner
        enrollment = owner['owner']
        self.hub = enrollment['authenticatedIdentityRef']['ownerHubId']
        self.profile, self.instance = enrollment['profileId'], enrollment['instanceId']
        self.organization = enrollment['scope']['organizationId']
        root = Path(root) if root is not None else AGENTMUX
        self.directory = root / 'application-enrollment' / self.profile
        self.home = root / 'hubs' / self.profile
        self.host_policy = str(root / 'profiles' / self.profile / 'host-policy.json')
        runtime = Path(request.get('applicationRuntime') or runtime or (root / 'application-runtime'))
        self.runtime = strict_loads(_read_material(runtime / 'runtime.json', max_bytes=65536, return_bytes=True))
        account_seed = _read_material(runtime / 'account.nk', max_bytes=256, return_bytes=True).strip()
        self.account = nkeys.from_seed(account_seed)
        if self.account.public_key.decode() != self.runtime['accountPublicKey']:
            raise ContractError('local_enrollment_runtime_mismatch')
        if self.runtime['endpoint'] == 'tls://127.0.0.1:%d' % owner['hostPort']:
            raise ContractError('local_enrollment_infrastructure_endpoint')
        release = _public_json(Path(owner['release']['packageDirectory']) / 'release-authorization.json')
        if release['releaseManifestDigest'] != owner['release']['releaseManifestDigest']:
            raise ContractError('local_enrollment_release_mismatch')
        self.kernel = {'hubId': self.hub, 'instanceId': self.instance, 'profileId': self.profile,
                       'assemblyDigest': release['assemblyDigest'],
                       'releaseManifestDigest': release['releaseManifestDigest'], 'releaseVersion': release['releaseVersion']}
        self.workspaces = list(owner['approvedWorkspaceRoots'])
        self.org_scope = {'organizationId': self.organization, 'projectId': None, 'workspaceId': None}
        self.project_scope = dict(self.org_scope, projectId=request['projectId'])
        self.authority = 'local_authority'
        # Streams and buckets are per profile inside the installation's runtime.
        self.suffix = hashlib.sha256(self.profile.encode()).hexdigest()[:12]
        self.artifact_bucket = 'local_artifacts_' + self.suffix
        self.client = None
        self.protocol_error = False

    def ref(self, name):
        return {'id': 'local_' + name, 'ownerHubId': self.hub, 'revision': 1}

    def __repr__(self):
        return '<LocalEnrollmentCeremony private>'

    # Stage 1: materials ----------------------------------------------------------

    def connection(self):
        r = self.runtime
        return {'endpoint': r['endpoint'], 'serverName': r['serverName'], 'rootsPEM': r['rootsPEM'],
                'leafCertificateSHA256': r['leafCertificateSHA256'], 'jetstreamDomain': r['domain']}

    def credentials(self, directory, name, publish, subscribe, *, response=None, validator=None, inputs=None):
        account = self.account.public_key.decode()
        raw = user_credential(self.account, publish, subscribe, name='agentmux-' + name,
                              expires_at=self.expires, response=response)
        if validator is not None:
            admitted = validator(raw, account_public_key=account, **inputs)
        else:
            admitted = validate_credential(raw, account_public_key=account, publish_subjects=publish,
                                           subscribe_subjects=subscribe, private_inbox=True)
        path = directory / 'user.creds'
        _private_bytes(path, raw)
        return {'path': str(path), 'sha256': digest(raw), 'accountPublicKey': account,
                'userPublicKey': admitted.public_key, 'replyPrefix': inputs['reply_prefix'] if inputs else subscribe[0][:-2]}

    def materials(self, staging, now):
        """Create real keys, credentials and possession proofs before broker I/O."""
        self.expires = now + timedelta(days=self.request['validityDays'])
        self.interval = {'issuedAt': stamp(now - timedelta(seconds=5)), 'expiresAt': stamp(self.expires)}
        interval = {'issued_at': self.interval['issuedAt'], 'expires_at': self.interval['expiresAt']}
        ref, payloads = self.ref, []
        value = {'schemaVersion': SCHEMA_VERSION, 'hostPolicy': self.host_policy, 'ownerUid': os.getuid(),
                 'workspaces': self.workspaces, 'kernelScope': self.kernel, 'authorityId': self.authority,
                 'organizationId': self.organization,
                 'authoritySwitch': {'custodyDirectory': authority_switch_custody_directory(self.host_policy), 'binding': None}}
        connection = self.connection()
        for role, service_id in SERVICE_ROLES:
            selected = _private_dir(staging / role)
            identity = {'ref': ref(role), 'kind': 'service', 'status': 'active',
                        'principalId': 'local_' + role, 'externalIdentity': None}
            payload, receipt = provision_application_service_issuer(selected / 'issuer.json', service_id=service_id,
                profile_id=self.profile, authority_id=self.authority, instance_id=self.instance, identity=identity,
                issuer_ref=ref(role + '_issuer'), **interval)
            payloads.append(payload)
            scope = self.org_scope if role == 'identity' else self.project_scope
            entity = (self.authority if role == 'identity' else 'local_catalog' if role == 'definitions'
                      else effect_id(scope, 'local_original_operation'))
            # One runtime may serve several profiles; streams are per profile.
            stream = 'LOCAL_' + role.upper() + '_' + self.suffix.upper()
            prefix = '_INBOX.local_' + role + '_0001'
            options = dict(role=role, hub_id=self.hub, entity_id=entity, scope=scope, stream=stream,
                           reply_prefix=prefix, jetstream_domain=self.runtime['domain'])
            if role != 'identity':
                options['artifact_bucket'] = self.artifact_bucket
            permissions = service_policy(**options)
            creds = self.credentials(selected, role, permissions.publish_subjects, permissions.subscribe_subjects,
                                     response=permissions.response_permissions, validator=validate_service, inputs=options)
            value[role] = {'credentials': creds, 'connection': dict(connection),
                'issuer': {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
                           'issuerRef': ref(role + '_issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']},
                'ledger': {'entityId': entity, 'scope': scope, 'stream': stream,
                    'retention': {'maxBytes': RETENTION.max_bytes, 'reserveBytes': RETENTION.reserve_bytes, 'replicas': 1},
                    'history': {'path': str(selected / 'history.sqlite'), 'maxRecords': 100000, 'maxBytes': 67108864},
                    'checkpoint': {'path': str(selected / 'checkpoint'), 'commitRef': ref(role + '_checkpoint')}}}
        backup = {'destinationId': 'local_backup', 'keyId': 'local_backup_key'}
        for field in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
            backup[field] = str(_private_dir(staging / field))
        value['identity']['backup'] = backup
        roots = {'projectRoot': self.workspaces[0], 'home': str(_private_dir(staging / 'definitions-home')),
                 'globalRoot': str(_private_dir(staging / 'definitions-global'))}
        artifacts = {'bucket': self.artifact_bucket, 'storeRef': ref('artifacts'), 'maxBytes': ARTIFACT_BYTES}
        value['definitions'].update(directories=roots, artifacts=dict(artifacts))
        # No provider credential: the integration owner creates no worker.
        value['integration'].update(artifacts=dict(artifacts), provider='github', credentialRef=ref('unused_provider_credential'),
                                    originalOperationId='local_original_operation', credentialEnrollment=None)
        identity_issuer = value['identity']['issuer']
        storage, extra_identities = self.storage_materials(staging, value, connection, payloads, interval)
        value['storage'] = storage
        # A private per-installation port for the services host's local browser
        # listener, chosen once and retained, never the historical shared default.
        value['localBrowser'] = {'port': self.local_browser_port()}
        observer = {'ref': ref('observer'), 'principalId': 'local_observer', 'kind': 'service',
                    'status': 'active', 'externalIdentity': None}
        payloads.append(provision_application_attestor(staging / 'attestor.json', profile_id=self.profile,
            authority_id=self.authority, instance_id=self.instance, identity=observer, issuer_ref=ref('observer_issuer'),
            transport_ref=ref('observer_transport'), ingress_issuer_ref=identity_issuer['issuerRef'], **interval))
        self.identity_command = '.'.join(('amx', 'v1', 'h', self.hub, 'o', self.organization, 'identity',
                                          self.authority, 'command'))
        attestor_dir = _private_dir(staging / 'attestor')
        attestor_credentials = self.credentials(attestor_dir, 'attestor', [self.identity_command],
                                                ['_INBOX.local_attestor_0001.>'])
        families = self.family_materials(staging, value, payloads, interval, extra_identities)
        state = self.initial_state(payloads, extra_identities, families)
        return {'schemaVersion': SCHEMA_VERSION, 'interval': self.interval, 'service': value,
                'attestor': {'keyPath': str(staging / 'attestor.json'), 'credentials': attestor_credentials},
                'families': families, 'state': state, 'payloads': payloads}

    def local_browser_port(self):
        import socket
        reserved = {LEGACY_BROWSER_PORT, self.owner['hostPort'], int(self.runtime['endpoint'].rsplit(':', 1)[1])}
        for _ in range(32):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            if 1024 <= port <= 65535 and port not in reserved:
                return port
        raise ContractError('local_enrollment_browser_port_unavailable')

    def storage_materials(self, staging, value, connection, payloads, interval):
        """Enroll the Hub's messages and Work storage owners on hub.db."""
        ref = self.ref
        receivers = {}
        for name in RECEIVERS:
            selected = _private_dir(staging / name)
            identity = {'ref': ref(name), 'kind': 'service', 'status': 'active',
                        'principalId': 'local_' + name, 'externalIdentity': None}
            payload, receipt = provision_application_service_issuer(selected / 'issuer.json', service_id=name + '-owner',
                profile_id=self.profile, authority_id=self.authority, instance_id=self.instance, identity=identity,
                issuer_ref=ref(name + '_issuer'), **interval)
            payloads.append(payload)
            inputs = {'hub_id': self.hub, 'scope': self.project_scope, 'service_id': name + '-owner',
                      'reply_prefix': '_INBOX.local_storage_' + name + '_0001'}
            policy = storage_receiver_policy(**inputs)
            creds = self.credentials(selected, name, policy.publish_subjects, policy.subscribe_subjects,
                                     response=policy.response_permissions, validator=validate_storage_receiver, inputs=inputs)
            receivers[name] = {'connection': dict(connection), 'credentials': creds,
                'issuer': {'keyFile': {'path': receipt.path, 'sha256': receipt.digest}, 'issuerRef': ref(name + '_issuer'),
                           'publicKey': payload['issuers'][0]['record']['publicKey']},
                'serviceIdentityRef': identity['ref'], 'serviceInstanceId': self.instance,
                'requestSigningKeyRef': value['identity']['issuer']['issuerRef']}
        hubdir = self.home / 'hub'
        repository = self.request['repositories'][0]
        source = {'database': {'path': str(hubdir / 'hub.db'), 'applicationId': APP_ID, 'userVersion': len(MIGRATIONS)},
                  'policy': {'path': str(hubdir / 'federation.toml'), 'sha256': digest(self.federation_policy())}}
        repo = {'localName': repository['localName'], 'repositoryId': rid_for_remote(repository['normalizedRemote']),
                'normalizedRemote': repository['normalizedRemote']}
        operator, federation = ref('operator'), ref('federation')
        grants = {
            'messages': {
                'operator': {'federation-message-' + c: ref('message_operator_' + c.replace('-', '_')) for c in MESSAGE_OPERATOR},
                'federation': {'federation-message-' + c: ref('message_federation_' + c.replace('-', '_')) for c in MESSAGE_SERVICE}},
            'work': {
                'operator': {'federation-work-' + c: ref('work_operator_' + c.replace('-', '_')) for c in WORK_OPERATOR},
                'federation': {'federation-work-' + c: ref('work_federation_' + c.replace('-', '_')) for c in WORK_SERVICE}}}
        self.grants = grants
        common = {'localPeer': self.request['localPeer'], 'localNode': self.request['localNode']}
        messages = {'source': source, 'repository': repo, **common, 'channels': [{
            'resourceRef': ref('message_channel'), 'peer': self.request['messagePeer'],
            'actors': [{'identityRef': operator, 'transportRef': ref('operator_message_transport'), 'caller': 'operator'}],
            'pluginIdentityRef': ref('plugin'), 'instanceId': 'local_messages', 'initialSource': None,
            'legacyActors': [
                {'identityRef': operator, 'transportRef': ref('operator_message_transport'), 'caller': 'operator',
                 'grants': grants['messages']['operator']},
                {'identityRef': federation, 'transportRef': ref('federation_message_transport'), 'caller': 'federation',
                 'grants': grants['messages']['federation']}]}]}
        work = {'source': source, 'repository': repo, **common, 'channels': [{
            'resourceRef': ref('work_channel'),
            'actors': [{'identityRef': operator, 'transportRef': ref('operator_work_transport'), 'caller': 'operator'}],
            'pluginIdentityRef': ref('plugin'), 'instanceId': 'local_work', 'initialSource': None,
            'legacyActors': [
                {'identityRef': operator, 'transportRef': ref('operator_work_transport'), 'caller': 'operator',
                 'grants': grants['work']['operator']},
                {'identityRef': federation, 'transportRef': ref('federation_work_transport'), 'caller': 'federation',
                 'grants': grants['work']['federation']}]}]}
        extra = [{'ref': operator, 'kind': 'human', 'status': 'active',
                  'principalId': self.owner['owner']['principalId'], 'externalIdentity': None},
                 {'ref': federation, 'kind': 'service', 'status': 'active', 'principalId': 'local_federation',
                  'externalIdentity': None},
                 {'ref': ref('plugin'), 'kind': 'plugin', 'status': 'active', 'principalId': 'local_plugin',
                  'externalIdentity': None}]
        return {'scope': self.project_scope, 'receivers': receivers, 'messages': messages, 'work': work}, extra

    def family_materials(self, staging, value, payloads, interval, extra_identities):
        """One client key, connection and credential per core Hub session."""
        ref = self.ref
        identity_issuer = value['identity']['issuer']
        storage_issuer = value['storage']['receivers']['storage']['issuer']
        subject = '.'.join(('amx', 'v1', 'h', self.hub, 'o', self.organization, 'p', self.request['projectId'],
                            'w', '_', 'capability', 'storage-owner', 'command'))
        repository = self.request['repositories'][0]
        repo = {'localName': repository['localName'], 'repositoryId': rid_for_remote(repository['normalizedRemote'])}
        callers = {'operator': extra_identities[0], 'federation': extra_identities[1]}
        sessions = {}
        for name, family, route in SESSIONS:
            selected = _private_dir(staging / ('client-' + name))
            caller = callers[route or 'operator']
            key = name.replace('-', '_')
            selection = {'hubId': self.hub, 'profileId': self.profile, 'instanceId': self.instance,
                'authorityId': self.authority, 'releaseDigest': self.kernel['releaseManifestDigest'],
                'policyRef': ref('policy'), 'workspaceRef': None, 'grantRef': ref(key + '_bind_grant'),
                'transportRef': ref(key + '_client_transport'), 'callerRef': caller['ref'], 'scope': self.project_scope,
                'replyIssuerRef': identity_issuer['issuerRef'], 'replyIssuerPublicKey': identity_issuer['publicKey']}
            publish = [self.identity_command]
            if family == 'identity':
                selection['legacyAliasResolve'] = {'subject': self.identity_command, 'grantRef': ref('alias_resolve_grant'),
                    'transportRef': ref('alias_resolve_transport'), 'replyIssuerRef': identity_issuer['issuerRef'],
                    'replyIssuerPublicKey': identity_issuer['publicKey']}
            else:
                channel = 'message' if family == 'messages' else 'work'
                block = {'transportRef': ref(route + '_' + channel + '_transport'),
                    'replyIssuerRef': storage_issuer['issuerRef'], 'replyIssuerPublicKey': storage_issuer['publicKey'],
                    'serviceIdentityRef': ref('storage'), 'serviceInstanceId': self.instance,
                    'resourceRef': ref(channel + '_channel'), 'authenticatedCaller': route, 'subject': subject,
                    'localPeer': self.request['localPeer'], 'localNode': self.request['localNode'], 'repository': repo,
                    'grantRefs': self.grants[family][route]}
                if family == 'messages':
                    block['peer'] = self.request['messagePeer']
                    selection['messageCommands'] = block
                else:
                    selection['workCommands'] = block
                publish.append(subject)
            payload = provision_application_client(selected / 'client-key.json', selection=selection,
                                                   identity=caller, **interval)
            payloads.append(payload)
            prefix = '_INBOX.local_client_' + key + '_0001'
            creds = self.credentials(selected, 'client-' + name, publish, [prefix + '.>'])
            sessions[name] = {'family': family, 'caller': caller['ref'], 'clientKey': str(selected / 'client-key.json'),
                              'credentials': creds, 'directory': str(selected)}
        return sessions

    def initial_state(self, payloads, extra_identities, families):
        ref = self.ref
        identities = {}
        for item in [p['identity'] for p in payloads] + extra_identities:
            identities[canonical_bytes(item['ref'])] = item
        state = {'schemaVersion': SCHEMA_VERSION, 'profileId': self.profile, 'organizationId': self.organization,
            'identities': list(identities.values()),
            'issuers': [item['record'] for p in payloads for item in p['issuers']],
            'transports': [item['record'] for p in payloads for item in p['transports']],
            'memberships': [], 'grants': [], 'approvals': []}

        def grant(name, identity, contract, resource, scope):
            state['grants'].append({'ref': name, 'callerRef': identity, 'actorRef': identity, 'scope': scope,
                'contractId': contract, 'resourceId': resource, 'decision': 'allowed', 'delegationRef': None,
                'definitionTarget': None, **self.interval, 'status': 'active'})

        operator, federation, observer = ref('operator'), ref('federation'), ref('observer')
        for identity, scope in ((operator, self.org_scope), (operator, self.project_scope),
                                (federation, self.project_scope), (observer, self.org_scope)):
            state['memberships'].append({'ref': {**identity, 'id': identity['id'] + '_' + ('org' if scope is self.org_scope else 'project') + '_membership'},
                                         'identityRef': identity, 'scope': scope, 'status': 'active'})
        for name, session in families.items():
            grant(ref(name.replace('-', '_') + '_bind_grant'), session['caller'], 'application-bind',
                  self.instance, self.project_scope)
        grant(ref('attest_grant'), observer, 'application-attest', self.instance, self.org_scope)
        grant(ref('alias_resolve_grant'), operator, 'identity-legacy-alias-resolve', self.authority, self.project_scope)
        for family, channel in (('messages', 'message_channel'), ('work', 'work_channel')):
            for caller, identity in (('operator', operator), ('federation', federation)):
                for contract, name in self.grants[family][caller].items():
                    grant(name, identity, contract, 'local_' + channel, self.project_scope)
        return state

    # Stage 2: bootstrap ----------------------------------------------------------

    async def connect(self):
        raw = user_credential(self.account, ['>'], ['>'], name='agentmux-setup',
                              expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
        lines = raw.splitlines()
        token, seed = lines[1], lines[-2]

        def sign(nonce):
            signer = nkeys.from_seed(seed)
            try:
                return base64.b64encode(signer.sign(nonce.encode()))
            finally:
                signer.wipe()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_verify_locations(cadata=self.runtime['rootsPEM'])

        async def error(_):
            self.protocol_error = True
        self.client = new_client(require_tls=True, leaf_certificate_sha256=self.runtime['leafCertificateSHA256'])
        await self.client.connect(servers=[self.runtime['endpoint']], tls=tls, tls_hostname=self.runtime['serverName'],
            user_jwt_cb=lambda: token, signature_cb=sign, inbox_prefix='_INBOX.local_setup_0001',
            tls_handshake_first=True, allow_reconnect=False, max_reconnect_attempts=1, connect_timeout=3,
            error_cb=error)

    def permit(self, materials, now):
        ref, state = self.ref, materials['state']
        actor = materials['payloads'][0]['identity']
        operation = {'schemaVersion': SCHEMA_VERSION, 'operationId': 'local_identity_bootstrap',
            'payloadDigest': payload_digest(state), 'expectedVersion': 0,
            'caller': {'principalId': actor['principalId'], 'kind': actor['kind'], 'authenticatedIdentityRef': actor['ref']},
            'effectiveActorRef': actor['ref'], 'scope': self.org_scope, 'taskId': None, 'runId': None,
            'attemptId': None, 'delegationRef': None, 'grantRef': ref('bootstrap_grant'), 'approvalRefs': [],
            'traceId': 'local_bootstrap_trace', 'causationId': 'local_setup',
            'deadline': stamp(now + timedelta(minutes=4)), 'cancellationRef': ref('bootstrap_cancel')}
        record = {'schemaVersion': SCHEMA_VERSION, 'recordId': 'local_initial_authority', 'entityId': self.authority,
            'entityKind': 'identity-authority', 'ownerHubId': self.hub, 'ownerDomain': 'identity', 'entityVersion': 1,
            'previousRevision': 0, 'operation': operation, 'recordedAt': stamp(now), 'outcome': 'committed',
            'state': state, 'effects': [], 'artifacts': [], 'repository': None,
            'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                'reason': 'explicit_enrollment', 'actorRef': actor['ref'], 'contractId': 'identity-bootstrap'}}
        return BootstrapPermit(canonical_bytes(record), self.hub, self.authority, self.profile, self.organization,
                               now, now + timedelta(minutes=4))

    async def bootstrap(self, materials):
        await self.connect()
        js = self.client.jetstream(domain=self.runtime['domain'], timeout=3)
        value = materials['service']
        committed = False
        for role, _service in SERVICE_ROLES:
            ledger = value[role]['ledger']
            domain, kind = {'identity': ('identity', 'identity-authority'), 'definitions': ('definitions', 'definition-catalog'),
                            'integration': ('integrations', 'effect')}[role]
            binding = OwnerBinding(self.hub, domain, ledger['entityId'], kind, canonical_bytes(ledger['scope']))
            info = await js.add_stream(RETENTION.stream_config(stream=ledger['stream'], subject=owner_subject(binding)))
            RETENTION.validate(info, stream=ledger['stream'], subject=owner_subject(binding))
            ledger['streamIdentity'] = {'created': stamp(info.created), 'minimumSequence': 0}
            if info.state.messages == 0 and info.state.last_seq == 0:
                continue
            # An interrupted run may already have committed. Accept only this
            # ceremony's own record as the single identity entry.
            if role != 'identity' or info.state.messages != 1 or info.state.last_seq != 1:
                raise ContractError('local_enrollment_stream_occupied')
            record = strict_loads((await js.get_msg(ledger['stream'], seq=1)).data)
            if (record.get('recordId') != 'local_initial_authority'
                    or record.get('operation', {}).get('payloadDigest') != payload_digest(materials['state'])):
                raise ContractError('local_enrollment_stream_occupied')
            committed = True
        await js.create_object_store(bucket=self.artifact_bucket, config=ObjectStoreConfig(
            storage=StorageType.FILE, max_bytes=ARTIFACT_BYTES, replicas=1))
        if not committed:
            selection = ApplicationServiceSelection(canonical_bytes(value))
            identity = selection.service('identity')
            proofs = [{'ref': item['record']['ref'], 'proof': item['proof']}
                      for p in materials['payloads'] for kind in ('issuers', 'transports') for item in p[kind]]
            owner = BootstrapOwner(OwnerLedger(js, stream=identity['ledger']['stream'],
                subject=owner_subject(selection.binding('identity')), binding=selection.binding('identity'),
                retention=RETENTION, stream_identity=selection.stream_identity('identity')),
                self.permit(materials, datetime.now(timezone.utc)))
            receipt = await owner.execute(proofs)
            if receipt.sequence != 1 or receipt.replayed or self.protocol_error:
                raise ContractError('local_enrollment_bootstrap_unconfirmed')
        value['identity']['ledger']['streamIdentity']['minimumSequence'] = 1
        selection = ApplicationServiceSelection(canonical_bytes(value))
        backup = selection.service('identity')['backup']
        backup_host = BackupHost(*(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=selection.binding('identity'),
            stream_identity=selection.stream_identity('identity'))
        try:
            backup_host.load_key(backup['keyId'])
        except ContractError:
            backup_host.enroll_key(backup['keyId'])
            backup_host.load_key(backup['keyId'])
        return {'schemaVersion': SCHEMA_VERSION, 'sequence': 1, 'service': value}

    async def close(self):
        client, self.client = self.client, None
        if client is None:
            return
        tasks = tuple(task for name in ('_reading_task', '_ping_interval_task', '_flusher_task', '_reconnection_task')
                      if isinstance((task := getattr(client, name, None)), asyncio.Task))
        try:
            await client.close()
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    # Stage 3: selections ---------------------------------------------------------

    def federation_policy(self):
        repository = self.request['repositories'][0]
        lines = ['[federation]', 'peer = "%s"' % self.request['localPeer'], '',
                 '[repos.%s]' % repository['localName'], 'remote = "%s"' % repository['normalizedRemote'], '',
                 # "approve" is the most restrictive trust the message owner admits:
                 # every message from the peer needs explicit human approval. A
                 # "deny" peer makes MessageStorageResource refuse the channel as
                 # stale, which stops the whole storage host. No link to this
                 # peer exists until federation enrollment adds one.
                 '[peers.%s]' % self.request['messagePeer'], 'trust = "approve"', '']
        return '\n'.join(lines).encode()

    def hub_files(self):
        hubdir = _private_dir(_private_dir(_private_dir(self.home.parent) / self.home.name) / 'hub')
        for name, raw in (('federation.toml', self.federation_policy()),
                          ('config.toml', ('node = "%s"\n' % self.request['localNode']).encode())):
            path = hubdir / name
            if path.exists():
                if _read_material(path, max_bytes=65536, return_bytes=True) != raw:
                    raise ContractError('local_enrollment_hub_file_conflict')
            else:
                _private_bytes(path, raw)
        database = hubdir / 'hub.db'
        if not database.exists():
            store = Store(str(database))
            try:
                for repository in self.request['repositories']:
                    store.repo_add(repository['localName'])
            finally:
                store.db.close()
            database.chmod(0o600)
        return hubdir

    def selections(self, directory, materials, confirmed):
        value = confirmed['service']
        selection = ApplicationServiceSelection(canonical_bytes(value))
        identity = selection.service('identity')['issuer']
        connection = {k: self.runtime[k] for k in ('endpoint', 'serverName', 'rootsPEM')}
        connection['leafCertificateSHA256'] = self.runtime['leafCertificateSHA256']
        attestor = {'schemaVersion': SCHEMA_VERSION, 'hostPolicy': self.host_policy, 'ownerUid': os.getuid(),
            'workspaces': self.workspaces, 'kernelScope': self.kernel, 'keyPath': materials['attestor']['keyPath'],
            'credentials': materials['attestor']['credentials'],
            'application': {'authorityId': self.authority, 'identityRef': self.ref('observer'),
                'issuerRef': self.ref('observer_issuer'), 'transportRef': self.ref('observer_transport'),
                'policyRef': self.ref('policy'), 'workspaceRef': None, 'scope': self.org_scope},
            'receiptTrust': {'issuerRef': identity['issuerRef'], 'publicKey': identity['publicKey'],
                'notBefore': materials['interval']['issuedAt'], 'expiresAt': materials['interval']['expiresAt'],
                'minimumAuthorityRevision': confirmed['sequence']},
            'initialGeneration': 1, 'connection': connection}
        attestor_path = directory / 'attestor-selection.json'
        if not _matches(attestor_path, attestor):
            write_application_attestor_host_selection(attestor_path, attestor)
        service_path = directory / 'service-selection.json'
        if not _matches(service_path, selection.policy):
            write_application_service_selection(service_path, selection.policy)
        services = {'applicationAttestor': {'selection': str(attestor_path), 'sha256': digest(canonical_bytes(attestor))},
                    'applicationServices': {'installationId': self.owner['clientInstallationId'],
                                            'selection': str(service_path), 'sha256': digest(canonical_bytes(selection.policy))}}
        pins = {}
        for name, family, _route in SESSIONS:
            entry = materials['families'][name]
            creds = entry['credentials']
            session_connection = {'schemaVersion': SCHEMA_VERSION, **connection, 'credentialsFile': creds['path'],
                                  **{k: creds[k] for k in ('accountPublicKey', 'userPublicKey', 'replyPrefix')}}
            connection_path = Path(entry['directory']) / 'connection.json'
            _write_or_match(connection_path, session_connection, max_bytes=32768)
            application = {'clientKey': entry['clientKey'], 'connection': str(connection_path)}
            if family == 'identity':
                application['repositories'] = [r['localName'] for r in self.request['repositories']]
            client = {'schemaVersion': SCHEMA_VERSION, 'hostPolicy': self.host_policy, 'workspaces': self.workspaces,
                      'instanceId': self.instance, 'profileId': self.profile, 'hubId': self.hub,
                      'application': application, **services}
            path = directory / ('client-selection-' + name + '.json')
            _write_or_match(path, client, max_bytes=16384)
            pins.setdefault(family, []).append({'selection': str(path), 'sha256': digest(canonical_bytes(client))})
        core = {'schemaVersion': SCHEMA_VERSION, 'home': str(self.home),
                'repositories': {r['root']: r['localName'] for r in self.request['repositories']},
                'identity': pins['identity'], 'messages': pins['messages'], 'work': pins['work']}
        core_path = directory / 'core-hub.json'
        _write_or_match(core_path, core, max_bytes=16384)
        return {'schemaVersion': SCHEMA_VERSION, 'coreHub': {'selection': str(core_path), 'sha256': digest(canonical_bytes(core))},
                'startupSelection': pins['identity'][0]}


def _matches(path, material):
    """True when a retained create-only file already holds exactly this material."""
    if not Path(path).exists():
        return False
    if _read_material(path, max_bytes=1048576, return_bytes=True) != canonical_bytes(material):
        raise ContractError('local_enrollment_selection_conflict')
    return True


def _write_or_match(path, material, *, max_bytes):
    if not _matches(path, material):
        _write_material(path, material, max_bytes=max_bytes)


def _stage_file(directory, name):
    return directory / name


async def run(request_path, request_sha256, *, root=None, now=None):
    """Run or resume the ceremony; return the public coreHub and startup pins."""
    request, owner = admit_request(request_path, request_sha256)
    ceremony = Ceremony(request, owner, root=root)
    try:
        directory = _private_dir(_private_dir(ceremony.directory.parent) / ceremony.directory.name)
        materials_path = _stage_file(directory, 'materials.json')
        if not materials_path.exists():
            staging = directory / 'materials'
            if staging.exists():
                # Keys exist without their recorded proofs; refuse rather than mint a second identity.
                raise ContractError('local_enrollment_materials_incomplete')
            _private_dir(staging)
            materials = ceremony.materials(staging, now or datetime.now(timezone.utc))
            _write_material(materials_path, materials, max_bytes=1048576)
        materials = _read_material(materials_path, max_bytes=1048576)
        ceremony.interval = materials['interval']
        bootstrap_path = _stage_file(directory, 'bootstrap.json')
        if not bootstrap_path.exists():
            try:
                confirmed = await ceremony.bootstrap(materials)
            finally:
                await ceremony.close()
            _write_material(bootstrap_path, confirmed, max_bytes=1048576)
        confirmed = _read_material(bootstrap_path, max_bytes=1048576)
        result_path = _stage_file(directory, 'result.json')
        if not result_path.exists():
            ceremony.hub_files()
            result = ceremony.selections(directory, materials, confirmed)
            _write_material(result_path, result, max_bytes=16384)
        return _read_material(result_path, max_bytes=16384)
    finally:
        ceremony.account.wipe()


def main(arguments):
    """Installed entry: ``--request PATH --request-sha256 DIGEST``.

    Only the public coreHub and startup pins reach stdout. Failures report a
    closed code; private paths, keys and causes never leave the process.
    """
    import json
    import sys
    if (len(arguments) != 4 or arguments[0] != '--request' or arguments[2] != '--request-sha256'
            or not os.path.isabs(arguments[1]) or os.path.normpath(arguments[1]) != arguments[1]
            or not _DIGEST.fullmatch(arguments[3])):
        sys.stderr.write(json.dumps({'schemaVersion': SCHEMA_VERSION, 'kind': 'local-enrollment-diagnostic',
                                     'code': 'local_enrollment_arguments_invalid'}) + '\n')
        return 1
    try:
        result = asyncio.run(run(arguments[1], arguments[3]))
    except ContractError as error:
        code = str(error) if re.fullmatch(r'[a-z_]{1,96}', str(error)) else 'local_enrollment_failed'
        sys.stderr.write(json.dumps({'schemaVersion': SCHEMA_VERSION, 'kind': 'local-enrollment-diagnostic',
                                     'code': code}) + '\n')
        return 1
    except Exception:
        sys.stderr.write(json.dumps({'schemaVersion': SCHEMA_VERSION, 'kind': 'local-enrollment-diagnostic',
                                     'code': 'local_enrollment_failed'}) + '\n')
        return 1
    sys.stdout.buffer.write(canonical_bytes({**result, 'kind': 'local-enrollment-result'}) + b'\n')
    sys.stdout.buffer.flush()
    return 0
