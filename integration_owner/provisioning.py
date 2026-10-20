"""Operator-owned provisioning for exact integration effect aggregates.

This module creates transport and recovery resources.  It does not create an
identity grant, approval, provider credential, or NATS account signing key.  A
separately admitted operator supplies the JetStream administration handle, an
existing backup key, and a credential issuer that retains account-key custody.
"""
from dataclasses import dataclass
from datetime import datetime
import fcntl
import hashlib
import inspect
import os
from pathlib import Path
import re
import stat

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from native_security.nats_credentials import (validate_service,
    validate_service_enrollment, CredentialError)
from state_owner.backup_host import BackupHost, _native_guard
from state_owner.checkpoint_host import CheckpointHost
from state_owner.checkpoints import _publish, _read
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, StreamIdentity, owner_subject
from state_owner.retention import Retention
from identity.application_enrollment import _read_material
from .intent import effect_id


_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_STREAM = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
_ROUTE = re.compile(r'route-([0-9]{16})\.json\Z')
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')


def _fail(code='integration_provisioning_invalid'):
    raise ContractError(code) from None


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _publish_private(path, raw, *, max_bytes):
    """Publish complete create-only bytes, or confirm the prior same result."""
    if type(raw) is not bytes or not 0 < len(raw) <= max_bytes:
        _fail('integration_provisioning_publication_invalid')
    path = Path(path)
    directory = _private_directory(path.parent)
    try:
        try:
            existing = _read(directory, path.name, max_bytes, admit=_native_guard)
        except FileNotFoundError:
            _publish(directory, path.name, raw, admit=_native_guard)
        else:
            if existing != raw:
                _fail('integration_provisioning_publication_uncertain')
        if _read(directory, path.name, max_bytes, admit=_native_guard) != raw:
            _fail('integration_provisioning_publication_uncertain')
        os.fsync(directory)
    except ContractError:
        raise
    except Exception:
        _fail('integration_provisioning_publication_uncertain')
    finally:
        os.close(directory)


def _private_directory(path, *, create=True):
    """Open a private absolute directory without following a path link."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        _fail()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o700, dir_fd=fd)
                os.fsync(fd)
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        meta = os.fstat(fd)
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid()
                or stat.S_IMODE(meta.st_mode) != 0o700):
            _fail()
        BackupHost._ancestor_identities(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


@dataclass(frozen=True, repr=False)
class IntegrationEffectResources:
    """One exact enrolled effect and its open local recovery resources."""
    effect_id: str
    stream: str
    binding: OwnerBinding
    stream_identity: StreamIdentity
    history: OwnerHistory
    checkpoint: CheckpointHost
    backup: BackupHost
    router_credential_path: str
    router_credential_digest: str
    additional_streams: tuple[str, ...]

    def __repr__(self):
        return '<IntegrationEffectResources private>'


@dataclass(frozen=True, repr=False)
class IntegrationRoute:
    generation: int
    streams: tuple[str, ...]
    credential_path: str
    credential_digest: str
    credential: object

    def __repr__(self):
        return '<IntegrationRoute private>'


class IntegrationEffectProvisioner:
    """Create and resume exact effect resources under explicit operator custody."""

    def __init__(self, jetstream, *, hub_id, scope, base_stream, artifact_bucket,
                 reply_prefix, jetstream_domain, account_public_key, retention,
                 max_history_records, max_history_bytes,
                 resource_directory, inventory_directory, credential_directory,
                 backup_key_directory, backup_key_id, backup_destination_id,
                 commit_ref, credential_issuer, _create_directories=True):
        try:
            scope = strict_loads(canonical_bytes(scope))
            roots = tuple(Path(p) for p in (resource_directory, inventory_directory,
                credential_directory, backup_key_directory))
            if (not _ID.fullmatch(hub_id) or type(scope) is not dict
                    or set(scope) != {'organizationId', 'projectId', 'workspaceId'}
                    or scope['projectId'] is None
                    or any(v is not None and not _ID.fullmatch(v)
                           for v in scope.values())
                    or not _STREAM.fullmatch(base_stream)
                    or not _STREAM.fullmatch(artifact_bucket)
                    or not isinstance(retention, Retention)
                    or type(max_history_records) is not int
                    or not 1 <= max_history_records <= 1_000_000
                    or type(max_history_bytes) is not int
                    or not 65_536 <= max_history_bytes <= 1_099_511_627_776
                    or not _ID.fullmatch(backup_key_id)
                    or not _ID.fullmatch(backup_destination_id)
                    or type(commit_ref) is not dict
                    or set(commit_ref) != {'id', 'ownerHubId', 'revision'}
                    or commit_ref['ownerHubId'] != hub_id
                    or not callable(credential_issuer)
                    or type(_create_directories) is not bool
                    or any(not p.is_absolute() or '..' in p.parts for p in roots)
                    or any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
                           for i, a in enumerate(roots) for b in roots[i + 1:])):
                raise ValueError()
            # Validate every broker-policy input before any mutation.
            from native_security.nats_credentials import service_policy
            service_policy(role='integration', hub_id=hub_id,
                entity_id='effect-placeholder', scope=scope, stream=base_stream,
                reply_prefix=reply_prefix, jetstream_domain=jetstream_domain,
                artifact_bucket=artifact_bucket, integration_routing=True)
        except Exception:
            _fail()
        self._js, self._hub, self._scope = jetstream, hub_id, scope
        self._base_stream, self._artifact_bucket = base_stream, artifact_bucket
        self._reply_prefix, self._domain = reply_prefix, jetstream_domain
        self._account = account_public_key
        self._retention, self._resource = retention, roots[0]
        self._max_history_records = max_history_records
        self._max_history_bytes = max_history_bytes
        self._inventory, self._credentials, self._keys = roots[1:]
        self._key_id, self._destination = backup_key_id, backup_destination_id
        self._commit_ref = strict_loads(canonical_bytes(commit_ref))
        self._issuer = credential_issuer
        for root in roots:
            try:
                fd = _private_directory(root, create=_create_directories)
                os.close(fd)
            except Exception:
                _fail('integration_provisioning_inventory_unavailable')

    def __repr__(self):
        return '<IntegrationEffectProvisioner private>'

    @staticmethod
    def stream_name(entity_id):
        if not isinstance(entity_id, str) or not entity_id.startswith('effect-'):
            _fail()
        return 'AMX_INTEGRATION_' + entity_id.removeprefix('effect-').upper()

    def _paths(self, entity_id):
        return {
            'history': self._resource / 'history' / (entity_id + '.sqlite'),
            'checkpoint': self._resource / 'checkpoints' / entity_id / 'checkpoint',
            'backup': self._resource / 'backups' / entity_id,
            'backupInventory': self._resource / 'backup-inventory' / entity_id,
        }

    def _policy_inputs(self, streams):
        return {'role': 'integration', 'hub_id': self._hub,
            'entity_id': 'effect-placeholder', 'scope': self._scope,
            'stream': self._base_stream, 'reply_prefix': self._reply_prefix,
            'jetstream_domain': self._domain, 'artifact_bucket': self._artifact_bucket,
            'integration_routing': True, 'additional_streams': tuple(streams)}

    def _effect_records(self):
        records = {}
        for path in sorted(self._inventory.glob('effect-*.json')):
            raw = _read_material(path, max_bytes=16384, return_bytes=True)
            value = strict_loads(raw)
            required = {'format', 'effectId', 'originalOperationId', 'scope', 'stream',
                'streamIdentity', 'paths'}
            expected_paths = ({k: str(v) for k, v in
                               self._paths(value.get('effectId')).items()}
                              if type(value) is dict and
                              isinstance(value.get('effectId'), str) else None)
            if (type(value) is not dict or set(value) != required
                    or value['format'] != 'amx-integration-effect-enrollment-v1'
                    or path.name != value['effectId'] + '.json'
                    or effect_id(value['scope'], value['originalOperationId']) != value['effectId']
                    or value['scope'] != self._scope
                    or value['stream'] != self.stream_name(value['effectId'])
                    or value['paths'] != expected_paths
                    or type(value['streamIdentity']) is not dict
                    or set(value['streamIdentity']) != {'created', 'minimumSequence'}):
                _fail('integration_provisioning_inventory_invalid')
            StreamIdentity(datetime.fromisoformat(value['streamIdentity']['created']),
                           value['streamIdentity']['minimumSequence'])
            if value['effectId'] in records:
                _fail('integration_provisioning_inventory_invalid')
            records[value['effectId']] = value
        return records

    def _route_records(self):
        routes = []
        for path in sorted(self._inventory.glob('route-*.json')):
            match = _ROUTE.fullmatch(path.name)
            value = strict_loads(_read_material(path, max_bytes=32768, return_bytes=True))
            if (match is None or type(value) is not dict
                    or set(value) != {'format', 'generation', 'streams', 'credential'}
                    or value['format'] != 'amx-integration-router-enrollment-v1'
                    or value['generation'] != int(match[1])
                    or value['generation'] != len(routes) + 1
                    or type(value['streams']) is not list
                    or value['streams'] != sorted(set(value['streams']))
                    or routes and not set(routes[-1]['streams']).issubset(value['streams'])
                    or any(not _STREAM.fullmatch(v) or v == self._base_stream
                           for v in value['streams'])):
                _fail('integration_provisioning_inventory_invalid')
            pin = value['credential']
            if (type(pin) is not dict or set(pin) != {'path', 'sha256', 'userPublicKey'}
                    or pin['path'] != str(self._credentials /
                        ('router-%016d.creds' % value['generation']))
                    or not isinstance(pin['sha256'], str)
                    or not _DIGEST.fullmatch(pin['sha256'])):
                _fail('integration_provisioning_inventory_invalid')
            raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
            if _digest(raw) != pin['sha256']:
                _fail('integration_provisioning_inventory_invalid')
            try:
                credential = validate_service_enrollment(raw,
                    account_public_key=self._account,
                    **self._policy_inputs(value['streams']))
            except CredentialError:
                _fail('integration_provisioning_inventory_invalid')
            if credential.public_key != pin['userPublicKey']:
                _fail('integration_provisioning_inventory_invalid')
            routes.append(value)
        return routes

    async def _stream(self, stream, subject, *, enrollment=None):
        try:
            info = await self._js.stream_info(stream)
        except Exception as exc:
            if exc.__class__.__name__ not in ('NotFoundError', 'KeyNotFoundError'):
                raise ContractError('integration_provisioning_stream_unavailable') from None
            try:
                info = await self._js.add_stream(
                    self._retention.stream_config(stream=stream, subject=subject))
            except Exception:
                raise ContractError('integration_provisioning_stream_uncertain') from None
        self._retention.validate(info, stream=stream, subject=subject)
        if enrollment is None and (info.state.messages != 0 or info.state.last_seq != 0):
            _fail('integration_provisioning_stream_occupied')
        if enrollment is not None:
            identity = StreamIdentity(datetime.fromisoformat(
                enrollment['streamIdentity']['created']),
                enrollment['streamIdentity']['minimumSequence'])
            if info.created != identity.created or info.state.last_seq < identity.minimum_sequence:
                _fail('owner_recovery_required')
        return info

    def _open_resources(self, record, route):
        identity = StreamIdentity(datetime.fromisoformat(
            record['streamIdentity']['created']), record['streamIdentity']['minimumSequence'])
        binding = OwnerBinding(self._hub, 'integrations', record['effectId'], 'effect',
                               canonical_bytes(self._scope))
        paths = record['paths']
        history = None
        try:
            history = OwnerHistory(paths['history'], binding, stream_identity=identity,
                max_records=self._max_history_records, max_bytes=self._max_history_bytes)
            checkpoint = CheckpointHost(paths['checkpoint'], stream=record['stream'],
                commit_ref=self._commit_ref, binding=binding, stream_identity=identity,
                max_records=self._max_history_records, max_bytes=self._max_history_bytes)
            backup = BackupHost(paths['backup'], paths['backupInventory'], self._keys,
                destination_id=self._destination, binding=binding, stream_identity=identity)
            key = backup.load_key(self._key_id)
            del key
            pin = route['credential']
            return IntegrationEffectResources(record['effectId'], record['stream'], binding,
                identity, history, checkpoint, backup, pin['path'], pin['sha256'],
                tuple(route['streams']))
        except Exception:
            if history is not None:
                history.close()
            raise

    def current_route(self):
        """Read the latest complete, currently usable routed credential."""
        records, routes = self._effect_records(), self._route_records()
        if not routes:
            _fail('integration_route_not_enrolled')
        route = routes[-1]
        enrolled = {record['stream'] for record in records.values()}
        if not set(route['streams']).issubset(enrolled):
            _fail('integration_provisioning_inventory_invalid')
        pin = route['credential']
        raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
        try:
            credential = validate_service(raw, account_public_key=self._account,
                **self._policy_inputs(route['streams']))
        except CredentialError:
            _fail('integration_route_credential_unavailable')
        return IntegrationRoute(route['generation'], tuple(route['streams']),
            pin['path'], pin['sha256'], credential)

    def open_effect(self, binding, original_operation_id, *, route):
        """Open one preprovisioned exact owner from an admitted route generation."""
        if (not isinstance(binding, OwnerBinding)
                or not isinstance(route, IntegrationRoute)):
            _fail()
        entity = effect_id(self._scope, original_operation_id)
        if binding != OwnerBinding(self._hub, 'integrations', entity, 'effect',
                                   canonical_bytes(self._scope)):
            _fail('integration_route_not_enrolled')
        record = self._effect_records().get(entity)
        if record is None or record['stream'] not in route.streams:
            _fail('integration_route_not_enrolled')
        return self._open_resources(record, {'streams': list(route.streams),
            'credential': {'path': route.credential_path,
                'sha256': route.credential_digest,
                'userPublicKey': route.credential.public_key}})

    async def provision(self, original_operation_id):
        """Provision or resume one operation without creating product authority."""
        entity = effect_id(self._scope, original_operation_id)
        stream = self.stream_name(entity)
        binding = OwnerBinding(self._hub, 'integrations', entity, 'effect',
                               canonical_bytes(self._scope))
        lock_fd = _private_directory(self._inventory)
        lock = None
        try:
            lock = os.open('.provision.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                           0o600, dir_fd=lock_fd)
            metadata = os.fstat(lock)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1):
                _fail()
            _native_guard(lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail('integration_provisioning_busy')
            records, routes = self._effect_records(), self._route_records()
            record = records.get(entity)
            if record is None and len(records) >= 64:
                _fail('integration_provisioning_capacity')
            info = await self._stream(stream, owner_subject(binding), enrollment=record)
            if record is None:
                identity = StreamIdentity(info.created, 0)
                paths = self._paths(entity)
                for path in (Path(paths['history']).parent, Path(paths['checkpoint']).parent,
                             paths['backup'], paths['backupInventory']):
                    directory = _private_directory(path)
                    os.close(directory)
                candidate = {'format': 'amx-integration-effect-enrollment-v1',
                    'effectId': entity, 'originalOperationId': original_operation_id,
                    'scope': self._scope, 'stream': stream,
                    'streamIdentity': {'created': identity.created.isoformat(),
                                       'minimumSequence': 0},
                    'paths': {k: str(v) for k, v in paths.items()}}
                # Check local recovery custody before publishing the enrollment.
                history = OwnerHistory(paths['history'], binding, stream_identity=identity,
                    max_records=self._max_history_records,
                    max_bytes=self._max_history_bytes)
                try:
                    CheckpointHost(paths['checkpoint'], stream=stream,
                        commit_ref=self._commit_ref, binding=binding,
                        stream_identity=identity,
                        max_records=self._max_history_records,
                        max_bytes=self._max_history_bytes)
                    host = BackupHost(paths['backup'], paths['backupInventory'], self._keys,
                        destination_id=self._destination, binding=binding, stream_identity=identity)
                    key = host.load_key(self._key_id)
                    del key
                finally:
                    history.close()
                _publish_private(self._inventory / (entity + '.json'),
                    canonical_bytes(candidate), max_bytes=16384)
                record = candidate
                records[entity] = record
            streams = sorted(item['stream'] for item in records.values())
            if routes and routes[-1]['streams'] == streams:
                pin = routes[-1]['credential']
                raw = _read_material(pin['path'], max_bytes=65536,
                                     return_bytes=True)
                try:
                    validate_service(raw, account_public_key=self._account,
                                     **self._policy_inputs(streams))
                except CredentialError:
                    pass
                else:
                    return self._open_resources(record, routes[-1])
            inputs = self._policy_inputs(streams)
            generation = len(routes) + 1
            credential_path = self._credentials / ('router-%016d.creds' % generation)
            try:
                raw = _read_material(credential_path, max_bytes=65536,
                                     return_bytes=True)
            except ContractError:
                try:
                    raw = self._issuer(inputs)
                    if inspect.isawaitable(raw):
                        raw = await raw
                    credential = validate_service(raw,
                        account_public_key=self._account, **inputs)
                except Exception:
                    _fail('integration_provisioning_credential_invalid')
                # Credential bytes are create-only and are never put in inventory.
                try:
                    _publish_private(credential_path, raw, max_bytes=65536)
                except ContractError:
                    _fail('integration_provisioning_credential_write_uncertain')
            try:
                credential = validate_service(raw, account_public_key=self._account,
                                              **inputs)
            except Exception:
                _fail('integration_provisioning_credential_invalid')
            pin = {'path': str(credential_path), 'sha256': _digest(raw),
                   'userPublicKey': credential.public_key}
            route = {'format': 'amx-integration-router-enrollment-v1',
                     'generation': generation, 'streams': streams, 'credential': pin}
            _publish_private(self._inventory / ('route-%016d.json' % generation),
                canonical_bytes(route), max_bytes=32768)
            return self._open_resources(record, route)
        finally:
            if lock is not None:
                os.close(lock)
            os.close(lock_fd)


class IntegrationEffectInventory(IntegrationEffectProvisioner):
    """Read only access to resources prepared by the explicit operator owner."""

    def __init__(self, **configuration):
        super().__init__(None, credential_issuer=lambda _inputs: None,
                         _create_directories=False, **configuration)

    def __repr__(self):
        return '<IntegrationEffectInventory private>'

    async def provision(self, original_operation_id):
        raise ContractError('integration_provisioning_authority_required')

