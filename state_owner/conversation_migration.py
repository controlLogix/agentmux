"""Import an explicitly staged encrypted conversation archive without delivery.

The host owns the admitted database, private brief/key descriptors, artifact
selection, current identity reader and scoped ledger connection. This module
never uploads, deletes, enrolls a caller, resolves a recipient or transfers a
writer. Keep the original source and staging selection for restart/recovery.
"""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from nacl.secret import SecretBox
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import LedgerAuthorityReader, evaluate_snapshot
from .artifacts import OwnerArtifacts
from .checkpoints import _directory
from .ledger import MAX_RECORD_BYTES, OwnerBinding, OwnerLedger, find_outcome, validate_record
from .task_migration import TaskMigrationSnapshot, _source, require_unmodified_import_source


MAX_BUNDLE_BYTES = 67_108_864 - SecretBox.NONCE_SIZE - SecretBox.MACBYTES
MAX_ROWS = 100_000
MAX_SOURCE_SECONDS = 5.0
MAX_SOURCE_INSTRUCTIONS = 5_000_000
MAX_ROW_BYTES = 1_048_576
BRIEF_CHUNK_BYTES = 48 * 1024
MAX_COORDINATION_BYTES = 4_194_304
MAX_COORDINATION_TOTAL_BYTES = 4_194_304
MAX_SOURCE_SCHEMA_VERSION = 6
MEDIA_TYPE = 'application/vnd.agentmux.conversation-jsonl-v1+secretbox'
_EVENTS = "entity IN ('message','delivery','conversation') OR (entity='agent' AND event='cli_receipt')"
TABLES = {
    'message_kinds': (('kind',), ('kind', 'ack_timeout_s', 'max_attempts')),
    'messages': (('id',), ('id', 'sender', 'target', 'kind', 'ref', 'work_id', 'body', 'body_ref',
        'body_sha', 'idem_key', 'created', 'expires', 'meta')),
    'deliveries': (('message_id', 'recipient'), ('message_id', 'recipient', 'state', 'attempts',
        'next_at', 'last_error', 'evidence', 'updated')),
    'events': (('seq',), ('seq', 'at', 'entity', 'entity_id', 'event', 'actor', 'detail')),
    # Preserve local bridge obligations as inert conversation evidence. Import
    # never turns these rows into effects or invokes the legacy bridge.
    'nats_outbox': (('seq',), ('seq', 'subject', 'payload', 'created', 'sent')),
}


def _digest(raw):
    return 'sha256:'+hashlib.sha256(raw).hexdigest()


def _scope(binding):
    if (type(binding) is not OwnerBinding
            or (binding.owner_domain, binding.entity_kind) != ('conversation-archive', 'conversation-archive')):
        raise ContractError('conversation_import_configuration')
    scope = strict_loads(binding.scope)
    if scope['projectId'] is not None or scope['workspaceId'] is not None:
        raise ContractError('conversation_import_organization_required')
    return scope


def _namespace(source_ref, binding):
    source = _source(source_ref)
    return {'format': 'amx-conversation-source-identity-v1', 'ownerHubId': binding.hub_id,
        'ownerDomain': binding.owner_domain, 'scope': _scope(binding),
        'source': {k: source[k] for k in ('id', 'ownerHubId')}}


def conversation_import_identity(source_ref, *, target_hub_id, scope):
    binding = OwnerBinding(target_hub_id, 'conversation-archive', 'archive-target',
        'conversation-archive', canonical_bytes(scope))
    digest = payload_digest(_namespace(source_ref, binding)).split(':')[1]
    return {'archiveId': 'archive_'+digest, 'operationId': 'import_'+digest}


def _member(source_ref, binding, table, primary):
    return 'member_'+payload_digest(_namespace(source_ref, binding) |
        {'table': table, 'primaryKey': primary}).split(':')[1]


class _SelectedFile:
    """Own one private descriptor, not a caller-supplied path lookup."""
    def __init__(self, path, *, max_bytes):
        self._fd = self._directory = None
        self._closed = False
        self._path = Path(os.path.abspath(path))
        self._limit = max_bytes
        try:
            if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BUNDLE_BYTES:
                raise ValueError()
            self._directory, self._name = _directory(self._path)
            self._fd = os.open(self._name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self._directory)
            self._identity = os.fstat(self._fd)
            if (not stat.S_ISREG(self._identity.st_mode) or self._identity.st_uid != os.getuid()
                    or stat.S_IMODE(self._identity.st_mode) != 0o600 or self._identity.st_nlink != 1
                    or not 0 <= self._identity.st_size <= max_bytes):
                raise ValueError()
            self.check()
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ContractError('conversation_source_file_unavailable') from None
            raise

    def __repr__(self):
        return '<ConversationSourceFile private>'

    def check(self):
        try:
            if self._closed:
                raise ValueError()
            current = os.stat(self._name, dir_fd=self._directory, follow_symlinks=False)
            opened = os.fstat(self._fd)
            parent = os.stat(self._path.parent, follow_symlinks=False)
            pinned = os.fstat(self._directory)
            original = self._identity
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_mode', 'st_nlink')
            if (any(getattr(current, k) != getattr(original, k) or getattr(opened, k) != getattr(original, k)
                    for k in fields) or current.st_nlink != 1
                    or (parent.st_dev, parent.st_ino) != (pinned.st_dev, pinned.st_ino)
                    or pinned.st_uid != os.getuid() or pinned.st_mode & 0o077):
                raise ValueError()
        except (OSError, TypeError, ValueError):
            raise ContractError('conversation_source_file_unavailable') from None

    def read(self):
        self.check()
        try:
            os.lseek(self._fd, 0, os.SEEK_SET)
            raw = bytearray()
            while len(raw) <= self._limit:
                chunk = os.read(self._fd, min(65536, self._limit+1-len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            self.check()
            if len(raw) != self._identity.st_size or len(raw) > self._limit:
                raise ValueError()
            return bytes(raw)
        except ContractError:
            raise
        except (OSError, ValueError):
            raise ContractError('conversation_source_file_unavailable') from None

    def close(self):
        self._closed = True
        for name in ('_fd', '_directory'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


class ConversationBrief(_SelectedFile):
    """The host explicitly selects a private captured copy of a source brief."""
    def __init__(self, path, *, max_bytes=MAX_BUNDLE_BYTES):
        super().__init__(path, max_bytes=max_bytes)


class CoordinationHistory(_SelectedFile):
    """One explicitly selected legacy journal or sender outbox.

    The logical source name is archive provenance. It is never used as a path,
    current actor, recipient selection or authority input.
    """
    def __init__(self, path, *, kind, name, max_bytes=MAX_COORDINATION_BYTES):
        if (kind not in ('journal', 'queue') or type(name) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', name)):
            raise ContractError('conversation_coordination_selection_invalid')
        self.kind, self.name = kind, name
        super().__init__(path, max_bytes=max_bytes)


class ConversationKey(_SelectedFile):
    """Keep the selected key private and detect withdrawn/replaced file custody."""
    def __init__(self, path, *, key_ref):
        self._reference = canonical_bytes(_source(key_ref))
        super().__init__(path, max_bytes=SecretBox.KEY_SIZE)
        if self._identity.st_size != SecretBox.KEY_SIZE:
            self.close()
            raise ContractError('conversation_source_key_unavailable')


@dataclass(frozen=True, repr=False)
class ConversationBundle:
    """Host-private canonical JSONL; never send its plaintext as an owner reply."""
    raw: bytes
    manifest: bytes

    @property
    def digest(self):
        return _digest(self.raw)

    def __repr__(self):
        return '<ConversationBundle private>'


class ConversationMigrationSource:
    def __init__(self, snapshot, *, source_owner_organization_id, briefs, coordination=()):
        if (type(snapshot) is not TaskMigrationSnapshot or type(briefs) is not dict
                or len(briefs) > 4096 or any(type(k) is not str or not k or type(v) is not ConversationBrief
                    for k, v in briefs.items()) or type(coordination) is not tuple
                or len(coordination) > 129
                or any(type(source) is not CoordinationHistory for source in coordination)):
            raise ContractError('conversation_import_configuration')
        coordination_keys = [(source.kind, source.name) for source in coordination]
        if len(set(coordination_keys)) != len(coordination_keys):
            raise ContractError('conversation_coordination_selection_invalid')
        OwnerBinding('source', 'conversation-archive', 'source', 'conversation-archive',
            canonical_bytes({'organizationId': source_owner_organization_id, 'projectId': None, 'workspaceId': None}))
        self._snapshot, self._organization, self._briefs = snapshot, source_owner_organization_id, dict(briefs)
        self._coordination = tuple(coordination)

    def __repr__(self):
        return '<ConversationMigrationSource private>'

    def check(self):
        try:
            self._snapshot._check_file()
            for brief in self._briefs.values():
                brief.check()
            for source in self._coordination:
                source.check()
        except ContractError:
            raise
        except OSError:
            raise ContractError('conversation_source_unavailable') from None

    def bundle(self, *, binding, key_ref, max_bytes=MAX_BUNDLE_BYTES):
        scope = _scope(binding)
        key_ref = _source(key_ref)
        if (scope['organizationId'] != self._organization or key_ref['ownerHubId'] != binding.hub_id
                or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BUNDLE_BYTES):
            raise ContractError('conversation_import_source_scope_mismatch')
        identity = conversation_import_identity(self._snapshot._source, target_hub_id=binding.hub_id, scope=scope)
        if identity['archiveId'] != binding.entity_id:
            raise ContractError('conversation_import_binding_mismatch')
        db = prior_limit = None
        progress = False
        try:
            self.check()
            snapshot = self._snapshot
            db = snapshot._db
            prior_limit = db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_ROW_BYTES)
            steps = 0
            deadline = time.monotonic()+MAX_SOURCE_SECONDS
            def stop():
                nonlocal steps
                steps += 1
                return steps > MAX_SOURCE_INSTRUCTIONS or (steps % 1000 == 0 and time.monotonic() >= deadline)
            # TaskMigrationSnapshot owns this serialized private connection and
            # has no original progress callback. Clear this temporary one below.
            db.set_progress_handler(stop, 1)
            progress = True
            counts = {}
            for table, (keys, columns) in TABLES.items():
                info = list(db.execute('PRAGMA table_xinfo('+table+')'))
                if (tuple(r['name'] for r in info) != columns or any(r['hidden'] for r in info)
                        or tuple(r['name'] for r in sorted(info, key=lambda r:r['pk']) if r['pk']) != keys):
                    raise ContractError('conversation_source_schema_invalid')
                where = ' WHERE '+_EVENTS if table == 'events' else ''
                count = db.execute('SELECT count(*) FROM (SELECT 1 FROM '+table+where+' LIMIT ?)',
                    (MAX_ROWS+1,)).fetchone()[0]
                counts[table] = {'present': True, 'count': count}
            if sum(f['count'] for f in counts.values()) > MAX_ROWS:
                raise ContractError('conversation_source_limit')
            coordination = []
            coordination_rows = []
            database_rows = sum(f['count'] for f in counts.values())
            coordination_bytes = coordination_count = 0
            for source in sorted(self._coordination, key=lambda item: (item.kind, item.name)):
                raw = source.read()
                coordination_bytes += len(raw)
                if coordination_bytes > min(MAX_COORDINATION_TOTAL_BYTES, max_bytes):
                    raise ContractError('conversation_source_limit')
                if raw and not raw.endswith(b'\n'):
                    raise ContractError('conversation_coordination_source_invalid')
                records = []
                for line in raw.splitlines():
                    try:
                        value = strict_loads(line)
                    except Exception:
                        raise ContractError('conversation_coordination_source_invalid') from None
                    self._validate_coordination_record(source.kind, source.name, value)
                    require_unmodified_import_source(value)
                    records.append(value)
                coordination_count += len(records)
                if database_rows + coordination_count > MAX_ROWS:
                    raise ContractError('conversation_source_limit')
                descriptor = {'kind': source.kind, 'name': source.name,
                    'digest': _digest(raw), 'records': len(records)}
                coordination.append(descriptor)
                coordination_rows.append((source, records))
            manifest = {'format': 'amx-conversation-jsonl-v1', 'archiveId': binding.entity_id,
                'binding': {'ownerHubId': binding.hub_id, 'ownerDomain': binding.owner_domain, 'scope': scope},
                'keyRef': key_ref, 'sourceOwnerOrganizationId': self._organization,
                'sourceRef': snapshot._source, 'captureDigest': snapshot._digest,
                'schemaVersion': snapshot._schema_version, 'applicationVersion': snapshot._application_version,
                'families': counts, 'briefCount': len(self._briefs)}
            if coordination:
                manifest.update(format='amx-conversation-jsonl-v2', coordination=coordination)
            require_unmodified_import_source(manifest)
            frames = bytearray()
            def add(frame):
                if time.monotonic() >= deadline:
                    raise ContractError('conversation_source_limit')
                raw = canonical_bytes(frame)+b'\n'
                if len(frames)+len(raw) > max_bytes:
                    raise ContractError('conversation_source_limit')
                frames.extend(raw)
            add({'kind': 'manifest', 'manifest': manifest})
            wanted = {}
            for table, (keys, _) in TABLES.items():
                where = ' WHERE '+_EVENTS if table == 'events' else ''
                order = ','.join(k+' COLLATE BINARY' for k in keys)
                seen = 0
                for row in db.execute('SELECT * FROM '+table+where+' ORDER BY '+order):
                    value = dict(row)
                    if any(type(v) not in (str, int, type(None)) for v in value.values()):
                        raise ContractError('conversation_source_schema_invalid')
                    require_unmodified_import_source(value)
                    primary = [{'column': k, 'type': 'integer' if type(value[k]) is int else 'text',
                        'value': value[k]} for k in keys]
                    if any(type(value[k]) is not (int if k == 'seq' else str) for k in keys):
                        raise ContractError('conversation_source_schema_invalid')
                    add({'kind': 'row', 'table': table, 'primaryKey': primary,
                        'memberId': _member(snapshot._source, binding, table, primary), 'row': value})
                    seen += 1
                    if table == 'messages' and value['body_ref'] is not None:
                        wanted.setdefault(value['body_ref'], set()).add('sha256:'+value['body_sha'])
                if seen != counts[table]['count']:
                    raise ContractError('conversation_source_unavailable')
            for source, records in coordination_rows:
                for ordinal, value in enumerate(records):
                    primary = [{'column': 'sourceKind', 'type': 'text', 'value': source.kind},
                        {'column': 'sourceName', 'type': 'text', 'value': source.name},
                        {'column': 'ordinal', 'type': 'integer', 'value': ordinal}]
                    add({'kind': 'coordination-record', 'sourceKind': source.kind,
                        'sourceName': source.name, 'ordinal': ordinal,
                        'memberId': _member(snapshot._source, binding, 'coordination', primary),
                        'record': value})
            if set(wanted) != set(self._briefs):
                raise ContractError('conversation_brief_selection_mismatch')
            for source_path in sorted(wanted):
                raw = self._briefs[source_path].read()
                digest = _digest(raw)
                if wanted[source_path] != {digest}:
                    raise ContractError('conversation_brief_digest_mismatch')
                try:
                    require_unmodified_import_source(raw.decode('utf-8', errors='strict'))
                except UnicodeError:
                    raise ContractError('conversation_brief_content_unavailable') from None
                primary = [{'column': 'body_ref', 'type': 'text', 'value': source_path}]
                brief_id = _member(snapshot._source, binding, 'briefs', primary)
                add({'kind': 'brief', 'briefId': brief_id, 'sourcePath': source_path,
                    'bytes': len(raw), 'digest': digest})
                for offset in range(0, len(raw), BRIEF_CHUNK_BYTES):
                    add({'kind': 'brief-bytes', 'briefId': brief_id, 'offset': offset,
                        'base64': base64.b64encode(raw[offset:offset+BRIEF_CHUNK_BYTES]).decode('ascii')})
            complete = {'kind': 'complete', 'families': counts, 'briefCount': len(wanted)}
            if coordination:
                complete['coordination'] = coordination
            add(complete)
            self.check()
            return ConversationBundle(bytes(frames), canonical_bytes(manifest))
        except ContractError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError, KeyError, OverflowError):
            raise ContractError('conversation_source_unavailable') from None
        finally:
            if progress:
                db.set_progress_handler(None, 0)
            if db is not None and prior_limit is not None:
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, prior_limit)

    @staticmethod
    def _validate_coordination_record(kind, name, value):
        try:
            if type(value) is not dict:
                raise ValueError()
            at = value.get('at')
            parsed = datetime.fromisoformat(at.replace('Z', '+00:00'))
            if parsed.tzinfo is None or parsed.utcoffset() is None or len(at) > 64:
                raise ValueError()
            token = re.compile(r'[A-Za-z0-9_.-]{1,64}\Z')
            if kind == 'journal':
                if (not {'at', 'kind', 'subject', 'body'} <= set(value)
                        or set(value) - {'at', 'kind', 'agent', 'subject', 'body'}):
                    raise ValueError()
                if (not token.fullmatch(value['kind']) or value.get('agent') is not None
                        and not token.fullmatch(value['agent'])
                        or type(value['subject']) is not str or len(value['subject']) > 256
                        or type(value['body']) is not str or len(value['body']) > 8192):
                    raise ValueError()
            elif kind == 'queue':
                if set(value) != {'at', 'sender', 'recipient', 'kind', 'body', 'ref'}:
                    raise ValueError()
                if (not token.fullmatch(value['sender']) or value['sender'] != name
                        or not token.fullmatch(value['recipient']) or not token.fullmatch(value['kind'])
                        or type(value['body']) is not str or len(value['body']) > 65536
                        or value['ref'] is not None
                        and (type(value['ref']) is not str or len(value['ref']) > 256)):
                    raise ValueError()
            else:
                raise ValueError()
        except (AttributeError, TypeError, ValueError, OverflowError):
            raise ContractError('conversation_coordination_source_invalid') from None


def prepare_conversation_import(source, *, binding, key, artifact_ref):
    """Prepare an explicit reference; never stage or upload an artifact."""
    if type(source) is not ConversationMigrationSource or type(key) is not ConversationKey:
        raise ContractError('conversation_import_configuration')
    key.read()
    bundle = source.bundle(binding=binding, key_ref=strict_loads(key._reference))
    manifest = strict_loads(bundle.manifest)
    return {'archiveId': binding.entity_id, 'sourceRef': manifest['sourceRef'],
        'captureDigest': manifest['captureDigest'], 'bundleDigest': bundle.digest,
        'artifactRef': strict_loads(canonical_bytes(artifact_ref))}


def validate_conversation_archive(raw, binding, *, authority_id):
    """Only one complete immutable reference is valid archive history."""
    try:
        scope = _scope(binding)
        record = validate_record(raw, binding)
        state, op = record['state'], record['operation']
        if (set(state) != {'archiveId', 'status', 'captureComplete', 'writerTransferRequired',
                'manifest', 'payload', 'importAuthorityRef'}
                or state['archiveId'] != binding.entity_id or state['status'] != 'reconciliation_required'
                or state['captureComplete'] is not True or state['writerTransferRequired'] is not True):
            raise ValueError()
        payload, manifest = state['payload'], state['manifest']
        validate('conversation-ledger-import', payload)
        require_unmodified_import_source(manifest)
        identity = conversation_import_identity(payload['sourceRef'], target_hub_id=binding.hub_id, scope=scope)
        authority = _source(state['importAuthorityRef'])
        base_manifest = {'format', 'archiveId', 'binding', 'keyRef', 'sourceOwnerOrganizationId',
            'sourceRef', 'captureDigest', 'schemaVersion', 'applicationVersion', 'families', 'briefCount'}
        coordination = manifest.get('coordination')
        if (set(manifest) not in (base_manifest, base_manifest | {'coordination'})
                or manifest['format'] not in ('amx-conversation-jsonl-v1', 'amx-conversation-jsonl-v2')
                or (manifest['format'] == 'amx-conversation-jsonl-v1') != (coordination is None)
                or manifest['archiveId'] != binding.entity_id
                or manifest['binding'] != {'ownerHubId': binding.hub_id, 'ownerDomain': binding.owner_domain, 'scope': scope}
                or manifest['sourceOwnerOrganizationId'] != scope['organizationId']
                or _source(manifest['keyRef'])['ownerHubId'] != binding.hub_id
                or manifest['sourceRef'] != payload['sourceRef'] or manifest['captureDigest'] != payload['captureDigest']
                or type(manifest['schemaVersion']) is not int
                or not 1 <= manifest['schemaVersion'] <= MAX_SOURCE_SCHEMA_VERSION
                or type(manifest['applicationVersion']) is not str
                or not 1 <= len(manifest['applicationVersion'].encode()) <= 256
                or type(manifest['briefCount']) is not int or not 0 <= manifest['briefCount'] <= 4096
                or set(manifest['families']) != set(TABLES)
                or identity['archiveId'] != binding.entity_id or payload['archiveId'] != binding.entity_id
                or op['operationId'] != identity['operationId'] or op['payloadDigest'] != payload_digest(payload)
                or record['entityVersion'] != 1 or record['previousRevision'] != 0 or op['expectedVersion'] != 0
                or any(op[k] is not None for k in ('taskId', 'runId', 'attemptId', 'delegationRef'))
                or op['caller']['kind'] not in ('human', 'service')
                or op['effectiveActorRef'] != op['caller']['authenticatedIdentityRef']
                or record['outcome'] != 'committed' or record['effects']
                or record['artifacts'] != [payload['artifactRef']] or record['repository'] is not None
                or authority['id'] != authority_id or authority['ownerHubId'] != binding.hub_id
                or record['authorizationDecision'] != {'operationId': op['operationId'], 'decision': 'allowed',
                    'reason': 'authorized', 'actorRef': op['effectiveActorRef'], 'contractId': 'conversation-ledger-import'}):
            raise ValueError()
        total = 0
        for family in manifest['families'].values():
            if (set(family) != {'present', 'count'} or family['present'] is not True
                    or type(family['count']) is not int or not 0 <= family['count'] <= MAX_ROWS):
                raise ValueError()
            total += family['count']
        if total > MAX_ROWS:
            raise ValueError()
        if coordination is not None:
            if (type(coordination) is not list or not 1 <= len(coordination) <= 129):
                raise ValueError()
            keys = set()
            for source in coordination:
                if (type(source) is not dict or set(source) != {'kind', 'name', 'digest', 'records'}
                        or source['kind'] not in ('journal', 'queue')
                        or type(source['name']) is not str
                        or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', source['name'])
                        or type(source['digest']) is not str
                        or not re.fullmatch(r'sha256:[0-9a-f]{64}', source['digest'])
                        or type(source['records']) is not int
                        or not 0 <= source['records'] <= MAX_ROWS
                        or (source['kind'], source['name']) in keys):
                    raise ValueError()
                keys.add((source['kind'], source['name']))
                total += source['records']
            if total > MAX_ROWS:
                raise ValueError()
        return record
    except Exception:
        raise ContractError('conversation_import_record_invalid') from None


class ConversationImporter:
    """Read an explicitly selected staged artifact and commit its reference once."""
    def __init__(self, authority, ledger, *, source, artifacts, staged_artifact_ref, key):
        if (not isinstance(authority, LedgerAuthorityReader) or not isinstance(ledger, OwnerLedger)
                or type(source) is not ConversationMigrationSource or type(artifacts) is not OwnerArtifacts
                or type(key) is not ConversationKey or not ledger.completion_budget_required):
            raise ContractError('conversation_import_configuration')
        scope = _scope(ledger._binding)
        if (authority._hub != ledger._binding.hub_id or authority._organization != scope['organizationId']
                or source._organization != scope['organizationId']
                or strict_loads(key._reference)['ownerHubId'] != ledger._binding.hub_id
                or artifacts._owner != ledger._binding.hub_id):
            raise ContractError('conversation_import_source_scope_mismatch')
        reference = strict_loads(canonical_bytes(staged_artifact_ref))
        artifacts._check_ref(reference)
        if reference['mediaType'] != MEDIA_TYPE:
            raise ContractError('conversation_import_artifact_selection_invalid')
        self._authority, self._ledger, self._source = authority, ledger, source
        self._artifacts, self._key, self._artifact = artifacts, key, canonical_bytes(reference)
        self._connection = getattr(ledger._js, '_nc', None)
        self._prefix = getattr(ledger._js, '_prefix', None)
        self._closed = False
        self._check_transport()

    def __repr__(self):
        return '<ConversationImporter private reconciliation-required>'

    def close(self):
        """Fence new/returning work; the caller still joins its original requests."""
        self._closed = True

    def _check_transport(self):
        artifacts, ledger = self._artifacts, self._ledger
        if (self._closed or self._connection is None or not getattr(self._connection, 'is_connected', False)
                or getattr(ledger._js, '_nc', None) is not self._connection
                or getattr(artifacts._js, '_nc', None) is not self._connection
                or type(self._prefix) is not str or not self._prefix
                or getattr(ledger._js, '_prefix', None) != self._prefix
                or getattr(artifacts._js, '_prefix', None) != self._prefix
                or getattr(artifacts._store, '_js', None) is not artifacts._js
                or getattr(artifacts._store, '_name', None) != artifacts._bucket):
            raise ContractError('conversation_import_transport_unavailable')
        artifacts._check_ref(strict_loads(self._artifact))

    def _check_sources(self):
        self._check_transport()
        self._source.check()
        self._key.read()

    async def _authorize(self, raw, envelope):
        self._check_transport()
        snapshot = await self._authority.current()
        self._check_transport()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw, audience={
            'hubId': self._ledger._binding.hub_id, 'serviceId': 'conversation-ledger-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.valid_until is None or not now < decision.valid_until
                or decision.operation != canonical_bytes(envelope['operation'])
                or canonical_bytes(envelope['operation']['scope']) != self._ledger._binding.scope):
            raise ContractError('conversation_import_access_refused')
        return decision

    async def handle(self, raw):
        if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
            raise ContractError('conversation_import_request_limit')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if (envelope['kind'] != 'command' or envelope['contractId'] != 'conversation-ledger-import'
                or canonical_bytes(envelope) != raw):
            raise ContractError('conversation_import_contract_unavailable')
        validate('conversation-ledger-import', envelope['payload'])
        try:
            remaining = (datetime.fromisoformat(envelope['operation']['deadline'])-datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                raise ContractError('conversation_import_access_refused')
            async with asyncio.timeout(min(30.0, remaining)):
                return await self._handle(raw, envelope)
        except TimeoutError:
            raise ContractError('conversation_import_unavailable') from None

    async def _handle(self, raw, envelope):
        await self._authorize(raw, envelope)
        payload, op = envelope['payload'], envelope['operation']
        snapshot, binding = self._source._snapshot, self._ledger._binding
        identity = conversation_import_identity(snapshot._source, target_hub_id=binding.hub_id,
            scope=strict_loads(binding.scope))
        if (payload['archiveId'] != binding.entity_id or identity['archiveId'] != binding.entity_id
                or payload['sourceRef'] != snapshot._source or payload['captureDigest'] != snapshot._digest
                or canonical_bytes(payload['artifactRef']) != self._artifact
                or op['operationId'] != identity['operationId'] or op['expectedVersion'] != 0
                or any(op[k] is not None for k in ('taskId', 'runId', 'attemptId', 'delegationRef'))):
            raise ContractError('conversation_import_binding_mismatch')
        current = await self._ledger.current()
        if current.sequence not in (0, 1) or len(current.records) != current.sequence:
            raise ContractError('conversation_import_record_invalid')
        if current.latest is not None:
            validate_conversation_archive(current.latest.record, binding, authority_id=self._authority._entity)
        replay = find_outcome(current, op['operationId'], op['payloadDigest'])
        await self._authorize(raw, envelope)
        self._check_sources()
        bundle = self._source.bundle(binding=binding, key_ref=strict_loads(self._key._reference),
            max_bytes=min(MAX_BUNDLE_BYTES, self._artifacts._max_bytes-SecretBox.NONCE_SIZE-SecretBox.MACBYTES))
        if payload['bundleDigest'] != bundle.digest:
            raise ContractError('conversation_import_bundle_mismatch')
        encrypted = await self._artifacts.retrieve(strict_loads(self._artifact))
        await self._authorize(raw, envelope)
        self._check_sources()
        try:
            plain = SecretBox(self._key.read()).decrypt(encrypted)
            if plain != bundle.raw or _digest(plain) != payload['bundleDigest']:
                raise ValueError()
        except Exception:
            raise ContractError('conversation_import_bundle_unavailable') from None
        manifest = strict_loads(bundle.manifest)
        decision = await self._authorize(raw, envelope)
        self._check_sources()
        if replay is not None:
            return await self._finish(replay, manifest, raw, envelope)
        if current.sequence:
            raise ContractError('owner_revision_conflict')
        record = {'schemaVersion': '1.0.0', 'recordId': 'conversation'+identity['operationId'],
            'entityId': binding.entity_id, 'entityKind': 'conversation-archive', 'ownerHubId': binding.hub_id,
            'ownerDomain': binding.owner_domain, 'entityVersion': 1, 'previousRevision': 0, 'operation': op,
            'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), 'outcome': 'committed',
            'state': {'archiveId': binding.entity_id, 'status': 'reconciliation_required', 'captureComplete': True,
                'writerTransferRequired': True, 'manifest': manifest, 'payload': payload,
                'importAuthorityRef': strict_loads(decision.authority_ref)},
            'effects': [], 'artifacts': [payload['artifactRef']], 'repository': None,
            'authorizationDecision': {'operationId': op['operationId'], 'decision': 'allowed',
                'reason': 'authorized', 'actorRef': op['effectiveActorRef'], 'contractId': 'conversation-ledger-import'}}
        encoded = canonical_bytes(record)
        if len(encoded) > MAX_RECORD_BYTES:
            raise ContractError('conversation_import_record_limit')
        validate_conversation_archive(encoded, binding, authority_id=self._authority._entity)
        stored = await self._ledger.append(record, expected_sequence=0, completion_records=0,
            valid_until=decision.valid_until)
        return await self._finish(stored, manifest, raw, envelope)

    async def _finish(self, stored, manifest, raw, envelope):
        # Artifact reads and conditional append can suspend or return an
        # internal replay. Neither can reuse the earlier prefix validation.
        current = await self._ledger.current()
        if (current.sequence != 1 or len(current.records) != 1
                or current.latest.sequence != stored.sequence or current.latest.record != stored.record):
            raise ContractError('conversation_import_record_invalid')
        record = validate_conversation_archive(current.latest.record, self._ledger._binding,
            authority_id=self._authority._entity)
        if record['state']['manifest'] != manifest or record['state']['payload'] != envelope['payload']:
            raise ContractError('conversation_import_record_invalid')
        # Current identity authority follows the last archive-ledger await.
        # This is a verified prefix/read, not a transaction across both owners.
        await self._authorize(raw, envelope)
        self._check_sources()
        return stored
