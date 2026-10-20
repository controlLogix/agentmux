"""Preserve a legacy repository catalog as reconciliation-only configuration.

The selected SQLite snapshot remains under host custody. Repository paths are
stored as data and are never opened here. The existing configuration owner must
authorize and commit the returned bytes; this module grants no authority and
does not transfer the legacy writer.
"""
import asyncio
import base64
import hashlib
import sqlite3
import time

from nacl.secret import SecretBox
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from .artifacts import OwnerArtifacts
from .configuration import ConfigurationOwner
from .conversation_migration import ConversationKey
from .ledger import OwnerBinding
from .task_migration import TaskMigrationSnapshot, _source, require_unmodified_import_source


TABLES = {
    'repos': (('repo',), ('repo', 'title', 'created')),
    'repo_aliases': (('alias',), ('alias', 'repo')),
    'repo_paths': (('repo', 'path'), ('repo', 'path', 'kind')),
    'groups': (('grp', 'repo'), ('grp', 'repo')),
    'agents': (('session',), ('session', 'repo', 'role', 'agent', 'cli', 'role_snapshot',
        'transport', 'handle', 'pane_pid', 'token_sha', 'state', 'state_note', 'last_seen',
        'last_output', 'last_bell', 'created', 'term_name', 'generation')),
    'legacy_names': (('legacy',), ('legacy', 'session')),
    'teams': (('repo', 'team'), ('repo', 'team', 'lead_role', 'created')),
    'team_members': (('repo', 'team', 'session'), ('repo', 'team', 'session')),
}
_AGENT_BASE_COLUMNS = TABLES['agents'][1][:-2]
_ENCRYPTED_FAMILIES = frozenset(('agents', 'legacy_names', 'teams', 'team_members'))
_NULLABLE_COLUMNS = {
    ('repos', 'title'), ('agents', 'handle'), ('agents', 'pane_pid'),
    ('agents', 'token_sha'), ('agents', 'state_note'), ('agents', 'last_seen'),
    ('agents', 'last_output'), ('agents', 'last_bell'), ('agents', 'term_name'),
}
_INTEGER_COLUMNS = {('agents', 'pane_pid'), ('agents', 'generation')}
MAX_ROWS = 4096
MAX_SOURCE_INSTRUCTIONS = 200_000
MAX_SOURCE_SECONDS = 1.0
MAX_CONFIGURATION_BYTES = 16_384
MAX_CATALOG_BYTES = 67_108_864 - SecretBox.NONCE_SIZE - SecretBox.MACBYTES
MEDIA_TYPE = 'application/vnd.agentmux.repository-catalog+json+secretbox'


def _value_schema(table, name):
    value = ({'type': 'integer',
              'minimum': 1 if (table, name) == ('agents', 'generation')
                         else -9007199254740991,
              'maximum': 9007199254740991}
        if (table, name) in _INTEGER_COLUMNS
        else {'type': 'string', 'maxLength': 8192})
    nullable = (table, name) in _NULLABLE_COLUMNS
    return {'oneOf': [value, {'type': 'null'}]} if nullable else value


def _row_schema(table, columns):
    return {'type': 'object', 'additionalProperties': False,
        'properties': {name: _value_schema(table, name) for name in columns},
        'required': list(_AGENT_BASE_COLUMNS if table == 'agents' else columns)}


def _primary_schema(keys):
    variants = []
    for name in keys:
        variants.append({'type': 'object', 'additionalProperties': False,
            'properties': {'column': {'const': name}, 'type': {'const': 'text'},
                'value': _value_schema('primary', name)},
            'required': ['column', 'type', 'value']})
    return {'type': 'array', 'prefixItems': variants, 'items': False,
        'minItems': len(keys), 'maxItems': len(keys)}


def _incarnation_schema():
    value = {'type': 'object', 'additionalProperties': False,
        'properties': {
            'incarnationId': {'type': 'string', 'pattern': '^incarnation_[0-9a-f]{64}$'},
            'canonicalSession': _value_schema('agents', 'session'),
            'registrationGeneration': _value_schema('agents', 'generation')},
        'required': ['incarnationId', 'canonicalSession', 'registrationGeneration']}
    return {'oneOf': [value, {'type': 'null'}]}


def _family_schema(table, keys, columns):
    properties = {
        'memberId': {'type': 'string', 'pattern': '^member_[0-9a-f]{64}$'},
        'primaryKey': _primary_schema(keys), 'row': _row_schema(table, columns)}
    required = ['memberId', 'primaryKey', 'row']
    if table in ('agents', 'legacy_names', 'team_members'):
        properties['incarnation'] = _incarnation_schema()
        required.append('incarnation')
    if table == 'team_members':
        properties['teamMemberOf'] = {'oneOf': [
            {'type': 'string', 'pattern': '^member_[0-9a-f]{64}$'}, {'type': 'null'}]}
        required.append('teamMemberOf')
    return {'type': 'object', 'additionalProperties': False,
        'properties': {'count': {'type': 'integer', 'minimum': 0, 'maximum': MAX_ROWS},
            'rows': {'type': 'array', 'maxItems': MAX_ROWS, 'items': {
                'type': 'object', 'additionalProperties': False,
                'properties': properties, 'required': required}}},
        'required': ['count', 'rows']}


def _empty_family_schema():
    return {'type': 'object', 'additionalProperties': False,
        'properties': {'count': {'const': 0},
            'rows': {'type': 'array', 'maxItems': 0}},
        'required': ['count', 'rows']}


_INLINE_FAMILIES = {name: (_empty_family_schema()
    if name in _ENCRYPTED_FAMILIES else _family_schema(name, *definition))
    for name, definition in TABLES.items()}


_INLINE_SCHEMA = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'type': 'object', 'additionalProperties': False,
    'properties': {
        'format': {'const': 'amx-legacy-repository-catalog-v1'},
        'catalogId': {'type': 'string', 'pattern': '^catalog_[0-9a-f]{64}$'},
        'status': {'const': 'reconciliation_required'},
        'captureComplete': {'const': True},
        'writerAuthorityTransferred': {'const': False},
        'identityEnrollmentActivated': {'const': False},
        'credentialsMinted': {'const': False},
        'membershipActivated': {'const': False},
        'sourceRef': {'type': 'object', 'additionalProperties': False,
            'properties': {'id': _value_schema('source', 'id'),
                'ownerHubId': _value_schema('source', 'ownerHubId'),
                'revision': {'type': 'integer', 'minimum': 1, 'maximum': 9007199254740991}},
            'required': ['id', 'ownerHubId', 'revision']},
        'captureDigest': {'type': 'string', 'pattern': '^sha256:[0-9a-f]{64}$'},
        'schemaVersion': {'type': 'integer', 'minimum': 1, 'maximum': 6},
        'applicationVersion': _value_schema('source', 'applicationVersion'),
        'families': {'type': 'object', 'additionalProperties': False,
            'properties': _INLINE_FAMILIES,
            'required': list(TABLES)},
    },
    'required': ['format', 'catalogId', 'status', 'captureComplete',
        'writerAuthorityTransferred', 'identityEnrollmentActivated', 'credentialsMinted',
        'membershipActivated', 'sourceRef', 'captureDigest', 'schemaVersion',
        'applicationVersion', 'families'],
}


def _reference_schema():
    return {'type': 'object', 'additionalProperties': False,
        'properties': {'id': _value_schema('source', 'id'),
            'ownerHubId': _value_schema('source', 'ownerHubId'),
            'revision': {'type': 'integer', 'minimum': 0, 'maximum': 9007199254740991}},
        'required': ['id', 'ownerHubId', 'revision']}


_ARTIFACT_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'properties': {
        'format': {'const': 'amx-legacy-repository-catalog-artifact-v1'},
        'catalogId': {'type': 'string', 'pattern': '^catalog_[0-9a-f]{64}$'},
        'status': {'const': 'reconciliation_required'},
        'captureComplete': {'const': True},
        'writerAuthorityTransferred': {'const': False},
        'identityEnrollmentActivated': {'const': False},
        'credentialsMinted': {'const': False},
        'membershipActivated': {'const': False},
        'sourceRef': _INLINE_SCHEMA['properties']['sourceRef'],
        'captureDigest': _INLINE_SCHEMA['properties']['captureDigest'],
        'schemaVersion': _INLINE_SCHEMA['properties']['schemaVersion'],
        'applicationVersion': _value_schema('source', 'applicationVersion'),
        'catalogDigest': {'type': 'string', 'pattern': '^sha256:[0-9a-f]{64}$'},
        'families': {'type': 'object', 'additionalProperties': False,
            'properties': {name: {'type': 'integer', 'minimum': 0, 'maximum': MAX_ROWS}
                for name in TABLES}, 'required': list(TABLES)},
        'keyRef': _reference_schema(),
        'artifactRef': {'type': 'object', 'additionalProperties': False,
            'properties': {'artifactId': _value_schema('source', 'artifactId'),
                'ownerHubId': _value_schema('source', 'ownerHubId'),
                'storeRef': _reference_schema(), 'version': _value_schema('source', 'version'),
                'digest': {'type': 'string', 'pattern': '^sha256:[0-9a-f]{64}$'},
                'bytes': {'type': 'integer', 'minimum': 1, 'maximum': 67108864},
                'mediaType': {'const': MEDIA_TYPE}},
            'required': ['artifactId', 'ownerHubId', 'storeRef', 'version', 'digest', 'bytes', 'mediaType']},
    },
    'required': ['format', 'catalogId', 'status', 'captureComplete',
        'writerAuthorityTransferred', 'identityEnrollmentActivated', 'credentialsMinted',
        'membershipActivated', 'sourceRef', 'captureDigest', 'schemaVersion',
        'applicationVersion', 'catalogDigest', 'families', 'keyRef', 'artifactRef'],
}


REPOSITORY_CATALOG_SCHEMA = canonical_bytes({'$schema':
    'https://json-schema.org/draft/2020-12/schema', 'oneOf': [_INLINE_SCHEMA, _ARTIFACT_SCHEMA]})


def _scope(binding):
    if (type(binding) is not OwnerBinding
            or (binding.owner_domain, binding.entity_kind) != ('configuration', 'configuration')):
        raise ContractError('repository_catalog_configuration')
    scope = strict_loads(binding.scope)
    if scope['projectId'] is not None or scope['workspaceId'] is not None:
        raise ContractError('repository_catalog_organization_required')
    return scope


def _namespace(source_ref, *, target_hub_id, scope):
    source = _source(source_ref)
    return {'format': 'amx-repository-catalog-identity-v1', 'targetOwnerHubId': target_hub_id,
        'ownerDomain': 'configuration', 'scope': scope,
        'source': {name: source[name] for name in ('id', 'ownerHubId')}}


def repository_catalog_identity(source_ref, *, target_hub_id, scope):
    digest = payload_digest(_namespace(source_ref, target_hub_id=target_hub_id,
        scope=scope)).split(':')[1]
    return {'catalogId': 'catalog_'+digest, 'operationId': 'import_'+digest}


def _primary(keys, row):
    if any(type(row[name]) is not str for name in keys):
        raise ContractError('repository_catalog_source_invalid')
    return [{'column': name, 'type': 'text', 'value': row[name]} for name in keys]


def _member(source_ref, binding, table, primary):
    namespace = _namespace(source_ref, target_hub_id=binding.hub_id,
        scope=strict_loads(binding.scope))
    return 'member_'+payload_digest(namespace | {'table': table,
        'primaryKey': primary}).split(':')[1]


def _columns(table, schema_version):
    if table != 'agents':
        return TABLES[table][1]
    return (_AGENT_BASE_COLUMNS
        + (('term_name',) if schema_version >= 2 else ())
        + (('generation',) if schema_version >= 6 else ()))


def _valid_value(table, name, value):
    if value is None:
        return (table, name) in _NULLABLE_COLUMNS
    expected = int if (table, name) in _INTEGER_COLUMNS else str
    return type(value) is expected


def _incarnation(source_ref, binding, session, generation):
    if generation is None:
        return None
    namespace = _namespace(source_ref, target_hub_id=binding.hub_id,
        scope=strict_loads(binding.scope))
    digest = payload_digest(namespace | {'canonicalSession': session,
        'registrationGeneration': generation}).split(':')[1]
    return {'incarnationId': 'incarnation_'+digest, 'canonicalSession': session,
        'registrationGeneration': generation}


class RepositoryCatalogSource:
    """Read repository metadata from one admitted immutable snapshot."""
    def __init__(self, snapshot, *, source_owner_organization_id):
        if type(snapshot) is not TaskMigrationSnapshot:
            raise ContractError('repository_catalog_configuration')
        OwnerBinding('source', 'configuration', 'source', 'configuration', canonical_bytes({
            'organizationId': source_owner_organization_id,
            'projectId': None, 'workspaceId': None}))
        self._snapshot = snapshot
        self._organization = source_owner_organization_id

    def __repr__(self):
        return '<RepositoryCatalogSource private read-only>'

    def _catalog_bytes(self, *, binding):
        scope = _scope(binding)
        if scope['organizationId'] != self._organization:
            raise ContractError('repository_catalog_source_scope_mismatch')
        snapshot = self._snapshot
        db = None
        progress = False
        prior_limit = None
        try:
            snapshot._check_file()
            db = snapshot._db
            prior_limit = db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_CATALOG_BYTES)
            steps = 0
            deadline = time.monotonic() + MAX_SOURCE_SECONDS
            def stop():
                nonlocal steps
                steps += 1
                return (steps > MAX_SOURCE_INSTRUCTIONS
                    or (steps % 100 == 0 and time.monotonic() >= deadline))
            db.set_progress_handler(stop, 1)
            progress = True
            identity = repository_catalog_identity(snapshot._source,
                target_hub_id=binding.hub_id, scope=scope)
            if identity['catalogId'] != binding.entity_id:
                raise ContractError('repository_catalog_binding_mismatch')
            families = {}
            incarnations = {}
            teams = {}
            total = 0
            encoded_rows = 0
            for table, (keys, _) in TABLES.items():
                columns = _columns(table, snapshot._schema_version)
                info = list(db.execute('PRAGMA table_xinfo('+table+')'))
                primary = tuple(row['name'] for row in sorted(info, key=lambda row: row['pk']) if row['pk'])
                if (tuple(row['name'] for row in info) != columns or primary != keys
                        or any(row['hidden'] for row in info)):
                    raise ContractError('repository_catalog_source_invalid')
                count = db.execute('SELECT count(*) FROM (SELECT 1 FROM '+table+' LIMIT ?)',
                    (MAX_ROWS+1,)).fetchone()[0]
                total += count
                if total > MAX_ROWS:
                    raise ContractError('repository_catalog_artifact_required')
                rows = []
                order = ','.join(name+' COLLATE BINARY' for name in keys)
                for source_row in db.execute('SELECT * FROM '+table+' ORDER BY '+order):
                    row = dict(source_row)
                    if any(not _valid_value(table, name, row[name]) for name in columns):
                        raise ContractError('repository_catalog_source_invalid')
                    require_unmodified_import_source(row)
                    key = _primary(keys, row)
                    member = {'memberId': _member(snapshot._source, binding, table, key),
                        'primaryKey': key, 'row': row}
                    if table == 'agents':
                        incarnation = _incarnation(snapshot._source, binding, row['session'],
                            row.get('generation'))
                        member['incarnation'] = incarnation
                        incarnations[row['session']] = incarnation
                    elif table == 'legacy_names':
                        member['incarnation'] = incarnations.get(row['session'])
                    elif table == 'teams':
                        teams[(row['repo'], row['team'])] = member['memberId']
                    elif table == 'team_members':
                        member['teamMemberOf'] = teams.get((row['repo'], row['team']))
                        member['incarnation'] = incarnations.get(row['session'])
                    encoded_rows += len(canonical_bytes(member))
                    if encoded_rows > MAX_CATALOG_BYTES:
                        raise ContractError('repository_catalog_artifact_required')
                    rows.append(member)
                if len(rows) != count:
                    raise ContractError('repository_catalog_source_unavailable')
                families[table] = {'count': count, 'rows': rows}
            document = {'format': 'amx-legacy-repository-catalog-v1',
                'catalogId': identity['catalogId'], 'status': 'reconciliation_required',
                'captureComplete': True, 'writerAuthorityTransferred': False,
                'identityEnrollmentActivated': False, 'credentialsMinted': False,
                'membershipActivated': False,
                'sourceRef': snapshot._source, 'captureDigest': snapshot._digest,
                'schemaVersion': snapshot._schema_version,
                'applicationVersion': snapshot._application_version, 'families': families}
            require_unmodified_import_source(document)
            raw = canonical_bytes(document)
            if len(raw) > MAX_CATALOG_BYTES:
                raise ContractError('repository_catalog_artifact_required')
            snapshot._check_file()
            return raw
        except ContractError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError, KeyError, OverflowError):
            raise ContractError('repository_catalog_source_unavailable') from None
        finally:
            if progress:
                db.set_progress_handler(None, 0)
            if db is not None and prior_limit is not None:
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, prior_limit)

    def catalog_bytes(self, *, binding):
        """Return bounded bytes for explicit encrypted artifact staging."""
        return self._catalog_bytes(binding=binding)

    def configuration_bytes(self, *, binding):
        raw = self._catalog_bytes(binding=binding)
        document = strict_loads(raw)
        if (any(document['families'][name]['count'] for name in _ENCRYPTED_FAMILIES)
                or len(raw) > MAX_CONFIGURATION_BYTES):
            raise ContractError('repository_catalog_artifact_required')
        return raw

    def _artifact_configuration_bytes(self, *, binding, artifact_ref, key_ref, catalog):
        document = strict_loads(catalog)
        artifact, key = _artifact_selection(binding, artifact_ref, key_ref)
        descriptor = {'format': 'amx-legacy-repository-catalog-artifact-v1',
            'catalogId': document['catalogId'], 'status': document['status'],
            'captureComplete': True, 'writerAuthorityTransferred': False,
            'identityEnrollmentActivated': False, 'credentialsMinted': False,
            'membershipActivated': False,
            'sourceRef': document['sourceRef'], 'captureDigest': document['captureDigest'],
            'schemaVersion': document['schemaVersion'],
            'applicationVersion': document['applicationVersion'],
            'catalogDigest': 'sha256:'+hashlib.sha256(catalog).hexdigest(),
            'families': {name: family['count']
                for name, family in document['families'].items()},
            'keyRef': key, 'artifactRef': artifact}
        encoded = canonical_bytes(descriptor)
        if len(encoded) > MAX_CONFIGURATION_BYTES:
            raise ContractError('repository_catalog_artifact_required')
        return encoded


def _artifact_selection(binding, artifact_ref, key_ref):
    artifact = strict_loads(canonical_bytes(artifact_ref))
    key = _source(key_ref)
    if (artifact.get('mediaType') != MEDIA_TYPE
            or artifact.get('ownerHubId') != binding.hub_id
            or key['ownerHubId'] != binding.hub_id):
        raise ContractError('repository_catalog_artifact_selection_invalid')
    return artifact, key


async def prepare_repository_catalog_artifact(source, *, binding, artifacts, key, artifact_ref):
    """Verify staged encrypted catalog bytes and return the small owner document."""
    if (type(source) is not RepositoryCatalogSource or type(artifacts) is not OwnerArtifacts
            or type(key) is not ConversationKey or artifacts._owner != binding.hub_id):
        raise ContractError('repository_catalog_configuration')
    try:
        artifact, key_ref = _artifact_selection(binding, artifact_ref,
            strict_loads(key._reference))
        artifacts._check_ref(artifact)
        expected = source._catalog_bytes(binding=binding)
        encrypted = await artifacts.retrieve(artifact)
        catalog = SecretBox(key.read()).decrypt(encrypted)
        if catalog != expected:
            raise ValueError()
        source._snapshot._check_file()
        return source._artifact_configuration_bytes(binding=binding,
            artifact_ref=artifact, key_ref=key_ref,
            catalog=catalog)
    except ContractError:
        raise
    except TimeoutError:
        raise
    except Exception:
        raise ContractError('repository_catalog_artifact_unavailable') from None


class RepositoryCatalogImporter:
    """Verify one encrypted catalog and commit its unchanged signed request."""
    def __init__(self, owner, *, source, artifacts, key):
        if (not isinstance(owner, ConfigurationOwner)
                or type(source) is not RepositoryCatalogSource
                or type(artifacts) is not OwnerArtifacts
                or type(key) is not ConversationKey
                or artifacts._owner != owner._ledger._binding.hub_id):
            raise ContractError('repository_catalog_configuration')
        scope = _scope(owner._ledger._binding)
        key_ref = _source(strict_loads(key._reference))
        if source._organization != scope['organizationId']:
            raise ContractError('repository_catalog_source_scope_mismatch')
        if key_ref['ownerHubId'] != owner._ledger._binding.hub_id:
            raise ContractError('repository_catalog_artifact_selection_invalid')
        self._owner, self._source = owner, source
        self._artifacts, self._key = artifacts, key

    def __repr__(self):
        return '<RepositoryCatalogImporter private reconciliation-required>'

    async def handle(self, raw):
        if type(raw) is not bytes or len(raw) > 65_536:
            raise ContractError('repository_catalog_artifact_required')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if (canonical_bytes(envelope) != raw or envelope['kind'] != 'command'
                or envelope['contractId'] != 'configuration-set'
                or envelope['destinationServiceId'] != 'configuration-owner'):
            raise ContractError('repository_catalog_contract_unavailable')
        payload, operation = envelope['payload'], envelope['operation']
        validate('configuration-set', payload)
        binding = self._owner._ledger._binding
        self._owner._target(payload)
        if payload['schemaRef'] != self._owner._schema:
            raise ContractError('configuration_binding_mismatch')
        identity = repository_catalog_identity(self._source._snapshot._source,
            target_hub_id=binding.hub_id, scope=strict_loads(binding.scope))
        if (payload['configurationRef'] != {'id': binding.entity_id,
                'ownerHubId': binding.hub_id, 'revision': 0}
                or operation['operationId'] != identity['operationId']
                or operation['expectedVersion'] != 0
                or any(operation[name] is not None
                    for name in ('taskId', 'runId', 'attemptId', 'delegationRef'))):
            raise ContractError('repository_catalog_binding_mismatch')
        try:
            encoded = payload['configurationBytes']
            descriptor_raw = base64.b64decode(encoded, validate=True)
            if base64.b64encode(descriptor_raw).decode() != encoded:
                raise ValueError()
            descriptor = strict_loads(descriptor_raw)
            if (descriptor['format'] != 'amx-legacy-repository-catalog-artifact-v1'
                    or descriptor['catalogId'] != identity['catalogId']
                    or payload['secretReferences'] != [descriptor['keyRef']]):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise ContractError('repository_catalog_binding_mismatch') from None
        try:
            async with asyncio.timeout(5):
                await self._owner._authorize(raw, envelope)
                expected = await prepare_repository_catalog_artifact(self._source,
                    binding=binding, artifacts=self._artifacts, key=self._key,
                    artifact_ref=descriptor['artifactRef'])
                if descriptor_raw != expected:
                    raise ContractError('repository_catalog_binding_mismatch')
                await self._owner._authorize(raw, envelope)
        except TimeoutError:
            raise ContractError('repository_catalog_deadline_exceeded') from None
        return await self._owner.handle(raw)
