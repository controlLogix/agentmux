"""Private code results retained with the original Hub completion transaction.

This helper performs no admission, Git or network work. Callers must check
current authority before disclosing a completed result.
"""
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate

_PREFIX = 'legacy-code-completion:'
_LIMIT = 1048576
_FIELDS = {'formatVersion', 'profile', 'principal', 'operationId', 'requestDigest',
           'binding', 'state', 'result', 'codeSource', 'messageSource'}


def _fail():
    raise ContractError('code_completion_invalid')


def _text(value, limit=256):
    return type(value) is str and 1 <= len(value) <= limit


def _public(value, depth=0):
    if depth > 32:
        _fail()
    if type(value) is dict:
        for key, child in value.items():
            if (type(key) is not str or key.lower().replace('_', '').replace('-', '') in
                    {'token', 'password', 'secret', 'seed', 'privatekey', 'credential', 'credentials', 'authorization'}):
                _fail()
            _public(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _public(child, depth + 1)
    elif value is not None and type(value) not in (str, int, bool):
        _fail()


def _copy(value):
    try:
        _public(value)
        raw = canonical_bytes(value)
        if len(raw) > _LIMIT:
            raise ContractError('code_completion_capacity')
        return strict_loads(raw)
    except (TypeError, ValueError, RecursionError):
        _fail()


def _reference(value):
    if (type(value) is not dict or set(value) != {'id', 'ownerHubId', 'revision'}
            or not _text(value['id']) or not _text(value['ownerHubId'])
            or type(value['revision']) is not int or not 1 <= value['revision'] <= 9007199254740991):
        _fail()


class CodeCompletionStore:
    """Synchronous DB-thread operations over the caller's pinned Hub Store."""
    def __init__(self, hub, federation, *, profile):
        from hub.server import Hub
        from hub.store import Store
        from hub.fed.runtime import Federation
        if (not isinstance(hub, Hub) or type(hub.store) is not Store
                or type(federation) is not Federation or federation.hub is not hub
                or type(profile) is not dict or set(profile) != {'hubId', 'profileId', 'authorityId'}
                or any(not _text(v) for v in profile.values())):
            _fail()
        self._hub, self._store, self._federation = hub, hub.store, federation
        self._connection = self._store.db
        self._profile = _copy(profile)

    def __repr__(self):
        return '<CodeCompletionStore private>'

    def _custody(self):
        if (self._hub.store is not self._store or self._federation.hub is not self._hub
                or self._store.db is not self._connection):
            raise ContractError('code_completion_binding')
        if hasattr(self._store, '_selected_custody'):
            self._store.check_existing()

    def _identity(self, operation_id, request_digest, principal):
        if (operation_id is not None and (type(operation_id) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', operation_id) is None)
                or type(request_digest) is not str or re.fullmatch(r'[0-9a-f]{64}', request_digest) is None
                or type(principal) is not dict or set(principal) != {'authenticatedCaller', 'caller'}
                or any(not _text(v, 512) for v in principal.values())):
            _fail()
        return _copy(dict(profile=self._profile, principal=principal,
                          operationId=operation_id, requestDigest=request_digest))

    @staticmethod
    def _suffix(identity):
        key = {k: identity[k] for k in ('profile', 'operationId')}
        if identity['operationId'] is None:
            key['principal'] = identity['principal']
            key['requestDigest'] = identity['requestDigest']
        return hashlib.sha256(canonical_bytes(key)).hexdigest()

    def _binding(self, value, identity, field='codeCommands'):
        if (type(value) is not dict or set(value) != {'hubId', 'profileId', 'authorityId', 'callerRef', 'scope', field}
                or any(value[k] != identity['profile'][k] for k in identity['profile'])):
            _fail()
        _reference(value['callerRef'])
        scope = value['scope']
        if (type(scope) is not dict or set(scope) != {'organizationId', 'projectId', 'workspaceId'}
                or not _text(scope['organizationId']) or not _text(scope['projectId'])
                or scope['workspaceId'] is not None and not _text(scope['workspaceId'])):
            _fail()
        validate('application-code-commands' if field == 'codeCommands' else 'application-message-commands', value[field])
        route = value[field]
        refs = (value['callerRef'], route['resourceRef'], route['transportRef'], route['replyIssuerRef'],
                route['serviceIdentityRef'], *route['grantRefs'].values())
        for reference in refs:
            _reference(reference)
            if reference['ownerHubId'] != value['hubId']:
                _fail()
        subject = '.'.join(('amx', 'v1', 'h', value['hubId'], 'o', scope['organizationId'],
            'p', scope['projectId'], 'w', scope['workspaceId'] or '_', 'capability', 'storage-owner', 'command'))
        if (route['authenticatedCaller'] != identity['principal']['authenticatedCaller']
                or route['subject'] != subject):
            _fail()
        return _copy(value)

    def _source(self, source, identity, binding, *, message=False):
        if (type(source) is not dict or set(source) != {'binding', 'contractId', 'operationId',
                'payloadDigest', 'resourceRef', 'result'}
                or source['contractId'] not in (('federation-message-send',) if message else
                    ('federation-code-publish', 'federation-code-fetched'))
                or not _text(source['operationId'])
                or type(source['payloadDigest']) is not str
                or re.fullmatch(r'sha256:[0-9a-f]{64}', source['payloadDigest']) is None
                or type(source['result']) is not dict or set(source['result']) != {'id'}
                or not _text(source['result']['id'])):
            _fail()
        field = 'messageCommands' if message else 'codeCommands'
        selected = self._binding(source['binding'], identity, field)
        if (not message and canonical_bytes(selected) != canonical_bytes(binding)
                or message and canonical_bytes(selected['scope']) != canonical_bytes(binding['scope'])):
            _fail()
        _reference(source['resourceRef'])
        route_ref = selected[field]['resourceRef']
        if (any(source['resourceRef'][k] != route_ref[k] for k in ('id', 'ownerHubId'))
                or source['resourceRef']['revision'] < route_ref['revision']
                or source['contractId'] not in selected[field]['grantRefs']):
            _fail()
        return _copy(source)

    def _validate(self, record, identity):
        if (type(record) is not dict or set(record) != _FIELDS
                or type(record['formatVersion']) is not int or record['formatVersion'] != 1
                or record['state'] not in ('pending', 'completed')
                or any(canonical_bytes(record[k]) != canonical_bytes(v) for k, v in identity.items())):
            _fail()
        self._binding(record['binding'], identity)
        if record['state'] == 'pending':
            if any(record[k] is not None for k in ('result', 'codeSource', 'messageSource')):
                _fail()
        else:
            if type(record['result']) is not dict:
                _fail()
            self._source(record['codeSource'], identity, record['binding'])
            if record['messageSource'] is not None:
                if record['codeSource']['contractId'] != 'federation-code-publish':
                    _fail()
                self._source(record['messageSource'], identity, record['binding'], message=True)
        return _copy(record)

    def _read(self, identity):
        self._custody()
        suffix = self._suffix(identity)
        keys = tuple(_PREFIX + state + ':' + suffix for state in ('pending', 'completed'))
        rows = self._store.q('SELECT k,v FROM fed_state WHERE k IN (?,?)', keys)
        if not rows:
            return None
        if len(rows) != 1 or type(rows[0]['v']) is not str or len(rows[0]['v'].encode()) > _LIMIT:
            _fail()
        try:
            record = strict_loads(rows[0]['v'])
            record = self._validate(record, identity)
            if (canonical_bytes(record).decode() != rows[0]['v']
                    or rows[0]['k'] != _PREFIX + record['state'] + ':' + suffix):
                _fail()
            return record
        except (TypeError, ValueError, KeyError, RecursionError):
            _fail()

    def lookup(self, *, operation_id, request_digest, principal):
        return self._read(self._identity(operation_id, request_digest, principal))

    def reserve(self, *, operation_id, request_digest, principal, binding):
        self._custody()
        identity = self._identity(operation_id, request_digest, principal)
        binding = self._binding(binding, identity)
        with self._store.tx():
            existing = self._read(identity)
            if existing is not None:
                if canonical_bytes(existing['binding']) != canonical_bytes(binding):
                    _fail()
                return existing
            # Pending keys occupy a separate indexed range. Completed receipts
            # neither consume this active budget nor get scanned or evicted.
            low, high = _PREFIX + 'pending:', _PREFIX + 'pending;'
            if len(self._store.q('SELECT k FROM fed_state WHERE k>=? AND k<? LIMIT 32', (low, high))) >= 32:
                raise ContractError('code_completion_capacity')
            record = self._validate(dict(formatVersion=1, **identity, binding=binding,
                state='pending', result=None, codeSource=None, messageSource=None), identity)
            self._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                (low + self._suffix(identity), canonical_bytes(record).decode()))
            return record

    def complete(self, *, operation_id, request_digest, principal, binding, result, code_source, message_source=None):
        self._custody()
        if not self._store.db.in_transaction:
            raise ContractError('code_completion_transaction_required')
        identity = self._identity(operation_id, request_digest, principal)
        record = self._validate(dict(formatVersion=1, **identity, binding=binding,
            state='completed', result=result, codeSource=code_source, messageSource=message_source), identity)
        existing = self._read(identity)
        if existing is None or canonical_bytes(existing['binding']) != canonical_bytes(record['binding']):
            _fail()
        if existing['state'] == 'completed':
            if canonical_bytes(existing) != canonical_bytes(record):
                _fail()
            return existing
        suffix = self._suffix(identity)
        self._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
            (_PREFIX + 'completed:' + suffix, canonical_bytes(record).decode()))
        self._store.db.execute('DELETE FROM fed_state WHERE k=?', (_PREFIX + 'pending:' + suffix,))
        return record

    def delivered(self, record):
        self._custody()
        if type(record) is not dict or not {'operationId', 'requestDigest', 'principal'} <= set(record):
            _fail()
        identity = self._identity(record['operationId'], record['requestDigest'], record['principal'])
        record = self._validate(record, identity)
        if record['state'] != 'completed':
            _fail()
        with self._store.tx():
            existing = self._read(identity)
            if existing is None or canonical_bytes(record) != canonical_bytes(existing):
                _fail()
            if record['operationId'] is None:
                self._store.db.execute('DELETE FROM fed_state WHERE k=?',
                    (_PREFIX + 'completed:' + self._suffix(identity),))
