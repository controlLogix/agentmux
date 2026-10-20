"""Private, explicit-ID work RPC receipts over the pinned Hub Store.

Records preserve results; they do not authorize replay. The caller must obtain
fresh signed owner outcomes before disclosing any retained result.
"""
from datetime import datetime
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate

_PREFIX = 'legacy-work-completion:'
_ACTIVE = 'legacy-work-client:'
_LIMIT = 1048576
_VERBS = {'work_add': {'create', 'offer'}, 'fed_work_add': {'offer'}, 'claim': {'claim'},
    'heartbeat': {'heartbeat'}, 'release': {'release'},
    'work_cancel': {'cancel'}, 'claim_path': {'claim-path'}}
_FIELDS = {'formatVersion', 'profile', 'principal', 'operationId', 'requestDigest',
    'verb', 'arguments', 'intentDigest', 'bindings', 'state', 'result', 'workSources'}
_SOURCE = {'formatVersion', 'binding', 'intentDigest', 'contractId', 'operationId',
    'payload', 'originalDeadline', 'conflictReceipt', 'confirmedReply'}


def _fail():
    raise ContractError('work_completion_invalid')


def _text(value, limit=256):
    return type(value) is str and 1 <= len(value) <= limit


def _copy(value):
    try:
        raw = canonical_bytes(value)
        if len(raw) > _LIMIT:
            raise ContractError('work_completion_capacity')
        return strict_loads(raw)
    except (ValueError, TypeError, RecursionError):
        _fail()


def _reference(value):
    if (type(value) is not dict or set(value) != {'id', 'ownerHubId', 'revision'}
            or not _text(value['id']) or not _text(value['ownerHubId'])
            or type(value['revision']) is not int or not 1 <= value['revision'] <= 9007199254740991):
        _fail()


class WorkCompletionStore:
    """Synchronous operations, called through the original joined DB worker."""

    def __init__(self, hub, *, profile):
        from hub.server import Hub
        from hub.store import Store
        if (type(hub) is not Hub or type(hub.store) is not Store
                or type(profile) is not dict or set(profile) != {'hubId', 'profileId', 'authorityId'}
                or any(not _text(v) for v in profile.values())):
            _fail()
        self._hub, self._store = hub, hub.store
        self._connection = self._store.db
        self._db, self._worker = hub.db, getattr(hub, 'dbx', None)
        self._profile = _copy(profile)

    def __repr__(self):
        return '<WorkCompletionStore private>'

    def _custody(self):
        if (self._hub.store is not self._store or self._store.db is not self._connection
                or self._hub.db != self._db or getattr(self._hub, 'dbx', None) is not self._worker):
            raise ContractError('work_completion_binding')
        if hasattr(self._store, '_selected_custody'):
            self._store.check_existing()

    def _identity(self, operation_id, request_digest, principal, verb, arguments):
        if (type(operation_id) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', operation_id) is None
                or type(request_digest) is not str or re.fullmatch(r'[0-9a-f]{64}', request_digest) is None
                or type(principal) is not dict or set(principal) != {'authenticatedCaller', 'caller'}
                or any(not _text(v, 512) for v in principal.values())
                or type(verb) is not str or verb not in _VERBS or type(arguments) is not dict):
            _fail()
        identity = _copy(dict(profile=self._profile, principal=principal, operationId=operation_id,
            requestDigest=request_digest, verb=verb, arguments=arguments))
        return {**identity, 'intentDigest': payload_digest(identity)}

    @staticmethod
    def _suffix(identity):
        return hashlib.sha256(canonical_bytes({k: identity[k] for k in ('profile', 'operationId')})).hexdigest()

    def _binding(self, binding, identity):
        if (type(binding) is not dict or set(binding) !=
                {'hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'workCommands'}
                or any(binding[k] != identity['profile'][k] for k in identity['profile'])):
            _fail()
        _reference(binding['callerRef'])
        scope = binding['scope']
        if (type(scope) is not dict or set(scope) != {'organizationId', 'projectId', 'workspaceId'}
                or not _text(scope['organizationId']) or not _text(scope['projectId'])
                or scope['workspaceId'] is not None and not _text(scope['workspaceId'])):
            _fail()
        route = binding['workCommands']
        validate('application-work-commands', route)
        for ref in (binding['callerRef'], route['resourceRef'], route['transportRef'],
                route['replyIssuerRef'], route['serviceIdentityRef'], *route['grantRefs'].values()):
            _reference(ref)
            if ref['ownerHubId'] != binding['hubId']:
                _fail()
        subject = '.'.join(('amx', 'v1', 'h', binding['hubId'], 'o', scope['organizationId'],
            'p', scope['projectId'], 'w', scope['workspaceId'] or '_', 'capability', 'storage-owner', 'command'))
        if (route['authenticatedCaller'] != identity['principal']['authenticatedCaller']
                or route['subject'] != subject):
            _fail()
        return _copy(binding)

    def _bindings(self, bindings, identity):
        if type(bindings) not in (list, tuple) or not 1 <= len(bindings) <= 64:
            _fail()
        values = [self._binding(value, identity) for value in bindings]
        if len({canonical_bytes(value) for value in values}) != len(values):
            _fail()
        return sorted(values, key=canonical_bytes)

    @staticmethod
    def _source_key(source):
        return _ACTIVE + hashlib.sha256(canonical_bytes({k: source[k]
            for k in ('binding', 'intentDigest', 'contractId')})).hexdigest()

    def _source(self, source, record):
        if (type(source) is not dict or set(source) != _SOURCE
                or type(source['formatVersion']) is not int or source['formatVersion'] != 1
                or source['contractId'] not in {'federation-work-' + name for name in _VERBS[record['verb']]}
                or not _text(source['operationId'], 128) or source['conflictReceipt'] is not None):
            _fail()
        binding = self._binding(source['binding'], record)
        if binding not in record['bindings'] or source['contractId'] not in binding['workCommands']['grantRefs']:
            _fail()
        expected = (payload_digest({'intentDigest': record['intentDigest'],
            'repository': binding['workCommands']['repository']}) if record['verb'] == 'heartbeat'
            else record['intentDigest'])
        if source['intentDigest'] != expected:
            _fail()
        if (record['verb'] == 'work_add' and source['contractId'] == 'federation-work-offer'
                and not record['arguments'].get('federate')):
            _fail()
        validate(source['contractId'], source['payload'])
        if source['payload']['attribution'] != record['principal']['authenticatedCaller']:
            _fail()
        for ref in (source['payload']['resourceRef'], source['confirmedReply'].get('resourceRef')
                if type(source['confirmedReply']) is dict else None):
            _reference(ref)
            selected = binding['workCommands']['resourceRef']
            if any(ref[k] != selected[k] for k in ('id', 'ownerHubId')) or ref['revision'] < selected['revision']:
                _fail()
        try:
            deadline = datetime.fromisoformat(source['originalDeadline'])
            if deadline.utcoffset() is None:
                _fail()
        except (TypeError, ValueError):
            _fail()
        reply = source['confirmedReply']
        if (type(reply) is not dict or set(reply) != {'outcome', 'receiptRef', 'resourceRef', 'result'}
                or reply['outcome'] != 'applied'):
            _fail()
        validate('capability-storage-write-reply', {k: reply[k] for k in ('outcome', 'receiptRef', 'resourceRef')})
        return _copy(source)

    def _validate(self, record, identity):
        if (type(record) is not dict or set(record) != _FIELDS
                or type(record['formatVersion']) is not int or record['formatVersion'] != 1
                or record['state'] not in ('pending', 'completed')
                or any(canonical_bytes(record[k]) != canonical_bytes(v) for k, v in identity.items())
                or record['bindings'] != self._bindings(record['bindings'], identity)
                or type(record['workSources']) is not list or len(record['workSources']) > 64):
            _fail()
        if record['state'] == 'pending':
            if record['result'] is not None or record['workSources']:
                _fail()
        else:
            if not record['workSources']:
                _fail()
            sources = [self._source(source, record) for source in record['workSources']]
            if len({self._source_key(source) for source in sources}) != len(sources):
                _fail()
            if record['verb'] == 'heartbeat':
                renewed = 0
                for source in sources:
                    value = source['confirmedReply']['result']
                    if (type(value) is not dict or set(value) != {'renewed'}
                            or type(value['renewed']) is not int or value['renewed'] < 0):
                        _fail()
                    renewed += value['renewed']
                if (sorted((source['binding'] for source in sources), key=canonical_bytes) != record['bindings']
                        or canonical_bytes(record['result']) != canonical_bytes({'renewed': renewed})):
                    _fail()
            elif (len(sources) != 1 or canonical_bytes(record['result']) !=
                    canonical_bytes(sources[0]['confirmedReply']['result'])):
                _fail()
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
            record = self._validate(strict_loads(rows[0]['v']), identity)
            if canonical_bytes(record).decode() != rows[0]['v'] or rows[0]['k'] != _PREFIX + record['state'] + ':' + suffix:
                _fail()
            return record
        except (ValueError, TypeError, KeyError, RecursionError):
            _fail()

    def lookup(self, *, operation_id, request_digest, principal, verb, arguments):
        return self._read(self._identity(operation_id, request_digest, principal, verb, arguments))

    def reserve(self, *, operation_id, request_digest, principal, verb, arguments, bindings):
        self._custody()
        identity = self._identity(operation_id, request_digest, principal, verb, arguments)
        bindings = self._bindings(bindings, identity)
        with self._store.tx():
            existing = self._read(identity)
            if existing is not None:
                if canonical_bytes(existing['bindings']) != canonical_bytes(bindings):
                    _fail()
                return existing
            low, high = _PREFIX + 'pending:', _PREFIX + 'pending;'
            if len(self._store.q('SELECT k FROM fed_state WHERE k>=? AND k<? LIMIT 32', (low, high))) >= 32:
                raise ContractError('work_completion_capacity')
            record = self._validate(dict(formatVersion=1, **identity, bindings=bindings,
                state='pending', result=None, workSources=[]), identity)
            self._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                (low + self._suffix(identity), canonical_bytes(record).decode()))
            return record

    def abandon_unsubmitted(self, *, operation_id, request_digest, principal, verb, arguments, bindings=None):
        """Remove only this failed RPC reservation when no owner effect was sent.

        The signed client retains its exact command before mutation transport.
        Any retained command, including an uncertain or conflicting original,
        therefore prevents removal. Completion and command retirement share one
        transaction, so an archived result cannot be mistaken for unsubmitted work.
        """
        self._custody()
        identity = self._identity(operation_id, request_digest, principal, verb, arguments)
        with self._store.tx():
            record = self._read(identity)
            if record is None or record['state'] != 'pending':
                return False
            if bindings is not None and canonical_bytes(record['bindings']) != canonical_bytes(
                    self._bindings(bindings, identity)):
                return False
            keys = []
            for binding in record['bindings']:
                intent = (payload_digest({'intentDigest': record['intentDigest'],
                    'repository': binding['workCommands']['repository']})
                    if verb == 'heartbeat' else record['intentDigest'])
                for command in _VERBS[verb]:
                    keys.append(self._source_key({'binding': binding, 'intentDigest': intent,
                        'contractId': 'federation-work-' + command}))
            placeholders = ','.join('?' for _ in keys)
            if self._store.q1('SELECT k FROM fed_state WHERE k IN (' + placeholders + ') LIMIT 1', keys):
                return False
            self._store.db.execute('DELETE FROM fed_state WHERE k=? AND v=?',
                (_PREFIX + 'pending:' + self._suffix(identity), canonical_bytes(record).decode()))
            return True

    def complete(self, *, operation_id, request_digest, principal, verb, arguments, bindings, result, completions):
        """Commit only after the caller's original durable follow-on work.

        The surrounding Store transaction also owns local notification evidence.
        Cross-owner capture must already have its original confirmed receipt.
        This method does not run those obligations or assert cross-store atomicity.
        """
        self._custody()
        if not self._store.db.in_transaction:
            raise ContractError('work_completion_transaction_required')
        identity = self._identity(operation_id, request_digest, principal, verb, arguments)
        existing = self._read(identity)
        bindings = self._bindings(bindings, identity)
        if existing is None or existing['bindings'] != bindings:
            _fail()
        if type(completions) not in (tuple, list) or not 1 <= len(completions) <= 64:
            _fail()
        sources = []
        for completion in completions:
            if type(completion) not in (tuple, list) or len(completion) != 5:
                _fail()
            session, enrollment, command, intent, expected_result = completion
            from hub.client_launch_session import ApplicationClientSession
            if (type(session) is not ApplicationClientSession or session.work_enrollment() != enrollment
                    or enrollment not in bindings or command not in _VERBS[verb]):
                _fail()
            key = self._source_key({'binding': enrollment, 'intentDigest': intent,
                'contractId': 'federation-work-' + command})
            if existing['state'] == 'completed':
                found = [source for source in existing['workSources'] if self._source_key(source) == key]
                source = found[0] if len(found) == 1 else None
            else:
                row = self._store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
                if row is None or type(row['v']) is not str or len(row['v'].encode()) > _LIMIT:
                    _fail()
                source = strict_loads(row['v'])
                if canonical_bytes(source).decode() != row['v']:
                    _fail()
            source = self._source(source, existing)
            if canonical_bytes(source['confirmedReply']['result']) != canonical_bytes(expected_result):
                _fail()
            sources.append(source)
        record = self._validate({**existing, 'state': 'completed', 'result': result,
            'workSources': sorted(sources, key=lambda value: self._source_key(value))}, identity)
        if existing['state'] == 'completed':
            if canonical_bytes(existing) != canonical_bytes(record):
                _fail()
            return existing
        suffix = self._suffix(identity)
        self._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
            (_PREFIX + 'completed:' + suffix, canonical_bytes(record).decode()))
        self._store.db.execute('DELETE FROM fed_state WHERE k=?', (_PREFIX + 'pending:' + suffix,))
        for source in sources:
            self._store.db.execute('DELETE FROM fed_state WHERE k=? AND v=?',
                (self._source_key(source), canonical_bytes(source).decode()))
        return record

    def delivered(self, record):
        """Validate a drained explicit-ID result without deleting its receipt."""
        self._custody()
        if type(record) is not dict:
            _fail()
        try:
            identity = self._identity(record['operationId'], record['requestDigest'], record['principal'],
                record['verb'], record['arguments'])
            record = self._validate(record, identity)
        except (KeyError, TypeError):
            _fail()
        if record['state'] != 'completed' or canonical_bytes(self._read(identity)) != canonical_bytes(record):
            _fail()
