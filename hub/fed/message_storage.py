"""Retain capability outcomes in the original message owner's transaction."""
from datetime import datetime, timezone
from datetime import datetime as _Timestamp
import hashlib

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.store import Store

_KNOWLEDGE_MUTATIONS = frozenset('federation-knowledge-' + action for action in
    ('share', 'index', 'approve', 'capture', 'withdraw'))
_CODE_MUTATIONS = frozenset('federation-code-' + action for action in
    ('publish', 'index', 'approve', 'fetched'))
_WORK_MUTATIONS = frozenset('federation-work-' + action for action in
    ('create', 'offer', 'claim', 'heartbeat', 'release', 'cancel', 'claim-path',
     'ingest', 'claim-envelope', 'grant-envelope', 'result-envelope', 'stage-result',
     'revoke', 'return-leases', 'sweep-leases', 'ingest-legacy', 'result-legacy',
     'approve', 'approve-privileged', 'register', 'state', 'sweep-global'))
_LEGACY_MUTATIONS = _KNOWLEDGE_MUTATIONS | _CODE_MUTATIONS | _WORK_MUTATIONS | frozenset(('federation-message-send',
    'federation-message-deliver', 'federation-message-approve', 'federation-message-finding'))


def _record_commit(contract, outcome, expected, revision):
    """Log one work journal commit: closed contract and outcome names and two revisions only."""
    try:
        import re
        import syslog
        name = contract if type(contract) is str and re.fullmatch(r'federation-work-[a-z-]{1,40}', contract) else 'other'
        syslog.syslog(syslog.LOG_NOTICE, 'application_services_work_commit contract=%s outcome=%s expected=%d revision=%d'
                      % (name, outcome if outcome in ('applied', 'conflict') else 'other', int(expected), int(revision)))
    except BaseException:
        pass


class MessageStorageJournal:
    """Private owner metadata in hub.db; no second store or state mutation API."""
    def __init__(self, store, binding, source, *, namespace='messages'):
        if type(store) is not Store or type(binding) is not bytes:
            raise ContractError('capability_owner_configuration')
        if namespace not in ('messages', 'knowledge', 'code', 'work'):
            raise ContractError('capability_owner_configuration')
        self.store, self.binding = store, binding
        self._namespace = namespace
        descriptor = strict_loads(binding)
        identity = canonical_bytes({key: descriptor[key] for key in ('hubId', 'entityId', 'scope')})
        self._base = 'capability-' + namespace + ':' + hashlib.sha256(identity).hexdigest() + ':'
        self._initial = {'formatVersion': 1, 'binding': strict_loads(binding), 'revision': 1, 'source': strict_loads(canonical_bytes(source))}
        canonical_bytes(self._initial)

    def _get(self, key):
        row = self.store.q1('SELECT v FROM fed_state WHERE k=?', (self._base + key,))
        if row is None:
            return None
        value = strict_loads(row['v'])
        if value is None:
            raise ContractError('capability_resource_stale')
        return value

    def _set(self, key, value, *, original=False):
        raw = canonical_bytes(value)
        if len(raw) > (1048576 if original else 65536):
            raise ContractError('capability_service_unavailable')
        self.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',
            (self._base + key, raw.decode()))

    def current(self):
        state = self._get('resource')
        if state is None:
            state = self._initial
        if (type(state) is not dict or set(state) != set(self._initial)
                or type(state['formatVersion']) is not int or state['formatVersion'] != 1 or type(state['revision']) is not int
                or not 1 <= state['revision'] <= 9007199254740991
                or state['binding'] != self._initial['binding']):
            raise ContractError('capability_resource_stale')
        return state

    def outcome(self, operation_id, digest):
        key = 'operation:' + hashlib.sha256(operation_id.encode()).hexdigest()
        stored = self._get(key)
        if stored is not None:
            if type(stored) is dict and stored.get('formatVersion') == 2:
                if set(stored) != {'formatVersion', 'binding', 'envelopeDigest', 'result', 'reply'}:
                    raise ContractError('capability_outcome_conflict')
                original = self._get('original:' + hashlib.sha256(operation_id.encode()).hexdigest())
                if (original is None or payload_digest(original) != stored['envelopeDigest']
                        or original.get('contractId') not in _LEGACY_MUTATIONS):
                    raise ContractError('capability_outcome_conflict')
                stored = {k: v for k, v in stored.items() if k != 'envelopeDigest'}
                stored.update(formatVersion=1, envelope=original)
            if (type(stored) is not dict or set(stored) != {'formatVersion', 'binding', 'envelope', 'result', 'reply'} or type(stored['formatVersion']) is not int
                    or stored['formatVersion'] != 1 or stored['envelope']['contractId'] not in
                        (_LEGACY_MUTATIONS | {'capability-storage-write'})
                    or stored['envelope']['operation'].get('operationId') != operation_id
                    or stored['envelope']['operation']['payloadDigest'] != digest
                    or payload_digest(stored['envelope']['payload']) != digest
                    or stored['binding'] != self._initial['binding']):
                raise ContractError('capability_outcome_conflict')
            validate('message-envelope', stored['envelope'])
            validate(stored['envelope']['contractId'], stored['envelope']['payload'])
            validate('capability-storage-write-reply', stored['reply'])
        return stored

    def commit(self, original, expected_revision, valid_until, effect):
        """Run an owner-owned synchronous effect and retain its result atomically.

        The receiving owner authenticates the original envelope before dispatch.
        The DB thread repeats deadline/CAS checks inside the same transaction as
        Store.post or Federation.stage. This callable never crosses the wire.
        """
        operation = original['operation']
        with self.store.tx():
            previous = self.outcome(operation['operationId'], operation['payloadDigest'])
            if previous is not None:
                if previous['envelope']['operation'] != operation:
                    raise ContractError('capability_outcome_conflict')
                return previous
            self._deadline(valid_until)
            current = self.current()
            revision, source = current['revision'], current['source']
            if expected_revision != revision:
                result, outcome = None, 'conflict'
            else:
                result, source = effect()
                outcome = 'applied'
                if revision == 9007199254740991:
                    raise ContractError('capability_service_unavailable')
                revision += 1
            binding = self._initial['binding']
            receipt = {'id': 'message-operation-' + hashlib.sha256(
                (operation['operationId'] + '\0' + operation['payloadDigest']).encode()).hexdigest(),
                'ownerHubId': binding['hubId'], 'revision': revision}
            resource = {'id': binding['entityId'], 'ownerHubId': binding['hubId'], 'revision': revision}
            record = {'formatVersion': 1, 'binding': binding, 'envelope': original,
                'result': result, 'reply': {'receiptRef': receipt, 'resourceRef': resource, 'outcome': outcome}}
            key = hashlib.sha256(operation['operationId'].encode()).hexdigest()
            retained = record
            if original['contractId'] in _LEGACY_MUTATIONS:
                self._set('original:' + key, original, original=True)
                retained = {k: v for k, v in record.items() if k != 'envelope'}
                retained.update(formatVersion=2, envelopeDigest=payload_digest(original))
            self._set('operation:' + key, retained,
                original=original['contractId'] in (_KNOWLEDGE_MUTATIONS | _CODE_MUTATIONS | _WORK_MUTATIONS))
            if outcome == 'applied':
                self._set('resource', {**current, 'revision': revision, 'source': source})
            self._deadline(valid_until)
            if self._namespace == 'work':
                _record_commit(original['contractId'], outcome, expected_revision, current['revision'])
            return record

    def reject(self, original, valid_until):
        """Retain one authenticated control rejection without running an effect."""
        if ((self._namespace, original.get('contractId')) not in (
                ('knowledge', 'federation-knowledge-withdraw'), ('work', 'federation-work-revoke'))
                or 'control' not in original.get('payload', {}).get('input', {})):
            raise ContractError('capability_access_refused')
        validate('message-envelope', original)
        validate(original['contractId'], original['payload'])
        operation = original['operation']
        with self.store.tx():
            previous = self.outcome(operation['operationId'], operation['payloadDigest'])
            if previous is not None:
                if previous['envelope']['operation'] != operation:
                    raise ContractError('capability_outcome_conflict')
                return previous
            self._deadline(valid_until)
            current = self.current()
            binding, revision = self._initial['binding'], current['revision']
            receipt = {'id': 'message-operation-' + hashlib.sha256(
                (operation['operationId'] + '\0' + operation['payloadDigest']).encode()).hexdigest(),
                'ownerHubId': binding['hubId'], 'revision': revision}
            record = {'formatVersion': 1, 'binding': binding, 'envelope': original,
                'result': {'withdrawn' if self._namespace == 'knowledge' else 'cancelled': 0}, 'reply': {'receiptRef': receipt, 'outcome': 'rejected',
                    'resourceRef': {'id': binding['entityId'], 'ownerHubId': binding['hubId'], 'revision': revision}}}
            key = hashlib.sha256(operation['operationId'].encode()).hexdigest()
            self._set('original:' + key, original, original=True)
            retained = {k: v for k, v in record.items() if k != 'envelope'}
            retained.update(formatVersion=2, envelopeDigest=payload_digest(original))
            self._set('operation:' + key, retained, original=True)
            self._deadline(valid_until)
            return record

    @staticmethod
    def _deadline(valid_until):
        if (not isinstance(valid_until, _Timestamp) or valid_until.utcoffset() is None
                or datetime.now(timezone.utc) >= valid_until):
            raise ContractError('capability_access_refused')
