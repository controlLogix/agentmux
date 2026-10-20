"""Retain one fixed lifecycle batch before any repository command is sent."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import re
import secrets

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.store import HubError
from .legacy_work_client import LegacyWorkCommandClient

_PREFIX = 'work-lifecycle-client:'
_LIMIT = 4 * 1048576
_ACTIONS = frozenset(('register', 'state', 'sweep-global'))
_FIELDS = frozenset(('formatVersion', 'profile', 'operationId', 'command', 'arguments', 'bindings',
    'descriptor', 'originalDeadline', 'state', 'result', 'receipts'))


def _fail():
    raise ContractError('work_lifecycle_client_binding')


def _copy(value):
    raw = canonical_bytes(value)
    if len(raw) > _LIMIT:
        raise ContractError('work_lifecycle_client_capacity')
    return strict_loads(raw)


class WorkLifecycleClient:
    """Borrow selected service sessions and the original joined Hub DB worker."""
    def __init__(self, commands):
        if type(commands) is not LegacyWorkCommandClient:
            _fail()
        commands.check(commands._federation)
        self._commands, self._hub = commands, commands._hub
        current = getattr(self._hub, '_work_lifecycle_client', None)
        if current is not None:
            _fail()
        profiles = {tuple(strict_loads(raw)[key] for key in ('hubId', 'profileId', 'authorityId'))
            for _, raw in commands._routes}
        if len(profiles) != 1:
            _fail()
        self._profile = dict(zip(('hubId', 'profileId', 'authorityId'), next(iter(profiles))))
        self._prefix = _PREFIX + hashlib.sha256(canonical_bytes(self._profile)).hexdigest() + ':'
        self._closed, self._lock, self._active = False, asyncio.Lock(), set()
        self._executor = ThreadPoolExecutor(max_workers=64, thread_name_prefix='work-lifecycle-session')
        self._hub._work_lifecycle_client = self

    def __repr__(self):
        return '<WorkLifecycleClient private>'

    def _current(self):
        if (self._closed or self._hub._work_lifecycle_client is not self
                or self._commands._hub is not self._hub):
            _fail()
        self._commands.check(self._commands._federation)

    @staticmethod
    def _deadline(expires):
        if (not isinstance(expires, datetime) or expires.utcoffset() is None
                or datetime.now(timezone.utc) >= expires):
            raise ContractError('work_lifecycle_client_expired')
        return expires

    def _key(self, operation_id):
        if type(operation_id) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', operation_id) is None:
            _fail()
        return self._prefix + hashlib.sha256(operation_id.encode()).hexdigest()

    def _record(self, value, operation_id, command, arguments):
        if (type(value) is not dict or set(value) != _FIELDS or type(value['formatVersion']) is not int
                or value['formatVersion'] != 1 or value['profile'] != self._profile
                or value['operationId'] != operation_id or value['command'] != command
                or canonical_bytes(value['arguments']) != canonical_bytes(arguments)
                or value['state'] not in ('prepared', 'uncertain', 'completed')
                or type(value['bindings']) is not list or not 1 <= len(value['bindings']) <= 64
                or type(value['receipts']) is not list):
            _fail()
        self._deadline_format(value['originalDeadline'])
        descriptor = value['descriptor']
        if descriptor != self._descriptor(command, arguments, operation_id, descriptor['repositories']):
            _fail()
        if len(value['bindings']) != len(descriptor['repositories']):
            _fail()
        for binding, entry in zip(value['bindings'], descriptor['repositories']):
            selected = binding['workCommands']
            validate('application-work-commands', selected)
            if (any(binding[key] != self._profile[key] for key in self._profile)
                    or selected['authenticatedCaller'] != 'federation' or selected['repository'] is None
                    or selected['repository']['localName'] != entry['repository']
                    or 'federation-work-' + command not in selected['grantRefs']):
                _fail()
            self._commands._reference(entry['resourceRef'], selected['resourceRef'])
            validate('federation-work-' + command,
                {'resourceRef': entry['resourceRef'], 'input': descriptor, 'attribution': 'federation'})
        if value['state'] == 'completed':
            if len(value['receipts']) != len(value['bindings']):
                _fail()
            for binding, receipt in zip(value['bindings'], value['receipts']):
                if type(receipt) is not dict or set(receipt) != {'outcome', 'receiptRef', 'resourceRef'}:
                    _fail()
                self._receipt({**receipt, 'result': value['result']}, binding)
        elif value['receipts'] or value['result'] is not None:
            _fail()
        return value

    @staticmethod
    def _deadline_format(value):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.utcoffset() is None:
                _fail()
            return parsed
        except (ValueError, TypeError):
            _fail()

    def _load(self, operation_id, command, arguments):
        self._current()
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(operation_id),))
        if row is None:
            return None
        try:
            value = strict_loads(row['v'])
            if canonical_bytes(value).decode() != row['v']:
                _fail()
            return self._record(value, operation_id, command, arguments)
        except (KeyError, TypeError, ValueError):
            _fail()

    def _write(self, record):
        self._current()
        self._record(record, record['operationId'], record['command'], record['arguments'])
        raw = canonical_bytes(_copy(record)).decode()
        self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',
            (self._key(record['operationId']), raw))

    def _active_ids(self):
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._prefix + 'active',))
        values = [] if row is None else strict_loads(row['v'])
        if (type(values) is not list or len(values) > 32
                or any(type(value) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is None for value in values)
                or len(set(values)) != len(values)):
            _fail()
        return values

    def _save_active(self, values):
        self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',
            (self._prefix + 'active', canonical_bytes(values).decode()))

    def _reserve(self, record):
        self._current()
        with self._hub.store.tx():
            previous = self._load(record['operationId'], record['command'], record['arguments'])
            if previous is not None:
                return previous
            active = self._active_ids()
            if len(active) >= 32:
                raise ContractError('work_lifecycle_client_capacity')
            self._write(record)
            self._save_active([*active, record['operationId']])
            return record

    def _transition(self, old, new):
        self._current()
        with self._hub.store.tx():
            current = self._load(old['operationId'], old['command'], old['arguments'])
            if current != old:
                _fail()
            active = self._active_ids()
            if old['state'] != 'completed' and old['operationId'] not in active:
                _fail()
            self._write(new)
            if new['state'] == 'completed':
                self._save_active([value for value in active if value != old['operationId']])
        return new

    def _routes(self, command, record=None):
        routes = self._commands._select('federation', command)
        routes = [(session, binding) for session, binding in routes if binding['workCommands']['repository'] is not None]
        routes.sort(key=lambda route: route[1]['workCommands']['repository']['localName'])
        if record is not None:
            selected = []
            for original in record['bindings']:
                matches = [(session, binding) for session, binding in routes
                    if self._commands._binding(binding) == original]
                if len(matches) != 1:
                    _fail()
                selected.extend(matches)
            routes = selected
        if (not 1 <= len(routes) <= 64
                or len({binding['workCommands']['repository']['localName'] for _, binding in routes}) != len(routes)
                or len({canonical_bytes(binding['callerRef']) for _, binding in routes}) != 1):
            _fail()
        return routes

    def _descriptor(self, command, arguments, operation_id, entries):
        if command not in _ACTIONS or type(arguments) is not dict or set(arguments) & {'batchId', 'localNode', 'repositories'}:
            _fail()
        fixed = {'register': 'hub-registration', 'state': 'hub-state', 'sweep-global': 'hub-lease-sweep'}[command]
        purpose = arguments.get('purpose', fixed)
        if (command != 'state' and purpose != fixed
                or command == 'state' and purpose not in ('hub-state', 'hub-observation')):
            _fail()
        return {**arguments, 'purpose': purpose, 'batchId': operation_id,
            'localNode': self._commands._node, 'repositories': entries}

    async def _round(self, routes, function):
        async def one(session, binding):
            async with self._commands._locks[id(session)]:
                self._current()
                return await function(session, binding)
        workers = [asyncio.create_task(one(session, binding)) for session, binding in routes]
        aggregate = asyncio.gather(*workers, return_exceptions=True)
        try:
            values = await asyncio.shield(aggregate)
        except asyncio.CancelledError:
            while not aggregate.done():
                try:
                    await asyncio.wait({aggregate})
                except asyncio.CancelledError:
                    continue
            aggregate.result()
            raise
        for value in values:
            if isinstance(value, BaseException):
                raise value
        return values

    async def _inspect(self, routes, expires):
        async def inspect(session, binding):
            reply = await self._commands._call(session, 'federation-work-inspect', 'lifecycle_inspect_' + secrets.token_hex(16),
                {'resourceRef': binding['workCommands']['resourceRef'], 'input': {}}, expires, _executor=self._executor)
            result = reply['result']
            if type(result) is not dict or set(result) != {'resourceRef'}:
                _fail()
            reference = self._commands._reference(result['resourceRef'], binding['workCommands']['resourceRef'])
            return reference, self._deadline_format(reply['validUntil'])
        values = await self._round(routes, inspect)
        return [value[0] for value in values], min(expires, *(value[1] for value in values))

    def _receipt(self, receipt, binding):
        if type(receipt) is not dict or set(receipt) != {'outcome', 'receiptRef', 'resourceRef', 'result'} or receipt['outcome'] != 'applied':
            raise ContractError('work_lifecycle_reply_unconfirmed')
        validate('capability-storage-write-reply', {key: receipt[key] for key in ('outcome', 'receiptRef', 'resourceRef')})
        self._commands._reference(receipt['resourceRef'], binding['workCommands']['resourceRef'])
        if (receipt['receiptRef']['ownerHubId'] != binding['hubId']
                or receipt['receiptRef']['revision'] != receipt['resourceRef']['revision']):
            raise ContractError('work_lifecycle_reply_unconfirmed')
        return receipt

    async def _exchange(self, routes, record, expires, *, submit, _fresh_receipts=None, ready_record=None):
        if ready_record is not None and (submit or record['command'] != 'register'
                or ready_record['command'] != 'state' or ready_record['state'] != 'completed'
                or record['state'] != 'completed' or ready_record['bindings'] != record['bindings']):
            _fail()
        if submit:
            if _fresh_receipts is not None:
                _fail()
            references = [entry['resourceRef'] for entry in record['descriptor']['repositories']]
        elif _fresh_receipts is not None:
            # Only the immediately verified receipts from this completed batch
            # supply these references. The following outcome query still checks
            # current authority and the exact original operation and digest.
            if (record['state']!='completed' or type(_fresh_receipts) is not list
                    or len(_fresh_receipts)!=len(routes)
                    or record['bindings']!=[self._commands._binding(binding) for _,binding in routes]
                    or len(record['receipts'])!=len(routes)):
                _fail()
            references=[]
            for receipt,metadata,(_,binding) in zip(_fresh_receipts,record['receipts'],routes):
                self._receipt(receipt,binding)
                if (metadata!={key:receipt[key] for key in ('outcome','receiptRef','resourceRef')}
                        or canonical_bytes(receipt['result'])!=canonical_bytes(record['result'])):
                    _fail()
                references.append(_copy(receipt['resourceRef']))
            self._deadline(expires)
        else:
            references, expires = await self._inspect(routes, expires)
        async def exchange(session, binding):
            index = record['bindings'].index(self._commands._binding(binding))
            original_ref = record['descriptor']['repositories'][index]['resourceRef']
            payload = {'resourceRef': original_ref, 'input': record['descriptor'], 'attribution': 'federation'}
            if submit:
                reply = await self._commands._call(session, 'federation-work-' + record['command'],
                    record['operationId'], payload, expires, _executor=self._executor)
                receipt = reply['result']
            else:
                query = {'contractId': 'federation-work-' + record['command'], 'operationId': record['operationId'],
                    'payloadDigest': payload_digest(payload)}
                if ready_record is not None:
                    ready_payload = {'resourceRef': ready_record['descriptor']['repositories'][index]['resourceRef'],
                        'input': ready_record['descriptor'], 'attribution': 'federation'}
                    query['readyState'] = {'operationId': ready_record['operationId'],
                        'payloadDigest': payload_digest(ready_payload)}
                reply = await self._commands._call(session, 'federation-work-outcome', 'lifecycle_outcome_' + secrets.token_hex(16),
                    {'resourceRef': references[index], 'input': query}, expires, _executor=self._executor)
                value = reply['result']
                if type(value) is not dict or any(value.get(key) != item for key, item in query.items()):
                    _fail()
                if value.get('outcome') == 'absent':
                    raise HubError('lifecycle outcome is unconfirmed; original recovery is retained')
                if ready_record is not None:
                    ready_receipt = self._receipt(value.get('readyStateReceipt'), binding)
                    expected = {**ready_record['receipts'][index], 'result': ready_record['result']}
                    if canonical_bytes(ready_receipt) != canonical_bytes(expected):
                        _fail()
                receipt = {key: value.get(key) for key in ('outcome', 'receiptRef', 'resourceRef', 'result')}
            return self._receipt(receipt, binding), self._deadline_format(reply['validUntil'])
        values = await self._round(routes, exchange)
        receipts = [value[0] for value in values]
        if len({canonical_bytes(receipt['result']) for receipt in receipts}) != 1:
            raise ContractError('work_lifecycle_reply_unconfirmed')
        return receipts, min(expires, *(value[1] for value in values))

    async def _execute(self, command, arguments, operation_id, expires, *, completed_only=False):
        self._current()
        self._deadline(expires)
        self._key(operation_id)
        arguments = _copy(arguments)
        if command not in _ACTIONS:
            _fail()
        record = await self._commands._owned_db(self._load, operation_id, command, arguments)
        if completed_only and (record is None or record['state'] != 'completed'):
            _fail()
        routes = self._routes(command, record)
        if record is None:
            references, expires = await self._inspect(routes, expires)
            entries = [{'repository': binding['workCommands']['repository']['localName'], 'resourceRef': reference}
                for (_, binding), reference in zip(routes, references)]
            descriptor = self._descriptor(command, arguments, operation_id, entries)
            record = await self._commands._owned_db(self._reserve, {'formatVersion': 1, 'profile': self._profile,
                'operationId': operation_id, 'command': command, 'arguments': arguments,
                'bindings': [self._commands._binding(binding) for _, binding in routes], 'descriptor': descriptor,
                'originalDeadline': expires.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'state': 'prepared', 'result': None, 'receipts': []})
        submit = record['state'] == 'prepared'
        if submit:
            expires = min(expires, self._deadline_format(record['originalDeadline']))
            self._deadline(expires)
            record = await self._commands._owned_db(self._transition, record, {**record, 'state': 'uncertain'})
        receipts, expires = await self._exchange(routes, record, expires, submit=submit)
        metadata = [{key: receipt[key] for key in ('outcome', 'receiptRef', 'resourceRef')} for receipt in receipts]
        already_completed = record['state'] == 'completed'
        if record['state'] == 'completed':
            if metadata != record['receipts'] or canonical_bytes(receipts[0]['result']) != canonical_bytes(record['result']):
                raise ContractError('work_lifecycle_reply_unconfirmed')
        else:
            record = await self._commands._owned_db(self._transition, record,
                {**record, 'state': 'completed', 'result': receipts[0]['result'], 'receipts': metadata})
        # Final use is a fresh original-outcome read. It never renews an effect.
        if not already_completed:
            receipts, expires = await self._exchange(routes, record, expires, submit=False,
                _fresh_receipts=receipts)
            if ([{key: receipt[key] for key in ('outcome', 'receiptRef', 'resourceRef')} for receipt in receipts] != record['receipts']
                    or canonical_bytes(receipts[0]['result']) != canonical_bytes(record['result'])):
                raise ContractError('work_lifecycle_reply_unconfirmed')
        self._commands._remember(routes, expires)
        return self._commands.confirm_disclosure(_copy(record['result']))

    async def execute(self, command, arguments, *, operation_id, expires, _completed_only=False):
        if len(self._active) >= 32:
            raise ContractError('work_lifecycle_client_capacity')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with self._lock:
                return await self._execute(command, arguments, operation_id, expires, completed_only=_completed_only)
        finally:
            self._active.discard(task)

    async def register(self, arguments, *, operation_id, expires):
        return await self.execute('register', arguments, operation_id=operation_id, expires=expires)

    async def set_state(self, arguments, *, operation_id, expires):
        return await self.execute('state', arguments, operation_id=operation_id, expires=expires)

    async def sweep(self, *, operation_id, expires):
        return await self.execute('sweep-global', {}, operation_id=operation_id, expires=expires)

    async def confirm_disclosure(self, operation_id, *, expires, finish=False):
        if type(finish) is not bool:
            _fail()
        def load():
            self._current()
            row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(operation_id),))
            if row is None:
                _fail()
            value = strict_loads(row['v'])
            record = self._load(operation_id, value['command'], value['arguments'])
            if record['state'] != 'completed':
                _fail()
            return record
        record = await self._commands._owned_db(load)
        result = await self.execute(record['command'], record['arguments'], operation_id=operation_id, expires=expires,
            _completed_only=True)
        return self._commands.finish_disclosure(result) if finish else result

    async def confirm_registration(self, operation_id, *, ready_operation_id=None, expires, finish=False):
        """Confirm completed originals together without submitting another effect."""
        if type(finish) is not bool:
            _fail()
        if len(self._active) >= 32:
            raise ContractError('work_lifecycle_client_capacity')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with self._lock:
                self._current()
                pending = self._commands._disclosures.get(task)
                if pending is not None:
                    expires = min(expires, pending[1])
                self._deadline(expires)
                def load(identifier, command):
                    row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(identifier),))
                    if row is None:
                        _fail()
                    value = strict_loads(row['v'])
                    record = self._load(identifier, command, value['arguments'])
                    if record['state'] != 'completed':
                        _fail()
                    return record
                record = await self._commands._owned_db(load, operation_id, 'register')
                ready = (None if ready_operation_id is None else
                    await self._commands._owned_db(load, ready_operation_id, 'state'))
                routes = self._routes('register', record)
                if ready is not None:
                    self._routes('state', ready)
                receipts, expires = await self._exchange(routes, record, expires, submit=False, ready_record=ready)
                expected = [{**receipt, 'result': record['result']} for receipt in record['receipts']]
                if canonical_bytes(receipts) != canonical_bytes(expected):
                    _fail()
                self._commands._remember(routes, expires)
                result = self._commands.confirm_disclosure(_copy(record['result']))
                return self._commands.finish_disclosure(result) if finish else result
        finally:
            self._active.discard(task)

    async def close(self):
        self._closed = True
        current = asyncio.current_task()
        pending = {task for task in self._active if task is not current}
        for task in pending:
            task.cancel()
        while pending:
            try:
                done, pending = await asyncio.wait(pending)
                for task in done:
                    if not task.cancelled():
                        task.exception()
            except asyncio.CancelledError:
                continue
        self._executor.shutdown(wait=True)
        if getattr(self._hub, '_work_lifecycle_client', None) is self:
            self._hub._work_lifecycle_client = None
