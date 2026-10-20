"""Retain exact signed work requests and private disclosure validity."""
import asyncio
from contextlib import asynccontextmanager, nullcontext
from datetime import datetime, timezone
from functools import partial
import hashlib
import re
import secrets
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.store import HubError
from identity.work_client import WORK_COMMANDS, WORK_MUTATIONS
from .legacy_messages_client import LegacyMessageCommandClient, LegacyStorageConflict


class LegacyWorkCommandClient(LegacyMessageCommandClient):
    """Host-private fixed sessions; caller adapters retain their own admission."""
    _field, _family, _state_prefix = 'workCommands', 'federation-work-', 'legacy-work-client:'
    _enrollment_method, _command_method = 'work_enrollment', 'work_command'
    _completed_commands = frozenset()

    def __init__(self, hub, sessions):
        from hub.server import Hub
        from hub.client_launch_session import ApplicationClientSession
        if (type(hub) is not Hub or type(sessions) is not tuple or not 1 <= len(sessions) <= 64
                or any(type(session) is not ApplicationClientSession for session in sessions)):
            raise ContractError('legacy_work_client_configuration')
        self._hub, self._federation = hub, None
        self._store, self._connection, self._db = hub.store, hub.store.db, hub.db
        self._hub_worker, self._stop = getattr(hub, 'dbx', None), getattr(hub, 'stop', None)
        self._node = hub.cfg['node']
        self._routes, seen = [], set()
        for session in sessions:
            enrollment = session.work_enrollment()
            selected = enrollment[self._field]
            if not {'federation-work-inspect', 'federation-work-outcome'} <= set(selected['grantRefs']):
                raise ContractError('legacy_work_client_configuration')
            key = self._route_key(enrollment)
            if key in seen:
                raise ContractError('legacy_work_client_configuration')
            seen.add(key)
            self._routes.append((session, canonical_bytes(enrollment)))
        if len({tuple(strict_loads(raw)[name] for name in ('hubId', 'profileId', 'authorityId'))
                for _, raw in self._routes}) != 1:
            raise ContractError('legacy_work_client_configuration')
        self._locks = {id(session): asyncio.Lock() for session, _ in self._routes}
        self._transport_locks = {id(session): asyncio.Lock() for session, _ in self._routes}
        self._workers, self._active = set(), set()
        self._closed, self._closing = False, None
        self._publications = weakref.WeakKeyDictionary()
        self._disclosures = weakref.WeakKeyDictionary()

    def __repr__(self):
        return '<LegacyWorkCommandClient private>'

    def _route_key(self, enrollment):
        selected = enrollment[self._field]
        return (selected['authenticatedCaller'], canonical_bytes(enrollment['scope']),
            canonical_bytes(selected['repository']))

    @staticmethod
    def _logical_route(binding):
        selected = binding['workCommands']
        return {**{key: binding[key] for key in ('hubId', 'scope')},
            **{key: selected[key] for key in ('authenticatedCaller', 'localPeer', 'localNode', 'repository')}}

    def check(self, federation=None):
        if (self._closed or federation is not self._federation
                or self._hub.store is not self._store or self._store.db is not self._connection
                or getattr(self._hub, 'dbx', None) is not self._hub_worker
                or getattr(self._hub, 'stop', None) is not self._stop
                or self._stop is not None and self._stop.is_set() or self._hub.cfg['node'] != self._node
                or self._federation is not None and self._federation.hub is not self._hub):
            raise ContractError('legacy_work_client_unavailable')
        self._check_store()
        source = getattr(self._hub, '_work_source_binding', None)
        if source is not None:
            source.check()

    def _check_store(self):
        if (self._hub.store is not self._store or self._store.db is not self._connection
                or self._hub.db != self._db or getattr(self._hub, 'dbx', None) is not self._hub_worker):
            raise ContractError('legacy_work_recovery_invalid')
        super()._check_store()

    def _select(self, caller, command, repository=None):
        self.check(self._federation)
        contract = self._family + command
        if (contract not in WORK_COMMANDS or repository is not None
                and (type(repository) is not str or not repository)):
            raise ContractError('legacy_work_route_unavailable')
        matches = []
        for session, raw in self._routes:
            enrollment = strict_loads(raw)
            selected, repo = enrollment[self._field], enrollment[self._field]['repository']
            if (selected['authenticatedCaller'] != caller or contract not in selected['grantRefs']
                    or repository is not None and (repo is None or repo['localName'] != repository)):
                continue
            if canonical_bytes(session.work_enrollment()) != raw or selected['localNode'] != self._node:
                raise ContractError('legacy_work_client_binding')
            if selected['localPeer'] is not None:
                fed = self._federation
                if (fed is None or selected['localPeer'] != fed.me or fed.node != self._node
                        or repo is not None and (fed.policy.rid_of(repo['localName']) != repo['repositoryId']
                            or repo['repositoryId'] is not None
                                and fed.policy.local_of(repo['repositoryId']) != repo['localName'])):
                    raise ContractError('legacy_work_client_binding')
            matches.append((session, enrollment))
        if not matches or repository is not None and len(matches) != 1:
            raise ContractError('legacy_work_route_unavailable')
        return matches

    @asynccontextmanager
    async def native_check_turn(self):
        """Drain signed exchanges before a short native check uses their DB worker."""
        acquired = []
        try:
            for lock in self._transport_locks.values():
                await lock.acquire()
                acquired.append(lock)
            # This interval grants no authority. Callers retain their original
            # deadlines and must join their DB job before releasing these locks.
            yield
        finally:
            for lock in reversed(acquired):
                lock.release()

    async def _call(self, session, contract, operation, payload, expires, *, include_valid_until=True,
                    _executor=None, _source_binding=False):
        # All work replies can carry rows. Keep the verified deadline private at
        # every call boundary, including mutation receipts and recovered results.
        source = getattr(self._hub, '_work_source_binding', None)
        if source is not None and not _source_binding:
            expires = await source.before_call(session, expires)
        async with self._transport_locks[id(session)]:
            expectation=None
            proof=None
            if source is not None:
                expectation=await source.expectation(session)
                if contract=='federation-work-inspect' and not _source_binding:
                    proof=source.request(secrets.token_hex(32))
                    payload={**payload,'input':{**payload['input'],'sourceBinding':proof}}
            reply=await self._exchange_command(session,contract,operation,payload,expires,
                _executor=_executor,source_expectation=expectation)
            if proof is not None:
                reply=await source.check_reply(session,proof,reply)
            return reply if include_valid_until else reply['result']

    async def _exchange_command(self,session,contract,operation,payload,expires,*,
                                _executor=None,source_expectation=None):
        source=getattr(self._hub,'_work_source_binding',None)
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        if self._closed or remaining <= 0 or contract not in WORK_COMMANDS:
            raise ContractError('legacy_work_client_expired')
        exchange = partial(session.work_command,
            contract_id=contract, operation_id=operation, payload=payload,
            expires_at=expires.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            deadline=time.monotonic() + min(5, remaining), include_valid_until=True,
            **({'source_expectation':source_expectation} if source_expectation is not None else {}))
        if _executor is None:
            worker = asyncio.create_task(asyncio.to_thread(exchange))
        else:
            worker = asyncio.ensure_future(asyncio.get_running_loop().run_in_executor(_executor, exchange))
        self._workers.add(worker)
        try:
            reply = await asyncio.shield(worker)
        except asyncio.CancelledError as cancelled:
            while not worker.done():
                try:
                    await asyncio.wait({worker})
                except asyncio.CancelledError:
                    continue
            if not worker.cancelled():
                worker.exception()
            raise cancelled
        finally:
            if worker.done():
                self._workers.discard(worker)
        if type(reply) is not dict or set(reply) != {'result', 'validUntil'}:
            raise ContractError('legacy_work_reply_unconfirmed')
        try:
            valid_until = datetime.fromisoformat(reply['validUntil'])
        except (ValueError, TypeError):
            raise ContractError('legacy_work_reply_unconfirmed') from None
        if valid_until.utcoffset() is None or valid_until > expires:
            raise ContractError('legacy_work_reply_unconfirmed')
        if datetime.now(timezone.utc) >= valid_until:
            raise ContractError('legacy_work_client_expired')
        if source is not None:
            source.check()
            await source._local()
            if datetime.now(timezone.utc) >= valid_until:
                raise ContractError('legacy_work_client_expired')
        return reply

    def _pending(self, key):
        self._check_store()
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
        if row is None:
            return None
        value = strict_loads(row['v'])
        if canonical_bytes(value).decode() != row['v']:
            raise ContractError('legacy_work_recovery_invalid')
        return self._checked_original(value)

    @staticmethod
    def _control_rejection(contract, payload, reply):
        """Only an authenticated work-control refusal is a terminal zero effect."""
        return (contract == 'federation-work-revoke' and type(payload) is dict
            and type(payload.get('input')) is dict and 'control' in payload['input']
            and type(reply) is dict and reply.get('outcome') == 'rejected'
            and canonical_bytes(reply.get('result')) == canonical_bytes({'cancelled': 0}))

    def _checked_original(self, value):
        fields = {'formatVersion', 'binding', 'intentDigest', 'contractId', 'operationId',
            'payload', 'originalDeadline', 'conflictReceipt'}
        if (type(value) is not dict or set(value) not in (fields, fields | {'confirmedReply'})
                or type(value['formatVersion']) is not int
                or value['formatVersion'] != 1 or value['contractId'] not in WORK_MUTATIONS):
            raise ContractError('legacy_work_recovery_invalid')
        try:
            deadline = datetime.fromisoformat(value['originalDeadline'])
        except (ValueError, TypeError):
            raise ContractError('legacy_work_recovery_invalid') from None
        if deadline.utcoffset() is None:
            raise ContractError('legacy_work_recovery_invalid')
        validate(value['contractId'], value['payload'])
        if 'confirmedReply' in value:
            reply = value['confirmedReply']
            if (type(reply) is not dict or set(reply) != {'outcome', 'receiptRef', 'resourceRef', 'result'}
                    or reply['outcome'] != 'applied'
                        and not self._control_rejection(value['contractId'], value['payload'], reply)):
                raise ContractError('legacy_work_recovery_invalid')
            validate('capability-storage-write-reply', {k: reply[k] for k in ('outcome', 'receiptRef', 'resourceRef')})
            self._reference(reply['resourceRef'], value['payload']['resourceRef'])
        return value

    async def _owned_db(self, function, *args, **kwargs):
        """Keep each original journal operation until its DB worker joins."""
        original = asyncio.create_task(self._hub.db(function, *args, **kwargs))
        self._workers.add(original)
        try:
            return await asyncio.shield(original)
        except asyncio.CancelledError:
            while not original.done():
                try:
                    await asyncio.wait({original})
                except asyncio.CancelledError:
                    continue
            if not original.cancelled():
                original.exception()
            raise
        finally:
            if original.done():
                self._workers.discard(original)

    async def pending_route(self, caller, command, intent_digest, *, repository=None):
        """Recover the original route before a caller selects different work."""
        contract = self._family + command
        if (contract not in WORK_MUTATIONS or type(intent_digest) is not str
                or re.fullmatch(r'sha256:[0-9a-f]{64}', intent_digest) is None):
            raise ContractError('legacy_work_recovery_invalid')
        routes = self._select(caller, command, repository)
        bindings = {canonical_bytes(self._binding(enrollment)): (session, enrollment)
            for session, enrollment in routes}
        def retained():
            self._check_store()
            rows = self._store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33',
                (self._state_prefix + '%',))
            if len(rows) > 32:
                raise ContractError('legacy_work_recovery_capacity')
            matches = []
            for row in rows:
                original = self._pending(row['k'])
                if (original['contractId'] != contract or original['intentDigest'] != intent_digest
                        or original['binding'][self._field]['authenticatedCaller'] != caller):
                    continue
                binding = canonical_bytes(original['binding'])
                if repository is not None and binding not in bindings:
                    raise ContractError('legacy_work_recovery_invalid')
                if original['conflictReceipt'] is not None:
                    continue
                expected = self._state_prefix + hashlib.sha256(canonical_bytes({
                    'binding': original['binding'], 'intentDigest': intent_digest,
                    'contractId': contract})).hexdigest()
                if row['k'] != expected or binding not in bindings:
                    raise ContractError('legacy_work_recovery_invalid')
                matches.append((binding, original['payload']['input']))
            if len(matches) > 1:
                raise ContractError('legacy_work_recovery_invalid')
            return matches[0] if matches else None
        task = asyncio.current_task()
        self._active.add(task)
        try:
            pending = await self._owned_db(retained)
            self.check(self._federation)
            if pending is None:
                return None
            binding, value = pending
            session, enrollment = bindings[binding]
            if canonical_bytes(session.work_enrollment()) != binding:
                raise ContractError('legacy_work_client_binding')
            return session, enrollment, value
        finally:
            self._active.discard(task)

    def _cleanup_confirmed(self):
        # Later caller adapters confirm only after their durable follow-on
        # transition. A successful reply alone cannot discard original intent.
        self._check_store()

    def _remember(self, routes, expires):
        task = asyncio.current_task()
        previous = self._disclosures.get(task)
        if previous is not None:
            routes, expires = (*previous[0], *routes), min(previous[1], expires)
        self._disclosures[task] = (tuple(routes), expires)

    def _disclose(self, value, routes, expires):
        self.check(self._federation)
        if datetime.now(timezone.utc) >= expires:
            raise ContractError('legacy_work_client_expired')
        for session, enrollment in routes:
            if session.work_enrollment() != enrollment:
                raise ContractError('legacy_work_client_binding')
            self._select(enrollment[self._field]['authenticatedCaller'], 'inspect',
                None if enrollment[self._field]['repository'] is None
                    else enrollment[self._field]['repository']['localName'])
        return value

    def confirm_disclosure(self, value=None):
        """Check all original reads without ending the aggregate or capture operation."""
        pending = self._disclosures.get(asyncio.current_task())
        if pending is None:
            raise ContractError('legacy_work_disclosure_unavailable')
        return self._disclose(value, *pending)

    def finish_disclosure(self, value=None):
        """Check and end an operation only at its final disclosure boundary.

        Caller adapters finish durable completion and intermediate capture checks
        first. Failed final checks retain the original minimum deadline; another
        read cannot silently turn an unfinished aggregate into a new operation.
        """
        result = self.confirm_disclosure(value)
        self._disclosures.pop(asyncio.current_task())
        return result

    def _rows(self, value, enrollment):
        repository = enrollment[self._field]['repository']
        if type(value) is list:
            for item in value:
                self._rows(item, enrollment)
        elif type(value) is dict:
            if ('repo' in value and repository is not None and value['repo'] != repository['localName']):
                raise ContractError('legacy_work_reply_unconfirmed')
            for item in value.values():
                if type(item) in (dict, list):
                    self._rows(item, enrollment)

    @asynccontextmanager
    async def _read_turn(self, routes):
        task = asyncio.current_task()
        self._active.add(task)
        try:
            maintenance = getattr(self._hub, '_work_maintenance', None)
            service_read = any(binding['workCommands']['authenticatedCaller'] == 'federation'
                               for _, binding in routes)
            async with (maintenance.observation_read_turn()
                        if maintenance is not None and service_read else nullcontext()):
                yield
        finally:
            self._active.discard(task)

    async def _read(self, routes, query, expires, *, include_deadline=False):
        async with self._read_turn(routes):
            # An already supplied deadline keeps its original bound while queued.
            return await self._read_current(routes, query, expires, include_deadline=include_deadline)

    async def _read_current(self, routes, query, expires, *, include_deadline=False):
        replies = []
        for session, enrollment in routes:
            reply = await self._call(session, self._family + 'read', 'work_read_' + secrets.token_hex(16),
                {'resourceRef': enrollment[self._field]['resourceRef'], 'input': {'query': query}}, expires)
            expires = min(expires, datetime.fromisoformat(reply['validUntil']))
            result = reply['result']
            if type(result) is not dict or set(result) != {'value'}:
                raise ContractError('legacy_work_reply_unconfirmed')
            self._rows(result['value'], enrollment)
            replies.append(result['value'])
        self._remember(routes, expires)
        self._disclose(None, routes, expires)
        if query['kind'] == 'readiness':
            # Readiness is one named repository's authorized target projection.
            # Callers combine explicit routes while retaining their deadlines.
            if len(replies) != 1:
                raise ContractError('legacy_work_reply_unconfirmed')
            value = replies[0]
            if (type(value) is not dict or set(value) != {'claimable', 'active', 'capacity'}
                    or any(type(value[key]) is not list
                        or any(type(row) is not dict for row in value[key]) for key in ('claimable', 'active'))
                    or type(value['capacity']) is not dict
                    or set(value['capacity']) != {'atCapacity', 'available'}
                    or type(value['capacity']['atCapacity']) is not bool
                    or type(value['capacity']['available']) is not int
                    or value['capacity']['available'] < 0
                    or value['capacity']['atCapacity'] != (value['capacity']['available'] == 0)):
                raise ContractError('legacy_work_reply_unconfirmed')
        elif query['kind'] == 'show':
            rows = [item for item in replies if item is not None]
            if len(rows) > 1 or rows and rows[0].get('id') != query['workId']:
                raise ContractError('legacy_work_reply_unconfirmed')
            value = rows[0] if rows else None
        else:
            if any(type(item) is not list for item in replies):
                raise ContractError('legacy_work_reply_unconfirmed')
            value = [row for items in replies for row in items]
            if len(canonical_bytes(value)) > 1_000_000:
                raise ContractError('legacy_work_reply_unconfirmed')
        return (value, expires) if include_deadline else value

    async def _execute(self, session, enrollment, command, intent_digest, value, attribution, expires,
                       *, stable_operation=None, recover_only=False):
        if type(recover_only) is not bool:
            raise ContractError('legacy_work_client_binding')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            return await self._execute_current(session, enrollment, command, intent_digest, value,
                attribution, expires, stable_operation=stable_operation, recover_only=recover_only)
        finally:
            self._active.discard(task)

    async def _execute_current(self, session, enrollment, command, intent_digest, value, attribution, expires,
                       *, stable_operation=None, recover_only=False):
        contract, binding = self._family + command, self._binding(enrollment)
        if contract not in WORK_MUTATIONS or attribution != enrollment[self._field]['authenticatedCaller']:
            raise ContractError('legacy_work_client_binding')
        key = self._state_prefix + hashlib.sha256(canonical_bytes({
            'binding': binding, 'intentDigest': intent_digest, 'contractId': contract})).hexdigest()
        async with self._locks[id(session)]:
            self.check(self._federation)
            await self._owned_db(self._check_pending_binding, binding, intent_digest, contract)
            original = await self._owned_db(self._pending, key)
            if recover_only and (original is None or original['conflictReceipt'] is not None):
                raise HubError('original work recovery is unavailable; no command was submitted')
            if original is not None and (original['binding'] != binding or original['intentDigest'] != intent_digest
                    or original['contractId'] != contract or original['payload']['input'] != value
                    or original['payload']['attribution'] != attribution):
                raise ContractError('legacy_work_recovery_invalid')
            selected = enrollment[self._field]
            inspected = await self._call(session, self._family + 'inspect', 'work_inspect_' + secrets.token_hex(16),
                {'resourceRef': selected['resourceRef'], 'input': {}}, expires)
            inspected_result = inspected['result']
            if type(inspected_result) is not dict or set(inspected_result) != {'resourceRef'}:
                raise ContractError('legacy_work_reply_unconfirmed')
            current = self._reference(inspected_result['resourceRef'], selected['resourceRef'])
            if original is None or original['conflictReceipt'] is not None:
                if original is not None:
                    validate('capability-storage-write-reply', original['conflictReceipt'])
                    if original['conflictReceipt']['outcome'] != 'conflict':
                        raise ContractError('legacy_work_recovery_invalid')
                fresh = {'formatVersion': 1, 'binding': binding, 'intentDigest': intent_digest, 'contractId': contract,
                    'operationId': stable_operation if original is None and stable_operation else 'work_' + secrets.token_hex(24),
                    'payload': {'resourceRef': current, 'input': value, 'attribution': attribution},
                    'originalDeadline': expires.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                    'conflictReceipt': None}
                validate(contract, fresh['payload'])
                if original is None:
                    await self._owned_db(self._retain, key, fresh)
                else:
                    await self._owned_db(self._replace, key, original, fresh)
                original = fresh
                reply = await self._call(session, contract, original['operationId'], original['payload'], expires)
            else:
                query = {'contractId': contract, 'operationId': original['operationId'],
                    'payloadDigest': payload_digest(original['payload'])}
                reply = await self._call(session, self._family + 'outcome', 'work_recover_' + secrets.token_hex(16),
                    {'resourceRef': current, 'input': query}, expires)
                outcome = reply['result']
                if type(outcome) is not dict or any(outcome.get(k) != v for k, v in query.items()):
                    raise ContractError('legacy_work_reply_unconfirmed')
                if outcome.get('outcome') == 'absent':
                    # Fresh query permission is never a renewal or evidence that
                    # the uncertain original effect may safely run a second time.
                    raise HubError('work outcome is unconfirmed; original recovery is retained')
            receipt = reply['result']
            if type(receipt) is not dict:
                raise ContractError('legacy_work_reply_unconfirmed')
            validate('capability-storage-write-reply', {k: receipt.get(k) for k in ('outcome', 'resourceRef', 'receiptRef')})
            self._reference(receipt['resourceRef'], selected['resourceRef'])
            if receipt['outcome'] == 'conflict':
                conflict = {k: receipt[k] for k in ('outcome', 'resourceRef', 'receiptRef')}
                await self._owned_db(self._replace, key, original, {**original, 'conflictReceipt': conflict})
                raise LegacyStorageConflict('work revision changed; retry the command')
            if ('result' not in receipt or receipt['outcome'] != 'applied'
                    and not self._control_rejection(contract, original['payload'], receipt)):
                raise ContractError('legacy_work_reply_unconfirmed')
            confirmed = {key: receipt[key] for key in ('outcome', 'receiptRef', 'resourceRef', 'result')}
            if 'confirmedReply' in original and original['confirmedReply'] != confirmed:
                raise ContractError('legacy_work_reply_unconfirmed')
            await self._owned_db(self._replace, key, original, {**original, 'confirmedReply': confirmed})
            result, expires = receipt['result'], min(expires, datetime.fromisoformat(reply['validUntil']))
            self._rows(result, enrollment)
            self._remember(((session, enrollment),), expires)
            return self._disclose(result, ((session, enrollment),), expires)

    async def confirm_completion(self, session, enrollment, command, intent_digest, result):
        """Forget a verified result after the caller's durable follow-on transition."""
        self.confirm_disclosure()
        contract, binding = self._family + command, self._binding(enrollment)
        key = self._state_prefix + hashlib.sha256(canonical_bytes({
            'binding': binding, 'intentDigest': intent_digest, 'contractId': contract})).hexdigest()
        async with self._locks[id(session)]:
            self._disclose(None, ((session, enrollment),), self._disclosures[asyncio.current_task()][1])
            def confirmed():
                original = self._pending(key)
                if (original is None or original['binding'] != binding or original['contractId'] != contract
                        or original['intentDigest'] != intent_digest
                        or original.get('confirmedReply', {}).get('outcome') != 'applied'
                        or canonical_bytes(original['confirmedReply']['result']) != canonical_bytes(result)):
                    raise ContractError('legacy_work_confirmation_unavailable')
                self._forget(key, original)
            await self._owned_db(confirmed)

    async def capture_source(self, completion, kind, row, expires):
        """Derive capture provenance from this exact verified pending receipt."""
        self.confirm_disclosure()
        if (type(completion) not in (tuple, list) or len(completion) != 5
                or kind not in ('work-released', 'fed-result') or type(row) is not dict):
            raise ContractError('legacy_work_capture_binding')
        session, enrollment, command, intent, expected = completion
        binding, contract = self._binding(enrollment), self._family + command
        if session.work_enrollment() != enrollment:
            raise ContractError('legacy_work_capture_binding')
        key = self._state_prefix + hashlib.sha256(canonical_bytes({
            'binding': binding, 'intentDigest': intent, 'contractId': contract})).hexdigest()
        original = await self._owned_db(self._pending, key)
        if (original is None or original['binding'] != binding or original['contractId'] != contract
                or original['intentDigest'] != intent or original['conflictReceipt'] is not None
                or original.get('confirmedReply', {}).get('outcome') != 'applied'
                or canonical_bytes(original['confirmedReply']['result']) != canonical_bytes(expected)):
            raise ContractError('legacy_work_capture_binding')
        if kind == 'work-released':
            matches = command == 'release' and canonical_bytes(expected) == canonical_bytes(row)
        else:
            matches = (command in ('result-envelope', 'approve', 'approve-privileged')
                and original['payload']['input']['envelope']['type'] == 'result'
                and expected.get('outcome') == 'delivered'
                and canonical_bytes(expected.get('work')) == canonical_bytes(row))
        if not matches:
            raise ContractError('legacy_work_capture_binding')
        # The receiving knowledge owner rechecks this retained work permission
        # under its fresh capture snapshot. Do not renew the caller deadline or
        # submit another work query merely to carry the already verified receipt.
        self.confirm_disclosure()
        receipt = original['confirmedReply']
        return ({'kind': kind, 'id': row['id'], 'digest': payload_digest(row),
            'resourceRef': receipt['resourceRef'], 'receiptRef': receipt['receiptRef'],
            'operationId': original['operationId'], 'payloadDigest': payload_digest(original['payload'])},
            min(expires, self._disclosures[asyncio.current_task()][1]))

    async def verify_completed_source(self, source, expires):
        """Read an exact completed owner result under fresh original permission."""
        task = asyncio.current_task()
        self._active.add(task)
        try:
            self.check(self._federation)
            source = self._checked_original(strict_loads(canonical_bytes(source)))
            if ('confirmedReply' not in source or source['conflictReceipt'] is not None
                    or source['confirmedReply']['outcome'] != 'applied'
                        and not self._control_rejection(source['contractId'], source['payload'], source['confirmedReply'])):
                raise ContractError('legacy_work_recovery_invalid')
            binding = source['binding']
            if type(binding) is not dict or type(binding.get(self._field)) is not dict:
                raise ContractError('legacy_work_recovery_invalid')
            selected = binding[self._field]
            repository = selected.get('repository')
            caller = selected.get('authenticatedCaller')
            command = source['contractId'][len(self._family):]
            matches = [(session, enrollment) for session, enrollment in self._select(caller, command,
                None if repository is None else repository['localName'])
                if self._binding(enrollment) == binding]
            if len(matches) != 1 or source['payload']['attribution'] != caller:
                raise ContractError('legacy_work_client_binding')
            session, enrollment = matches[0]
            async with self._locks[id(session)]:
                self.check(self._federation)
                inspected = await self._call(session, self._family + 'inspect',
                    'work_inspect_' + secrets.token_hex(16),
                    {'resourceRef': selected['resourceRef'], 'input': {}}, expires)
                expires = min(expires, datetime.fromisoformat(inspected['validUntil']))
                result = inspected['result']
                if type(result) is not dict or set(result) != {'resourceRef'}:
                    raise ContractError('legacy_work_reply_unconfirmed')
                current = self._reference(result['resourceRef'], selected['resourceRef'])
                query = {'contractId': source['contractId'], 'operationId': source['operationId'],
                    'payloadDigest': payload_digest(source['payload'])}
                reply = await self._call(session, self._family + 'outcome',
                    'work_recover_' + secrets.token_hex(16), {'resourceRef': current, 'input': query}, expires)
                outcome = reply['result']
                expected = {**query, **source['confirmedReply']}
                if canonical_bytes(outcome) != canonical_bytes(expected):
                    raise ContractError('legacy_work_reply_unconfirmed')
                expires = min(expires, datetime.fromisoformat(reply['validUntil']))
                value = outcome['result']
                self._rows(value, enrollment)
                self._remember(((session, enrollment),), expires)
                return self._disclose(value, ((session, enrollment),), expires)
        finally:
            self._active.discard(task)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('legacy_work_cleanup_invalid')
        self._closed = True
        if self._closing is None:
            async def finish():
                source = getattr(self._hub, '_work_source_binding', None)
                if source is not None and source.commands is self:
                    await source.close()
                await super(LegacyWorkCommandClient, self).close(timeout=None)
                self._disclosures.clear()
            self._closing = asyncio.create_task(finish())
        try:
            _, pending = await asyncio.wait({self._closing}, timeout=timeout)
            if pending:
                raise ContractError('legacy_work_cleanup_incomplete')
        except asyncio.CancelledError:
            while not self._closing.done():
                try:
                    await asyncio.wait({self._closing})
                except asyncio.CancelledError:
                    continue
            self._closing.result()
            raise
        self._closing.result()
