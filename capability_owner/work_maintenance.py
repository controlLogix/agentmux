"""Fixed Hub lifecycle calls over the retained, signed lifecycle client."""
import asyncio
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import secrets
import stat
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import names
from hub.store import HubError
from .work_lifecycle_client import WorkLifecycleClient


class _MaintenanceLock:
    """Allow one spawn admission ahead of queued work, then serve that work."""
    def __init__(self):
        self._held = False
        self._ordinary = deque()
        self._foreground = deque()
        self._ordinary_next = False

    def locked(self):
        return self._held

    async def acquire(self, *, foreground=False):
        future = asyncio.get_running_loop().create_future()
        queue = self._foreground if foreground else self._ordinary
        queue.append(future)
        self._grant()
        try:
            await future
        except BaseException:
            if not future.cancelled():
                # A grant owns the lock even before its task resumes.
                self.release()
            else:
                if future in queue:
                    queue.remove(future)
                self._grant()
            raise
        return True

    def _grant(self):
        if self._held:
            return
        for queue in (self._ordinary, self._foreground):
            while queue and queue[0].cancelled():
                queue.popleft()
        if self._ordinary and (self._ordinary_next or not self._foreground):
            queue = self._ordinary
            self._ordinary_next = False
        elif self._foreground:
            queue = self._foreground
            self._ordinary_next = bool(self._ordinary)
        else:
            return
        self._held = True
        queue.popleft().set_result(True)

    def release(self):
        if not self._held:
            raise RuntimeError('maintenance lock is not acquired')
        self._held = False
        self._grant()

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *_):
        self.release()


class HubWorkMaintenance:
    """Retain private trigger IDs; never infer a retry from changed arguments."""
    def __init__(self, hub, commands):
        self._hub, self._commands = hub, commands
        current = getattr(hub, '_work_lifecycle_client', None)
        if current is not None and (type(current) is not WorkLifecycleClient or current._commands is not commands):
            raise ContractError('work_maintenance_unavailable')
        self._client = current or WorkLifecycleClient(commands)
        self._profile = self._client._profile
        self._prefix = 'hub-work-maintenance:' + hashlib.sha256(canonical_bytes(self._profile)).hexdigest() + ':'
        self._requests = weakref.WeakKeyDictionary()
        self._last_operations = weakref.WeakKeyDictionary()
        self._result_validities = weakref.WeakKeyDictionary()
        self._lock, self._closed = _MaintenanceLock(), False
        self._turn_owner = None
        self._serialized_owner = None
        self._request_turn = None
        self._discovery_turn = None
        self._spawn_request_turn = None
        self._kill_admission_turn = None

    def __repr__(self):
        return '<HubWorkMaintenance private>'

    def _current(self):
        if self._closed or self._hub._work_maintenance is not self:
            raise ContractError('work_maintenance_unavailable')
        self._client._current()

    def _inside_turn(self, task):
        """Report whether this task already runs inside a held maintenance turn."""
        reserved = self._request_turn
        spawn = self._spawn_request_turn
        return (self._turn_owner is task or reserved is not None and reserved['child'] is task
                or spawn is not None and spawn['child'] is task)

    @asynccontextmanager
    async def _serialized(self):
        task = asyncio.current_task()
        if self._inside_turn(task):
            yield
        else:
            async with self._lock:
                self._serialized_owner = task
                try:
                    yield
                finally:
                    self._serialized_owner = None

    @asynccontextmanager
    async def adoption_request_turn(self, request):
        """Wait before authentication; retain only this connection's original child."""
        async with self._lock:
            self._current()
            reservation = {'owner': asyncio.current_task(), 'request': request, 'child': None}
            self._request_turn = reservation
            try:
                yield
            finally:
                # The connection joins its shielded lifecycle call before leaving.
                # Keep custody even if a later connection failure interrupts cleanup.
                child = reservation['child']
                cancelled = False
                while child is not None and not child.done():
                    try:
                        await asyncio.shield(child)
                    except asyncio.CancelledError:
                        cancelled = True
                    except Exception:
                        break
                self._request_turn = None
                if cancelled:
                    raise asyncio.CancelledError

    @asynccontextmanager
    async def spawn_request_turn(self, request):
        """Keep original preparation together, ending before physical dispatch."""
        await self._lock.acquire(foreground=True)
        reservation = {'owner': asyncio.current_task(), 'request': request, 'child': None,
                       'disclosure_only': False}
        self._spawn_request_turn = reservation
        try:
            self._current()
            yield
        finally:
            child = reservation['child']
            cancelled = False
            while child is not None and not child.done():
                try:
                    await asyncio.shield(child)
                except asyncio.CancelledError:
                    cancelled = True
                except Exception:
                    break
            self._release_spawn_turn(reservation)
            if cancelled:
                raise asyncio.CancelledError

    def _release_spawn_turn(self, reservation):
        if self._spawn_request_turn is reservation:
            self._spawn_request_turn = None
            self._lock.release()

    def retain_spawn_disclosure(self):
        reservation = self._spawn_request_turn
        if reservation is not None and reservation['child'] is asyncio.current_task():
            reservation['disclosure_only'] = True

    def release_spawn_preparation(self, *, original_finished=False):
        reservation = self._spawn_request_turn
        if reservation is not None and reservation['child'] is asyncio.current_task():
            if original_finished and reservation['disclosure_only']:
                return
            self._release_spawn_turn(reservation)

    def reserve_spawn_child(self, task):
        reservation = self._spawn_request_turn
        if reservation is None or reservation['owner'] is not asyncio.current_task():
            return
        request = self._requests.get(asyncio.current_task())
        if (request is None or request['verb'] != 'spawn' or reservation['child'] is not None
                or self._requests.get(task) != request
                or request['requestDigest'] != hashlib.sha256(reservation['request']).hexdigest()):
            raise HubError('authenticated spawn request does not match')
        reservation['child'] = task

    @asynccontextmanager
    async def kill_admission_turn(self, request):
        """Keep identity and the late source check together until admission."""
        await self._lock.acquire(foreground=True)
        reservation = {'owner': asyncio.current_task(), 'request': request,
                       'digest': hashlib.sha256(request).hexdigest()}
        self._kill_admission_turn = reservation
        try:
            self._current()
            yield
        finally:
            # Native, source and DB waits join their original work before this
            # parent unwinds. No kill child inherits this scheduling reservation.
            self._release_kill_admission(reservation)

    def _release_kill_admission(self, reservation):
        if self._kill_admission_turn is reservation:
            self._kill_admission_turn = None
            self._lock.release()

    @asynccontextmanager
    async def discovery_request_turn(self, request):
        """Keep one discovery request together without granting a worker child."""
        async with self._lock:
            self._current()
            self._discovery_turn = {'owner': asyncio.current_task(), 'request': request}
            try:
                yield
            finally:
                self._discovery_turn = None

    @asynccontextmanager
    async def native_check_turn(self, *, foreground=False):
        """Finish whole maintenance reads before draining their transport calls."""
        reserved = self._request_turn
        discovery = self._discovery_turn
        spawn = self._spawn_request_turn
        kill = self._kill_admission_turn
        if ((reserved is not None and reserved['owner'] is asyncio.current_task())
                or (spawn is not None and spawn['owner'] is asyncio.current_task())
                or (kill is not None and kill['owner'] is asyncio.current_task())
                or (discovery is not None and discovery['owner'] is asyncio.current_task())):
            # Adoption's connection already holds this lock before authentication.
            # This exact task may schedule a check; it gains no caller authority.
            self._current()
            yield
        elif foreground and not self._inside_turn(asyncio.current_task()):
            # Kill's final check and the selected-repository status precheck and
            # read use this short turn. A holder performs no Work exchange, physical termination
            # or callback while holding it, and joins its DB job before release.
            await self._lock.acquire(foreground=True)
            try:
                self._current()
                yield
            finally:
                self._lock.release()
        else:
            async with self.observation_read_turn():
                yield

    @asynccontextmanager
    async def source_read_turn(self):
        """Admit a whole new source read before it creates signed deadlines."""
        task = asyncio.current_task()
        reservations = (self._request_turn, self._spawn_request_turn, self._discovery_turn,
                        self._kill_admission_turn)
        if (self._turn_owner is task or self._serialized_owner is task
                or any(reservation is not None and
                (reservation['owner'] is task or reservation.get('child') is task)
                for reservation in reservations)):
            self._current()
            yield
        else:
            async with self.observation_read_turn():
                yield

    @asynccontextmanager
    async def observation_read_turn(self):
        """Keep service reads outside another task's active adoption turn."""
        async with self._serialized():
            self._current()
            yield

    @asynccontextmanager
    async def adoption_turn(self):
        async with self._serialized():
            self._current()
            task = asyncio.current_task()
            request = self._requests.get(task)
            if self._turn_owner is not None or request is None or request['verb'] != 'adopt':
                raise HubError('authenticated adoption request is unavailable')
            if time.monotonic() >= request['expires']:
                raise HubError('authenticated lifecycle request expired')
            # Only the original shielded task may reuse this turn. Background
            # tasks keep their place on the existing lock until it finishes.
            self._turn_owner = task
            try:
                yield
            finally:
                self._turn_owner = None

    async def admit(self, verb, arguments, caller):
        self._current()
        admitted = self._hub._consume_authenticated_caller(self._hub.current_authenticated_caller())
        reservation = self._request_turn
        spawn = self._spawn_request_turn
        kill = self._kill_admission_turn
        owns_kill = kill is not None and kill['owner'] is asyncio.current_task()
        if owns_kill and (verb != 'kill' or admitted.request != kill['request']
                or admitted.request_digest != kill['digest']):
            raise HubError('authenticated kill request does not match')
        if (spawn is not None and spawn['owner'] is asyncio.current_task()
                and admitted.request != spawn['request']):
            raise HubError('authenticated spawn request does not match')
        if (reservation is not None and reservation['owner'] is asyncio.current_task()
                and admitted.request != reservation['request']):
            raise HubError('authenticated lifecycle request does not match')
        request = json.loads(admitted.request)
        if (admitted.authenticated_caller != 'operator' or admitted.caller != caller
                or caller != 'operator' or request.get('verb') != verb
                or request.get('args', {}) != arguments):
            raise HubError('authenticated lifecycle request does not match')
        operation = request.get('operationId')
        if operation is not None and (type(operation) is not str or not operation
                or len(operation) > 128 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in operation)):
            raise HubError('invalid lifecycle operation ID')
        request = {
            'operationId': operation or secrets.token_hex(16), 'requestDigest': admitted.request_digest,
            'verb': verb, 'authenticatedCaller': admitted.authenticated_caller, 'caller': caller,
            'expires': admitted.expires_monotonic}
        await self._commands._owned_db(self._admit_request, request)
        self._requests[asyncio.current_task()] = request
        if owns_kill:
            session = arguments.get('session')
            if (session not in getattr(self._hub, 'terminating', ())
                    and session not in self._hub.rings):
                identities = [self._identity(phase, '') for phase in
                    ('kill-process', 'kill-metadata', 'kill-state-0', 'kill-state-1', 'kill-state-2')]
                completed = await self._commands._owned_db(self._completed_kill, session, identities)
                if completed is not None:
                    kill['completed'] = completed
                    kill['identities'] = identities
                    return
            # Release synchronously before dispatch can create physical work or
            # callbacks. A later connection may now own a different reservation.
            self._release_kill_admission(kill)

    def _admit_request(self, request):
        self._current()
        identity = {key: value for key, value in request.items() if key != 'expires'}
        key = self._prefix + 'request:' + hashlib.sha256(request['operationId'].encode()).hexdigest()
        with self._hub.store.tx():
            row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
            if row is not None and row['v'] != canonical_bytes(identity).decode():
                raise HubError('lifecycle operation ID belongs to a different original request')
            if row is None:
                self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                    (key, canonical_bytes(identity).decode()))

    def _identity(self, phase, trigger):
        request = self._requests.get(asyncio.current_task())
        if request is None:
            return {'trigger': trigger, 'phase': phase}
        return {key: value for key, value in request.items() if key != 'expires'} | {'phase': phase}

    def inherit(self, task):
        request = self._requests.get(asyncio.current_task())
        if request is not None:
            self._requests[task] = dict(request)

    def reserve_adoption_child(self, task):
        request = self._requests.get(asyncio.current_task())
        reservation = self._request_turn
        if (request is not None and request['verb'] == 'adopt' and reservation is not None
                and reservation['owner'] is asyncio.current_task()
                and reservation['child'] is None and self._requests.get(task) == request
                and request['requestDigest'] == hashlib.sha256(reservation['request']).hexdigest()):
            reservation['child'] = task

    def metadata_key(self, phase, trigger):
        return self._slot(self._identity(phase, trigger)) + ':metadata'

    def last_operation_id(self):
        return self._last_operations[asyncio.current_task()]

    async def confirm_operation(self, operation_id):
        self._current()
        return await self._client.confirm_disclosure(operation_id,
            expires=datetime.now(timezone.utc) + timedelta(seconds=5), finish=True)

    @staticmethod
    def _read_token(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or metadata.st_size > 4096):
                raise HubError('retained lifecycle token is unavailable')
            token = os.read(descriptor, 4097).decode().strip()
            if len(token) != 43 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in token):
                raise HubError('retained lifecycle token is unavailable')
            return token
        finally:
            os.close(descriptor)

    def _token(self, identity, final_path):
        from hub.server import HUBDIR
        self._current()
        key = self._slot(identity)
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
        record = None if row is None else strict_loads(row['v'])
        expected = None if record is None else record['intent']['tokenSha']
        directory = os.path.join(HUBDIR, 'work-tokens')
        os.makedirs(directory, mode=0o700, exist_ok=True)
        metadata = os.lstat(directory)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise HubError('retained lifecycle token is unavailable')
        path = os.path.join(directory, hashlib.sha256(key.encode()).hexdigest())
        for candidate in (path, final_path):
            try:
                token = self._read_token(candidate)
            except FileNotFoundError:
                continue
            if expected is None and candidate == path or expected == hashlib.sha256(token.encode()).hexdigest():
                return token, path
        if record is not None:
            raise HubError('original lifecycle token is unavailable; original operation is retained')
        token = secrets.token_urlsafe(32)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, (token + '\n').encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return token, path

    async def registration_token(self, session, final_path):
        identity = self._identity('register', 'register:' + session)
        try:
            return await self._commands._owned_db(self._token, identity, final_path)
        except (OSError, UnicodeError):
            raise HubError('retained lifecycle token is unavailable') from None

    async def token_installed(self, path, token):
        def remove():
            self._current()
            try:
                if self._read_token(path) != token:
                    raise HubError('retained lifecycle token changed')
                os.unlink(path)
            except FileNotFoundError:
                pass
        try:
            await self._commands._owned_db(remove)
        except (OSError, UnicodeError):
            raise HubError('retained lifecycle token cleanup is unavailable') from None

    def _phase(self, identity):
        self._current()
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._slot(identity),))
        if row is None:
            return None
        record = strict_loads(row['v'])
        if record['identity'] != identity:
            raise HubError('lifecycle operation ID belongs to a different original request')
        return record

    async def recover_phase(self, phase, trigger):
        async with self._serialized():
            identity = self._identity(phase, trigger)
            record = await self._commands._owned_db(self._phase, identity)
            if record is None:
                return False, None
            result = await self._client.execute(record['command'], record['arguments'],
                operation_id=record['operationId'], expires=datetime.now(timezone.utc) + timedelta(seconds=5))
            pending = self._commands._disclosures[asyncio.current_task()]
            await self._commands._owned_db(self._complete, record, pending)
            if phase in ('register', 'adopt-ready') and asyncio.current_task() in self._requests:
                self._retain_result_validity(pending)
            self._commands.finish_disclosure()
            self._last_operations[asyncio.current_task()] = record['operationId']
            return True, result

    def _local_phase(self, identity, *, new=False, result=None, state=None):
        self._current()
        key = self._slot(identity)
        with self._hub.store.tx():
            row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
            record = None if row is None else strict_loads(row['v'])
            if record is not None and record['identity'] != identity:
                raise HubError('lifecycle operation ID belongs to a different original request')
            if new and record is None:
                record = {'identity': identity, 'state': 'uncertain', 'result': None}
            elif state is None:
                return record
            if state is not None:
                if record is None:
                    raise ContractError('work_maintenance_recovery_invalid')
                if record['state'] == 'completed' and record['result'] != result:
                    raise ContractError('work_maintenance_recovery_invalid')
                record = {**record, 'state': state, 'result': result}
            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',
                (key, canonical_bytes(record).decode()))
            return None if new and row is None else record

    async def saved_result(self, verb):
        identity = self._identity(verb + '-result', verb)
        record = await self._commands._owned_db(self._local_phase, identity)
        return record if record is not None and record['state'] == 'completed' else None

    def _pending_recovery(self):
        self._current()
        records = []
        for row in self._hub.store.q('SELECT v FROM fed_state WHERE k LIKE ? AND json_valid(v) '
                "AND json_extract(v,'$.formatVersion')=1 AND json_extract(v,'$.completed')=0", (self._prefix + '%',)):
            record = strict_loads(row['v'])
            if record.get('command') not in ('register', 'state', 'sweep-global'):
                continue
            original = self._client._load(record['operationId'], record['command'], record['arguments'])
            if original is not None and original['state'] in ('uncertain', 'completed'):
                records.append(record)
                if len(records) == 32:
                    break
        return records

    async def recover_pending(self):
        """Query accepted original submissions; never dispatch a prepared effect."""
        async with self._serialized():
            for record in await self._commands._owned_db(self._pending_recovery):
                try:
                    result = await self._client.execute(record['command'], record['arguments'],
                        operation_id=record['operationId'], expires=datetime.now(timezone.utc) + timedelta(seconds=5))
                    pending = self._commands._disclosures[asyncio.current_task()]
                    await self._commands._owned_db(self._complete, record, pending)
                    self._commands.finish_disclosure(result)
                except Exception:
                    # One unavailable original cannot prevent another confirmed
                    # operation from retiring. Its exact request remains kept.
                    self._commands._disclosures.pop(asyncio.current_task(), None)

    async def save_result(self, verb, result):
        identity = self._identity(verb + '-result', verb)
        await self._commands._owned_db(self._local_phase, identity, new=True)
        await self._commands._owned_db(self._local_phase, identity, result=result, state='completed')

    def _retain_result_validity(self, pending):
        task = asyncio.current_task()
        previous = self._result_validities.get(task)
        self._result_validities[task] = pending if previous is None else (
            (*previous[0], *pending[0]), min(previous[1], pending[1]))

    async def confirm_result(self, verb, result):
        request = self._requests.get(asyncio.current_task())
        if request is None or request['verb'] != verb:
            raise HubError('authenticated lifecycle request is unavailable')
        remaining = request['expires'] - time.monotonic()
        if remaining <= 0:
            raise HubError('authenticated lifecycle request expired')
        expires = datetime.now(timezone.utc) + timedelta(seconds=min(5, remaining))
        original = self._result_validities.get(asyncio.current_task())
        if original is not None:
            self._commands._remember(*original)
        phases = [('register', 'register:' + result['session'])]
        if verb == 'adopt':
            phases.append(('adopt-ready', 'state:' + result['session']))
        async with self._serialized():
            records = []
            for phase, trigger in phases:
                record = await self._commands._owned_db(self._phase, self._identity(phase, trigger))
                if record is None or not record['completed']:
                    raise HubError('original lifecycle result is unavailable')
                records.append(record)
            # Confirm both original actions together under current authority.
            # Keep their minimum validity until the outer caller's final use.
            confirmed = await self._client.confirm_registration(records[0]['operationId'],
                ready_operation_id=None if verb == 'spawn' else records[1]['operationId'], expires=expires)
            if confirmed != result['session']:
                raise ContractError('work_maintenance_recovery_invalid')

    def finish_result(self, task, result):
        self._current()
        request = self._requests.get(asyncio.current_task())
        if request is None or self._requests.get(task) != request:
            raise HubError('authenticated lifecycle request is unavailable')
        if time.monotonic() >= request['expires']:
            raise HubError('authenticated lifecycle request expired')
        pending = self._commands._disclosures.get(task)
        if pending is None:
            raise ContractError('legacy_work_disclosure_unavailable')
        value = self._commands._disclose(result, *pending)
        self._commands._disclosures.pop(task)
        return value

    async def begin_spawn(self):
        identity = self._identity('spawn-process', 'spawn')
        record = await self._commands._owned_db(self._local_phase, identity, new=True)
        if record is not None and record['state'] != 'completed':
            raise HubError('original physical spawn is unconfirmed; it will not be repeated')
        return None if record is None else record['result']

    def _spawn_refusal_result(self, identity):
        registration = self._phase({**identity, 'phase': 'register'})
        if registration is None or registration.get('completed') is not True:
            raise ContractError('work_maintenance_recovery_invalid')
        arguments = registration['arguments']
        session = names.session_name(arguments['repo'], arguments['role'], arguments['agent'])
        generation = 1 if arguments['generation'] is None else arguments['generation'] + 1
        agent = self._hub.store.agent(session)
        if (agent is None or agent['generation'] != generation or agent['handle'] is not None
                or agent['pane_pid'] is not None or agent['token_sha'] != arguments['tokenSha']):
            raise ContractError('work_maintenance_recovery_invalid')
        return {'session': session, 'generation': generation, 'operationId': identity['operationId'],
            'outcome': 'not-started', 'reason': 'original-caller-expired'}

    def _retain_spawn_refusal(self, request):
        identity = {key: value for key, value in request.items() if key != 'expires'} | {
            'phase': 'spawn-process'}
        record = self._local_phase(identity)
        if record != {'identity': identity, 'state': 'uncertain', 'result': None}:
            raise ContractError('work_maintenance_recovery_invalid')
        result = self._spawn_refusal_result(identity)
        self._local_phase(identity, state='not-started', result=result)

    def _saved_spawn_refusal(self, identity):
        record = self._local_phase(identity)
        if record is None or record['state'] != 'not-started':
            return None
        result = self._spawn_refusal_result(identity)
        if record != {'identity': identity, 'state': 'not-started', 'result': result}:
            raise ContractError('work_maintenance_recovery_invalid')
        return result

    async def saved_spawn_refusal(self):
        return await self._commands._owned_db(self._saved_spawn_refusal,
            self._identity('spawn-process', 'spawn'))

    def spawn_request(self):
        self._current()
        request = self._requests.get(asyncio.current_task())
        if request is None or request['verb'] != 'spawn':
            raise HubError('authenticated spawn request is unavailable')
        return dict(request)

    def check_spawn_dispatch(self, request):
        # Keep source validation on the original worker. Check the original
        # caller deadline after IO queueing, immediately before process launch.
        self._hub.dbx.submit(self._current).result()
        if time.monotonic() >= request['expires']:
            # Only this original closure knows it has not invoked the process.
            # A failed save leaves uncertainty; recovery never launches this ID.
            self._hub.dbx.submit(self._retain_spawn_refusal, request).result()
            raise HubError('authenticated lifecycle request expired')

    async def finish_spawn(self, result):
        identity = self._identity('spawn-process', 'spawn')
        await self._commands._owned_db(self._local_phase, identity, result={
            'returncode': result.returncode, 'stdout': result.stdout[-400:], 'stderr': result.stderr[-400:]}, state='completed')

    def _kill_source(self):
        self._current()
        source = self._hub._work_source_binding
        source.check()
        return {'source': source.pin.read(), 'node': self._commands._node,
            'routesDigest': 'sha256:' + hashlib.sha256(canonical_bytes(
                [strict_loads(raw) for _, raw in self._commands._routes])).hexdigest()}

    @staticmethod
    def _kill_target(agent):
        return {key: agent[key] for key in ('session', 'handle', 'pane_pid', 'created', 'generation')} | {
            'term_name': agent.get('term_name') or agent['session']}

    def _kill_record(self, identity, target, *, create=False, deadline=None, confirm=None):
        source = self._kill_source()
        key = self._slot(identity)
        with self._hub.store.tx():
            row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
            record = None if row is None else strict_loads(row['v'])
            if record is not None:
                fields = {'formatVersion', 'identity', 'profile', 'source', 'target', 'effectDeadline', 'state'}
                if (type(record) is not dict or set(record) != fields or type(record['formatVersion']) is not int
                        or record['formatVersion'] != 1 or record['state'] not in ('uncertain', 'confirmed')
                        or canonical_bytes(record).decode() != row['v']):
                    raise ContractError('work_maintenance_recovery_invalid')
                if (record['identity'] != identity or record['profile'] != self._profile
                        or record['source'] != source or record['target'] != target):
                    raise HubError('original termination target or source changed')
                if record['effectDeadline'] is not None:
                    try:
                        expires = datetime.fromisoformat(record['effectDeadline'])
                    except (ValueError, TypeError):
                        raise ContractError('work_maintenance_recovery_invalid') from None
                    if expires.utcoffset() is None:
                        raise ContractError('work_maintenance_recovery_invalid')
            current = self._hub.store.agent(target['session'])
            if current is None or self._kill_target(current) != target:
                raise HubError('original termination target or source changed')
            if confirm is not None:
                if record != confirm or record['state'] != 'uncertain':
                    raise ContractError('work_maintenance_recovery_invalid')
                record = {**record, 'state': 'confirmed'}
                self._hub.store.db.execute('UPDATE fed_state SET v=? WHERE k=? AND v=?',
                    (canonical_bytes(record).decode(), key, canonical_bytes(confirm).decode()))
            elif create and record is None:
                record = {'formatVersion': 1, 'identity': identity, 'profile': self._profile,
                    'source': source, 'target': target, 'effectDeadline': deadline, 'state': 'uncertain'}
                self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                    (key, canonical_bytes(record).decode()))
                return record, True
            return record, False

    def _completed_kill(self, session, identities):
        """Read a fully completed original without creating or changing a phase."""
        self._current()
        agent = self._hub.store.agent(session)
        if agent is None:
            return None
        physical, _ = self._kill_record(identities[0], self._kill_target(agent))
        if physical is None or physical['state'] != 'confirmed':
            return None
        metadata = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?',
            (self._slot(identities[1]) + ':metadata',))
        if metadata is None:
            return None
        value = strict_loads(metadata['v'])
        if type(value) is not dict or set(value) != {'operationId'}:
            raise ContractError('work_maintenance_recovery_invalid')
        matches = []
        for identity in identities[2:]:
            phase = self._phase(identity)
            if phase is not None and phase.get('operationId') == value['operationId']:
                matches.append(phase)
        if len(matches) != 1:
            raise ContractError('work_maintenance_recovery_invalid')
        phase = matches[0]
        fields = {'formatVersion', 'identity', 'command', 'intent', 'arguments', 'operationId', 'completed'}
        if (set(phase) != fields or type(phase['formatVersion']) is not int or phase['formatVersion'] != 1
                or type(phase['completed']) is not bool or phase['command'] != 'state'):
            raise ContractError('work_maintenance_recovery_invalid')
        if not phase['completed']:
            return None
        args = phase['arguments']
        observation = args.get('observation', {})
        if (phase['intent'] != args or args.get('session') != session
                or args.get('generation') != agent['generation'] or args.get('state') != 'dead'
                or args.get('note') != 'killed by operator' or args.get('purpose') != 'hub-observation'
                or any(observation.get(key) != agent[column] for key, column in
                    (('handle', 'handle'), ('panePid', 'pane_pid'), ('created', 'created')))):
            raise ContractError('work_maintenance_recovery_invalid')
        lifecycle = self._client._load(phase['operationId'], 'state', args)
        if lifecycle is None or lifecycle['state'] != 'completed':
            return None
        if lifecycle['result'] is not True or agent['state'] != 'dead':
            raise ContractError('work_maintenance_recovery_invalid')
        return {'physical': physical, 'metadata': metadata['v'], 'phase': phase, 'lifecycle': lifecycle}

    async def confirm_completed_kill(self, agent):
        reservation = self._kill_admission_turn
        if (reservation is None or reservation['owner'] is not asyncio.current_task()
                or 'completed' not in reservation):
            return False
        session = agent['session']
        if session in getattr(self._hub, 'terminating', ()) or session in self._hub.rings:
            raise HubError('termination already in progress')
        expected = reservation['completed']
        current = await self._commands._owned_db(self._completed_kill, session, reservation['identities'])
        if current != expected or self._kill_target(agent) != expected['physical']['target']:
            raise ContractError('work_maintenance_recovery_invalid')
        remaining = self._requests[asyncio.current_task()]['expires'] - time.monotonic()
        if remaining <= 0:
            raise HubError('authenticated lifecycle request expired')
        expires = datetime.now(timezone.utc) + timedelta(seconds=remaining)
        pending = self._commands._disclosures.get(asyncio.current_task())
        if pending is not None:
            expires = min(expires, pending[1])
        result = await self._client.confirm_disclosure(expected['phase']['operationId'],
            expires=expires, finish=False)
        current = await self._commands._owned_db(self._completed_kill, session, reservation['identities'])
        if (result is not True or current != expected or session in self._hub.rings
                or session in getattr(self._hub, 'terminating', ())):
            raise ContractError('work_maintenance_recovery_invalid')
        return True

    async def begin_kill(self, agent, reason):
        trigger = 'kill:' + hashlib.sha256(canonical_bytes({'target': self._kill_target(agent), 'reason': reason})).hexdigest()
        identity = self._identity('kill-process', trigger)
        request = self._requests.get(asyncio.current_task())
        remaining = None if request is None else request['expires'] - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise HubError('authenticated lifecycle request expired')
        deadline = None if remaining is None else (datetime.now(timezone.utc) + timedelta(seconds=remaining)).isoformat()
        record, new = await self._commands._owned_db(self._kill_record, identity,
            self._kill_target(agent), create=True, deadline=deadline)
        if not new and record['state'] != 'confirmed':
            raise HubError('original physical termination is unconfirmed; it will not be repeated')
        return record, new, None if request is None else request['expires']

    def check_kill_dispatch(self, record, request_expires):
        # Run on the retained IO owner immediately before the existing harness.
        # The DB check uses the original worker; no replacement connection opens.
        current, _ = self._hub.dbx.submit(self._kill_record, record['identity'], record['target']).result()
        if current != record or current['state'] != 'uncertain':
            raise ContractError('work_maintenance_recovery_invalid')
        if request_expires is not None and time.monotonic() >= request_expires:
            raise HubError('authenticated lifecycle request expired')

    async def confirm_kill(self, record):
        await self._commands._owned_db(self._kill_record, record['identity'], record['target'], confirm=record)

    def _slot(self, identity):
        # An external ID is unique within its profile. A different request with
        # that ID must conflict rather than acquire another recovery record.
        key = ({'operationId': identity['operationId'], 'phase': identity['phase']}
            if 'operationId' in identity else identity)
        return self._prefix + hashlib.sha256(canonical_bytes(key)).hexdigest()

    def _prepare(self, identity, command, intent, *, repeat):
        self._current()
        key = self._slot(identity)
        with self._hub.store.tx():
            row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
            if row is not None:
                record = strict_loads(row['v'])
                if (type(record) is not dict or set(record) != {'formatVersion', 'identity', 'command',
                        'intent', 'arguments', 'operationId', 'completed'} or record['formatVersion'] != 1
                        or type(record['completed']) is not bool
                        or canonical_bytes(record).decode() != row['v']):
                    raise ContractError('work_maintenance_recovery_invalid')
                if (record['identity'] != identity or record['command'] != command
                        or record['intent'] != intent):
                    if 'operationId' in identity or not record['completed']:
                        raise HubError('original lifecycle request is retained; changed input cannot recover it')
                elif not repeat or 'operationId' in identity or not record['completed']:
                    return record
            arguments = dict(intent)
            if command == 'register':
                session = names.session_name(intent['repo'], intent['role'], intent['agent'])
                current = self._hub.store.agent(session)
                arguments['generation'] = None if current is None else current['generation']
            record = {'formatVersion': 1, 'identity': identity, 'command': command,
                'intent': intent, 'arguments': arguments, 'operationId': 'lifecycle_' + secrets.token_hex(16), 'completed': False}
            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',
                (key, canonical_bytes(record).decode()))
            return record

    def _complete(self, record, pending):
        self._current()
        self._commands._disclose(None, *pending)
        key = self._slot(record['identity'])
        with self._hub.store.tx():
            current = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
            if current is None or strict_loads(current['v']) != record:
                raise ContractError('work_maintenance_recovery_invalid')
            self._hub.store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                (canonical_bytes({**record, 'completed': True}).decode(), key))
            self._commands._disclose(None, *pending)

    async def _execute(self, command, intent, *, phase, trigger, repeat=False):
        self._current()
        intent = strict_loads(canonical_bytes(intent))
        async with self._serialized():
            identity = self._identity(phase, trigger)
            record = await self._commands._owned_db(self._prepare, identity, command, intent, repeat=repeat)
            expires = datetime.now(timezone.utc) + timedelta(seconds=5)
            request = self._requests.get(asyncio.current_task())
            # Registration precedes the physical launch. Its user request must
            # still be live; later observed cleanup uses its own service grant.
            if command == 'register' and request is not None:
                remaining = request['expires'] - time.monotonic()
                if remaining <= 0:
                    raise HubError('authenticated lifecycle request expired')
                expires = min(expires, datetime.now(timezone.utc) + timedelta(seconds=remaining))
            result = await self._client.execute(command, record['arguments'],
                operation_id=record['operationId'], expires=expires)
            pending = self._commands._disclosures[asyncio.current_task()]
            await self._commands._owned_db(self._complete, record, pending)
            if phase in ('register', 'adopt-ready') and request is not None:
                self._retain_result_validity(pending)
            self._commands.finish_disclosure()
            self._last_operations[asyncio.current_task()] = record['operationId']
            return result, record

    async def register(self, repo, role, agent, cli, snapshot, *, transport='tmux', handle=None,
                       pane_pid=None, legacy=None, token_sha=None):
        result, record = await self._execute('register', {'repo': repo, 'role': role, 'agent': agent,
            'cli': cli, 'roleSnapshot': snapshot, 'transport': transport, 'handle': handle,
            'panePid': pane_pid, 'legacy': legacy, 'tokenSha': token_sha},
            phase='register', trigger='register:' + names.session_name(repo, role, agent), repeat=True)
        previous = record['arguments']['generation']
        return result, 1 if previous is None else previous + 1

    async def state(self, agent, state, note=None, *, observation=True, phase='state'):
        arguments = {'session': agent['session'], 'generation': agent['generation'], 'state': state, 'note': note}
        if observation:
            arguments.update(purpose='hub-observation', observation={
                'handle': agent['handle'], 'panePid': agent['pane_pid'],
                'created': agent['created'], 'state': agent['state']})
        result, _ = await self._execute('state', arguments, phase=phase,
            trigger='state:' + agent['session'] + ':' + str(agent['generation']), repeat=True)
        return result

    async def sweep(self):
        result, _ = await self._execute('sweep-global', {}, phase='sweep', trigger='sweep', repeat=True)
        return result

    async def close(self):
        if not self._closed:
            if asyncio.current_task() in getattr(self._hub, 'kills', ()):
                raise ContractError('work_maintenance_unavailable')
            await self._hub.finish_kills()
            # The lifecycle client joins original calls before its borrowed
            # command client, Hub Store and executor may close.
            await self._client.close()
            self._closed = True
