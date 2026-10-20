"""Retain legacy core-NATS result notices across failed posts and restarts."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import re
import weakref

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.store import HubError
from .legacy_work_client import LegacyWorkCommandClient


# The suffix is preserved display text; signed owner reads supply authority.
_ATTRIBUTION = re.compile(r'nats:[a-z0-9_]{1,32}:[\s\S]*\Z')
_ROW_FIELDS = ('id', 'repo', 'title', 'state', 'result', 'created_by', 'parent_id', 'claimed_by')
_FIELDS = {'formatVersion', 'profile', 'binding', 'work', 'body', 'targets'}


class LegacyWorkNotifications:
    """Use fixed signed service reads and the Hub's current recipient fence."""
    def __init__(self, hub, commands):
        from hub.server import Hub
        if type(hub) is not Hub or type(commands) is not LegacyWorkCommandClient or commands._hub is not hub:
            raise ContractError('legacy_work_notice_configuration')
        self._hub, self._commands = hub, commands
        profiles = {tuple(strict_loads(raw)[key] for key in ('hubId', 'profileId', 'authorityId'))
            for _, raw in commands._routes}
        if len(profiles) != 1:
            raise ContractError('legacy_work_notice_configuration')
        self._profile = dict(zip(('hubId', 'profileId', 'authorityId'), next(iter(profiles))))
        self._prefix = 'legacy-work-notice:' + hashlib.sha256(canonical_bytes(self._profile)).hexdigest() + ':'
        self._closed, self._lock, self._pending = False, asyncio.Lock(), set()
        self._current()

    def __repr__(self):
        return '<LegacyWorkNotifications private>'

    def _current(self):
        if self._closed or self._hub._work_storage_commands is not self._commands:
            raise ContractError('legacy_work_notice_unavailable')
        self._commands.check(self._commands._federation)

    @staticmethod
    def _candidate(row):
        return (type(row) is dict and row.get('state') in ('done', 'failed')
            and type(row.get('claimed_by')) is str and _ATTRIBUTION.fullmatch(row['claimed_by']) is not None)

    def _key(self, work):
        return self._prefix + hashlib.sha256(canonical_bytes([work['id'], work['state']])).hexdigest()

    @staticmethod
    def _body(work):
        body = f"work {work['id']} \"{work['title']}\" is {work['state']} (by {work['claimed_by']})"
        if work['result']:
            body += f"\nresult: {work['result']}"
        return body

    def _validate(self, record):
        if (type(record) is not dict or set(record) != _FIELDS or type(record['formatVersion']) is not int
                or record['formatVersion'] != 1 or record['profile'] != self._profile
                or type(record['work']) is not dict or set(record['work']) != set(_ROW_FIELDS)
                or not self._candidate(record['work']) or record['body'] != self._body(record['work'])
                or type(record['targets']) is not list or len(record['targets']) > 256
                or len(canonical_bytes(record)) > 1048576):
            raise ContractError('legacy_work_notice_recovery_invalid')
        seen = set()
        for target in record['targets']:
            if (type(target) is not dict or set(target) != {'target', 'generation', 'state', 'messageId'}
                    or type(target['target']) is not str or not target['target']
                    or len(target['target']) > 300 or target['target'] in seen
                    or target['state'] not in ('pending', 'completed')
                    or (target['state'] == 'pending') != (target['messageId'] is None)
                    or target['state'] == 'completed' and (type(target['messageId']) is not str or not target['messageId'])
                    or target['generation'] is not None and (not target['target'].startswith('agent:')
                        or type(target['generation']) is not int
                        or not 1 <= target['generation'] <= 9007199254740991)
                    or target['state'] == 'completed' and not target['target'].startswith('virtual:')
                        and (not target['target'].startswith('agent:') or target['generation'] is None)):
                raise ContractError('legacy_work_notice_recovery_invalid')
            seen.add(target['target'])
        return record

    def _load(self, work):
        self._current()
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(work),))
        if row is None:
            return None
        record = self._validate(strict_loads(row['v']))
        if canonical_bytes(record).decode() != row['v']:
            raise ContractError('legacy_work_notice_recovery_invalid')
        return record

    def _guard(self, pending):
        self._current()
        self._commands._disclose(None, *pending)

    def _reserve(self, record, pending):
        self._guard(pending)
        with self._hub.store.tx():
            original = self._load(record['work'])
            if original is not None:
                return original
            self._validate(record)
            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                (self._key(record['work']), canonical_bytes(record).decode()))
            self._guard(pending)
        return record

    @staticmethod
    def _idempotency(record, target):
        work = record['work']
        return f"result:{work['id']}:{work['state']}:{target['target']}"

    def _reconcile(self, record, target, pending):
        """An exact durable old post can complete even after its recipient leaves."""
        self._guard(pending)
        with self._hub.store.tx():
            original = self._load(record['work'])
            if original != record:
                raise ContractError('legacy_work_notice_recovery_invalid')
            message = self._hub.store.q1('SELECT * FROM messages WHERE sender=? AND idem_key=?',
                ('virtual:hub', self._idempotency(record, target)))
            if message is None:
                return record, False
            work = record['work']
            if (any(message[key] != value for key, value in (
                    ('target', target['target']), ('kind', 'result'), ('body', record['body']),
                    ('ref', work['id']), ('work_id', work['id'])))
                    or self._hub.store._recips_of(message['id']) != [
                        target['target'][6:] if target['target'].startswith('agent:') else target['target']]):
                raise ContractError('legacy_work_notice_recovery_invalid')
            updated = {**record, 'targets': [{**entry, 'state': 'completed', 'messageId': message['id']}
                if entry['target'] == target['target'] else entry for entry in record['targets']]}
            self._validate(updated)
            self._hub.store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                (canonical_bytes(updated).decode(), self._key(work)))
            self._guard(pending)
            return updated, True

    async def _read(self, repository, work_id=None):
        routes = self._commands._select('federation', 'read', repository)
        named = [route for route in routes if route[1]['workCommands']['repository'] is not None]
        if named:
            routes = named
        query = {'kind': 'list', 'state': None} if work_id is None else {'kind': 'show', 'workId': work_id}
        previous = self._commands._disclosures.get(asyncio.current_task())
        async with self._commands._read_turn(routes):
            expires = datetime.now(timezone.utc) + timedelta(seconds=5)
            if previous is not None:
                self._commands.confirm_disclosure()
                expires = min(expires, previous[1])
            result = await self._commands._read_current(routes, query, expires)
        return self._commands.confirm_disclosure(result), routes

    async def _recipients(self, work):
        targets = set()
        unresolved = set()
        if work['created_by'] and work['created_by'] != 'agent:' + work['claimed_by']:
            targets.add(work['created_by'])
        if work['parent_id']:
            try:
                rows, _ = await self._read(None)
                parents = [row for row in rows if row['id'] == work['parent_id']]
                if len(parents) != 1:
                    raise HubError('parent notice authority is unavailable')
                parent = parents[0]
                if parent.get('claimed_by') and parent['claimed_by'] != work['claimed_by']:
                    targets.add('agent:' + parent['claimed_by'])
            except Exception:
                self._commands.confirm_disclosure()
                # Keep the original unresolved relationship; later reassignment
                # cannot supply a different first recipient for this notice.
                unresolved.add('work-parent:' + work['parent_id'])
        result = {target: None for target in unresolved}
        for target in sorted(targets):
            if target.startswith('peer:'):
                continue
            try:
                selected, resolution = await self._hub._current_identity_target(target)
                self._commands.confirm_disclosure()
                if selected.startswith('virtual:'):
                    result[selected] = None
                    continue
                bindings = self._hub._identity_bindings(resolution)
                if bindings:
                    registrations = [(binding.canonical_session, binding.registration_generation) for binding in bindings]
                else:
                    registrations = [(entry.canonical_session, entry.generation) for entry in
                        await self._commands._owned_db(self._hub.store.recipient_registrations, selected)]
            except Exception:
                self._commands.confirm_disclosure()
                # Record an intended recipient without claiming identity admission.
                # A retained original generation can be retried through the normal
                # current fence; an unknown incarnation never binds a future agent.
                selected = target
                generation = None
                try:
                    selected = await self._commands._owned_db(self._hub.store.canonical_target,
                        target, self._hub.virtual_names())
                    if selected.startswith('agent:'):
                        agent = await self._commands._owned_db(self._hub.store.agent, selected[6:])
                        if agent is not None:
                            generation = agent['generation']
                except HubError:
                    pass
                result[selected] = generation
                continue
            self._commands.confirm_disclosure()
            for session, generation in registrations:
                if 'agent:' + session in result and result['agent:' + session] != generation:
                    raise ContractError('legacy_work_notice_recovery_invalid')
                result['agent:' + session] = generation
        return [{'target': target, 'generation': generation, 'state': 'pending', 'messageId': None}
            for target, generation in sorted(result.items())]

    async def _one(self, work_id, repository):
        self._current()
        task = asyncio.current_task()
        try:
            async with self._lock:
                row, routes = await self._read(repository, work_id)
                if not self._candidate(row):
                    self._commands.finish_disclosure()
                    return False
                work = {key: row.get(key) for key in _ROW_FIELDS}
                binding = [self._commands._binding(enrollment) for _, enrollment in routes]
                record = await self._commands._owned_db(self._load, work)
                if record is None:
                    targets = await self._recipients(work)
                    pending = self._commands._disclosures[task]
                    record = await self._commands._owned_db(self._reserve,
                        {'formatVersion': 1, 'profile': self._profile, 'binding': binding,
                            'work': work, 'body': self._body(work), 'targets': targets}, pending)
                if record['work'] != work or record['binding'] != binding:
                    raise ContractError('legacy_work_notice_recovery_invalid')
                for target in tuple(record['targets']):
                    if target['state'] == 'completed':
                        continue
                    pending = self._commands._disclosures[task]
                    record, completed = await self._commands._owned_db(self._reconcile, record, target, pending)
                    if completed:
                        continue
                    if target['generation'] is None and not target['target'].startswith('virtual:'):
                        continue
                    if target['generation'] is not None:
                        if not hasattr(self._hub, '_work_read_targets'):
                            self._hub._work_read_targets = weakref.WeakKeyDictionary()
                        self._hub._work_read_targets.setdefault(task, {})[target['target'][6:]] = target['generation']
                    try:
                        await self._hub._post_current('virtual:hub', target['target'], 'result', record['body'],
                            work['id'], work['id'], self._idempotency(record, target), _work_reply=True)
                        self._commands.confirm_disclosure()
                        pending = self._commands._disclosures[task]
                        record, completed = await self._commands._owned_db(self._reconcile, record, target, pending)
                        if not completed:
                            raise HubError('legacy result notice remains unconfirmed')
                    except Exception:
                        # A failed target remains retained while independent targets proceed.
                        self._commands.confirm_disclosure()
                    finally:
                        getattr(self._hub, '_work_read_targets', {}).pop(task, None)
                self._commands.finish_disclosure()
                return all(target['state'] == 'completed' for target in record['targets'])
        finally:
            # End this failed attempt; a later retry must obtain new signed reads.
            self._commands._disclosures.pop(task, None)
            getattr(self._hub, '_work_read_targets', {}).pop(task, None)

    async def _joined(self, awaitable):
        original = asyncio.create_task(awaitable)
        self._pending.add(original)
        cancelled = None
        try:
            while not original.done():
                try:
                    await asyncio.shield(original)
                except asyncio.CancelledError as error:
                    cancelled = error
            result = original.result()
            if cancelled is not None:
                raise cancelled
            return result
        finally:
            if original.done():
                self._pending.discard(original)

    async def notify(self, work_id, repository):
        return await self._joined(self._one(work_id, repository))

    async def poll(self):
        return await self._joined(self._poll())

    async def _poll(self):
        self._current()
        try:
            rows, _ = await self._read(None)
            candidates = [(row['id'], row['repo']) for row in rows if self._candidate(row)]
            self._commands.finish_disclosure()
        finally:
            self._commands._disclosures.pop(asyncio.current_task(), None)
        result = {'completed': 0, 'pending': 0}
        for work_id, repository in candidates:
            try:
                completed = await self.notify(work_id, repository)
            except Exception:
                completed = False
            result['completed' if completed else 'pending'] += 1
        return result

    async def close(self):
        self._closed = True
        for task in tuple(self._pending):
            task.cancel()
        while self._pending:
            originals = tuple(self._pending)
            try:
                done, _ = await asyncio.wait(originals)
                for task in done:
                    if not task.cancelled():
                        task.exception()
                    self._pending.discard(task)
            except asyncio.CancelledError:
                continue
