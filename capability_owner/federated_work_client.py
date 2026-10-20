"""Federation callers for the retained, signed work command boundary."""
import asyncio
from contextvars import ContextVar
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import hashlib
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.store import HubError
from hub import names
from hub.fed import envelope, guard, ledger
from hub.fed.message_bridge import MessageBridgeIntents, MessageIntent
from .legacy_work_client import LegacyWorkCommandClient


class WorkBridgeIntents(MessageBridgeIntents):
    """Reuse the actual receive and held-row approval proof, with work routes."""
    def __init__(self, federation, client):
        from hub.fed.runtime import Federation
        if (type(federation) is not Federation or type(client) is not FederatedWorkCommandClient
                or client._federation is not federation):
            raise ContractError('legacy_work_intent_configuration')
        self._federation, self._client = federation, client
        self._pending = weakref.WeakKeyDictionary()
        self._current = ContextVar('legacy_work_intent', default=None)


    @asynccontextmanager
    async def control(self, subject, item, message):
        """Retain the actual callback candidate; only owner proof permits withdrawal."""
        from nats.aio.msg import Msg
        from identity.peer_control import HEADER
        from hub.fed.peer_control import HEADER_REPOSITORY
        session, fed = self._session(), self._federation
        subscription = getattr(fed.nc, '_subs', {}).get(getattr(message, '_sid', None))
        owned = session._resources.get(id(subscription))
        plane, peer, _ = envelope.validate_route(subject, item)
        headers = message.headers or {}
        repository_id = headers.get(HEADER_REPOSITORY)
        if (type(message) is not Msg or message._client is not fed.nc or message.subject != subject
                or canonical_bytes(strict_loads(message.data)) != canonical_bytes(item)
                or subscription is None or owned is None or owned[1] is not subscription
                or getattr(subscription, '_closed', True)
                or asyncio.current_task() is not subscription._wait_for_msgs_task
                or plane != 'ctl' or item['type'] != 'revoke' or peer == fed.me
                or item['rid'] is not None or item['to'] != '*'
                or type(headers.get(HEADER)) is not str or type(repository_id) is not str):
            raise ContractError('legacy_work_control_unavailable')
        repo = fed.policy.local_of(repository_id)
        if repo is None:
            raise ContractError('legacy_work_control_unavailable')
        _, enrollment = self._client._route('federation', 'revoke', repo)
        selector = {'eventId': item['id'], 'eventDigest': payload_digest(item), 'subject': subject,
            'signature': headers[HEADER], 'repositoryId': repository_id}
        with self._retain({'command': 'revoke', 'peer': peer, 'control': selector,
                'binding': self._client._client._binding(enrollment)}, session=session, connection=fed.nc):
            yield

    def consume_control(self, peer):
        proof = self._current.get()
        retained = self._pending.pop(proof, None) if type(proof) is MessageIntent else None
        if retained is None or time.monotonic() >= retained.expires_monotonic:
            raise ContractError('legacy_work_control_unavailable')
        value = strict_loads(retained.content)
        if (value.get('command') != 'revoke' or value['peer'] != peer
                or self._session() is not retained.transport_session
                or self._federation.nc is not retained.transport_connection):
            raise ContractError('legacy_work_control_unavailable')
        return retained


class FederatedWorkCommandClient:
    """A host-private adapter; the shared client owns transport and recovery."""
    def __init__(self, federation, client):
        from hub.fed.runtime import Federation
        if (type(federation) is not Federation or type(client) is not LegacyWorkCommandClient
                or client._hub is not federation.hub):
            raise ContractError('legacy_work_client_configuration')
        self._federation, self._client = federation, client
        self._hub = federation.hub
        self._sessions = weakref.WeakKeyDictionary()
        self._received = weakref.WeakKeyDictionary()
        client.bind(federation)
        self._control_locks = {id(session): asyncio.Lock() for session, _ in client._routes}

    def check(self, federation=None):
        fed = self._federation
        if federation is not None and federation is not fed:
            raise ContractError('legacy_work_client_binding')
        self._client.check(fed)
        pending = self._sessions.get(asyncio.current_task())
        if pending is not None and fed.session is not pending[0]:
            raise ContractError('legacy_work_client_unavailable')
        if fed.session is not None:
            fed.session.check_open()

    def _begin(self):
        self.check()
        self._sessions.setdefault(asyncio.current_task(), (self._federation.session,))

    @staticmethod
    async def _joined(awaitable):
        original = asyncio.create_task(awaitable)
        cancelled = None
        while not original.done():
            try:
                await asyncio.shield(original)
            except asyncio.CancelledError as exc:
                cancelled = exc
            except BaseException:
                # Retrieve the original result below, including a child failure
                # that arrives after the caller was already cancelled.
                break
        try:
            result = original.result()
        except BaseException:
            if cancelled is not None:
                raise cancelled
            raise
        if cancelled is not None:
            raise cancelled
        return result

    def confirm_disclosure(self, value=None):
        self.check()
        return self._client.confirm_disclosure(value)

    def finish_disclosure(self, value=None):
        self.check()
        result = self._client.finish_disclosure(value)
        self._sessions.pop(asyncio.current_task(), None)
        return result

    def _route(self, caller, command, repo):
        self.check()
        return self._client._select(caller, command, repo)[0]

    def intent_binding(self, command, item):
        repo = self._federation.policy.local_of(item['rid'])
        if repo is None:
            raise ContractError('legacy_work_route_unavailable')
        if command == 'deliver':
            command = {'work': 'ingest', 'work_claim': 'claim-envelope',
                'work_grant': 'grant-envelope', 'result': 'result-envelope'}[item['type']]
            caller = 'federation'
        else:
            # The proof records the exact approval flag separately. Both current
            # approval routes must belong to this same authenticated operator.
            caller = 'operator'
        _, enrollment = self._route(caller, command, repo)
        return self._client._binding(enrollment)

    def _caller(self, caller, verbs, *, panel=False):
        self._begin()
        admitted = self._hub._consume_authenticated_caller(self._hub.current_authenticated_caller(),
            **({'purpose': 'panel-work'} if panel else {}))
        request = strict_loads(admitted.request)
        if admitted.caller != caller or request.get('verb') not in verbs:
            raise ContractError('legacy_work_caller_binding')
        remaining = admitted.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise ContractError('legacy_work_client_expired')
        return admitted, request, datetime.now(timezone.utc) + timedelta(seconds=min(5, remaining))

    async def _mutate(self, caller, command, repo, value, intent, expires):
        session, enrollment = self._route(caller, command, repo)
        result = await self._client._execute(session, enrollment, command, intent, value, caller, expires)
        return result, (session, enrollment, command, intent, result)

    async def add(self, caller, to, title, body=None, task_key=None, requirements=None, priority=100):
        admitted, request, expires = self._caller(caller, {'fed_work_add', 'work_add'})
        args = request.get('args', {})
        expected = {'target': to, 'title': title, 'body': body, 'taskKey': task_key,
            'requirements': requirements, 'priority': priority}
        actual = {'target': args.get('to'), 'title': args.get('title'), 'body': args.get('body'),
            'taskKey': args.get('task_key'),
            'requirements': {'capabilities': args['require']} if args.get('require') else args.get('requirements'),
            'priority': int(args.get('priority') or 100)}
        if actual != expected:
            raise ContractError('legacy_work_caller_binding')
        address = names.parse_address(to)
        if address.kind != 'role' or address.scope == '*' or address.scope.startswith(('group:', 'team:')):
            raise HubError('a federated item targets role:<repo>/<role>')
        result, _ = await self._mutate(admitted.authenticated_caller, 'offer', address.scope,
            expected, admitted.request_digest, expires)
        return self.confirm_disclosure(result)

    def _receive_intent(self, item, decision):
        self._begin()
        admitted = self._federation._work_intents.consume(item, decision)
        proof = strict_loads(admitted.content)
        command = ({'work': 'ingest', 'work_claim': 'claim-envelope', 'work_grant': 'grant-envelope',
            'result': 'result-envelope'}[item['type']] if proof['command'] == 'deliver' else
            'approve-privileged' if proof['privileged'] else 'approve')
        caller = 'federation' if proof['command'] == 'deliver' else 'operator'
        repo = self._federation.policy.local_of(item['rid'])
        session, enrollment = self._route(caller, command, repo)
        if self._client._binding(enrollment) != proof['binding']:
            raise ContractError('legacy_work_intent_binding')
        value = {'envelope': item, 'subject': proof['subject'], 'localNode': self._federation.node}
        if caller == 'operator':
            value['quarantineId'] = proof['quarantineId']
        intent = payload_digest(value)
        return admitted, command, caller, session, enrollment, value, intent

    async def receive(self, item, decision):
        admitted, command, caller, session, enrollment, value, intent = self._receive_intent(item, decision)
        result = await self._client._execute(session, enrollment, command, intent, value,
            caller, admitted.valid_until)
        self._received[asyncio.current_task()] = (item, value.get('quarantineId'),
            (session, enrollment, command, intent, result))
        row = result.get('work')
        if item['type'] == 'result' and row is not None and result.get('outcome') == 'delivered':
            self.confirm_disclosure(row)
            await self._hub._notify_work_owner(row, row['claimed_by'])
            self.confirm_disclosure(row)
            await self._federation.local_event('fed_result', {**row, 'from_peer': item['from']},
                require_completion=True)
            self.confirm_disclosure(row)
        return self.confirm_disclosure(result)['outcome']

    async def capture_source(self, data):
        """Use only the exact owner result retained by this receive task."""
        self.confirm_disclosure()
        pending = self._received.get(asyncio.current_task())
        if pending is None:
            raise ContractError('legacy_work_capture_binding')
        item, _, completion = pending
        result = completion[4]
        row = result.get('work')
        if (item['type'] != 'result' or result.get('outcome') != 'delivered'
                or type(row) is not dict
                or canonical_bytes(data) != canonical_bytes({**row, 'from_peer': item['from']})):
            raise ContractError('legacy_work_capture_binding')
        source = await self._client.capture_source(completion, 'fed-result', row,
            self._client._disclosures[asyncio.current_task()][1])
        self.confirm_disclosure(row)
        return source

    async def confirm_seen(self, item, decision):
        """Release an exact retained receipt after its durable follow-on exists."""
        admitted, command, caller, session, enrollment, value, intent = self._receive_intent(item, decision)
        if caller != 'federation':
            raise ContractError('legacy_work_confirmation_unavailable')
        if not await self._joined(self._hub.db(ledger.seen, self._hub.store, item['id'])):
            raise ContractError('legacy_work_confirmation_unavailable')
        pending = await self._client.pending_route(caller, command, intent)
        self.check()
        if (time.monotonic() >= admitted.expires_monotonic
                or self._federation.session is not admitted.transport_session
                or self._federation.nc is not admitted.transport_connection):
            raise ContractError('legacy_work_client_unavailable')
        if pending is None:
            return False
        retained_session, retained_enrollment, retained_value = pending
        if (retained_session is not session or retained_enrollment != enrollment or retained_value != value):
            raise ContractError('legacy_work_confirmation_unavailable')
        # Existing pending intent selects recovery only. An absent owner outcome
        # remains uncertain; the shared client must never submit another effect.
        result = await self._client._execute(session, enrollment, command, intent, value,
            caller, admitted.valid_until, recover_only=True)
        self._received[asyncio.current_task()] = (item, None,
            (session, enrollment, command, intent, result))
        await self.confirm_receive(item)
        return True

    async def confirm_receive(self, item, *, quarantine_id=None, privileged=False):
        self.check()
        pending = self._received.get(asyncio.current_task())
        if (pending is None or pending[:2] != (item, quarantine_id)
                or quarantine_id is not None and (pending[2][2] == 'approve-privileged') != privileged):
            raise ContractError('legacy_work_confirmation_unavailable')
        self.confirm_disclosure()

        original_session = self._federation.session
        def completed():
            self._client.check(self._federation)
            if self._federation.session is not original_session:
                raise ContractError('legacy_work_client_unavailable')
            if quarantine_id is None:
                if not ledger.seen(self._hub.store, item['id']):
                    raise ContractError('legacy_work_confirmation_unavailable')
            else:
                held = ledger.quarantine_get(self._hub.store, quarantine_id)
                if held is None or held['state'] != 'approved' or held['envelope'] != item:
                    raise ContractError('legacy_work_confirmation_unavailable')
        await self._joined(self._hub.db(completed))
        await self._client.confirm_completion(*pending[2])
        self._received.pop(asyncio.current_task(), None)
        self.confirm_disclosure()

    async def recover_approved(self, held, caller):
        """Recover the original held-row effect after its approved follow-on."""
        admitted, request, expires = self._caller(caller, {'fed_approve'})
        args = request.get('args', {})
        if (caller != 'operator' or admitted.authenticated_caller != 'operator'
                or held['state'] != 'approved' or set(args) - {'id', 'privileged'}
                or args.get('id') != held['id'] or type(args.get('privileged', False)) is not bool):
            raise ContractError('legacy_work_confirmation_unavailable')
        command = 'approve-privileged' if args.get('privileged', False) else 'approve'
        item = held['envelope']
        repo = self._federation.policy.local_of(item['rid'])
        session, enrollment = self._route('operator', command, repo)
        value = {'envelope': item, 'subject': held['subject'], 'localNode': self._federation.node,
            'quarantineId': held['id']}
        intent = payload_digest(value)
        pending = await self._client.pending_route('operator', command, intent)
        if pending is None:
            raise HubError('the approved item has no retained operation to recover')
        if pending != (session, enrollment, value):
            raise ContractError('legacy_work_confirmation_unavailable')
        result = await self._client._execute(session, enrollment, command, intent, value,
            'operator', expires, recover_only=True)
        self._received[asyncio.current_task()] = (item, held['id'],
            (session, enrollment, command, intent, result))
        return self.confirm_disclosure(result)['outcome']

    async def read(self, caller, *, panel=False):
        admitted, request, expires = self._caller(caller, {'fed_panel' if panel else 'fed_work_list'}, panel=panel)
        if not panel and request.get('args', {}):
            raise ContractError('legacy_work_caller_binding')
        rows = await self._client._read(self._client._select(admitted.authenticated_caller, 'read'),
            {'kind': 'federated'}, expires)
        rows.sort(key=lambda row: row['updated'], reverse=True)
        rows = rows[:50]
        return self.confirm_disclosure(self.panel_value(rows) if panel else rows)

    @staticmethod
    def panel_value(rows):
        return {'title': 'Federated work', 'columns': ['id', 'title', 'state', 'from / by', 'task_key', 'result'],
            'rows': [[r['id'], r['title'], r['state'],
                f"from {r['origin_peer']}" if r['origin_peer'] else r['claimed_by'] or '',
                r['task_key'] or '', (r['result'] or '')[:80]] for r in rows]}

    async def service_read(self, query, *, repo=None):
        self._begin()
        expires = datetime.now(timezone.utc) + timedelta(seconds=5)
        return await self._client._read(self._client._select('federation', 'read', repo), query, expires)

    async def service_readiness(self, target_session, *, repo):
        """Read a target's bounded capacity using the enrolled service grant."""
        value = await self.service_read({'kind': 'readiness', 'session': target_session}, repo=repo)
        return self.confirm_disclosure(value)

    def service_repositories(self):
        """Enumerate only current named repositories with enrolled read grants."""
        self.check()
        return frozenset(enrollment['workCommands']['repository']['localName']
            for _, enrollment in self._client._select('federation', 'read')
            if enrollment['workCommands']['repository'] is not None)

    async def stage_result(self, row):
        self.check()
        result, completion = await self._mutate('federation', 'stage-result', row['repo'], {'workId': row['id']},
            payload_digest({'stageResult': row['id']}), datetime.now(timezone.utc) + timedelta(seconds=5))
        self.confirm_disclosure()
        await self._client.confirm_completion(*completion)
        return self.confirm_disclosure(result)

    async def recover_results(self):
        await self.recover_controls()
        rows = await self.service_read({'kind': 'list', 'state': None})
        for row in rows:
            flags = json.loads(row.get('fed_flags') or '{}')
            if row.get('origin_peer') and row['state'] in ('done', 'failed') and flags.get('result_pending') and flags.get('grant_id'):
                self.confirm_disclosure(row)
                try:
                    await self.stage_result(row)
                except Exception as exc:
                    self._federation.log('fed: result remains pending', row['id'], type(exc).__name__)
        return self.finish_disclosure()

    async def local_event(self, kind, row):
        if kind == 'work_released' and row and row.get('origin_peer'):
            # Resolve the current raw row through the owner, not event content.
            rows = await self.service_read({'kind': 'list', 'state': None}, repo=row['repo'])
            current = next((r for r in rows if r['id'] == row['id']), None)
            if current is None:
                raise ContractError('legacy_work_reply_unconfirmed')
            await self.stage_result(current)
            self.finish_disclosure()

    def _control_key(self, binding, value):
        logical = {**self._client._logical_route(binding),
            'resourceRef': binding['workCommands']['resourceRef'], 'control': value}
        return 'legacy-work-control:' + hashlib.sha256(canonical_bytes(logical)).hexdigest()

    def _load_control(self, enrollment, value):
        self._client._check_store()
        binding = self._client._binding(enrollment)
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._control_key(binding, value),))
        if row is None:
            return None
        source = self._client._checked_original(strict_loads(row['v']))
        if (canonical_bytes(source).decode() != row['v'] or source['binding'] != binding
                or source['contractId'] != 'federation-work-revoke'
                or source['payload']['input'] != value or source['payload']['attribution'] != 'federation'
                or source['intentDigest'] != payload_digest(value)
                or source['conflictReceipt'] is not None or 'confirmedReply' not in source):
            raise ContractError('legacy_work_control_binding')
        return source

    async def _control_revoke(self, session, enrollment, value, expires, *, recover_only=False):
        original = asyncio.current_task()
        self._client._workers.add(original)
        try:
            return await self._control_revoke_current(session, enrollment, value, expires,
                recover_only=recover_only)
        finally:
            self._client._workers.discard(original)

    async def _control_revoke_current(self, session, enrollment, value, expires, *, recover_only=False):
        self._begin()
        binding, intent = self._client._binding(enrollment), payload_digest(value)
        async with self._control_locks[id(session)]:
            source = await self._client._owned_db(self._load_control, enrollment, value)
            self.check()
            if source is not None:
                result = await self._client.verify_completed_source(source, expires)
            else:
                operation = 'work_control_' + hashlib.sha256(canonical_bytes({
                    'route': self._client._logical_route(binding),
                    'resourceRef': binding['workCommands']['resourceRef'], 'control': value})).hexdigest()
                result = await self._client._execute(session, enrollment, 'revoke', intent, value,
                    'federation', expires, stable_operation=operation, recover_only=recover_only)
                self.confirm_disclosure(result)
                async with self._client._locks[id(session)]:
                    def archive():
                        self._client._check_store()
                        key = self._client._state_prefix + hashlib.sha256(canonical_bytes({
                            'binding': binding, 'intentDigest': intent,
                            'contractId': 'federation-work-revoke'})).hexdigest()
                        with self._hub.store.tx():
                            original = self._client._pending(key)
                            if (original is None or original['binding'] != binding
                                    or original['payload']['input'] != value
                                    or original.get('confirmedReply', {}).get('outcome') != 'applied'
                                        and not self._client._control_rejection(original['contractId'],
                                            original['payload'], original.get('confirmedReply'))
                                    or canonical_bytes(original['confirmedReply']['result']) != canonical_bytes(result)):
                                raise ContractError('legacy_work_control_unconfirmed')
                            completed_key = self._control_key(binding, value)
                            previous = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (completed_key,))
                            raw = canonical_bytes(original)
                            if previous is not None and previous['v'] != raw.decode():
                                raise ContractError('legacy_work_control_unconfirmed')
                            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) '
                                'ON CONFLICT(k) DO UPDATE SET v=excluded.v', (completed_key, raw.decode()))
                            self._client._forget(key, original)
                    await self._client._owned_db(archive)
            return self.finish_disclosure(result)

    async def recover_controls(self):
        """Query retained self-revoke outcomes without submitting another effect."""
        self.check()
        def pending():
            self._client._check_store()
            rows = self._hub.store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33',
                (self._client._state_prefix + '%',))
            if len(rows) > 32:
                raise ContractError('legacy_work_recovery_capacity')
            originals = [self._client._pending(row['k']) for row in rows]
            return [original for original in originals
                if original['contractId'] == 'federation-work-revoke'
                and 'control' in original['payload']['input']]
        for original in await self._client._owned_db(pending):
            binding = original['binding']
            selected = binding['workCommands']['repository']
            session, enrollment = self._route('federation', 'revoke', selected['localName'])
            if self._client._binding(enrollment) != binding:
                raise ContractError('legacy_work_control_binding')
            await self._joined(self._control_revoke(session, enrollment, original['payload']['input'],
                datetime.now(timezone.utc) + timedelta(seconds=5), recover_only=True))

    async def revoke(self, peer):
        self.check()
        intents = self._federation._work_intents
        if intents._current.get() is not None:
            admitted = intents.consume_control(peer)
            intent = strict_loads(admitted.content)
            repo = self._federation.policy.local_of(intent['control']['repositoryId'])
            session, enrollment = self._route('federation', 'revoke', repo)
            if self._client._binding(enrollment) != intent['binding']:
                raise ContractError('legacy_work_control_binding')
            return await self._joined(self._control_revoke(session, enrollment,
                {'peer': peer, 'control': intent['control']}, admitted.valid_until))
        # No control proof means only the existing current local deny/removal path.
        routes = self._client._select('federation', 'revoke')
        total = 0
        for session, enrollment in routes:
            value = {'peer': peer}
            intent = payload_digest(value)
            result = await self._client._execute(session, enrollment, 'revoke', intent, value,
                'federation', datetime.now(timezone.utc) + timedelta(seconds=5))
            self.confirm_disclosure(result)
            await self._client.confirm_completion(session, enrollment, 'revoke', intent, result)
            total += result['cancelled']
        self.finish_disclosure()
        self._federation.log(f'fed: cancelled {total} unclaimed item(s) from {peer}')
