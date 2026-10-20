"""Qualified legacy knowledge commands retain original intents and typed replies."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import math
import secrets
import time

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.fed import envelope, ledger
from hub.store import HubError
from .legacy_messages_client import LegacyMessageCommandClient, LegacyStorageConflict


class LegacyKnowledgeCommandClient(LegacyMessageCommandClient):
    _field, _family, _state_prefix = 'knowledgeCommands', 'federation-knowledge-', 'legacy-knowledge-client:'
    _enrollment_method, _command_method = 'knowledge_enrollment', 'knowledge_command'
    _completed_commands = frozenset(('share', 'capture', 'withdraw'))

    def __init__(self, hub, sessions):
        super().__init__(hub, sessions)
        self._receipt_capture_locks = {id(session): asyncio.Lock() for session, _ in self._routes}

    def __repr__(self):
        return '<LegacyKnowledgeCommandClient private>'

    def _route_key(self, enrollment):
        selected = enrollment[self._field]
        return (selected['authenticatedCaller'], canonical_bytes(enrollment['scope']),
            selected['repository']['repositoryId'])

    @staticmethod
    def _logical_route(binding):
        selected = binding['knowledgeCommands']
        return {**{key: binding[key] for key in ('hubId', 'scope')},
            **{key: selected[key] for key in ('authenticatedCaller', 'localPeer', 'repository')}}

    def _select(self, caller, command, repo=None):
        self.check(self._federation)
        matched = []
        for session, raw in self._routes:
            enrollment = strict_loads(raw)
            selected = enrollment[self._field]
            repository = selected['repository']
            if selected['authenticatedCaller'] != caller or repo is not None and repository['localName'] != repo:
                continue
            if self._family + command not in selected['grantRefs']:
                continue
            if (canonical_bytes(session.knowledge_enrollment()) != raw or selected['localPeer'] != self._federation.me
                    or selected['localNode'] != self._federation.node
                    or self._federation.policy.rid_of(repository['localName']) != repository['repositoryId']
                    or self._federation.policy.local_of(repository['repositoryId']) != repository['localName']):
                raise ContractError('legacy_knowledge_client_binding')
            matched.append((session, enrollment))
        if not matched or repo is not None and len(matched) != 1:
            raise ContractError('legacy_knowledge_route_unavailable')
        return matched

    def intent_binding(self, command, item):
        repo = self._federation.policy.local_of(item['rid'])
        if repo is None:
            raise ContractError('legacy_knowledge_route_unavailable')
        _, enrollment = self._select('operator' if command == 'approve' else 'federation', command, repo)[0]
        return self._binding(enrollment)

    def _check_result(self, command, original, receipt, result):
        selected = original['binding'][self._field]
        if command == 'share':
            if (set(result) != {'id', 'redacted', 'repo', 'title'}
                    or result['id'] != original['payload']['input']['envelope']['id']
                    or result['repo'] != selected['repository']['localName'] or type(result['title']) is not str
                    or type(result['redacted']) is not list or any(type(v) is not str for v in result['redacted'])):
                raise ContractError('legacy_knowledge_reply_unconfirmed')
        elif command in ('index', 'approve'):
            if (set(result) != {'id', 'outcome'} or result['id'] != original['payload']['input']['envelope']['id']
                    or result['outcome'] != 'delivered'):
                raise ContractError('legacy_knowledge_reply_unconfirmed')
        elif command == 'capture':
            if type(result.get('captured')) is not bool:
                raise ContractError('legacy_knowledge_reply_unconfirmed')
            if not result['captured']:
                if set(result) != {'captured', 'id'} or result['id'] is not None:
                    raise ContractError('legacy_knowledge_reply_unconfirmed')
            elif (set(result) != {'captured', 'id', 'redacted', 'repo', 'title'}
                    or type(result['id']) is not str or not result['id']
                    or result['repo'] != selected['repository']['localName'] or type(result['title']) is not str
                    or type(result['redacted']) is not list or any(type(v) is not str for v in result['redacted'])):
                raise ContractError('legacy_knowledge_reply_unconfirmed')
        elif command == 'withdraw':
            if set(result) != {'withdrawn'} or type(result['withdrawn']) is not int or result['withdrawn'] < 0:
                raise ContractError('legacy_knowledge_reply_unconfirmed')
        else:
            raise ContractError('legacy_knowledge_reply_unconfirmed')

    def _cleanup_confirmed(self):
        self._check_store()
        rows = self._hub.store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33', (self._state_prefix + '%',))
        if len(rows) > 32:
            raise ContractError('legacy_knowledge_recovery_capacity')
        for row in rows:
            original = self._pending(row['k'])
            if original['contractId'] == self._family + 'index' and ledger.seen(
                    self._hub.store, original['payload']['input']['envelope']['id']):
                self._forget(row['k'], original)
            elif original['contractId'] == self._family + 'approve':
                value = original['payload']['input']
                held = ledger.quarantine_get(self._hub.store, value['quarantineId'])
                if held is not None and held['state'] == 'approved' and held['envelope'] == value['envelope']:
                    self._forget(row['k'], original)

    async def confirm_receive(self, item, *, quarantine_id=None, privileged=False):
        self.check(self._federation)
        def confirm():
            if quarantine_id is None:
                if not ledger.seen(self._hub.store, item['id']):
                    raise ContractError('legacy_knowledge_confirmation_unavailable')
            else:
                held = ledger.quarantine_get(self._hub.store, quarantine_id)
                if held is None or held['state'] != 'approved' or held['envelope'] != item:
                    raise ContractError('legacy_knowledge_confirmation_unavailable')
            self._cleanup_confirmed()
        await self._hub.db(confirm)

    def _caller(self, caller, verbs):
        self.check(self._federation)
        proof = self._hub.current_authenticated_caller()
        admitted = self._hub._consume_authenticated_caller(proof,
            **({'purpose': 'panel-knowledge'} if verbs == {'fed_panel'} else {}))
        request = strict_loads(admitted.request)
        if (admitted.caller != caller or request.get('verb') not in verbs
                or type(request.get('args', {})) is not dict):
            raise ContractError('legacy_knowledge_caller_binding')
        remaining = admitted.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise ContractError('legacy_knowledge_client_expired')
        return admitted, request, datetime.now(timezone.utc) + timedelta(seconds=min(5, remaining))

    async def share(self, caller, repo, title, body, tags=(), reference=None, source='explicit'):
        if source != 'explicit':
            return await self.capture(caller, repo, title, body, tags, reference, source)
        admitted, request, expires = self._caller(caller, {'fed_knowledge_share'})
        args = request.get('args', {})
        expected_repo = args.get('repo') or self._federation.sender_of(caller).get('repo')
        expected_tags = args.get('tags') or []
        if isinstance(expected_tags, str):
            expected_tags = [expected_tags]
        if (expected_repo != repo or args.get('title') != title or args.get('body') != body
                or expected_tags != list(tags) or args.get('ref') != reference):
            raise ContractError('legacy_knowledge_caller_binding')
        session, enrollment = self._select(admitted.authenticated_caller, 'share', repo)[0]
        sender = self._federation.sender_of(caller)
        author = 'operator' if sender.get('operator') else f"{sender['role']}/{sender['agent']}"
        item = envelope.make('knowledge', self._federation.me, self._federation.node,
            enrollment[self._field]['repository']['repositoryId'], '*',
            {'title': title, 'body': body, 'tags': list(tags), 'ref': reference, 'author': author, 'source': 'explicit'})
        task = asyncio.current_task()
        self._active.add(task)
        try:
            return await self._execute(session, enrollment, 'share', payload_digest(request),
                {'envelope': item}, caller, expires)
        finally:
            self._active.discard(task)

    async def receive(self, item, decision):
        self.check(self._federation)
        admitted = self._federation._knowledge_intents.consume_inbound(item, decision)
        intent = strict_loads(admitted.content)
        command = intent['command']
        caller = 'operator' if command == 'approve' else 'federation'
        session, enrollment = self._select(caller, command, decision.local_repo)[0]
        binding = self._binding(enrollment)
        if intent['binding'] != binding:
            raise ContractError('legacy_knowledge_intent_binding')
        value = {'envelope': item, 'subject': intent['subject'], 'localNode': self._federation.node}
        if command == 'approve':
            value.update(quarantineId=intent['quarantineId'], privileged=intent['privileged'])
        task = asyncio.current_task()
        self._active.add(task)
        try:
            operation = 'legacy_knowledge_' + hashlib.sha256(canonical_bytes({'binding': binding,
                'envelopeId': item['id'], 'quarantineId': intent.get('quarantineId')})).hexdigest()
            result = await self._execute(session, enrollment, command, payload_digest(value), value,
                caller, admitted.valid_until, stable_operation=operation)
            return result['outcome']
        finally:
            self._active.discard(task)

    async def capture(self, caller, repo, title, body, tags, reference, source):
        self.check(self._federation)
        admitted = self._federation._knowledge_intents.consume_event(caller, repo, title, body, tags, reference, source)
        intent = strict_loads(admitted.content)
        session, enrollment = self._select('federation', 'capture', repo)[0]
        if intent['binding'] != self._binding(enrollment):
            raise ContractError('legacy_knowledge_intent_binding')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            value = {'source': intent['source']}
            result = await self._capture_original(session, enrollment, value, admitted.valid_until)
            return {key: result[key] for key in ('id', 'repo', 'title', 'redacted')} if result['captured'] else None
        finally:
            self._active.discard(task)

    async def _capture_original(self, session, enrollment, value, expires, *, recover_only=False):
        if 'resourceRef' in value['source']:
            async with self._receipt_capture_locks[id(session)]:
                await self._hub.db(self._restore_capture, enrollment, value)
                return await self._capture_execute(session, enrollment, value, expires, recover_only=recover_only)
        return await self._capture_execute(session, enrollment, value, expires, recover_only=recover_only)

    async def _capture_execute(self, session, enrollment, value, expires, *, recover_only=False):
        try:
            return await self._execute(session, enrollment, 'capture', payload_digest(value), value,
                'federation', expires, recover_only=recover_only)
        except LegacyStorageConflict:
            # The initial retained selection may predate other findings. Only
            # this verified no-effect receipt permits one immediate fresh
            # attempt, with the exact original source and unchanged deadline.
            return await self._execute(session, enrollment, 'capture', payload_digest(value), value,
                'federation', expires, recover_only=recover_only)

    async def withdraw(self, peer):
        self.check(self._federation)
        intents = self._federation._knowledge_intents
        if intents._current.get() is not None:
            admitted = intents.consume_control(peer)
            intent = strict_loads(admitted.content)
            repo = self._federation.policy.local_of(intent['control']['repositoryId'])
            session, enrollment = self._select('federation', 'withdraw', repo)[0]
            if self._binding(enrollment) != intent['binding']:
                raise ContractError('legacy_knowledge_control_binding')
            task = asyncio.create_task(self._control_execute(session, enrollment,
                {'peer': peer, 'control': intent['control']}, admitted.valid_until))
            self._workers.add(task)
            def finished(done):
                self._workers.discard(done)
                if not done.cancelled():
                    done.exception()
            task.add_done_callback(finished)
            return await asyncio.shield(task)
        # The owner checks that the peer is currently denied or removed before
        # changing only the selected repository's retained rows.
        task = asyncio.current_task()
        self._active.add(task)
        try:
            for session, enrollment in self._select('federation', 'withdraw'):
                value = {'peer': peer}
                await self._execute(session, enrollment, 'withdraw', payload_digest(value), value,
                    'federation', datetime.now(timezone.utc) + timedelta(seconds=5))
        finally:
            self._active.discard(task)

    def _control_key(self, binding, value):
        selected = binding[self._field]
        logical = {**self._logical_route(binding), 'resourceId': selected['resourceRef']['id'],
            'resourceHubId': selected['resourceRef']['ownerHubId'], 'control': value}
        return 'legacy-knowledge-control:' + hashlib.sha256(canonical_bytes(logical)).hexdigest()

    def _forget(self, key, original):
        if (original['contractId'] == self._family + 'capture'
                and original['payload']['input']['source']['kind'] in ('work-released', 'fed-result')
                and 'resourceRef' in original['payload']['input']['source']):
            self._check_store()
            archive = self._capture_key(original['binding'], original['payload']['input'])
            with self._hub.store.tx():
                if self._pending(key) != original:
                    raise ContractError('legacy_knowledge_recovery_conflict')
                previous = self._pending(archive)
                if previous is not None and previous != original:
                    raise ContractError('legacy_knowledge_recovery_conflict')
                self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) '
                    'ON CONFLICT(k) DO UPDATE SET v=excluded.v', (archive, canonical_bytes(original).decode()))
                self._hub.store.db.execute('DELETE FROM fed_state WHERE k=?', (key,))
            return
        if (original['contractId'] == self._family + 'capture'
                and original['payload']['input']['source']['kind'] == 'handoff'
                and getattr(self._federation, '_qualified_code', False)):
            if self._federation._code_commands._retain_handoff_capture(original['payload']['input']['source']):
                # The existing recovery loop retires this same confirmed capture
                # after the original code/message group commits. Until then a
                # repeated source must query its original operation and result.
                return
        if (original['contractId'] != self._family + 'withdraw'
                or 'control' not in original['payload']['input']):
            return super()._forget(key, original)
        self._check_store()
        completed_key = self._control_key(original['binding'], original['payload']['input'])
        with self._hub.store.tx():
            if self._pending(key) != original:
                raise ContractError('legacy_knowledge_recovery_conflict')
            previous = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (completed_key,))
            if previous is not None and strict_loads(previous['v']) != original:
                raise ContractError('legacy_knowledge_recovery_conflict')
            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) '
                'ON CONFLICT(k) DO UPDATE SET v=excluded.v', (completed_key, canonical_bytes(original).decode()))
            self._hub.store.db.execute('DELETE FROM fed_state WHERE k=?', (key,))

    def _restore_control(self, enrollment, value):
        binding = self._binding(enrollment)
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._control_key(binding, value),))
        if row is None:
            return
        original = strict_loads(row['v'])
        if (original['binding'] != binding or original['payload']['input'] != value
                or original['contractId'] != self._family + 'withdraw'
                or original['intentDigest'] != payload_digest(value)):
            raise ContractError('legacy_knowledge_recovery_binding_changed')
        validate(original['contractId'], original['payload'])
        key = self._state_prefix + hashlib.sha256(canonical_bytes({'binding': binding,
            'intentDigest': original['intentDigest'], 'contractId': original['contractId']})).hexdigest()
        pending = self._pending(key)
        if pending is None:
            self._retain(key, original)
        elif pending != original:
            raise ContractError('legacy_knowledge_recovery_conflict')

    def _capture_key(self, binding, value):
        selected = binding[self._field]
        return 'legacy-knowledge-capture:' + hashlib.sha256(canonical_bytes({
            'route': self._logical_route(binding), 'resourceId': selected['resourceRef']['id'],
            'resourceHubId': selected['resourceRef']['ownerHubId'], 'source': value['source']})).hexdigest()

    def _restore_capture(self, enrollment, value):
        """Recover the first completed capture without allocating another effect."""
        binding = self._binding(enrollment)
        original = self._pending(self._capture_key(binding, value))
        if original is None:
            return
        if (original['binding'] != binding or original['payload']['input'] != value
                or original['contractId'] != self._family + 'capture'
                or original['intentDigest'] != payload_digest(value)
                or original.get('conflictReceipt') is not None):
            raise ContractError('legacy_knowledge_recovery_binding_changed')
        validate(original['contractId'], original['payload'])
        key = self._state_prefix + hashlib.sha256(canonical_bytes({'binding': binding,
            'intentDigest': original['intentDigest'], 'contractId': original['contractId']})).hexdigest()
        pending = self._pending(key)
        if pending is None:
            self._retain(key, original)
        elif pending != original:
            raise ContractError('legacy_knowledge_recovery_conflict')

    async def _control_execute(self, session, enrollment, value, expires, *, recover_only=False):
        binding = self._binding(enrollment)
        await self._hub.db(self._restore_control, enrollment, value)
        operation = 'legacy_knowledge_revoke_' + hashlib.sha256(canonical_bytes({
            'route': self._logical_route(binding), 'resourceId': enrollment[self._field]['resourceRef']['id'],
            'peer': value['peer'], 'control': value['control']})).hexdigest()
        if not recover_only:
            def seed():
                key = self._state_prefix + hashlib.sha256(canonical_bytes({'binding': binding,
                    'intentDigest': payload_digest(value), 'contractId': self._family + 'withdraw'})).hexdigest()
                if self._pending(key) is None:
                    original = {'formatVersion': 1, 'binding': binding, 'intentDigest': payload_digest(value),
                        'contractId': self._family + 'withdraw', 'operationId': operation,
                        'payload': {'resourceRef': enrollment[self._field]['resourceRef'],
                            'attribution': 'federation', 'input': value}, 'conflictReceipt': None}
                    validate(original['contractId'], original['payload'])
                    self._retain(key, original)
            await self._hub.db(seed)
        try:
            return await self._execute(session, enrollment, 'withdraw', payload_digest(value), value,
                'federation', expires, stable_operation=operation, recover_only=recover_only)
        except LegacyStorageConflict:
            # A verified no-effect conflict permits one fresh version attempt;
            # the original event and its retained proof never change.
            return await self._execute(session, enrollment, 'withdraw', payload_digest(value), value,
                'federation', expires, stable_operation=operation, recover_only=recover_only)

    async def recover_captures(self):
        """Finish retained service captures without replaying a human request."""
        self.check(self._federation)
        task = asyncio.current_task()
        self._active.add(task)
        try:
            def pending():
                self._check_store()
                self._cleanup_confirmed()
                rows = self._hub.store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33',
                    (self._state_prefix + '%',))
                if len(rows) > 32:
                    raise ContractError('legacy_knowledge_recovery_capacity')
                return [value for row in rows if ((value := self._pending(row['k']))['contractId']
                    == self._family + 'capture' or value['contractId'] == self._family + 'withdraw'
                    and 'control' in value['payload']['input'])]
            for original in await self._hub.db(pending):
                try:
                    selected = original['binding'][self._field]
                    command = original['contractId'].removeprefix(self._family)
                    session, enrollment = self._select('federation', command,
                        selected['repository']['localName'])[0]
                    if (original['binding'] != self._binding(enrollment)
                            or original['payload'].get('attribution') != 'federation'
                            or original['intentDigest'] != payload_digest(original['payload']['input'])):
                        raise ContractError('legacy_knowledge_recovery_binding_changed')
                    if self._locks[id(session)].locked():
                        continue
                    # This is a new, bounded service admission for the original
                    # operation. The owner still checks its current grant and
                    # committed source before any absent/conflict retry.
                    recover = self._capture_original if command == 'capture' else self._control_execute
                    await recover(session, enrollment, original['payload']['input'],
                        datetime.now(timezone.utc) + timedelta(seconds=5), recover_only=True)
                except Exception as exc:
                    self._federation.log('fed: knowledge capture remains pending', type(exc).__name__)
        finally:
            self._active.discard(task)

    async def read(self, caller, command, arguments):
        verbs = {'fed_panel'} if command == 'panel' else {'fed_knowledge_' + command}
        admitted, request, expires = self._caller(caller, verbs)
        args = request.get('args', {})
        if command != 'panel' and args != arguments:
            raise ContractError('legacy_knowledge_caller_binding')
        routes = self._select(admitted.authenticated_caller, 'read', arguments.get('repo'))
        if command == 'show':
            value = {'command': command, 'id': arguments['id']}
        elif command == 'search':
            value = {'command': command, 'query': arguments['query'], 'limit': int(arguments.get('limit') or 10)}
            if not ' '.join(word for word in value['query'].replace('"', ' ').split() if word):
                raise HubError('empty query')
        elif command == 'recent':
            value = {'command': command, 'limit': int(arguments.get('limit') or 20)}
        elif command == 'panel':
            value = {'command': command}
        else:
            raise ContractError('legacy_knowledge_read_unavailable')
        if 'limit' in value:
            value['limit'] = max(-1, value['limit'])
            if value['limit'] > 9007199254740991:
                raise HubError('knowledge limit is too large')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            replies = []
            for session, enrollment in routes:
                selected = enrollment[self._field]
                replies.append(await self._call(session, self._family + 'read', 'knowledge_read_' + secrets.token_hex(16),
                    {'resourceRef': selected['resourceRef'], 'input': value}, expires))
            if command == 'show':
                rows = []
                for (_, enrollment), reply in zip(routes, replies):
                    if type(reply) is not dict or set(reply) != {'row'}:
                        raise ContractError('legacy_knowledge_reply_unconfirmed')
                    if reply['row'] is not None:
                        self._row(reply['row'], enrollment)
                        rows.append(reply['row'])
                if len(rows) != 1:
                    raise HubError(f"no finding {arguments['id']}")
                return self._disclose(rows[0], routes, expires)
            if command == 'panel':
                rows = []
                for (_, enrollment), reply in zip(routes, replies):
                    if (type(reply) is not dict or set(reply) != {'panel', 'ordering'}
                            or type(reply['panel']) is not dict
                            or set(reply['panel']) != {'title', 'columns', 'rows'}
                            or reply['panel']['title'] != 'Knowledge'
                            or reply['panel']['columns'] != ['at', 'repo', 'from', 'title', 'source', 'flags']
                            or type(reply['panel']['rows']) is not list
                            or type(reply['ordering']) is not list
                            or any(type(at) is not str for at in reply['ordering'])
                            or len(reply['ordering']) != len(reply['panel']['rows'])):
                        raise ContractError('legacy_knowledge_reply_unconfirmed')
                    if any(type(row) is not list or len(row) != 6
                            or any(type(field) is not str for field in row)
                            or row[1] != enrollment[self._field]['repository']['localName']
                            for row in reply['panel']['rows']):
                        raise ContractError('legacy_knowledge_reply_unconfirmed')
                    rows.extend(zip(reply['ordering'], reply['panel']['rows']))
                rows.sort(key=lambda row: row[0], reverse=True)
                return self._disclose({'title': 'Knowledge', 'columns': ['at', 'repo', 'from', 'title', 'source', 'flags'],
                    'rows': [row for _, row in rows[:30]]}, routes, expires)
            rows = []
            for (_, enrollment), reply in zip(routes, replies):
                if type(reply) is not dict or set(reply) != {'rows'} or type(reply['rows']) is not list:
                    raise ContractError('legacy_knowledge_reply_unconfirmed')
                for row in reply['rows']:
                    self._row(row, enrollment)
                    if command == 'search' and (type(row.get('_rank')) not in (int, float)
                            or not math.isfinite(row['_rank'])):
                        raise ContractError('legacy_knowledge_reply_unconfirmed')
                    rows.append(row)
            limit = None if value['limit'] < 0 else value['limit']
            if command == 'search':
                rows.sort(key=lambda row: row['_rank'])
                return self._disclose([{key: field for key, field in row.items() if key != '_rank'}
                    for row in rows[:limit]], routes, expires)
            rows.sort(key=lambda row: row['at'], reverse=True)
            return self._disclose(rows[:limit], routes, expires)
        finally:
            self._active.discard(task)

    def _row(self, row, enrollment):
        selected = enrollment[self._field]['repository']
        if (type(row) is not dict or row.get('repo') != selected['localName']
                or type(row.get('id')) is not str or type(row.get('at')) is not str
                or 'rid' in row and row['rid'] != selected['repositoryId']):
            raise ContractError('legacy_knowledge_reply_unconfirmed')

    def _disclose(self, value, routes, expires):
        self.check(self._federation)
        if datetime.now(timezone.utc) >= expires:
            raise ContractError('legacy_knowledge_client_expired')
        for session, enrollment in routes:
            if session.knowledge_enrollment() != enrollment:
                raise ContractError('legacy_knowledge_client_binding')
        return value
