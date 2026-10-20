"""Existing code callers use selected owners and retain original operations."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import time
import re
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import ledger
from hub.store import HubError
from .legacy_messages_client import LegacyMessageCommandClient


class LegacyCodeCommandClient(LegacyMessageCommandClient):
    _field, _family, _state_prefix = 'codeCommands', 'federation-code-', 'legacy-code-client:'
    _enrollment_method, _command_method = 'code_enrollment', 'code_command'
    # Publication remains available until its original Git/handoff group is
    # confirmed. Inbound records remain until durable seen/approval state.
    _completed_commands = frozenset()

    def __init__(self, hub, sessions):
        super().__init__(hub, sessions)
        self._code_git = None
        self._completion = None
        self._local_replies = weakref.WeakKeyDictionary()
        self._panel_reads = weakref.WeakKeyDictionary()
        self._operation_lock = asyncio.Lock()

    def __repr__(self):
        return '<LegacyCodeCommandClient private>'

    def _route_key(self, enrollment):
        selected = enrollment[self._field]
        return (selected['authenticatedCaller'], canonical_bytes(enrollment['scope']),
            selected['repository']['repositoryId'])

    @staticmethod
    def _logical_route(binding):
        selected = binding['codeCommands']
        return {**{key: binding[key] for key in ('hubId', 'scope')},
            **{key: selected[key] for key in ('authenticatedCaller', 'localPeer', 'repository')}}

    def _select(self, caller, command, repo=None):
        self.check(self._federation)
        matches = []
        for session, raw in self._routes:
            enrollment = strict_loads(raw)
            selected = enrollment[self._field]
            repository = selected['repository']
            if (selected['authenticatedCaller'] != caller
                    or repo is not None and repository['localName'] != repo
                    or self._family + command not in selected['grantRefs']):
                continue
            if (canonical_bytes(session.code_enrollment()) != raw
                    or selected['localPeer'] != self._federation.me
                    or selected['localNode'] != self._federation.node
                    or self._federation.policy.rid_of(repository['localName']) != repository['repositoryId']
                    or self._federation.policy.local_of(repository['repositoryId']) != repository['localName']):
                raise ContractError('legacy_code_client_binding')
            matches.append((session, enrollment))
        if not matches or repo is not None and len(matches) != 1:
            raise ContractError('legacy_code_route_unavailable')
        return matches

    def intent_binding(self, command, item):
        repo = self._federation.policy.local_of(item['rid'])
        if repo is None:
            raise ContractError('legacy_code_route_unavailable')
        _, enrollment = self._select('operator' if command == 'approve' else 'federation', command, repo)[0]
        return self._binding(enrollment)

    def _check_result(self, command, original, receipt, result):
        value = original['payload']['input']
        expected = value['id'] if command == 'fetched' else value['envelope']['id']
        if result.get('id') != expected:
            raise ContractError('legacy_code_reply_unconfirmed')
        if command in ('index', 'approve') and result.get('outcome') != 'delivered':
            raise ContractError('legacy_code_reply_unconfirmed')
        if command == 'fetched' and type(result.get('fetched')) is not str:
            raise ContractError('legacy_code_reply_unconfirmed')
        if command == 'publish':
            self._publications[asyncio.current_task()] = canonical_bytes({
                'binding': original['binding'], 'operationId': original['operationId'],
                'payloadDigest': payload_digest(original['payload']),
                'resourceRef': receipt['resourceRef'], 'id': expected})

    def _cleanup_confirmed(self):
        self._check_store()
        rows = self._hub.store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33', (self._state_prefix + '%',))
        if len(rows) > 32:
            raise ContractError('legacy_code_recovery_capacity')
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

    def _retain_handoff_capture(self, source):
        """DB thread: keep recovery only while both original group records exist."""
        self._check_store()
        messages = getattr(self._federation, '_message_commands', None)
        if messages is None:
            return False
        message = messages._pending_code_handoff(source)
        if message is None:
            return False
        item = message['payload']['input']['envelope']
        rows = self._hub.store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33', (self._state_prefix + '%',))
        if len(rows) > 32:
            raise ContractError('legacy_code_recovery_capacity')
        configured = {raw for _, raw in self._routes}
        matches = []
        for row in rows:
            original = self._pending(row['k'])
            if (original['contractId'] != 'federation-code-publish'
                    or canonical_bytes(original['binding']) not in configured):
                continue
            binding, message_binding = original['binding'], message['binding']
            if (original['payload']['input']['envelope']['id'] == item['data']['code']
                    and original['intentDigest'] == message['intentDigest']
                    and original['payload']['attribution'] == message['payload']['attribution']
                    and binding['scope'] == message_binding['scope']
                    and binding['hubId'] == message_binding['hubId']
                    and binding[self._field]['authenticatedCaller']
                        == message_binding['messageCommands']['authenticatedCaller']):
                matches.append(original)
        if len(matches) > 1:
            raise ContractError('legacy_code_recovery_invalid')
        return bool(matches)

    async def confirm_receive(self, item, *, quarantine_id=None, privileged=False):
        self.check(self._federation)
        def confirm():
            if quarantine_id is None:
                if not ledger.seen(self._hub.store, item['id']):
                    raise ContractError('legacy_code_confirmation_unavailable')
            else:
                held = ledger.quarantine_get(self._hub.store, quarantine_id)
                if held is None or held['state'] != 'approved' or held['envelope'] != item:
                    raise ContractError('legacy_code_confirmation_unavailable')
            self._cleanup_confirmed()
        await self._hub.db(confirm)

    async def receive(self, item, decision):
        self.check(self._federation)
        admitted = self._federation._code_intents.consume_inbound(item, decision)
        intent = strict_loads(admitted.content)
        command = intent['command']
        caller = 'operator' if command == 'approve' else 'federation'
        session, enrollment = self._select(caller, command, decision.local_repo)[0]
        binding = self._binding(enrollment)
        if intent['binding'] != binding:
            raise ContractError('legacy_code_intent_binding')
        value = {'envelope': item, 'subject': intent['subject'], 'localNode': self._federation.node}
        if command == 'approve':
            value.update(quarantineId=intent['quarantineId'], privileged=intent['privileged'])
        task = asyncio.current_task()
        self._active.add(task)
        try:
            operation = 'legacy_code_' + hashlib.sha256(canonical_bytes({'binding': binding,
                'envelopeId': item['id'], 'quarantineId': intent.get('quarantineId')})).hexdigest()
            result = await self._execute(session, enrollment, command, payload_digest(value), value,
                caller, admitted.valid_until, stable_operation=operation)
            return result['outcome']
        finally:
            self._active.discard(task)

    def _caller(self, caller, verbs):
        self.check(self._federation)
        admitted = self._hub._consume_authenticated_caller(self._hub.current_authenticated_caller(),
            **({'purpose': 'panel-code'} if verbs == {'fed_panel'} else {}))
        request = strict_loads(admitted.request)
        if (admitted.caller != caller or request.get('verb') not in verbs
                or type(request.get('args', {})) is not dict):
            raise ContractError('legacy_code_caller_binding')
        remaining = admitted.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise ContractError('legacy_code_client_expired')
        return admitted, request, datetime.now(timezone.utc) + timedelta(seconds=min(5, remaining))

    async def _read(self, routes, value, expires, *, include_deadline=False):
        replies = []
        for session, enrollment in routes:
            reply = await self._call(session, self._family + 'read', 'code_read_' + secrets.token_hex(16),
                {'resourceRef': enrollment[self._field]['resourceRef'], 'input': value}, expires,
                include_valid_until=True)
            if type(reply) is not dict or set(reply) != {'result', 'validUntil'}:
                raise ContractError('legacy_code_reply_unconfirmed')
            expires = min(expires, datetime.fromisoformat(reply['validUntil']))
            replies.append(reply['result'])
        rows = []
        for (_, enrollment), reply in zip(routes, replies):
            if value['command'] == 'get':
                if type(reply) is not dict or set(reply) != {'row'}:
                    raise ContractError('legacy_code_reply_unconfirmed')
                selected = [] if reply['row'] is None else [reply['row']]
            else:
                if type(reply) is not dict or set(reply) != {'rows'} or type(reply['rows']) is not list:
                    raise ContractError('legacy_code_reply_unconfirmed')
                selected = reply['rows']
            for row in selected:
                self._row(row, enrollment)
                if value['command'] == 'get' and row['id'] != value['id']:
                    raise ContractError('legacy_code_reply_unconfirmed')
                rows.append(row)
        if value['command'] == 'get':
            if len(rows) > 1:
                raise ContractError('legacy_code_reply_unconfirmed')
            result = self._disclose(rows[0] if rows else None, routes, expires)
            return (result, expires) if include_deadline else result
        rows.sort(key=lambda row: row['at'], reverse=True)
        result = self._disclose(rows[:50 if value['command'] == 'list' else 20], routes, expires)
        return (result, expires) if include_deadline else result

    async def read(self, caller, command, arguments):
        verb = 'fed_panel' if command == 'panel' else 'fed_code_list'
        admitted, request, expires = self._caller(caller, {verb})
        if command not in ('list', 'panel') or command != 'panel' and request.get('args', {}) != arguments:
            raise ContractError('legacy_code_caller_binding')
        routes = self._select(admitted.authenticated_caller, 'read', arguments.get('repo'))
        task = asyncio.current_task()
        self._active.add(task)
        try:
            if command == 'panel':
                self._panel_reads.pop(task, None)
                result, expires = await self._read(routes, {'command': command}, expires,
                    include_deadline=True)
                self._panel_reads[task] = (routes, expires)
                return self.panel_value(result)
            return await self._read(routes, {'command': command}, expires)
        finally:
            self._active.discard(task)

    def confirm_panel_disclosure(self):
        """Check the original read after the combined panel finishes awaiting."""
        self.check(self._federation)
        pending = self._panel_reads.pop(asyncio.current_task(), None)
        if pending is None:
            raise ContractError('legacy_code_panel_unavailable')
        routes, expires = pending
        self._disclose(None, routes, expires)

    def _row(self, row, enrollment):
        selected = enrollment[self._field]['repository']
        if (type(row) is not dict or row.get('repo') != selected['localName']
                or type(row.get('id')) is not str or type(row.get('at')) is not str
                or 'rid' in row and row['rid'] != selected['repositoryId']):
            raise ContractError('legacy_code_reply_unconfirmed')

    def _disclose(self, value, routes, expires):
        self.check(self._federation)
        if datetime.now(timezone.utc) >= expires:
            raise ContractError('legacy_code_client_expired')
        for session, enrollment in routes:
            if session.code_enrollment() != enrollment:
                raise ContractError('legacy_code_client_binding')
        return value

    @staticmethod
    def panel_value(rows):
        return {'title': 'Code', 'columns': ['at', 'from', 'ref', 'sha', 'stat', 'note', 'fetched'],
            'rows': [[row['at'][:19], f"{row['from_peer']} {row['author'] or ''}", row['ref'],
                row['sha'][:10], row['stat'], (row['note'] or '')[:60], 'yes' if row['fetched'] else '']
                for row in rows],
            'actions': [{'verb': 'fed_code_fetch', 'label': 'fetch', 'params': ['id']}]}

    async def _git_owner(self):
        from .code_git import CodeGitCoordinator
        if self._code_git is not None and self._code_git._session is not self._federation.session:
            await self._code_git.close()
            self._code_git = None
        if self._code_git is None:
            self._code_git = CodeGitCoordinator(self._hub, self._federation, self._federation.session)
        return self._code_git

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('legacy_message_cleanup_invalid')
        self._closed = True
        if self._closing is None:
            async def finish():
                await super(LegacyCodeCommandClient, self).close(timeout=None)
                if self._code_git is not None:
                    await self._code_git.close()
                self._local_replies.clear()
                self._panel_reads.clear()
            self._closing = asyncio.create_task(finish())
        cancelled = None
        try:
            _, remaining = await asyncio.wait({self._closing}, timeout=timeout)
            if remaining:
                raise ContractError('legacy_message_cleanup_incomplete')
        except asyncio.CancelledError as error:
            cancelled = error
            while not self._closing.done():
                try:
                    await asyncio.wait({self._closing})
                except asyncio.CancelledError:
                    pass
        self._closing.result()
        if cancelled is not None:
            raise cancelled

    def _retained_git(self, kind, admitted, binding):
        self._check_store()
        rows = self._hub.store.q('SELECT v FROM fed_state WHERE k LIKE ? LIMIT 33', ('legacy-code-git:%',))
        if len(rows) > 32:
            raise ContractError('legacy_code_recovery_capacity')
        principal = {'authenticatedCaller': admitted.authenticated_caller, 'caller': admitted.caller}
        matches = []
        for row in rows:
            if len(row['v'].encode()) > 1048576:
                raise ContractError('legacy_code_recovery_invalid')
            state = strict_loads(row['v'])
            if type(state) is not dict or type(state.get('intent')) is not dict:
                raise ContractError('legacy_code_recovery_invalid')
            intent = state['intent']
            if (intent.get('effectKind') != kind or intent.get('principal') != principal
                    or intent.get('requestDigest') != admitted.request_digest):
                continue
            if intent.get('binding') != binding:
                raise ContractError('legacy_code_recovery_binding_changed')
            matches.append(intent)
        if len(matches) > 1:
            raise ContractError('legacy_code_recovery_invalid')
        return matches[0] if matches else None

    def _live_git(self, admitted):
        self.check(self._federation)
        invocation = self._hub._current_code_share_invocation()
        if (invocation.authenticated_caller, invocation.caller, invocation.request_digest) != (
                admitted.authenticated_caller, admitted.caller, admitted.request_digest):
            raise ContractError('legacy_code_caller_binding')

    def _check_git_selection(self, binding):
        selected = binding[self._field]
        session, enrollment = self._select(selected['authenticatedCaller'],
            'outcome', selected['repository']['localName'])[0]
        if self._binding(enrollment) != binding:
            raise ContractError('legacy_code_client_binding')
        return session

    async def _authorize_git(self, admitted, session, enrollment, command, fields, value, expires):
        self._live_git(admitted)
        reference = enrollment[self._field]['resourceRef']
        payload = {'resourceRef': reference, 'attribution': admitted.caller, 'input': value}
        query = {'contractId': self._family + command, 'operationId': fields['operation_id'],
            'payloadDigest': payload_digest(payload)}
        # The existing outcome route checks current original mutation authority
        # even when no mutation receipt exists. It does not authorize a Git retry.
        received_at = time.monotonic()
        reply = await self._call(session, self._family + 'outcome', 'code_admit_' + secrets.token_hex(16),
            {'resourceRef': reference, 'input': query}, expires, include_valid_until=True)
        if type(reply) is not dict or set(reply) != {'result', 'validUntil'}:
            raise ContractError('legacy_code_reply_unconfirmed')
        authoritative_remaining = (datetime.fromisoformat(reply['validUntil']) - datetime.now(timezone.utc)).total_seconds()
        reply = reply['result']
        if type(reply) is not dict or any(reply.get(key) != value for key, value in query.items()):
            raise ContractError('legacy_code_reply_unconfirmed')
        self._live_git(admitted)
        self._disclose(None, ((session, enrollment),), expires)
        return min(admitted.expires_monotonic, received_at + authoritative_remaining)

    async def _storage_caller(self, admitted):
        proof = await self._hub.code_share_caller('storage')
        current = self._hub._consume_authenticated_caller(proof, purpose='storage')
        if (current.authenticated_caller, current.caller, current.request_digest) != (
                admitted.authenticated_caller, admitted.caller, admitted.request_digest):
            raise ContractError('legacy_code_caller_binding')
        remaining = current.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise ContractError('legacy_code_client_expired')
        return datetime.now(timezone.utc) + timedelta(seconds=min(5, remaining))

    async def _mutate(self, session, enrollment, command, digest, value, caller, expires):
        from .legacy_messages_client import LegacyStorageConflict
        try:
            return await self._execute(session, enrollment, command, digest, value, caller, expires)
        except LegacyStorageConflict:
            # Only this signed no-effect conflict permits a new storage attempt.
            # The original Git operation is already retained and is not rerun.
            return await self._execute(session, enrollment, command, digest, value, caller, expires)

    def _completion_owner(self):
        self.check(self._federation)
        if self._completion is None:
            from .code_completion import CodeCompletionStore
            enrollment = strict_loads(self._routes[0][1])
            self._completion = CodeCompletionStore(self._hub, self._federation,
                profile={key: enrollment[key] for key in ('hubId', 'profileId', 'authorityId')})
        return self._completion

    @staticmethod
    def _completion_identity(admitted, request):
        return {'operation_id': request.get('operationId'), 'request_digest': admitted.request_digest,
            'principal': {'authenticatedCaller': admitted.authenticated_caller, 'caller': admitted.caller}}

    async def _completed(self, admitted, request, expires):
        owner = self._completion_owner()
        self._local_replies.pop(asyncio.current_task(), None)
        record = await self._hub.db(lambda: owner.lookup(**self._completion_identity(admitted, request)))
        if record is None or record['state'] != 'completed':
            return None
        deadline = admitted.expires_monotonic
        routes = []
        for source, client, field in ((record['codeSource'], self, 'codeCommands'),
                (record['messageSource'], getattr(self._federation, '_message_commands', None), 'messageCommands')):
            if source is None:
                continue
            if client is None:
                raise ContractError('legacy_code_completion_unavailable')
            binding = source['binding']
            client.check(self._federation)
            matched = [(session, strict_loads(raw)) for session, raw in client._routes
                if canonical_bytes(binding) == raw]
            if len(matched) != 1:
                raise ContractError('legacy_code_client_binding')
            session, enrollment = matched[0]
            if getattr(session, client._enrollment_method)() != enrollment:
                raise ContractError('legacy_code_client_binding')
            if client is self:
                self._check_git_selection(binding)
            query = {key: source[key] for key in ('contractId', 'operationId', 'payloadDigest')}
            started = time.monotonic()
            reply = await client._call(session, client._family + 'outcome',
                'code_replay_' + secrets.token_hex(16),
                {'resourceRef': enrollment[field]['resourceRef'], 'input': query}, expires,
                include_valid_until=True)
            if type(reply) is not dict or set(reply) != {'result', 'validUntil'}:
                raise ContractError('legacy_code_reply_unconfirmed')
            remaining = (datetime.fromisoformat(reply['validUntil']) - datetime.now(timezone.utc)).total_seconds()
            deadline = min(deadline, started + remaining)
            value = reply['result']
            if (type(value) is not dict or any(value.get(key) != item for key, item in query.items())
                    or value.get('outcome') != 'applied' or value.get('resourceRef') != source['resourceRef']
                    or type(value.get('result')) is not dict
                    or value['result'].get('id') != source['result']['id']):
                raise ContractError('legacy_code_reply_unconfirmed')
            routes.append((client, session, enrollment))
        if request['verb'] == 'fed_code_fetch':
            read_routes = self._select(admitted.authenticated_caller, 'read',
                record['binding'][self._field]['repository']['localName'])
            if any(self._binding(enrollment) != record['binding'] for _, enrollment in read_routes):
                raise ContractError('legacy_code_client_binding')
            read_expires = min(expires, datetime.now(timezone.utc) +
                timedelta(seconds=max(0, deadline - time.monotonic())))
            row, read_expires = await self._read(read_routes,
                {'command': 'get', 'id': record['codeSource']['result']['id']},
                read_expires, include_deadline=True)
            output = record['result']
            if (row is None or any(row[key] != output.get(key) for key in ('ref', 'sha'))
                    or row['files'].split('\n') != output.get('files')):
                raise ContractError('legacy_code_reply_unconfirmed')
            deadline = min(deadline, time.monotonic() +
                (read_expires - datetime.now(timezone.utc)).total_seconds())
        self._live_git(admitted)
        self._check_git_selection(record['binding'])
        if time.monotonic() >= deadline:
            raise ContractError('legacy_code_client_expired')
        for client, session, enrollment in routes:
            client.check(self._federation)
            if getattr(session, client._enrollment_method)() != enrollment:
                raise ContractError('legacy_code_client_binding')
        self._local_replies[asyncio.current_task()] = record
        return record

    async def confirm_local_reply(self):
        """Retire only a legacy receipt after this connection drains successfully.

        Drain is not proof of caller receipt. First-party operation IDs remain
        durable and supply retry identity after an undetected transport loss.
        """
        record = self._local_replies.pop(asyncio.current_task(), None)
        if record is None:
            return
        owner = self._completion_owner()
        worker = asyncio.create_task(self._hub.db(owner.delivered, record))
        self._workers.add(worker)
        cancelled = None
        try:
            while not worker.done():
                try:
                    await asyncio.wait({worker})
                except asyncio.CancelledError as error:
                    cancelled = error
            worker.result()
            if cancelled is not None:
                raise cancelled
        finally:
            if worker.done():
                self._workers.discard(worker)

    async def _finish_effect(self, coordinator, fields, kind, enrollment, command, digest, *,
                             completion, result, handoff=None):
        binding = self._binding(enrollment)
        key = self._state_prefix + hashlib.sha256(canonical_bytes({'binding': binding,
            'intentDigest': digest, 'contractId': self._family + command})).hexdigest()
        intent = coordinator._intent(effect_kind=kind, **fields)
        owner = self._completion_owner()
        def finish():
            with self._hub.store.tx():
                pending = self._pending(key)
                if pending is None or pending['binding'] != binding:
                    raise ContractError('legacy_code_recovery_invalid')
                message_source = None
                if handoff is not None:
                    if kind != 'push':
                        raise ContractError('legacy_code_recovery_invalid')
                    message_source = self._federation._message_commands._confirm_code_handoff(
                        digest, handoff, fields['envelope']['id'], fields['principal'])
                source = {key: pending[key] for key in ('binding', 'contractId', 'operationId')}
                source.update(payloadDigest=payload_digest(pending['payload']),
                    resourceRef={**pending['payload']['resourceRef'],
                        'revision': pending['payload']['resourceRef']['revision'] + 1},
                    result={'id': fields['envelope']['id'] if kind == 'push' else fields['share']['id']})
                completed = owner.complete(**completion, binding=binding, result=result,
                    code_source=source, message_source=message_source)
                coordinator._confirm(intent)
                self._forget(key, pending)
                return completed
        worker = asyncio.create_task(self._hub.db(finish))
        self._workers.add(worker)
        cancelled = None
        try:
            while not worker.done():
                try:
                    await asyncio.wait({worker})
                except asyncio.CancelledError as error:
                    cancelled = error
            result = worker.result()
            self._local_replies[asyncio.current_task()] = result
            if cancelled is not None:
                raise cancelled
            return result
        finally:
            if worker.done():
                self._workers.discard(worker)

    async def share(self, context, arguments, caller):
        # Keep lookup, physical effect and completion in one caller-task group.
        # A concurrent retry must see the first group's retained result.
        self.check(self._federation)
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with self._operation_lock:
                return await self._share(context, arguments, caller)
        finally:
            self._active.discard(task)

    async def _share(self, context, arguments, caller):
        from hub.fed import envelope
        from hub.fed.plugins.code import slugify
        from hub.fed.plugins.messages import parse_peer_address
        from .code_git import public_code_remote
        admitted, request, original_expires = self._caller(caller, {'fed_code_share'})
        if request.get('args', {}) != arguments:
            raise ContractError('legacy_code_caller_binding')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            completed = await self._completed(admitted, request, original_expires)
            if completed is not None:
                return completed['result']
            sender = context.repositories.sender(caller)
            repo = arguments.get('repo') or sender.get('repo')
            if not repo:
                raise HubError('code share needs --repo')
            if arguments.get('to'):
                if not getattr(self._federation, '_qualified_messages', False):
                    raise HubError('qualified code handoff needs message routes')
                peer, remote_repo, _, _ = parse_peer_address(arguments['to'])
                if remote_repo:
                    context.repositories.resolve_repo(peer, remote_repo)
            session, enrollment = self._select(admitted.authenticated_caller, 'publish', repo)[0]
            binding = self._binding(enrollment)
            completion = self._completion_identity(admitted, request)
            await self._hub.db(lambda: self._completion_owner().reserve(**completion, binding=binding))
            retained = await self._hub.db(self._retained_git, 'push', admitted, binding)
            checkout = await context.repositories.checkout(repo,
                retained['checkout']['path'] if retained else arguments.get('path') or arguments.get('cwd'),
                enrollment[self._field]['repository']['repositoryId'])
            if retained is not None:
                item, sha, destination = retained['envelope'], retained['sha'], retained['destination']
            else:
                reference = arguments.get('ref') or 'HEAD'
                sha = await context.git.revision(checkout, reference)
                branch = await context.git.branch(checkout, reference) if reference == 'HEAD' else reference
                slug = slugify(arguments.get('slug') or branch) + '_' + sha[:8]
                destination = 'refs/agentmux/' + context.me + '/' + slug
                base, files, stat, log = await context.git.summary(checkout, sha)
                author = 'operator' if sender.get('operator') else f"{sender['role']}/{sender['agent']}"
                item = envelope.make('code', context.me, context.node, checkout.rid, '*',
                    {'ref': destination, 'sha': sha, 'base': base, 'files': files, 'stat': stat, 'log': log,
                        'note': arguments.get('note') or '', 'slug': slug, 'author': author,
                        'remote': public_code_remote(checkout.url)})
            fields = {'operation_id': retained['operationId'] if retained else 'code_push_' + secrets.token_hex(24),
                'principal': {'authenticatedCaller': admitted.authenticated_caller, 'caller': caller},
                'request_digest': admitted.request_digest, 'binding': binding, 'checkout': checkout,
                'destination': destination, 'sha': sha, 'envelope': item}
            coordinator = await self._git_owner()
            async def authorize():
                return await self._authorize_git(admitted, session, enrollment, 'publish', fields,
                    {'envelope': item}, original_expires)
            await coordinator.push(authorize=authorize, **fields)
            expires = await self._storage_caller(admitted)
            digest = payload_digest(request)
            await self._mutate(session, enrollment, 'publish', digest, {'envelope': item}, caller, expires)
            out = {'id': item['id'], 'ref': destination, 'sha': sha,
                'files': len(item['data']['files']), 'stat': item['data']['stat']}
            if arguments.get('to'):
                out['handoff'] = await context.messages.send_handoff(caller, arguments['to'],
                    (arguments.get('note') or 'code ' + item['data']['slug']) + '\n' + str(item['data']['stat']),
                    item['id'])
            await self._finish_effect(coordinator, fields, 'push', enrollment, 'publish', digest,
                completion=completion, result=out, handoff=out.get('handoff'))
            return out
        except (HubError, asyncio.CancelledError):
            raise
        except Exception:
            raise HubError('qualified code outcome is unconfirmed; original recovery is retained') from None
        finally:
            self._publications.pop(task, None)
            self._active.discard(task)

    async def fetch(self, context, arguments, caller):
        self.check(self._federation)
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with self._operation_lock:
                return await self._fetch(context, arguments, caller)
        finally:
            self._active.discard(task)

    async def _fetch(self, context, arguments, caller):
        admitted, request, expires = self._caller(caller, {'fed_code_fetch'})
        if request.get('args', {}) != arguments:
            raise ContractError('legacy_code_caller_binding')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            completed = await self._completed(admitted, request, expires)
            if completed is not None:
                return completed['result']
            read_routes = self._select(admitted.authenticated_caller, 'read')
            row, expires = await self._read(read_routes, {'command': 'get', 'id': arguments['id']},
                expires, include_deadline=True)
            if row is None:
                raise HubError(f"no code share {arguments['id']} (agentmux hub fed code list)")
            session, enrollment = self._select(admitted.authenticated_caller, 'fetched', row['repo'])[0]
            binding = self._binding(enrollment)
            completion = self._completion_identity(admitted, request)
            await self._hub.db(lambda: self._completion_owner().reserve(**completion, binding=binding))
            retained = await self._hub.db(self._retained_git, 'fetch', admitted, binding)
            if retained is not None:
                if {k: v for k, v in retained['share'].items() if k != 'fetched'} != {
                        k: v for k, v in row.items() if k != 'fetched'}:
                    raise ContractError('legacy_code_recovery_invalid')
                row = retained['share']
            checkout = await context.repositories.checkout(row['repo'],
                retained['checkout']['path'] if retained else arguments.get('path') or arguments.get('cwd'), row['rid'])
            fields = {'operation_id': retained['operationId'] if retained else 'code_fetch_' + secrets.token_hex(24),
                'principal': {'authenticatedCaller': admitted.authenticated_caller, 'caller': caller},
                'request_digest': admitted.request_digest, 'binding': binding, 'checkout': checkout, 'share': row}
            coordinator = await self._git_owner()
            async def authorize():
                return await self._authorize_git(admitted, session, enrollment, 'fetched', fields,
                    {'id': row['id']}, expires)
            got = await coordinator.fetch(authorize=authorize, **fields)
            if got != row['sha']:
                raise ContractError('legacy_code_reply_unconfirmed')
            expires = await self._storage_caller(admitted)
            digest = payload_digest(request)
            await self._mutate(session, enrollment, 'fetched', digest, {'id': row['id']}, caller, expires)
            # Slow Git outlives the initial row authority. The existing single
            # caller refresh also bounds a fresh read before returning its data.
            current_routes = self._select(admitted.authenticated_caller, 'read', row['repo'])
            current, expires = await self._read(current_routes, {'command': 'get', 'id': row['id']},
                expires, include_deadline=True)
            if current is None or {k: v for k, v in current.items() if k != 'fetched'} != {
                    k: v for k, v in row.items() if k != 'fetched'}:
                raise ContractError('legacy_code_reply_unconfirmed')
            self._disclose(row, ((session, enrollment),), expires)
            out = {'ref': row['ref'], 'sha': got, 'checkout': checkout.path, 'verified': True,
                'files': row['files'].split('\n'), 'next': [
                    f"git -C {checkout.path} diff {row['base'] or row['sha'] + '~1'}..{row['ref']}",
                    f"git -C {checkout.path} switch -c {row['ref'].split('/')[-1]} {row['ref']}"]}
            await self._finish_effect(coordinator, fields, 'fetch', enrollment, 'fetched', digest,
                completion=completion, result=out)
            self._disclose(None, (*current_routes, (session, enrollment)), expires)
            return out
        except (HubError, asyncio.CancelledError):
            raise
        except Exception:
            raise HubError('qualified code outcome is unconfirmed; original recovery is retained') from None
        finally:
            self._active.discard(task)

    async def validate_handoff(self, request, caller, body, share_id, expires):
        from hub.fed import redact
        raw = self._publications.get(asyncio.current_task())
        if raw is None:
            raise ContractError('legacy_code_handoff_unavailable')
        source = strict_loads(raw)
        selected = source['binding'][self._field]
        session, enrollment = self._select(selected['authenticatedCaller'], 'outcome',
            selected['repository']['localName'])[0]
        if self._binding(enrollment) != source['binding'] or source['id'] != share_id:
            raise ContractError('legacy_code_handoff_unavailable')
        outcome = await self._call(session, self._family + 'outcome', 'code_handoff_' + secrets.token_hex(16),
            {'resourceRef': source['resourceRef'], 'input': {'contractId': self._family + 'publish',
                'operationId': source['operationId'], 'payloadDigest': source['payloadDigest']}}, expires)
        if (outcome.get('outcome') != 'applied' or outcome.get('resourceRef') != source['resourceRef']
                or outcome.get('result', {}).get('id') != share_id):
            raise ContractError('legacy_code_handoff_unavailable')
        share = await self._read(((session, enrollment),), {'command': 'get', 'id': share_id}, expires)
        sender = self._federation.sender_of(caller)
        author = 'operator' if sender.get('operator') else f"{sender['role']}/{sender['agent']}"
        if (share is None or share['from_peer'] != self._federation.me or share['untrusted'] != 0
                or share['author'] != author or not re.fullmatch(r'[0-9a-f]{40}', share['sha'])
                or not share['ref'].startswith('refs/agentmux/' + self._federation.me + '/')
                or not share['ref'].endswith('_' + share['sha'][:8])):
            raise ContractError('legacy_code_handoff_unavailable')
        note = request['args'].get('note') or ''
        expected = (note or 'code ' + share['ref'].rsplit('/', 1)[1]) + '\n' + str(share['stat'])
        if (share['note'] != redact.scrub({'note': note})[0]['note']
                or redact.scrub({'body': body})[0] != redact.scrub({'body': expected})[0]):
            raise ContractError('legacy_code_handoff_binding')
