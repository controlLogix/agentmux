"""Authenticated legacy callers use fixed enrolled message routes and recovery."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import re
import sqlite3
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.store import HubError


class LegacyStorageConflict(HubError):
    """A verified owner receipt confirms that the attempt had no effect."""


class LegacyMessageCommandClient:
    """Borrow admitted application sessions; keep original intent in the Hub store."""
    _field, _family, _state_prefix = 'messageCommands', 'federation-message-', 'legacy-message-client:'
    _enrollment_method, _command_method = 'message_enrollment', 'message_command'
    _completed_commands = frozenset(('send', 'finding'))

    def __init__(self, hub, sessions):
        from hub.server import Hub
        from hub.client_launch_session import ApplicationClientSession
        if (not isinstance(hub, Hub) or type(sessions) is not tuple or not 1 <= len(sessions) <= 64
                or any(type(session) is not ApplicationClientSession for session in sessions)):
            raise ContractError('legacy_message_client_configuration')
        if (self._field, self._family, self._state_prefix, self._enrollment_method, self._command_method) not in (
                ('messageCommands', 'federation-message-', 'legacy-message-client:', 'message_enrollment', 'message_command'),
                ('knowledgeCommands', 'federation-knowledge-', 'legacy-knowledge-client:', 'knowledge_enrollment', 'knowledge_command'),
                ('codeCommands', 'federation-code-', 'legacy-code-client:', 'code_enrollment', 'code_command')):
            raise ContractError('legacy_message_client_configuration')
        self._hub, self._federation = hub, None
        self._routes = []
        seen = set()
        for session in sessions:
            enrollment = getattr(session, self._enrollment_method)()
            selected = enrollment[self._field]
            if not {self._family + 'inspect', self._family + 'outcome'} <= set(selected['grantRefs']):
                raise ContractError('legacy_message_client_configuration')
            route = canonical_bytes(enrollment)
            key = self._route_key(enrollment)
            if key in seen:
                raise ContractError('legacy_message_client_configuration')
            seen.add(key)
            self._routes.append((session, route))
        if len({tuple(strict_loads(route)[k] for k in ('hubId', 'profileId', 'authorityId'))
                for _, route in self._routes}) != 1:
            raise ContractError('legacy_message_client_configuration')
        self._locks = {id(session): asyncio.Lock() for session, _ in self._routes}
        self._workers, self._active = set(), set()
        self._closed, self._closing = False, None
        self._publications = weakref.WeakKeyDictionary()

    def __repr__(self):
        return '<LegacyMessageCommandClient private>'

    def _route_key(self, enrollment):
        selected = enrollment['messageCommands']
        return (selected['authenticatedCaller'], canonical_bytes(enrollment['scope']), selected['peer'])

    def bind(self, federation):
        from hub.fed.runtime import Federation
        if (type(federation) is not Federation or federation.hub is not self._hub
                or self._federation is not None and self._federation is not federation):
            raise ContractError('legacy_message_client_binding')
        self._federation = federation
        return self

    def check(self, federation):
        if self._closed or federation is not self._federation or federation.hub is not self._hub:
            raise ContractError('legacy_message_client_unavailable')
        stopped = getattr(self._hub, 'stop', None)
        if stopped is not None and stopped.is_set():
            raise ContractError('legacy_message_client_unavailable')

    def _route(self, caller, command, env):
        fed = self._federation
        self.check(fed)
        matched = []
        for session, raw in self._routes:
            enrollment = strict_loads(raw)
            selected = enrollment['messageCommands']
            repository = selected['repository']
            outbound = command == 'send'
            origin, target = ((selected['localPeer'], selected['peer']) if outbound else
                (selected['peer'], selected['localPeer']))
            if command == 'finding':
                target = '*'
            if (selected['authenticatedCaller'] == caller and env.get('from') == origin
                    and env.get('to') == target and env.get('rid') == (
                        None if repository is None else repository['repositoryId'])):
                if (selected['localPeer'] != fed.me or selected['localNode'] != fed.node
                        or canonical_bytes(session.message_enrollment()) != raw
                        or repository is not None and fed.policy.local_of(repository['repositoryId']) != repository['localName']
                        or 'federation-message-' + command not in selected['grantRefs']):
                    raise ContractError('legacy_message_client_binding')
                matched.append((session, enrollment))
        if len(matched) != 1:
            raise ContractError('legacy_message_route_unavailable')
        return matched[0]

    @staticmethod
    def _binding(enrollment):
        # Includes the actual application actor and transport, not display text.
        return strict_loads(canonical_bytes(enrollment))

    def intent_binding(self, command, envelope):
        caller = 'federation' if command == 'deliver' else 'operator'
        _, enrollment = self._route(caller, command, envelope)
        return self._binding(enrollment)

    def take_publication_source(self):
        """Consume the confirmed handoff from this exact original caller task."""
        self.check(self._federation)
        raw = self._publications.pop(asyncio.current_task(), None)
        if raw is None:
            raise ContractError('legacy_message_publication_unavailable')
        return strict_loads(raw)

    async def _call(self, session, contract, operation, payload, expires, *, include_valid_until=False):
        if include_valid_until and (self._field, contract) not in (
                ('codeCommands', 'federation-code-outcome'), ('codeCommands', 'federation-code-read'),
                ('messageCommands', 'federation-message-outcome')):
            raise ContractError('legacy_message_client_binding')
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        if self._closed or remaining <= 0:
            raise ContractError('legacy_message_client_expired')
        task = asyncio.create_task(asyncio.to_thread(getattr(session, self._command_method),
            contract_id=contract, operation_id=operation, payload=payload,
            expires_at=expires.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            deadline=time.monotonic() + min(5, remaining),
            **({'include_valid_until': True} if include_valid_until else {})))
        self._workers.add(task)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError as cancelled:
            while not task.done():
                try:
                    await asyncio.wait({task})
                except asyncio.CancelledError:
                    continue
            if not task.cancelled():
                task.exception()
            raise cancelled
        finally:
            if task.done():
                self._workers.discard(task)

    def _check_store(self):
        from hub.store import Store
        if type(self._hub.store) is not Store:
            raise ContractError('legacy_message_recovery_invalid')
        if hasattr(self._hub.store, '_selected_custody'):
            self._hub.store.check_existing()

    def _pending(self, key):
        self._check_store()
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
        if row is None:
            return None
        value = strict_loads(row['v'])
        fields = {'formatVersion', 'binding', 'intentDigest', 'contractId', 'operationId', 'payload'}
        shapes = (fields, fields | {'conflictReceipt'})
        if type(value) is dict and 'originalDeadline' in value:
            if (self._family != 'federation-knowledge-' or value.get('contractId') != self._family + 'capture'
                    or type(value['originalDeadline']) is not str):
                raise ContractError('legacy_message_recovery_invalid')
            try:
                deadline = datetime.fromisoformat(value['originalDeadline'])
            except ValueError:
                raise ContractError('legacy_message_recovery_invalid') from None
            if deadline.tzinfo != timezone.utc:
                raise ContractError('legacy_message_recovery_invalid')
            shapes = tuple(shape | {'originalDeadline'} for shape in shapes)
        if (type(value) is not dict or set(value) not in shapes
                or type(value['formatVersion']) is not int or value['formatVersion'] != 1
                or canonical_bytes(value).decode() != row['v']):
            raise ContractError('legacy_message_recovery_invalid')
        return value

    def _retain(self, key, value):
        self._check_store()
        raw = canonical_bytes(value)
        if len(raw) > 1048576:
            raise ContractError('legacy_message_recovery_capacity')
        count = self._hub.store.q1('SELECT count(*) n FROM fed_state WHERE k LIKE ?', (self._state_prefix + '%',))['n']
        if count >= 32 and self._pending(key) is None:
            raise ContractError('legacy_message_recovery_capacity')
        with self._hub.store.tx():
            self._check_pending_binding(value['binding'], value['intentDigest'], value['contractId'])
            if self._pending(key) is not None:
                raise ContractError('legacy_message_recovery_conflict')
            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)', (key, raw.decode()))

    @staticmethod
    def _logical_route(binding):
        selected = binding['messageCommands']
        return {**{k: binding[k] for k in ('hubId', 'scope')},
            **{k: selected[k] for k in ('authenticatedCaller', 'localPeer', 'peer', 'repository')}}

    def _check_pending_binding(self, binding, intent_digest, contract):
        self._check_store()
        rows = self._hub.store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33', (self._state_prefix + '%',))
        if len(rows) > 32:
            raise ContractError('legacy_message_recovery_capacity')
        for row in rows:
            original = self._pending(row['k'])
            if (original['contractId'] == contract and original['intentDigest'] == intent_digest
                    and self._logical_route(original['binding']) == self._logical_route(binding)
                    and original['binding'] != binding):
                raise ContractError('legacy_message_recovery_binding_changed')

    def _forget(self, key, original):
        self._check_store()
        with self._hub.store.tx():
            if self._pending(key) != original:
                raise ContractError('legacy_message_recovery_conflict')
            self._hub.store.db.execute('DELETE FROM fed_state WHERE k=?', (key,))

    def _replace(self, key, original, replacement):
        self._check_store()
        raw = canonical_bytes(replacement)
        if len(raw) > 1048576:
            raise ContractError('legacy_message_recovery_capacity')
        with self._hub.store.tx():
            if self._pending(key) != original:
                raise ContractError('legacy_message_recovery_conflict')
            self._hub.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (raw.decode(), key))

    @staticmethod
    def _reference(value, selected):
        if (type(value) is not dict or set(value) != {'id', 'ownerHubId', 'revision'}
                or any(value[k] != selected[k] for k in ('id', 'ownerHubId'))
                or type(value['revision']) is not int or not selected['revision'] <= value['revision'] <= 9007199254740991):
            raise ContractError('legacy_message_reply_unconfirmed')
        return value

    async def _execute(self, session, enrollment, command, intent_digest, value, attribution, expires,
                       *, stable_operation=None, recover_only=False, retain_code_handoff=False):
        if retain_code_handoff and (self._field != 'messageCommands' or command != 'send'
                or value['envelope']['type'] != 'handoff'
                or not self._hub.code_share_dispatch_active()
                or not getattr(self._federation, '_qualified_code', False)):
            raise ContractError('legacy_message_caller_binding')
        if recover_only:
            if self._family != 'federation-knowledge-' or command not in ('capture', 'withdraw'):
                raise ContractError('legacy_message_recovery_invalid')
            if command == 'withdraw':
                validate('federation-knowledge-withdraw', {'resourceRef': enrollment[self._field]['resourceRef'],
                    'attribution': attribution, 'input': value})
                if set(value) != {'peer', 'control'}:
                    raise ContractError('legacy_message_recovery_invalid')
        selected, binding = enrollment[self._field], self._binding(enrollment)
        contract = self._family + command
        key = self._state_prefix + hashlib.sha256(canonical_bytes({
            'binding': binding, 'intentDigest': intent_digest, 'contractId': contract})).hexdigest()
        async with self._locks[id(session)]:
            self.check(self._federation)
            await self._hub.db(self._cleanup_confirmed)
            await self._hub.db(self._check_pending_binding, binding, intent_digest, contract)
            original = await self._hub.db(self._pending, key)
            if recover_only and original is None:
                # The original caller may have completed after recovery took
                # its snapshot. Recovery cannot create another operation.
                return None
            if recover_only:
                if (original['binding'] != binding or original['intentDigest'] != intent_digest
                        or original['contractId'] != contract
                        or original['payload'].get('attribution') != attribution
                        or original['payload'].get('input') != value):
                    raise ContractError('legacy_message_recovery_invalid')
                validate(contract, original['payload'])
            if original is None and self._family == 'federation-knowledge-' and command == 'capture':
                # A local completion may never be emitted again. Retain its
                # exact source before even the first inspection exchange.
                # Recovery uses this original version and operation; a stale
                # version must first produce a verified conflict receipt.
                original = {'formatVersion': 1, 'binding': binding, 'intentDigest': intent_digest,
                    'contractId': contract, 'operationId': stable_operation or 'message_' + secrets.token_hex(24),
                    'payload': {'resourceRef': selected['resourceRef'], 'attribution': attribution, 'input': value},
                    'conflictReceipt': None,
                    'originalDeadline': expires.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
                validate(contract, original['payload'])
                await self._hub.db(self._retain, key, original)
            inspected = await self._call(session, self._family + 'inspect', 'inspect_' + secrets.token_hex(16),
                {'resourceRef': selected['resourceRef'], 'input': {}}, expires)
            if type(inspected) is not dict or set(inspected) != {'resourceRef'}:
                raise ContractError('legacy_message_reply_unconfirmed')
            current = self._reference(inspected['resourceRef'], selected['resourceRef'])
            if original is None:
                original = {'formatVersion': 1, 'binding': binding, 'intentDigest': intent_digest,
                    'contractId': contract, 'operationId': stable_operation or 'message_' + secrets.token_hex(24),
                    'payload': {'resourceRef': current, 'attribution': attribution, 'input': value},
                    'conflictReceipt': None}
                validate(contract, original['payload'])
                await self._hub.db(self._retain, key, original)
                receipt = await self._call(session, contract, original['operationId'], original['payload'], expires)
            else:
                if (original['binding'] != binding or original['intentDigest'] != intent_digest
                        or original['contractId'] != contract
                        or original['payload'].get('attribution') != attribution):
                    raise ContractError('legacy_message_recovery_invalid')
                validate(contract, original['payload'])
                if original.get('conflictReceipt') is not None:
                    conflict = original['conflictReceipt']
                    validate('capability-storage-write-reply', conflict)
                    if conflict['outcome'] != 'conflict':
                        raise ContractError('legacy_message_recovery_invalid')
                    self._reference(conflict['resourceRef'], selected['resourceRef'])
                    # A verified terminal conflict proves no effect occurred.
                    # Only this branch may allocate a fresh attempt, retaining
                    # the same immutable envelope/quarantine intent.
                    replacement = {**original, 'operationId': 'message_retry_' + secrets.token_hex(24),
                        'payload': {**original['payload'], 'resourceRef': current}, 'conflictReceipt': None}
                    await self._hub.db(self._replace, key, original, replacement)
                    original = replacement
                    receipt = await self._call(session, contract, original['operationId'], original['payload'], expires)
                else:
                    receipt = None
                query = {'contractId': contract, 'operationId': original['operationId'],
                    'payloadDigest': payload_digest(original['payload'])}
                if receipt is None:
                    receipt = await self._call(session, self._family + 'outcome', 'recover_' + secrets.token_hex(16),
                        {'resourceRef': current, 'input': query}, expires)
                    if (type(receipt) is not dict or any(receipt.get(k) != v for k, v in query.items())):
                        raise ContractError('legacy_message_reply_unconfirmed')
                    if receipt.get('outcome') == 'absent':
                        if (set(receipt) != {*query, 'outcome', 'receiptRef', 'resourceRef', 'result'}
                                or any(receipt[k] is not None for k in ('receiptRef', 'resourceRef', 'result'))):
                            raise ContractError('legacy_message_reply_unconfirmed')
                        receipt = await self._call(session, contract, original['operationId'], original['payload'], expires)
            if type(receipt) is not dict:
                raise ContractError('legacy_message_reply_unconfirmed')
            validate('capability-storage-write-reply', {k: receipt.get(k) for k in ('outcome', 'receiptRef', 'resourceRef')})
            self._reference(receipt['resourceRef'], selected['resourceRef'])
            if receipt['outcome'] == 'conflict':
                conflict = {k: receipt[k] for k in ('outcome', 'receiptRef', 'resourceRef')}
                await self._hub.db(self._replace, key, original, {**original, 'conflictReceipt': conflict})
                raise LegacyStorageConflict('message revision changed; retry the command')
            result = receipt.get('result')
            if type(result) is not dict:
                raise ContractError('legacy_message_reply_unconfirmed')
            self._check_result(command, original, receipt, result)
            if command in self._completed_commands and not retain_code_handoff:
                await self._hub.db(self._forget, key, original)
            return result

    def _check_result(self, command, original, receipt, result):
        if command == 'send':
            if result.get('id') != original['payload']['input']['envelope']['id']:
                raise ContractError('legacy_message_reply_unconfirmed')
            if original['payload']['input']['envelope']['type'] == 'handoff':
                self._publications[asyncio.current_task()] = canonical_bytes({'kind': 'handoff',
                    'id': result['id'], 'resourceRef': receipt['resourceRef'],
                    'operationId': original['operationId'], 'payloadDigest': payload_digest(original['payload'])})
        elif result.get('deliveryOutcome') not in ('delivered', 'to_operator', 'not_hosted'):
            raise ContractError('legacy_message_reply_unconfirmed')

    async def finding(self, envelope, recipient):
        """A service may notify only from the owner's existing indexed finding."""
        self.check(self._federation)
        session, enrollment = self._route('federation', 'finding', envelope)
        value = {'envelope': envelope, 'recipient': recipient, 'localNode': self._federation.node}
        task = asyncio.current_task()
        self._active.add(task)
        try:
            result = await self._execute(session, enrollment, 'finding', payload_digest(value), value,
                'federation', datetime.now(timezone.utc) + timedelta(seconds=5))
            if result['deliveryOutcome'] == 'not_hosted':
                return None
            if type(result.get('id')) is not str:
                raise ContractError('legacy_message_reply_unconfirmed')
            return {'id': result['id']}
        finally:
            self._active.discard(task)

    def _confirm_receive(self, envelope, quarantine_id, privileged):
        from hub.fed import ledger
        self._check_store()
        if quarantine_id is None:
            command = 'deliver'
            if not ledger.seen(self._hub.store, envelope['id']):
                raise ContractError('legacy_message_confirmation_unavailable')
        else:
            command = 'approve'
            held = ledger.quarantine_get(self._hub.store, quarantine_id)
            if (held is None or held['state'] != 'approved' or held['envelope'] != envelope
                    or held['subject'] != 'am.msg.' + envelope['from'] + '.' + envelope['to']):
                raise ContractError('legacy_message_confirmation_unavailable')
        binding = self.intent_binding(command, envelope)
        rows = self._hub.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-message-client:%' LIMIT 33")
        if len(rows) > 32:
            raise ContractError('legacy_message_recovery_capacity')
        for row in rows:
            original = self._pending(row['k'])
            value = original['payload']['input']
            if (original['binding'] == binding and original['contractId'] == 'federation-message-' + command
                    and value['envelope'] == envelope and (command != 'approve' or (
                        value['quarantineId'] == quarantine_id and value['privileged'] == privileged))):
                self._forget(row['k'], original)

    async def confirm_receive(self, envelope, *, quarantine_id=None, privileged=False):
        """Release local recovery only after the actual durable caller transition."""
        self.check(self._federation)
        await self._hub.db(self._confirm_receive, envelope, quarantine_id, privileged)

    def _cleanup_confirmed(self):
        from hub.fed import ledger
        self._check_store()
        rows = self._hub.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-message-client:%' LIMIT 33")
        if len(rows) > 32:
            raise ContractError('legacy_message_recovery_capacity')
        for row in rows:
            original = self._pending(row['k'])
            contract, value = original['contractId'], original['payload']['input']
            if contract == 'federation-message-deliver':
                if ledger.seen(self._hub.store, value['envelope']['id']):
                    self._confirm_receive(value['envelope'], None, False)
            elif contract == 'federation-message-approve':
                held = ledger.quarantine_get(self._hub.store, value['quarantineId'])
                if held is not None and held['state'] == 'approved' and held['envelope'] == value['envelope']:
                    self._confirm_receive(value['envelope'], value['quarantineId'], value['privileged'])

    async def send(self, caller, to, kind, body, ref=None, code=None, work_id=None):
        self._publications.pop(asyncio.current_task(), None)
        from hub.fed import envelope
        from hub.fed.plugins.messages import parse_peer_address
        self.check(self._federation)
        code_dispatch = self._hub.code_share_dispatch_active()
        proof = (await self._hub.reauthenticate_code_share_caller() if code_dispatch
            else self._hub.current_authenticated_caller())
        admitted = self._hub._consume_authenticated_caller(proof,
            **({'purpose': 'handoff'} if code_dispatch else {}))
        request = strict_loads(admitted.request)
        args = request.get('args', {})
        verb = request.get('verb')
        remaining = admitted.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise ContractError('legacy_message_client_expired')
        expires = datetime.now(timezone.utc) + timedelta(seconds=min(5, remaining))
        if (type(args) is not dict or admitted.caller != caller or args.get('to') != to
                or work_id is not None):
            raise ContractError('legacy_message_caller_binding')
        if verb in ('post', 'fed_messages_send'):
            if (args.get('body') != body or (args.get('kind') or 'note') != kind
                    or args.get('ref') != ref or args.get('code') != code):
                raise ContractError('legacy_message_caller_binding')
        elif verb == 'fed_code_share':
            if not code_dispatch or kind != 'handoff' or ref is not None or type(code) is not str:
                raise ContractError('legacy_message_caller_binding')
            if getattr(self._federation, '_qualified_code', False):
                await self._federation._code_commands.validate_handoff(request, caller, body, code, expires)
            else:
                await self._hub.db(self._code_handoff, request, caller, body, code)
        else:
            raise ContractError('legacy_message_caller_binding')
        fed = self._federation
        peer, repo, role, agent = parse_peer_address(to)
        rid = fed.resolve_repo(peer, repo) if repo else None
        local = fed.policy.local_of(rid) if rid else None
        sender = {k: v for k, v in fed.sender_of(caller).items() if k != 'repo'}
        data = {'kind': kind, 'body': body, 'ref': ref, 'sender': sender,
            'target': {'rid': rid, 'role': role, 'agent': agent} if local else None,
            'code': code, 'work_id': work_id}
        env = envelope.make('handoff' if kind == 'handoff' else 'message', fed.me, fed.node, rid, peer, data)
        session, enrollment = self._route(admitted.authenticated_caller, 'send', env)
        value = {'envelope': env, 'subject': envelope.subject('msg', fed.me, peer), 'localNode': fed.node,
            'requestedTo': to}
        task = asyncio.current_task()
        self._active.add(task)
        try:
            result = await self._execute(session, enrollment, 'send', payload_digest(request), value, caller, expires,
                retain_code_handoff=code_dispatch and getattr(fed, '_qualified_code', False))
            return {'id': result['id'], 'to': to, 'kind': kind, 'queued': True}
        except asyncio.CancelledError:
            raise
        except HubError:
            raise
        except Exception:
            raise HubError('qualified message outcome is unconfirmed; original recovery is retained') from None
        finally:
            self._active.discard(task)

    def _pending_code_handoff(self, source):
        """Find only the exact original source; this does not authorize capture."""
        self._check_store()
        if type(source) is not dict or source.get('kind') != 'handoff':
            return None
        rows = self._hub.store.q('SELECT k FROM fed_state WHERE k LIKE ? LIMIT 33', (self._state_prefix + '%',))
        if len(rows) > 32:
            raise ContractError('legacy_message_recovery_capacity')
        configured = {raw for _, raw in self._routes}
        matches = []
        for row in rows:
            original = self._pending(row['k'])
            if (original['contractId'] != 'federation-message-send'
                    or canonical_bytes(original['binding']) not in configured):
                continue
            value = original['payload']['input']
            item = value['envelope']
            reference = original['payload']['resourceRef']
            if (item['type'] == 'handoff' and type(item['data'].get('code')) is str
                    and item['id'] == source.get('id') and original['operationId'] == source.get('operationId')
                    and payload_digest(original['payload']) == source.get('payloadDigest')
                    and source.get('resourceRef') == {**reference, 'revision': reference['revision'] + 1}):
                matches.append(original)
        if len(matches) > 1:
            raise ContractError('legacy_message_recovery_conflict')
        return matches[0] if matches else None

    def _confirm_code_handoff(self, digest, receipt, share_id, principal):
        """DB thread, inside the original code group's completion transaction."""
        self._check_store()
        if (type(receipt) is not dict or receipt.get('kind') != 'handoff'
                or receipt.get('queued') is not True):
            raise ContractError('legacy_message_code_handoff_binding')
        matches = []
        for _, raw in self._routes:
            binding = strict_loads(raw)
            if binding['messageCommands']['authenticatedCaller'] != principal['authenticatedCaller']:
                continue
            key = self._state_prefix + hashlib.sha256(canonical_bytes({
                'binding': binding, 'intentDigest': digest, 'contractId': 'federation-message-send'})).hexdigest()
            pending = self._pending(key)
            if pending is None:
                continue
            value = pending['payload']['input']
            item = value['envelope']
            if (pending['binding'] != binding or pending['intentDigest'] != digest
                    or pending['contractId'] != 'federation-message-send'
                    or pending['payload']['attribution'] != principal['caller']
                    or item['type'] != 'handoff' or item['id'] != receipt['id']
                    or item['data']['code'] != share_id or value['requestedTo'] != receipt['to']):
                raise ContractError('legacy_message_code_handoff_binding')
            matches.append((key, pending))
        if len(matches) != 1:
            raise ContractError('legacy_message_code_handoff_binding')
        pending = matches[0][1]
        source = {key: pending[key] for key in ('binding', 'contractId', 'operationId')}
        source.update(payloadDigest=payload_digest(pending['payload']),
            resourceRef={**pending['payload']['resourceRef'],
                'revision': pending['payload']['resourceRef']['revision'] + 1},
            result={'id': receipt['id']})
        self._forget(*matches[0])
        return source

    def _code_handoff(self, request, caller, body, share_id):
        """Bind derived handoff data to the actual local code owner's record."""
        from hub.fed import envelope, redact
        self._check_store()
        fed, args = self._federation, request['args']
        sender = fed.sender_of(caller)
        repo = args.get('repo') or sender.get('repo')
        try:
            share = self._hub.store.q1('SELECT * FROM p_code_shares WHERE id=?', (share_id,))
        except sqlite3.Error:
            raise ContractError('legacy_message_code_handoff_unavailable') from None
        author = 'operator' if sender.get('operator') else f"{sender['role']}/{sender['agent']}"
        if (share is None or share['from_peer'] != fed.me or share['untrusted'] != 0 or share['repo'] != repo
                or fed.policy.rid_of(repo) != share['rid'] or share['author'] != author
                or not re.fullmatch(r'[0-9a-f]{40}', share['sha'])
                or not share['ref'].startswith('refs/agentmux/' + fed.me + '/')
                or not share['ref'].endswith('_' + share['sha'][:8])):
            raise ContractError('legacy_message_code_handoff_unavailable')
        note = args.get('note') or ''
        cleaned_note = redact.scrub({'note': note})[0]['note']
        slug = share['ref'].rsplit('/', 1)[1]
        expected = (note or 'code ' + slug) + f"\n{share['stat']}"
        if (share['note'] != cleaned_note or type(body) is not str
                or redact.scrub({'body': body})[0] != redact.scrub({'body': expected})[0]):
            raise ContractError('legacy_message_code_handoff_binding')
        # A drained outbox is normal. If it is still retained, require the
        # original publication to agree with the local materialized record.
        queued = self._hub.store.q1('SELECT payload, subject FROM fed_outbox WHERE msg_id=?', (share_id,))
        if queued is not None:
            original = strict_loads(queued['payload'])
            envelope.validate_route(queued['subject'], original)
            if (original['type'] != 'code' or original['from'] != fed.me or original['id'] != share_id
                    or original['rid'] != share['rid'] or original['to'] != '*'
                    or any(original['data'].get(k) != share[k] for k in ('ref', 'sha', 'author', 'stat', 'note'))):
                raise ContractError('legacy_message_code_handoff_binding')

    async def receive(self, envelope, decision):
        from hub.fed.message_bridge import intent_operation
        self.check(self._federation)
        admitted = self._federation._message_intents.consume(envelope, decision)
        intent = strict_loads(admitted.content)
        command = intent['command']
        caller = 'federation' if command == 'deliver' else 'operator'
        session, enrollment = self._route(caller, command, envelope)
        if self._binding(enrollment) != intent['binding']:
            raise ContractError('legacy_message_client_binding')
        value = {k: intent[k] for k in ('envelope', 'subject', 'localNode')}
        if command == 'approve':
            value.update(quarantineId=intent['quarantineId'], privileged=intent['privileged'])
        operation = intent_operation(intent['binding'], command, envelope['id'], intent['quarantineId'])
        task = asyncio.current_task()
        self._active.add(task)
        try:
            intent_digest = payload_digest({k: v for k, v in intent.items() if k != 'binding'})
            result = await self._execute(session, enrollment, command, intent_digest, value, caller,
                admitted.valid_until, stable_operation=operation)
            return result['deliveryOutcome']
        finally:
            self._active.discard(task)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('legacy_message_cleanup_invalid')
        self._closed = True
        self._publications.clear()
        for task in tuple(self._active):
            task.cancel()
        pending = {*self._active, *self._workers}
        if pending:
            _, remaining = await asyncio.wait(pending, timeout=timeout)
            if remaining:
                raise ContractError('legacy_message_cleanup_incomplete')
        self._publications.clear()
