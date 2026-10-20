"""Hub-side typed self-revoke commands; no protected publisher is exposed."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import time

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate


class PeerControlCommandClient:
    def __init__(self, hub, sessions):
        from hub.server import Hub
        from hub.client_launch_session import ApplicationClientSession
        if (not isinstance(hub, Hub) or type(sessions) is not tuple or not sessions
                or any(type(s) is not ApplicationClientSession for s in sessions)):
            raise ContractError('peer_control_client_configuration')
        self._hub, self._federation = hub, None
        self._routes = tuple((s, canonical_bytes(s.peer_control_enrollment())) for s in sessions)
        keys = [(strict_loads(raw)['peerControlCommands']['routeId'], canonical_bytes(strict_loads(raw)['scope']))
            for _, raw in self._routes]
        if len(set(keys)) != len(keys):
            raise ContractError('peer_control_client_configuration')
        self._closed, self._closing = False, None
        self._active, self._workers = set(), set()
        self._lock = asyncio.Lock()

    def __repr__(self):
        return '<PeerControlCommandClient private>'

    def bind(self, federation):
        from hub.fed.runtime import Federation
        if (type(federation) is not Federation or federation.hub is not self._hub
                or self._federation is not None and self._federation is not federation):
            raise ContractError('peer_control_client_binding')
        self._federation = federation
        return self

    def check(self):
        from hub.store import Store
        if (self._closed or self._federation is None or self._federation.hub is not self._hub
                or type(self._hub.store) is not Store
                or getattr(self._hub, 'stop', None) is not None and self._hub.stop.is_set()):
            raise ContractError('peer_control_client_unavailable')
        if hasattr(self._hub.store, '_selected_custody'):
            self._hub.store.check_existing()
        for session, raw in self._routes:
            if canonical_bytes(session.peer_control_enrollment()) != raw:
                raise ContractError('peer_control_client_binding')
            selected = strict_loads(raw)['peerControlCommands']
            if selected['localPeer'] != self._federation.me or selected['localNode'] != self._federation.node:
                raise ContractError('peer_control_client_binding')

    def _caller(self, caller, item):
        self.check()
        proof = self._hub.current_authenticated_caller()
        admitted = self._hub._consume_authenticated_caller(proof)
        request = strict_loads(admitted.request)
        args = request.get('args', {})
        if (admitted.authenticated_caller != 'operator' or admitted.caller != 'operator' or caller != 'operator'
                or request.get('verb') != 'fed_kill' or type(args) is not dict or args.get('revoke') is not True
                or item.get('data') != {'reason': args.get('reason') or 'kill switch'}):
            raise ContractError('peer_control_client_caller_refused')
        remaining = admitted.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise ContractError('peer_control_client_expired')
        return request, datetime.now(timezone.utc) + timedelta(seconds=min(remaining, 5))

    async def _joined(self, coroutine):
        worker = asyncio.create_task(coroutine)
        self._workers.add(worker)
        def finished(done):
            self._workers.discard(done)
            if not done.cancelled():
                done.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    def _key(self, enrollment):
        return 'peer-control-client:' + hashlib.sha256(canonical_bytes(enrollment)).hexdigest()

    @staticmethod
    def _effect_digest(request):
        # Query approval binds a different command. It cannot change the
        # retained effect, its original approval or any other kill argument.
        frozen = strict_loads(canonical_bytes(request))
        frozen['args'].pop('outcomeOperationId', None)
        frozen['args'].pop('outcomeApprovalRefs', None)
        return payload_digest(frozen)

    def _load(self, enrollment):
        self.check()
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(enrollment),))
        if row is None:
            return None
        value = strict_loads(row['v'])
        if (type(value) is not dict or set(value) != {'formatVersion', 'binding', 'requestDigest',
                'operationId', 'payload', 'result', 'killDigest'} or value['formatVersion'] != 1
                or value['binding'] != enrollment):
            raise ContractError('peer_control_client_conflict')
        validate('federation-peer-revoke', value['payload'])
        if value['result'] is not None:
            validate('federation-peer-revoke-result', value['result'])
        return value

    def _retain(self, enrollment, request, item):
        self.check()
        selected = enrollment['peerControlCommands']
        with self._hub.store.tx():
            current = self._load(enrollment)
            if current is not None:
                killed = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', ('killed',))
                if (current['killDigest'] is None
                        or killed is not None and strict_loads(killed['v']) is not None):
                    if current['requestDigest'] != self._effect_digest(request):
                        raise ContractError('peer_control_client_unconfirmed')
                    return current
                # Only a confirmed original local kill followed by resume
                # permits a new event for a later explicit operator kill.
            payload = {'resourceRef': selected['resourceRef'],
                'input': {'routeId': selected['routeId'], 'envelope': item}}
            validate('federation-peer-revoke', payload)
            value = {'formatVersion': 1, 'binding': enrollment, 'requestDigest': self._effect_digest(request),
                'operationId': 'peer_revoke_' + secrets.token_hex(24), 'payload': payload,
                'result': None, 'killDigest': None}
            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) '
                'ON CONFLICT(k) DO UPDATE SET v=excluded.v', (self._key(enrollment), canonical_bytes(value).decode()))
            return value

    async def _call(self, session, contract, operation, payload, approvals, expires):
        self.check()
        if datetime.now(timezone.utc) >= expires:
            raise ContractError('peer_control_client_expired')
        return await self._joined(asyncio.to_thread(session.peer_control_command,
            contract_id=contract, operation_id=operation, payload=payload, approval_refs=approvals,
            expires_at=expires.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            deadline=time.monotonic() + max(0, (expires - datetime.now(timezone.utc)).total_seconds())))

    def _save_result(self, enrollment, original, result):
        self.check()
        validate('federation-peer-revoke-result', result)
        item = original['payload']['input']['envelope']
        if (result['operationId'] != original['operationId'] or result['payloadDigest'] != payload_digest(original['payload'])
                or result['eventId'] != item['id'] or result['eventDigest'] != payload_digest(item)):
            raise ContractError('peer_control_client_reply_unconfirmed')
        with self._hub.store.tx():
            if self._load(enrollment) != original:
                raise ContractError('peer_control_client_conflict')
            replacement = {**original, 'result': result}
            self._hub.store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                (canonical_bytes(replacement).decode(), self._key(enrollment)))
            return result

    async def revoke(self, caller, item):
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            request, expires = self._caller(caller, item)
            approvals = request.get('args', {}).get('approvalRefs', [])
            if type(approvals) is not list:
                raise ContractError('peer_control_client_caller_refused')
            args = request['args']
            query_approvals = args.get('outcomeApprovalRefs', [])
            query_operation = args.get('outcomeOperationId')
            if query_approvals and query_operation is None:
                raise ContractError('peer_control_client_caller_refused')
            query_metadata = {'operationId': ('peer_revoke_query_' + secrets.token_hex(16)
                if query_operation is None else query_operation),
                'approvalRefs': query_approvals}
            validate('peer-control-outcome-approval', query_metadata)
            results = []
            async with self._lock:
                for session, raw in self._routes:
                    self.check()
                    enrollment = strict_loads(raw)
                    previous = await self._joined(self._hub.db(self._load, enrollment))
                    self.check()
                    original = await self._joined(self._hub.db(self._retain, enrollment, request, item))
                    self.check()
                    if previous is not None and previous['killDigest'] is None:
                        if query_metadata['operationId'] == original['operationId']:
                            raise ContractError('peer_control_client_caller_refused')
                        query = {'resourceRef': original['payload']['resourceRef'], 'input': {
                            'routeId': original['payload']['input']['routeId'], 'operationId': original['operationId'],
                            'payloadDigest': payload_digest(original['payload'])}}
                        result = await self._call(session, 'federation-peer-revoke-outcome',
                            query_metadata['operationId'], query, query_metadata['approvalRefs'], expires)
                    else:
                        result = await self._call(session, 'federation-peer-revoke', original['operationId'],
                            original['payload'], approvals, expires)
                    self.check()
                    results.append(await self._joined(self._hub.db(self._save_result, enrollment, original, result)))
                self.check()
                return results
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def confirm_killed(self, report):
        """Release retry intent only after the original local killed state commits."""
        self.check()
        def confirm():
            self.check()
            with self._hub.store.tx():
                killed = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', ('killed',))
                if killed is None or strict_loads(killed['v']) != report:
                    raise ContractError('peer_control_client_unconfirmed')
                for _, raw in self._routes:
                    enrollment = strict_loads(raw)
                    current = self._load(enrollment)
                    if current is None or current['result'] is None or current['result']['outcome'] != 'published':
                        raise ContractError('peer_control_client_unconfirmed')
                    current['killDigest'] = payload_digest(report)
                    self._hub.store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                        (canonical_bytes(current).decode(), self._key(enrollment)))
        await self._joined(self._hub.db(confirm))

    async def close(self, *, timeout=5):
        self._closed = True
        if self._closing is None:
            async def joined():
                if self._active or self._workers:
                    await asyncio.gather(*tuple(self._active | self._workers), return_exceptions=True)
            self._closing = asyncio.create_task(joined(), name='peer-control-client:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('peer_control_client_cleanup_incomplete')
        self._closing.result()
