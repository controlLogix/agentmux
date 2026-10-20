"""Adapt authenticated Hub policy verbs to the dedicated enrolled owner."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import secrets
import time

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from jsonschema import Draft202012Validator, ValidationError
from state_owner.federation_policy import FEDERATION_POLICY_SCHEMA, SCHEMA_REF, _digest, _policy, _reference
from identity.application_enrollment import _read_material
from identity.federation_policy_client import PolicyClientResult
from .federation_policy_transition import changed_policy


class LegacyPolicyCommandClient:
    def __init__(self, hub, sessions):
        from hub.server import Hub
        from hub.client_launch_session import ApplicationClientSession
        if (not isinstance(hub, Hub) or type(sessions) is not tuple or not sessions
                or any(type(session) is not ApplicationClientSession for session in sessions)):
            raise ContractError('policy_client_configuration')
        self._hub, self._federation = hub, None
        self._routes = tuple((session, canonical_bytes(session.federation_policy_enrollment())) for session in sessions)
        if len({canonical_bytes(strict_loads(raw)['federationPolicyCommands']['target'])
                for _, raw in self._routes}) != len(self._routes):
            raise ContractError('policy_client_configuration')
        self._closed, self._closing = False, None
        self._calls, self._workers = set(), set()
        self._lock = asyncio.Lock()

    def __repr__(self):
        return '<LegacyPolicyCommandClient private>'

    def bind(self, federation):
        from hub.fed.runtime import Federation
        if (type(federation) is not Federation or federation.hub is not self._hub
                or self._federation is not None and self._federation is not federation):
            raise ContractError('policy_client_binding')
        self._federation = federation
        return self

    def check(self):
        from hub.store import Store
        if (self._closed or self._federation is None or type(self._hub.store) is not Store
                or self._federation.hub is not self._hub or self._hub.stop.is_set()):
            raise ContractError('policy_client_unavailable')
        for session, raw in self._routes:
            if canonical_bytes(session.federation_policy_enrollment()) != raw:
                raise ContractError('policy_client_binding')
            route = strict_loads(raw)['federationPolicyCommands']
            if (route['policyPath'] != str(Path(self._federation.hubdir) / 'federation.toml')
                    or route['localPeer'] != self._federation.me):
                raise ContractError('policy_client_binding')

    async def _joined(self, coroutine):
        if self._closed:
            coroutine.close()
            raise ContractError('policy_client_unavailable')
        original = asyncio.create_task(coroutine)
        self._workers.add(original)
        def finished(done):
            self._workers.discard(done)
            if not done.cancelled():
                done.exception()
        original.add_done_callback(finished)
        await asyncio.wait({original})
        return original.result()

    def _caller(self, caller, verb, arguments):
        self.check()
        admitted = self._hub._consume_authenticated_caller(self._hub.current_authenticated_caller())
        request = strict_loads(admitted.request)
        args = request.get('args', {})
        fields = {'trust': ('peer', 'level'), 'share': ('repo', 'peers', 'remote', 'board_prefix'),
            'unshare': ('repo',)}
        if (verb not in fields or admitted.authenticated_caller != 'operator' or admitted.caller != 'operator'
                or caller != 'operator' or request.get('verb') != 'fed_' + verb or type(args) is not dict
                or any(args.get(key) != arguments.get(key) for key in fields[verb])):
            raise ContractError('policy_client_caller_refused')
        remaining = admitted.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise ContractError('policy_client_expired')
        change = {'verb': verb, 'arguments': {key: args[key] for key in fields[verb] if key in args}}
        return args, change, datetime.now(timezone.utc) + timedelta(seconds=min(remaining, 5)), admitted.request_digest

    def _key(self, enrollment):
        return 'federation-policy-client:' + hashlib.sha256(canonical_bytes(enrollment)).hexdigest()

    def _load(self, enrollment):
        self.check()
        row = self._hub.store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(enrollment),))
        if row is None:
            return None
        value = strict_loads(row['v'])
        fields = {'formatVersion', 'binding', 'change', 'operationId',
                'revision', 'phase', 'proposal', 'descriptor', 'finalPayload', 'result'}
        if (type(value) is not dict or set(value) not in (fields, fields | {'requestDigest'})
                or type(value['formatVersion']) is not int or value['formatVersion'] not in (1, 2)
                or (value['formatVersion'] == 2) != ('requestDigest' in value)
                or value['formatVersion'] == 2 and (type(value['requestDigest']) is not str
                    or re.fullmatch(r'[a-f0-9]{64}', value['requestDigest']) is None)
                or value['binding'] != enrollment
                or type(value['revision']) is not int or not 0 <= value['revision'] < 9007199254740991
                or type(value['operationId']) is not str
                or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', value['operationId']) is None
                or value['phase'] not in ('preparing', 'committing', 'committed')):
            raise ContractError('policy_client_conflict')
        route = enrollment['federationPolicyCommands']
        try:
            proposal_raw = base64.b64decode(value['proposal'], validate=True)
            proposal = strict_loads(proposal_raw)
            if (not 1 <= len(proposal_raw) <= 16384 or canonical_bytes(proposal) != proposal_raw
                    or base64.b64encode(proposal_raw).decode() != value['proposal']
                    or proposal['format'] != 'amx-federation-policy-preparation-v1'
                    or proposal['target'] != route['target'] or proposal['originDigest'] != route['originDigest']
                    or proposal['previousRevision'] != value['revision'] or proposal['change'] != value['change']):
                raise ValueError()
            if value['phase'] == 'preparing':
                if any(value[name] is not None for name in ('descriptor', 'finalPayload', 'result')):
                    raise ValueError()
            else:
                descriptor = base64.b64decode(value['descriptor'], validate=True)
                document = strict_loads(descriptor)
                Draft202012Validator(strict_loads(FEDERATION_POLICY_SCHEMA)).validate(document)
                if (not 1 <= len(descriptor) <= 16384 or canonical_bytes(document) != descriptor
                        or base64.b64encode(descriptor).decode() != value['descriptor']
                        or document['format'] != 'amx-federation-policy-v1'
                        or document['target'] != route['target'] or document['originDigest'] != route['originDigest']
                        or document['previousRevision'] != value['revision']
                        or document['projectionIntent']['operationId'] != value['operationId']
                        or document['projectionIntent']['change'] != value['change']
                        or document['projectionIntent']['actorRef'] != enrollment['callerRef']
                        or document['projectionIntent']['callerRef'] != enrollment['callerRef']
                        or document['projectionIntent']['preparationDigest'] != payload_digest(
                            self._payload(route, value['revision'], proposal_raw))
                        or any(document[name]['keyRef'] != route['keyRef']
                            or {key: document[name][key] for key in ('digest', 'bytes')} != proposal[name]
                            for name in ('oldPolicy', 'desiredPolicy'))
                        or value['finalPayload'] != self._payload(route, value['revision'], descriptor)):
                    raise ValueError()
                expected = {'revision': value['revision']+1, 'operationId': value['operationId'], 'change': value['change']}
                if value['result'] != (expected if value['phase'] == 'committed' else None):
                    raise ValueError()
        except (ValueError, KeyError, TypeError, ValidationError):
            raise ContractError('policy_client_conflict') from None
        return value

    def _save(self, enrollment, value, previous):
        self.check()
        with self._hub.store.tx():
            if self._load(enrollment) != previous:
                raise ContractError('policy_client_conflict')
            self._hub.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) '
                'ON CONFLICT(k) DO UPDATE SET v=excluded.v',
                (self._key(enrollment), canonical_bytes(value).decode()))
        return value

    async def _command(self, session, route, contract, operation, revision, payload, approvals, expires):
        self.check()
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise ContractError('policy_client_expired')
        result = await self._joined(asyncio.to_thread(session.federation_policy_command,
            contract_id=contract, operation_id=operation, expected_version=revision,
            payload=payload, approval_refs=approvals,
            expires_at=expires.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            deadline=time.monotonic() + remaining))
        self.check()
        if type(result) is not PolicyClientResult:
            raise ContractError('policy_client_response_refused')
        return result

    def _payload(self, route, revision, document=None):
        value = {'configurationRef': {**route['configurationRef'], 'revision': revision}, 'owner': route['owner']}
        if document is not None:
            value.update(configurationBytes=base64.b64encode(document).decode(), schemaRef=SCHEMA_REF,
                secretReferences=[route['keyRef']])
        return value

    async def change(self, caller, verb, arguments):
        finished = asyncio.get_running_loop().create_future()
        self._calls.add(finished)
        try:
            args, change, expires, request_digest = self._caller(caller, verb, arguments)
            async with self._lock:
                candidates = [(session, strict_loads(raw)) for session, raw in self._routes
                    if verb == 'trust' or strict_loads(raw)['federationPolicyCommands']['repository']['localName']
                        == change['arguments']['repo']]
                if len(candidates) != 1:
                    raise ContractError('policy_client_route_refused')
                session, enrollment = candidates[0]
                route = enrollment['federationPolicyCommands']
                for name in ('operationId', 'readOperationId'):
                    if args.get(name) is not None and (type(args[name]) is not str
                            or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', args[name]) is None):
                        raise ContractError('policy_client_caller_refused')
                for name in ('approvalRefs', 'preparationApprovalRefs', 'readApprovalRefs'):
                    refs = args.get(name, [])
                    if type(refs) is not list or len(refs) > 32:
                        raise ContractError('policy_client_caller_refused')
                    for reference in refs:
                        _reference(reference, enrollment['hubId'])
                    if len({canonical_bytes(ref) for ref in refs}) != len(refs):
                        raise ContractError('policy_client_caller_refused')
                previous = await self._joined(self._hub.db(self._load, enrollment))
                requested = args.get('operationId')
                same = previous is not None and (previous.get('requestDigest') == request_digest
                    or requested == previous['operationId'])
                if previous is not None:
                    if same and previous['change'] != change:
                        raise ContractError('policy_client_conflict')
                    if previous['phase'] != 'committed' and (previous['change'] != change
                            or requested is not None and requested != previous['operationId']):
                        raise ContractError('policy_client_original_unconfirmed')
                read = await self._command(session, route, 'configuration-read',
                    args.get('readOperationId') or 'policy_read_' + secrets.token_hex(16), 0,
                    self._payload(route, 0), args.get('readApprovalRefs', []), expires)
                if read.kind != 'current':
                    raise ContractError('policy_client_response_refused')
                current = strict_loads(read.data)
                if previous is not None and previous['phase'] == 'committed':
                    # The local result was saved only after a verified actual
                    # commit and projection. Replaying that authenticated request
                    # reads current authority; it does not authorize a new set.
                    legacy_same = previous['formatVersion'] == 1 and previous['change'] == change and requested is None
                    exact_current = (current['originalOperationId'] == previous['operationId']
                        and current['originalPayloadDigest'] == payload_digest(previous['finalPayload'])
                        and current['projected']
                        and current['configurationRef']['revision'] == previous['result']['revision'])
                    # Fresh approval/read metadata does not make a new policy
                    # effect while that exact original intent remains current.
                    current_same = requested is None and previous['change'] == change and exact_current
                    if same or legacy_same or current_same:
                        if current['configurationRef']['revision'] < previous['result']['revision']:
                            raise ContractError('policy_client_original_unconfirmed')
                        if legacy_same and not same and not exact_current:
                            raise ContractError('policy_client_original_unconfirmed')
                        return previous['result']
                if previous is not None and previous['phase'] == 'committing':
                    if (current['originalOperationId'] != previous['operationId']
                            or current['originalPayloadDigest'] != payload_digest(previous['finalPayload'])
                            or current['configurationRef']['revision'] != previous['revision'] + 1
                            or not current['projected']):
                        raise ContractError('policy_client_original_unconfirmed')
                    result = {'revision': current['configurationRef']['revision'],
                        'operationId': previous['operationId'], 'change': change}
                    await self._joined(self._hub.db(self._save, enrollment,
                        {**previous, 'phase': 'committed', 'result': result}, previous))
                    return result
                if previous is None or previous['phase'] == 'committed':
                    path = Path(self._federation.hubdir) / 'federation.toml'
                    raw = await self._joined(asyncio.to_thread(_read_material, str(path),
                        max_bytes=65536, return_bytes=True))
                    _policy(raw)
                    desired = changed_policy(raw, change, repository=route['repository'])
                    if current['state'] is None:
                        if _digest(raw) != route['originDigest']:
                            raise ContractError('policy_client_source_changed')
                    elif (not current['projected'] or _digest(raw) != strict_loads(base64.b64decode(
                            current['state']['configurationBytes'], validate=True))['desiredPolicy']['digest']):
                        raise ContractError('policy_client_source_changed')
                    revision = current['configurationRef']['revision']
                    proposal = canonical_bytes({'format': 'amx-federation-policy-preparation-v1',
                        'target': route['target'], 'previousRevision': revision, 'originDigest': route['originDigest'],
                        'oldPolicy': _policy(raw), 'desiredPolicy': _policy(desired), 'change': change})
                    original = {'formatVersion': 2, 'requestDigest': request_digest, 'binding': enrollment, 'change': change,
                        'operationId': args.get('operationId') or 'policy_change_' + secrets.token_hex(16),
                        'revision': revision, 'phase': 'preparing', 'proposal': base64.b64encode(proposal).decode(),
                        'descriptor': None, 'finalPayload': None, 'result': None}
                    original = await self._joined(self._hub.db(self._save, enrollment, original, previous))
                else:
                    original = previous
                prepared = await self._command(session, route, 'configuration-set', original['operationId'],
                    original['revision'], self._payload(route, original['revision'],
                        base64.b64decode(original['proposal'], validate=True)),
                    args.get('preparationApprovalRefs', []), expires)
                if prepared.kind != 'prepared':
                    raise ContractError('policy_client_response_refused')
                final = self._payload(route, original['revision'], prepared.data)
                committing = {**original, 'phase': 'committing',
                    'descriptor': base64.b64encode(prepared.data).decode(), 'finalPayload': final}
                committing = await self._joined(self._hub.db(self._save, enrollment, committing, original))
                committed = await self._command(session, route, 'configuration-set', original['operationId'],
                    original['revision'], final, args.get('approvalRefs', []), expires)
                if committed.kind != 'committed':
                    raise ContractError('policy_client_response_refused')
                result = {'revision': original['revision'] + 1, 'operationId': original['operationId'], 'change': change}
                await self._joined(self._hub.db(self._save, enrollment,
                    {**committing, 'phase': 'committed', 'result': result}, committing))
                return result
        finally:
            self._calls.discard(finished)
            finished.set_result(None)

    async def close(self, *, timeout=5):
        self._closed = True
        if self._closing is None:
            async def joined():
                if self._calls or self._workers:
                    await asyncio.gather(*tuple(self._calls | self._workers), return_exceptions=True)
            self._closing = asyncio.create_task(joined(), name='policy-client:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('policy_client_cleanup_incomplete')
        self._closing.result()
