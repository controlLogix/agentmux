"""Owner-private dispatch and publication for preserved core work obligations.

No instance of these classes enters the Hub application process. The protected
receiver proves its own local service authority, and the Work owner separately
verifies the original publisher evidence retained by the owned subscription.
"""
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import secrets

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.core_work_transport import (INGEST, RESULT, body_route, check_authority,
    local_credential, refused, selected_route)


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


class CoreWorkDispatcher:
    """Call the existing typed owner path with an explicitly enrolled receiver."""
    def __init__(self, owner):
        from .core_work import CoreWorkOwner
        if type(owner) is not CoreWorkOwner:
            refused()
        self._owner = owner
        self._locks = {id(resource): asyncio.Lock() for resource, _ in owner._routes.values()}
        self._workers, self._active = set(), set()
        self._closed = False

    def __repr__(self):
        return '<CoreWorkDispatcher private>'

    async def _db(self, resource, function, *args):
        original = asyncio.create_task(resource._owner.db(function, *args))
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

    async def _admit(self, route, contract, payload, operation, expires):
        self._owner.check()
        receiver = route['receiver']
        grant = receiver['grantRefs'].get(contract)
        if grant is None:
            refused()
        reader, ingress = self._owner._selection.check_storage_identity_source(self._owner._identity)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': reader._hub,
            'profileId': reader._profile, 'authorityId': reader._entity,
            'transportRef': receiver['transportRef'], 'grantRef': grant,
            'operationId': operation, 'expectedVersion': payload['resourceRef']['revision'],
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': _stamp(datetime.now(timezone.utc)), 'expiresAt': _stamp(expires)}
        key = nkeys.from_seed(local_credential(self._owner._selection, route)[1])
        try:
            signature = base64.urlsafe_b64encode(key.sign(canonical_bytes(claims))).decode().rstrip('=')
        finally:
            key.wipe()
        admitted = await ingress.admit(canonical_bytes({'schemaVersion': '1.0.0',
            'claims': claims, 'signature': signature}), cancellation_ref={
                'id': 'cancel_core_' + hashlib.sha256(operation.encode()).hexdigest(),
                'ownerHubId': reader._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            refused()
        return admitted.envelope

    async def _inspect(self, resource, route, expires):
        payload = {'resourceRef': route['resourceRef'], 'input': {}}
        raw = await self._admit(route, 'federation-work-inspect', payload,
                                'core_inspect_' + secrets.token_hex(24), expires)
        reply = await resource.legacy(self._owner._authority, raw)
        if type(reply) is not dict or set(reply) != {'resourceRef'}:
            refused()
        return reply['resourceRef']

    def _record(self, resource, key):
        resource._current()
        row = resource._store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
        if row is None:
            return None
        record = strict_loads(row['v'])
        if (type(record) is not dict or set(record) != {'formatVersion', 'event', 'attempts'}
                or type(record['formatVersion']) is not int or record['formatVersion'] != 1
                or type(record['attempts']) is not list or not 1 <= len(record['attempts']) <= 32
                or canonical_bytes(record).decode() != row['v']):
            refused()
        for attempt in record['attempts']:
            if (type(attempt) is not dict or set(attempt) not in ({'original'}, {'original', 'reply'})
                    or type(attempt['original']) is not dict
                    or attempt['original']['contractId'] not in (INGEST, RESULT)
                    or attempt['original']['payload']['input']['coreTransport']['eventId'] != record['event']['eventId']
                    or attempt['original']['payload']['input']['coreTransport']['eventDigest'] != record['event']['eventDigest']):
                refused()
        return record

    async def _outcome(self, resource, route, original, current, expires):
        query = {'contractId': original['contractId'], 'operationId': original['operation']['operationId'],
                 'payloadDigest': original['operation']['payloadDigest']}
        raw = await self._admit(route, 'federation-work-outcome',
            {'resourceRef': current, 'input': query}, 'core_outcome_' + secrets.token_hex(24), expires)
        outcome = await resource.legacy(self._owner._authority, raw)
        if (type(outcome) is not dict or any(outcome.get(k) != v for k, v in query.items())):
            refused()
        if outcome.get('outcome') == 'absent':
            raise ContractError('core_work_original_outcome_unconfirmed')
        return {k: outcome[k] for k in ('outcome', 'receiptRef', 'resourceRef', 'result')}

    def _complete(self, resource, key, original, result):
        # Completion metadata cannot authorize an effect. Check the actual retained
        # owner receipt before sealing it, including when the response timed out.
        stored = resource._journal.outcome(original['operation']['operationId'],
                                            original['operation']['payloadDigest'])
        expected = None if stored is None else {**stored['reply'], 'result': stored['result']}
        if expected is None or canonical_bytes(expected) != canonical_bytes(result):
            refused()
        record = self._record(resource, key)
        if (record is None or record['attempts'][-1]['original'] != original
                or 'reply' in record['attempts'][-1]
                    and canonical_bytes(record['attempts'][-1]['reply']) != canonical_bytes(result)):
            refused()
        record['attempts'][-1]['reply'] = result
        with resource._store.tx():
            resource._store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                                      (canonical_bytes(record).decode(), key))

    async def _submit(self, resource, raw, key):
        result = await resource.legacy(self._owner._authority, raw)
        await self._db(resource, self._complete, resource, key, strict_loads(raw), result)
        return result

    async def receive(self, resource, message, handle):
        if self._closed:
            refused()
        self._owner.check()
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            ingress = self._owner._ingresses.get(id(resource))
            if ingress is None:
                refused()
            proof_raw, expires = await ingress.consume(handle)
            proof = strict_loads(proof_raw)
            body = base64.b64decode(proof['body'], validate=True)
            if message.subject != proof['subject'] or message.data != body:
                refused()
            item, contract, event_id, _ = body_route(proof['route'], body, proof['subject'])
            route = selected_route(self._owner._selection, proof['route']['routeId'])
            event = {'routeId': route['routeId'], 'eventId': event_id, 'eventDigest': proof['eventDigest'],
                     'signature': proof['signature'], 'subject': proof['subject']}
            key = 'core-work-dispatch:' + hashlib.sha256(canonical_bytes({
                'resourceBinding': strict_loads(resource._journal.binding), 'event': event})).hexdigest()
            async with self._locks[id(resource)]:
                self._owner.check()
                record = await self._db(resource, self._record, resource, key)
                if record is not None and record['event'] != event:
                    refused()
                reference = await self._inspect(resource, route, expires)
                # A retained uncertain original is query-only, even on a new
                # callback or a restarted owner. A proven conflict is zero effect.
                if record is not None:
                    last = record['attempts'][-1]
                    result = await self._outcome(resource, route, last['original'], reference, expires)
                    await self._db(resource, self._complete, resource, key, last['original'], result)
                    record = await self._db(resource, self._record, resource, key)
                    if result['outcome'] == 'applied':
                        self._owner.check()
                        if datetime.now(timezone.utc) >= expires:
                            refused()
                        return result['result']
                    if result['outcome'] != 'conflict':
                        refused()
                    if len(record['attempts']) >= 32:
                        raise ContractError('core_work_conflict_capacity')
                    # Preserve the old conflict and select a new operation only
                    # from this new genuine owned callback admission.
                    old_admission = last['original']['payload']['input']['coreTransport']['admissionId']
                    if old_admission == proof['admissionId']:
                        raise ContractError('core_work_revision_conflict')
                    reference = result['resourceRef']
                selector = {k: proof[k] for k in ('eventId', 'eventDigest', 'subject', 'signature', 'admissionId')}
                selector['routeId'] = route['routeId']
                payload = {'resourceRef': reference, 'attribution': 'federation',
                           'input': {'envelope': item, 'coreTransport': selector}}
                operation = 'core_work_' + secrets.token_hex(24)
                raw = await self._admit(route, contract, payload, operation, expires)
                # The concrete owner checks publisher proof before intent storage,
                # and again on its original transaction's final commit boundary.
                await resource.authorize_legacy(self._owner._authority, raw)
                original = strict_loads(raw)
                def retain():
                    self._owner.check()
                    previous = self._record(resource, key)
                    if (previous is None) != (record is None) or previous is not None and previous != record:
                        refused()
                    updated = {'formatVersion': 1, 'event': event,
                               'attempts': ([] if previous is None else previous['attempts']) + [{'original': original}]}
                    with resource._store.tx():
                        resource._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) '
                            'ON CONFLICT(k) DO UPDATE SET v=excluded.v', (key, canonical_bytes(updated).decode()))
                await self._db(resource, retain)
                worker = asyncio.create_task(self._submit(resource, raw, key), name='core-work:original-effect')
                self._workers.add(worker)
                def finished(done):
                    self._workers.discard(done)
                    if not done.cancelled():
                        done.exception()
                worker.add_done_callback(finished)
                try:
                    result = await asyncio.shield(worker)
                finally:
                    if worker.done():
                        self._workers.discard(worker)
                self._owner.check()
                if datetime.now(timezone.utc) >= expires:
                    refused()
                if result['outcome'] != 'applied':
                    raise ContractError('core_work_revision_conflict')
                return result['result']
        finally:
            if not completion.done():
                completion.set_result(None)
            self._active.discard(completion)

    async def join(self):
        pending = {*self._workers, *self._active}
        if pending:
            await asyncio.wait(pending)
        self._workers = {worker for worker in self._workers if not worker.done()}

    async def close(self):
        self._closed = True
        await self.join()


class CoreWorkOutbox:
    """Publish only original work/result rows from this exact selected owner."""
    def __init__(self, owner):
        self._owner = owner
        self._lock = asyncio.Lock()
        self._active = set()
        self._last_error = None
        self._scan_after = {}
        self._scan_end = {}

    def __repr__(self):
        return '<CoreWorkOutbox private>'

    def _rows(self, resource):
        self._owner.check()
        resource._current()
        # One bounded window per resource and pass. Advance over rows owned by
        # another route; repeatedly reading the same prefix would starve this one.
        after = self._scan_after.get(id(resource), 0)
        end = self._scan_end.get(id(resource))
        if end is None:
            end = resource._store.q1('SELECT COALESCE(MAX(seq),0) AS seq FROM nats_outbox')['seq']
            self._scan_end[id(resource)] = end
        rows = resource._store.q('SELECT seq,subject,payload,created FROM nats_outbox '
            "WHERE seq>? AND seq<=? AND sent IS NULL AND (subject LIKE 'am.work.%' OR subject LIKE 'am.result.%') "
            'ORDER BY seq LIMIT 32', (after, end))
        self._scan_after[id(resource)] = rows[-1]['seq'] if rows else 0
        if len(rows) < 32 or rows[-1]['seq'] >= end:
            # A finite cycle also revisits earlier unresolved rows when new rows
            # keep arriving. New arrivals belong to the next cycle.
            self._scan_after[id(resource)] = 0
            self._scan_end.pop(id(resource), None)
        return rows

    def _route(self, resource, row):
        body = row['payload'].encode()
        matches = []
        for rid, (candidate, _) in self._owner._routes.items():
            if candidate is not resource or rid not in self._owner._publishers:
                continue
            route = selected_route(self._owner._selection, rid)
            try:
                item, contract, _, _ = body_route(route, body, row['subject'], publisher=True)
            except (ContractError, ValueError, KeyError):
                continue
            if contract == RESULT:
                origin = route['peer']['nodeId'] + ':' + item['origin_id']
                retained = resource._store.q('SELECT repo FROM work_items WHERE origin=?', (origin,))
                if len(retained) != 1 or retained[0]['repo'] != resource.repository:
                    continue
            matches.append((rid, route, contract))
        if not matches:
            return None
        # A shared role publication may have several peer routes, but only one
        # exact local publisher may claim a single original row.
        bindings = {canonical_bytes({k: route[k] for k in ('scope', 'repository', 'localNode',
            'accountPublicKey', 'connection', 'publisher')}) for _, route, _ in matches}
        if len(bindings) != 1:
            refused()
        return sorted(matches, key=lambda candidate: candidate[0])[0]

    def _retain(self, resource, row, route, deadline):
        self._owner.check()
        resource._current()
        original = resource._store.q1('SELECT seq,subject,payload,created,sent FROM nats_outbox WHERE seq=?',
                                      (row['seq'],))
        if original is None or original['sent'] is not None or {k: original[k] for k in row} != row:
            refused()
        binding = {'resourceBinding': strict_loads(resource._journal.binding),
                   'source': resource._owner._source._pins,
                   'route': route}
        key = 'core-work-outbox:' + hashlib.sha256(canonical_bytes({
            'resourceBinding': binding['resourceBinding'], 'sequence': row['seq']})).hexdigest()
        record = {'formatVersion': 1, 'binding': binding, 'row': row,
                  'deadline': _stamp(deadline), 'state': 'pending'}
        previous = resource._store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
        if previous is not None:
            saved = strict_loads(previous['v'])
            if (type(saved) is not dict or set(saved) != set(record) or saved['formatVersion'] != 1
                    or saved['binding'] != binding or saved['row'] != row
                    or saved['state'] not in ('pending', 'uncertain', 'confirmed')
                    or canonical_bytes(saved).decode() != previous['v']):
                refused()
            if datetime.now(timezone.utc) >= datetime.fromisoformat(saved['deadline']):
                raise ContractError('core_work_publication_unconfirmed')
            return key, saved
        if datetime.now(timezone.utc) >= deadline:
            refused()
        with resource._store.tx():
            resource._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                                      (key, canonical_bytes(record).decode()))
        return key, record

    def _mark(self, resource, key, expected, state, deadline):
        resource._current()
        row = resource._store.q1('SELECT v FROM fed_state WHERE k=?', (key,))
        if row is None or row['v'] != canonical_bytes(expected).decode():
            refused()
        if state == 'confirmed':
            self._owner.check()
            if datetime.now(timezone.utc) >= min(deadline, datetime.fromisoformat(expected['deadline'])):
                refused()
        updated = {**expected, 'state': state}
        with resource._store.tx():
            if state == 'confirmed':
                original = expected['row']
                current = resource._store.q1('SELECT seq,subject,payload,created,sent FROM nats_outbox WHERE seq=?',
                                             (original['seq'],))
                if current is None or current['sent'] is not None or {k: current[k] for k in original} != original:
                    refused()
                from hub.store import now
                resource._store.db.execute('UPDATE nats_outbox SET sent=? WHERE seq=? AND sent IS NULL',
                                           (now(), original['seq']))
            resource._store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                                      (canonical_bytes(updated).decode(), key))
        return updated

    async def drain(self):
        self._owner.check()
        self._last_error = None
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            async with self._lock:
                resources = {id(resource): resource for resource, _ in self._owner._routes.values()}
                for resource in resources.values():
                    rows = await self._owner._dispatcher._db(resource, self._rows, resource)
                    for row in rows:
                        selected = await self._owner._dispatcher._db(resource, self._route, resource, row)
                        if selected is None:
                            continue
                        rid, route, contract = selected
                        _, deadline = await check_authority(self._owner._selection, self._owner._identity,
                            route_id=rid, contract=contract, publisher=True)
                        try:
                            key, original = await self._owner._dispatcher._db(
                                resource, self._retain, resource, row, route, deadline)
                        except ContractError as error:
                            if error.code != 'core_work_publication_unconfirmed':
                                raise
                            # Retain the expired original unchanged. Its unresolved
                            # delivery must not stop a later independent obligation.
                            self._last_error = error.code
                            continue
                        deadline = min(deadline, datetime.fromisoformat(original['deadline']))
                        try:
                            # Repetition sends the identical retained event, never
                            # a new Work command or a replacement outbox payload.
                            await self._owner._publishers[rid].publish(row['subject'], row['payload'].encode(),
                                                                    expires=deadline)
                            _, current_deadline = await check_authority(self._owner._selection,
                                self._owner._identity, route_id=rid, contract=contract, publisher=True)
                            await self._owner._dispatcher._db(resource, self._mark,
                                resource, key, original, 'confirmed', min(deadline, current_deadline))
                        except BaseException:
                            await self._owner._dispatcher._db(resource, self._mark,
                                resource, key, original, 'uncertain', deadline)
                            raise
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def run(self):
        while not self._owner._closed:
            if not self._owner._policy_paused:
                try:
                    await self.drain()
                except ContractError as error:
                    self._last_error = error.code
                except (OSError, TimeoutError):
                    self._last_error = 'core_work_publication_unconfirmed'
            await asyncio.sleep(.5)

    async def join(self):
        if self._active:
            # A cancelled observer cannot cancel the original drain markers.
            await asyncio.wait(set(self._active))
