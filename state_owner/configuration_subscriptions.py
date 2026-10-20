"""Own remote configuration subscriptions and their original cleanup work."""
import asyncio
import base64
from datetime import datetime, timezone
import uuid

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import _active, _indexes, _key
from identity.configuration_subscription_control import evaluate_control


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


class _Allocation:
    def __init__(self, raw, reply_subject):
        self.raw, self.reply_subject = raw, reply_subject
        self.authority = self.lease_id = self.watch = self.cursor = self.offered = None
        self.opening = self.next_work = self.closing = self.timer = None
        self.next_digest = None
        self.deliveries = set()
        self.stop = asyncio.Event()
        self.joined = False


class ConfigurationSubscriptions:
    """One service-owned allocation per original openRequestId.

    The shared configuration command subscription transports these controls.
    Allocation proofs remain in a bounded table for this service lifetime so a
    delayed cleanup can authenticate after the original read authority expires.
    Unknown allocations never establish a successful join.
    """
    def __init__(self, owner, events):
        self._owner, self._events = owner, events
        self._entries = {}
        self._closed = False
        self._closing = None
        self.done = asyncio.Event()

    def __repr__(self):
        return '<ConfigurationSubscriptions private>'

    async def _admit(self, raw, reply_subject, entry=None, expected_cursor=None):
        action = strict_loads(raw)['claims']['action']
        snapshot = None if action == 'close' else await self._owner._authority.current()
        admission = evaluate_control(snapshot, raw, now=datetime.now(timezone.utc), reply_subject=reply_subject,
            allocation=None if entry is None else entry.authority, expected_cursor=expected_cursor,
            expected_lease_id=None if entry is None else entry.lease_id)
        return admission

    async def _allocate(self, entry):
        async with asyncio.timeout(5):
            admission = await self._admit(entry.raw, entry.reply_subject)
            if not admission.can_read:
                raise ContractError('configuration_subscription_not_authorized')
            entry.authority = admission.allocation
            claims = strict_loads(admission.claims)
            subscription = strict_loads(entry.authority.subscription)
            payload = subscription['payload']
            entry.cursor = strict_loads(canonical_bytes(claims['cursor']))
            entry.offered = entry.cursor
            entry.lease_id = 'subscription_' + uuid.uuid4().hex
            # Expiry owns admitted startup too, including a pending subscribe or
            # a failed flush. It must not depend on successful watch startup.
            entry.timer = asyncio.create_task(self._expire(entry))
            if self._closed or entry.stop.is_set():
                return
            binding = self._owner._ledger._binding
            if (payload['resourceRef']['id'] != binding.entity_id
                    or payload['resourceRef']['ownerHubId'] != binding.hub_id
                    or payload['filter']['schemaRef'] != self._owner._schema
                    or not self._owner._same_slot(payload['filter']['owner'])):
                raise ContractError('configuration_subscription_source_binding')
            position = self._events.route.position(entry.cursor)
            pin = await self._events.enrollment_pin()
            if position > pin['configurationRef']['revision']:
                raise ContractError('configuration_event_resync_required')
            await self._admit(entry.raw, entry.reply_subject, entry)
            if self._closed or entry.stop.is_set():
                return
            self._owner._require_watch_cleanup()
            if len(self._owner._watches) >= 32:
                raise ContractError('configuration_subscription_capacity')
            from .configuration import ConfigurationWatch
            entry.watch = ConfigurationWatch(self._owner)
            self._owner._watches.add(entry.watch)
            await entry.watch.start()
            if self._closed or entry.stop.is_set():
                await entry.watch.close(timeout=None)
                return

    async def _expire(self, entry):
        subscription = strict_loads(entry.authority.subscription)
        end = min(datetime.fromisoformat(subscription['operation']['deadline']),
            datetime.fromisoformat(subscription['ingressAttestation']['claims']['expiresAt']))
        remaining = max(0, (end - datetime.now(timezone.utc)).total_seconds())
        try:
            await asyncio.wait_for(entry.stop.wait(), remaining)
        except asyncio.TimeoutError:
            self._begin_close(entry)

    def _begin_close(self, entry):
        entry.stop.set()
        if entry.closing is None or (entry.closing.done() and entry.closing.exception() is not None):
            entry.closing = asyncio.create_task(self._close_entry(entry))
            # Automatic expiry has no waiting caller to retrieve a failed drain.
            entry.closing.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        return entry.closing

    async def _close_entry(self, entry):
        if entry.next_work is not None and not entry.next_work.done():
            entry.next_work.cancel()
        if entry.next_work is not None:
            await asyncio.gather(entry.next_work, return_exceptions=True)
        failures = []
        original_watch = entry.watch
        if original_watch is not None:
            try:
                await original_watch.close(timeout=None)
            except BaseException as error:
                failures.append(error)
        if entry.opening is not None:
            await asyncio.gather(entry.opening, return_exceptions=True)
        if entry.watch is not None and entry.watch is not original_watch and not entry.watch.done.is_set():
            try:
                await entry.watch.close(timeout=None)
            except BaseException as error:
                failures.append(error)
        if entry.timer is not None:
            await asyncio.gather(entry.timer, return_exceptions=True)
        deliveries = tuple(entry.deliveries)
        if deliveries:
            await asyncio.gather(*deliveries, return_exceptions=True)
        if failures:
            raise ContractError('configuration_subscription_cleanup_incomplete')
        entry.joined = True

    def _track_delivery(self, entry, task):
        if task is not None:
            entry.deliveries.add(task)
            def finished(original):
                entry.deliveries.discard(original)
                self._discard_unadmitted(entry)
            task.add_done_callback(finished)

    def _discard_unadmitted(self, entry):
        if (entry.authority is None and entry.watch is None and not entry.deliveries
                and entry.opening is not None and entry.opening.done()):
            key = strict_loads(entry.raw)['claims']['openRequestId']
            if self._entries.get(key) is entry:
                del self._entries[key]

    def _expected_cursor(self, entry, cursor):
        # A new signed next request may acknowledge the last offered event.
        # Preparing or publishing its preceding response did not advance it.
        if cursor == entry.cursor:
            return entry.cursor
        if cursor == entry.offered:
            return entry.offered
        raise ContractError('configuration_subscription_cursor_binding')

    async def _next(self, entry, cursor, end):
        remaining = (end - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise ContractError('configuration_subscription_unavailable')
        async with asyncio.timeout(min(5, remaining)):
            while not entry.stop.is_set():
                entry.watch.changed.clear()
                delivery = await self._events.next(cursor)
                if delivery is not None:
                    return delivery
                await entry.watch.changed.wait()
        raise ContractError('configuration_subscription_unavailable')

    async def handle(self, raw, *, reply_subject, delivery_task=None):
        try:
            async with asyncio.timeout(5):
                return await self._handle_control(raw, reply_subject=reply_subject, delivery_task=delivery_task)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise
        except Exception:
            raise ContractError('configuration_subscription_unavailable') from None

    async def _handle_control(self, raw, *, reply_subject, delivery_task=None):
        if self._closed or self._owner._closed or type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('configuration_subscription_unavailable')
        request = strict_loads(raw)
        validate('configuration-subscription-control', request)
        claims = request['claims']
        action, key = claims['action'], claims['openRequestId']
        if action != 'close' and hasattr(self._owner, '_host'):
            self._owner._host.check_health()
        entry = self._entries.get(key)
        if action == 'open':
            if entry is None:
                if (len(self._entries) >= 1024 or sum(not item.joined for item in self._entries.values()) >= 32
                        or self._owner._connection is None):
                    raise ContractError('configuration_subscription_capacity')
                entry = _Allocation(raw, reply_subject)
                self._entries[key] = entry
                entry.opening = asyncio.create_task(self._allocate(entry))
                def allocated(task):
                    failed = task.cancelled() or task.exception() is not None
                    if failed and entry.authority is not None:
                        self._begin_close(entry)
                    self._discard_unadmitted(entry)
                entry.opening.add_done_callback(allocated)
            self._track_delivery(entry, delivery_task)
            await asyncio.shield(entry.opening)
            if entry.stop.is_set() or entry.watch is None:
                raise ContractError('configuration_subscription_closed')
            return await self._respond(raw, reply_subject, entry, 'opened', claims['cursor'])
        if entry is None:
            raise ContractError('subscription_control_allocation_required')
        if entry.authority is None:
            # Keep the original authorization/allocation task alive if this
            # control's wait expires or is canceled.
            await asyncio.shield(entry.opening)
        if action == 'close':
            admission = await self._admit(raw, reply_subject, entry)
            if admission.can_read:
                raise ContractError('configuration_subscription_cleanup_binding')
            self._expected_cursor(entry, claims['cursor'])
            work = self._begin_close(entry)
            remaining = max(0, (admission.valid_until - datetime.now(timezone.utc)).total_seconds())
            _, pending = await asyncio.wait({work}, timeout=min(3, remaining))
            joined = not pending and entry.joined
            if not pending:
                work.result()
            return await self._respond(raw, reply_subject, entry, 'closed', claims['cursor'], joined=joined)
        if action != 'next' or entry.stop.is_set() or entry.watch is None:
            raise ContractError('configuration_subscription_closed')
        self._track_delivery(entry, delivery_task)
        expected = self._expected_cursor(entry, claims['cursor'])
        admission = await self._admit(raw, reply_subject, entry, expected)
        if not admission.can_read:
            raise ContractError('configuration_subscription_not_authorized')
        # Authorization yields. A newer next or close may have changed this
        # allocation while that snapshot was read. Admit work and acknowledge
        # its cursor together from the current local state, without an await.
        if self._closed or self._owner._closed or entry.stop.is_set():
            raise ContractError('configuration_subscription_closed')
        if hasattr(self._owner, '_host'):
            self._owner._host.check_health()
        self._owner._require_watch_cleanup()
        digest = payload_digest(request)
        if entry.next_work is not None and not entry.next_work.done():
            if entry.next_digest != digest:
                raise ContractError('configuration_subscription_busy')
        else:
            expected = self._expected_cursor(entry, claims['cursor'])
            entry.cursor = strict_loads(canonical_bytes(expected))
            entry.next_digest = digest
            entry.next_work = asyncio.create_task(self._next(entry, entry.cursor, admission.valid_until))
            entry.next_work.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        try:
            delivery = await asyncio.shield(entry.next_work)
        except ContractError as error:
            if error.code != 'configuration_event_resync_required':
                raise
            return await self._respond(raw, reply_subject, entry, 'resync-required', claims['cursor'])
        if entry.stop.is_set():
            raise ContractError('configuration_subscription_closed')
        return await self._respond(raw, reply_subject, entry, 'event', delivery.cursor, delivery=delivery)

    async def _respond(self, raw, reply_subject, entry, outcome, cursor, *, joined=None, delivery=None):
        request = strict_loads(raw)
        wanted = request['claims']
        snapshot = await self._owner._authority.current()
        admission = evaluate_control(None if wanted['action'] == 'close' else snapshot, raw,
            now=datetime.now(timezone.utc), reply_subject=reply_subject, allocation=entry.authority,
            expected_cursor=entry.cursor if wanted['action'] == 'next' else None,
            expected_lease_id=entry.lease_id)
        if wanted['action'] != 'close':
            if hasattr(self._owner, '_host'):
                self._owner._host.check_health()
            if not admission.can_read or entry.stop.is_set():
                raise ContractError('configuration_subscription_closed')
            self._owner._require_watch_cleanup()
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], record['ownerHubId'])
        issuer = index['issuers'].get(_key(strict_loads(self._owner._issuer)))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        now = datetime.now(timezone.utc)
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._owner._seed).verify_key)).decode().rstrip('=')
        if (issuer is None or identity is None or identity['kind'] != 'service'
                or not _active(issuer, now) or not _active(identity, now) or issuer['publicKey'] != public):
            raise ContractError('configuration_signer_unavailable')
        end = min(admission.valid_until, datetime.fromisoformat(issuer['expiresAt']))
        if delivery is not None:
            if not admission.can_read:
                raise ContractError('configuration_subscription_not_authorized')
            event = strict_loads(delivery.envelope)
            subscription = strict_loads(entry.authority.subscription)['payload']
            emitted = event['payload']
            if (emitted['owner'] != subscription['filter']['owner']
                    or emitted['schemaRef'] != subscription['filter']['schemaRef']
                    or any(emitted['configurationRef'][k] != subscription['resourceRef'][k] for k in ('id', 'ownerHubId'))
                    or emitted['configurationRef']['revision'] != cursor['sequence']
                    or cursor['sequence'] <= wanted['cursor']['sequence']):
                raise ContractError('configuration_subscription_event_binding')
            end = min(end, self._owner._publication_decision(snapshot, delivery.envelope))
        if not now < end:
            raise ContractError('configuration_subscription_unavailable')
        claims = {k: wanted[k] for k in ('action', 'requestId', 'openRequestId', 'owner', 'operationId',
            'approvedEnvelopeDigest', 'filterDigest', 'profileId', 'hubId', 'authorityId', 'replySubject')}
        claims.update(purpose='agentmux-configuration-subscription-response-v1', leaseId=entry.lease_id,
            cursor=cursor, previousCursor=wanted['cursor'], requestDigest=payload_digest(request),
            signingKeyRef=issuer['ref'], authorityRef={'id': record['entityId'], 'ownerHubId': record['ownerHubId'],
                'revision': record['entityVersion']}, issuedAt=_stamp(now), validUntil=_stamp(end), outcome=outcome)
        if joined is not None:
            claims['joined'] = joined
        if delivery is not None:
            claims['eventEnvelopeBytes'] = base64.b64encode(delivery.envelope).decode()
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519', 'canonicalization': 'RFC8785-JCS-UTF8',
            'claims': claims, 'signature': sign_claims(claims, self._owner._seed)}
        validate('configuration-subscription-response', response)
        encoded = canonical_bytes(response)
        if len(encoded) > 65536:
            raise ContractError('configuration_subscription_body_limit')
        if delivery is not None:
            entry.offered = strict_loads(canonical_bytes(cursor))
        return encoded

    async def _close(self):
        work = [self._begin_close(entry) for entry in self._entries.values()]
        results = await asyncio.gather(*work, return_exceptions=True)
        if any(isinstance(result, BaseException) for result in results):
            raise ContractError('configuration_subscription_cleanup_incomplete')
        self.done.set()

    async def close(self, *, timeout=3):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('configuration_subscription_cleanup_incomplete')
        self._closed = True
        if self.done.is_set():
            return
        if self._closing is None or (self._closing.done() and self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._close())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('configuration_subscription_cleanup_incomplete')
        self._closing.result()
