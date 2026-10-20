"""Authenticated configuration over one retained owner; notifications are hints.

The host supplies admitted package schema bytes and enrolled identity/transport.
This module never creates streams, grants access, stores secret values separately,
or treats a notification, KV value or cached snapshot as authority.
"""
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import re
from urllib.parse import urljoin
import uuid

from jsonschema import Draft202012Validator
from nacl.signing import SigningKey
from nats.aio.client import Client as NatsClient
from nats.aio.subscription import Subscription as NatsSubscription
from referencing import Registry, Resource

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate, verify_envelope
from identity.authority import AuthorityReader, _active, _key, evaluate_snapshot, _indexes
from identity.ingress import verify_possession
from identity.native_records import validate_native_lineage
from identity.configuration_events import ConfigurationEventProducer, PreparedConfigurationEvent
from .configuration_events import change_payload, event_intent, retained_event
from .configuration_watch_control import ConfigurationWatchControls, PURPOSE as WATCH_CLOSE_PURPOSE
from .ledger import OwnerLedger, validate_record

COMMANDS = ('configuration-read', 'configuration-set', 'configuration-watch')


def _stamp(now):
    return now.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _callback_worker(subscription):
    worker = getattr(subscription, '_wait_for_msgs_task', None)
    if ((isinstance(subscription, NatsSubscription) or worker is not None)
            and not isinstance(worker, asyncio.Task)):
        raise ContractError('configuration_cleanup_incomplete')
    return worker


def _subscription_ownership(subscription, connection, previous=None):
    worker = _callback_worker(subscription)
    identifier = None
    if isinstance(subscription, NatsSubscription):
        identifier = subscription._id
        if (subscription._conn is not connection or type(identifier) is not int or identifier <= 0):
            raise ContractError('configuration_cleanup_incomplete')
    if previous is not None:
        original, transport, original_id, original_worker = previous
        if (subscription is not original or connection is not transport
                or identifier != original_id or worker is not original_worker):
            raise ContractError('configuration_cleanup_incomplete')
        return previous
    return subscription, connection, identifier, worker


def _require_subscription_detached(ownership):
    subscription, connection, identifier, _ = ownership
    if isinstance(connection, NatsClient) and (identifier in connection._subs
            or any(item is subscription for item in connection._subs.values())):
        raise ContractError('configuration_cleanup_incomplete')


async def _drain_subscription(ownership):
    subscription, connection, identifier, _ = ownership
    _subscription_ownership(subscription, connection, ownership)
    if isinstance(subscription, NatsSubscription) and connection.is_closed:
        # Connection close can remove the subscription before its original
        # callback finishes. Its owner still has to join that callback below.
        if not isinstance(connection, NatsClient):
            raise ContractError('configuration_cleanup_incomplete')
        _require_subscription_detached(ownership)
        return
    if isinstance(connection, NatsClient) and (connection._subs.get(identifier) is not subscription
            or sum(item is subscription for item in connection._subs.values()) != 1):
        raise ContractError('configuration_cleanup_incomplete')
    if isinstance(subscription, NatsSubscription) and subscription._closed:
        # The pinned drain sets _closed even when unsubscribe or flush fails.
        # Retry that same subscription's unfinished drain, including subclasses.
        if (not isinstance(connection, NatsClient) or connection.is_draining
                or connection._subs.get(identifier) is not subscription):
            raise ContractError('configuration_cleanup_incomplete')
        await subscription._drain()
    else:
        await subscription.drain()
    _subscription_ownership(subscription, connection, ownership)
    _require_subscription_detached(ownership)


async def _join_callback_worker(worker):
    if worker is not None:
        if worker is asyncio.current_task():
            raise ContractError('configuration_cleanup_incomplete')
        # The pinned SDK cancels this task during drain without awaiting it.
        # Waiting here never cancels or replaces the original callback worker.
        await asyncio.wait({worker})
        if not worker.cancelled():
            worker.result()


class ConfigurationWatch:
    """Own the original subscription allocation and drain, including failed close."""
    def __init__(self, source):
        self.source, self.changed, self.done = source, asyncio.Event(), asyncio.Event()
        self.subscription = None
        self._allocation = asyncio.create_task(source._connection.subscribe(source._ledger._subject,
            cb=self._hint, pending_msgs_limit=32, pending_bytes_limit=32 * 65_536))
        self._closing = None
        self._worker = None
        self._ownership = None
        self._drained = False

    def _retain_subscription(self, subscription):
        if self.subscription is not None and self.subscription is not subscription:
            raise ContractError('configuration_cleanup_incomplete')
        self.subscription = subscription
        self._ownership = _subscription_ownership(subscription, self.source._connection, self._ownership)
        self._worker = self._ownership[3]

    async def _hint(self, message):
        # A rejected conditional publish may also be visible on core NATS.
        # Ignore all message fields; only a new retained ledger revision counts.
        self.changed.set()

    async def start(self):
        self._retain_subscription(await asyncio.shield(self._allocation))
        await self.source._connection.flush()

    async def _close(self):
        self._retain_subscription(await asyncio.shield(self._allocation))
        if not self._drained:
            await _drain_subscription(self._ownership)
            self._drained = True
        await _join_callback_worker(self._worker)
        _subscription_ownership(self.subscription, self.source._connection, self._ownership)
        _require_subscription_detached(self._ownership)
        self.done.set()
        self.source._watches.discard(self)

    async def close(self, *, timeout=3):
        if self.done.is_set():
            return
        if self._closing is None or (self._closing.done() and self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._close())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('configuration_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            raise ContractError('configuration_cleanup_incomplete') from None


class ConfigurationOwner:
    def __init__(self, authority, ledger, *, owner, schema_ref, schema_resources,
                 issuer_ref, signing_seed, connection=None, require_native_activation=True,
                 event_producer=None, event_start_revision=1):
        try:
            if (not isinstance(authority, AuthorityReader) or not isinstance(ledger, OwnerLedger)
                    or not ledger.completion_budget_required
                    or ledger._binding.owner_domain != 'configuration'
                    or ledger._binding.entity_kind != 'configuration'
                    or authority._hub != ledger._binding.hub_id
                    or authority._organization != strict_loads(ledger._binding.scope)['organizationId']
                    or type(signing_seed) is not bytes or len(signing_seed) != 32
                    or type(require_native_activation) is not bool
                    or type(event_start_revision) is not int or not 1 <= event_start_revision <= 9007199254740991
                    or type(schema_resources) is not dict or not 1 <= len(schema_resources) <= 64):
                raise ValueError()
            owner = strict_loads(canonical_bytes(owner))
            validate('configuration-read', {'configurationRef': {'id': ledger._binding.entity_id,
                'ownerHubId': ledger._binding.hub_id, 'revision': 0}, 'owner': owner})
            base = 'https://schemas.agentmux.invalid/package/' + owner['pin']['packageChecksum'][7:] + '/'
            resources = []
            total = 0
            for name, raw in schema_resources.items():
                if not isinstance(name, str) or type(raw) is not bytes:
                    raise ValueError()
                total += len(raw)
                if total > 262144:
                    raise ValueError()
                body = strict_loads(raw)
                if body.get('$schema', 'https://json-schema.org/draft/2020-12/schema') != 'https://json-schema.org/draft/2020-12/schema':
                    raise ValueError()
                body.setdefault('$schema', 'https://json-schema.org/draft/2020-12/schema')
                Draft202012Validator.check_schema(body)
                resources.append((urljoin(base, name), Resource.from_contents(body)))
            def unavailable(uri):
                raise ValueError()
            registry = Registry(retrieve=unavailable).with_resources(resources)
            location = urljoin(base, schema_ref)
            registry.resolver().lookup(location)
            self._validator = Draft202012Validator({'$ref': location}, registry=registry)
            self._owner, self._schema = canonical_bytes(owner), schema_ref
            self._authority, self._ledger = authority, ledger
            self._require_native_activation = require_native_activation
            if event_producer is not None and (not isinstance(event_producer, ConfigurationEventProducer)
                    or event_producer._authority is not authority or event_producer._hub != ledger._binding.hub_id
                    or event_producer._configuration != ledger._binding.entity_id
                    or event_producer._scope != ledger._binding.scope
                    or event_producer._ingress._issuer_ref != canonical_bytes(issuer_ref)
                    or event_producer._ingress._seed != signing_seed):
                raise ValueError()
            self._event_producer, self._event_start_revision = event_producer, event_start_revision
            self._publications = set()
            self._publication_handed, self._publication_failures = set(), {}
            self._subscription_service = None
            self._issuer, self._seed = canonical_bytes(issuer_ref), signing_seed
            self._connection = connection
            self._watches, self._active, self._requests = set(), set(), set()
            self._cleanup_requests = set()
            self._closed = False
            self._watch_controls = ConfigurationWatchControls(self)
            self.done = asyncio.Event()
            self._subscribe_task = self._subscription = self._closing = None
            self._subscription_worker = None
            self._subscription_ownership = None
            self._subscription_drained = False
            scope = strict_loads(ledger._binding.scope)
            self.subject = '.'.join(('amx', 'v1', 'h', ledger._binding.hub_id,
                'o', scope['organizationId'], 'p', scope['projectId'] or '_',
                'w', scope['workspaceId'] or '_', 'configuration', ledger._binding.entity_id, 'command'))
        except Exception:
            raise ContractError('configuration_owner_configuration') from None

    def __repr__(self):
        return '<ConfigurationOwner private>'

    async def start(self, *, reply_prefix):
        """Use only the host's enrolled connection, exact subject and reply scope."""
        if (self._closed or self._subscribe_task is not None or self._connection is None
                or not isinstance(reply_prefix, str)
                or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.', reply_prefix)):
            raise ContractError('configuration_service_configuration')
        self._reply_prefix = reply_prefix
        if self._ledger._history is not None:
            while not self._closed:
                if (await self._ledger.prepare_history()).ready:
                    break
                await asyncio.sleep(0)
        if self._closed:
            raise ContractError('configuration_owner_closed')
        self._subscribe_task = asyncio.create_task(self._connection.subscribe(self.subject,
            cb=self._receive, pending_msgs_limit=32, pending_bytes_limit=32 * 65536))
        self._subscription = await asyncio.shield(self._subscribe_task)
        self._subscription_ownership = _subscription_ownership(
            self._subscription, self._connection, self._subscription_ownership)
        self._subscription_worker = self._subscription_ownership[3]
        await asyncio.wait_for(self._connection.flush(), 3)

    async def _receive(self, message):
        if (self._closed or not isinstance(message.reply, str) or len(message.reply) > 512
                or not message.reply.startswith(self._reply_prefix)
                or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*', message.reply)):
            return
        cleanup = False
        if type(message.data) is bytes and len(message.data) <= 65536:
            try:
                claims = strict_loads(message.data).get('claims', {})
                cleanup = (claims.get('purpose') == WATCH_CLOSE_PURPOSE
                    or self._subscription_service is not None
                    and claims.get('purpose') == 'agentmux-configuration-subscription-control-v1'
                    and claims.get('action') == 'close')
            except Exception:
                pass
        # Cleanup has separate bounded capacity so pending read/reply workers
        # cannot prevent an authenticated close from joining those workers.
        if cleanup:
            if len(self._cleanup_requests) >= 32:
                return
        elif len((self._requests | self._active) - self._cleanup_requests) >= 32:
            return
        # The SDK invokes callbacks serially. A watch must release that worker
        # so a later write can commit the revision it is waiting to observe.
        task = asyncio.create_task(self._deliver(message.data, message.reply))
        self._requests.add(task)
        if cleanup:
            self._cleanup_requests.add(task)
        def finished(original):
            self._requests.discard(original)
            self._cleanup_requests.discard(original)
            if not original.cancelled():
                original.exception()
        task.add_done_callback(finished)

    async def _deliver(self, raw, reply):
        try:
            if type(raw) is not bytes or len(raw) > 65536:
                return
            message = strict_loads(raw)
            if message.get('claims', {}).get('purpose') == WATCH_CLOSE_PURPOSE:
                response = await self._watch_controls.handle(raw, reply_subject=reply)
            elif (self._subscription_service is not None
                    and message.get('claims', {}).get('purpose') == 'agentmux-configuration-subscription-control-v1'):
                response = await self._subscription_service.handle(raw, reply_subject=reply,
                    delivery_task=asyncio.current_task())
            else:
                response = await self.handle(raw)
            if not self._closed:
                await asyncio.wait_for(self._connection.publish(reply, response), 3)
                await asyncio.wait_for(self._connection.flush(), 3)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Fixed refusal through transport timeout; never publish private errors.
            pass

    def _document(self, state):
        validate('configuration-state', state)
        if not self._same_slot(state['owner']) or state['schemaRef'] != self._schema:
            raise ContractError('configuration_binding_mismatch')
        try:
            raw = base64.b64decode(state['configurationBytes'], validate=True)
            if (not 1 <= len(raw) <= 16384 or base64.b64encode(raw).decode() != state['configurationBytes']
                    or _digest(raw) != state['configurationChecksum']):
                raise ValueError()
            value = strict_loads(raw)
            self._validator.validate(value)
        except Exception:
            raise ContractError('configuration_value_invalid') from None
        return raw

    async def _authorize(self, raw, envelope):
        if self._closed:
            raise ContractError('configuration_owner_closed')
        snapshot = await self._authority.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw,
            audience={'hubId': self._ledger._binding.hub_id, 'serviceId': 'configuration-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(envelope['operation'])
                or decision.valid_until is None or not now < decision.valid_until
                or canonical_bytes(envelope['operation']['scope']) != self._ledger._binding.scope):
            raise ContractError('configuration_access_refused')
        return decision, snapshot

    def _target(self, payload):
        ref = payload['configurationRef']
        if (ref['id'] != self._ledger._binding.entity_id or ref['ownerHubId'] != self._ledger._binding.hub_id
                or not self._same_slot(payload['owner'])):
            raise ContractError('configuration_binding_mismatch')

    def _same_slot(self, owner):
        admitted = strict_loads(self._owner)
        return owner['pin'] == admitted['pin'] and owner['instanceId'] == admitted['instanceId']

    def _activation(self, snapshot, envelope, state):
        """Require the current retained activation before changing full owners."""
        authority = strict_loads(snapshot.record)
        rows = [row for row in authority['state'].get('nativeInstances', [])
                if self._same_slot(row['owner']) and row['status'] == 'active']
        operation = envelope['operation']
        if len(rows) != 1:
            raise ContractError('configuration_binding_mismatch')
        row, = rows
        facts = row['facts']
        if (row['owner'] != state['owner'] or row['configurationChecksum'] != state['configurationChecksum']
                or facts['configurationRevision'] != state['revision']
                or facts['secretReferences'] != state['secretReferences']
                or canonical_bytes(facts['grant']['scope']) != self._ledger._binding.scope
                or operation['caller']['kind'] != 'service'
                or operation['caller']['authenticatedIdentityRef'] != row['hostIdentityRef']
                or operation['effectiveActorRef'] != row['hostIdentityRef']):
            raise ContractError('configuration_binding_mismatch')
        now = datetime.now(timezone.utc)
        method = ('prepare-configuration-initialization' if envelope['contractId'] == 'configuration-set'
            else 'prepare-configuration-request')
        grants = [grant for grant in authority['state']['grants']
            if grant['status'] == 'active' and grant['callerRef'] == row['hostIdentityRef']
            and grant['actorRef'] == row['hostIdentityRef'] and grant['scope'] == operation['scope']
            and grant['contractId'] == 'native-authority-' + method
            and grant['resourceId'] == row['owner']['instanceId'] and grant['delegationRef'] is None]
        active = [grant for grant in grants if _active(grant, now)]
        if (any(grant['decision'] == 'denied' for grant in active)
                or not any(grant['decision'] == 'allowed' for grant in active)):
            raise ContractError('configuration_initialization_not_authorized' if envelope['contractId'] == 'configuration-set'
                else 'configuration_native_not_authorized')
        end = validate_native_lineage(authority['state'],
            _indexes(authority['state'], authority['ownerHubId']), row, now)
        # Bound the append by expiry or a scheduled denial of this separate
        # method authority, even when ordinary set authority lasts longer.
        for grant in grants:
            for name in ('issuedAt', 'expiresAt'):
                boundary = datetime.fromisoformat(grant[name])
                if boundary > now:
                    end = min(end, boundary)
        return end

    def _requires_activation(self, snapshot, state):
        return (self._require_native_activation or canonical_bytes(state['owner']) != self._owner
            or any(self._same_slot(row['owner'])
                for row in strict_loads(snapshot.record)['state'].get('nativeInstances', [])))

    async def prepare_initialization(self, *, owner, configuration_bytes, secret_references):
        """Return a proposal for the host to authorize through configuration-set.

        This reads the retained revision and validates supplied values. It does
        not admit an activation, grant authority, or change configuration.
        """
        if (self._closed or type(configuration_bytes) is not bytes
                or not 1 <= len(configuration_bytes) <= 16384 or len(self._active) >= 32):
            raise ContractError('configuration_unavailable')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with asyncio.timeout(5):
                snapshot = await self._ledger.current()
                if self._closed:
                    raise ContractError('configuration_owner_closed')
                if snapshot.latest is not None:
                    self._retained(snapshot.latest)
                payload = {'configurationRef': {'id': self._ledger._binding.entity_id,
                    'ownerHubId': self._ledger._binding.hub_id, 'revision': snapshot.sequence},
                    'owner': owner, 'schemaRef': self._schema,
                    'configurationBytes': base64.b64encode(configuration_bytes).decode(),
                    'secretReferences': secret_references}
                validate('configuration-set', payload)
                self._target(payload)
                self._document({'format': 'amx-configuration-v1', 'owner': owner, 'schemaRef': self._schema,
                    'configurationBytes': payload['configurationBytes'], 'secretReferences': secret_references,
                    'configurationChecksum': _digest(configuration_bytes), 'revision': snapshot.sequence + 1})
                return strict_loads(canonical_bytes(payload))
        finally:
            self._active.discard(task)

    def _retained(self, stored):
        record = validate_record(stored.record, self._ledger._binding)
        state = record['state']
        self._document(state)
        if (record['outcome'] != 'committed' or state['revision'] != stored.sequence
                or record['artifacts'] != self._record_artifacts(state) or record['repository'] is not None
                or record.get('authorizationDecision') != {'operationId': record['operation']['operationId'],
                    'decision': 'allowed', 'reason': 'authorized', 'actorRef': record['operation']['effectiveActorRef'],
                    'contractId': 'configuration-set'}):
            raise ContractError('configuration_history_invalid')
        if self._event_producer is not None or self._require_native_activation:
            raw = retained_event(record, self._ledger._binding, start_revision=self._event_start_revision)
            if raw is not None:
                if self._event_producer is None:
                    raise ContractError('configuration_event_producer_required')
                event = strict_loads(raw)
                self._event_pins(event)
                verify_envelope(event, bytes(SigningKey(self._seed).verify_key),
                    {'hubId': self._ledger._binding.hub_id, 'serviceId': 'configuration-owner'},
                    datetime.fromisoformat(record['recordedAt']))
        elif record['effects']:
            raise ContractError('configuration_history_invalid')
        return state

    def _record_artifacts(self, state):
        # Ordinary plugin configuration has no artifact custody. A typed domain
        # specialization must derive its exact retained references from state.
        return []

    def _event_pins(self, event):
        producer, operation = self._event_producer, event['operation']
        claims = event['ingressAttestation']['claims']
        if (producer is None or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != producer._identity
                or canonical_bytes(operation['effectiveActorRef']) != producer._identity
                or canonical_bytes(operation['grantRef']) != producer._grant
                or canonical_bytes(claims['authenticatedTransportRef']) != producer._transport
                or canonical_bytes(claims['signingKeyRef']) != self._issuer):
            raise ContractError('configuration_event_binding')

    async def _authorize_publication(self, raw):
        if self._closed:
            raise ContractError('configuration_owner_closed')
        event = strict_loads(raw)
        self._event_pins(event)
        snapshot = await self._authority.current()
        return self._publication_decision(snapshot, raw)

    def _publication_decision(self, snapshot, raw):
        event = strict_loads(raw)
        self._event_pins(event)
        now = datetime.now(timezone.utc)
        if now >= min(datetime.fromisoformat(event['operation']['deadline']),
                datetime.fromisoformat(event['ingressAttestation']['claims']['expiresAt'])):
            raise ContractError('configuration_event_resync_required')
        decision = evaluate_snapshot(snapshot, raw,
            audience={'hubId': self._ledger._binding.hub_id, 'serviceId': 'configuration-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.valid_until is None
                or canonical_bytes(event['operation']['scope']) != self._ledger._binding.scope):
            raise ContractError('configuration_event_publication_not_authorized')
        return decision.valid_until

    async def _current(self, minimum):
        snapshot = await self._ledger.current()
        if snapshot.latest is None or snapshot.sequence < minimum:
            raise ContractError('configuration_unavailable')
        return self._retained(snapshot.latest)

    def _require_watch_cleanup(self):
        # Open healthy watches may coexist. A started close must finish on its
        # original subscription before a read can authorize another watch.
        if any(watch._closing is not None and not watch.done.is_set() for watch in self._watches):
            raise ContractError('configuration_cleanup_incomplete')

    async def handle(self, raw):
        if self._closed or type(raw) is not bytes or len(raw) > 65536 or len(self._active) >= 32:
            raise ContractError('configuration_unavailable')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if envelope['contractId'] != 'configuration-watch' or not self._require_native_activation:
            return await self._handle(raw)
        validate('configuration-watch', envelope['payload'])
        self._target(envelope['payload'])
        current = asyncio.current_task()
        delivery = current if current in self._requests else None
        entry = self._watch_controls.reserve(envelope, delivery)
        handler = asyncio.create_task(self._handle(raw, watch_entry=entry))
        self._watch_controls.retain_handler(entry, handler)
        try:
            return await asyncio.shield(handler)
        except asyncio.CancelledError:
            # Retain the original handler through authorization and cleanup.
            # Its caller disappearing does not cancel its subscription owner.
            self._watch_controls.begin_close(entry)
            raise

    async def _handle(self, raw, *, watch_entry=None):
        if self._closed or type(raw) is not bytes or len(raw) > 65536 or len(self._active) >= 32:
            raise ContractError('configuration_unavailable')
        task = asyncio.current_task()
        self._active.add(task)
        watch = None
        cleanup_started = False
        try:
            async with asyncio.timeout(5) as budget:
                envelope = strict_loads(raw)
                validate('message-envelope', envelope)
                contract = envelope['contractId']
                if contract not in COMMANDS:
                    raise ContractError('configuration_contract_invalid')
                payload = envelope['payload']
                validate(contract, payload)
                self._target(payload)
                decision, authority = await self._authorize(raw, envelope)
                if contract == 'configuration-watch':
                    # Request preparation has already spent part of the caller's
                    # budget. Begin cleanup at its authenticated deadline rather
                    # than starting another full wait after server receipt.
                    remaining = (decision.valid_until - datetime.now(timezone.utc)).total_seconds()
                    budget.reschedule(min(budget.when(), asyncio.get_running_loop().time() + max(0, remaining)))
                    if watch_entry is not None:
                        current = await self._current(payload['configurationRef']['revision'])
                        if current['owner'] != payload['owner']:
                            raise ContractError('configuration_binding_mismatch')
                        decision, authority = await self._authorize(raw, envelope)
                        until = min(decision.valid_until, self._activation(authority, envelope, current))
                        remaining = (until - datetime.now(timezone.utc)).total_seconds()
                        if remaining <= 0:
                            raise ContractError('configuration_watch_expired')
                        budget.reschedule(min(budget.when(), asyncio.get_running_loop().time() + remaining))
                        self._watch_controls.admit(watch_entry, authority, envelope)
                if contract == 'configuration-set':
                    state = await self._set(raw, envelope)
                else:
                    self._require_watch_cleanup()
                    if contract == 'configuration-watch':
                        if self._connection is None or len(self._watches) >= 32:
                            raise ContractError('configuration_unavailable')
                        watch = ConfigurationWatch(self)
                        if watch_entry is not None:
                            watch_entry.watch = watch
                        self._watches.add(watch)
                        await watch.start()
                    while True:
                        if watch is not None:
                            watch.changed.clear()
                        state = await self._current(payload['configurationRef']['revision'])
                        if state['owner'] != payload['owner']:
                            raise ContractError('configuration_binding_mismatch')
                        if watch is None or state['revision'] > payload['afterRevision']:
                            break
                        if state['revision'] < payload['afterRevision']:
                            raise ContractError('configuration_revision_conflict')
                        await watch.changed.wait()
                        if self._closed:
                            raise ContractError('configuration_owner_closed')
                if watch is not None:
                    cleanup_started = True
                    await watch.close()
                    watch = None
                # No watch cleanup may delay disclosure after this final current
                # authority check and signature. The request stays owned above.
                return await self._reply(raw, envelope, state)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise
        except Exception:
            raise ContractError('configuration_unavailable') from None
        finally:
            try:
                if watch is not None and not cleanup_started:
                    await watch.close()
            finally:
                self._active.discard(task)

    async def _set(self, raw, envelope):
        operation, payload = envelope['operation'], envelope['payload']
        existing = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
        if existing is not None:
            if canonical_bytes(strict_loads(existing.record)['operation']) != canonical_bytes(operation):
                raise ContractError('owner_operation_conflict')
            return await self._confirmed(existing)
        if self._publication_failures:
            raise ContractError('configuration_event_publication_uncertain')
        snapshot = await self._ledger.current()
        if snapshot.sequence != operation['expectedVersion']:
            raise ContractError('configuration_revision_conflict')
        previous = None if snapshot.latest is None else self._retained(snapshot.latest)
        encoded = payload['configurationBytes']
        try:
            checksum = _digest(base64.b64decode(encoded, validate=True))
        except Exception:
            raise ContractError('configuration_value_invalid') from None
        state = {'format': 'amx-configuration-v1', 'owner': payload['owner'],
            'schemaRef': payload['schemaRef'], 'configurationBytes': encoded,
            'secretReferences': payload['secretReferences'], 'configurationChecksum': checksum,
            'revision': snapshot.sequence + 1}
        self._document(state)
        decision, authority = await self._authorize(raw, envelope)
        valid_until = decision.valid_until
        if (self._requires_activation(authority, state)
                or previous is not None and previous['owner'] != state['owner']):
            valid_until = min(valid_until, self._activation(authority, envelope, state))
        effects = []
        if self._event_producer is not None:
            prepared = await self._event_producer.prepare_change_event(
                change_payload(self._ledger._binding, state), operation=operation)
            if not isinstance(prepared, PreparedConfigurationEvent):
                raise ContractError('configuration_event_invalid')
            effects = [event_intent(prepared.envelope)]
            valid_until = min(valid_until, prepared.valid_until)
            # Producer signing reads authority too. Recheck set/native authority
            # after it returns so their revocation cannot cross this await.
            decision, authority = await self._authorize(raw, envelope)
            valid_until = min(valid_until, decision.valid_until)
            valid_until = min(valid_until, self._publication_decision(authority, prepared.envelope))
            if self._requires_activation(authority, state) or previous is not None and previous['owner'] != state['owner']:
                valid_until = min(valid_until, self._activation(authority, envelope, state))
        elif self._require_native_activation:
            raise ContractError('configuration_event_producer_required')
        if snapshot.sequence + 1 < self._event_start_revision and effects:
            raise ContractError('configuration_event_coverage_invalid')
        binding = self._ledger._binding
        record = {'schemaVersion': '1.0.0', 'recordId': 'configuration-' + uuid.uuid4().hex,
            'entityId': binding.entity_id, 'entityKind': binding.entity_kind,
            'ownerHubId': binding.hub_id, 'ownerDomain': binding.owner_domain,
            'entityVersion': snapshot.sequence + 1, 'previousRevision': snapshot.sequence,
            'operation': operation, 'recordedAt': _stamp(datetime.now(timezone.utc)),
            'outcome': 'committed', 'state': state, 'effects': effects,
            'artifacts': self._record_artifacts(state), 'repository': None,
            'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': 'configuration-set'}}
        try:
            stored = await self._ledger.append(record, expected_sequence=snapshot.sequence,
                valid_until=valid_until, completion_records=0)
        except ContractError as error:
            if error.code != 'owner_commit_uncertain':
                raise
            stored = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
            if stored is None:
                raise ContractError('owner_commit_uncertain') from None
        return await self._confirmed(stored)

    async def _confirmed(self, stored):
        state = self._retained(stored)
        # Enrolled service connections disable core echo. Signal local watches
        # only after ACK or retained-outcome reconciliation, including exact
        # retries after caller cancellation; each rereads the
        # ledger and never treats this wakeup as configuration authority.
        for watch in tuple(self._watches):
            watch.changed.set()
        if self._event_producer is not None:
            record = strict_loads(stored.record)
            raw = retained_event(record, self._ledger._binding, start_revision=self._event_start_revision)
            if raw is not None:
                confirmed = await self._ledger.outcome(record['operation']['operationId'], record['operation']['payloadDigest'])
                if confirmed is None or confirmed.sequence != stored.sequence or confirmed.record != stored.record:
                    raise ContractError('owner_commit_uncertain')
                task = asyncio.create_task(self._publish_event(raw))
                event_id = strict_loads(raw)['messageId']
                self._publications.add(task)
                def finished(original):
                    self._publications.discard(original)
                    failed = original.cancelled() or original.exception() is not None
                    if failed and original in self._publication_handed:
                        self._publication_failures[event_id] = original
                    self._publication_handed.discard(original)
                task.add_done_callback(finished)
                _, pending = await asyncio.wait({task}, timeout=3)
                if pending:
                    raise ContractError('configuration_event_publication_uncertain')
                task.result()
                self._publication_failures.pop(event_id, None)
        return state

    async def _publish_event(self, raw):
        valid_until = await self._authorize_publication(raw)
        if self._closed:
            raise ContractError('configuration_owner_closed')
        if self._connection is not None:
            subject = self.subject.removesuffix('.command') + '.event.configuration-change'
            remaining = (valid_until - datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                raise ContractError('configuration_event_resync_required')
            self._publication_handed.add(asyncio.current_task())
            await asyncio.wait_for(self._connection.publish(subject, raw), min(3, remaining))
            await asyncio.wait_for(self._connection.flush(), 3)

    async def _reply(self, raw, envelope, state):
        decision, snapshot = await self._authorize(raw, envelope)
        valid_until = decision.valid_until
        if self._requires_activation(snapshot, state):
            valid_until = min(valid_until, self._activation(snapshot, envelope, state))
        if envelope['contractId'] != 'configuration-set':
            self._require_watch_cleanup()
        record = strict_loads(snapshot.record)
        now = datetime.now(timezone.utc)
        index = _indexes(record['state'], record['ownerHubId'])
        issuer = index['issuers'].get(_key(strict_loads(self._issuer)))
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        if (issuer is None or not _active(issuer, now) or issuer['publicKey'] != public
                or identity is None or identity['kind'] != 'service' or not _active(identity, now)):
            raise ContractError('configuration_signer_unavailable')
        claims = {'purpose': 'agentmux-configuration-response-v1', 'requestDigest': payload_digest(envelope),
            'configurationRef': {'id': self._ledger._binding.entity_id, 'ownerHubId': self._ledger._binding.hub_id,
                'revision': state['revision']}, 'owner': state['owner'],
            'authorityRef': strict_loads(decision.authority_ref), 'signingKeyRef': issuer['ref'],
            'issuedAt': _stamp(now), 'validUntil': _stamp(valid_until), 'state': state}
        response = {'claims': claims, 'signature': sign_claims(claims, self._seed)}
        validate('configuration-reply', response)
        return canonical_bytes(response)

    async def _close(self):
        self._closed = True
        if self._subscription_service is not None:
            await self._subscription_service.close(timeout=None)
        if self._subscribe_task is not None:
            self._subscription = await asyncio.shield(self._subscribe_task)
            self._subscription_ownership = _subscription_ownership(
                self._subscription, self._connection, self._subscription_ownership)
            self._subscription_worker = self._subscription_ownership[3]
        for task in tuple(self._active):
            task.cancel()
        await self._watch_controls.close()
        for watch in tuple(self._watches):
            await watch.close(timeout=None)
        active = tuple(self._active)
        if active:
            await asyncio.gather(*active, return_exceptions=True)
        requests = tuple(self._requests)
        if requests:
            # Replies already handed to transport remain owned until their
            # original publish/flush completes or its bounded deadline expires.
            await asyncio.gather(*requests, return_exceptions=True)
        publications = tuple(self._publications)
        publication_failed = False
        if publications:
            results = await asyncio.gather(*publications, return_exceptions=True)
            publication_failed = any(isinstance(result, BaseException) for result in results)
        if self._subscription is not None:
            if not self._subscription_drained:
                await _drain_subscription(self._subscription_ownership)
                self._subscription_drained = True
            await _join_callback_worker(self._subscription_worker)
            _subscription_ownership(self._subscription, self._connection, self._subscription_ownership)
            _require_subscription_detached(self._subscription_ownership)
        if publication_failed or self._publication_failures:
            self._publication_failures.clear()
            raise ContractError('configuration_event_publication_uncertain')
        self.done.set()

    async def close(self, *, timeout=3):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('configuration_cleanup_incomplete')
        self._closed = True
        if self.done.is_set():
            return
        if self._closing is None or (self._closing.done() and self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._close())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('configuration_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            raise ContractError('configuration_cleanup_incomplete') from None


def verify_configuration_response(raw, request, *, public_key, issuer_ref, now):
    """The caller supplies the enrolled signer; the response cannot select trust."""
    response, envelope = strict_loads(raw), strict_loads(request)
    validate('configuration-reply', response)
    claims = response['claims']
    verify_possession(claims, response['signature'], public_key)
    payload = envelope['payload']
    actual, wanted = claims['configurationRef'], payload['configurationRef']
    expiry = min(datetime.fromisoformat(envelope['operation']['deadline']),
                 datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt']))
    if (claims['signingKeyRef'] != issuer_ref or claims['requestDigest'] != payload_digest(envelope)
            or claims['owner'] != payload['owner'] or claims['state']['owner'] != claims['owner']
            or actual['id'] != wanted['id'] or actual['ownerHubId'] != wanted['ownerHubId']
            or actual['revision'] < wanted['revision'] or actual['revision'] != claims['state']['revision']
            or not datetime.fromisoformat(claims['issuedAt']) <= now < datetime.fromisoformat(claims['validUntil'])
            or datetime.fromisoformat(claims['validUntil']) > expiry
            or (envelope['contractId'] == 'configuration-watch' and actual['revision'] <= payload['afterRevision'])):
        raise ContractError('configuration_response_binding')
    if envelope['contractId'] == 'configuration-set' and (actual['revision'] != envelope['operation']['expectedVersion'] + 1
            or any(claims['state'][field] != payload[field] for field in ('configurationBytes', 'schemaRef', 'secretReferences'))):
        raise ContractError('configuration_response_binding')
    data = base64.b64decode(claims['state']['configurationBytes'], validate=True)
    if (not 1 <= len(data) <= 16384 or _digest(data) != claims['state']['configurationChecksum']
            or base64.b64encode(data).decode() != claims['state']['configurationBytes']):
        raise ContractError('configuration_response_binding')
    return strict_loads(canonical_bytes(claims))
