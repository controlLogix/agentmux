"""Host lifecycle for the retained configuration source and recovery custody.

The installed host supplies admitted resources. History and the connection remain
borrowed until close succeeds; no stream, credential, key or schema is enrolled
implicitly. Local backup behavior does not qualify off-volume recovery objectives.
"""
import asyncio
import time
import uuid

from agentmux_contracts import ContractError
from identity.authority import LedgerAuthorityReader
from .backup_host import BackupHost
from .backup_lifecycle import OwnerBackupLifecycle
from .checkpoint_host import CheckpointHost
from .checkpoints import CheckpointCadence, CheckpointReceipt, export_checkpoint_async
from .configuration import ConfigurationOwner
from .federation_policy import FederationPolicyCustody, FederationPolicyOwner
from .configuration_events import ConfigurationEventRoute, ConfigurationEventSource
from .configuration_subscriptions import ConfigurationSubscriptions
from .history import OwnerHistory
from .ledger import OwnerLedger


class _ManagedConfigurationOwner(ConfigurationOwner):
    async def handle(self, raw):
        self._host.check_health()
        result = await super().handle(raw)
        self._host._checkpoint_if_due()
        return result


class _ManagedFederationPolicyOwner(FederationPolicyOwner):
    async def handle(self, raw):
        self._host.check_health()
        from agentmux_contracts import strict_loads
        transition = self._host._policy_transition
        if transition is not None and strict_loads(raw).get('contractId') == 'configuration-set':
            result = await transition.apply(raw)
        else:
            result = await super().handle(raw)
        self._host._checkpoint_if_due()
        return result

    async def _deliver(self, raw, reply):
        from agentmux_contracts import strict_loads
        try:
            if (type(raw) is not bytes or len(raw) > 65536
                    or strict_loads(raw).get('claims', {}).get('purpose') != 'agentmux-client-possession-v1'):
                return await super()._deliver(raw, reply)
            host = self._host
            host.check_health()
            if host._policy_transition is None:
                return
            response = await host._policy_transition.client_command(raw, reply_subject=reply)
            host._checkpoint_if_due()
            if not self._closed:
                await asyncio.wait_for(self._connection.publish(reply, response), 3)
                await asyncio.wait_for(self._connection.flush(), 3)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Reconciliation uses its own current service grant. The caller
            # still observes uncertainty when its original reply was lost.
            try:
                if self._host._policy_transition is not None and self._host._policy_transition._uncertain is not None:
                    await self._host.recover_policy_projection()
            except Exception:
                pass


class ConfigurationHost:
    def __init__(self, authority, ledger, *, connection, owner, schema_ref, schema_resources,
                 issuer_ref, signing_seed, reply_prefix, checkpoint_host, backup_host, backup_key_id,
                 event_producer=None, event_account_public_key=None, event_jetstream_domain=None, event_start_revision=1,
                 monotonic=time.monotonic, clock=time.time, backup_max_total_bytes=1_073_741_824,
                 federation_policy=None):
        if not isinstance(authority, LedgerAuthorityReader):
            raise ContractError('configuration_enrolled_authority_required')
        if event_producer is None:
            raise ContractError('configuration_event_producer_required')
        if (federation_policy is not None and (type(federation_policy) is not FederationPolicyCustody
                or federation_policy.target.binding != ledger._binding)):
            raise ContractError('configuration_host_configuration')
        if (not isinstance(ledger, OwnerLedger) or not isinstance(ledger._history, OwnerHistory)
                or not isinstance(checkpoint_host, CheckpointHost) or not isinstance(backup_host, BackupHost)
                or checkpoint_host.binding != ledger._binding or checkpoint_host.stream != ledger._stream
                or checkpoint_host.stream_identity.created != ledger._identity.created
                or backup_host.binding != ledger._binding or backup_host.stream_identity.created != ledger._identity.created
                or not callable(monotonic)):
            raise ContractError('configuration_host_configuration')
        self.ledger, self._history = ledger, ledger._history
        self._checkpoint, self._monotonic = checkpoint_host, monotonic
        self._backup = OwnerBackupLifecycle(self._history, ledger._binding, ledger._identity, backup_host,
            key_id=backup_key_id, retrieve_artifact=(self._unexpected_artifact if federation_policy is None
                else federation_policy.retrieve_backup), max_total_bytes=backup_max_total_bytes,
            max_artifacts=0 if federation_policy is None else 4096, clock=clock)
        owner_type = _ManagedConfigurationOwner if federation_policy is None else _ManagedFederationPolicyOwner
        domain = {} if federation_policy is None else {'policy_custody': federation_policy}
        self.owner = owner_type(authority, ledger, owner=owner, schema_ref=schema_ref,
            schema_resources=schema_resources, issuer_ref=issuer_ref, signing_seed=signing_seed,
            connection=connection, require_native_activation=federation_policy is None, event_producer=event_producer,
            event_start_revision=event_start_revision, **domain)
        self.owner._host = self
        self.events = ConfigurationEventSource(self.owner, ConfigurationEventRoute.from_ledger(ledger,
            account_public_key=event_account_public_key, jetstream_domain=event_jetstream_domain,
            start_revision=event_start_revision))
        self.subscriptions = ConfigurationSubscriptions(self.owner, self.events)
        self.owner._subscription_service = self.subscriptions
        self._reply_prefix = reply_prefix
        self._cadence = CheckpointCadence(now=monotonic())
        self._startup = self._closing = self._timer = self._checkpoint_work = None
        self._stop, self.done = asyncio.Event(), asyncio.Event()
        self._closed = self._ready = False
        self._policy_transition = None

    def bind_policy_transition(self, transition):
        from capability_owner.federation_policy_transition import FederationPolicyTransition
        if (type(transition) is not FederationPolicyTransition or transition._owner is not self.owner
                or self._closed or self._policy_transition is not None and self._policy_transition is not transition):
            raise ContractError('configuration_policy_transition_invalid')
        self._policy_transition = transition

    async def recover_policy_projection(self):
        """Resume only the retained decision using the selected service route."""
        from datetime import datetime, timedelta, timezone
        from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads
        transition = self._policy_transition
        if transition is None:
            raise ContractError('configuration_policy_transition_invalid')
        self.check_health()
        async with self.owner._policy_call():
            snapshot = await self.ledger.current()
            if snapshot.sequence == 0:
                return False
            raw, _ = await self.owner.custody._backup_request(snapshot.sequence)
            current = await self.owner.read_current(raw)
            now = datetime.now(timezone.utc)
            stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00', 'Z')
            payload = {'configurationRef': {'id': self.ledger._binding.entity_id,
                'ownerHubId': self.ledger._binding.hub_id, 'revision': current.revision},
                'owner': strict_loads(self.owner._owner), 'target': self.owner.custody.target.descriptor,
                'originalOperationId': current.operation_id, 'originalPayloadDigest': current.payload_digest,
                'desiredPolicyDigest': current.document['desiredPolicy']['digest']}
            claims = {'purpose': 'agentmux-client-possession-v1',
                'hubId': self.ledger._binding.hub_id, 'profileId': self.owner._authority._profile,
                'authorityId': self.owner._authority._entity,
                'transportRef': strict_loads(transition._projection_transport),
                'grantRef': strict_loads(transition._projection_grant),
                'operationId': 'policy_project_' + payload_digest(payload).split(':')[1],
                'expectedVersion': current.revision, 'contractId': 'federation-policy-project',
                'payload': payload, 'approvalRefs': [], 'issuedAt': stamp(now),
                'expiresAt': stamp(now + timedelta(seconds=30))}
            packet = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
                'signature': sign_claims(claims, self.owner._seed)})
            admitted = await self.owner.custody._ingress.admit(packet, cancellation_ref={
                'id': 'cancel_' + claims['operationId'], 'ownerHubId': self.ledger._binding.hub_id, 'revision': 1})
            if admitted.envelope is None or admitted.decision.outcome != 'allowed':
                raise ContractError('configuration_policy_recovery_refused')
            await transition.project(admitted.envelope)
            self._checkpoint_if_due()
            return True

    @classmethod
    def from_enrolled_host(cls, connection, *, authority, stream, binding, stream_identity,
                           retention, history, reply_prefix, jetstream_domain=None, **resources):
        from .ledger import owner_subject
        if not isinstance(authority, LedgerAuthorityReader):
            raise ContractError('configuration_enrolled_authority_required')
        if not isinstance(reply_prefix, str) or reply_prefix.endswith('.'):
            raise ContractError('configuration_host_configuration')
        jetstream = connection.jetstream() if jetstream_domain is None else connection.jetstream(domain=jetstream_domain)
        ledger = OwnerLedger(jetstream, stream=stream, subject=owner_subject(binding), binding=binding,
            retention=retention, stream_identity=stream_identity, history=history, require_completion_budget=True)
        return cls(authority, ledger, connection=connection, reply_prefix=reply_prefix + '.', **resources)

    def __repr__(self):
        return '<ConfigurationHost private>'

    @property
    def subject(self):
        return self.owner.subject

    async def _unexpected_artifact(self, reference):
        raise ContractError('configuration_backup_artifact_unavailable')

    def check_health(self):
        if self._closed or not self._ready:
            raise ContractError('configuration_host_unavailable')
        self._backup.check()
        for task in (self._startup, self._timer, self._checkpoint_work):
            if task is not None and task.done():
                task.result()

    async def handle(self, raw):
        return await self.owner.handle(raw)

    async def handle_subscription(self, raw, *, reply_subject):
        return await self.subscriptions.handle(raw, reply_subject=reply_subject)

    async def prepare_initialization(self, **values):
        self.check_health()
        return await self.owner.prepare_initialization(**values)

    async def _start(self):
        # Apply both trusted inventories before the first retained source page.
        self.ledger.require_recovery_identity(await self._checkpoint.recovery_identity())
        self.ledger.require_recovery_identity(await self._backup.recovery_identity())
        while not self._closed:
            if (await self.ledger.prepare_history()).ready:
                break
            await asyncio.sleep(0)
        if self._closed:
            raise ContractError('configuration_host_unavailable')
        snapshot = await self.ledger.current()
        if snapshot.sequence < self.owner._event_start_revision - 1:
            raise ContractError('configuration_event_coverage_invalid')
        if snapshot.latest is not None:
            self.owner._retained(snapshot.latest)
        await self._backup.start()
        if self._closed:
            raise ContractError('configuration_host_unavailable')
        await self.owner.start(reply_prefix=self._reply_prefix)
        if self._closed:
            raise ContractError('configuration_host_unavailable')
        self._timer = asyncio.create_task(self._checkpoint_loop())
        self._ready = True
        self._checkpoint_if_due()

    async def start(self):
        if self._closed or self._startup is not None:
            raise ContractError('configuration_host_lifecycle')
        self._startup = asyncio.create_task(self._start())
        await asyncio.shield(self._startup)

    def _checkpoint_if_due(self):
        if self._closed or not self._ready:
            return
        if self._checkpoint_work is not None:
            if not self._checkpoint_work.done():
                return
            self._checkpoint_work.result()
        cursor = self._history.verified_cursor
        if self._cadence.due(cursor, self._monotonic()):
            self._checkpoint_work = asyncio.create_task(self._export_checkpoint(cursor))

    async def _export_checkpoint(self, cursor):
        prefix = self._checkpoint.checkpoint_prefix
        path = prefix.with_name(prefix.name + '.' + str(cursor) + '.' + uuid.uuid4().hex + '.json')
        digest = await export_checkpoint_async(path, self._history, self.ledger._binding,
                                               self.ledger._identity, through=cursor)
        await self._checkpoint.committed(CheckpointReceipt(str(path), digest, cursor))
        self._cadence.completed(cursor, self._monotonic())

    async def _checkpoint_loop(self):
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), 30)
            except asyncio.TimeoutError:
                if self._policy_transition is not None and self._policy_transition._uncertain is not None:
                    try:
                        await self.recover_policy_projection()
                    except ContractError:
                        pass
                self._checkpoint_if_due()

    async def _close(self):
        self._stop.set()
        failures = []
        if self._startup is not None:
            if not self._startup.done():
                self._startup.cancel()
            try:
                await self._startup
            except BaseException:
                pass  # Retain the exact startup task and its original result.
        try:
            await self.owner.close(timeout=None)
        except BaseException as error:
            failures.append(error)
        for task in (self._timer, self._checkpoint_work):
            if task is not None:
                try:
                    await asyncio.shield(task)
                except BaseException as error:
                    failures.append(error)
        try:
            await self._backup.close()
        except BaseException as error:
            failures.append(error)
        if failures:
            raise BaseExceptionGroup('private configuration cleanup', failures)
        self.done.set()

    async def close(self, *, timeout=3):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('configuration_host_cleanup_incomplete')
        self._closed = True
        self._ready = False
        if self.done.is_set():
            return
        if self._closing is None or (self._closing.done() and self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._close())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('configuration_host_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            raise ContractError('configuration_host_cleanup_incomplete') from None
