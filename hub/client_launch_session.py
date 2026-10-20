"""Keep an enrolled NATS event loop alive beside synchronous client protocol I/O."""
import asyncio
from datetime import datetime, timezone
import math
import re
import secrets
import threading
import time

from hub.client_launch_connection import ConnectionFailure
from hub.client_launch_enrollment import open_application_client
from hub.client_launch_selection import SelectionError


class ApplicationSessionFailure(ValueError):
    def __init__(self, owner):
        super().__init__('application_connection_unavailable')
        self.owner = owner


def validate_query_arguments(arguments):
    """The tool chooses request identity and revision, never routing or authority."""
    if (type(arguments) is not dict or set(arguments) != {'operationId', 'expectedVersion'}
            or type(arguments['operationId']) is not str
            or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', arguments['operationId'])
            or type(arguments['expectedVersion']) is not int
            or not 0 <= arguments['expectedVersion'] <= 9007199254740991):
        raise ValueError('integration_query_arguments_invalid')
    return arguments['operationId'], arguments['expectedVersion']


def validate_integration_command_arguments(arguments):
    """Freeze one caller-selected operation; routing and transport stay enrolled."""
    from agentmux_contracts import canonical_bytes, strict_loads, validate
    contracts = {'integration-intent', 'integration-effect-query', 'integration-attempt-start',
                 'integration-attempt-complete', 'integration-effect-reconcile'}
    if (type(arguments) is not dict or set(arguments) != {'contractId', 'operationId',
            'expectedVersion', 'grantRef', 'payload', 'approvalRefs'}
            or arguments.get('contractId') not in contracts
            or type(arguments.get('operationId')) is not str
            or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', arguments['operationId']) is None
            or type(arguments.get('expectedVersion')) is not int
            or not 0 <= arguments['expectedVersion'] <= 9007199254740991
            or type(arguments.get('grantRef')) is not dict
            or type(arguments.get('approvalRefs')) is not list):
        raise ValueError('integration_command_arguments_invalid')
    try:
        frozen = strict_loads(canonical_bytes(arguments))
        validate(frozen['contractId'], frozen['payload'])
    except Exception:
        raise ValueError('integration_command_arguments_invalid') from None
    return frozen


class ApplicationClientSession:
    """Own one thread, loop and original connection inside this client process."""
    def __init__(self, selected):
        self._selected = selected
        self._loop = self._owner = self._opening = self._opening_task = None
        self._closing = self._cleanup = self._final_closing = self._status_future = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name='agentmux-client-connection', daemon=False)
        self._started = self._stopped = self._loop_stopping = False
        self._closed_complete = False
        self._loop_failure = None
        self._query_enrolled = self._legacy_alias_query_enrolled = False
        self._authority_switch_recovery_enrolled = False
        self._local_browser_enrolled = self._terminal_enrolled = False
        self._terminal_active = False
        self._integration_commands = frozenset()
        self._message_enrollment = None
        self._knowledge_enrollment = None
        self._code_enrollment = None
        self._work_enrollment = None
        self._peer_control_enrollment = None
        self._federation_policy_enrollment = None
        self._command_future = self._command_identity = None

    def __repr__(self):
        return '<ApplicationClientSession private>'

    def _run(self):
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
        except BaseException as error:
            self._loop_failure = error
            self._ready.set()
            return
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    async def _open(self, deadline):
        self._opening_task = asyncio.current_task()
        try:
            remaining = max(0, deadline - time.monotonic())
            self._owner = await open_application_client(self._selected.application_client,
                self._selected.application_connection, selected=self._selected,
                deadline=self._loop.time() + remaining, cleanup_deadline=self._loop.time() + remaining + 1)
            # Capability comes from the admitted signer selection. Subject
            # counts are ambiguous because enrolled commands can share routes.
            signer = getattr(self._owner, '_signer', None)
            enrollment = {} if signer is None else signer.selection
            self._query_enrolled = 'integrationEffectQuery' in enrollment
            commands = enrollment.get('integrationEffectCommands')
            self._integration_commands = frozenset(() if commands is None else commands['contracts'])
            self._legacy_alias_query_enrolled = 'legacyAliasResolve' in enrollment
            self._authority_switch_recovery_enrolled = 'authoritySwitchRecovery' in enrollment
            self._local_browser_enrolled = 'localBrowserSessionOpen' in enrollment
            self._terminal_enrolled = 'oidcTerminalSession' in enrollment
            if 'messageCommands' in enrollment:
                from agentmux_contracts import canonical_bytes
                self._message_enrollment = canonical_bytes({
                    **{k: enrollment[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
                    'messageCommands': enrollment['messageCommands']})
            if 'knowledgeCommands' in enrollment:
                from agentmux_contracts import canonical_bytes
                self._knowledge_enrollment = canonical_bytes({
                    **{k: enrollment[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
                    'knowledgeCommands': enrollment['knowledgeCommands']})
            if 'codeCommands' in enrollment:
                from agentmux_contracts import canonical_bytes
                self._code_enrollment = canonical_bytes({
                    **{k: enrollment[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
                    'codeCommands': enrollment['codeCommands']})
            if 'workCommands' in enrollment:
                from agentmux_contracts import canonical_bytes
                self._work_enrollment = canonical_bytes({
                    **{k: enrollment[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
                    'workCommands': enrollment['workCommands']})
            if 'peerControlCommands' in enrollment:
                from agentmux_contracts import canonical_bytes
                self._peer_control_enrollment = canonical_bytes({
                    **{k: enrollment[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
                    'peerControlCommands': enrollment['peerControlCommands']})
            if 'federationPolicyCommands' in enrollment:
                from agentmux_contracts import canonical_bytes
                self._federation_policy_enrollment = canonical_bytes({
                    **{k: enrollment[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
                    'federationPolicyCommands': enrollment['federationPolicyCommands']})
        except ConnectionFailure as error:
            self._owner = error.owner
            raise
        except SelectionError as error:
            self._cleanup = error.cleanup
            raise

    def start(self, *, deadline):
        if self._started or time.monotonic() >= deadline:
            raise ApplicationSessionFailure(self)
        self._started = True
        try:
            self._thread.start()
        except RuntimeError:
            self._started = False
            raise ApplicationSessionFailure(self) from None
        if not self._ready.wait(max(0, deadline - time.monotonic())):
            raise ApplicationSessionFailure(self)
        if self._loop_failure is not None:
            raise ApplicationSessionFailure(self)
        self._opening = asyncio.run_coroutine_threadsafe(self._open(deadline), self._loop)
        try:
            self._opening.result(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            # The original open remains owned; never cancel its proxy or retry.
            raise ApplicationSessionFailure(self) from None
        return self

    async def _status(self):
        if self._owner is None:
            return {'state': 'unavailable', 'hubId': None}
        try:
            claims = self._owner.binding.current(self._owner.require_connection(), now=datetime.now(timezone.utc))
            return {'state': 'verified', 'hubId': claims['hubId']}
        except (ValueError, ConnectionFailure):
            return {'state': 'unavailable', 'hubId': None}

    def status(self, *, deadline=None):
        if (self._stopped or self._loop is None or self._closing is not None
                or not self._thread.is_alive()):
            return {'state': 'unavailable', 'hubId': None}
        remaining = 1 if deadline is None else min(1, max(0, deadline - time.monotonic()))
        if remaining <= 0:
            return {'state': 'unavailable', 'hubId': None}
        if self._status_future is None or self._status_future.done():
            self._status_future = asyncio.run_coroutine_threadsafe(self._status(), self._loop)
        try:
            return self._status_future.result(timeout=remaining)
        except BaseException:
            return {'state': 'unavailable', 'hubId': None}

    def query_enabled(self):
        """Advertise only an explicitly enrolled route, not current authority."""
        return (self._query_enrolled
                and (not self._terminal_enrolled or self._terminal_active)
                and not self._stopped and self._closing is None
                and self._final_closing is None)

    def legacy_alias_query_enabled(self):
        """Advertise only the explicitly enrolled legacy alias route."""
        return (self._legacy_alias_query_enrolled
                and (not self._terminal_enrolled or self._terminal_active)
                and not self._stopped
                and self._closing is None and self._final_closing is None)

    def authority_switch_recovery_enabled(self):
        """Advertise only the enrolled recovery route on this retained session."""
        return (self._authority_switch_recovery_enrolled
                and (not self._terminal_enrolled or self._terminal_active)
                and not self._stopped and self._closing is None
                and self._final_closing is None)

    def authority_switch_recovery_route(self):
        if not self.authority_switch_recovery_enabled() or self._owner is None:
            raise ApplicationSessionFailure(self)
        from agentmux_contracts import canonical_bytes, strict_loads
        route = self._owner._signer.selection['authoritySwitchRecovery']
        return strict_loads(canonical_bytes(route))

    def integration_command_enabled(self, contract_id):
        """Advertise one explicitly enrolled integration purpose."""
        return (contract_id in self._integration_commands
                and (not self._terminal_enrolled or self._terminal_active)
                and not self._stopped
                and self._closing is None and self._final_closing is None)

    def message_enrollment(self):
        """Return only protected public route pins, never keys or a connection."""
        if (self._message_enrollment is None or self._stopped or self._closing is not None
                or self._final_closing is not None or self._terminal_enrolled and not self._terminal_active):
            raise ApplicationSessionFailure(self)
        from agentmux_contracts import strict_loads
        return strict_loads(self._message_enrollment)

    async def _message_command(self, arguments, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.message_command(**arguments, deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    def message_command(self, *, contract_id, operation_id, payload, expires_at, deadline=None,
                        include_valid_until=False):
        enrollment = self.message_enrollment()
        from agentmux_contracts import canonical_bytes, strict_loads, validate
        if contract_id not in enrollment['messageCommands']['grantRefs']:
            raise ApplicationSessionFailure(self)
        if include_valid_until and contract_id != 'federation-message-outcome':
            raise ApplicationSessionFailure(self)
        validate(contract_id, payload)
        arguments = strict_loads(canonical_bytes({'contract_id': contract_id, 'operation_id': operation_id,
            'payload': payload, 'expires_at': expires_at,
            **({'include_valid_until': True} if include_valid_until else {})}))
        deadline = self._command_deadline(deadline)
        identity = ('message-command', canonical_bytes(arguments))
        # Only this typed outcome proves the original exchange joined and its
        # inbox retired. A running or otherwise failed future remains retained.
        from hub.client_launch_connection import MessageOutcomeUnconfirmed
        previous = self._command_future
        if previous is not None and previous.done() and not previous.cancelled():
            if type(previous.exception()) is MessageOutcomeUnconfirmed:
                self._command_future = self._command_identity = None
        try:
            return self._wait_command(identity, lambda: self._message_command(arguments, deadline), deadline)
        except ApplicationSessionFailure:
            previous = self._command_future
            if previous is not None and previous.done() and not previous.cancelled():
                if type(previous.exception()) is MessageOutcomeUnconfirmed:
                    self._command_future = self._command_identity = None
            raise

    def knowledge_enrollment(self):
        """Return only protected public route pins, never keys or a connection."""
        if (self._knowledge_enrollment is None or self._stopped or self._closing is not None
                or self._final_closing is not None or self._terminal_enrolled and not self._terminal_active):
            raise ApplicationSessionFailure(self)
        from agentmux_contracts import strict_loads
        return strict_loads(self._knowledge_enrollment)

    async def _knowledge_command(self, arguments, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.knowledge_command(**arguments, deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    def knowledge_command(self, *, contract_id, operation_id, payload, expires_at, deadline=None):
        enrollment = self.knowledge_enrollment()
        from agentmux_contracts import canonical_bytes, strict_loads, validate
        if contract_id not in enrollment['knowledgeCommands']['grantRefs']:
            raise ApplicationSessionFailure(self)
        validate(contract_id, payload)
        arguments = strict_loads(canonical_bytes({'contract_id': contract_id, 'operation_id': operation_id,
            'payload': payload, 'expires_at': expires_at}))
        deadline = self._command_deadline(deadline)
        identity = ('knowledge-command', canonical_bytes(arguments))
        # Only this typed outcome proves the original exchange joined and its
        # inbox retired. A running or otherwise failed future remains retained.
        from hub.client_launch_connection import MessageOutcomeUnconfirmed
        previous = self._command_future
        if previous is not None and previous.done() and not previous.cancelled():
            if type(previous.exception()) is MessageOutcomeUnconfirmed:
                self._command_future = self._command_identity = None
        try:
            return self._wait_command(identity, lambda: self._knowledge_command(arguments, deadline), deadline)
        except ApplicationSessionFailure:
            previous = self._command_future
            if previous is not None and previous.done() and not previous.cancelled():
                if type(previous.exception()) is MessageOutcomeUnconfirmed:
                    self._command_future = self._command_identity = None
            raise

    def code_enrollment(self):
        """Return only protected public route pins, never keys or a connection."""
        if (self._code_enrollment is None or self._stopped or self._closing is not None
                or self._final_closing is not None or self._terminal_enrolled and not self._terminal_active):
            raise ApplicationSessionFailure(self)
        from agentmux_contracts import strict_loads
        return strict_loads(self._code_enrollment)

    async def _code_command(self, arguments, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.code_command(**arguments, deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    def code_command(self, *, contract_id, operation_id, payload, expires_at, deadline=None,
                     include_valid_until=False):
        enrollment = self.code_enrollment()
        from agentmux_contracts import canonical_bytes, strict_loads, validate
        if contract_id not in enrollment['codeCommands']['grantRefs']:
            raise ApplicationSessionFailure(self)
        if include_valid_until and contract_id not in ('federation-code-outcome', 'federation-code-read'):
            raise ApplicationSessionFailure(self)
        validate(contract_id, payload)
        arguments = strict_loads(canonical_bytes({'contract_id': contract_id, 'operation_id': operation_id,
            'payload': payload, 'expires_at': expires_at,
            **({'include_valid_until': True} if include_valid_until else {})}))
        deadline = self._command_deadline(deadline)
        identity = ('code-command', canonical_bytes(arguments))
        # Only this typed outcome proves the original exchange joined and its
        # inbox retired. A running or otherwise failed future remains retained.
        from hub.client_launch_connection import MessageOutcomeUnconfirmed
        previous = self._command_future
        if previous is not None and previous.done() and not previous.cancelled():
            if type(previous.exception()) is MessageOutcomeUnconfirmed:
                self._command_future = self._command_identity = None
        try:
            return self._wait_command(identity, lambda: self._code_command(arguments, deadline), deadline)
        except ApplicationSessionFailure:
            previous = self._command_future
            if previous is not None and previous.done() and not previous.cancelled():
                if type(previous.exception()) is MessageOutcomeUnconfirmed:
                    self._command_future = self._command_identity = None
            raise

    def work_enrollment(self):
        """Return only protected public route pins, never keys or a connection."""
        if (self._work_enrollment is None or self._stopped or self._closing is not None
                or self._final_closing is not None or self._terminal_enrolled and not self._terminal_active):
            raise ApplicationSessionFailure(self)
        from agentmux_contracts import strict_loads
        return strict_loads(self._work_enrollment)

    async def _work_command(self, arguments, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.work_command(**arguments, deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    def work_command(self, *, contract_id, operation_id, payload, expires_at, deadline=None,
                     include_valid_until=False, source_expectation=None):
        enrollment = self.work_enrollment()
        from agentmux_contracts import canonical_bytes, strict_loads, validate
        if contract_id not in enrollment['workCommands']['grantRefs']:
            raise ApplicationSessionFailure(self)
        from identity.work_client import WORK_COMMANDS
        if contract_id not in WORK_COMMANDS:
            raise ApplicationSessionFailure(self)
        validate(contract_id, payload)
        arguments = strict_loads(canonical_bytes({'contract_id': contract_id, 'operation_id': operation_id,
            'payload': payload, 'expires_at': expires_at,
            **({'source_expectation': source_expectation} if source_expectation is not None else {}),
            **({'include_valid_until': True} if include_valid_until else {})}))
        deadline = self._command_deadline(deadline)
        identity = ('work-command', canonical_bytes(arguments))
        # Only this typed outcome proves the original exchange joined and its
        # inbox retired. A running or otherwise failed future remains retained.
        from hub.client_launch_connection import MessageOutcomeUnconfirmed
        previous = self._command_future
        if previous is not None and previous.done() and not previous.cancelled():
            if type(previous.exception()) is MessageOutcomeUnconfirmed:
                self._command_future = self._command_identity = None
        try:
            return self._wait_command(identity, lambda: self._work_command(arguments, deadline), deadline)
        except ApplicationSessionFailure:
            previous = self._command_future
            if previous is not None and previous.done() and not previous.cancelled():
                if type(previous.exception()) is MessageOutcomeUnconfirmed:
                    self._command_future = self._command_identity = None
            raise

    def peer_control_enrollment(self):
        """Return the enrolled public command route without owner credentials."""
        if (self._peer_control_enrollment is None or self._stopped or self._closing is not None
                or self._final_closing is not None or self._terminal_enrolled and not self._terminal_active):
            raise ApplicationSessionFailure(self)
        from agentmux_contracts import strict_loads
        return strict_loads(self._peer_control_enrollment)

    async def _peer_control_command(self, arguments, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.peer_control_command(**arguments, deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    def peer_control_command(self, *, contract_id, operation_id, payload, expires_at,
                             approval_refs=(), deadline=None):
        enrollment = self.peer_control_enrollment()
        from agentmux_contracts import canonical_bytes, strict_loads, validate
        if contract_id not in enrollment['peerControlCommands']['grantRefs']:
            raise ApplicationSessionFailure(self)
        validate(contract_id, payload)
        arguments = strict_loads(canonical_bytes({'contract_id': contract_id, 'operation_id': operation_id,
            'payload': payload, 'expires_at': expires_at, 'approval_refs': list(approval_refs)}))
        deadline = self._command_deadline(deadline)
        identity = ('peer-control-command', canonical_bytes(arguments))
        return self._wait_command(identity, lambda: self._peer_control_command(arguments, deadline), deadline)

    def federation_policy_enrollment(self):
        """Return only protected public policy route pins."""
        if (self._federation_policy_enrollment is None or self._stopped or self._closing is not None
                or self._final_closing is not None or self._terminal_enrolled and not self._terminal_active):
            raise ApplicationSessionFailure(self)
        from agentmux_contracts import strict_loads
        return strict_loads(self._federation_policy_enrollment)

    async def _federation_policy_command(self, arguments, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.federation_policy_command(**arguments, deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    def federation_policy_command(self, *, contract_id, operation_id, expected_version,
                                  payload, expires_at, approval_refs=(), deadline=None):
        enrollment = self.federation_policy_enrollment()
        from agentmux_contracts import canonical_bytes, strict_loads, validate
        if contract_id not in enrollment['federationPolicyCommands']['grantRefs']:
            raise ApplicationSessionFailure(self)
        validate(contract_id, payload)
        arguments = strict_loads(canonical_bytes({'contract_id': contract_id, 'operation_id': operation_id,
            'expected_version': expected_version, 'payload': payload, 'expires_at': expires_at,
            'approval_refs': list(approval_refs)}))
        deadline = self._command_deadline(deadline)
        identity = ('federation-policy-command', canonical_bytes(arguments))
        from hub.client_launch_connection import PolicyOutcomeUnconfirmed
        previous = self._command_future
        if previous is not None and previous.done() and not previous.cancelled():
            if type(previous.exception()) is PolicyOutcomeUnconfirmed:
                self._command_future = self._command_identity = None
        try:
            return self._wait_command(identity,
                lambda: self._federation_policy_command(arguments, deadline), deadline)
        except ApplicationSessionFailure:
            previous = self._command_future
            if previous is not None and previous.done() and not previous.cancelled():
                if type(previous.exception()) is PolicyOutcomeUnconfirmed:
                    self._command_future = self._command_identity = None
            raise

    def local_browser_enabled(self):
        return (self._local_browser_enrolled and not self._stopped
                and self._closing is None and self._final_closing is None)

    def oidc_terminal_enabled(self):
        return (self._terminal_enrolled and not self._stopped
                and self._closing is None and self._final_closing is None)

    async def _query_effect(self, identity, deadline):
        from agentmux_contracts import validate, canonical_bytes, strict_loads
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        receipt = await self._owner.query_integration_effect(operation_id=identity[0], expected_version=identity[1],
            deadline=self._loop.time() + remaining, cleanup_deadline=self._loop.time() + remaining + 1)
        validate('integration-effect-reply', receipt)
        # Only the closed receipt crosses back into the synchronous protocol.
        return strict_loads(canonical_bytes(receipt))

    async def _query_legacy_aliases(self, selector, operation_id, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.query_legacy_aliases(**selector, operation_id=operation_id,
            deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    async def _authority_switch_recovery(self, operation_id, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.authority_switch_recovery(operation_id=operation_id,
            deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    async def _integration_command(self, arguments, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        receipt = await self._owner.integration_command(
            contract_id=arguments['contractId'], operation_id=arguments['operationId'],
            expected_version=arguments['expectedVersion'], grant_ref=arguments['grantRef'],
            payload=arguments['payload'], approval_refs=arguments['approvalRefs'],
            deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)
        from agentmux_contracts import canonical_bytes, strict_loads, validate
        validate('integration-effect-reply', receipt)
        return strict_loads(canonical_bytes(receipt))

    async def _local_browser_session_open(self, challenge, origin, operation_id, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.local_browser_session_open(challenge=challenge, origin=origin,
            operation_id=operation_id, deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    async def _oidc_terminal_command(self, contract_id, payload, operation_id, deadline):
        if self._owner is None:
            raise ApplicationSessionFailure(self)
        remaining = max(0, deadline - time.monotonic())
        return await self._owner.oidc_terminal_command(
            contract_id=contract_id, payload=payload, operation_id=operation_id,
            deadline=self._loop.time() + remaining,
            cleanup_deadline=self._loop.time() + remaining + 1)

    def _command_deadline(self, deadline, *, maximum=5):
        if (self._loop is None or not self._thread.is_alive() or self._loop_stopping
                or deadline is not None
                and (type(deadline) not in (int, float) or not math.isfinite(deadline))):
            raise ApplicationSessionFailure(self)
        deadline = (time.monotonic() + maximum if deadline is None
                    else min(deadline, time.monotonic() + maximum))
        if deadline - time.monotonic() <= 0:
            raise ApplicationSessionFailure(self)
        return deadline

    def _command_failure(self, stage, original, deadline, waiter=None):
        failure = ApplicationSessionFailure(self)
        try:
            from concurrent.futures import CancelledError
            from agentmux_contracts import ContractError
            from hub.client_launch_binding import BindingError
            from hub.client_launch_connection import MessageOutcomeUnconfirmed, PolicyOutcomeUnconfirmed
            kinds = {
                TimeoutError: 'TimeoutError', ConnectionFailure: 'ConnectionFailure',
                ContractError: 'ContractError', CancelledError: 'CancelledError',
                asyncio.CancelledError: 'CancelledError', SelectionError: 'SelectionError',
                BindingError: 'BindingError',
                MessageOutcomeUnconfirmed: 'MessageOutcomeUnconfirmed',
                PolicyOutcomeUnconfirmed: 'PolicyOutcomeUnconfirmed',
            }
            codes = {
                'application_binding_unavailable', 'application_command_unavailable',
                'application_command_unconfirmed', 'application_connection_already_started',
                'application_connection_changed', 'application_connection_cleanup_pending',
                'application_connection_deadline', 'application_connection_owner_loop',
                'application_connection_unavailable', 'application_policy_reply_unconfirmed',
                'application_reply_refused', 'application_request_in_progress',
                'application_request_refused', 'application_request_unconfirmed',
                'oidc_terminal_session_required', 'schema_invalid',
                'application_observation_expired', 'application_binding_mismatch',
                'application_credential_unavailable', 'application_permission_unavailable',
                'application_time_invalid', 'work_lifecycle_client_expired',
                'legacy_work_client_expired', 'capability_service_unavailable',
                'application_binding_budget', 'application_message_outcome_unconfirmed',
                'application_policy_outcome_unconfirmed', 'application_lifetime_ended',
                'application_lease_invalid', 'application_response_binding',
            }

            def chain(error):
                result, seen = [], set()
                while error is not None and id(error) not in seen and len(result) < 8:
                    seen.add(id(error))
                    code = error.args[0] if error.args else None
                    result.append({'type': kinds.get(type(error), 'other'),
                        'code': code if type(code) is str and code in codes else None})
                    error = (error._cause if type(error) in (
                                ConnectionFailure, MessageOutcomeUnconfirmed, PolicyOutcomeUnconfirmed)
                             else error.__cause__ or error.__context__)
                return result

            state = ('cancelled' if original.cancelled() else
                     'done' if original.done() else 'pending')
            # Observing an already completed exception does not consume the
            # original result or release its retained identity.
            future_error = original.exception(timeout=0) if state == 'done' else None
            remaining = deadline - time.monotonic()
            failure._command_diagnostic = {
                'stage': stage if stage in ('identity-mismatch', 'wait') else 'other',
                'deadlineRemaining': remaining if math.isfinite(remaining) else None,
                'futureState': state,
                'waiterChain': chain(waiter),
                'futureChain': chain(future_error),
            }
            from agentmux_contracts import strict_loads
            from identity.work_client import WORK_COMMANDS
            identity = self._command_identity
            if (type(identity) is tuple and len(identity) == 2
                    and identity[0] == 'work-command' and type(identity[1]) is bytes):
                arguments = strict_loads(identity[1])
                contract = arguments.get('contract_id') if type(arguments) is dict else None
                failure._command_diagnostic['futureContract'] = (
                    contract if type(contract) is str and contract in WORK_COMMANDS else 'other')
            if type(waiter) in (ConnectionFailure, MessageOutcomeUnconfirmed):
                timing = getattr(waiter, '_storage_command_timing', None)
                stages = {'bindingStart', 'bindingComplete', 'exchangeStart',
                          'publish', 'replyReceived', 'exchangeJoined'}
                if (type(timing) is dict
                        and set(timing) <= stages | {'contract', 'bindingRefreshed'}
                        and timing.get('contract') in (
                            'federation-work-inspect', 'federation-work-register',
                            'federation-work-state', 'federation-work-outcome')
                        and type(timing.get('bindingRefreshed', False)) is bool
                        and all(type(value) is dict and set(value) == {'at', 'remaining'}
                            and all(type(number) in (int, float) and math.isfinite(number)
                                    for number in value.values())
                            for key, value in timing.items() if key in stages)):
                    failure._command_diagnostic['timing'] = {
                        key: dict(value) if key in stages else value
                        for key, value in timing.items()}
        except BaseException:
            # Diagnostic capture must not replace the original failure or future.
            pass
        return failure

    def _wait_command(self, identity, submit, deadline):
        remaining = deadline - time.monotonic()
        if self._command_future is None:
            self._command_identity = identity
            self._command_future = asyncio.run_coroutine_threadsafe(submit(), self._loop)
        elif self._command_identity != identity:
            raise self._command_failure('identity-mismatch', self._command_future, deadline)
        original = self._command_future
        try:
            result = original.result(timeout=remaining)
        except BaseException as error:
            # A timed-out or interrupted waiter cannot replace the original
            # request. The exact same identity may consume it; close joins it.
            raise self._command_failure('wait', original, deadline, error) from None
        self._command_future = self._command_identity = None
        return result

    def query_effect(self, arguments, *, deadline=None):
        identity = validate_query_arguments(arguments)
        if not self.query_enabled():
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline)
        command_identity = ('integration-effect-query', *identity)
        return self._wait_command(command_identity,
            lambda: self._query_effect(identity, deadline), deadline)

    def integration_command(self, arguments, *, deadline=None):
        frozen = validate_integration_command_arguments(arguments)
        if not self.integration_command_enabled(frozen['contractId']):
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline)
        from agentmux_contracts import canonical_bytes
        identity = ('integration-command', frozen['contractId'], frozen['operationId'],
                    frozen['expectedVersion'], canonical_bytes(frozen['grantRef']),
                    canonical_bytes(frozen['payload']), canonical_bytes(frozen['approvalRefs']))
        return self._wait_command(identity,
            lambda: self._integration_command(frozen, deadline), deadline)

    def query_legacy_aliases(self, registrations=None, *, remote_address=None,
                             operation_id, deadline=None):
        """Resolve one exact trusted local or remote selector on the enrolled route."""
        from agentmux_contracts import canonical_bytes, strict_loads
        if (type(operation_id) is not str
                or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', operation_id)):
            raise ValueError('legacy_alias_query_arguments_invalid')
        try:
            if (registrations is None) == (remote_address is None):
                raise ValueError()
            if remote_address is None:
                frozen = canonical_bytes({'registrations': registrations})
                selector = {'registrations': strict_loads(frozen)['registrations']}
            else:
                if (type(remote_address) is not str or re.fullmatch(
                        r'agent:[a-z0-9_]{1,32}-[a-z0-9_]{1,24}-[a-z0-9_]{1,32}',
                        remote_address) is None):
                    raise ValueError()
                frozen = canonical_bytes({'remoteAddress': remote_address})
                selector = {'remote_address': remote_address}
        except (TypeError, ValueError):
            raise ValueError('legacy_alias_query_arguments_invalid') from None
        if not self.legacy_alias_query_enabled():
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline)
        identity = ('identity-legacy-alias-resolve', operation_id, frozen)
        resolution = self._wait_command(identity,
            lambda: self._query_legacy_aliases(selector, operation_id, deadline), deadline)
        from identity.legacy_identity import VerifiedLegacyAliasResolution
        if (type(resolution) is not VerifiedLegacyAliasResolution
                or datetime.now(timezone.utc) >= resolution.valid_until):
            raise ApplicationSessionFailure(self)
        return resolution

    def request_authority_switch_recovery(self, operation_id, *, deadline=None):
        """Consume one verified response from the fixed enrolled recovery route."""
        if (type(operation_id) is not str
                or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', operation_id) is None
                or not self.authority_switch_recovery_enabled()):
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline)
        identity = ('authority-switch-recovery', operation_id)
        result = self._wait_command(identity,
            lambda: self._authority_switch_recovery(operation_id, deadline), deadline)
        from state_owner.authority_switch_service import VerifiedEnrolledRecovery
        signer = self._owner._signer
        if (type(result) is not VerifiedEnrolledRecovery
                or result._seal is not signer._authority_switch_seal
                or datetime.now(timezone.utc) >= result._valid_until):
            raise ApplicationSessionFailure(self)
        return result

    def local_browser_session_open(self, challenge, origin, *, deadline=None):
        """Approve one browser-displayed challenge on this retained connection."""
        if (type(challenge) is not str or re.fullmatch(
                r'[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){4}', challenge) is None
                or type(origin) is not str or re.fullmatch(
                    r'http://(?:127\.0\.0\.1|localhost):[1-9][0-9]{0,4}', origin) is None
                or not 1 <= int(origin.rsplit(':', 1)[1]) <= 65535
                or not self.local_browser_enabled()):
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline)
        operation_id = 'browser_' + secrets.token_hex(16)
        identity = ('local-browser-session-open', challenge, origin, operation_id)
        return self._wait_command(identity,
            lambda: self._local_browser_session_open(challenge, origin, operation_id, deadline), deadline)

    def oidc_terminal_start(self, *, deadline=None):
        """Start one device login without accepting identity or provider input."""
        if not self.oidc_terminal_enabled():
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline, maximum=10)
        operation_id = self._terminal_operation_id('oidc-terminal-session-open')
        identity = ('oidc-terminal-session-open', operation_id)
        return self._wait_command(identity, lambda: self._oidc_terminal_command(
            'oidc-terminal-session-open', {}, operation_id, deadline), deadline)

    def oidc_terminal_status(self, attempt_id, *, deadline=None):
        if (not self.oidc_terminal_enabled() or type(attempt_id) is not str
                or re.fullmatch(r'oidc_attempt_[a-f0-9]{32}', attempt_id) is None):
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline, maximum=10)
        operation_id = self._terminal_operation_id(
            'oidc-terminal-session-status', attempt_id)
        identity = ('oidc-terminal-session-status', attempt_id, operation_id)
        result = self._wait_command(identity, lambda: self._oidc_terminal_command(
            'oidc-terminal-session-status', {'attemptId': attempt_id},
            operation_id, deadline), deadline)
        if result['outcome'] == 'approved':
            self._terminal_active = True
        return result

    def oidc_terminal_logout(self, session_id, *, deadline=None):
        if (not self.oidc_terminal_enabled() or type(session_id) is not str
                or re.fullmatch(r'oidc_session_[a-f0-9]{32}', session_id) is None):
            raise ApplicationSessionFailure(self)
        deadline = self._command_deadline(deadline, maximum=10)
        operation_id = self._terminal_operation_id(
            'oidc-terminal-session-close', session_id)
        identity = ('oidc-terminal-session-close', session_id, operation_id)
        result = self._wait_command(identity, lambda: self._oidc_terminal_command(
            'oidc-terminal-session-close', {'sessionId': session_id},
            operation_id, deadline), deadline)
        self._terminal_active = False
        return result

    def _terminal_operation_id(self, contract_id, target=None):
        """Reuse the hidden operation ID while its exact future is retained."""
        prefix = ((contract_id,) if target is None else (contract_id, target))
        identity = self._command_identity
        if (self._command_future is not None and isinstance(identity, tuple)
                and identity[:-1] == prefix):
            return identity[-1]
        labels = {'oidc-terminal-session-open': 'open',
                  'oidc-terminal-session-status': 'status',
                  'oidc-terminal-session-close': 'close'}
        return 'oidc_' + labels[contract_id] + '_' + secrets.token_hex(16)

    async def _close_owner(self, deadline, *, final=False):
        if self._opening_task is not None:
            try:
                await asyncio.shield(self._opening_task)
            except BaseException:
                pass
        if self._status_future is not None:
            try:
                await asyncio.wrap_future(self._status_future)
            except Exception:
                pass
        if self._command_future is not None:
            try:
                await asyncio.shield(asyncio.wrap_future(self._command_future))
            except Exception:
                pass
        if self._owner is not None:
            if final:
                if self._owner._close_task is None:
                    try:
                        await self._owner.close(deadline=self._loop.time() + 1)
                    except ConnectionFailure:
                        pass
                # Retain/join the original close even when its initial budget expired.
                await asyncio.shield(self._owner._close_task)
            else:
                await self._owner.close(deadline=self._loop.time() + max(0, deadline - time.monotonic()))
        return self._cleanup is None or self._cleanup.finish_cleanup()

    def close(self, *, deadline):
        if not self._started:
            return True
        if self._stopped:
            return self._closed_complete
        if self._ready.is_set() and not self._thread.is_alive():
            self._stopped = True
            return self._closed_complete
        if self._loop_stopping:
            self._thread.join(timeout=max(0, deadline - time.monotonic()))
            self._stopped = not self._thread.is_alive()
            return self._closed_complete and self._stopped
        if not self._ready.wait(max(0, deadline - time.monotonic())):
            return False
        if self._loop_failure is not None:
            self._thread.join(timeout=max(0, deadline - time.monotonic()))
            self._stopped = not self._thread.is_alive()
            self._closed_complete = self._stopped
            return self._closed_complete
        if self._closing is None or self._closing.done():
            self._closing = asyncio.run_coroutine_threadsafe(self._close_owner(deadline), self._loop)
        try:
            complete = self._closing.result(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            return False
        self._closed_complete = complete
        self._loop_stopping = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=max(0, deadline - time.monotonic()))
        self._stopped = not self._thread.is_alive()
        return complete and self._stopped

    def join_final(self):
        if not self._started:
            return True
        if self._stopped:
            return self._closed_complete
        if self._ready.is_set() and not self._thread.is_alive():
            self._stopped = True
            return self._closed_complete
        if self._loop_stopping:
            self._thread.join()
            self._stopped = True
            return self._closed_complete
        self._ready.wait()
        if self._loop_failure is not None:
            self._thread.join()
            self._stopped = self._closed_complete = True
            return True
        if self._final_closing is None:
            self._final_closing = asyncio.run_coroutine_threadsafe(
                self._close_owner(time.monotonic(), final=True), self._loop)
        try:
            complete = self._final_closing.result()
        except BaseException:
            if not self._final_closing.done():
                # An interrupted waiter cannot retire a still-running original
                # close. Keep the loop, connection and this exact future alive.
                raise ApplicationSessionFailure(self) from None
            complete = False
        self._closed_complete = complete
        self._loop_stopping = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()
        self._stopped = True
        return complete
