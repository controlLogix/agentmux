"""Project one retained policy decision onto its original selected sources.

ConfigurationOwner remains the decision authority. This owner only joins source
work and materializes that same decision; a file digest never grants admission.
"""
import asyncio
import base64
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import re
import tomllib
import uuid

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from hub import names
from hub.fed.config import DEFAULTS, TRUST_LEVELS, dump
from hub.fed.policy import normalize_remote
from identity.application_enrollment import _read_material
from identity.authority import _active, _indexes, _key
from state_owner.backup_lifecycle import _join
from state_owner.checkpoints import _directory
from state_owner.configuration import ConfigurationOwner, verify_configuration_response
from state_owner.federation_policy import FederationPolicyOwner, _digest, _policy, _reference
from .selected_storage import BoardAuditMirrorHost, SelectedStorageHost, _file_identity


@dataclass(frozen=True, repr=False)
class _PolicyPause:
    """Original observations for cleanup; these grant no policy authority."""
    revision: int
    record: bytes | None = field(repr=False)
    sources: tuple = field(repr=False)
    gates: tuple = field(repr=False)

    def __repr__(self):
        return '<_PolicyPause private>'


@dataclass(frozen=True, repr=False)
class _PolicyBootstrapProjection:
    request: bytes = field(repr=False)
    record: bytes = field(repr=False)
    revision: int
    identity: tuple = field(repr=False)
    digest: str
    sources: tuple = field(repr=False)


def changed_policy(raw, change, *, repository):
    """Derive the existing supported mutation, without granting permission."""
    _policy(raw)
    if (type(change) is not dict or set(change) != {'verb', 'arguments'}
            or type(change['arguments']) is not dict):
        raise ContractError('federation_policy_change_invalid')
    parsed = tomllib.loads(raw.decode('utf-8'))
    config = {'federation': {**DEFAULTS, **parsed.get('federation', {})},
        'repos': dict(parsed.get('repos', {})), 'peers': dict(parsed.get('peers', {}))}
    args, verb = change['arguments'], change['verb']
    if verb == 'trust':
        if set(args) != {'peer', 'level'} or args['level'] not in TRUST_LEVELS:
            raise ContractError('federation_policy_change_invalid')
        if args['peer'] != '*':
            names.check_part(args['peer'], 'peer')
        config['peers'].setdefault(args['peer'], {})['trust'] = args['level']
    elif verb in ('share', 'unshare'):
        allowed = {'repo', 'peers', 'remote', 'board_prefix'} if verb == 'share' else {'repo'}
        if (not {'repo'} <= set(args) <= allowed or args['repo'] != repository['localName']):
            raise ContractError('federation_policy_change_invalid')
        if verb == 'unshare':
            config['repos'].pop(args['repo'], None)
        else:
            peers = args.get('peers') or ['*']
            if isinstance(peers, str):
                peers = peers.replace(',', ' ').split()
            if type(peers) is not list or any(type(peer) is not str for peer in peers):
                raise ContractError('federation_policy_change_invalid')
            table = {'peers': peers}
            if args.get('remote'):
                table['remote'] = normalize_remote(args['remote'])
            if args.get('board_prefix'):
                table['board_prefix'] = args['board_prefix'].upper()
            config['repos'][args['repo']] = table
    else:
        raise ContractError('federation_policy_change_invalid')
    result = dump(config).encode('utf-8')
    _policy(result)
    return result


class FederationPolicyTransition:
    """Keep source generations behind the actual selected configuration owner.

    This object belongs to the owner process. Clients receive neither it nor its
    sources, credentials, key material or authority reader.
    """
    def __init__(self, owner, sources, *, projection_service_ref=None, selected_host=None,
                 requester_reply_prefix=None, projection_transport_ref=None, projection_grant_ref=None):
        if not isinstance(owner, FederationPolicyOwner):
            raise ContractError('federation_policy_transition_configuration')
        selected = strict_loads(owner.custody.target._selection)
        sources = tuple(sources)
        original = lambda source: {'source': source._pins,
            'repository': source._repository, 'localPeer': source._peer}
        primary = {'source': selected['source'], 'repository': selected['repository'],
            'localPeer': selected['localPeer']}
        declarations = [primary]
        if selected_host is not None:
            if type(selected_host) is not SelectedStorageHost or selected_host._authority is not owner._authority:
                raise ContractError('federation_policy_transition_configuration')
            selected_host._open()
            storage = selected_host._selection.policy['storage']
            if canonical_bytes(storage['scope']) != owner._ledger._binding.scope:
                raise ContractError('federation_policy_transition_configuration')
            declarations = []
            for name in ('board', 'messages', 'knowledge', 'code', 'work'):
                descriptor = storage.get(name)
                if descriptor is not None and (name != 'work' or 'policy' in descriptor['source']):
                    declarations.append({'source': descriptor['auditMirror'] if name == 'board' else descriptor['source'],
                        'repository': descriptor['repository'], 'localPeer': descriptor['localPeer']})
            if primary not in declarations:
                raise ContractError('federation_policy_transition_configuration')
            owned = [source for source in (selected_host._audit, *selected_host._message_stores) if source is not None]
            affected = [source for source in owned if source._pins.get('policy') == selected['source']['policy']]
            if {id(source) for source in affected} != {id(source) for source in sources}:
                raise ContractError('federation_policy_transition_configuration')
        def declared(source):
            current = original(source)
            return any(current == descriptor for descriptor in declarations)
        if (not sources or len(sources) > 32 or len({id(source) for source in sources}) != len(sources)
                or any(not isinstance(source, BoardAuditMirrorHost)
                    or not declared(source) or source._pins['policy'] != selected['source']['policy']
                    or source._loop is not asyncio.get_running_loop()
                    or source._policy_transition is not None or source._closed for source in sources)):
            raise ContractError('federation_policy_transition_configuration')
        if not any(source._pins == selected['source'] and source._repository is not None
                and all(source._repository.get(key) == value for key, value in selected['repository'].items())
                and source._peer == selected['localPeer'] for source in sources):
            raise ContractError('federation_policy_transition_configuration')
        self._owner, self._sources, self._selection = owner, sources, selected
        self._lock = asyncio.Lock()
        self._operations = {}
        self._closed = False
        self._closing = None
        self._uncertain = None
        self._precommit_refusal = self._commit_handed_off = None
        self._calls = set()
        reference = lambda value: None if value is None else canonical_bytes(_reference(value, owner._ledger._binding.hub_id))
        self._projection_service = reference(projection_service_ref)
        self._projection_transport = reference(projection_transport_ref)
        self._projection_grant = reference(projection_grant_ref)
        self._projected_identity = None
        self._bootstrap_projection = None
        self._selected_host = selected_host
        self._source_bindings = canonical_bytes([original(source) for source in sources])
        self._reply_prefix = requester_reply_prefix
        if requester_reply_prefix is not None:
            from state_owner.configuration_host import ConfigurationHost
            host = getattr(owner, '_host', None)
            if (type(host) is not ConfigurationHost or host.owner is not owner
                    or requester_reply_prefix != host._reply_prefix
                    or type(requester_reply_prefix) is not str
                    or not requester_reply_prefix.startswith('_INBOX.') or not requester_reply_prefix.endswith('.')):
                raise ContractError('federation_policy_transition_configuration')
        for source in sources:
            source._bind_policy_transition(self)
        if selected_host is not None:
            selected_host.register_policy_transition(self)

    def __repr__(self):
        return '<FederationPolicyTransition private>'

    @property
    def source_bindings(self):
        """Original protected declarations for the selected host's join gate."""
        return strict_loads(self._source_bindings)

    def _available(self):
        if self._closed or self._owner._closed or any(source._closed for source in self._sources):
            raise ContractError('federation_policy_transition_unavailable')
        original = [{'source': source._pins, 'repository': source._repository, 'localPeer': source._peer}
            for source in self._sources]
        if canonical_bytes(original) != self._source_bindings:
            raise ContractError('federation_policy_transition_configuration')
        if self._selected_host is not None:
            self._selected_host._open()
            owned = [source for source in (self._selected_host._audit, *self._selected_host._message_stores)
                if source is not None and source._pins.get('policy') == self._selection['source']['policy']]
            if {id(source) for source in owned} != {id(source) for source in self._sources}:
                raise ContractError('federation_policy_transition_configuration')

    @asynccontextmanager
    async def _call(self):
        self._available()
        if len(self._calls) >= 32:
            raise ContractError('federation_policy_transition_capacity')
        finished = asyncio.get_running_loop().create_future()
        self._calls.add(finished)
        try:
            async with self._owner._policy_call():
                yield
        finally:
            self._calls.discard(finished)
            finished.set_result(None)

    def _read_source(self):
        for source in self._sources:
            source._check_files()
        path = self._selection['source']['policy']['path']
        identity = _file_identity(path)
        raw = _read_material(path, max_bytes=65536, return_bytes=True)
        if identity != _file_identity(path):
            raise ContractError('federation_policy_source_changed')
        for source in self._sources:
            if source._policy_identity != identity:
                raise ContractError('federation_policy_source_changed')
        return raw, identity

    async def prepare(self, raw):
        """Independently derive bytes before the actual owner's staging path."""
        async with self._call():
            async with self._lock:
                self._available()
                if self._uncertain is not None:
                    raise ContractError('federation_policy_projection_uncertain')
                envelope = self._owner._envelope(raw, 'configuration-set')
                await self._owner._authorize(raw, envelope)
                self._available()
                old, _ = self._read_source()
                try:
                    proposal = strict_loads(base64.b64decode(envelope['payload']['configurationBytes'], validate=True))
                    desired = changed_policy(old, proposal['change'], repository=self._selection['repository'])
                except (KeyError, ValueError, TypeError):
                    raise ContractError('federation_policy_preparation_invalid') from None
                return await self._owner.prepare(raw, old_policy=old, desired_policy=desired)

    def _signed_receipt(self, envelope, decision, snapshot, claims, schema):
        now = datetime.now(timezone.utc)
        index = _indexes(strict_loads(snapshot.record)['state'], self._owner._ledger._binding.hub_id)
        issuer = index['issuers'].get(_key(strict_loads(self._owner._issuer)))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._owner._seed).verify_key)).decode().rstrip('=')
        if (issuer is None or identity is None or identity['kind'] != 'service'
                or not _active(issuer, now) or not _active(identity, now)
                or issuer['publicKey'] != public or decision.valid_until is None or now >= decision.valid_until):
            raise ContractError('federation_policy_signer_unavailable')
        stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00', 'Z')
        claims.update(requestDigest=payload_digest(envelope), configurationRef=envelope['payload']['configurationRef'],
            owner=strict_loads(self._owner._owner), target=self._owner.custody.target.descriptor,
            authorityRef=strict_loads(decision.authority_ref), signingKeyRef=issuer['ref'],
            issuedAt=stamp(now), validUntil=stamp(decision.valid_until))
        response = {'claims': claims, 'signature': sign_claims(claims, self._owner._seed)}
        validate(schema, response)
        return canonical_bytes(response)

    async def prepare_reply(self, raw):
        """The actual client route gets a distinct signed preparation receipt."""
        async with self._call():
            descriptor = await self.prepare(raw)
            envelope = self._owner._envelope(raw, 'configuration-set')
            decision, snapshot = await self._owner._authorize(raw, envelope)
            self._available()
            return self._signed_receipt(envelope, decision, snapshot, {
                'purpose': 'agentmux-federation-policy-prepared-v1',
                'operationId': envelope['operation']['operationId'],
                'preparationDigest': envelope['operation']['payloadDigest'],
                'previousRevision': envelope['operation']['expectedVersion'],
                'descriptorBytes': base64.b64encode(descriptor).decode()}, 'federation-policy-prepared-reply')

    def _observed_projection(self, state):
        """Observe completed admission without repairing a file or opening sources."""
        if state is None or self._uncertain is not None:
            return False
        try:
            if any(source._store is None or source._policy_generation != state['revision']
                    or source._policy_paused or source._policy_replacing for source in self._sources):
                return False
            selected = self._selected_host
            if selected is not None:
                if (not selected._ready or selected._policy_change is not None
                        or self not in selected._policy_transitions
                        or any(gate._closed or gate._policy_paused for gate in selected._policy_gates())):
                    return False
                selected.check_health()
            document = strict_loads(self._owner._document(state))
            raw, _ = self._read_source()
            desired = document['desiredPolicy']
            if len(raw) != desired['bytes'] or _digest(raw) != desired['digest']:
                return False
            parsed = tomllib.loads(raw.decode('utf-8'))
            config = {'federation': {**DEFAULTS, **parsed.get('federation', {})},
                'repos': parsed.get('repos', {}), 'peers': parsed.get('peers', {})}
            for source in self._sources:
                suspended = source._repository is not None and source._repository['localName'] not in config['repos']
                if source._policy_suspended != suspended or source._policy.cfg != config:
                    return False
            return True
        except (ContractError, OSError, ValueError):
            return False

    async def current(self, raw):
        """Read the actual retained prefix, including a genuinely empty owner.

        Projection status is an observation of all original sources and gates.
        Reading never projects a file or opens admissions after restart.
        """
        async with self._call():
            async with self._lock:
                envelope = self._owner._envelope(raw, 'configuration-read')
                await self._owner._authorize(raw, envelope)
                self._available()
                snapshot = await self._owner._ledger.current()
                wanted = envelope['payload']['configurationRef']
                if snapshot.sequence < wanted['revision']:
                    raise ContractError('configuration_unavailable')
                state = operation = None
                if snapshot.latest is None:
                    if snapshot.sequence != 0 or snapshot.records:
                        raise ContractError('configuration_unavailable')
                else:
                    # Reuse the existing full read path, including retained
                    # state, exact owner, signed reply and current read authority.
                    response = await ConfigurationOwner.handle(self._owner, raw)
                    public = base64.urlsafe_b64encode(bytes(SigningKey(self._owner._seed).verify_key)).decode().rstrip('=')
                    verified = verify_configuration_response(response, raw, public_key=public,
                        issuer_ref=strict_loads(self._owner._issuer), now=datetime.now(timezone.utc))
                    state = self._owner._retained(snapshot.latest)
                    if verified['state'] != state:
                        raise ContractError('federation_policy_stale')
                    operation = strict_loads(snapshot.latest.record)['operation']
                after = await self._owner._ledger.current()
                if (after.sequence != snapshot.sequence
                        or (None if after.latest is None else after.latest.record)
                            != (None if snapshot.latest is None else snapshot.latest.record)):
                    raise ContractError('federation_policy_stale')
                await self._owner._authorize(raw, envelope)
                self._available()
                result = {'format': 'amx-federation-policy-current-v1',
                    'configurationRef': dict(wanted, revision=snapshot.sequence),
                    'owner': strict_loads(self._owner._owner), 'target': self._owner.custody.target.descriptor,
                    'projected': self._observed_projection(state),
                    'state': state, 'operation': operation,
                    'originalOperationId': None if operation is None else operation['operationId'],
                    'originalPayloadDigest': None if operation is None else operation['payloadDigest']}
                validate('federation-policy-current-state', result)
                return canonical_bytes(result)

    async def client_command(self, raw, *, reply_subject):
        """Bind the exact external possession packet and actual received inbox."""
        async with self._call():
            host = getattr(self._owner, '_host', None)
            if (self._reply_prefix is None or host is None or host.owner is not self._owner
                    or self._reply_prefix != host._reply_prefix
                    or type(reply_subject) is not str or len(reply_subject) > 512
                    or not reply_subject.startswith(self._reply_prefix)
                    or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*', reply_subject[len(self._reply_prefix):])
                    or type(raw) is not bytes or len(raw) > 65536):
                raise ContractError('federation_policy_client_binding')
            host.check_health()
            packet = strict_loads(raw)
            validate('identity-ingress-request', packet)
            external = packet['claims']
            if external['contractId'] not in ('configuration-set', 'configuration-read', 'federation-policy-project'):
                raise ContractError('federation_policy_client_binding')
            cancellation = {'id': 'policy_cancel_' + payload_digest(packet).split(':')[1],
                'ownerHubId': self._owner._ledger._binding.hub_id, 'revision': 1}
            admitted = await self._owner.custody._ingress.admit(raw, cancellation_ref=cancellation)
            if admitted.envelope is None or admitted.decision.outcome != 'allowed':
                raise ContractError('federation_policy_client_binding')
            envelope = self._owner._envelope(admitted.envelope, external['contractId'])
            payload, operation = envelope['payload'], envelope['operation']
            if external['contractId'] == 'configuration-read':
                kind = 'current'
                result = await self.current(admitted.envelope)
            elif external['contractId'] == 'federation-policy-project':
                kind = 'projected'
                result = await self.project(admitted.envelope)
            else:
                if operation['caller']['kind'] != 'human':
                    raise ContractError('federation_policy_client_binding')
                document = strict_loads(base64.b64decode(payload['configurationBytes'], validate=True))
                if type(document) is not dict:
                    raise ContractError('federation_policy_client_binding')
                if document.get('format') == 'amx-federation-policy-preparation-v1':
                    kind = 'prepared'
                    result = await self.prepare(admitted.envelope)
                elif document.get('format') == 'amx-federation-policy-v1':
                    kind = 'committed'
                    result = await self.apply(admitted.envelope)
                    public = base64.urlsafe_b64encode(bytes(SigningKey(self._owner._seed).verify_key)).decode().rstrip('=')
                    verify_configuration_response(result, admitted.envelope, public_key=public,
                        issuer_ref=strict_loads(self._owner._issuer), now=datetime.now(timezone.utc))
                else:
                    raise ContractError('federation_policy_client_binding')
            decision, snapshot = await self._owner._authorize(admitted.envelope, envelope)
            self._available()
            host.check_health()
            response = strict_loads(self._signed_receipt(envelope, decision, snapshot, {
                'purpose': 'agentmux-federation-policy-client-response-v1',
                'kind': kind, 'replySubject': reply_subject, 'requestBinding': {
                    **{name: external[name] for name in ('hubId', 'profileId', 'authorityId', 'transportRef',
                        'grantRef', 'contractId', 'operationId', 'expectedVersion')},
                    'payloadDigest': payload_digest(external['payload']),
                    'callerRef': operation['caller']['authenticatedIdentityRef'], 'scope': operation['scope']},
                'resultBytes': base64.b64encode(result).decode()}, 'federation-policy-client-reply'))
            # The outer proof binds bytes the client actually sent. The admitted
            # message ID remains internal to the owner and its inner receipt.
            response['claims']['requestDigest'] = payload_digest(packet)
            response['signature'] = sign_claims(response['claims'], self._owner._seed)
            encoded = canonical_bytes(response)
            if len(encoded) > 65536:
                raise ContractError('federation_policy_response_size')
            return encoded

    async def apply(self, raw):
        """Retain the original commit/projection task when its waiter leaves."""
        async with self._call():
            return await self._apply_request(raw)

    async def _apply_request(self, raw):
        self._available()
        envelope = self._owner._envelope(raw, 'configuration-set')
        await self._owner._authorize(raw, envelope)
        self._available()
        key = canonical_bytes(envelope['operation'])
        original = self._operations.get(key)
        if original is None:
            if len(self._operations) >= 32:
                # Completed calls are not needed for recovery; the owner ledger
                # retains their original outcomes and supplies replay authority.
                self._operations = {key: task for key, task in self._operations.items() if not task.done()}
                if len(self._operations) >= 32:
                    raise ContractError('federation_policy_transition_capacity')
            original = asyncio.create_task(self._apply(raw, envelope))
            original.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            self._operations[key] = original
        await asyncio.wait({original})
        result = original.result()
        await self._owner._authorize(raw, envelope)
        self._available()
        if self._uncertain is not None or any(source._policy_paused for source in self._sources):
            raise ContractError('federation_policy_projection_uncertain')
        return result

    async def _apply(self, raw, envelope):
        async with self._owner._policy_call():
            async with self._lock:
                self._available()
                await self._owner._authorize(raw, envelope)
                self._available()
                operation, payload = envelope['operation'], envelope['payload']
                state = {'format': 'amx-configuration-v1', 'owner': payload['owner'],
                    'schemaRef': payload['schemaRef'], 'secretReferences': payload['secretReferences'],
                    'configurationBytes': payload['configurationBytes'],
                    'configurationChecksum': _digest(base64.b64decode(payload['configurationBytes'], validate=True)),
                    'revision': operation['expectedVersion'] + 1}
                document = strict_loads(self._owner._document(state))
                intent = document['projectionIntent']
                if (intent['operationId'] != operation['operationId']
                        or intent['actorRef'] != operation['effectiveActorRef']
                        or intent['callerRef'] != operation['caller']['authenticatedIdentityRef']):
                    raise ContractError('federation_policy_binding')
                key = (operation['operationId'], operation['payloadDigest'])
                if self._uncertain is not None and self._uncertain != key:
                    raise ContractError('federation_policy_projection_uncertain')
                old = await self._owner.custody.retrieve(document['oldPolicy'])
                await self._owner._authorize(raw, envelope)
                desired = await self._owner.custody.retrieve(document['desiredPolicy'])
                await self._owner._authorize(raw, envelope)
                if changed_policy(old, document['projectionIntent']['change'],
                        repository=self._selection['repository']) != desired:
                    raise ContractError('federation_policy_change_invalid')
                actual, before = self._read_source()
                stored = await self._owner._ledger.outcome(*key)
                if actual != old and (stored is None or actual != desired):
                    raise ContractError('federation_policy_source_changed')
                paused = []
                committing = False
                try:
                    if self._selected_host is not None:
                        await self._selected_host.pause_policy_transition(self, original_operation=key)
                    for source in self._sources:
                        await source._pause_policy(self)
                        paused.append(source)
                    candidates = []
                    for source in self._sources:
                        candidates.append(await source._submit(source._policy_candidate, self, desired))
                    if self._read_source() != (actual, before):
                        raise ContractError('federation_policy_source_changed')
                    # A refusal here has not entered the committing owner. Once
                    # handed off, absence of a reply or record cannot prove that
                    # the broker rejected the original operation.
                    await self._owner._authorize(raw, envelope)
                    self._available()
                    committing = True
                    self._uncertain = key
                    self._commit_handed_off = key
                    # Call the existing base dispatcher, preserving the typed
                    # owner's _set, current grants, CAS, events and signed reply.
                    reply = await ConfigurationOwner.handle(self._owner, raw)
                    stored = await self._owner._ledger.outcome(*key)
                    if stored is None:
                        raise ContractError('federation_policy_projection_uncertain')
                    committed = await self._owner._resolve_stored(raw, envelope, stored)
                    if committed.document != document or committed.policy_bytes != desired:
                        raise ContractError('federation_policy_projection_uncertain')
                    decision, _ = await self._owner._authorize(raw, envelope)
                    self._available()
                    for source in self._sources:
                        source._begin_policy_projection(self)
                    identity = await asyncio.to_thread(self._replace, actual, desired, before, decision.valid_until)
                    self._available()
                    for source, candidate in zip(self._sources, candidates):
                        source._install_policy_generation(self, candidate, identity, committed.revision)
                    if self._selected_host is not None:
                        await self._selected_host.resume_policy_transition(self, committed.revision,
                            tuple(dict.fromkeys(source._repository['repositoryId'] for source in self._sources
                                if source._policy_suspended and source._repository is not None)))
                    await self._owner._authorize(raw, envelope)
                    self._uncertain = None
                    return reply
                except BaseException as error:
                    if not committing and isinstance(error, ContractError):
                        self._precommit_refusal = key
                        if self._selected_host is None:
                            for source in paused:
                                source._resume_old_policy(self)
                            self._precommit_refusal = None
                        elif (self._selected_host._policy_change is not None
                                and self._selected_host._policy_change[0] is self):
                            try:
                                await self._selected_host.abort_policy_transition(self)
                            except BaseException:
                                self._uncertain = key
                                raise
                    # A commit or file effect may already exist. Keep admissions
                    # paused and let the original retained intent reconcile it.
                    raise

    async def project(self, raw):
        """Reconcile the original committed intent under a distinct service grant."""
        async with self._call():
            envelope = self._owner._envelope(raw, 'federation-policy-project')
            await self._project_authority(raw, envelope)
            key = b'project:' + canonical_bytes(envelope['operation'])
            original = self._operations.get(key)
            if original is None:
                if len(self._operations) >= 32:
                    self._operations = {key: task for key, task in self._operations.items() if not task.done()}
                    if len(self._operations) >= 32:
                        raise ContractError('federation_policy_transition_capacity')
                original = asyncio.create_task(self._project(raw, envelope))
                original.add_done_callback(lambda done: None if done.cancelled() else done.exception())
                self._operations[key] = original
            await asyncio.wait({original})
            result = original.result()
            await self._project_authority(raw, envelope)
            return result

    async def _project_authority(self, raw, envelope):
        self._available()
        operation, payload = envelope['operation'], envelope['payload']
        if (envelope['contractId'] != 'federation-policy-project' or self._projection_service is None
                or self._projection_transport is None or self._projection_grant is None
                or operation['caller']['kind'] != 'service'
                or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != self._projection_service
                or canonical_bytes(operation['effectiveActorRef']) != self._projection_service
                or canonical_bytes(operation['grantRef']) != self._projection_grant
                or canonical_bytes(envelope['ingressAttestation']['claims']['authenticatedTransportRef']) != self._projection_transport
                or operation['expectedVersion'] != payload['configurationRef']['revision']
                or any(operation[name] is not None for name in ('taskId', 'runId', 'attemptId', 'delegationRef'))
                or payload['target'] != self._owner.custody.target.descriptor):
            raise ContractError('federation_policy_projection_refused')
        decision, snapshot = await self._owner._authorize(raw, envelope)
        self._available()
        return decision, snapshot

    async def _project(self, raw, envelope):
        async with self._owner._policy_call():
            async with self._lock:
                self._bootstrap_projection = None
                await self._project_authority(raw, envelope)
                payload = envelope['payload']
                key = (payload['originalOperationId'], payload['originalPayloadDigest'])
                if self._uncertain is not None and self._uncertain != key:
                    raise ContractError('federation_policy_projection_uncertain')
                stored = await self._owner._ledger.outcome(*key)
                if stored is None or stored.sequence != payload['configurationRef']['revision']:
                    raise ContractError('federation_policy_projection_refused')
                committed = await self._owner._resolve_stored(raw, envelope, stored)
                document, desired = committed.document, committed.policy_bytes
                if (document['target'] != payload['target']
                        or document['desiredPolicy']['digest'] != payload['desiredPolicyDigest']):
                    raise ContractError('federation_policy_projection_refused')
                old = await self._owner.custody.retrieve(document['oldPolicy'])
                await self._project_authority(raw, envelope)
                if changed_policy(old, document['projectionIntent']['change'],
                        repository=self._selection['repository']) != desired:
                    raise ContractError('federation_policy_change_invalid')
                path = self._selection['source']['policy']['path']
                before = _file_identity(path)
                actual = _read_material(path, max_bytes=65536, return_bytes=True)
                if before != _file_identity(path) or actual not in (old, desired):
                    raise ContractError('federation_policy_source_changed')
                for source in self._sources:
                    if source._store is None:
                        await self._project_authority(raw, envelope)
                        await source._recover_policy_start(self, actual, before)
                    if (source._database_identity != _file_identity(source._pins['database']['path'], mutable=True)
                            or (before != source._policy_identity
                                and not (source._policy_paused and source._policy_replacing
                                    and before == self._projected_identity and actual == desired))):
                        raise ContractError('federation_policy_source_changed')
                self._uncertain = key
                if self._selected_host is not None:
                    await self._selected_host.pause_policy_transition(self, original_operation=key)
                for source in self._sources:
                    await source._pause_policy(self)
                candidates = [await source._submit(source._policy_candidate, self, desired)
                    for source in self._sources]
                # Revalidate the latest retained decision, not a cached receipt,
                # after joins and database checks have yielded to other owners.
                current = await self._owner._ledger.current()
                if current.sequence != stored.sequence or current.latest.record != stored.record:
                    raise ContractError('federation_policy_stale')
                decision, _ = await self._project_authority(raw, envelope)
                for source in self._sources:
                    source._begin_policy_projection(self)
                identity = await asyncio.to_thread(self._replace, actual, desired, before, decision.valid_until)
                self._available()
                for source, candidate in zip(self._sources, candidates):
                    source._install_policy_generation(self, candidate, identity, committed.revision)
                if self._selected_host is not None:
                    await self._selected_host.resume_policy_transition(self, committed.revision,
                        tuple(dict.fromkeys(source._repository['repositoryId'] for source in self._sources
                            if source._policy_suspended and source._repository is not None)))
                decision, snapshot = await self._project_authority(raw, envelope)
                self._uncertain = None
                receipt = self._signed_receipt(envelope, decision, snapshot, {
                    'purpose': 'agentmux-federation-policy-projected-v1',
                    'originalOperationId': key[0], 'originalPayloadDigest': key[1],
                    'desiredPolicyDigest': payload['desiredPolicyDigest']}, 'federation-policy-projected-reply')
                self._bootstrap_projection = _PolicyBootstrapProjection(raw, stored.record,
                    committed.revision, identity, payload['desiredPolicyDigest'],
                    tuple((source, source._store, source._database_identity, source._policy,
                        source._policy_identity, source._policy_generation, source._policy_suspended)
                        for source in self._sources))
                return receipt

    async def _bootstrap_authority(self):
        """Recheck the same completed service projection for structural startup."""
        async with self._call():
            async with self._lock:
                proof = self._bootstrap_projection
                if proof is None or self._uncertain is not None:
                    raise ContractError('selected_policy_bootstrap_refused')
                envelope = self._owner._envelope(proof.request, 'federation-policy-project')
                await self._project_authority(proof.request, envelope)
                latest = await self._owner._ledger.current()
                if (proof is not self._bootstrap_projection or latest.sequence != proof.revision
                        or latest.latest is None or latest.latest.record != proof.record):
                    raise ContractError('selected_policy_bootstrap_refused')
                self._owner._retained(latest.latest)
                await self._project_authority(proof.request, envelope)
                raw, identity = self._read_source()
                if (proof is not self._bootstrap_projection or identity != proof.identity
                        or _digest(raw) != proof.digest
                        or any(source._store is not store or source._database_identity != database
                            or source._policy is not policy or source._policy_identity != policy_identity
                            or source._policy_generation != generation or source._policy_suspended != suspended
                            or source._policy_paused or source._policy_replacing
                            for source, store, database, policy, policy_identity, generation, suspended in proof.sources)):
                    raise ContractError('selected_policy_bootstrap_refused')
                return proof

    def _replace(self, old, desired, before, valid_until):
        path = self._selection['source']['policy']['path']
        directory, name = _directory(path)
        temporary = '.policy-' + uuid.uuid4().hex
        descriptor = None
        owned = None
        try:
            if _file_identity(path) != before or _read_material(path, max_bytes=65536, return_bytes=True) != old:
                raise ContractError('federation_policy_source_changed')
            if old == desired:
                return before
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=directory)
            owned = os.fstat(descriptor)
            with os.fdopen(descriptor, 'wb') as stream:
                descriptor = None
                stream.write(desired)
                stream.flush()
                os.fsync(stream.fileno())
            if (_file_identity(path) != before
                    or _read_material(path, max_bytes=65536, return_bytes=True) != old
                    or datetime.now(timezone.utc) >= valid_until):
                raise ContractError('federation_policy_source_changed')
            # The private parent descriptor prevents symlink traversal. Every
            # participating writer uses this transition; observed drift refuses.
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            self._projected_identity = _file_identity(path)
            os.fsync(directory)
            identity = _file_identity(path)
            if (_read_material(path, max_bytes=65536, return_bytes=True) != desired
                    or identity != _file_identity(path)):
                raise ContractError('federation_policy_source_changed')
            return identity
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if owned is not None:
                try:
                    current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                        os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.close(directory)

    async def close(self):
        self._closed = True
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())
        await _join(self._closing)

    async def _close(self):
        pending = tuple(self._calls)
        if pending:
            await asyncio.wait(pending)
        for original in tuple(self._operations.values()):
            try:
                await _join(original)
            except BaseException:
                if not original.done() or asyncio.current_task().cancelling():
                    raise
