"""Join original configuration watches without renewing their read authority."""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key
from identity.ingress import verify_possession


PURPOSE = 'agentmux-configuration-watch-close-v1'
_BOUND = ('watchRequestDigest', 'operationId', 'cancellationRef', 'owner',
          'configurationRef', 'profileId', 'hubId', 'authorityId')


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _sizing_frames(binding):
    """Use the same conservative canonical frames as the native preparer."""
    stamp = '9999-12-31T23:59:59.999999Z'
    maximum_ref = {'id': 'a' * 96, 'ownerHubId': 'a' * 96, 'revision': 9007199254740991}
    def encode(claims):
        return canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims, 'signature': 'a' * 86})
    common = {'requestId': 'request_' + 'a' * 64,
        'replySubject': '_INBOX.' + 'a' * 64 + '.' + 'a' * 64, 'issuedAt': stamp}
    proof = encode({'purpose': 'agentmux-configuration-watch-close-response-v1',
        **{k: binding[k] for k in _BOUND}, **common,
        'requestDigest': 'sha256:' + 'a' * 64, 'requestSigningKeyRef': binding['signingKeyRef'],
        'requestPublicKey': 'a' * 43, 'watchExpiresAt': stamp, 'signingKeyRef': maximum_ref,
        'authorityRef': maximum_ref, 'validUntil': stamp, 'joined': False, 'receiptConfirmed': False})
    confirmation = encode({'purpose': PURPOSE, **binding, **common, 'expiresAt': stamp,
        'joinedResponseBytes': base64.b64encode(proof).decode()})
    return proof, confirmation


@dataclass(frozen=True, repr=False)
class _Admission:
    binding: bytes
    host_public_key: str
    expires_at: datetime
    authority_ref: bytes


class _Allocation:
    def __init__(self, digest, delivery):
        self.digest = digest
        self.admission = asyncio.get_running_loop().create_future()
        self.handler = self.watch = self.closing = None
        self.deliveries = set() if delivery is None else {delivery}
        self.joined = self.confirmed = False


class ConfigurationWatchControls:
    """Retain each original allocation and its receipt until safe retirement.

    Only an authenticated receipt can make a joined entry reclaimable. The
    original signed deadline then prevents a delayed request from allocating
    again. A retained service-signed proof lets a host recover a lost receipt
    acknowledgement after reclamation, without reopening a watch or reading data.
    """
    def __init__(self, owner):
        self._owner = owner
        self._entries = {}
        self._capacity = 1024
        self._active = set()
        self._closed = False

    def __repr__(self):
        return '<ConfigurationWatchControls private>'

    def _reclaim(self):
        now = datetime.now(timezone.utc)
        for digest, entry in tuple(self._entries.items()):
            if (entry.joined and entry.confirmed and entry.admission.done()
                    and now >= entry.admission.result().expires_at):
                del self._entries[digest]

    def reserve(self, envelope, delivery):
        """Reserve before the first authorization await; no resource is open yet."""
        end = min(datetime.fromisoformat(envelope['operation']['deadline']),
            datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt']))
        if self._closed or datetime.now(timezone.utc) >= end:
            raise ContractError('configuration_watch_expired')
        # The full owner appears in both the proof and its enclosing receipt.
        # Refuse an unrepresentable exchange before any resource allocation.
        proof, confirmation = _sizing_frames(self._binding(envelope))
        if len(proof) > 12288 or len(base64.b64encode(proof)) > 16384 or len(confirmation) > 65536:
            raise ContractError('configuration_watch_receipt_capacity')
        self._reclaim()
        digest = payload_digest(envelope)
        if digest in self._entries:
            raise ContractError('configuration_watch_duplicate')
        if len(self._entries) >= self._capacity:
            raise ContractError('configuration_watch_capacity')
        entry = _Allocation(digest, delivery)
        self._entries[digest] = entry
        if delivery is not None:
            delivery.add_done_callback(lambda task: self._delivery_done(entry, task))
        return entry

    def _binding(self, envelope):
        operation, reader = envelope['operation'], self._owner._authority
        return {'watchRequestDigest': payload_digest(envelope), 'operationId': operation['operationId'],
            'cancellationRef': operation['cancellationRef'], 'owner': envelope['payload']['owner'],
            'configurationRef': envelope['payload']['configurationRef'], 'profileId': reader._profile,
            'hubId': reader._hub, 'authorityId': reader._entity,
            'signingKeyRef': envelope['ingressAttestation']['claims']['authenticatedTransportRef']}

    def retain_handler(self, entry, handler):
        entry.handler = handler
        def finished(original):
            if not original.cancelled():
                original.exception()
            if not entry.admission.done():
                entry.admission.set_result(None)
            if entry.admission.result() is None:
                self._discard_unadmitted(entry)
            else:
                self.begin_close(entry)
        handler.add_done_callback(finished)

    def _delivery_done(self, entry, task):
        entry.deliveries.discard(task)
        self._discard_unadmitted(entry)

    def _discard_unadmitted(self, entry):
        if (entry.admission.done() and entry.admission.result() is None
                and entry.handler is not None and entry.handler.done()
                and not entry.deliveries and entry.watch is None
                and self._entries.get(entry.digest) is entry):
            del self._entries[entry.digest]

    def admit(self, entry, snapshot, envelope):
        """Capture the exact host key from the snapshot authorizing this watch."""
        record, operation = strict_loads(snapshot.record), envelope['operation']
        state = record['state']
        index = _indexes(state, record['ownerHubId'])
        reference = envelope['ingressAttestation']['claims']['authenticatedTransportRef']
        transport = index['transports'].get(_key(reference))
        issuer = None if transport is None else index['issuers'].get(_key(transport['issuerRef']))
        host = None if transport is None else index['identities'].get(_key(transport['identityRef']))
        rows = [row for row in state.get('nativeInstances', []) if row['owner'] == envelope['payload']['owner']]
        now = datetime.now(timezone.utc)
        end = min(datetime.fromisoformat(operation['deadline']),
            datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt']))
        if (entry.admission.done() or now >= end or transport is None or issuer is None or host is None
                or transport['method'] != 'nats-credential-mapping'
                or not all(_active(item, now) for item in (transport, issuer, host))
                or host['kind'] != 'service' or operation['caller']['kind'] != 'service'
                or operation['caller']['authenticatedIdentityRef'] != host['ref']
                or operation['effectiveActorRef'] != host['ref']
                or len(rows) != 1 or rows[0]['hostIdentityRef'] != host['ref']
                or rows[0]['status'] != 'active'):
            raise ContractError('configuration_watch_admission_refused')
        binding = {'watchRequestDigest': entry.digest, 'operationId': operation['operationId'],
            'cancellationRef': operation['cancellationRef'], 'owner': envelope['payload']['owner'],
            'configurationRef': envelope['payload']['configurationRef'], 'profileId': state['profileId'],
            'hubId': record['ownerHubId'], 'authorityId': record['entityId'], 'signingKeyRef': reference}
        authority = {'id': record['entityId'], 'ownerHubId': record['ownerHubId'], 'revision': record['entityVersion']}
        entry.admission.set_result(_Admission(canonical_bytes(binding), transport['publicKey'], end,
            canonical_bytes(authority)))

    def begin_close(self, entry):
        if entry.closing is None or (entry.closing.done() and entry.closing.exception() is not None):
            entry.closing = asyncio.create_task(self._join(entry))
            entry.closing.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        return entry.closing

    async def _join(self, entry):
        # An early close waits for the same admission. It cannot cancel that
        # decision and then manufacture a successful join for an unknown request.
        await asyncio.wait({entry.admission})
        if entry.admission.result() is not None and not entry.handler.done():
            entry.handler.cancel()
        await asyncio.gather(entry.handler, return_exceptions=True)
        if entry.watch is not None:
            await entry.watch.close(timeout=None)
        deliveries = tuple(entry.deliveries)
        if asyncio.current_task() in deliveries:
            raise ContractError('configuration_watch_cleanup_incomplete')
        if deliveries:
            await asyncio.gather(*deliveries, return_exceptions=True)
        if entry.admission.result() is not None:
            entry.joined = True
            # A completed handler may contain a configuration response or a
            # private traceback. Retain only cleanup metadata after it joins.
            entry.handler = None
            entry.watch = None
            entry.deliveries.clear()

    def _fresh(self, request, reply):
        claims = request['claims']
        issued, end = (datetime.fromisoformat(claims[k]) for k in ('issuedAt', 'expiresAt'))
        if not issued <= datetime.now(timezone.utc) < end or end - issued > timedelta(seconds=5):
            raise ContractError('configuration_watch_close_expired')
        if claims['replySubject'] != reply:
            raise ContractError('configuration_watch_close_reply_binding')
        return end

    def _source_binding(self, claims):
        reader, binding = self._owner._authority, self._owner._ledger._binding
        if (claims['profileId'] != reader._profile or claims['hubId'] != reader._hub
                or claims['authorityId'] != reader._entity
                or claims['configurationRef']['id'] != binding.entity_id
                or claims['configurationRef']['ownerHubId'] != binding.hub_id
                or not self._owner._same_slot(claims['owner'])):
            raise ContractError('configuration_watch_close_source_binding')

    def _authenticate(self, request, admission):
        claims, expected = request['claims'], strict_loads(admission.binding)
        if any(claims[k] != expected[k] for k in (*_BOUND, 'signingKeyRef')):
            raise ContractError('configuration_watch_close_binding')
        verify_possession(claims, request['signature'], admission.host_public_key)

    async def _historical_signer(self, proof, current):
        """Resolve the proof's exact signer from trusted authority, never its wire key."""
        reader = self._owner._authority
        reference = proof['authorityRef']
        if (proof['signingKeyRef'] != strict_loads(self._owner._issuer)
                or reference['id'] != reader._entity or reference['ownerHubId'] != reader._hub
                or reference['revision'] > current['entityVersion']):
            raise ContractError('configuration_watch_receipt_authority')
        # A validated retained record proves the signer was enrolled at the
        # authority revision covered by the original signed response. Inactive
        # historical keys verify only that receipt; they never authorize reads.
        if reference['revision'] == current['entityVersion']:
            record = current
        elif isinstance(reader, LedgerAuthorityReader):
            history = await reader._ledger.current()
            if reference['revision'] > history.sequence:
                raise ContractError('configuration_watch_receipt_authority')
            stored = history.records[reference['revision'] - 1]
            record = strict_loads(reader._validate_snapshot(stored.record, stored.sequence).record)
            if record['entityVersion'] != reference['revision']:
                raise ContractError('configuration_watch_receipt_authority')
        else:
            raise ContractError('configuration_watch_receipt_history_unavailable')
        index = _indexes(record['state'], record['ownerHubId'])
        issuer = index['issuers'].get(_key(proof['signingKeyRef']))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        issued, end = (datetime.fromisoformat(proof[k]) for k in ('issuedAt', 'validUntil'))
        if (issuer is None or identity is None or identity['kind'] != 'service'
                or not _active(issuer, issued) or not _active(identity, issued)
                or not issued < end <= datetime.fromisoformat(issuer['expiresAt'])
                or end - issued > timedelta(seconds=5) or issued > datetime.now(timezone.utc)):
            raise ContractError('configuration_watch_receipt_signer')
        return issuer['publicKey']

    async def _receipt(self, request, entry, current):
        claims = request['claims']
        try:
            encoded = claims['joinedResponseBytes']
            raw = base64.b64decode(encoded, validate=True)
            if not 1 <= len(raw) <= 12288 or base64.b64encode(raw).decode() != encoded:
                raise ValueError()
            response = strict_loads(raw)
            validate('configuration-watch-close-response', response)
        except Exception:
            raise ContractError('configuration_watch_receipt_invalid') from None
        proof = response['claims']
        self._source_binding(proof)
        if (not proof['joined'] or any(proof[k] != claims[k] for k in _BOUND)
                or proof['requestSigningKeyRef'] != claims['signingKeyRef']):
            raise ContractError('configuration_watch_receipt_binding')
        public = await self._historical_signer(proof, current)
        verify_possession(proof, response['signature'], public)
        expires = datetime.fromisoformat(proof['watchExpiresAt'])
        binding = {k: claims[k] for k in (*_BOUND, 'signingKeyRef')}
        admission = _Admission(canonical_bytes(binding), proof['requestPublicKey'], expires,
            canonical_bytes(proof['authorityRef']))
        if entry is not None:
            original = entry.admission.result()
            floor = strict_loads(original.authority_ref)
            if (not entry.joined or admission.binding != original.binding
                    or admission.host_public_key != original.host_public_key or expires != original.expires_at
                    or proof['authorityRef']['revision'] < floor['revision']):
                raise ContractError('configuration_watch_receipt_binding')
        elif datetime.now(timezone.utc) < expires:
            # Retirement is impossible before this cutoff. An unknown request
            # must not be treated as joined while it could still be allocated.
            raise ContractError('configuration_watch_receipt_early')
        self._authenticate(request, admission)
        return admission

    async def handle(self, raw, *, reply_subject):
        if self._closed or type(raw) is not bytes or len(raw) > 65536 or len(self._active) >= 32:
            raise ContractError('configuration_watch_close_unavailable')
        request = strict_loads(raw)
        validate('configuration-watch-close', request)
        end = self._fresh(request, reply_subject)
        claims = request['claims']
        self._source_binding(claims)
        task = asyncio.current_task()
        self._active.add(task)
        try:
            self._reclaim()
            entry = self._entries.get(claims['watchRequestDigest'])
            if entry is None and 'joinedResponseBytes' not in claims:
                raise ContractError('configuration_watch_allocation_required')
            if entry is not None:
                remaining = max(0, (end - datetime.now(timezone.utc)).total_seconds())
                _, pending = await asyncio.wait({entry.admission}, timeout=min(3, remaining))
                if pending or entry.admission.result() is None:
                    raise ContractError('configuration_watch_allocation_required')
                admission = entry.admission.result()
                self._authenticate(request, admission)
                remaining = max(0, (end - datetime.now(timezone.utc)).total_seconds())
                work = self.begin_close(entry)
                _, pending = await asyncio.wait({work}, timeout=min(3, remaining))
                if not pending:
                    work.result()
                joined = not pending and entry.joined
            else:
                joined = True
            current = strict_loads((await self._owner._authority.current()).record)
            confirmed = 'joinedResponseBytes' in claims
            if confirmed:
                admission = await self._receipt(request, entry, current)
                if entry is not None:
                    entry.confirmed = True
                # Resolving historical authority can await its retained ledger.
                # Recheck the current signing authority after that work finishes.
                current = strict_loads((await self._owner._authority.current()).record)
            response = self._respond(request, reply_subject, admission, current, joined, confirmed)
            self._reclaim()
            return response
        finally:
            self._active.discard(task)

    def _respond(self, request, reply_subject, admission, record, joined, confirmed):
        end = self._fresh(request, reply_subject)
        self._authenticate(request, admission)
        wanted = request['claims']
        index = _indexes(record['state'], record['ownerHubId'])
        issuer = index['issuers'].get(_key(strict_loads(self._owner._issuer)))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        now = datetime.now(timezone.utc)
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._owner._seed).verify_key)).decode().rstrip('=')
        floor = strict_loads(admission.authority_ref)
        if (self._closed or self._owner._closed or issuer is None or identity is None
                or identity['kind'] != 'service' or not _active(issuer, now) or not _active(identity, now)
                or issuer['publicKey'] != public or record['entityVersion'] < floor['revision']
                or record['entityId'] != wanted['authorityId'] or record['ownerHubId'] != wanted['hubId']
                or record['state']['profileId'] != wanted['profileId']):
            raise ContractError('configuration_signer_unavailable')
        end = min(end, datetime.fromisoformat(issuer['expiresAt']))
        claims = {'purpose': 'agentmux-configuration-watch-close-response-v1',
            'requestId': wanted['requestId'], **{k: wanted[k] for k in _BOUND},
            'replySubject': reply_subject, 'requestDigest': payload_digest(request),
            'requestSigningKeyRef': wanted['signingKeyRef'], 'requestPublicKey': admission.host_public_key,
            'watchExpiresAt': _stamp(admission.expires_at), 'signingKeyRef': strict_loads(self._owner._issuer),
            'authorityRef': {'id': record['entityId'], 'ownerHubId': record['ownerHubId'], 'revision': record['entityVersion']},
            'issuedAt': _stamp(now), 'validUntil': _stamp(end), 'joined': joined,
            'receiptConfirmed': confirmed}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519', 'canonicalization': 'RFC8785-JCS-UTF8',
            'claims': claims, 'signature': sign_claims(claims, self._owner._seed)}
        validate('configuration-watch-close-response', response)
        return canonical_bytes(response)

    async def close(self):
        self._closed = True
        work = tuple(self.begin_close(entry) for entry in self._entries.values())
        if work:
            results = await asyncio.gather(*work, return_exceptions=True)
            if any(isinstance(result, BaseException) for result in results):
                raise ContractError('configuration_watch_cleanup_incomplete')
