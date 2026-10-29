"""Signed work frames on the selected storage owner route."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import re

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key
from identity.work_client import WORK_COMMANDS
from identity.ingress import EnrolledIngress, verify_possession
from .work import WorkStorageResource

LIMIT = 1048576
_INBOX = re.compile(r'_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?\Z')


def _time(value):
    return datetime.fromisoformat(value)


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _parse(raw, schema):
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ContractError('legacy_work_frame_invalid')
    value = strict_loads(raw)
    validate(schema, value)
    if canonical_bytes(value) != raw:
        raise ContractError('legacy_work_frame_invalid')
    return value


class WorkBridgeService:
    """Borrow owners and ingress; retain original writes through cancellation."""
    def __init__(self, ingress, *, resources, service_identity_ref, service_instance_id,
                 signing_key_ref, signing_seed):
        if (type(ingress) is not EnrolledIngress or not isinstance(ingress._reader, LedgerAuthorityReader)
                or type(resources) is not tuple or not resources or len(resources) > 64
                or any(type(resource) is not WorkStorageResource or not resource._legacy_actors for resource in resources)
                or len({r.binding.entity_id for r in resources}) != len(resources)
                or len({r.binding.scope for r in resources}) != 1
                or any(r.binding.hub_id != ingress._reader._hub
                    or r._legacy_authority is not ingress._reader for r in resources)
                or type(signing_seed) is not bytes or len(signing_seed) != 32
                or type(service_instance_id) is not str or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', service_instance_id)):
            raise ContractError('legacy_work_service_configuration')
        from .policy import _reference
        if not _reference(service_identity_ref) or not _reference(signing_key_ref):
            raise ContractError('legacy_work_service_configuration')
        self._ingress, self._authority = ingress, ingress._reader
        self._resources = {r.binding.entity_id: r for r in resources}
        self._identity, self._issuer = map(canonical_bytes, (service_identity_ref, signing_key_ref))
        self._instance, self._seed = service_instance_id, signing_seed
        self._active, self._workers = set(), set()
        from .work_lifecycle import WorkLifecycleOwner
        lifecycle = {id(owner): owner for resource in resources
            if type(owner := getattr(resource, '_lifecycle_owner', None)) is WorkLifecycleOwner}
        # Each repository in an atomic lifecycle batch must reach the owner
        # before any result can finish. Count both request and worker custody,
        # with bounded room for the batch's inspect and recovery calls.
        participants = max((len(owner._resources) for owner in lifecycle.values()), default=0)
        self._capacity = max(32, 2 * participants + 32) if participants else 32
        self._closed, self._closing = False, None

    def __repr__(self):
        return '<WorkBridgeService private>'

    async def _admit(self, raw, reply_subject):
        request = _parse(raw, 'identity-ingress-request')
        claims = request['claims']
        if (claims['contractId'] not in WORK_COMMANDS or claims.get('replySubject') != reply_subject
                or type(reply_subject) is not str or not _INBOX.fullmatch(reply_subject)
                or _time(claims['expiresAt']) - _time(claims['issuedAt']) > timedelta(seconds=5)):
            raise ContractError('legacy_work_request_refused')
        validate(claims['contractId'], claims['payload'])
        resource = self._resources.get(claims['payload']['resourceRef']['id'])
        if resource is None:
            raise ContractError('legacy_work_request_refused')
        cancellation = {'id': 'cancel_work_' + hashlib.sha256(claims['operationId'].encode()).hexdigest(),
            'ownerHubId': resource.binding.hub_id, 'revision': 1}
        # Admission checks current transport possession, principal and exact
        # grant here and again after the owning operation completes.
        admitted = await self._ingress.admit(raw, cancellation_ref=cancellation)
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('legacy_work_request_refused')
        checked = await resource.authorize_legacy(self._authority, admitted.envelope,
            source_expectation=claims.get('workSource'))
        return request, resource, admitted.envelope, checked

    @staticmethod
    def _record_bound(now, started, bounds):
        """Log which bound set a reply's validity: closed names and milliseconds only."""
        try:
            import syslog
            remaining = {name: int((value - now).total_seconds() * 1000) for name, value in bounds.items()
                         if value is not None}
            record = 'application_services_reply_bound bound=%s handle_ms=%d %s' % (
                min(remaining, key=remaining.get),
                -1 if started is None else int((now - started).total_seconds() * 1000),
                ' '.join('%s_ms=%d' % item for item in sorted(remaining.items())))
            syslog.syslog(syslog.LOG_NOTICE, record)
        except BaseException:
            pass

    def _sign(self, request, resource, result, checked, *, original_valid_until=None, started=None):
        # Domain permission and reply signer come from the same final snapshot.
        # No await separates that checked admission from signing and disclosure.
        snapshot = checked.snapshot
        now = datetime.now(timezone.utc)
        index = _indexes(strict_loads(snapshot.record)['state'], self._authority._hub)
        signer = index['issuers'].get(_key(strict_loads(self._issuer)))
        identity = index['identities'].get(_key(strict_loads(self._identity)))
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        if (signer is None or identity is None or not _active(signer, now) or not _active(identity, now)
                or identity['kind'] != 'service' or signer['identityRef'] != strict_loads(self._identity)
                or signer['instanceId'] != self._instance or signer['publicKey'] != public):
            raise ContractError('legacy_work_signer_unavailable')
        claims = request['claims']
        end = min(checked.valid_until, _time(claims['expiresAt']), _time(signer['expiresAt']))
        if original_valid_until is not None:
            end = min(end, original_valid_until)
        self._record_bound(now, started, {'checked': checked.valid_until, 'request': _time(claims['expiresAt']),
            'signer': _time(signer['expiresAt']), 'original': original_valid_until})
        task = asyncio.current_task()
        if self._closed or task is None or task.cancelling() or not now < end:
            raise ContractError('legacy_work_service_unavailable')
        from .work_source import check_source_disclosure
        if not check_source_disclosure(resource, checked,
            mode=(result.get('sourceBinding', {}).get('coreTransport')
                if claims['contractId'] == 'federation-work-inspect' else None)):
            resource._current()
        response = {k: claims[k] for k in ('profileId', 'hubId', 'authorityId', 'operationId', 'replySubject')}
        record = strict_loads(snapshot.record)
        response.update(purpose='agentmux-legacy-work-response-v1',
            serviceIdentityRef=strict_loads(self._identity), serviceInstanceId=self._instance,
            signingKeyRef=strict_loads(self._issuer), requestContractId=claims['contractId'],
            requestDigest=payload_digest(request), payloadDigest=payload_digest(claims['payload']),
            resourceRef=claims['payload']['resourceRef'], authorityRef={'id': record['entityId'],
                'ownerHubId': record['ownerHubId'], 'revision': record['entityVersion']},
            result=result, issuedAt=_stamp(now), validUntil=_stamp(end))
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': response,
            'signature': sign_claims(response, self._seed)})

    async def handle(self, raw, *, received_reply_subject):
        if self._closed or len(self._active) + len(self._workers) >= self._capacity:
            raise ContractError('legacy_work_service_unavailable')
        task = asyncio.current_task()
        self._active.add(task)
        started = datetime.now(timezone.utc)
        try:
            async with asyncio.timeout(5):
                request, resource, inner, original = await self._admit(raw, received_reply_subject)
                if self._closed:
                    raise ContractError('legacy_work_service_unavailable')
                worker = asyncio.create_task(resource.legacy(self._authority, inner,
                    source_expectation=request['claims'].get('workSource')))
                self._workers.add(worker)
                def finished(original):
                    self._workers.discard(original)
                    if not original.cancelled():
                        original.exception()
                worker.add_done_callback(finished)
                result = await asyncio.shield(worker)
                from .work_lifecycle import LIFECYCLE_COMMANDS
                claims = request['claims']
                source = None if original.source is None else strict_loads(original.source)
                if (claims['contractId'] in LIFECYCLE_COMMANDS and source is not None
                        and source.get('coreTransport', {}).get('mode') == 'tm218-core-v1'):
                    from .work_source import _core_owner
                    # The original effect has committed. Install its actual role
                    # interests before the unchanged current source proof runs.
                    owner = _core_owner(resource, disclosure=True)
                    if owner is None:
                        raise ContractError('legacy_work_service_unavailable')
                    role_sync = asyncio.create_task(owner._roles.sync())
                    self._workers.add(role_sync)
                    role_sync.add_done_callback(finished)
                    await asyncio.shield(role_sync)
                _, current_resource, _, checked = await self._admit(raw, received_reply_subject)
                if current_resource is not resource:
                    raise ContractError('legacy_work_service_unavailable')
                from .work_legacy import check_core_disclosure, check_disclosure
                claims = request['claims']
                core_outcome = (claims['contractId'] == 'federation-work-outcome'
                    and claims['payload']['input']['contractId'] in (
                        'federation-work-ingest-legacy', 'federation-work-result-legacy'))
                if checked.core is not None or core_outcome:
                    final_core = asyncio.create_task(check_core_disclosure(resource, original, checked))
                    self._workers.add(final_core)
                    final_core.add_done_callback(finished)
                    await asyncio.shield(final_core)
                check_disclosure(resource, original, checked)
                response = self._sign(request, resource, result, checked,
                    original_valid_until=original.valid_until, started=started)
                _parse(response, 'federation-work-reply')
                return response
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('legacy_work_service_unavailable') from None
        finally:
            self._active.discard(task)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('legacy_work_cleanup_invalid')
        self._closed = True
        if self._closing is None:
            async def finish():
                active = tuple(self._active)
                for task in active:
                    task.cancel()
                pending = {*active, *self._workers}
                if pending:
                    await asyncio.wait(pending)
            self._closing = asyncio.create_task(finish())
        try:
            _, remaining = await asyncio.wait({self._closing}, timeout=timeout)
            if remaining:
                raise ContractError('legacy_work_cleanup_incomplete')
        except asyncio.CancelledError:
            while not self._closing.done():
                try:
                    await asyncio.wait({self._closing})
                except asyncio.CancelledError:
                    continue
            self._closing.result()
            raise
        self._closing.result()


def verify_work_bridge_reply(raw, request_raw, *, public_key, service_identity_ref,
                                service_instance_id, signing_key_ref, now, include_valid_until=False):
    """Only protected enrollment supplies reply keys and service identity."""
    try:
        reply = _parse(raw, 'federation-work-reply')['claims']
        packet = strict_loads(raw)
        request = _parse(request_raw, 'identity-ingress-request')
        wanted = request['claims']
        verify_possession(reply, packet['signature'], public_key)
        if (any(reply[k] != wanted[k] for k in ('profileId', 'hubId', 'authorityId', 'operationId', 'replySubject'))
                or reply['requestContractId'] != wanted['contractId']
                or reply['requestDigest'] != payload_digest(request) or reply['payloadDigest'] != payload_digest(wanted['payload'])
                or reply['resourceRef'] != wanted['payload']['resourceRef']
                or reply['serviceIdentityRef'] != service_identity_ref or reply['serviceInstanceId'] != service_instance_id
                or reply['signingKeyRef'] != signing_key_ref or reply['authorityRef']['id'] != wanted['authorityId']
                or reply['authorityRef']['ownerHubId'] != wanted['hubId'] or reply['authorityRef']['revision'] < 1
                or not _time(wanted['issuedAt']) <= _time(reply['issuedAt']) <= now < _time(reply['validUntil'])
                or _time(reply['validUntil']) > _time(wanted['expiresAt'])):
            raise ContractError('legacy_work_reply_refused')
        result = strict_loads(canonical_bytes(reply['result']))
        if include_valid_until:
            return {'result': result, 'validUntil': reply['validUntil']}
        return result
    except Exception:
        raise ContractError('legacy_work_reply_unconfirmed') from None
