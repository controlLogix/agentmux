"""Bind an enrolled client to a short-lived, signed application observation.

The host must produce the observation from verified runtime, profile, policy and
workspace state and end its lease when that lifetime ends. Clients must call this
on their already approved connection and verify the signed reply. Broker
readiness alone is not application readiness. This module creates no connection.
"""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from .authority import LedgerAuthorityReader, _active, _indexes, _key
from .ingress import verify_possession


class ApplicationObservationLease:
    """Host-owned refreshable observations for one fixed runtime generation."""
    _PIN = ('hubId', 'profileId', 'instanceId', 'generation', 'lifetimeId', 'releaseDigest',
            'policyRef', 'workspaceRef', 'scope')

    def __init__(self, observation, done):
        if not isinstance(done, asyncio.Event):
            raise ContractError('application_lease_invalid')
        self.done = done
        self._observation = None
        self.refresh(observation)

    @property
    def observation(self):
        return self._observation

    @property
    def generation(self):
        return strict_loads(self._observation)['claims']['generation']

    @property
    def lifetime_id(self):
        return strict_loads(self._observation)['claims']['lifetimeId']

    def validate_refresh(self, observation):
        if self.done.is_set():
            raise ContractError('application_lifetime_ended')
        claims = _read(observation, 'application-runtime-observation')['claims']
        if self._observation is not None:
            old = strict_loads(self._observation)['claims']
            if (any(claims[k] != old[k] for k in self._PIN)
                    or _time(claims['issuedAt']) < _time(old['issuedAt'])
                    or (claims['issuedAt'] == old['issuedAt'] and observation != self._observation)):
                raise ContractError('application_refresh_mismatch')
    def refresh(self, observation):
        self.validate_refresh(observation)
        # This is host input, not authority. Every use still verifies the signed
        # observation against the current enrolled issuer and its purpose grant.
        self._observation = observation

    def __repr__(self):
        return '<ApplicationObservationLease private>'


def _time(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() != timedelta(0):
            raise ValueError()
        return parsed
    except (TypeError, ValueError):
        raise ContractError('application_time_invalid') from None


def _interval(claims, now):
    start, end = _time(claims['issuedAt']), _time(claims['expiresAt'])
    if not start <= now < end or end - start > timedelta(seconds=5):
        raise ContractError('application_observation_expired')
    return end


def _read(raw, schema):
    if type(raw) is not bytes or len(raw) > 65536:
        raise ContractError('owner_body_limit')
    value = strict_loads(raw)
    validate(schema, value)
    return value


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _permission(index, identity_ref, scope, contract, instance, now):
    grants = [g for g in index['grants'].values() if _active(g, now)
              and g['callerRef'] == identity_ref and g['actorRef'] == identity_ref
              and g['scope'] == scope and g['contractId'] == contract
              and g['resourceId'] == instance and g['delegationRef'] is None]
    if (not any(m['identityRef'] == identity_ref and m['scope'] == scope and _active(m, now)
                for m in index['memberships'].values())
            or any(g['decision'] == 'denied' for g in grants)
            or not any(g['decision'] == 'allowed' for g in grants)):
        raise ContractError('application_permission_unavailable')


class ApplicationBindingProvider:
    """Resolve current authority; accept no runtime observations from clients."""
    def __init__(self, reader, *, observation_lease, issuer_ref, signing_seed):
        if (not isinstance(reader, LedgerAuthorityReader)
                or not isinstance(observation_lease, ApplicationObservationLease)
                or type(signing_seed) is not bytes or len(signing_seed) != 32):
            raise ContractError('application_provider_configuration')
        self._reader, self._lease = reader, observation_lease
        self._issuer, self._seed = canonical_bytes(issuer_ref), signing_seed

    def __repr__(self):
        return '<ApplicationBindingProvider private>'

    async def open_local_browser_binding(self, caller_ref, scope):
        """Mint the private server binding after signed command admission."""
        if (type(caller_ref) is not dict or type(scope) is not dict
                or scope.get('projectId') is None):
            raise ContractError('application_permission_unavailable')
        binding = _LocalBrowserApplicationBinding(self, caller_ref, scope)
        await binding.current()
        return binding

    async def _current_local_browser_binding(self, caller_ref, scope):
        self._live()
        observation = _read(self._lease.observation, 'application-runtime-observation')
        snapshot = await self._reader.current()
        self._live()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        state, observed = record['state'], observation['claims']
        index = _indexes(state, record['ownerHubId'])
        end = _interval(observed, now)
        if (observed['hubId'] != record['ownerHubId']
                or observed['profileId'] != state['profileId']
                or observed['scope'] != scope):
            raise ContractError('application_binding_mismatch')
        observer = index['issuers'].get(_key(observed['signingKeyRef']))
        if observer is None or not _active(observer, now):
            raise ContractError('application_credential_unavailable')
        identity = index['identities'].get(_key(observer['identityRef']))
        caller = index['identities'].get(_key(caller_ref))
        if (identity is None or identity['kind'] != 'service' or not _active(identity, now)
                or caller is None or caller['kind'] != 'human' or not _active(caller, now)):
            raise ContractError('application_credential_unavailable')
        verify_possession(observed, observation['signature'], observer['publicKey'])
        _permission(index, caller_ref, scope, 'application-bind', observed['instanceId'], now)
        _permission(index, observer['identityRef'], scope, 'application-attest', observed['instanceId'], now)
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in state[collection]:
                if item['status'] != 'active':
                    continue
                start, expiry = _time(item['issuedAt']), _time(item['expiresAt'])
                if start > now:
                    end = min(end, start)
                elif expiry > now:
                    end = min(end, expiry)
        self._live()
        if datetime.now(timezone.utc) >= end:
            raise ContractError('application_observation_expired')
        return {'callerRef': caller_ref, 'scope': scope,
            'instanceId': observed['instanceId'], 'generation': observed['generation'],
            'lifetimeId': observed['lifetimeId'],
            'authorityRef': {'id': record['entityId'], 'ownerHubId': record['ownerHubId'],
                             'revision': record['entityVersion']},
            'authoritySequence': snapshot.sequence, 'validUntil': _stamp(end)}

    def _live(self):
        if self._lease.done.is_set():
            raise ContractError('application_lifetime_ended')

    async def handle(self, raw, *, discovery=False):
        self._live()
        protocol = 'application-discovery' if discovery else 'application-binding'
        request = _read(raw, protocol + '-request')
        observation = _read(self._lease.observation, 'application-runtime-observation')
        snapshot = await self._reader.current()
        self._live()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        state = record['state']
        index = _indexes(state, record['ownerHubId'])
        claims, observed = request['claims'], observation['claims']
        end = min(_interval(claims, now), _interval(observed, now))
        if (claims['hubId'] != record['ownerHubId'] or claims['authorityId'] != record['entityId']
                or claims['profileId'] != state['profileId']
                or any(claims[k] != observed[k] for k in
                       ('hubId', 'profileId', 'instanceId', 'releaseDigest', 'policyRef', 'workspaceRef'))
                or (not discovery and any(claims[k] != observed[k] for k in ('generation', 'lifetimeId')))):
            raise ContractError('application_binding_mismatch')
        issuer = index['issuers'].get(_key(strict_loads(self._issuer)))
        observer = index['issuers'].get(_key(observed['signingKeyRef']))
        transport = index['transports'].get(_key(claims['transportRef']))
        if (any(item is None or not _active(item, now) for item in (issuer, observer, transport))
                or transport['issuerRef'] != issuer['ref']
                or transport['method'] != 'nats-credential-mapping'):
            raise ContractError('application_credential_unavailable')
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        if public != issuer['publicKey']:
            raise ContractError('application_credential_unavailable')
        for item in (issuer, observer):
            identity = index['identities'].get(_key(item['identityRef']))
            if identity is None or identity['kind'] != 'service' or not _active(identity, now):
                raise ContractError('application_credential_unavailable')
        verify_possession(observed, observation['signature'], observer['publicKey'])
        verify_possession(claims, request['signature'], transport['publicKey'])
        caller = index['identities'].get(_key(transport['identityRef']))
        grant = index['grants'].get(_key(claims['grantRef']))
        if (caller is None or not _active(caller, now) or caller['kind'] not in ('human', 'device', 'service')
                or grant is None or not _active(grant, now) or grant['decision'] != 'allowed'
                or grant['callerRef'] != caller['ref'] or grant['actorRef'] != caller['ref']
                or grant['contractId'] != 'application-bind' or grant['resourceId'] != claims['instanceId']
                or grant['delegationRef'] is not None or grant['scope'] != observed['scope']):
            raise ContractError('application_permission_unavailable')
        scope = grant['scope']
        _permission(index, caller['ref'], scope, 'application-bind', claims['instanceId'], now)
        _permission(index, observer['identityRef'], scope, 'application-attest', claims['instanceId'], now)
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in state[collection]:
                if item['status'] != 'active':
                    continue
                start, expiry = _time(item['issuedAt']), _time(item['expiresAt'])
                if start > now:
                    end = min(end, start)
                elif expiry > now:
                    end = min(end, expiry)
        signed = {'purpose': 'agentmux-' + protocol + '-response-v1',
            **{k: claims[k] for k in ('requestId', 'nonce', 'hubId', 'profileId', 'authorityId',
                'instanceId', 'releaseDigest', 'policyRef', 'workspaceRef', 'transportRef', 'grantRef')},
            'generation': observed['generation'], 'lifetimeId': observed['lifetimeId'],
            'requestDigest': payload_digest(claims), 'scope': scope, 'callerRef': caller['ref'],
            'signingKeyRef': issuer['ref'], 'authorityRef': {'id': record['entityId'],
                'ownerHubId': record['ownerHubId'], 'revision': record['entityVersion']},
            'authoritySequence': snapshot.sequence, 'issuedAt': _stamp(now), 'validUntil': _stamp(end)}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': signed,
            'signature': sign_claims(signed, self._seed)}
        validate(protocol + '-response', response)
        encoded = canonical_bytes(response)
        if len(encoded) > 65536:
            raise ContractError('owner_body_limit')
        self._live()
        if datetime.now(timezone.utc) >= end:
            raise ContractError('application_observation_expired')
        return encoded


class _LocalBrowserApplicationBinding:
    """Private refresh owner; browser and lifecycle data cannot construct it."""
    def __init__(self, provider, caller_ref, scope):
        self._provider = provider
        self._caller = canonical_bytes(caller_ref)
        self._scope = canonical_bytes(scope)
        self._pins = None

    async def current(self):
        value = await self._provider._current_local_browser_binding(
            strict_loads(self._caller), strict_loads(self._scope))
        pins = [value['callerRef'], value['scope'], value['instanceId'],
                value['generation'], value['lifetimeId']]
        if self._pins is None:
            self._pins = canonical_bytes(pins)
        elif canonical_bytes(pins) != self._pins:
            raise ContractError('application_binding_mismatch')
        return strict_loads(canonical_bytes(value))

    def __repr__(self):
        return '<LocalBrowserApplicationBinding private>'


def verify_response(raw, request_raw, *, public_key, signing_key_ref, now, discovery=False):
    """Verify with the trusted enrolled issuer key supplied by the application."""
    protocol = 'application-discovery' if discovery else 'application-binding'
    response = _read(raw, protocol + '-response')
    request = _read(request_raw, protocol + '-request')
    claims, wanted = response['claims'], request['claims']
    verify_possession(claims, response['signature'], public_key)
    request_end = _interval(wanted, now)
    if (claims['signingKeyRef'] != signing_key_ref or claims['requestDigest'] != payload_digest(wanted)
            or any(claims[k] != wanted[k] for k in ('requestId', 'nonce', 'hubId', 'profileId', 'authorityId',
                'instanceId', 'releaseDigest', 'policyRef', 'workspaceRef', 'transportRef', 'grantRef'))
            or (not discovery and any(claims[k] != wanted[k] for k in ('generation', 'lifetimeId')))
            or not _time(wanted['issuedAt']) <= _time(claims['issuedAt']) <= now < _time(claims['validUntil']) <= request_end
            or claims['authorityRef']['id'] != wanted['authorityId']
            or claims['authorityRef']['ownerHubId'] != wanted['hubId']):
        raise ContractError('application_response_binding')
    return strict_loads(canonical_bytes(claims))
