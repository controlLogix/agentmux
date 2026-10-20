"""Turn a Hub-authenticated legacy board request into an enrolled operation."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
import base64
import time

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate, verify_envelope
from .authority import LedgerAuthorityReader, _indexes, _key
from .ingress import EnrolledIngress

_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_FIELDS = {'add': ('title','body','labels','assign','from'), 'move': ('key','status'),
           'assign': ('key','to'), 'comment': ('key','text'), 'claim': ('key',)}


def _ref(value, hub):
    value = strict_loads(value) if type(value) is bytes else value
    if (type(value) is not dict or set(value) != {'id','ownerHubId','revision'}
            or any(type(value[k]) is not str or not _ID.fullmatch(value[k]) for k in ('id','ownerHubId'))
            or value['ownerHubId'] != hub or type(value['revision']) is not int
            or not 0 <= value['revision'] <= 9_007_199_254_740_991):
        raise ContractError('legacy_board_enrollment_invalid')
    return canonical_bytes(value)


@dataclass(frozen=True, repr=False)
class LegacyBoardRoute:
    repository: str
    card_key: str | None
    resource_ref: bytes
    grant_ref: bytes
    scope: bytes
    recovery_grant_ref: bytes | None = None

    def __post_init__(self):
        if (type(self.repository) is not str or not self.repository
                or self.card_key is not None and (type(self.card_key) is not str or not self.card_key)):
            raise ContractError('legacy_board_enrollment_invalid')
        for name in ('resource_ref','grant_ref','scope'):
            value=getattr(self,name)
            object.__setattr__(self,name,canonical_bytes(strict_loads(value) if type(value) is bytes else value))
        if self.recovery_grant_ref is not None:
            object.__setattr__(self,'recovery_grant_ref',_ref(self.recovery_grant_ref,strict_loads(self.resource_ref)['ownerHubId']))

    def __repr__(self):
        return '<LegacyBoardRoute private>'


@dataclass(frozen=True, repr=False)
class LegacyBoardCallerEnrollment:
    authenticated_caller: str
    profile_id: str
    hub_id: str
    authority_id: str
    identity_ref: bytes
    transport_ref: bytes
    signing_seed: bytes
    routes: tuple

    def __post_init__(self):
        if (type(self.authenticated_caller) is not str or not self.authenticated_caller
                or self.authenticated_caller == 'unregistered'
                or any(type(v) is not str or not _ID.fullmatch(v)
                       for v in (self.profile_id,self.hub_id,self.authority_id))
                or type(self.signing_seed) is not bytes or len(self.signing_seed) != 32
                or type(self.routes) is not tuple or not 1 <= len(self.routes) <= 64
                or any(type(r) is not LegacyBoardRoute for r in self.routes)):
            raise ContractError('legacy_board_enrollment_invalid')
        for name in ('identity_ref','transport_ref'):
            object.__setattr__(self,name,_ref(getattr(self,name),self.hub_id))
        route_keys=set()
        for route in self.routes:
            key=(route.repository,route.card_key)
            if key in route_keys:
                raise ContractError('legacy_board_enrollment_invalid')
            route_keys.add(key)
            _ref(route.resource_ref,self.hub_id);_ref(route.grant_ref,self.hub_id)

    def __repr__(self):
        return '<LegacyBoardCallerEnrollment private>'


class LegacyBoardIngress:
    def __init__(self, hub, ingress, enrollment):
        from hub.server import Hub
        if (not isinstance(hub,Hub) or not isinstance(ingress,EnrolledIngress)
                or type(enrollment) is not LegacyBoardCallerEnrollment
                or not isinstance(ingress._reader,LedgerAuthorityReader)
                or (ingress._reader._hub,ingress._reader._profile,ingress._reader._entity) !=
                   (enrollment.hub_id,enrollment.profile_id,enrollment.authority_id)):
            raise ContractError('legacy_board_enrollment_invalid')
        self._hub,self._ingress,self._enrollment=hub,ingress,enrollment

    def __repr__(self):
        return '<LegacyBoardIngress private>'

    def _local(self, proof):
        authenticated=self._hub._consume_authenticated_caller(proof)
        selected=self._enrollment
        if authenticated.authenticated_caller != selected.authenticated_caller:
            raise ContractError('legacy_board_caller_binding')
        request=strict_loads(authenticated.request)
        verb=request.get('verb')
        if type(verb) is not str or verb not in {'fed_board_'+name for name in _FIELDS}:
            raise ContractError('legacy_board_command_unavailable')
        command=verb.removeprefix('fed_board_')
        args=request.get('args',{})
        if type(args) is not dict or set(args)-set(_FIELDS[command])-{'repo'}:
            raise ContractError('legacy_board_command_binding')
        routes=[r for r in selected.routes if r.card_key == (None if command=='add' else args.get('key'))
                and (args.get('repo') is None or args['repo']==r.repository)]
        if len(routes)!=1:
            raise ContractError('legacy_board_route_unavailable')
        route=routes[0]
        return authenticated, route, command, args

    async def admit_local(self, proof, *, operation_id, cancellation_ref, expected_version=None):
        authenticated,route,command,args=self._local(proof)
        selected=self._enrollment
        resource=strict_loads(route.resource_ref)
        if expected_version is None:
            expected_version=resource['revision']
        if type(expected_version) is not int or not 0 <= expected_version <= 9_007_199_254_740_991:
            raise ContractError('legacy_board_caller_binding')
        resource['revision']=expected_version
        payload={'resourceRef':resource,'attribution':authenticated.caller,
                 'input':{'command':command,**{k:args[k] for k in _FIELDS[command] if k in args}}}
        validate('federation-board-command',payload)
        snapshot=await self._ingress._reader.current()
        index=_indexes(strict_loads(snapshot.record)['state'],selected.hub_id)
        transport=index['transports'].get(_key(strict_loads(selected.transport_ref)))
        grant=index['grants'].get(_key(strict_loads(route.grant_ref)))
        if (transport is None or canonical_bytes(transport['identityRef'])!=selected.identity_ref
                or grant is None or grant['contractId']!='federation-board-command'
                or grant['resourceId']!=resource['id'] or canonical_bytes(grant['scope'])!=route.scope
                or canonical_bytes(grant['callerRef'])!=selected.identity_ref
                or canonical_bytes(grant['actorRef'])!=selected.identity_ref):
            raise ContractError('legacy_board_enrollment_binding')
        remaining=authenticated.expires_monotonic-time.monotonic()
        if remaining<=0:
            raise ContractError('legacy_board_proof_expired')
        now=datetime.now(timezone.utc)
        stamp=lambda value:value.isoformat(timespec='microseconds').replace('+00:00','Z')
        claims={'purpose':'agentmux-client-possession-v1','profileId':selected.profile_id,
            'hubId':selected.hub_id,'authorityId':selected.authority_id,
            'transportRef':strict_loads(selected.transport_ref),'grantRef':strict_loads(route.grant_ref),
            'operationId':operation_id,'expectedVersion':expected_version,'contractId':'federation-board-command',
            'payload':payload,'approvalRefs':[],'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=min(5,remaining)))}
        raw=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,selected.signing_seed)})
        admitted=await self._ingress.admit(raw,cancellation_ref=cancellation_ref)
        if time.monotonic()>=authenticated.expires_monotonic:
            raise ContractError('legacy_board_proof_expired')
        return admitted

    async def admit_recovery(self, proof, original_bytes, *, operation_id, cancellation_ref):
        """A fresh proof for the same request may query its retained operation."""
        authenticated,route,command,args=self._local(proof)
        selected=self._enrollment
        if type(original_bytes) is not bytes or len(original_bytes)>65536 or route.recovery_grant_ref is None:
            raise ContractError('legacy_board_recovery_unavailable')
        original=strict_loads(original_bytes)
        validate('message-envelope',original)
        expected_input={'command':command,**{k:args[k] for k in _FIELDS[command] if k in args}}
        if (canonical_bytes(original)!=original_bytes or original['contractId']!='federation-board-command'
                or original['payload']['input']!=expected_input or original['payload']['attribution']!=authenticated.caller
                or original['operation']['caller']['authenticatedIdentityRef']!=strict_loads(selected.identity_ref)
                or original['operation']['effectiveActorRef']!=strict_loads(selected.identity_ref)
                or original['ingressAttestation']['claims']['authenticatedTransportRef']!=strict_loads(selected.transport_ref)
                or canonical_bytes(original['operation']['scope'])!=route.scope
                or any(original['payload']['resourceRef'][k]!=strict_loads(route.resource_ref)[k] for k in ('id','ownerHubId'))):
            raise ContractError('legacy_board_recovery_binding')
        snapshot=await self._ingress._reader.current()
        index=_indexes(strict_loads(snapshot.record)['state'],selected.hub_id)
        signer=index['issuers'].get(_key(original['ingressAttestation']['claims']['signingKeyRef']))
        transport=index['transports'].get(_key(strict_loads(selected.transport_ref)))
        grant=index['grants'].get(_key(strict_loads(route.recovery_grant_ref)))
        if (signer is None or transport is None or canonical_bytes(transport['identityRef'])!=selected.identity_ref
                or grant is None or grant['contractId']!='capability-outcome-query'
                or grant['resourceId']!=strict_loads(route.resource_ref)['id'] or canonical_bytes(grant['scope'])!=route.scope
                or canonical_bytes(grant['callerRef'])!=selected.identity_ref or canonical_bytes(grant['actorRef'])!=selected.identity_ref):
            raise ContractError('legacy_board_enrollment_binding')
        # Verify historical intent at its signed issue time; current query and
        # original permissions are checked afresh by EnrolledIngress below.
        verify_envelope(original,base64.urlsafe_b64decode(signer['publicKey']+'='),
            {'hubId':selected.hub_id,'serviceId':'storage-owner'},
            datetime.fromisoformat(original['ingressAttestation']['claims']['issuedAt']))
        now=datetime.now(timezone.utc)
        remaining=authenticated.expires_monotonic-time.monotonic()
        if remaining<=0:raise ContractError('legacy_board_proof_expired')
        stamp=lambda value:value.isoformat(timespec='microseconds').replace('+00:00','Z')
        payload={'resourceRef':strict_loads(route.resource_ref),'input':{'contractId':'federation-board-command',
            **{k:original['operation'][k] for k in ('operationId','payloadDigest')}}}
        claims={'purpose':'agentmux-client-possession-v1','profileId':selected.profile_id,'hubId':selected.hub_id,
            'authorityId':selected.authority_id,'transportRef':strict_loads(selected.transport_ref),
            'grantRef':strict_loads(route.recovery_grant_ref),'operationId':operation_id,
            'expectedVersion':payload['resourceRef']['revision'],'contractId':'capability-outcome-query',
            'payload':payload,'approvalRefs':[],'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=min(5,remaining)))}
        raw=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,selected.signing_seed)})
        admitted=await self._ingress.admit(raw,cancellation_ref=cancellation_ref)
        if time.monotonic()>=authenticated.expires_monotonic:
            raise ContractError('legacy_board_proof_expired')
        return admitted
