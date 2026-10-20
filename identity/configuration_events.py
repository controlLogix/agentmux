"""Create producer-authorized configuration events for atomic owner retention."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate
from .authority import LedgerAuthorityReader, _indexes, _key
from .ingress import EnrolledIngress


@dataclass(frozen=True, repr=False)
class PreparedConfigurationEvent:
    envelope: bytes
    valid_until: datetime

    def __repr__(self):
        return '<PreparedConfigurationEvent private>'


class ConfigurationEventProducer:
    """A selected producer transport and issuer; this object never publishes."""
    def __init__(self, authority, *, hub_id, profile_id, authority_id, configuration_id, scope,
                 identity_ref, transport_ref, grant_ref, transport_seed, issuer_ref, signing_seed):
        if (not isinstance(authority, LedgerAuthorityReader)
                or (authority._hub,authority._profile,authority._entity,authority._organization) !=
                   (hub_id,profile_id,authority_id,scope['organizationId'])
                or type(transport_seed) is not bytes or len(transport_seed)!=32
                or type(signing_seed) is not bytes or len(signing_seed)!=32
                or any(r['ownerHubId']!=hub_id for r in (identity_ref,transport_ref,grant_ref,issuer_ref))):
            raise ContractError('configuration_event_producer_invalid')
        self._authority=authority
        self._hub,self._profile,self._authority_id,self._configuration=hub_id,profile_id,authority_id,configuration_id
        self._scope=canonical_bytes(scope)
        self._identity,self._transport,self._grant=map(canonical_bytes,(identity_ref,transport_ref,grant_ref))
        self._issuer=canonical_bytes(issuer_ref)
        self._seed=transport_seed
        self._ingress=EnrolledIngress(authority,issuer_ref=issuer_ref,signing_seed=signing_seed)

    def __repr__(self):
        return '<ConfigurationEventProducer private>'

    async def prepare_change_event(self,payload,*,operation):
        validate('configuration-change',payload)
        validate('operation-context',operation)
        reference=payload['configurationRef']
        if (reference['id']!=self._configuration or reference['ownerHubId']!=self._hub
                or canonical_bytes(operation['scope'])!=self._scope
                or operation['cancellationRef']['ownerHubId']!=self._hub):
            raise ContractError('configuration_event_binding')
        now=datetime.now(timezone.utc)
        end=min(datetime.fromisoformat(operation['deadline']),now+timedelta(seconds=60))
        if not now<end:
            raise ContractError('configuration_event_expired')
        snapshot=await self._authority.current()
        authority=strict_loads(snapshot.record)
        index=_indexes(authority['state'],self._hub)
        issuer=index['issuers'].get(_key(strict_loads(self._issuer)))
        transport=index['transports'].get(_key(strict_loads(self._transport)))
        if (issuer is None or transport is None
                or canonical_bytes(issuer['identityRef'])!=self._identity
                or canonical_bytes(transport['identityRef'])!=self._identity):
            raise ContractError('configuration_event_binding')
        event_id='configuration_event_'+hashlib.sha256(canonical_bytes({
            'operationId':operation['operationId'],'payload':payload})).hexdigest()
        stamp=lambda value:value.isoformat(timespec='microseconds').replace('+00:00','Z')
        claims={'purpose':'agentmux-client-possession-v1','hubId':self._hub,'profileId':self._profile,
            'authorityId':self._authority_id,'transportRef':strict_loads(self._transport),
            'grantRef':strict_loads(self._grant),'operationId':event_id,'expectedVersion':reference['revision'],
            'contractId':'configuration-change','payload':payload,'approvalRefs':[],
            'issuedAt':stamp(now),'expiresAt':stamp(end)}
        request=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,self._seed)})
        admitted=await self._ingress.admit(request,cancellation_ref=operation['cancellationRef'])
        if admitted.envelope is None or admitted.decision.valid_until is None:
            raise ContractError('configuration_event_not_authorized')
        envelope=strict_loads(admitted.envelope)
        if (envelope['operation']['caller']['kind']!='service'
                or canonical_bytes(envelope['operation']['caller']['authenticatedIdentityRef'])!=self._identity
                or envelope['kind']!='event' or not datetime.now(timezone.utc)<admitted.decision.valid_until):
            raise ContractError('configuration_event_binding')
        return PreparedConfigurationEvent(admitted.envelope,admitted.decision.valid_until)
