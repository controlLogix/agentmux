"""Current signed native delivery evidence for one immutable execution original.

This module does not sign, renew, reconstruct or weaken an operation. The existing
native wrapper evaluator authenticates every current delivery. Its short delivery
window is separate from the first finite business bound retained by the owner.
"""
import base64
from dataclasses import dataclass
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate, verify_envelope
from .authority import LedgerAuthorityReader, _indexes, _active, _key, approval_reason
from .capability_service import evaluate_capability_service_request
from .ingress import EnrolledIngress, verify_possession
from .downstream import check_domain_binding
from .native_records import validate_native_lineage


def fail():raise ContractError('execution_native_evidence_refused') from None


def business(envelope):
    return {name:envelope[name] for name in
        ('contractId','operation','payload','destinationHubId','destinationServiceId')}


def stamp(value):return value.isoformat(timespec='microseconds').replace('+00:00','Z')


@dataclass(frozen=True,slots=True,repr=False)
class NativeExecutionEvidence:
    request: bytes
    caller_ingress: object
    plugin_identity: bytes
    instance_id: str
    package_id: str
    terminal_owner: object = None

    def __post_init__(self):
        if (type(self.request) is not bytes or not 0<len(self.request)<=98304
                or type(self.caller_ingress) is not EnrolledIngress
                or type(self.plugin_identity) is not bytes):fail()
        validate('execution-plan-read',{'planRef':strict_loads(self.plugin_identity)})
        if not self.instance_id or not self.package_id:fail()

    def __repr__(self):return '<NativeExecutionEvidence private; current checks required>'

    def _check(self,snapshot,original,*,now,retained):
        packet=strict_loads(self.request);validate('capability-service-request',packet)
        if canonical_bytes(packet)!=self.request:fail()
        claims=packet['claims'];inner=base64.b64decode(claims['envelopeBytes'],validate=True)
        fresh=strict_loads(inner);first=strict_loads(original)
        if (canonical_bytes(first)!=original or first['contractId']!='capability-process-start'
                or business(first)!=business(fresh)
                or retained is None and inner!=original):fail()
        checked=evaluate_capability_service_request(snapshot,self.request,service_id='process-owner',now=now)
        if checked.operation!=canonical_bytes(first['operation']):fail()
        return self._bound(snapshot,first,claims,now=now,retained=retained)

    def _bound(self,snapshot,first,claims,*,now,retained):
        record=strict_loads(snapshot.record);state=record['state']
        rows=[row for row in state.get('nativeInstances',[]) if row['owner']==claims['owner']]
        if len(rows)!=1:fail()
        row=rows[0];index=_indexes(state,record['ownerHubId'])
        def current(collection,reference):
            value=index[collection].get(_key(reference))
            if value is None or not _active(value,now):fail()
            return value
        host=current('identities',row['hostIdentityRef']);plugin=current('identities',row['identityRef'])
        issuer=current('issuers',claims['signingKeyRef']);transport=current('transports',claims['hostTransportRef'])
        verify_possession(claims,strict_loads(self.request)['signature'],issuer['publicKey'])
        scope=first['operation']['scope']
        host_grants=[g for g in index['grants'].values() if _active(g,now)
            and g['callerRef']==host['ref'] and g['actorRef']==host['ref'] and g['scope']==scope
            and g['resourceId']==row['owner']['instanceId'] and g['contractId']=='native-authority-prepare-domain-call'
            and g['delegationRef'] is None]
        if (row['status']!='active' or host['kind']!='service' or plugin['kind']!='plugin'
                or transport['identityRef']!=host['ref'] or transport['issuerRef']!=issuer['ref']
                or transport['method']!='nats-credential-mapping'
                or not any(g['decision']=='allowed' for g in host_grants)
                or any(g['decision']=='denied' for g in host_grants)
                or not any(_active(m,now) and m['identityRef']==host['ref'] and m['scope']==scope
                    for m in state['memberships'])
                or claims['nativeFactsDigest']!=payload_digest(row['facts'])):fail()
        check_domain_binding(row,binding_id=None,contract='capability-process-start',
            resource=first['payload']['resourceRef']['id'],scope=scope,now=now)
        if (canonical_bytes(row['identityRef'])!=self.plugin_identity
                or row['owner']['instanceId']!=self.instance_id
                or row['owner']['pin']['packageId']!=self.package_id):fail()
        limits=[datetime.fromisoformat(first['operation']['deadline']),
            validate_native_lineage(state,_indexes(state,record['ownerHubId']),row,now)]
        for timed in (row['facts']['grant'],row['facts']['policy']):
            if not datetime.fromisoformat(timed['issuedAt'])<=now<datetime.fromisoformat(timed['expiresAt']):fail()
            limits.append(datetime.fromisoformat(timed['expiresAt']))
        # Match the normal evaluator's conservative upcoming authority changes,
        # excluding only delivery timestamps which it has just authenticated.
        for collection in ('issuers','transports','grants','approvals'):
            for item in state[collection]:
                if item['status']=='active':
                    for field in ('issuedAt','expiresAt'):
                        boundary=datetime.fromisoformat(item[field])
                        if boundary>now:limits.append(boundary)
        end=min(limits)
        pin={'format':'agentmux-execution-native-binding-v1','profileId':state['profileId'],
            'authorityId':record['entityId'],'hubId':record['ownerHubId'],
            'firstEnvelopeDigest':payload_digest(first),'businessDigest':payload_digest(business(first)),
            'owner':row['owner'],'nativeInstanceRef':row['ref'],'pluginIdentityRef':row['identityRef'],'hostIdentityRef':row['hostIdentityRef'],
            'hostTransportRef':claims['hostTransportRef'],'signingKeyRef':claims['signingKeyRef'],
            'nativeFactsDigest':claims['nativeFactsDigest'],'businessEnd':stamp(end)}
        if retained is not None:
            old=strict_loads(retained);validate('execution-native-binding',old)
            if any(pin[key]!=old[key] for key in pin if key!='businessEnd'):fail()
            end=min(end,datetime.fromisoformat(old['businessEnd']));pin=old
        if now>=end:fail()
        return end,pin

    async def _terminal(self,reader,original):
        operation=strict_loads(original)['operation']
        if operation['caller']['kind']!='human':return None
        ingress=self.caller_ingress
        await ingress.authorize_terminal(operation)
        if ingress._session_authorizer is None:return None
        from .service import IdentityService
        owner=self.terminal_owner
        if (type(owner) is not IdentityService or owner.reader is not reader or owner.ingress is not ingress
                or ingress._session_authorizer!=owner.authorize_oidc_terminal):fail()
        return await owner.execution_terminal_deadline(operation)

    async def authorize(self,reader,original,*,retained=None):
        """A public delivery must be live now, including final disclosure."""
        if type(reader) is not LedgerAuthorityReader or self.caller_ingress._reader is not reader:fail()
        snapshot=await reader.current();now=datetime.now(timezone.utc)
        end,pin=self._check(snapshot,original,now=now,retained=retained)
        terminal=await self._terminal(reader,original)
        if terminal is not None:end=min(end,terminal)
        snapshot=await reader.current();now=datetime.now(timezone.utc)
        current,current_pin=self._check(snapshot,original,now=now,retained=retained)
        end=min(end,current)
        if now>=end:fail()
        if retained is None:current_pin['businessEnd']=stamp(end)
        return snapshot,end,canonical_bytes(current_pin)

    async def admit(self,reader,original,*,retained=None):
        snapshot,end,pin=await self.authorize(reader,original,retained=retained)
        return _AdmittedNativeExecution(self,reader,original,pin,end,snapshot.sequence,_ADMITTED)


_ADMITTED=object()


def _current_business(snapshot,original,*,now):
    """Current Process.Start policy for an already authenticated exact original.

    Historical signature validation uses its signed issue instant only to verify
    unchanged content. Every identity, permission and expiry below uses NOW.
    This closed path is reachable only through the private admitted object.
    """
    envelope=strict_loads(original);op=envelope['operation'];claims=envelope['ingressAttestation']['claims']
    record=strict_loads(snapshot.record);state=record['state'];index=_indexes(state,record['ownerHubId'])
    def current(collection,reference):
        value=index[collection].get(_key(reference))
        if value is None or not _active(value,now):fail()
        return value
    issuer=current('issuers',claims['signingKeyRef']);principal=current('identities',issuer['identityRef'])
    if (principal['kind']!='service' or issuer['instanceId']!=claims['sourceInstanceId']
            or claims['sourceHubId']!=record['ownerHubId']):fail()
    verify_envelope(envelope,base64.urlsafe_b64decode(issuer['publicKey']+'='),
        {'hubId':record['ownerHubId'],'serviceId':'process-owner'},datetime.fromisoformat(claims['issuedAt']))
    transport=current('transports',claims['authenticatedTransportRef'])
    caller=current('identities',op['caller']['authenticatedIdentityRef']);actor=current('identities',op['effectiveActorRef'])
    scope=op['scope'];resource=envelope['payload']['resourceRef']
    if (envelope['contractId']!='capability-process-start' or now>=datetime.fromisoformat(op['deadline'])
            or caller['kind']=='plugin' or caller['principalId']!=op['caller']['principalId']
            or caller['kind']!=op['caller']['kind'] or caller['ref']!=actor['ref'] or op['delegationRef'] is not None
            or transport['issuerRef']!=issuer['ref'] or transport['identityRef']!=caller['ref']
            or transport['method']!=claims['authenticationMethod'] or resource['ownerHubId']!=record['ownerHubId']
            or not any(_active(m,now) and m['identityRef']==actor['ref'] and m['scope']==scope for m in state['memberships'])):fail()
    matches=[g for g in index['grants'].values() if _active(g,now) and g['callerRef']==caller['ref']
        and g['actorRef']==actor['ref'] and g['scope']==scope and g['contractId']=='capability-process-start'
        and g['resourceId']==resource['id']]
    grant=current('grants',op['grantRef'])
    if (grant not in matches or grant['delegationRef'] is not None or any(g['decision']=='denied' for g in matches)
            or approval_reason(index,grant,op,audience={'hubId':record['ownerHubId'],'serviceId':'process-owner'},
                scope=scope,contract='capability-process-start',now=now) is not None):fail()


class _AdmittedNativeExecution:
    """Private ownership of one admitted call; never accepted as new ingress."""
    __slots__=('_evidence','_reader','_original','_pin','_ceiling','_sequence','_brand')
    def __init__(self,evidence,reader,original,pin,ceiling,sequence,brand):
        if brand is not _ADMITTED:fail()
        self._evidence,self._reader,self._original,self._pin=evidence,reader,original,pin
        self._ceiling,self._sequence,self._brand=ceiling,sequence,brand

    def __repr__(self):return '<AdmittedNativeExecution private>'
    def __reduce__(self):raise TypeError('admitted execution is not serializable')

    async def authorize(self,reader,original,*,retained=None):
        if self._brand is not _ADMITTED or reader is not self._reader or original!=self._original:fail()
        first=strict_loads(original);claims=strict_loads(self._evidence.request)['claims']
        selected=retained if retained is not None else self._pin
        async def current():
            snapshot=await reader.current();now=datetime.now(timezone.utc)
            if snapshot.sequence<self._sequence or now>=self._ceiling:fail()
            _current_business(snapshot,original,now=now)
            end,pin=self._evidence._bound(snapshot,first,claims,now=now,retained=selected)
            return snapshot,min(end,self._ceiling),pin
        _,end,_=await current()
        terminal=await self._evidence._terminal(reader,original)
        if terminal is not None:end=min(end,terminal)
        snapshot,latest,pin=await current();end=min(end,latest)
        if datetime.now(timezone.utc)>=end:fail()
        return snapshot,end,canonical_bytes(pin)
