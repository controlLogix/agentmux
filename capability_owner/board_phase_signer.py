"""Host-owned fresh signed board phase operations over enrolled authority.

Signing material is supplied by protected enrollment. It never enters a plugin
context or a board command payload, and this adapter cannot grant permissions.
"""
from datetime import datetime, timedelta, timezone
import secrets

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate
from identity.ingress import EnrolledIngress
from .board_journal import BoardOperationJournal, PHASE_CONTRACTS, _valid_ref


class BoardPhaseSigner:
    def __init__(self, journal, ingress, *, transport_ref, grants, signing_seed):
        from .board_allocation_journal import BoardAllocationJournal
        if (type(journal) not in (BoardOperationJournal,BoardAllocationJournal) or not isinstance(ingress,EnrolledIngress)
                or ingress._reader is not journal._authority or not _valid_ref(transport_ref)
                or type(grants) is not dict or set(grants) != PHASE_CONTRACTS
                or any(not _valid_ref(value) for value in grants.values())
                or any(value['ownerHubId'] != journal._binding.hub_id for value in
                       (transport_ref,*grants.values()))
                or type(signing_seed) is not bytes or len(signing_seed) != 32):
            raise ContractError('board_phase_signer_configuration')
        self._journal,self._ingress = journal,ingress
        self._transport = canonical_bytes(transport_ref)
        self._grants = canonical_bytes(grants)
        self._seed = signing_seed

    def __repr__(self):
        return '<BoardPhaseSigner private>'

    async def admit(self, contract, *, expected_sequence, payload, cancellation_ref):
        if contract not in PHASE_CONTRACTS:
            raise ContractError('board_phase_contract_refused')
        validate(contract,payload)
        if (type(expected_sequence) is not int or expected_sequence < 0
                or payload['journalRef']['revision'] != expected_sequence
                or payload['journalRef']['id'] != self._journal._binding.entity_id):
            raise ContractError('board_phase_binding_refused')
        reader = self._journal._authority
        now = datetime.now(timezone.utc)
        stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00','Z')
        claims = {'purpose':'agentmux-client-possession-v1','hubId':reader._hub,
            'profileId':reader._profile,'authorityId':reader._entity,
            'transportRef':strict_loads(self._transport),'grantRef':strict_loads(self._grants)[contract],
            'operationId':'board-owner-'+secrets.token_hex(24),'expectedVersion':expected_sequence,
            'contractId':contract,'payload':strict_loads(canonical_bytes(payload)),'approvalRefs':[],
            'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=5))}
        request = canonical_bytes({'schemaVersion':'1.0.0','claims':claims,
                                   'signature':sign_claims(claims,self._seed)})
        try:
            admitted = await self._ingress.admit(request,cancellation_ref=cancellation_ref)
        except ContractError:
            raise ContractError('board_phase_access_refused') from None
        if admitted.decision.outcome != 'allowed' or admitted.envelope is None:
            raise ContractError('board_phase_access_refused')
        operation = strict_loads(admitted.envelope)['operation']
        if (operation['caller']['kind'] != 'service'
                or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != self._journal._owner
                or canonical_bytes(operation['effectiveActorRef']) != self._journal._owner):
            raise ContractError('board_phase_access_refused')
        return admitted
