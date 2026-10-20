"""Current authority for owner-custodied application NATS account secrets.

Identity state retains public account metadata and opaque secret references only.
This module never reads secret bytes, opens a broker connection, or issues a NATS
credential.  The custody owner must re-run this check for every resolution,
rotation, and recovery operation before it resolves either returned reference.
"""
from dataclasses import dataclass
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate

from .authority import (AuthoritySnapshot, LedgerAuthorityReader, _active,
                        _indexes, _key, evaluate_snapshot)


@dataclass(frozen=True, slots=True, repr=False)
class ApplicationAccountResolution:
    account_ref: dict
    account_public_key: str
    profile_id: str
    scope: dict
    administrator_identity_ref: dict
    administrator_transport_ref: dict
    administrator_credential_ref: dict
    account_issuer_ref: dict
    authority_sequence: int
    valid_until: datetime

    def __repr__(self):
        return '<ApplicationAccountResolution private references>'


def resolve_snapshot(snapshot, request_bytes, *, audience, now):
    """Resolve public custody references from one currently authorized snapshot."""
    if not isinstance(snapshot, AuthoritySnapshot) or type(request_bytes) is not bytes:
        raise ContractError('application_account_resolution_invalid')
    request = strict_loads(request_bytes)
    validate('message-envelope', request)
    if request['contractId'] != 'identity-application-account-resolve':
        raise ContractError('application_account_resolution_invalid')
    payload = request['payload']
    validate('identity-application-account-resolve', payload)
    decision = evaluate_snapshot(snapshot, request_bytes, audience=audience, now=now)
    if decision.outcome != 'allowed' or decision.operation is None or decision.valid_until is None:
        raise ContractError('application_account_not_authorized')
    record = strict_loads(snapshot.record)
    index = _indexes(record['state'], record['ownerHubId'])

    def current(collection, reference):
        item = index[collection].get(_key(reference))
        if item is None or not _active(item, now):
            raise ContractError('application_account_unavailable')
        return item

    account = current('applicationAccounts', payload['accountRef'])
    if (account['ref'] != payload['accountRef']
            or account['profileId'] != payload['profileId']
            or account['scope'] != payload['scope']
            or account['accountPublicKey'] != payload['accountPublicKey']):
        raise ContractError('application_account_binding_mismatch')
    identity = current('identities', account['administratorIdentityRef'])
    transport = current('transports', account['administratorTransportRef'])
    transport_issuer = current('issuers', transport['issuerRef'])
    issuer_identity = current('identities', transport_issuer['identityRef'])
    credential = current('secretReferences', account['administratorCredentialRef'])
    account_issuer = current('secretReferences', account['accountIssuerRef'])
    if (identity['kind'] != 'service'
            or transport['identityRef'] != identity['ref']
            or transport['method'] != 'nats-credential-mapping'
            or issuer_identity['kind'] != 'service'
            or {credential['kind'], account_issuer['kind']} != {
                'nats-administrator-credential', 'nats-account-issuer'}
            or credential['kind'] != 'nats-administrator-credential'
            or account_issuer['kind'] != 'nats-account-issuer'
            or any(secret['ownerIdentityRef'] != identity['ref']
                   or secret['profileId'] != account['profileId']
                   or secret['scope'] != account['scope'] for secret in (credential, account_issuer))
            or not any(_active(member, now) and member['identityRef'] == identity['ref']
                       and member['scope'] == account['scope']
                       for member in index['memberships'].values())):
        raise ContractError('application_account_binding_mismatch')
    valid_until = min(decision.valid_until, *(datetime.fromisoformat(item['expiresAt'])
        for item in (account, credential, account_issuer, transport, transport_issuer)))
    if now >= valid_until:
        raise ContractError('application_account_not_authorized')
    return ApplicationAccountResolution(
        strict_loads(canonical_bytes(account['ref'])), account['accountPublicKey'],
        account['profileId'], strict_loads(canonical_bytes(account['scope'])),
        strict_loads(canonical_bytes(identity['ref'])),
        strict_loads(canonical_bytes(transport['ref'])),
        strict_loads(canonical_bytes(credential['ref'])),
        strict_loads(canonical_bytes(account_issuer['ref'])), snapshot.sequence,
        valid_until)


class ApplicationAccountAuthority:
    """Re-read the retained identity owner before each custody operation."""
    def __init__(self, reader):
        if type(reader) is not LedgerAuthorityReader:
            raise ContractError('application_account_authority_required')
        self._reader = reader

    async def resolve(self, request_bytes, *, now=None):
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc) if now is None else now
        return resolve_snapshot(snapshot, request_bytes,
            audience={'hubId': self._reader._hub, 'serviceId': 'identity-owner'}, now=now)
