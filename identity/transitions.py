"""Pure changes to a validated identity aggregate.

The caller authenticates the operation, checks current authority and conditionally
commits the returned state. This module supplies none of those guarantees. Inputs
are copied through canonical JSON; returned state shares no mutable input values.
Enrollment verifies possession of public application keys in addition to the
separate broker credential provisioning. It generates no keys or credentials.
"""
from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from .authority import _indexes, _key
from .ingress import verify_possession
from .capacity import require_state_capacity

_MAX_REVISION = 9007199254740991
_SET_COLLECTIONS = {
    'identity-membership-set': 'memberships',
    'identity-legacy-alias-set': 'legacyAliases',
    'identity-grant-set': 'grants',
    'identity-approval-set': 'approvals',
    'identity-native-instance-set': 'nativeInstances',
}


def _copy(value):
    return strict_loads(canonical_bytes(value))


def _find(state, reference):
    """Find the stable ID across collections, including its previous revision."""
    for collection in ('identities', 'issuers', 'transports', 'memberships', 'grants', 'approvals',
                       'nativeInstances', 'legacyAliases', 'secretReferences', 'applicationAccounts',
                       'ordinarySecretReferences'):
        for position, item in enumerate(state.get(collection, [])):
            if _key(item['ref'])[:2] == _key(reference)[:2]:
                return collection, position, item
    return None


def _require_active(index, collection, reference):
    item = index[collection].get(_key(reference))
    if item is None or item['status'] != 'active':
        raise ContractError('identity_reference_unavailable')
    return item


def _new(state, collection, item, hub_id):
    reference = item['ref']
    if reference['ownerHubId'] != hub_id or reference['revision'] != 1:
        raise ContractError('identity_initial_revision_invalid')
    if item['status'] != 'active':
        raise ContractError('identity_enrollment_inactive')
    if _find(state, reference) is not None:
        raise ContractError('identity_reference_exists')
    state[collection].append(item)


def _enroll(state, payload, hub_id):
    identity = payload['identity']
    existing = _find(state, identity['ref'])
    if existing is None:
        _new(state, 'identities', identity, hub_id)
    elif (existing[0] != 'identities' or existing[2] != identity
          or identity['status'] != 'active'):
        raise ContractError('identity_enrollment_conflict')
    # Building the index here also rejects duplicated principal/external identity.
    index = _indexes(state, hub_id)
    for collection in ('issuers', 'transports'):
        for credential in payload[collection]:
            item = credential['record']
            subject = _require_active(index, 'identities', item['identityRef'])
            if collection == 'issuers':
                if subject['kind'] != 'service':
                    raise ContractError('identity_issuer_service_required')
            else:
                if item['method'] != 'nats-credential-mapping':
                    raise ContractError('identity_transport_method_unsupported')
                _require_active(index, 'issuers', item['issuerRef'])
            verify_possession({
                'purpose': 'agentmux-enrollment-possession-v1',
                'profileId': state['profileId'], 'authorityId': payload['authorityId'],
                'credential': item,
            }, credential['proof'], item['publicKey'])
            _new(state, collection, item, hub_id)
            index = _indexes(state, hub_id)


def _set(state, payload, collection, hub_id):
    item, previous = payload['record'], payload['previousRef']
    reference = item['ref']
    if reference['ownerHubId'] != hub_id:
        raise ContractError('identity_reference_owner_mismatch')
    existing = _find(state, reference)
    if previous is None:
        if existing is not None or reference['revision'] != 1:
            raise ContractError('identity_initial_revision_invalid')
    elif (existing is None or existing[0] != collection or existing[2]['ref'] != previous
          or previous['revision'] == _MAX_REVISION
          or reference['revision'] != previous['revision'] + 1):
        raise ContractError('identity_previous_revision_mismatch')
    index = _indexes(state, hub_id)
    if collection == 'memberships':
        _require_active(index, 'identities', item['identityRef'])
    elif collection == 'grants':
        _require_active(index, 'identities', item['callerRef'])
        _require_active(index, 'identities', item['actorRef'])
        if item['delegationRef'] is not None or item['callerRef'] != item['actorRef']:
            raise ContractError('delegation_not_supported')
    elif collection == 'approvals':
        _require_active(index, 'identities', item['approverRef'])
        _require_active(index, 'grants', item['grantRef'])
        _require_active(index, 'grants', item['approverGrantRef'])
    elif collection == 'nativeInstances':
        _require_active(index, 'identities', item['identityRef'])
        _require_active(index, 'identities', item['hostIdentityRef'])
    elif collection == 'legacyAliases':
        _require_active(index, 'identities', item['identityRef'])
        if not any(member['identityRef'] == item['identityRef'] and member['scope'] == item['scope']
                   and member['status'] == 'active' for member in index['memberships'].values()):
            raise ContractError('legacy_identity_membership_unavailable')
        if item['instanceOwner'] is not None and not any(
                native['owner'] == item['instanceOwner'] and native['identityRef'] == item['identityRef']
                and native['status'] == 'active' for native in index['nativeInstances'].values()):
            raise ContractError('legacy_identity_instance_unavailable')
    elif collection == 'secretReferences':
        owner = _require_active(index, 'identities', item['ownerIdentityRef'])
        if owner['kind'] != 'service':
            raise ContractError('application_account_service_required')
        if (item['profileId'] != state['profileId']
                or item['scope']['organizationId'] != state['organizationId']
                or item['scope']['projectId'] is None
                or item['scope']['workspaceId'] is not None
                or not any(member['identityRef'] == item['ownerIdentityRef']
                    and member['scope'] == item['scope'] and member['status'] == 'active'
                    for member in index['memberships'].values())):
            raise ContractError('application_account_scope_mismatch')
    if existing is None:
        state.setdefault(collection, []).append(item)
    else:
        state[collection][existing[1]] = item


def _set_application_account(state, payload, hub_id):
    from .application_host_selection import _nkey
    account = payload['record']
    changes = {'nats-administrator-credential': payload['administratorCredential'],
               'nats-account-issuer': payload['accountIssuer']}
    records = {kind: change['record'] for kind, change in changes.items()}
    if any(record['kind'] != kind for kind, record in records.items()):
        raise ContractError('application_account_secret_binding')
    if (not _nkey(account['accountPublicKey'], 0)
            or account['administratorCredentialRef'] != records['nats-administrator-credential']['ref']
            or account['accountIssuerRef'] != records['nats-account-issuer']['ref']
            or account['administratorCredentialRef'] == account['accountIssuerRef']):
        raise ContractError('application_account_secret_binding')
    for kind, item in records.items():
        if (item['ownerIdentityRef'] != account['administratorIdentityRef']
                or item['profileId'] != account['profileId'] or item['scope'] != account['scope']):
            raise ContractError('application_account_secret_binding')
        _set(state, {'record': item, 'previousRef': changes[kind]['previousRef']},
             'secretReferences', hub_id)
    index = _indexes(state, hub_id)
    identity = _require_active(index, 'identities', account['administratorIdentityRef'])
    transport = _require_active(index, 'transports', account['administratorTransportRef'])
    issuer = _require_active(index, 'issuers', transport['issuerRef'])
    issuer_identity = _require_active(index, 'identities', issuer['identityRef'])
    if (identity['kind'] != 'service' or transport['identityRef'] != identity['ref']
            or transport['method'] != 'nats-credential-mapping'
            or issuer_identity['kind'] != 'service'
            or account['profileId'] != state['profileId']
            or account['scope']['organizationId'] != state['organizationId']
            or account['scope']['projectId'] is None or account['scope']['workspaceId'] is not None
            or not any(member['identityRef'] == identity['ref'] and member['scope'] == account['scope']
                and member['status'] == 'active' for member in index['memberships'].values())):
        raise ContractError('application_account_scope_mismatch')
    _set(state, {'record': account, 'previousRef': payload['previousRef']}, 'applicationAccounts', hub_id)


def _link_external_account(state, payload, hub_id):
    if payload['identityRef']['ownerHubId'] != hub_id:
        raise ContractError('identity_reference_owner_mismatch')
    found = _find(state, payload['identityRef'])
    if (found is None or found[0] != 'identities'
            or found[2]['ref'] != payload['identityRef']
            or found[2]['status'] != 'active'):
        raise ContractError('identity_reference_unavailable')
    identity = found[2]
    if identity['kind'] != 'human':
        raise ContractError('identity_external_account_human_required')
    if identity['externalIdentity'] is not None:
        raise ContractError('identity_external_account_already_linked')
    # This one-time link preserves the stable local identity reference, so its
    # existing memberships and grants do not become a different account. The
    # authority entity version and audit still advance, and relinking is refused.
    identity['externalIdentity'] = payload['externalIdentity']


def _set_ordinary_secret(state, payload, hub_id):
    from .ordinary_secret import validate_enrollment
    item = payload['record']
    index = _indexes(state, hub_id)
    validate_enrollment(state, index, item, hub_id)
    # A generation is born once. Rotation retires the original row and creates
    # a new identity; it cannot bind any old reference to different material.
    if item['generationRef'] != item['ref']:
        raise ContractError('ordinary_secret_generation_invalid')
    previous = payload['previousRef']
    if previous is not None:
        found = _find(state, previous)
        if (found is None or found[0] != 'ordinarySecretReferences'
                or found[2]['ref'] != previous or found[2]['status'] != 'active'
                or previous['revision'] >= _MAX_REVISION):
            raise ContractError('ordinary_secret_previous_generation_invalid')
        original = found[2]
        if any(original[key] != item[key] for key in (
                'profileId', 'scope', 'ownerIdentityRef', 'ownerAudience',
                'callerIdentityRef', 'consumerRef', 'purposeRef')):
            raise ContractError('ordinary_secret_rotation_binding')
        original['status'] = 'revoked'
        original['ref']['revision'] += 1
    state.setdefault('ordinarySecretReferences', [])
    _new(state, 'ordinarySecretReferences', item, hub_id)


def transition(state, contract_id, payload, *, hub_id):
    """Return new state; authorityId-to-owner binding belongs to the caller.

    Revision changes intentionally invalidate references to the previous revision.
    Dependent records require explicit owner operations; no implicit regrant occurs.
    Validity intervals and operation authorization are checked by the caller and
    receiving evaluator, not inferred from the presence of these JSON records.
    """
    validate('identity-authority-state', state)
    _indexes(state, hub_id)
    if contract_id not in (*_SET_COLLECTIONS, 'identity-enroll', 'identity-revoke',
                           'identity-application-account-set',
                           'identity-external-account-link', 'identity-ordinary-secret-set'):
        raise ContractError('identity_transition_unsupported')
    validate(contract_id, payload)
    result, request = _copy(state), _copy(payload)
    if contract_id == 'identity-enroll':
        _enroll(result, request, hub_id)
    elif contract_id == 'identity-application-account-set':
        _set_application_account(result, request, hub_id)
    elif contract_id == 'identity-external-account-link':
        _link_external_account(result, request, hub_id)
    elif contract_id == 'identity-ordinary-secret-set':
        _set_ordinary_secret(result, request, hub_id)
    elif contract_id in _SET_COLLECTIONS:
        _set(result, request, _SET_COLLECTIONS[contract_id], hub_id)
    else:
        found = _find(result, request['targetRef'])
        if found is None or found[2]['ref'] != request['targetRef']:
            raise ContractError('identity_reference_unavailable')
        item = found[2]
        if item['ref']['revision'] == _MAX_REVISION:
            raise ContractError('identity_revision_exhausted')
        item['status'] = 'revoked'
        item['ref']['revision'] += 1
    validate('identity-authority-state', result)
    _indexes(result, hub_id)
    # Revocation may retire an older record that predates the growth reserve.
    # The command owner still enforces the complete 64 KiB record limit.
    if contract_id != 'identity-revoke':
        require_state_capacity(result)
    return result
