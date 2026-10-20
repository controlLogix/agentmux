"""Reserve a durable receipt for every current unresolved definition attempt.

The catalog retains every definition, including tombstones. Its current version
supersedes older versions; retry commands replace the prior attempt. Those older
attempts cannot accept another completion. A terminal reconciliation receipt
closes its attempt; an optional fresh retry must reserve its own new completion.
"""
from agentmux_contracts import ContractError, canonical_bytes
from state_owner.ledger import StoredRecord, validate_record
from definition_owner_adapter import _validate_catalog
from definition_completion import _receipt_record, same_definition


async def completion_records(owner, proposed, *, expected_sequence):
    """Count all obligations in the durable candidate, never local observations.

    Walk the bounded catalog, not owner history. Resolve its exact receipt and
    original intent through indexed outcomes. The caller passes the result with
    the same expected sequence, so a concurrent transition causes a CAS conflict.
    """
    if not owner._ledger.completion_budget_required:
        return None
    state = proposed['state']
    _validate_catalog(state)
    count = 0
    proposal_ref = {'operationId': proposed['operation']['operationId'],
                    'payloadDigest': proposed['operation']['payloadDigest']}
    for entry in state['definitions']:
        reference = entry.get('effectReceiptRef')
        if reference is None:
            # Physical success is private until a durable receipt closes it.
            count += 1
            continue
        if reference == proposal_ref:
            stored = StoredRecord(canonical_bytes(proposed), expected_sequence + 1)
        else:
            stored = await owner._ledger.outcome(reference['operationId'], reference['payloadDigest'])
            if stored is None or stored.sequence > expected_sequence:
                raise ContractError('definition_receipt_unavailable')
        record = validate_record(stored.record, owner._binding)
        receipt = record.get('definitionEffectReceipt')
        if receipt is None:
            raise ContractError('definition_receipt_invalid')
        original = await owner._ledger.outcome(receipt['originalOperationId'], receipt['originalPayloadDigest'])
        if original is None or original.sequence > expected_sequence:
            raise ContractError('definition_outcome_not_found')
        value = validate_record(original.record, owner._binding)
        if len(value['effects']) != 1:
            raise ContractError('definition_outcome_invalid')
        effect = value['effects'][0]
        value, effect, original_entry = owner._retained(original, value['operation'],
            {'contractId': effect['contractId'], 'payload': effect['payload']})
        if not same_definition(entry, original_entry):
            raise ContractError('definition_catalog_conflict')
        _, receipt = _receipt_record(owner, stored, value, effect, original_entry)
        if receipt['status'] == 'retry-authorized':
            count += 1
    return count
