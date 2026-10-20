"""Read a complete retained integration history without granting authority.

The host supplies one actual owner Snapshot and its enrolled OwnerBinding. This
reader checks retained provenance and transition semantics only. It performs no
broker reads, provider calls, retries or current authority evaluation.
"""
from collections.abc import Sequence
from dataclasses import dataclass

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from state_owner.ledger import OwnerBinding, Snapshot, StoredRecord, validate_history, validate_record
from .intent import effect_id, retained_state
from .observations import MAX_OBSERVATION_BYTES


_COMMANDS = {'integration-attempt-start', 'integration-attempt-complete',
             'integration-effect-reconcile'}


@dataclass(frozen=True, slots=True, repr=False)
class LifecycleView:
    """Private original/latest records and canonical latest state; empty is absent."""
    original: StoredRecord | None
    latest: StoredRecord | None
    state: bytes | None

    def __repr__(self):
        return '<LifecycleView private>'


def _refuse():
    raise ContractError('integration_lifecycle_invalid')


def _observation_identity(value, intent):
    """Bind a schema-valid observation to the original provider action and target."""
    kind, identity = value['kind'], value['identity']
    action, target = intent['action'], intent['target']
    if kind in ('uncertain', 'not-dispatched'):
        if identity is not None:
            _refuse()
        return
    if kind == 'read-only':
        # A null identity means no usable read was available. Neither form proves
        # a write outcome or permits another dispatch.
        if identity is None:
            return
        resource = (target.get('issueKey') or target.get('pageId') or target.get('projectKey')
                    or target.get('spaceKey') or target.get('repository'))
        if action == 'github-repo-create':
            resource = target['owner'] + '/' + target['name']
        if set(identity) != {'presence', 'resourceId'} or identity['resourceId'] != resource:
            _refuse()
        return
    if identity is None:
        _refuse()
    if action == 'jira-transition':
        matches = identity == target
    elif action == 'jira-comment':
        matches = set(identity) == {'issueKey', 'commentId'} and identity['issueKey'] == target['issueKey']
    elif action == 'jira-create':
        matches = set(identity) == {'issueKey'} and identity['issueKey'].startswith(target['projectKey'] + '-')
    elif action in ('confluence-create', 'confluence-update'):
        matches = (set(identity) == {'spaceKey', 'pageId', 'version'}
                   and identity['spaceKey'] == target['spaceKey'])
        if matches:
            matches = (identity['version'] == 1 if action == 'confluence-create' else
                       identity['pageId'] == target['pageId']
                       and identity['version'] == target['expectedVersion'] + 1)
    elif action == 'github-repo-create':
        matches = identity == {'repository': target['owner'] + '/' + target['name']}
    elif action == 'github-issue-create':
        matches = (set(identity) == {'repository', 'issueNumber'}
                   and identity['repository'] == target['repository'])
    else:
        matches = False
    if not matches:
        _refuse()


def _observation(state, original):
    value = state['observation']
    if len(canonical_bytes(value)) > MAX_OBSERVATION_BYTES:
        _refuse()
    validate('integration-provider-observation', value)
    if (value['originalOperationId'] != original['originalOperationId']
            or value['originalPayloadDigest'] != original['originalPayloadDigest']
            or value['attemptOperationId'] != state['attempt']['operationId']
            or value['retryAllowed'] is not False):
        _refuse()
    _observation_identity(value, original['intent'])
    return value


def _transition(record, sequence, previous, original, first, binding):
    state, operation = record['state'], record['operation']
    validate('integration-effect-state', state)
    if (record['outcome'] != 'committed' or operation['expectedVersion'] != sequence - 1
            or any(canonical_bytes(record[key]) != canonical_bytes(first[key])
                   for key in ('effects', 'artifacts', 'repository'))
            or any(canonical_bytes(state[key]) != canonical_bytes(original[key])
                   for key in ('intent', 'originalOperationId', 'originalPayloadDigest'))):
        _refuse()
    audit = record.get('authorizationDecision', {})
    contract = audit.get('contractId')
    if contract not in _COMMANDS or audit != {
            'operationId': operation['operationId'], 'decision': 'allowed', 'reason': 'authorized',
            'actorRef': operation['effectiveActorRef'], 'contractId': contract}:
        _refuse()
    attempt = state.get('attempt')
    if attempt is None or operation['operationId'] == original['originalOperationId']:
        _refuse()
    payload = {
        'effectRef': {'id': binding.entity_id, 'ownerHubId': binding.hub_id, 'revision': sequence - 1},
        'originalOperationId': original['originalOperationId'],
        'originalPayloadDigest': original['originalPayloadDigest'],
        'attemptOperationId': attempt['operationId'],
    }
    validate(contract, payload)
    if payload_digest(payload) != operation['payloadDigest']:
        _refuse()
    if contract == 'integration-attempt-start':
        if (previous['phase'] != 'intent-committed' or state['phase'] != 'dispatch-claimed'
                or not operation['approvalRefs']
                or attempt != {'operationId': operation['operationId'],
                    'payloadDigest': operation['payloadDigest'], 'claimRecordId': record['recordId'],
                    'claimSequence': sequence}):
            _refuse()
        return state
    if (operation['operationId'] == attempt['operationId']
            or previous.get('attempt') != attempt):
        _refuse()
    observation = _observation(state, original)
    if contract == 'integration-attempt-complete':
        phases = {'acknowledged': 'applied', 'not-dispatched': 'not-dispatched',
                  'uncertain': 'reconciliation-required'}
        # An unresolved read does not stop the original worker. Its eventual
        # owner-held observation may complete this same claim without redispatch.
        if (previous['phase'] not in ('dispatch-claimed', 'reconciliation-required')
                or state['phase'] != phases.get(observation['kind'])):
            _refuse()
    elif (previous['phase'] not in ('dispatch-claimed', 'reconciliation-required')
            or observation['kind'] not in ('read-only', 'uncertain')
            or state['phase'] != 'reconciliation-required'):
        _refuse()
    return state


def read_lifecycle(snapshot, binding):
    """Validate one full snapshot and return immutable private retained data.

    Empty history is valid only at sequence zero. No record may be skipped, and
    a retained authorization audit is not proof of current caller admission.
    """
    try:
        if (type(snapshot) is not Snapshot or type(binding) is not OwnerBinding
                or binding.owner_domain != 'integrations' or binding.entity_kind != 'effect'
                or strict_loads(binding.scope)['projectId'] is None
                or type(snapshot.sequence) is not int
                or not isinstance(snapshot.records, Sequence)):
            _refuse()
        # Copy a mutable collection once. StoredRecord and its bytes are immutable;
        # the returned view never borrows a caller-owned list or mutable state.
        records = tuple(snapshot.records)
        if any(type(stored) is not StoredRecord for stored in records):
            _refuse()
        checked = validate_history(records, binding)
        if checked.sequence != snapshot.sequence:
            _refuse()
        if not records:
            return LifecycleView(None, None, None)
        first = validate_record(records[0].record, binding)
        original = retained_state(first)
        validate('integration-effect-state', original)
        if (binding.entity_id != effect_id(strict_loads(binding.scope), original['originalOperationId'])
                or original['intent']['effectRef'] != {
                    'id': binding.entity_id, 'ownerHubId': binding.hub_id, 'revision': 0}):
            _refuse()
        latest = original
        for stored in records[1:]:
            record = validate_record(stored.record, binding)
            latest = _transition(record, stored.sequence, latest, original, first, binding)
        return LifecycleView(records[0], records[-1], canonical_bytes(latest))
    except (ContractError, KeyError, TypeError, ValueError):
        raise ContractError('integration_lifecycle_invalid') from None
