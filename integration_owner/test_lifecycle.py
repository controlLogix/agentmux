"""Offline lifecycle provenance tests; these do not qualify broker or authority I/O."""
import copy
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from integration_owner.lifecycle import read_lifecycle
from integration_owner.observations import observation
from integration_owner.test_intent import BINDING, intent_record
from state_owner.ledger import OwnerBinding, Snapshot, StoredRecord


PROVIDER_CASES = (
    ('jira-transition', {'issueKey': 'AMUX-66', 'transitionId': '31'},
     {'issueKey': 'AMUX-66', 'transitionId': '31'}, 'AMUX-66'),
    ('jira-comment', {'issueKey': 'AMUX-66'},
     {'issueKey': 'AMUX-66', 'commentId': '123'}, 'AMUX-66'),
    ('jira-create', {'projectKey': 'AMUX', 'issueType': 'Task'},
     {'issueKey': 'AMUX-72'}, 'AMUX'),
    ('confluence-create', {'spaceKey': 'DOCS', 'parentId': None},
     {'spaceKey': 'DOCS', 'pageId': '42', 'version': 1}, 'DOCS'),
    ('confluence-update', {'spaceKey': 'DOCS', 'pageId': '42', 'expectedVersion': 3},
     {'spaceKey': 'DOCS', 'pageId': '42', 'version': 4}, '42'),
    ('github-repo-create', {'owner': 'example', 'name': 'repo-one', 'visibility': 'private'},
     {'repository': 'example/repo-one'}, 'example/repo-one'),
    ('github-issue-create', {'repository': 'example/repo-one'},
     {'repository': 'example/repo-one', 'issueNumber': 12}, 'example/repo-one'),
)


def provider_intent(action, target):
    first = intent_record()
    body = first['state']['intent']
    body.update(action=action, target=copy.deepcopy(target))
    if action not in ('jira-transition', 'github-repo-create'):
        body['contentRef'] = {'artifactId': 'content-one', 'ownerHubId': 'hub-one',
            'storeRef': {'id': 'store-one', 'ownerHubId': 'hub-one', 'revision': 1},
            'version': 'v-one', 'digest': 'sha256:' + 'a' * 64, 'bytes': 1,
            'mediaType': 'application/vnd.agentmux.integration-content+json'}
        first['artifacts'] = [copy.deepcopy(body['contentRef'])]
    digest = payload_digest(body)
    first['operation']['payloadDigest'] = first['state']['originalPayloadDigest'] = digest
    first['effects'][0].update(payloadDigest=digest, payload=copy.deepcopy(body))
    return first


def snapshot(records):
    return Snapshot(tuple(StoredRecord(canonical_bytes(value), index)
                          for index, value in enumerate(records, 1)), len(records))


def next_record(records, contract, *, operation_id=None, kind=None, identity=None):
    """Extend the existing retained-intent fixture using the shared command fields."""
    original = records[0]['state']
    previous = records[-1]['state']
    sequence = len(records) + 1
    operation_id = operation_id or ('operation-step-' + str(sequence))
    attempt_id = operation_id if contract == 'integration-attempt-start' else previous['attempt']['operationId']
    payload = {'effectRef': {'id': BINDING.entity_id, 'ownerHubId': BINDING.hub_id, 'revision': sequence - 1},
        'originalOperationId': original['originalOperationId'],
        'originalPayloadDigest': original['originalPayloadDigest'], 'attemptOperationId': attempt_id}
    result = copy.deepcopy(records[0])
    result.update(recordId='lifecycle-record-' + str(sequence), entityVersion=sequence, previousRevision=sequence - 1)
    result['operation'].update(operationId=operation_id, expectedVersion=sequence - 1,
        payloadDigest=payload_digest(payload), approvalRefs=[])
    result['authorizationDecision'].update(operationId=operation_id, contractId=contract)
    state = result['state']
    if contract == 'integration-attempt-start':
        result['operation']['approvalRefs'] = [{'id': 'current-approval', 'ownerHubId': 'hub-one', 'revision': 2}]
        state.update(phase='dispatch-claimed', attempt={'operationId': operation_id,
            'payloadDigest': result['operation']['payloadDigest'], 'claimRecordId': result['recordId'],
            'claimSequence': sequence}, observation=None)
    else:
        phase = {'acknowledged': 'applied', 'not-dispatched': 'not-dispatched',
                 'uncertain': 'reconciliation-required', 'read-only': 'reconciliation-required'}[kind]
        if kind == 'acknowledged' and identity is None and original['intent']['action'] == 'jira-transition':
            identity = copy.deepcopy(original['intent']['target'])
        state.update(phase=phase, attempt=copy.deepcopy(previous['attempt']), observation=observation(
            original['originalOperationId'], original['originalPayloadDigest'], attempt_id,
            kind=kind, identity=identity).private_copy())
    return result


def claimed(first=None):
    records = [intent_record() if first is None else first]
    records.append(next_record(records, 'integration-attempt-start'))
    return records


class LifecycleTests(unittest.TestCase):
    def assert_refused(self, records, binding=BINDING):
        with self.assertRaisesRegex(ContractError, '^integration_lifecycle_invalid$'):
            read_lifecycle(snapshot(records), binding)

    def test_empty_snapshot_is_absent(self):
        view = read_lifecycle(Snapshot((), 0), BINDING)
        self.assertEqual((view.original, view.latest, view.state), (None, None, None))

    def test_original_stored_record_and_latest_state_are_preserved(self):
        stored = snapshot([intent_record()])
        view = read_lifecycle(stored, BINDING)
        self.assertIs(view.original, stored.records[0])
        self.assertIs(view.latest, stored.records[0])
        self.assertEqual(view.state, canonical_bytes(intent_record()['state']))

    def test_view_is_private_immutable_and_does_not_borrow_mutable_history(self):
        records = list(snapshot(claimed()).records)
        view = read_lifecycle(Snapshot(records, 2), BINDING)
        records.clear()
        self.assertEqual(view.latest.sequence, 2)
        self.assertEqual(repr(view), '<LifecycleView private>')
        with self.assertRaises(FrozenInstanceError):
            view.state = b'changed'
        with self.assertRaises(FrozenInstanceError):
            view.latest.record = b'changed'

    def test_only_actual_snapshot_records_and_binding_are_accepted(self):
        valid = snapshot([intent_record()])
        for stored, binding in ((SimpleNamespace(records=valid.records, sequence=1), BINDING),
                                (valid, SimpleNamespace()), (Snapshot((object(),), 1), BINDING),
                                (Snapshot(iter(valid.records), 1), BINDING)):
            with self.assertRaisesRegex(ContractError, '^integration_lifecycle_invalid$'):
                read_lifecycle(stored, binding)

    def test_snapshot_sequence_must_match_the_complete_history(self):
        stored = snapshot(claimed())
        for bad in (Snapshot((), 1), Snapshot(stored.records, 1), Snapshot(stored.records, True),
                    Snapshot((stored.records[-1],), 2)):
            with self.assertRaisesRegex(ContractError, '^integration_lifecycle_invalid$'):
                read_lifecycle(bad, BINDING)

    def test_owner_scope_domain_kind_and_full_record_are_checked(self):
        for binding in (OwnerBinding('hub-two', 'integrations', BINDING.entity_id, 'effect', BINDING.scope),
                        OwnerBinding('hub-one', 'other', BINDING.entity_id, 'effect', BINDING.scope),
                        OwnerBinding('hub-one', 'integrations', BINDING.entity_id, 'task', BINDING.scope)):
            self.assert_refused([intent_record()], binding)
        records = [intent_record()]
        records[0]['secret'] = 'synthetic-private'
        self.assert_refused(records)

    def test_initial_intent_provenance_cannot_be_skipped(self):
        for change in ('approval', 'digest', 'audit', 'phase', 'effect-ref'):
            records = [intent_record()]
            first = records[0]
            if change == 'approval':
                first['operation']['approvalRefs'] = []
            elif change == 'digest':
                first['state']['originalPayloadDigest'] = 'sha256:' + 'f' * 64
            elif change == 'audit':
                first['authorizationDecision']['actorRef'] = {
                    'id': 'someone-else', 'ownerHubId': 'hub-one', 'revision': 1}
            elif change == 'phase':
                first['state']['phase'] = 'applied'
            else:
                body = first['state']['intent']
                body['effectRef']['id'] = 'different-effect'
                first['operation']['payloadDigest'] = first['state']['originalPayloadDigest'] = payload_digest(body)
                first['effects'][0].update(payloadDigest=payload_digest(body), payload=copy.deepcopy(body))
            with self.subTest(change=change):
                self.assert_refused(records)

    def test_original_operation_cannot_be_moved_to_another_effect_aggregate(self):
        first = intent_record()
        first['operation']['operationId'] = 'different-original'
        first['state']['originalOperationId'] = 'different-original'
        first['authorizationDecision']['operationId'] = 'different-original'
        self.assert_refused([first])

    def test_start_retains_original_and_binds_current_claim(self):
        records = claimed()
        stored = snapshot(records)
        view = read_lifecycle(stored, BINDING)
        self.assertIs(view.original, stored.records[0])
        self.assertIs(view.latest, stored.records[1])
        self.assertEqual(strict_loads(view.state), records[-1]['state'])

    def test_start_requires_its_current_approval_and_exact_attempt_claim(self):
        for key, value in (('operationId', 'different-attempt'), ('payloadDigest', 'sha256:' + 'a' * 64),
                           ('claimRecordId', 'different-record'), ('claimSequence', 3)):
            records = claimed()
            records[-1]['state']['attempt'][key] = value
            with self.subTest(key=key):
                self.assert_refused(records)
        records = claimed()
        records[-1]['operation']['approvalRefs'] = []
        self.assert_refused(records)

    def test_a_second_start_cannot_replace_an_existing_claim(self):
        records = claimed()
        records.append(next_record(records, 'integration-attempt-start'))
        self.assert_refused(records)

    def test_later_expected_version_and_reconstructed_command_digest_are_exact(self):
        records = claimed()
        records[-1]['operation']['expectedVersion'] = 0
        self.assert_refused(records)
        records = claimed()
        bad_payload = {'effectRef': {'id': BINDING.entity_id, 'ownerHubId': 'hub-one', 'revision': 0},
            'originalOperationId': records[0]['state']['originalOperationId'],
            'originalPayloadDigest': records[0]['state']['originalPayloadDigest'],
            'attemptOperationId': records[-1]['operation']['operationId']}
        digest = payload_digest(bad_payload)
        records[-1]['operation']['payloadDigest'] = records[-1]['state']['attempt']['payloadDigest'] = digest
        self.assert_refused(records)

    def test_every_current_audit_is_exact_and_allowed(self):
        for key, value in (('operationId', 'different'), ('decision', 'denied'), ('reason', 'different'),
                           ('contractId', 'other-contract'), ('actorRef', {'id': 'other', 'ownerHubId': 'hub-one', 'revision': 1})):
            records = claimed()
            records[-1]['authorizationDecision'][key] = value
            with self.subTest(key=key):
                self.assert_refused(records)

    def test_later_records_preserve_original_intent_identity_and_effects(self):
        for change in ('intent', 'originalOperationId', 'originalPayloadDigest', 'effects', 'artifacts', 'repository'):
            records = claimed()
            latest = records[-1]
            if change == 'intent':
                latest['state']['intent']['target']['transitionId'] = '41'
            elif change in ('originalOperationId', 'originalPayloadDigest'):
                latest['state'][change] = 'another-original' if change.endswith('Id') else 'sha256:' + 'a' * 64
            elif change == 'effects':
                latest['effects'] = []
            elif change == 'artifacts':
                latest['artifacts'] = [{'artifactId': 'artifact-one', 'ownerHubId': 'hub-one',
                    'storeRef': {'id': 'store-one', 'ownerHubId': 'hub-one', 'revision': 1},
                    'version': 'v-one', 'digest': 'sha256:' + 'a' * 64, 'bytes': 1, 'mediaType': 'text/plain'}]
            else:
                latest['repository'] = {'repositoryId': 'repo-one', 'revision': 'r1', 'treeDigest': 'sha256:' + 'a' * 64}
            with self.subTest(change=change):
                self.assert_refused(records)

    def test_complete_maps_only_worker_observation_kinds(self):
        for kind, phase in (('acknowledged', 'applied'), ('not-dispatched', 'not-dispatched'),
                            ('uncertain', 'reconciliation-required')):
            records = claimed()
            records.append(next_record(records, 'integration-attempt-complete', kind=kind))
            self.assertEqual(strict_loads(read_lifecycle(snapshot(records), BINDING).state)['phase'], phase)
        records = claimed()
        records.append(next_record(records, 'integration-attempt-complete', kind='read-only'))
        self.assert_refused(records)

    def test_complete_cannot_change_attempt_or_claim_phase(self):
        for change in ('attempt', 'phase'):
            records = claimed()
            records.append(next_record(records, 'integration-attempt-complete', kind='acknowledged'))
            if change == 'attempt':
                records[-1]['state']['attempt']['claimRecordId'] = 'different-record'
            else:
                records[-1]['state']['phase'] = 'not-dispatched'
            self.assert_refused(records)

    def test_current_actor_can_change_only_with_its_matching_current_audit(self):
        records = claimed()
        records.append(next_record(records, 'integration-attempt-complete', kind='acknowledged'))
        actor = {'id': 'current-worker', 'ownerHubId': 'hub-one', 'revision': 2}
        records[-1]['operation']['effectiveActorRef'] = actor
        records[-1]['authorizationDecision']['actorRef'] = copy.deepcopy(actor)
        self.assertEqual(strict_loads(read_lifecycle(snapshot(records), BINDING).state)['phase'], 'applied')

    def test_lifecycle_operations_and_record_ids_cannot_be_reused(self):
        for operation_id in (intent_record()['operation']['operationId'], claimed()[-1]['operation']['operationId']):
            records = claimed()
            records.append(next_record(records, 'integration-attempt-complete', operation_id=operation_id, kind='uncertain'))
            self.assert_refused(records)
        records = claimed()
        records[-1]['recordId'] = records[0]['recordId']
        records[-1]['state']['attempt']['claimRecordId'] = records[0]['recordId']
        self.assert_refused(records)

    def test_reconcile_from_claimed_or_uncertain_always_remains_unresolved(self):
        for finish_first in (False, True):
            records = claimed()
            if finish_first:
                records.append(next_record(records, 'integration-attempt-complete', kind='uncertain'))
            for kind in ('read-only', 'uncertain'):
                records.append(next_record(records, 'integration-effect-reconcile', kind=kind))
                view = read_lifecycle(snapshot(records), BINDING)
                self.assertEqual(strict_loads(view.state)['phase'], 'reconciliation-required')

    def test_reconcile_cannot_claim_success_or_authorize_a_retry(self):
        for kind in ('acknowledged', 'not-dispatched'):
            records = claimed()
            records.append(next_record(records, 'integration-effect-reconcile', kind=kind))
            self.assert_refused(records)
        records = claimed()
        records.append(next_record(records, 'integration-effect-reconcile', kind='read-only'))
        records[-1]['state']['phase'] = 'applied'
        self.assert_refused(records)

    def test_late_completion_after_unresolved_reconcile_keeps_the_original_attempt(self):
        for kind in ('read-only', 'uncertain'):
            records = claimed()
            attempt = copy.deepcopy(records[-1]['state']['attempt'])
            records.append(next_record(records, 'integration-effect-reconcile', kind=kind))
            records.append(next_record(records, 'integration-attempt-complete', kind='acknowledged'))
            state = strict_loads(read_lifecycle(snapshot(records), BINDING).state)
            self.assertEqual(state['phase'], 'applied')
            self.assertEqual(state['attempt'], attempt)
            self.assertEqual(sum(record['state']['phase'] == 'dispatch-claimed' for record in records), 1)
            records[-1]['state']['attempt']['claimRecordId'] = 'different-claim'
            self.assert_refused(records)

    def test_terminal_states_refuse_completion_and_all_states_refuse_another_start(self):
        for kind in ('acknowledged', 'not-dispatched', 'uncertain'):
            records = claimed()
            records.append(next_record(records, 'integration-attempt-complete', kind=kind))
            contracts = ['integration-attempt-start']
            if kind != 'uncertain':
                contracts.append('integration-attempt-complete')
            for contract in contracts:
                changed = copy.deepcopy(records)
                changed.append(next_record(changed, contract, kind='uncertain'))
                self.assert_refused(changed)
            if kind != 'uncertain':
                records.append(next_record(records, 'integration-effect-reconcile', kind='read-only'))
                self.assert_refused(records)

    def test_observation_identity_digest_retry_and_canonical_size_are_checked(self):
        for key, value in (('originalOperationId', 'wrong-original'), ('originalPayloadDigest', 'sha256:' + 'f' * 64),
                           ('attemptOperationId', 'wrong-attempt'), ('retryAllowed', True),
                           ('identity', {'presence': 'present', 'resourceId': 'x' * 5000}),
                           ('secret', 'synthetic-private')):
            records = claimed()
            records.append(next_record(records, 'integration-attempt-complete', kind='uncertain'))
            records[-1]['state']['observation'][key] = value
            with self.subTest(key=key):
                self.assert_refused(records)

    def test_acknowledgements_match_all_supported_actions(self):
        for action, target, identity, _ in PROVIDER_CASES:
            with self.subTest(action=action):
                records = claimed(provider_intent(action, target))
                records.append(next_record(records, 'integration-attempt-complete',
                                           kind='acknowledged', identity=identity))
                state = strict_loads(read_lifecycle(snapshot(records), BINDING).state)
                self.assertEqual(state['phase'], 'applied')
                self.assertEqual(state['observation']['identity'], identity)

    def test_acknowledgement_requires_provider_specific_identity(self):
        for action, target, identity, resource in PROVIDER_CASES:
            other_provider = ({'issueKey': 'AMUX-66'} if action.startswith('github-') else
                              {'repository': 'example/repo-one'})
            for invalid in (None, other_provider, {'presence': 'present', 'resourceId': resource}):
                with self.subTest(action=action, identity=invalid):
                    records = claimed(provider_intent(action, target))
                    records.append(next_record(records, 'integration-attempt-complete',
                                               kind='acknowledged', identity=identity))
                    records[-1]['state']['observation']['identity'] = invalid
                    self.assert_refused(records)

    def test_acknowledgement_requires_the_retained_target_and_exact_shape(self):
        invalid_by_action = {
            'jira-transition': ({'issueKey': 'OTHER-66', 'transitionId': '31'},
                                {'issueKey': 'AMUX-66', 'transitionId': '41'}, {'issueKey': 'AMUX-66'}),
            'jira-comment': ({'issueKey': 'OTHER-66', 'commentId': '123'},
                             {'issueKey': 'AMUX-66'}, {'issueKey': 'AMUX-66', 'transitionId': '31'}),
            'jira-create': ({'issueKey': 'OTHER-72'}, {'issueKey': 'AMUX_EXTRA-72'},
                            {'issueKey': 'AMUX-72', 'commentId': '123'}),
            'confluence-create': ({'spaceKey': 'OTHER', 'pageId': '42', 'version': 1},
                                  {'spaceKey': 'DOCS', 'pageId': '42', 'version': 2}),
            'confluence-update': ({'spaceKey': 'OTHER', 'pageId': '42', 'version': 4},
                                  {'spaceKey': 'DOCS', 'pageId': '43', 'version': 4},
                                  {'spaceKey': 'DOCS', 'pageId': '42', 'version': 3},
                                  {'spaceKey': 'DOCS', 'pageId': '42', 'version': 5}),
            'github-repo-create': ({'repository': 'other/repo-one'}, {'repository': 'example/repo-two'},
                                   {'repository': 'example/repo-one', 'issueNumber': 12}),
            'github-issue-create': ({'repository': 'other/repo-one', 'issueNumber': 12},
                                    {'repository': 'example/repo-two', 'issueNumber': 12},
                                    {'repository': 'example/repo-one'}),
        }
        for action, target, identity, _ in PROVIDER_CASES:
            for invalid in invalid_by_action[action]:
                with self.subTest(action=action, identity=invalid):
                    records = claimed(provider_intent(action, target))
                    records.append(next_record(records, 'integration-attempt-complete',
                                               kind='acknowledged', identity=identity))
                    records[-1]['state']['observation']['identity'] = invalid
                    self.assert_refused(records)

    def test_acknowledgement_numeric_fields_still_use_the_shared_schema(self):
        fields = {'jira-comment': ('commentId', ('0', '../123')),
                  'confluence-create': ('pageId', ('0', '../42')),
                  'confluence-update': ('version', (0, True)),
                  'github-issue-create': ('issueNumber', (0, -1, True, '12'))}
        for action, target, identity, _ in PROVIDER_CASES:
            if action not in fields:
                continue
            key, invalid_values = fields[action]
            for invalid in invalid_values:
                with self.subTest(action=action, value=invalid):
                    records = claimed(provider_intent(action, target))
                    records.append(next_record(records, 'integration-attempt-complete',
                                               kind='acknowledged', identity=identity))
                    records[-1]['state']['observation']['identity'][key] = invalid
                    self.assert_refused(records)

    def test_uncertain_and_not_dispatched_have_no_provider_identity(self):
        for action, target, identity, resource in PROVIDER_CASES:
            for kind in ('uncertain', 'not-dispatched'):
                for invalid in (identity, {'presence': 'unavailable', 'resourceId': resource}):
                    with self.subTest(action=action, kind=kind, identity=invalid):
                        records = claimed(provider_intent(action, target))
                        records.append(next_record(records, 'integration-attempt-complete', kind=kind))
                        records[-1]['state']['observation']['identity'] = invalid
                        self.assert_refused(records)

    def test_read_only_identity_matches_known_resource_and_stays_unresolved(self):
        for action, target, _, resource in PROVIDER_CASES:
            for presence in ('present', 'absent', 'unavailable'):
                with self.subTest(action=action, presence=presence):
                    records = claimed(provider_intent(action, target))
                    records.append(next_record(records, 'integration-effect-reconcile', kind='read-only',
                                               identity={'presence': presence, 'resourceId': resource}))
                    state = strict_loads(read_lifecycle(snapshot(records), BINDING).state)
                    self.assertEqual(state['phase'], 'reconciliation-required')
                    self.assertIs(state['observation']['retryAllowed'], False)

    def test_read_only_rejects_acknowledgements_and_unrelated_resources(self):
        for action, target, identity, _ in PROVIDER_CASES:
            for invalid in (identity, {'presence': 'present', 'resourceId': 'unrelated-target'}):
                with self.subTest(action=action, identity=invalid):
                    records = claimed(provider_intent(action, target))
                    records.append(next_record(records, 'integration-effect-reconcile', kind='read-only'))
                    records[-1]['state']['observation']['identity'] = invalid
                    self.assert_refused(records)

    def test_invalid_intermediate_state_cannot_be_hidden_by_a_valid_latest_state(self):
        records = claimed()
        records.append(next_record(records, 'integration-attempt-complete', kind='uncertain'))
        records.append(next_record(records, 'integration-effect-reconcile', kind='read-only'))
        records[1]['operation']['approvalRefs'] = []
        self.assert_refused(records)

    def test_later_lifecycle_state_must_match_the_closed_shared_schema(self):
        records = claimed()
        records[-1]['state']['approved'] = True
        self.assert_refused(records)
        records = claimed()
        records[-1]['state']['observation'] = {'kind': 'uncertain'}
        self.assert_refused(records)


if __name__ == '__main__':
    unittest.main()
