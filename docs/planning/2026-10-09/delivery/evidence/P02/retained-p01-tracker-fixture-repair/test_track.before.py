"""Coverage and dependency checks must reject incomplete delivery records."""
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import track


class TrackingTests(unittest.TestCase):
    def setUp(self):
        self.data = track.read(track.STATE)

    def test_complete_inventory_is_consistent(self):
        self.assertTrue(track.validate(self.data))

    def test_missing_work_is_rejected(self):
        self.data['tasks'] = [t for t in self.data['tasks'] if t['id'] != 'P02-T01']
        with self.assertRaisesRegex(AssertionError, 'work coverage'):
            track.validate(self.data)

    def test_removed_phase_criterion_is_rejected(self):
        self.data['epics'][0]['acceptanceCriteria'].pop()
        with self.assertRaisesRegex(AssertionError, 'criteria'):
            track.validate(self.data)

    def test_missing_catalog_record_is_rejected(self):
        task = next(t for t in self.data['tasks'] if t.get('catalogRecordIds'))
        task['catalogRecordIds'] = []
        with self.assertRaisesRegex(AssertionError, 'catalog coverage'):
            track.validate(self.data)

    def test_predecessor_cannot_be_bypassed(self):
        task = next(t for t in self.data['tasks'] if t['id'] == 'P02-T01')
        task['status'] = 'in_progress'
        with self.assertRaisesRegex(AssertionError, 'predecessor|prior phase|only one phase'):
            track.validate(self.data)

    def test_removed_dependency_cannot_skip_phase_gate(self):
        for row in self.data['tasks']:
            row['status'] = 'planned'
        task = next(t for t in self.data['tasks'] if t['id'] == 'P02-T01')
        task['dependsOn'] = []
        task['status'] = 'in_progress'
        with self.assertRaisesRegex(AssertionError, 'prior phase gate'):
            track.validate(self.data)

    def test_parallel_phases_are_rejected(self):
        for row in self.data['tasks']:
            row['status'] = 'planned'
        for key in ('P00-T06', 'P01-T01'):
            next(t for t in self.data['tasks'] if t['id'] == key)['status'] = 'ready'
        with self.assertRaisesRegex(AssertionError, 'only one phase'):
            track.validate(self.data)

    def test_cycle_is_rejected(self):
        # Isolate dependency-cycle validation from the live board's progress.
        for row in self.data['tasks']:
            row['status'] = 'planned'
        task = next(t for t in self.data['tasks'] if t['id'] == 'P00-T06')
        task['dependsOn'] = ['P00-T01']
        with self.assertRaisesRegex(AssertionError, 'cycle'):
            track.validate(self.data)

    def test_duplicate_behavior_owner_is_rejected(self):
        source = next(t for t in self.data['tasks'] if t.get('behaviorCheckIds'))
        target = next(t for t in self.data['tasks'] if t['id'] == 'P00-T02')
        target['behaviorCheckIds'].append(source['behaviorCheckIds'][0])
        with self.assertRaisesRegex(AssertionError, 'duplicate component behavior owner'):
            track.validate(self.data)

    def test_host_qualification_cannot_be_moved_before_host_implementation(self):
        owner = next(t for t in self.data['tasks'] if 'REPO-01-C01' in t.get('behaviorCheckIds', []))
        owner['behaviorCheckIds'].remove('REPO-01-C01')
        earlier = next(t for t in self.data['tasks'] if t['id'] == 'P00-T06')
        earlier['behaviorCheckIds'].append('REPO-01-C01')
        with self.assertRaisesRegex(AssertionError, 'qualification phase mismatch'):
            track.validate(self.data)


class FinalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tasks = {f'P{i:02}-GATE': {'id': f'P{i:02}-GATE', 'kind': 'phase-verification', 'status': 'done'} for i in range(15)}
        self.record = {
            'sourceCommit': 'candidate', 'reviewer': 'Codex', 'mergeAuthorized': False,
            'decision': {'actor': 'Codex', 'date': '2026-10-09', 'decision': 'accepted'},
            'phaseGateEvidence': [{'taskId': k, 'evidence': ['reviewed.log']} for k in self.tasks],
            'hubs': [{'hubId': h, 'adminIdentity': 'admin-' + h, 'enrollmentEvidence': ['enroll.log'], 'startupEvidence': ['start.log']} for h in ('a', 'b')],
            'bilateralRuns': [{
                'originHubId': a, 'executorHubId': b, 'nonDestructive': True,
                'inputDigestBefore': 'sha256:fixture', 'inputDigestAfter': 'sha256:fixture',
                'taskId': 'task-' + a, 'delegationId': 'delegation-' + a, 'attemptId': 'attempt-' + a,
                'resultId': 'result-' + a, 'artifactDigest': 'sha256:artifact', 'evidence': ['run.log'],
                'originAcceptance': {'hubId': a, 'decision': 'accepted', 'evidence': ['accepted.log']}
            } for a, b in (('a', 'b'), ('b', 'a'))]
        }

    def check(self):
        track.final_evidence(self.record, self.tasks, 'candidate')

    def test_valid_autonomous_record(self):
        self.check()

    def test_merge_permission_is_rejected(self):
        self.record['mergeAuthorized'] = True
        with self.assertRaisesRegex(AssertionError, 'must not authorize'):
            self.check()

    def test_worker_claim_is_not_codex_review(self):
        self.record['reviewer'] = 'worker'
        with self.assertRaisesRegex(AssertionError, 'Codex must review'):
            self.check()

    def test_missing_or_incomplete_phase_is_rejected(self):
        self.record['phaseGateEvidence'].pop()
        with self.assertRaisesRegex(AssertionError, 'every phase'):
            self.check()

    def test_unaccepted_gate_is_rejected(self):
        self.tasks['P14-GATE']['status'] = 'verification'
        with self.assertRaisesRegex(AssertionError, 'completed reviewed'):
            self.check()

    def test_missing_reverse_run_is_rejected(self):
        self.record['bilateralRuns'].pop()
        with self.assertRaisesRegex(AssertionError, 'both directions'):
            self.check()

    def test_executor_cannot_accept_for_origin(self):
        self.record['bilateralRuns'][0]['originAcceptance']['hubId'] = 'b'
        with self.assertRaisesRegex(AssertionError, 'origin-owned'):
            self.check()

    def test_modified_input_is_rejected(self):
        self.record['bilateralRuns'][0]['inputDigestAfter'] = 'changed'
        with self.assertRaisesRegex(AssertionError, 'non-destructive'):
            self.check()

    def test_shared_administration_is_rejected(self):
        self.record['hubs'][1]['adminIdentity'] = 'admin-a'
        with self.assertRaisesRegex(AssertionError, 'independent hub'):
            self.check()

    def test_wrong_candidate_is_rejected(self):
        self.record['sourceCommit'] = 'other'
        with self.assertRaisesRegex(AssertionError, 'wrong final candidate'):
            self.check()

    def test_missing_dated_codex_decision_is_rejected(self):
        self.record['decision']['actor'] = 'worker'
        with self.assertRaisesRegex(AssertionError, 'dated Codex'):
            self.check()

    def test_final_update_checks_remote_before_saving(self):
        task = {'id': 'MERGE-01', 'kind': 'final-acceptance', 'status': 'verification',
                'acceptanceCriteria': [{'id': 'AC01'}], 'evidence': [], 'commits': [], 'history': []}
        data = {'branch': 'feat/agentmux-platform-rearchitecture', 'history': []}
        completion = {'taskId': task['id'], 'sourceCommit': 'candidate', 'remoteCommit': 'candidate',
                      'finalAcceptanceRecord': 'final.json',
                      'acceptanceResults': [{'criterionId': 'AC01', 'status': 'passed', 'evidence': ['actual.log']}]}
        args = SimpleNamespace(task=task['id'], status='done', record='completion.json', actor='Codex', note='Reviewed')
        with patch.object(track, 'read', side_effect=[data, completion, self.record]), \
             patch.object(track, 'validate', return_value={**self.tasks, task['id']: task}), \
             patch.object(track.subprocess, 'run'), \
             patch.object(track.subprocess, 'check_output', side_effect=[data['branch'], 'different refs/heads/feature']), \
             patch.object(track, 'save') as save:
            with self.assertRaisesRegex(AssertionError, 'not the current pushed'):
                track.update(args)
            save.assert_not_called()
        self.assertEqual(task['status'], 'verification')
