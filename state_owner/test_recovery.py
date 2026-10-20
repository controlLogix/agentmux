"""Offline checkpoint preservation and filesystem failure tests."""
import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts.wire import ContractError, canonical_bytes, payload_digest, strict_loads
from state_owner.ledger import OwnerBinding, Snapshot, StoredRecord
from state_owner.recovery import build_checkpoint, read_checkpoint, restore_backup, write_backup


def history(count=2, padding=''):
    scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
    binding = OwnerBinding(hub_id='hub-one', owner_domain='tasks', entity_id='task-one',
                           entity_kind='task', scope=canonical_bytes(scope))
    ref = {'id': 'ref-one', 'ownerHubId': 'hub-one', 'revision': 1}
    records = []
    previous = 0
    for index in range(1, count + 1):
        operation = {'schemaVersion': '1.0.0', 'operationId': f'operation-{index}',
                     'payloadDigest': payload_digest({'index': index}), 'expectedVersion': index - 1,
                     'caller': {'principalId': 'user-one', 'kind': 'human', 'authenticatedIdentityRef': ref},
                     'effectiveActorRef': ref, 'scope': scope, 'taskId': 'task-one', 'runId': None,
                     'attemptId': None, 'delegationRef': None, 'grantRef': ref, 'approvalRefs': [],
                     'traceId': 'trace-one', 'causationId': 'cause-one', 'deadline': '2026-10-16T12:00:00Z',
                     'cancellationRef': ref}
        record = {'schemaVersion': '1.0.0', 'recordId': f'record-{index}', 'entityId': 'task-one',
                  'entityKind': 'task', 'ownerHubId': 'hub-one', 'ownerDomain': 'tasks',
                  'entityVersion': index, 'previousRevision': previous, 'operation': operation,
                  'recordedAt': '2026-10-16T11:00:00Z', 'outcome': 'committed',
                  'state': {'reservation': 'executor-one', 'private': 'secret-value', 'padding': padding,
                            'legacyIds': ['sqlite-row-42'], 'quarantine': ['source-entry']},
                  'effects': [{'effectId': 'effect-one', 'contractId': 'task-dispatch',
                               'payloadDigest': payload_digest({'taskId': 'task-one'}),
                               'grantRef': ref, 'recovery': 'human-reconciliation',
                               'payload': {'taskId': 'task-one'}}],
                  'artifacts': [{'artifactId': 'artifact-one', 'ownerHubId': 'hub-one',
                                 'storeRef': ref, 'version': 'version-one', 'digest': payload_digest({}),
                                 'bytes': 2, 'mediaType': 'application/json'}], 'repository': None}
        previous = index  # The owner uses one dedicated aggregate stream.
        records.append(StoredRecord(record=canonical_bytes(record), sequence=previous))
    return binding, Snapshot(records=tuple(records), sequence=previous)


def reframe(raw, change):
    frames = [strict_loads(frame) for frame in raw.splitlines()]
    change(frames)
    body = b''.join(canonical_bytes(frame) + b'\n' for frame in frames[:-1])
    return body + canonical_bytes({'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}) + b'\n'


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.binding, self.snapshot = history()
        self.raw = build_checkpoint(self.snapshot, self.binding)

    def test_preserves_exact_records_and_fences_recovery(self):
        recovered = read_checkpoint(self.raw, self.binding)
        self.assertEqual(recovered.snapshot, self.snapshot)
        self.assertTrue(recovered.reconciliation_required)
        self.assertNotIn('secret-value', repr(recovered))
        with self.assertRaises(Exception):
            recovered.reconciliation_required = False

    def test_multiple_frames_can_exceed_sdk_single_json_limit(self):
        binding, snapshot = history(count=24, padding='a' * 40000)
        raw = build_checkpoint(snapshot, binding)
        self.assertGreater(len(raw), 1048576)
        self.assertEqual(read_checkpoint(raw, binding).snapshot, snapshot)

    def test_corruption_truncation_wrong_digest_and_scope_fail(self):
        for raw in (self.raw[:-1], self.raw[:-80], self.raw.replace(b'amx-owner', b'bad-owner'), b'{}\n'):
            with self.subTest(raw_length=len(raw)), self.assertRaisesRegex(ContractError, '^checkpoint_invalid$'):
                read_checkpoint(raw, self.binding)
        with self.assertRaisesRegex(ContractError, '^checkpoint_invalid$'):
            read_checkpoint(self.raw, self.binding, expected_digest='sha256:' + '0' * 64)
        with self.assertRaisesRegex(ContractError, '^checkpoint_invalid$'):
            read_checkpoint(self.raw, replace(self.binding, hub_id='other-hub'))

    def test_recomputed_digest_cannot_hide_missing_genesis_or_revision_gap(self):
        def missing(frames):
            del frames[1]
            frames[0]['recordCount'] -= 1
        def bad_revision(frames):
            record = strict_loads(base64.b64decode(frames[2]['record']))
            record['previousRevision'] = 2
            frames[2]['record'] = base64.b64encode(canonical_bytes(record)).decode('ascii')
        for change in (missing, bad_revision):
            with self.assertRaisesRegex(ContractError, '^checkpoint_invalid$'):
                read_checkpoint(reframe(self.raw, change), self.binding)

    def test_empty_and_wrong_snapshot_cursor_fail(self):
        for snapshot in (Snapshot(records=(), sequence=0), replace(self.snapshot, sequence=99)):
            with self.assertRaisesRegex(ContractError, '^checkpoint_invalid$'):
                build_checkpoint(snapshot, self.binding)

    def test_checkpoint_byte_limit_fails_closed(self):
        with patch('state_owner.recovery.MAX_CHECKPOINT_BYTES', 1024):
            with self.assertRaisesRegex(ContractError, '^checkpoint_invalid$'):
                build_checkpoint(self.snapshot, self.binding)
            with self.assertRaisesRegex(ContractError, '^checkpoint_invalid$'):
                read_checkpoint(self.raw, self.binding)

    def test_private_no_replace_publication_and_fenced_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'backup'
            digest = write_backup(path, self.raw, self.binding)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(restore_backup(path, self.binding, expected_digest=digest).snapshot, self.snapshot)
            with self.assertRaisesRegex(ContractError, '^backup_exists$'):
                write_backup(path, self.raw, self.binding)
            self.assertEqual(path.read_bytes(), self.raw)
            self.assertEqual([p.name for p in Path(folder).iterdir()], ['backup'])

    def test_before_publish_failure_cleans_only_owned_temp(self):
        with tempfile.TemporaryDirectory() as folder:
            unrelated = Path(folder) / '.amx-checkpoint-unrelated'
            unrelated.write_text('keep')
            with patch('state_owner.recovery.os.write', side_effect=OSError('private-error')):
                with self.assertRaisesRegex(ContractError, '^backup_write_failed$'):
                    write_backup(Path(folder) / 'backup', self.raw, self.binding)
            self.assertEqual([p.name for p in Path(folder).iterdir()], [unrelated.name])
            self.assertEqual(unrelated.read_text(), 'keep')

    def test_after_publish_failure_preserves_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'backup'
            real_sync = os.fsync
            calls = []
            def fail_directory(fd):
                calls.append(fd)
                if len(calls) == 2:
                    raise OSError('private-error')
                real_sync(fd)
            with patch('state_owner.recovery.os.fsync', side_effect=fail_directory):
                with self.assertRaisesRegex(ContractError, '^backup_publication_uncertain$'):
                    write_backup(path, self.raw, self.binding)
            self.assertEqual(path.read_bytes(), self.raw)

    def test_symlink_and_wrong_inventory_digest_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'backup'
            digest = write_backup(path, self.raw, self.binding)
            link = Path(folder) / 'link'
            link.symlink_to(path)
            for target, expected in ((link, digest), (path, 'sha256:' + '0' * 64)):
                with self.assertRaisesRegex(ContractError, '^backup_restore_failed$'):
                    restore_backup(target, self.binding, expected_digest=expected)
            with self.assertRaisesRegex(ContractError, '^backup_exists$'):
                write_backup(link, self.raw, self.binding)
            path.chmod(0o644)
            with self.assertRaisesRegex(ContractError, '^backup_restore_failed$'):
                restore_backup(path, self.binding, expected_digest=digest)


if __name__ == '__main__':
    unittest.main()
