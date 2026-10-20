"""Offline cache reopening, corruption and bounded lazy replay checks."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import hashlib
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from state_owner.history import OwnerHistory
from state_owner.ledger import StoredRecord, StreamIdentity
from state_owner.test_recovery import history


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name).resolve() / 'cache.sqlite'
        self.binding, self.snapshot = history()
        self.source = StreamIdentity(datetime(2026, 10, 16, tzinfo=timezone.utc), 0)

    def open(self, **kwargs):
        kwargs.setdefault('stream_identity', self.source)
        owner = OwnerHistory(self.path, self.binding, **kwargs)
        self.addCleanup(owner.close)
        return owner

    def populate(self, owner):
        for record in self.snapshot.records:
            owner.verify_source(record)

    def test_reopen_requires_source_validation_before_absence_or_rows(self):
        owner = self.open()
        self.populate(owner)
        self.assertEqual(owner.cursor, self.snapshot.sequence)
        self.assertEqual(owner.total_bytes, sum(len(r.record) for r in self.snapshot.records))
        owner.close()
        owner = self.open()
        self.assertEqual(owner.verified_cursor, 0)
        with self.assertRaises(ContractError):
            owner.record(1)
        with self.assertRaises(ContractError):
            owner.outcome('missing', 'sha256:' + '0' * 64)
        owner.verify_source(self.snapshot.records[0])
        self.assertEqual(owner.record(1), self.snapshot.records[0])
        with self.assertRaises(ContractError):
            owner.append_verified(self.snapshot.records[1])
        owner.verify_source(self.snapshot.records[1])
        operation = strict_loads(self.snapshot.records[0].record)['operation']
        outcome = owner.outcome(operation['operationId'], operation['payloadDigest'])
        self.assertTrue(outcome.replayed)
        self.assertEqual(outcome.record, self.snapshot.records[0].record)
        with self.assertRaisesRegex(ContractError, 'owner_operation_conflict'):
            owner.outcome(operation['operationId'], 'sha256:' + '0' * 64)
        self.assertIsNone(owner.outcome('missing', 'sha256:' + '0' * 64))

    def test_lazy_fixed_prefix_private_repr_and_close(self):
        owner = self.open()
        owner.verify_source(self.snapshot.records[0])
        prefix = owner.records(1)
        owner.verify_source(self.snapshot.records[1])
        self.assertEqual(len(prefix), 1)
        self.assertEqual(list(prefix), [self.snapshot.records[0]])
        self.assertEqual(prefix[-1], self.snapshot.records[0])
        with self.assertRaises(IndexError):
            prefix[1]
        with self.assertRaises(TypeError):
            prefix[:]
        self.assertNotIn('secret-value', repr(prefix) + repr(owner))
        owner.close()
        with self.assertRaises(ContractError):
            prefix[0]

    def test_sequence_and_duplicate_identity_fail_without_partial_append(self):
        owner = self.open()
        with self.assertRaises(ContractError):
            owner.verify_source(self.snapshot.records[1])
        owner.verify_source(self.snapshot.records[0])
        second = strict_loads(self.snapshot.records[1].record)
        second['operation']['operationId'] = 'operation-1'
        with self.assertRaises(ContractError):
            owner.append_verified(StoredRecord(canonical_bytes(second), 2))
        self.assertEqual(owner.cursor, 1)
        owner.append_verified(self.snapshot.records[1])
        self.assertEqual(owner.cursor, 2)

    def test_check_next_has_no_side_effects(self):
        owner = self.open()
        owner.check_next(self.snapshot.records[0])
        self.assertEqual(owner.cursor, 0)
        self.assertEqual(owner.total_bytes, 0)
        owner.append_verified(self.snapshot.records[0])
        with self.assertRaises(ContractError):
            owner.check_next(self.snapshot.records[0])
        owner.check_next(self.snapshot.records[1])
        self.assertEqual(owner.cursor, 1)

    def test_effect_change_fails_and_preserves_cached_tip(self):
        owner = self.open()
        owner.verify_source(self.snapshot.records[0])
        second = strict_loads(self.snapshot.records[1].record)
        second['effects'][0]['recovery'] = 'idempotent-retry'
        with self.assertRaises(ContractError):
            owner.append_verified(StoredRecord(canonical_bytes(second), 2))
        self.assertEqual(owner.cursor, 1)

    def test_external_sqlite_change_fences_open_cache(self):
        owner = self.open()
        self.populate(owner)
        with closing(sqlite3.connect(self.path)) as attacker:
            attacker.execute("UPDATE records SET payload_digest='changed' WHERE position=1")
            attacker.commit()
        with self.assertRaises(ContractError):
            owner.record(1)
        with self.assertRaises(ContractError):
            owner.cursor

    def test_reopened_corruption_cannot_pass_source_check(self):
        owner = self.open()
        self.populate(owner)
        owner.close()
        with closing(sqlite3.connect(self.path)) as attacker:
            attacker.execute("UPDATE records SET record=? WHERE position=1", (b'private-corruption',))
            attacker.commit()
        owner = self.open()
        with self.assertRaisesRegex(ContractError, '^owner_history_cache_invalid$'):
            owner.verify_source(self.snapshot.records[0])
        self.assertEqual(owner.verified_cursor, 0)

    def test_recomputed_local_digest_cannot_replace_broker_record(self):
        owner = self.open()
        self.populate(owner)
        owner.close()
        value = strict_loads(self.snapshot.records[0].record)
        value['state']['reservation'] = 'other-executor'
        changed = canonical_bytes(value)
        with closing(sqlite3.connect(self.path)) as attacker:
            attacker.execute('UPDATE records SET record=?,digest=? WHERE position=1',
                             (changed, hashlib.sha256(changed).digest()))
            attacker.commit()
        owner = self.open()
        with self.assertRaises(ContractError):
            owner.verify_source(self.snapshot.records[0])
        self.assertEqual(owner.verified_cursor, 0)

    def test_lock_symlink_permissions_and_binding(self):
        owner = self.open()
        with self.assertRaises(ContractError):
            self.open()
        owner.close()
        with self.assertRaises(ContractError):
            OwnerHistory(self.path, replace(self.binding, hub_id='hub-other'), stream_identity=self.source)
        self.path.chmod(0o644)
        with self.assertRaises(ContractError):
            self.open()
        self.path.chmod(0o600)
        link = self.path.parent / 'linked'
        link.symlink_to(self.path)
        with self.assertRaises(ContractError):
            OwnerHistory(link, self.binding, stream_identity=self.source)

    def test_secondary_index_corruption_is_rejected_at_open(self):
        owner = self.open()
        self.populate(owner)
        owner.close()
        with closing(sqlite3.connect(self.path)) as database:
            page_size = database.execute('PRAGMA page_size').fetchone()[0]
            operation_index = next(row[1] for row in database.execute('PRAGMA index_list(records)')
                                   if database.execute('SELECT name FROM pragma_index_info(?)', (row[1],)).fetchone() == ('operation_id',))
            root_page = database.execute('SELECT rootpage FROM sqlite_master WHERE name=?', (operation_index,)).fetchone()[0]
        raw = bytearray(self.path.read_bytes())
        start, end = (root_page - 1) * page_size, root_page * page_size
        offset = raw.find(b'operation-1', start, end)
        self.assertGreaterEqual(offset, start)
        raw[offset:offset + len(b'operation-1')] = b'operation-0'
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ContractError, '^owner_history_cache_invalid$'):
            self.open()

    def test_raw_file_write_fences_open_cache_without_sqlite_notification(self):
        owner = self.open()
        self.populate(owner)
        # Change an unused header byte, bypassing SQLite's data_version tracking.
        with self.path.open('r+b') as database:
            database.seek(72)
            original = database.read(1)
            database.seek(72)
            database.write(bytes([original[0] ^ 1]))
        with self.assertRaises(ContractError):
            owner.outcome('missing', 'sha256:' + '0' * 64)

    def test_integrity_deadline_fails_closed(self):
        with patch('state_owner.history.time.monotonic', side_effect=[0.0, 31.0]):
            with self.assertRaisesRegex(ContractError, '^owner_history_cache_invalid$'):
                self.open()

    def test_source_epoch_is_persisted_without_automatic_adoption(self):
        owner = self.open()
        self.populate(owner)
        self.assertEqual(owner.source_identity, self.source)
        owner.close()
        with self.assertRaises(ContractError):
            self.open(stream_identity=StreamIdentity(self.source.created + timedelta(seconds=1), 0))
        same_epoch = StreamIdentity(self.source.created, 2)
        owner = self.open(stream_identity=same_epoch)
        self.assertEqual(owner.source_identity, same_epoch)
        self.assertEqual(owner.verified_cursor, 0)
        self.populate(owner)
        self.assertEqual(owner.verified_cursor, 2)

    def test_source_identity_is_required(self):
        with self.assertRaises(TypeError):
            OwnerHistory(self.path, self.binding)
        with self.assertRaises(ContractError):
            self.open(stream_identity=None)

    def test_capacity_properties_and_large_deployment_budget(self):
        owner = self.open(max_bytes=1_099_511_627_776)
        self.assertEqual(owner.max_bytes, 1_099_511_627_776)
        self.assertEqual(owner.max_records, 1_000_000)
        owner.close()
        with self.assertRaises(ContractError):
            self.open(max_bytes=1_099_511_627_777)
        with self.assertRaises(ContractError):
            self.open(max_records=1_000_001)

    def test_outcome_input_syntax(self):
        owner = self.open()
        for operation, digest in (('bad.token', 'sha256:' + '0' * 64),
                                  ('operation-one', 'sha256:' + 'G' * 64),
                                  ('operation-one', 'arbitrary'), (None, None)):
            with self.assertRaisesRegex(ContractError, '^owner_operation_invalid$'):
                owner.outcome(operation, digest)

    def test_capacity_boundaries(self):
        owner = self.open(max_records=1)
        owner.verify_source(self.snapshot.records[0])
        with self.assertRaises(ContractError):
            owner.verify_source(self.snapshot.records[1])
        self.assertEqual(owner.cursor, 1)
        owner.close()
        with self.assertRaises(ContractError):
            self.open(max_bytes=1)

    def test_thousand_records_lazy_restart_revalidation(self):
        binding, snapshot = history(count=1000)
        owner = self.open(max_records=1000)
        for record in snapshot.records:
            owner.verify_source(record)
        rows = owner.records(snapshot.sequence)
        self.assertEqual(len(rows), 1000)
        self.assertEqual(rows[999], snapshot.records[-1])
        owner.close()
        owner = self.open(max_records=1000)
        for record in snapshot.records:
            owner.verify_source(record)
        self.assertEqual(sum(1 for _ in owner.records(snapshot.sequence)), 1000)


if __name__ == '__main__':
    unittest.main()
