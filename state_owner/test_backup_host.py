"""Local key custody and trusted receipt inventory failure tests."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import tempfile
import subprocess
import stat
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from nacl.secret import SecretBox
from state_owner.recovery import _binding
from state_owner.backup import BackupReceipt
from state_owner.backup_host import BackupHost
from state_owner.ledger import StreamIdentity
from state_owner.test_recovery import history


class BackupHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.backup, self.inventory, self.keys = (self.root / name for name in ('backup', 'inventory', 'keys'))
        for directory in (self.backup, self.inventory, self.keys):
            directory.mkdir(mode=0o700)
        self.binding, _ = history()
        self.source = StreamIdentity(datetime(2026, 10, 16, tzinfo=timezone.utc), 0)
        self.host = self.make_host()

    def make_host(self, **changes):
        config = dict(destination_id='destination-one', binding=self.binding, stream_identity=self.source)
        config.update(changes)
        return BackupHost(self.backup, self.inventory, self.keys, **config)

    def receipt(self, index=1):
        # Part coverage belongs to restore sampling; these tests bind real encrypted top metadata.
        components = []
        for number, logical in enumerate(('manifest.json', 'part-' + 'a' * 32 + '-000000.jsonl'), 1):
            components.append({'name': 'backup-' + f'{index + number + 100:032x}' + '.box',
                'kind': 'checkpoint', 'plainBytes': 2, 'cipherBytes': 42,
                'plainDigest': 'sha256:' + '0' * 64, 'cipherDigest': 'sha256:' + '1' * 64,
                'logical': logical, 'reference': None})
        top = {'format': 'amx-owner-encrypted-backup-v1', 'binding': _binding(self.binding),
               'source': {'created': self.source.created.isoformat(), 'minimumSequence': 0},
               'cursor': index, 'checkpointDigest': 'sha256:' + '2' * 64, 'components': components}
        raw = bytes(SecretBox(self.host.load_key('key-one')).encrypt(canonical_bytes(top)))
        name = 'backup-' + f'{index:032x}' + '.box'
        path = self.backup / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return BackupReceipt(name, 'sha256:' + hashlib.sha256(raw).hexdigest(), index)

    def commit(self, index=1, completed_at=100):
        return self.host.commit(self.receipt(index), key_id='key-one', completed_at=completed_at)

    def test_missing_key_never_creates_and_enrollment_never_overwrites(self):
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            self.host.load_key('key-one')
        self.assertEqual(list(self.keys.iterdir()), [])
        self.host.enroll_key('key-one')
        key = self.host.load_key('key-one')
        self.assertEqual(len(key), 32)
        self.assertEqual((self.keys / 'key-key-one.key').stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ContractError, '^backup_key_enrollment_uncertain$'):
            self.host.enroll_key('key-one')
        self.assertEqual(self.host.load_key('key-one'), key)
        self.assertNotIn(key.hex(), repr(self.host))

    def test_private_roots_and_no_symlink_ancestors_or_overlap(self):
        self.keys.chmod(0o755)
        with self.assertRaisesRegex(ContractError, '^backup_host_configuration$'):
            self.make_host()
        self.keys.chmod(0o700)
        linked = self.root / 'link'
        linked.symlink_to(self.root, target_is_directory=True)
        for directories in ((self.backup, self.inventory, self.backup),
                            (self.backup, self.inventory, self.backup / 'nested'),
                            (linked / 'backup', self.inventory, self.keys),
                            (Path('relative'), self.inventory, self.keys)):
            with self.assertRaisesRegex(ContractError, '^backup_host_configuration$'):
                BackupHost(*directories, destination_id='destination-one', binding=self.binding, stream_identity=self.source)

    def test_case_alias_roots_cannot_overlap_on_case_insensitive_filesystem(self):
        alias = self.root / 'BACKUP'
        if not alias.exists() or not os.path.samefile(alias, self.backup):
            self.skipTest('Temporary filesystem is case-sensitive')
        nested = self.backup / 'nested-key-root'
        nested.mkdir(mode=0o700)
        for keys in (alias, alias / nested.name):
            with self.assertRaisesRegex(ContractError, '^backup_host_configuration$'):
                BackupHost(self.backup, self.inventory, keys, destination_id='destination-one',
                           binding=self.binding, stream_identity=self.source)

    def test_key_permission_symlink_size_and_path_errors_are_private(self):
        self.host.enroll_key('key-one')
        path = self.keys / 'key-key-one.key'
        path.chmod(0o644)
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            self.host.load_key('key-one')
        path.chmod(0o600)
        path.write_bytes(b'short')
        with self.assertRaises(ContractError):
            self.host.load_key('key-one')
        (self.keys / 'key-linked.key').symlink_to(path)
        for key_id in ('linked', '../private-key', ''):
            with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
                self.host.load_key(key_id)

    def test_fifo_key_is_opened_nonblocking_and_refused_before_read(self):
        name = 'key-pipe.key'
        os.mkfifo(self.keys / name, 0o600)
        flags_seen = []
        opened = os.open
        def observe(path, flags, *args, **kwargs):
            if path == name:
                flags_seen.append(flags)
                if not flags & os.O_NONBLOCK:
                    # Keep a regression from hanging the test process.
                    raise OSError('blocking FIFO open refused by test')
            return opened(path, flags, *args, **kwargs)
        with patch('state_owner.checkpoints.os.open', side_effect=observe):
            with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
                self.host.load_key('pipe')
        self.assertTrue(flags_seen)
        self.assertTrue(all(flags & os.O_NONBLOCK for flags in flags_seen))

    def grant_acl(self, path, entry):
        result = subprocess.run(['/bin/chmod', '+a', entry, str(path)],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, 'Owned ACL control could not be created')

    def test_native_acl_refuses_key_and_directory_despite_private_mode_bits(self):
        self.host.enroll_key('key-one')
        key = self.keys / 'key-key-one.key'
        self.grant_acl(key, 'everyone allow read')
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            self.host.load_key('key-one')
        self.grant_acl(self.keys, 'everyone allow read')
        self.assertEqual(self.keys.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(ContractError, '^backup_host_configuration$'):
            self.make_host()
        with self.assertRaisesRegex(ContractError, '^backup_key_enrollment_uncertain$'):
            self.host.enroll_key('blocked')
        self.assertFalse((self.keys / 'key-blocked.key').exists())

    def test_native_acl_refuses_writable_ancestor(self):
        self.host.enroll_key('key-one')
        self.grant_acl(self.root, 'everyone allow write')
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            self.host.load_key('key-one')

    def test_native_mount_refusal_precedes_secret_read_or_write(self):
        from native_security import descriptor_admission as native
        self.host.enroll_key('key-one')
        check = native._Darwin.check
        def refuse_file(backend, descriptor, purpose, deadline):
            if purpose is native.DescriptorPurpose.PRIVATE_FILE:
                raise native.AdmissionError('native_admission_mount')
            return check(backend, descriptor, purpose, deadline)
        with patch.object(native._Darwin, 'check', new=refuse_file):
            with patch('state_owner.checkpoints.os.read') as read:
                with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
                    self.host.load_key('key-one')
                read.assert_not_called()
            with patch('state_owner.checkpoints.os.write') as write:
                with self.assertRaisesRegex(ContractError, '^backup_key_enrollment_uncertain$'):
                    self.host.enroll_key('blocked')
                write.assert_not_called()
        self.assertFalse((self.keys / 'key-blocked.key').exists())

    def test_native_policy_is_rechecked_before_returning_key_bytes(self):
        from native_security import descriptor_admission as native
        self.host.enroll_key('key-one')
        check = native._Darwin.check
        files = []
        def changed_policy(backend, descriptor, purpose, deadline):
            if purpose is native.DescriptorPurpose.PRIVATE_FILE:
                files.append(descriptor)
                if len(files) == 2:
                    raise native.AdmissionError('native_admission_mount')
            return check(backend, descriptor, purpose, deadline)
        with patch.object(native._Darwin, 'check', new=changed_policy):
            with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
                self.host.load_key('key-one')
        self.assertEqual(len(files), 2)

    def test_key_publication_stat_failure_closes_its_new_descriptor(self):
        inspect = os.fstat
        created = []
        def failed_stat(descriptor):
            metadata = inspect(descriptor)
            if stat.S_ISREG(metadata.st_mode) and metadata.st_size == 0:
                created.append(descriptor)
                raise OSError('private metadata error')
            return metadata
        with patch('state_owner.checkpoints.os.fstat', side_effect=failed_stat):
            with self.assertRaisesRegex(ContractError, '^backup_key_enrollment_uncertain$'):
                self.host.enroll_key('blocked')
        self.assertEqual(len(created), 1)
        with self.assertRaises(OSError):
            os.fstat(created[0])
        self.assertFalse((self.keys / 'key-blocked.key').exists())

    def test_inventory_round_trip_latest_and_strong_floor(self):
        self.assertIsNone(self.host.latest())
        self.host.enroll_key('key-one')
        first = self.commit(1, 200)
        second = self.commit(2, 300)
        self.assertEqual(self.make_host().latest(), second)
        self.assertEqual(first.source_identity.minimum_sequence, 1)
        self.assertEqual(second.source_identity.minimum_sequence, 2)
        self.assertEqual(repr(second), '<InventoryEntry private>')
        for path in self.inventory.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(self.host.load_key('key-one').hex().encode(), path.read_bytes())
        advanced = self.make_host(stream_identity=StreamIdentity(self.source.created, 3))
        self.assertEqual(advanced.latest(), second)  # Historic, not viable for the new floor.
        with self.assertRaises(ContractError):
            advanced.commit(first.receipt, key_id='key-one', completed_at=400)
        third = advanced.commit(self.receipt(3), key_id='key-one', completed_at=400)
        self.assertEqual(advanced.latest(), third)

    def test_latest_tie_is_deterministic_and_ignores_unrelated_files(self):
        self.host.enroll_key('key-one')
        self.commit(1, 100)
        winner = self.commit(2, 100)
        (self.inventory / 'unrelated').write_text('not an inventory entry')
        self.assertEqual(self.host.latest(), winner)

    def test_later_old_prefix_never_downgrades_retained_watermark(self):
        self.host.enroll_key('key-one')
        greatest = self.commit(100, 1000)
        self.commit(90, 1001)
        selected = self.host.latest()
        self.assertEqual(selected, greatest)
        self.assertEqual(selected.receipt.cursor, 100)
        self.assertEqual(selected.source_identity.minimum_sequence, 100)

    def test_corrupt_inventory_and_binding_epoch_destination_floor_fail_closed(self):
        self.host.enroll_key('key-one')
        self.commit()
        path = next(self.inventory.iterdir())
        original = path.read_bytes()
        value = strict_loads(original)
        variants = []
        for update in (lambda v: v['binding'].update(ownerHubId='other'),
                       lambda v: v['source'].update(created=(self.source.created + timedelta(seconds=1)).isoformat()),
                       lambda v: v.update(destinationId='other'),
                       lambda v: v['source'].update(minimumSequence=0)):
            changed = strict_loads(original)
            update(changed)
            variants.append(canonical_bytes(changed))
        for raw in [b'private malformed content', *variants]:
            path.write_bytes(raw)
            with self.assertRaisesRegex(ContractError, '^backup_inventory_unavailable$'):
                self.host.latest()
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(ContractError):
            self.host.latest()
        path.chmod(0o600)
        link = self.inventory / ('inventory-' + 'f' * 32 + '.json')
        link.symlink_to(path)
        with self.assertRaises(ContractError):
            self.host.latest()

    def test_commit_checks_ciphertext_digest_key_and_time(self):
        self.host.enroll_key('key-one')
        receipt = self.receipt()
        for changed in (replace(receipt, digest='sha256:' + '0' * 64), replace(receipt, manifest_name='../outside')):
            with self.assertRaisesRegex(ContractError, '^backup_inventory_commit_uncertain$'):
                self.host.commit(changed, key_id='key-one', completed_at=1)
        for timestamp in (float('nan'), float('inf'), -1, True):
            with self.assertRaises(ContractError):
                self.host.commit(receipt, key_id='key-one', completed_at=timestamp)
        with self.assertRaises(ContractError):
            self.host.commit(receipt, key_id='missing', completed_at=1)
        self.assertEqual(list(self.inventory.iterdir()), [])

    def test_fsync_failure_reports_uncertainty_and_does_not_expose_details(self):
        with patch('state_owner.checkpoints.os.fsync', side_effect=OSError('private filesystem details')):
            with self.assertRaisesRegex(ContractError, '^backup_key_enrollment_uncertain$'):
                self.host.enroll_key('key-one')
        self.assertEqual(list(self.keys.iterdir()), [])
        self.host.enroll_key('key-one')
        receipt = self.receipt()
        with patch('state_owner.checkpoints.os.fsync', side_effect=OSError('private filesystem details')):
            with self.assertRaisesRegex(ContractError, '^backup_inventory_commit_uncertain$'):
                self.host.commit(receipt, key_id='key-one', completed_at=100)
        self.assertIsNone(self.host.latest())

    def test_uncertain_published_inventory_requires_digest_and_directory_sync(self):
        self.host.enroll_key('key-one')
        receipt = self.receipt()
        sync = os.fsync
        calls = 0
        def fail_publication(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('private publication error')
            sync(fd)
        with patch('state_owner.checkpoints.os.fsync', side_effect=fail_publication):
            with self.assertRaisesRegex(ContractError, '^backup_inventory_commit_uncertain$'):
                self.host.commit(receipt, key_id='key-one', completed_at=100)
        with patch('state_owner.backup_host.os.fsync', side_effect=OSError('private sync error')):
            with self.assertRaisesRegex(ContractError, '^backup_inventory_unavailable$'):
                self.host.latest()
        self.assertEqual(self.host.latest().receipt, receipt)
        (self.backup / receipt.manifest_name).write_bytes(b'changed')
        with self.assertRaisesRegex(ContractError, '^backup_inventory_unavailable$'):
            self.host.latest()

    def test_bundle_key_owner_epoch_and_cursor_cannot_be_relabelled(self):
        self.host.enroll_key('key-one')
        self.host.enroll_key('key-other')
        receipt = self.receipt()
        with self.assertRaisesRegex(ContractError, '^backup_inventory_commit_uncertain$'):
            self.host.commit(receipt, key_id='key-other', completed_at=1)
        path = self.backup / receipt.manifest_name
        box = SecretBox(self.host.load_key('key-one'))
        original = strict_loads(box.decrypt(path.read_bytes()))
        changes = (lambda v: v['binding'].update(hubId='other-hub'),
                   lambda v: v['source'].update(created=(self.source.created + timedelta(seconds=1)).isoformat()),
                   lambda v: v.update(cursor=2), lambda v: v['source'].update(minimumSequence=2))
        for change in changes:
            value = strict_loads(canonical_bytes(original))
            change(value)
            raw = bytes(box.encrypt(canonical_bytes(value)))
            path.write_bytes(raw)
            relabelled = replace(receipt, digest='sha256:' + hashlib.sha256(raw).hexdigest())
            with self.assertRaisesRegex(ContractError, '^backup_inventory_commit_uncertain$'):
                self.host.commit(relabelled, key_id='key-one', completed_at=1)
        self.assertEqual(list(self.inventory.iterdir()), [])

    def test_latest_rechecks_recorded_key_and_actual_bundle_binding(self):
        self.host.enroll_key('key-one')
        self.host.enroll_key('key-other')
        self.commit()
        inventory_path = next(self.inventory.iterdir())
        original = inventory_path.read_bytes()
        value = strict_loads(original)
        value['keyId'] = 'key-other'
        inventory_path.write_bytes(canonical_bytes(value))
        with self.assertRaisesRegex(ContractError, '^backup_inventory_unavailable$'):
            self.host.latest()
        value = strict_loads(original)
        bundle_path = self.backup / value['receipt']['manifestName']
        box = SecretBox(self.host.load_key('key-one'))
        top = strict_loads(box.decrypt(bundle_path.read_bytes()))
        top['binding']['hubId'] = 'other-hub'
        raw = bytes(box.encrypt(canonical_bytes(top)))
        bundle_path.write_bytes(raw)
        value['receipt']['digest'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
        inventory_path.write_bytes(canonical_bytes(value))
        with self.assertRaisesRegex(ContractError, '^backup_inventory_unavailable$'):
            self.host.latest()

    def test_inventory_bound_and_root_replacement_fail_closed(self):
        self.host.enroll_key('key-one')
        self.commit()
        with patch('state_owner.backup_host.MAX_ENTRIES', 0):
            with self.assertRaises(ContractError):
                self.host.latest()
        self.keys.rename(self.root / 'old-keys')
        self.keys.mkdir(mode=0o700)
        with self.assertRaises(ContractError):
            self.host.load_key('key-one')


if __name__ == '__main__':
    unittest.main()
