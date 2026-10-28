"""Offline admission controls. These do not qualify installed client startup."""
import ctypes as C
import errno
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from native_security import descriptor_admission as native


class NativeLibrary:
    """Return native-shaped results without opening a mount or changing ACLs."""
    def __init__(self, *, entries=(), present=1, flags=0x1000, owner=0, fs=b'apfs'):
        self.entries, self.present, self.flags, self.owner, self.fs = entries, present, flags, owner, fs
        self.freed, self.security_freed = 0, 0
        self.fail = None

    def fstatfs(self, fd, output):
        output._obj.flags, output._obj.owner, output._obj.fstypename = self.flags, self.owner, self.fs
        return 0

    def filesec_init(self): return 10
    def filesec_free(self, security): self.security_freed += 1
    def fstatx_np(self, *args): return -1 if self.fail == 'stat' else 0
    def filesec_query_property(self, security, prop, output):
        output._obj.value = self.present
        return -1 if self.fail == 'query' else 0
    def filesec_get_property(self, security, prop, output):
        output._obj.value = 20
        return -1 if self.fail == 'get' else 0
    def acl_valid(self, acl): return -1 if self.fail == 'valid' else 0
    def acl_get_entry(self, acl, index, output):
        if index >= len(self.entries):
            C.set_errno(errno.EIO if self.fail == 'iterator' else errno.EINVAL)
            return -1
        output._obj.value = index + 1
        return 0
    def acl_get_tag_type(self, entry, output):
        output._obj.value = self.entries[entry.value - 1][0]
        return 0
    def acl_get_permset(self, entry, output):
        output._obj.value = entry.value
        return 0
    def acl_get_perm_np(self, permissions, mask):
        return -1 if self.fail == 'permission' else int(bool(self.entries[permissions.value - 1][1] & mask))
    def acl_free(self, acl):
        self.freed += 1
        return -1 if self.fail == 'free' else 0


def metadata(*, directory=False, uid=501, mode=None, inode=22, links=1):
    return SimpleNamespace(st_dev=3, st_ino=inode,
        st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | (mode if mode is not None else (0o700 if directory else 0o600)),
        st_uid=uid, st_gid=20, st_nlink=links, st_size=50, st_mtime_ns=1, st_ctime_ns=2)


class NativeDescriptorAdmission(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(native.time, 'monotonic', return_value=10).start()
        self.addCleanup(patch.stopall)

    def check(self, library, purpose=native.DescriptorPurpose.PRIVATE_FILE):
        backend = object.__new__(native._Darwin)
        backend.lib = library
        backend.check(7, purpose, 11)

    def test_legacy_import_preserves_module_and_public_api_identity(self):
        from hub import native_descriptor_admission as legacy
        self.assertIs(legacy, native)
        self.assertIs(legacy.check_descriptor, native.check_descriptor)
        self.assertIs(legacy.AdmissionError, native.AdmissionError)
        self.assertIs(legacy.DescriptorPurpose, native.DescriptorPurpose)
        self.assertEqual(len(native.DescriptorPurpose), 7)

    def test_acl_absence_deny_and_read_only_ancestor(self):
        for lib, purpose in [(NativeLibrary(present=0), native.DescriptorPurpose.PRIVATE_FILE),
                             (NativeLibrary(entries=[(2, 0xffff)]), native.DescriptorPurpose.PRIVATE_FILE),
                             (NativeLibrary(entries=[(1, 1 << 1)]), native.DescriptorPurpose.PRIVATE_ANCESTOR)]:
            self.check(lib, purpose)
            self.assertEqual(lib.security_freed, 1)
            self.assertEqual(lib.freed, int(lib.present != 0))

    def test_protected_objects_reject_every_allow_but_ancestors_allow_reads(self):
        for purpose in (native.DescriptorPurpose.PROTECTED_FILE,
                        native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                        native.DescriptorPurpose.PREPARED_CORE_FILE):
            for permissions in (0, 1 << 1, 1 << 3, 1 << 2):
                lib = NativeLibrary(entries=[(1, permissions)])
                with self.subTest(purpose=purpose, permissions=permissions):
                    with self.assertRaisesRegex(native.AdmissionError, 'native_admission_acl'):
                        self.check(lib, purpose)
                    self.assertEqual((lib.freed, lib.security_freed), (1, 1))
            self.check(NativeLibrary(entries=[(2, 0xffff)]), purpose)
        for purpose in (native.DescriptorPurpose.PRIVATE_ANCESTOR,
                        native.DescriptorPurpose.PROTECTED_ANCESTOR):
            self.check(NativeLibrary(entries=[(1, 1 << 1)]), purpose)

    def test_nonzero_acl_presence_still_runs_full_authorization_and_cleanup(self):
        for present in (1, 32, 64, -1):
            for purpose in native.DescriptorPurpose:
                lib = NativeLibrary(present=present, entries=[(2, 0xffff)])
                with self.subTest(present=present, purpose=purpose):
                    self.check(lib, purpose)
                    self.assertEqual((lib.freed, lib.security_freed), (1, 1))
            for purpose in (native.DescriptorPurpose.PRIVATE_DIRECTORY,
                            native.DescriptorPurpose.PRIVATE_FILE,
                            native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                            native.DescriptorPurpose.PROTECTED_FILE):
                lib = NativeLibrary(present=present, entries=[(1, 1 << 1)])
                with self.subTest(present=present, purpose=purpose), self.assertRaises(native.AdmissionError):
                    self.check(lib, purpose)
                self.assertEqual((lib.freed, lib.security_freed), (1, 1))
            for purpose in (native.DescriptorPurpose.PRIVATE_ANCESTOR,
                            native.DescriptorPurpose.PROTECTED_ANCESTOR):
                self.check(NativeLibrary(present=present, entries=[(1, 1 << 1)]), purpose)
                with self.assertRaises(native.AdmissionError):
                    self.check(NativeLibrary(present=present, entries=[(1, 1 << 2)]), purpose)
            for failure in ('get', 'valid', 'iterator', 'permission', 'free'):
                lib = NativeLibrary(present=present, entries=[(1, 0)])
                lib.fail = failure
                with self.subTest(present=present, failure=failure), self.assertRaises(native.AdmissionError):
                    self.check(lib, native.DescriptorPurpose.PRIVATE_ANCESTOR)
                self.assertEqual(lib.security_freed, 1)

    def test_grants_malformed_acl_and_unknown_results_refuse_and_free(self):
        for purpose, entries in [(native.DescriptorPurpose.PRIVATE_FILE, [(1, 1 << 1)]),
                                 (native.DescriptorPurpose.PROTECTED_EXECUTABLE, [(3, 0)]),
                                 (native.DescriptorPurpose.PRIVATE_ANCESTOR, [(2, 0)] * 129)]:
            lib = NativeLibrary(entries=entries)
            with self.assertRaises(native.AdmissionError): self.check(lib, purpose)
            self.assertEqual((lib.freed, lib.security_freed), (1, 1))
        for failure in ['stat', 'query', 'get', 'valid', 'iterator', 'permission', 'free']:
            lib = NativeLibrary(entries=[(1, 0)])
            lib.fail = failure
            with self.subTest(failure=failure), self.assertRaises(native.AdmissionError):
                self.check(lib, native.DescriptorPurpose.PROTECTED_ANCESTOR)
            self.assertEqual(lib.security_freed, 1)
        for bit in (2, 4, 5, 6, 8, 10, 12, 13):
            with self.subTest(bit=bit), self.assertRaises(native.AdmissionError):
                self.check(NativeLibrary(entries=[(1, 1 << bit)]), native.DescriptorPurpose.PROTECTED_ANCESTOR)

    def test_mount_purposes_remain_distinct(self):
        for flags in (0, 0x201000):
            with self.assertRaises(native.AdmissionError): self.check(NativeLibrary(flags=flags))
        self.check(NativeLibrary(owner=501, fs=b'other'))
        for library in (NativeLibrary(owner=501), NativeLibrary(fs=b'other')):
            with self.assertRaises(native.AdmissionError):
                self.check(library, native.DescriptorPurpose.PROTECTED_EXECUTABLE)

    def test_deadline_expiry_after_allocation_still_frees(self):
        lib = NativeLibrary()
        def allocate():
            self.clock.return_value = 11
            return 10
        lib.filesec_init = allocate
        with self.assertRaisesRegex(native.AdmissionError, 'deadline'): self.check(lib)
        self.assertEqual(lib.security_freed, 1)

    def test_input_and_platform_refusal_precede_duplication(self):
        with patch.object(native, '_supported'), patch.object(native.os, 'dup') as duplicate:
            for deadline in (None, True, float('nan'), float('inf'), 10):
                with self.assertRaises(native.AdmissionError):
                    native.check_descriptor(1, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=deadline)
            for fd, purpose in [(True, native.DescriptorPurpose.PRIVATE_FILE), (-1, native.DescriptorPurpose.PRIVATE_FILE), (1, 'private_selection')]:
                with self.assertRaises(native.AdmissionError): native.check_descriptor(fd, purpose=purpose, deadline=11)
            duplicate.assert_not_called()
        with patch.object(native.sys, 'platform', 'linux'), self.assertRaises(native.AdmissionError):
            native.check_descriptor(1, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11)

    def test_duplicate_owned_only_for_check_and_close_failure_refuses(self):
        checker = Mock()
        with patch.object(native, '_supported'), patch.object(native, '_Darwin', return_value=checker), \
             patch.object(native.os, 'geteuid', return_value=501), \
             patch.object(native.os, 'dup', return_value=90), patch.object(native.os, 'close') as close, \
             patch.object(native.os, 'fstat', return_value=metadata()):
            self.assertIs(native.check_descriptor(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=21), True)
            checker.check.assert_called_with(90, native.DescriptorPurpose.PRIVATE_FILE, 11)
            close.assert_called_once_with(90)
            close.reset_mock()
            close.side_effect = OSError('private detail')
            with self.assertRaisesRegex(native.AdmissionError, '^native_admission_cleanup$'):
                native.check_descriptor(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11)
            close.assert_called_once_with(90)

    def changing(self, every_pass):
        """fstat results that differ at a pass's after-read (its third; a changed pass stops there)."""
        state = {'reads': 0}
        def inspect(fd):
            state['reads'] += 1
            changed = state['reads'] % 3 == 0 if every_pass else state['reads'] == 3
            return metadata(inode=23 if changed else 22)
        return inspect

    def test_mutation_on_every_pass_refuses_after_bounded_passes(self):
        for check, fd in ((native.check_descriptor, 90), (native.check_retained_descriptor, 7)):
            checker = Mock()
            with self.subTest(check=check.__name__), patch.object(native, '_supported'), \
                 patch.object(native, '_Darwin', return_value=checker), \
                 patch.object(native.os, 'geteuid', return_value=501), \
                 patch.object(native.os, 'dup', return_value=90), patch.object(native.os, 'close') as close, \
                 patch.object(native.os, 'fstat', side_effect=self.changing(every_pass=True)):
                with self.assertRaisesRegex(native.AdmissionError, '^native_admission_changed$'):
                    check(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11)
                self.assertEqual(checker.check.call_count, native._STABLE_PASSES)
                checker.check.assert_called_with(fd, native.DescriptorPurpose.PRIVATE_FILE, 11)
                self.assertEqual(close.call_count, int(check is native.check_descriptor))

    def test_one_overlapping_change_is_accepted_only_from_a_later_stable_pass(self):
        for check in (native.check_descriptor, native.check_retained_descriptor):
            checker = Mock()
            with self.subTest(check=check.__name__), patch.object(native, '_supported'), \
                 patch.object(native, '_Darwin', return_value=checker), \
                 patch.object(native.os, 'geteuid', return_value=501), \
                 patch.object(native.os, 'dup', return_value=90), patch.object(native.os, 'close'), \
                 patch.object(native.os, 'fstat', side_effect=self.changing(every_pass=False)):
                self.assertIs(check(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11), True)
                self.assertEqual(checker.check.call_count, 2)

    def test_change_to_refused_policy_is_refused_not_retried(self):
        reads = iter([metadata(), metadata(), metadata(mode=0o640)])
        checker = Mock()
        with patch.object(native, '_supported'), patch.object(native, '_Darwin', return_value=checker), \
             patch.object(native.os, 'geteuid', return_value=501), \
             patch.object(native.os, 'fstat', side_effect=lambda fd: next(reads)):
            with self.assertRaisesRegex(native.AdmissionError, '^native_admission_permissions$'):
                native.check_retained_descriptor(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11)
            self.assertEqual(checker.check.call_count, 1)

    def test_change_at_the_deadline_refuses_without_another_pass(self):
        checker = Mock()
        def late(*args):
            self.clock.return_value = 11
        checker.check.side_effect = late
        with patch.object(native, '_supported'), patch.object(native, '_Darwin', return_value=checker), \
             patch.object(native.os, 'geteuid', return_value=501), \
             patch.object(native.os, 'fstat', side_effect=self.changing(every_pass=False)):
            with self.assertRaisesRegex(native.AdmissionError, '^native_admission_changed$'):
                native.check_retained_descriptor(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11)
            self.assertEqual(checker.check.call_count, 1)

    def test_native_refusal_is_never_retried(self):
        checker = Mock()
        checker.check.side_effect = native.AdmissionError('native_admission_acl')
        with patch.object(native, '_supported'), patch.object(native, '_Darwin', return_value=checker), \
             patch.object(native.os, 'geteuid', return_value=501), \
             patch.object(native.os, 'fstat', return_value=metadata()):
            with self.assertRaisesRegex(native.AdmissionError, '^native_admission_acl$'):
                native.check_retained_descriptor(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11)
            self.assertEqual(checker.check.call_count, 1)

    def test_native_refusal_closes_duplicate_and_not_callers_descriptor(self):
        checker = Mock()
        checker.check.side_effect = native.AdmissionError('native_admission_acl')
        with patch.object(native, '_supported'), patch.object(native, '_Darwin', return_value=checker), \
             patch.object(native.os, 'geteuid', return_value=501), \
             patch.object(native.os, 'dup', return_value=90), patch.object(native.os, 'close') as close, \
             patch.object(native.os, 'fstat', return_value=metadata()):
            with self.assertRaises(native.AdmissionError):
                native.check_descriptor(7, purpose=native.DescriptorPurpose.PRIVATE_FILE, deadline=11)
            close.assert_called_once_with(90)

    def test_protected_data_has_distinct_mode_and_same_native_protection(self):
        purpose = native.DescriptorPurpose.PROTECTED_FILE
        self.check(NativeLibrary(), purpose)
        for library in (NativeLibrary(owner=501), NativeLibrary(fs=b'other'),
                        NativeLibrary(entries=[(1, 1 << 2)])):
            with self.assertRaises(native.AdmissionError):
                self.check(library, purpose)
        with patch.object(native.os, 'fstat') as inspect:
            inspect.return_value = metadata(uid=0, mode=0o444)
            native._metadata(7, purpose)
            inspect.return_value.st_size = 0
            native._metadata(7, purpose)
            for item in (metadata(uid=0, mode=0o555), metadata(uid=501, mode=0o444),
                         metadata(uid=0, mode=0o444, links=2), metadata(uid=0, mode=0o444, directory=True)):
                inspect.return_value = item
                with self.assertRaises(native.AdmissionError):
                    native._metadata(7, purpose)

    def test_metadata_purposes_and_links(self):
        with patch.object(native.os, 'geteuid', return_value=501), patch.object(native.os, 'fstat') as inspect:
            for purpose, data in [(native.DescriptorPurpose.PRIVATE_FILE, metadata()),
                                  (native.DescriptorPurpose.PRIVATE_DIRECTORY, metadata(directory=True)),
                                  (native.DescriptorPurpose.PRIVATE_ANCESTOR, metadata(directory=True, uid=0, mode=0o755)),
                                  (native.DescriptorPurpose.PROTECTED_ANCESTOR, metadata(directory=True, uid=0, mode=0o755)),
                                  (native.DescriptorPurpose.PROTECTED_EXECUTABLE, metadata(uid=0, mode=0o555))]:
                inspect.return_value = data
                native._metadata(7, purpose)
            for data in (metadata(links=2), metadata(mode=0o640), metadata(uid=0), metadata(mode=0o4600)):
                inspect.return_value = data
                with self.assertRaises(native.AdmissionError): native._metadata(7, native.DescriptorPurpose.PRIVATE_FILE)

    def test_prepared_core_files_do_not_expand_protected_limits(self):
        purpose = native.DescriptorPurpose.PREPARED_CORE_FILE
        with patch.object(native.os, 'geteuid', return_value=501), patch.object(native.os, 'fstat') as inspect:
            large = metadata(uid=501, mode=0o755)
            large.st_size = 235 * 1024 * 1024
            inspect.return_value = large
            native._metadata(7, purpose)
            with self.assertRaises(native.AdmissionError):
                native._metadata(7, native.DescriptorPurpose.PROTECTED_EXECUTABLE)
            for item in (metadata(uid=502, mode=0o755), metadata(mode=0o775),
                         metadata(mode=0o4755), metadata(mode=0o755, links=2),
                         metadata(mode=0o755, directory=True)):
                inspect.return_value = item
                with self.subTest(item=item), self.assertRaises(native.AdmissionError):
                    native._metadata(7, purpose)
            large.st_size = 512 * 1024 * 1024 + 1
            inspect.return_value = large
            with self.assertRaises(native.AdmissionError):
                native._metadata(7, purpose)




@unittest.skipUnless(native.sys.platform == 'darwin' and native.platform.machine() == 'arm64'
                     and os.geteuid() != 0, 'native macOS ARM64 ordinary user required')
class NativeDescriptorLocalFiles(unittest.TestCase):
    def test_real_private_descriptors_and_purpose_refusal(self):
        import tempfile
        import time
        # Descriptor checks only: no protected installation, ACL changes or service.
        with tempfile.TemporaryDirectory(prefix='agentmux-descriptor-') as directory:
            os.chmod(directory, 0o700)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                self.assertIs(native.check_descriptor(directory_fd,
                    purpose=native.DescriptorPurpose.PRIVATE_DIRECTORY,
                    deadline=time.monotonic() + 1), True)
                self.assertIs(native.check_descriptor(directory_fd,
                    purpose=native.DescriptorPurpose.PRIVATE_ANCESTOR,
                    deadline=time.monotonic() + 1), True)
                with self.assertRaises(native.AdmissionError):
                    native.check_descriptor(directory_fd, purpose=native.DescriptorPurpose.PRIVATE_FILE,
                                            deadline=time.monotonic() + 1)
                fd = os.open('selection.json', os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC,
                             0o600, dir_fd=directory_fd)
                try:
                    os.write(fd, b'{}')
                    self.assertIs(native.check_descriptor(fd,
                        purpose=native.DescriptorPurpose.PRIVATE_FILE,
                        deadline=time.monotonic() + 1), True)
                    with self.assertRaises(native.AdmissionError):
                        native.check_descriptor(fd, purpose=native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                                                deadline=time.monotonic() + 1)
                    # The checker must never consume its caller's descriptor.
                    self.assertEqual(os.fstat(fd).st_size, 2)
                finally:
                    os.close(fd)
            finally:
                os.close(directory_fd)

    def test_entry_changes_in_a_held_ancestor_are_not_a_policy_change(self):
        import tempfile
        import threading
        import time
        # Unrelated tools add and remove entries in held ancestors such as $HOME.
        # Before stable passes, about 2% of these checks refused as changed.
        with tempfile.TemporaryDirectory(prefix='agentmux-descriptor-') as directory:
            os.chmod(directory, 0o700)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stop = threading.Event()
            def churn():
                while not stop.is_set():
                    path = os.path.join(directory, 'entry')
                    open(path, 'w').close()
                    os.unlink(path)
            worker = threading.Thread(target=churn)
            worker.start()
            try:
                for _ in range(2000):
                    for check, purpose in ((native.check_retained_descriptor, native.DescriptorPurpose.PRIVATE_ANCESTOR),
                                           (native.check_descriptor, native.DescriptorPurpose.PRIVATE_DIRECTORY)):
                        self.assertIs(check(fd, purpose=purpose, deadline=time.monotonic() + 1), True)
                # A real policy change is still refused.
                os.chmod(directory, 0o777)
                with self.assertRaisesRegex(native.AdmissionError, '^native_admission_permissions$'):
                    native.check_retained_descriptor(fd, purpose=native.DescriptorPurpose.PRIVATE_ANCESTOR,
                                                     deadline=time.monotonic() + 1)
            finally:
                stop.set()
                worker.join()
                os.chmod(directory, 0o700)
                os.close(fd)


if __name__ == "__main__": unittest.main()
