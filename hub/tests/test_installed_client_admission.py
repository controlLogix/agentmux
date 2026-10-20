"""Offline installed-client ownership checks; no clients or services are started."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from hub import installed_client_admission as admission


class RetainedInstalledClient(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='installed-client-admission-')
        self.addCleanup(self.directory.cleanup)
        self.base = Path(os.path.realpath(self.directory.name))
        self.file = self.base / 'client-file'
        self.file.write_bytes(b'bounded fixture bytes')
        self.file.chmod(0o555)
        self.owners = admission._Descriptors()
        self.addCleanup(self.owners.close_all)
        self.check_patch = patch('hub.installed_client_admission.native.check_descriptor', return_value=True)
        self.check = self.check_patch.start()
        self.addCleanup(self.check_patch.stop)
        self.deadline = time.monotonic() + 1

    def open_file(self):
        return admission._open_absolute(str(self.file), purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                                        owners=self.owners, deadline=self.deadline)

    def test_no_follow_walk_retains_original_ancestors_and_file(self):
        rows = self.open_file()
        self.assertEqual(rows[-1][0], str(self.file))
        self.assertEqual(len(self.owners.live), len(rows))
        self.assertEqual(os.fstat(rows[-1][1]).st_ino, self.file.stat().st_ino)
        self.assertIs(self.check.call_args_list[-1].kwargs['purpose'],
                      admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE)
        for call in self.check.call_args_list:
            self.assertEqual(call.kwargs['deadline'], self.deadline)
        self.owners.close_all()
        self.assertTrue(self.owners.closed)

    def test_symlink_file_and_ancestor_are_not_followed(self):
        target = self.base / 'target'
        self.file.rename(target)
        self.file.symlink_to(target)
        with self.assertRaises(OSError):
            self.open_file()
        directory_link = self.base / 'linked-directory'
        directory_link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            admission._open_absolute(str(directory_link / 'target'),
                    purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                    owners=self.owners, deadline=self.deadline)

    def test_bounded_hash_keeps_bytes_private_and_refuses_oversize(self):
        import hashlib
        fd = self.open_file()[-1][1]
        digest, identity, raw = admission._read_file(fd,
            purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
            limit=64, deadline=self.deadline)
        self.assertEqual(digest, 'sha256:' + hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertIsNone(raw)
        self.assertEqual(identity, admission._identity(fd))
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_file_invalid$'):
            admission._read_file(fd, purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                                 limit=2, deadline=self.deadline)

    def test_native_refusal_and_expiry_do_not_become_admission(self):
        self.check.side_effect = admission.native.AdmissionError('native_admission_acl')
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_admission_failed$'):
            self.open_file()
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_deadline$'):
            admission._deadline(time.monotonic() - 1)

    def test_declaration_representation_excludes_selection_and_arguments(self):
        value = admission.InstalledClientDeclaration('1.0.0', 'a' * 64, 'claude-desktop',
                    admission.STABLE_FRONTEND, ('mcp', '--selection', '/PRIVATE_SENTINEL'),
                    '/PRIVATE_SENTINEL', 'stdio')
        self.assertNotIn('PRIVATE_SENTINEL', repr(value))

    def test_path_and_read_failures_use_closed_diagnostics(self):
        missing = str(self.base / 'PRIVATE_SENTINEL')
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_path_unavailable$'):
            admission._RetainedPath(missing,
                    purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                    deadline=self.deadline)
        fd = self.open_file()[-1][1]
        with patch('hub.installed_client_admission.os.read', side_effect=OSError('PRIVATE_SENTINEL')):
            with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_file_unavailable$'):
                admission._read_file(fd, purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                                     limit=64, deadline=self.deadline)

    def test_retained_path_refuses_same_bytes_at_a_replacement_inode(self):
        retained = admission._RetainedPath(str(self.file),
                    purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                    deadline=self.deadline)
        try:
            retained.recheck(deadline=self.deadline)
            replacement = self.file.with_name('replacement')
            replacement.write_bytes(self.file.read_bytes())
            replacement.chmod(0o555)
            os.replace(replacement, self.file)
            with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_path_changed$'):
                retained.recheck(deadline=self.deadline)
        finally:
            retained.close()
        self.assertTrue(retained.closed)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_unavailable$'):
            retained.recheck(deadline=self.deadline)

    def test_private_directory_uses_private_ancestor_roles_for_user_paths(self):
        roles = []
        def private_metadata(fd, *, purpose, deadline):
            roles.append(purpose)
            self.assertIn(purpose, (admission.native.DescriptorPurpose.PRIVATE_ANCESTOR,
                                   admission.native.DescriptorPurpose.PRIVATE_DIRECTORY))
            admission.native._metadata(fd, purpose)
            return True
        self.check.side_effect = private_metadata
        retained = admission._RetainedPath(str(self.base),
            purpose=admission.native.DescriptorPurpose.PRIVATE_DIRECTORY, deadline=self.deadline)
        try:
            retained.recheck(deadline=self.deadline)
            self.assertIn(admission.native.DescriptorPurpose.PRIVATE_DIRECTORY, roles)
        finally:
            retained.close()

    def test_native_cleanup_uncertainty_remains_attached_to_retained_owner(self):
        retained = admission._RetainedPath(str(self.file),
                    purpose=admission.native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                    deadline=self.deadline)
        self.check.side_effect = admission.native.AdmissionError('native_admission_cleanup')
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_cleanup_pending$'):
            retained.recheck(deadline=self.deadline)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_cleanup_pending$'):
            retained.close()
        self.assertFalse(retained.closed)
        self.assertFalse(retained._owners.live)

    def test_consumed_close_uncertainty_is_never_retried(self):
        fd = self.open_file()[-1][1]
        real_close = os.close
        calls = []
        def consumed_close(value):
            calls.append(value)
            real_close(value)
            if value == fd:
                raise OSError('private close details')
        with patch('hub.installed_client_admission.os.close', side_effect=consumed_close):
            with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_cleanup_pending$'):
                self.owners.close(fd)
            with self.assertRaises(admission.InstalledClientError):
                self.owners.close_all()
        self.assertEqual(calls.count(fd), 1)
        self.assertFalse(self.owners.closed)
        self.assertNotIn(fd, self.owners.live)
        self.assertIn(fd, self.owners.uncertain)
        # The uncertainty is intentionally retained. Cleanup must not retry it.
        self.owners.uncertain.clear()


class InstalledClientPackage(unittest.TestCase):
    """Synthetic bytes test admission controls, not native Python qualification."""
    @staticmethod
    def native_image(*loads, subtype=0, kind=2):
        import struct
        commands = []
        for command, value in loads:
            offset = 24 if command in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20) else 12
            text = value.encode() + b'\x00'
            length = offset + len(text)
            length += -length % 8
            commands.append(struct.pack('<3I', command, length, offset) + bytes(offset - 12)
                            + text + bytes(length - offset - len(text)))
        body = b''.join(commands)
        return struct.pack('<8I', 0xfeedfacf, 0x100000c, subtype, kind,
                           len(commands), len(body), 0, 0) + body

    @staticmethod
    def fat_image(*images, table_override=None):
        import struct
        offset = 8 + 20 * len(images)
        table = []
        for index, image in enumerate(images):
            cpu, subtype = struct.unpack_from('<2I', image, 4)
            if table_override is not None and index in table_override:
                cpu, subtype = table_override[index]
            table.append(struct.pack('>5I', cpu, subtype, offset, len(image), 0))
            offset += len(image)
        return struct.pack('>2I', 0xcafebabe, len(images)) + b''.join(table) + b''.join(images)

    def setUp(self):
        import hashlib
        import json
        import struct
        self.json, self.hashlib = json, hashlib
        self.directory = tempfile.TemporaryDirectory(prefix='installed-client-package-')
        self.addCleanup(self.directory.cleanup)
        self.base = Path(os.path.realpath(self.directory.name))
        self.clients = self.base / 'clients'
        self.clients.mkdir(mode=0o755)
        self.frontend = self.base / 'frontend'
        self.frontend.write_bytes(b'fixture frontend')
        self.frontend.chmod(0o555)
        self.selection = self.base / 'enrollment.json'
        self.selection.write_text(json.dumps({'schemaVersion': '1.0.0', 'hostPolicy': '/fixture/policy',
            'workspaces': ['/fixture/workspace'], 'instanceId': 'fixture-instance',
            'profileId': 'fixture-profile', 'hubId': 'fixture-hub'}))
        self.selection.chmod(0o600)
        arm_header = self.native_image((0x8000001c, '@executable_path/../lib'),
                                      (0xc, '@rpath/libpython3.14.dylib'), (0xe, '/usr/lib/dyld'))
        self.files = []
        self.payload = {}
        for name in sorted(admission._REQUIRED):
            data = arm_header if name == 'python/bin/python3.14' else (
                struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, 0, 0, 0, 0)
                if name.endswith('.dylib') else b'fixture')
            self.payload[name] = data
            self.files.append({'path': name, 'digest': self.digest(data), 'size': len(data),
                               'mode': 0o555 if name == 'python/bin/python3.14' else 0o444})
        self.metadata = {'schemaVersion': '1.0.0', 'kind': 'ordinary-python-client',
            'foundationInstallationId': 'a' * 64, 'frontendDigest': self.digest(self.frontend.read_bytes()),
            'pythonVersion': '3.14.4', 'interpreter': 'python/bin/python3.14',
            'bootstrap': 'bootstrap.py', 'files': self.files}
        self.raw = json.dumps(self.metadata, separators=(',', ':')).encode()
        self.installation_id = self.digest(self.raw)[7:]
        self.package = self.clients / self.installation_id
        self.package.mkdir(mode=0o755)
        for item in self.files:
            target = self.package / item['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.payload[item['path']])
            target.chmod(item['mode'])
        for directory in self.package.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o755)
        manifest = self.package / 'client-manifest.json'
        manifest.write_bytes(self.raw)
        manifest.chmod(0o444)
        self.patches = [patch.object(admission, 'PROTECTED_CLIENT_BASE', str(self.clients)),
                        patch.object(admission, 'STABLE_FRONTEND', str(self.frontend)),
                        patch('hub.installed_client_admission.native.check_descriptor', return_value=True)]
        for boundary in self.patches:
            boundary.start()
            self.addCleanup(boundary.stop)

    def digest(self, raw):
        return 'sha256:' + self.hashlib.sha256(raw).hexdigest()

    def admit(self):
        return admission.admit_installed_client(self.installation_id, str(self.selection),
                                              deadline=time.monotonic() + 2)

    def test_complete_factory_rechecks_roster_and_returns_fixed_declaration(self):
        owner = self.admit()
        try:
            owner.recheck(deadline=time.monotonic() + 2)
            declaration = owner.declaration
            self.assertEqual(declaration.installation_id, self.installation_id)
            self.assertEqual(declaration.client_id, 'claude-desktop')
            self.assertEqual(declaration.command, str(self.frontend))
            self.assertEqual(declaration.arguments, ('mcp', '--client-installation', self.installation_id,
                                                     '--selection', str(self.selection)))
            self.assertEqual(declaration.transport, 'stdio')
        finally:
            owner.close()
        self.assertTrue(owner.closed)

    def test_manifest_unknown_duplicate_fields_and_invalid_rosters_refuse(self):
        import copy
        invalid = []
        wrong = copy.deepcopy(self.metadata)
        wrong['unreviewed'] = True
        invalid.append(self.json.dumps(wrong).encode())
        invalid.append(self.raw[:-1] + b',"kind":"ordinary-python-client"}')
        for change in (lambda value: value['files'].reverse(),
                       lambda value: value['files'][0].update(mode=True),
                       lambda value: value['files'][0].update(size=-1),
                       lambda value: value['files'][0].update(path='app/../outside'),
                       lambda value: value.update(pythonVersion='3.14.5'),
                       lambda value: value['files'].pop()):
            wrong = copy.deepcopy(self.metadata)
            change(wrong)
            invalid.append(self.json.dumps(wrong).encode())
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_manifest_invalid$'):
                    admission._decode_manifest(raw)

    def manifest_with_directory_count(self, count):
        import posixpath
        directories = set()
        for item in self.files:
            parent = posixpath.dirname(item['path'])
            while parent:
                directories.add(parent)
                parent = posixpath.dirname(parent)
        extras = [{'path': f'app/boundary-{index:04d}/file.py',
                   'digest': self.digest(b''), 'size': 0, 'mode': 0o444}
                  for index in range(count - len(directories))]
        metadata = dict(self.metadata, files=sorted(self.files + extras, key=lambda item: item['path']))
        return self.json.dumps(metadata, separators=(',', ':')).encode()

    def test_manifest_accepts_1024_non_root_directories_and_keeps_root_sentinel(self):
        raw = self.manifest_with_directory_count(1024)
        _, _, directories = admission._decode_manifest(raw)
        self.assertIn('', directories)
        self.assertEqual(len(directories) - 1, 1024)

    def test_manifest_rejects_1025_non_root_directories(self):
        raw = self.manifest_with_directory_count(1025)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_manifest_invalid$'):
            admission._decode_manifest(raw)

    def test_roster_mutation_extra_file_and_symlink_refuse(self):
        owner = self.admit()
        extra = self.package / 'app/extra.py'
        try:
            extra.write_bytes(b'extra')
            extra.chmod(0o444)
            with self.assertRaises(admission.InstalledClientError):
                owner.recheck(deadline=time.monotonic() + 2)
            extra.unlink()
            target = self.package / 'app/hub/cli.py'
            target.chmod(0o644)
            target.write_bytes(b'changed')
            target.chmod(0o444)
            with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_file_changed$'):
                owner.recheck(deadline=time.monotonic() + 2)
            target.unlink()
            target.symlink_to(self.selection)
            with self.assertRaises(admission.InstalledClientError):
                owner.recheck(deadline=time.monotonic() + 2)
        finally:
            owner.close()

    def test_frontend_digest_manifest_identity_and_native_architecture_refuse(self):
        self.frontend.chmod(0o755)
        self.frontend.write_bytes(b'changed frontend')
        self.frontend.chmod(0o555)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_frontend_changed$'):
            self.admit()
        manifest = self.package / 'client-manifest.json'
        manifest.chmod(0o644)
        manifest.write_bytes(self.raw + b' ')
        manifest.chmod(0o444)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_manifest_changed$'):
            self.admit()
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_image_invalid$'):
            admission._native_libraries('python/bin/python3.14', b'not native', self.payload)
        import struct
        x86 = struct.pack('<8I', 0xfeedfacf, 0x1000007, 0, 2, 0, 0, 0, 0)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_architecture_invalid$'):
            admission._native_libraries('python/bin/python3.14', x86, self.payload)

    def test_native_library_references_stay_inside_roster_or_system_paths(self):
        import struct
        def image(command, value):
            return self.native_image((0x8000001c, '@executable_path/../lib'), (command, value))
        for library in ('/usr/lib/libSystem.B.dylib', '@rpath/libpython3.14.dylib'):
            admission._native_libraries('python/bin/python3.14', image(0xc, library), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_library_outside_package$'):
            admission._native_libraries('python/bin/python3.14', image(0xc, '/private/other/lib.dylib'), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_library_path_invalid$'):
            admission._native_libraries('python/bin/python3.14', image(0x8000001c, '/private/other'), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_loader_invalid$'):
            admission._native_libraries('python/bin/python3.14', image(0xe, '/private/loader'), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_loader_invalid$'):
            admission._native_libraries('python/bin/python3.14', image(0xe, '/usr/lib/dyld\x00other'), self.payload)
        admission._native_libraries('python/bin/python3.14', image(0xe, '/usr/lib/dyld'), self.payload)
        data = image(0xc, '/usr/lib/libSystem.B.dylib')
        with patch('hub.installed_client_admission.time.monotonic', side_effect=[10, 12]):
            with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_deadline$'):
                admission._native_libraries('app/optional-image', data, self.payload, deadline=11)
        oversized_commands = (struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 4097, 4097 * 8, 0, 0)
                              + struct.pack('<2I', 0, 8) * 4097)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_image_invalid$'):
            admission._native_libraries('python/bin/python3.14', oversized_commands, self.payload)

    def test_selection_cleanup_owner_survives_combined_cleanup_failures(self):
        from hub.client_launch_selection import SelectionError
        selection_cleanup, path_cleanup = object(), object()
        real_close = admission._RetainedPath.close
        def close(value):
            real_close(value)
            if value._path == str(self.selection):
                raise admission.InstalledClientError('installed_client_cleanup_pending', cleanup=path_cleanup)
        with patch('hub.client_launch_selection.load_selection',
                   side_effect=SelectionError('selection_cleanup_pending', cleanup=selection_cleanup)):
            with patch.object(admission._RetainedPath, 'close', close):
                with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_cleanup_pending$') as caught:
                    self.admit()
        self.assertIn(selection_cleanup, caught.exception.cleanup)
        self.assertIn(path_cleanup, caught.exception.cleanup)

    def test_native_environment_and_lazy_library_loads_refuse_unsafe_paths(self):
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_loader_environment_denied$'):
            admission._native_libraries('python/bin/python3.14',
                    self.native_image((0x27, 'DYLD_LIBRARY_PATH=/private/other')), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_library_outside_package$'):
            admission._native_libraries('python/bin/python3.14',
                    self.native_image((0x20, '/private/other/lazy.dylib')), self.payload)

    def test_fat_slices_reject_unqualified_subtypes_and_header_mismatch(self):
        generic = self.native_image((0xc, '/usr/lib/libSystem.B.dylib'), kind=6)
        unqualified = self.native_image((0xc, '/private/other/lib.dylib'), subtype=1, kind=6)
        benign_unqualified = self.native_image((0xc, '/usr/lib/libSystem.B.dylib'), subtype=1, kind=6)
        unsafe_generic = self.native_image((0xc, '/private/other/lib.dylib'), kind=6)
        for images in ((unqualified, generic), (generic, unqualified), (benign_unqualified, unsafe_generic)):
            with self.subTest(first_subtype=images[0][8]):
                with self.assertRaisesRegex(admission.InstalledClientError,
                                           '^installed_client_native_architecture_invalid$'):
                    admission._native_libraries('site-packages/fixture.so', self.fat_image(*images), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_architecture_invalid$'):
            admission._native_libraries('site-packages/fixture.so',
                self.fat_image(unqualified, table_override={0: (0x100000c, 0)}), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_image_invalid$'):
            admission._native_libraries('site-packages/fixture.so', self.fat_image(generic, generic), self.payload)
        # A wheel may carry another CPU's slice alongside its sole generic ARM64 slice.
        import struct
        other_cpu = bytearray(generic)
        struct.pack_into('<I', other_cpu, 4, 0x1000007)
        admission._native_libraries('site-packages/fixture.so',
                                   self.fat_image(bytes(other_cpu), generic), self.payload)
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_architecture_invalid$'):
            admission._native_libraries('site-packages/fixture.so',
                self.fat_image(bytes(other_cpu), generic, table_override={0: (0x1000007, 1)}), self.payload)

    def test_library_context_comes_from_actual_interpreter_rpaths(self):
        interpreter = self.native_image((0x8000001c, '@executable_path/../lib'),
                                        (0xc, '@rpath/libpython3.14.dylib'))
        extension = self.native_image((0xc, '@rpath/libpython3.14.dylib'), kind=6)
        files = {'python/bin/python3.14': interpreter, 'site-packages/fixture.so': extension}
        deadline = time.monotonic() + 1
        admission._native_payload(files, self.payload, deadline=deadline)
        # An interpreter with an unresolved @rpath load cannot borrow a default.
        files['python/bin/python3.14'] = self.native_image((0xc, '@rpath/libpython3.14.dylib'))
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_library_outside_package$'):
            admission._native_payload(files, self.payload, deadline=deadline)
        # A valid interpreter without rpaths cannot invent a path for extensions.
        files['python/bin/python3.14'] = self.native_image((0xc, '/usr/lib/libSystem.B.dylib'))
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_library_outside_package$'):
            admission._native_payload(files, self.payload, deadline=deadline)

    def test_malformed_optional_native_image_is_not_treated_as_plain_data(self):
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_image_invalid$'):
            admission._native_libraries('app/optional-image', b'\xcf\xfa\xed\xfe', self.payload)

    def test_structural_native_commands_match_go_rejection_boundaries(self):
        import struct
        def image(*commands, data=b''):
            body = b''.join(commands)
            return struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6,
                               len(commands), len(body), 0, 0) + body + data
        malformed = [image(struct.pack('<2I', command, 8))
                     for command in (1, 0x19, 2, 0xb, 0xc, 0x8000001c)]
        # A segment's declared section must fit in its command.
        malformed.append(image(struct.pack('<II16sQQQQIIII', 0x19, 72, bytes(16),
                                          0, 0, 0, 0, 0, 0, 1, 0)))
        # Symbol and relocation ranges must exist in this particular image.
        malformed.append(image(struct.pack('<6I', 2, 24, 9999, 1, 0, 0)))
        segment = struct.pack('<II16sQQQQIIII', 0x19, 152, bytes(16), 0, 0, 0, 0, 0, 0, 1, 0)
        section = bytearray(80)
        struct.pack_into('<2I', section, 56, 9999, 1)
        malformed.append(image(segment + section))
        malformed.append(image(struct.pack('<20I', 0xb, 80, *([0] * 18))))
        for data in malformed:
            with self.subTest(command=data[32:36].hex()):
                with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_image_invalid$'):
                    admission._native_libraries('site-packages/fixture.so', data, self.payload)
        valid_segment = struct.pack('<II16sQQQQIIII', 0x19, 72, bytes(16), 0, 0, 0, 0, 0, 0, 0, 0)
        admission._native_libraries('site-packages/fixture.so', image(valid_segment), self.payload)
        symbols = bytes(16) + b'\x00'
        symtab = struct.pack('<6I', 2, 24, 56, 1, 72, 1)
        admission._native_libraries('site-packages/fixture.so', image(symtab, data=symbols), self.payload)
        invalid_name = struct.pack('<I', 1) + symbols[4:]
        with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_native_image_invalid$'):
            admission._native_libraries('site-packages/fixture.so', image(symtab, data=invalid_name), self.payload)

    def test_replaced_enrollment_selection_refuses_recheck(self):
        owner = self.admit()
        try:
            replacement = self.selection.with_name('replacement-selection')
            replacement.write_bytes(self.selection.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, self.selection)
            with self.assertRaisesRegex(admission.InstalledClientError, '^installed_client_path_changed$'):
                owner.recheck(deadline=time.monotonic() + 2)
        finally:
            owner.close()

    def test_desktop_settings_composition_retains_admission_through_receipt_write(self):
        from dashboard.resource_settings import desktop_registration
        import threading
        settings = self.base / 'desktop'
        settings.mkdir(mode=0o700)
        configuration = settings / 'config.json'
        before = {'theme': 'dark', 'mcpServers': {'unrelated': {'env': {'TOKEN': 'PRIVATE_SENTINEL'}}}}
        configuration.write_text(self.json.dumps(before))
        configuration.chmod(0o600)
        owner = self.admit()
        try:
            with desktop_registration(str(configuration), admission=owner,
                                      deadline=time.monotonic() + 2) as publication:
                ownership = publication.edit.ownership
                probe = []
                def attempt_lock():
                    acquired = owner._lock.acquire(blocking=False)
                    probe.append(acquired)
                    if acquired:
                        owner._lock.release()
                thread = threading.Thread(target=attempt_lock)
                thread.start()
                thread.join(timeout=1)
                self.assertFalse(thread.is_alive())
                self.assertEqual(probe, [False])
                # Cooperating settings writers remain excluded through persistence.
                import fcntl
                competing = os.open(settings, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(competing)
                # The trusted setup caller persists its complete private record
                # before leaving the publication context. This is a disposable file.
                receipt = self.json.dumps({'installation_id': ownership.installation_id,
                    'configuration_path': ownership.configuration_path,
                    'entry': self.json.loads(ownership.entry_json),
                    'created_container': ownership.created_container}).encode()
                fd = os.open(settings / 'receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, receipt)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(publication._directory_owner.fd)
                self.assertEqual(os.fstat(publication._fd).st_ino, configuration.stat().st_ino)
                self.assertNotIn('PRIVATE_SENTINEL', repr(publication))
            self.assertIsNone(publication._fd)
            self.assertIsNone(publication._original_fd)
            self.assertIsNone(publication._directory_owner)
            self.assertIsNone(publication._lock_fd)
            with desktop_registration(str(configuration), admission=owner, owned=ownership,
                                      remove=True, deadline=time.monotonic() + 2) as removed:
                self.assertIsNone(removed.edit.ownership)
            self.assertEqual(self.json.loads(configuration.read_bytes()), before)
        finally:
            owner.close()

    def test_desktop_settings_refuses_serialized_declaration_and_wrong_profile_removal(self):
        from dashboard.resource_settings import desktop_registration
        from dashboard.resource_registration import RegistrationConflict
        settings = self.base / 'desktop'
        settings.mkdir(mode=0o700)
        configuration = settings / 'config.json'
        configuration.write_bytes(b'{}')
        configuration.chmod(0o600)
        owner = self.admit()
        other = None
        try:
            with self.assertRaisesRegex(RegistrationConflict, '^settings_application_admission_required$'):
                with desktop_registration(str(configuration), admission=owner.declaration):
                    self.fail('Serialized declarations do not carry admission.')
            self.assertEqual(configuration.read_bytes(), b'{}')
            with desktop_registration(str(configuration), admission=owner,
                                      deadline=time.monotonic() + 2) as publication:
                ownership = publication.edit.ownership
            existing = configuration.read_bytes()
            another = self.selection.with_name('another-selection.json')
            another.write_bytes(self.selection.read_bytes())
            another.chmod(0o600)
            other = admission.admit_installed_client(self.installation_id, str(another),
                                                    deadline=time.monotonic() + 2)
            with self.assertRaisesRegex(RegistrationConflict, '^settings_registration_declaration_mismatch$'):
                with desktop_registration(str(configuration), admission=other, owned=ownership,
                                          remove=True, deadline=time.monotonic() + 2):
                    self.fail('A different enrollment selection must not remove this entry.')
            self.assertEqual(configuration.read_bytes(), existing)
        finally:
            owner.close()
            if other is not None:
                other.close()

    def test_desktop_settings_receipt_failure_retains_exact_recovery_owner(self):
        from dashboard.resource_settings import desktop_registration, SettingsPublicationError
        settings = self.base / 'desktop'
        settings.mkdir(mode=0o700)
        configuration = settings / 'config.json'
        configuration.write_bytes(b'{"unrelated":true}')
        configuration.chmod(0o600)
        owner = self.admit()
        try:
            with self.assertRaisesRegex(SettingsPublicationError, '^settings_receipt_pending$') as caught:
                with desktop_registration(str(configuration), admission=owner,
                                          deadline=time.monotonic() + 2):
                    raise OSError('PRIVATE_SENTINEL receipt failure')
            recovery = caught.exception.recovery
            try:
                self.assertEqual(os.fstat(recovery._fd).st_ino, configuration.stat().st_ino)
                self.assertIsNotNone(recovery._directory_owner)
                self.assertIs(recovery._admission, owner)
                self.assertTrue(self.json.loads(configuration.read_bytes())['unrelated'])
                self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
            finally:
                recovery.close()
        finally:
            owner.close()

    def test_desktop_settings_detects_external_replacement_during_receipt_write(self):
        from dashboard.resource_settings import desktop_registration, SettingsPublicationError
        settings = self.base / 'desktop'
        settings.mkdir(mode=0o700)
        configuration = settings / 'config.json'
        configuration.write_bytes(b'{"unrelated":true}')
        configuration.chmod(0o600)
        owner = self.admit()
        try:
            with self.assertRaisesRegex(SettingsPublicationError, '^settings_publication_uncertain$') as caught:
                with desktop_registration(str(configuration), admission=owner,
                                          deadline=time.monotonic() + 2) as publication:
                    replacement = settings / 'external-replacement'
                    replacement.write_bytes(configuration.read_bytes())
                    replacement.chmod(0o600)
                    os.replace(replacement, configuration)
            try:
                self.assertNotEqual(os.fstat(publication._fd).st_ino, configuration.stat().st_ino)
                self.assertIs(caught.exception.recovery, publication)
                self.assertIsNotNone(publication._lock_fd)
            finally:
                caught.exception.recovery.close()
        finally:
            owner.close()

    def test_desktop_settings_cleanup_interruption_consumes_once_and_releases_lock(self):
        from dashboard.resource_settings import desktop_registration, SettingsPublicationError
        import fcntl
        settings = self.base / 'desktop'
        settings.mkdir(mode=0o700)
        configuration = settings / 'config.json'
        configuration.write_bytes(b'{}')
        configuration.chmod(0o600)
        owner = self.admit()
        real_close, calls, target = os.close, [], [None]
        def interrupted_close(fd):
            calls.append(fd)
            real_close(fd)
            if fd == target[0]:
                raise KeyboardInterrupt
        try:
            with patch('dashboard.resource_settings.os.close', side_effect=interrupted_close):
                with self.assertRaisesRegex(SettingsPublicationError, '^settings_cleanup_pending$') as caught:
                    with desktop_registration(str(configuration), admission=owner,
                                              deadline=time.monotonic() + 2) as publication:
                        target[0] = publication._fd
                        calls.clear()
            self.assertIs(caught.exception.recovery, publication)
            self.assertTrue(publication.cleanup_pending)
            self.assertEqual(calls.count(target[0]), 1)
            self.assertIsNone(publication._fd)
            self.assertIsNone(publication._original_fd)
            self.assertIsNone(publication._lock_fd)
            self.assertIsNone(publication._directory_owner)
            competing = os.open(settings, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(competing, fcntl.LOCK_UN)
            finally:
                os.close(competing)
            with self.assertRaisesRegex(SettingsPublicationError, '^settings_cleanup_pending$'):
                publication.close()
        finally:
            owner.close()


if __name__ == '__main__':
    unittest.main()
