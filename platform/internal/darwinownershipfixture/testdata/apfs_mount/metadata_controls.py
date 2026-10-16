"""Pure metadata controls. All host/device/native operations below use substitutes."""
import ast
import hashlib
import os
import plistlib
import stat
import types
import unittest
from unittest import mock

BASE = os.path.dirname(__file__) + '/'
PINS = {'setup.py': 'f96072677c2dbcf89dbb4aef6b901538d93f281ee9288fa922e81d813d8c3abc',
        'teardown.py': '116e87a1abd76ec66c057d108dfab58dc194dd0d593d8c51dbfd20c096229d35'}


def load(name):
    fd = os.open(BASE + name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
        assert before.st_nlink == 1 and not before.st_mode & 0o022
        parts, size = [], 0
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            size += len(part)
            assert size <= 262144
            parts.append(part)
        raw = b''.join(parts)
        after = os.fstat(fd)
        assert all(getattr(before, k) == getattr(after, k) for k in
                   ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                    'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        assert len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == PINS[name]
    finally:
        os.close(fd)
    module = types.ModuleType('pure_metadata_' + name)
    exec(compile(raw, '<held-metadata-candidate>', 'exec'), module.__dict__)
    return module.__dict__, raw


class MetadataControls(unittest.TestCase):
    def setUp(self):
        self.modules = [load(name) for name in PINS]

    def mapping(self, m, label='owners'):
        return {'/dev/disk99': {'hint': 'GUID_partition_scheme', 'mountpoint': ''},
                '/dev/disk100s1': {'hint': 'Apple_APFS_Volume',
                                    'mountpoint': m['ROOT'] + '/' + label}}

    def test_native_helpers_are_identical_in_pair(self):
        def body(raw):
            return {v.name: ast.dump(v, include_attributes=False) for v in ast.parse(raw).body
                    if isinstance(v, (ast.FunctionDef, ast.ClassDef)) and
                    (v.name.startswith('metadata_') or v.name.startswith('partial_v2_') or
                     v.name in ('Timespec', 'NativeStat', 'NativeMount'))}
        self.assertEqual(body(self.modules[0][1]), body(self.modules[1][1]))

    def test_dynamic_mount_policy_and_owner_flags(self):
        for m, _ in self.modules:
            for label in ('owners', 'noowners'):
                value = {'fsid': [12345, 88], 'owner': 0,
                         'flags': 0x1000 | (0x200000 if label == 'noowners' else 0),
                         'type': 'apfs', 'source': '/dev/disk100s1',
                         'mountpoint': m['ROOT'] + '/' + label}
                with mock.patch.dict(m, metadata_native_mount=mock.Mock(return_value=value),
                                     partial_v2_acl_absent=mock.Mock()):
                    self.assertEqual(m['metadata_mount'](None, 11, label, self.mapping(m, label)), value)
                    for key, wrong in (('owner', 501), ('fsid', [0, 0]), ('type', 'hfs'),
                                       ('source', '/dev/disk101s1'), ('mountpoint', '/wrong'),
                                       ('flags', value['flags'] ^ 0x200000), ('flags', 0)):
                        changed = dict(value, **{key: wrong})
                        m['metadata_native_mount'].return_value = changed
                        with self.assertRaises(m['FixtureFailure']):
                            m['metadata_mount'](None, 11, label, self.mapping(m, label))

    def test_no_device_opens_dynamic_relative_metadata(self):
        for m, _ in self.modules:
            mapping = self.mapping(m)
            def node(path, *, dir_fd, follow_symlinks):
                self.assertEqual(dir_fd, 10)
                self.assertFalse(follow_symlinks)
                self.assertIn('/dev/' + path, mapping)
                return types.SimpleNamespace(st_mode=stat.S_IFBLK | 0o640, st_uid=0, st_gid=5,
                                             st_nlink=1, st_dev=222, st_ino=333, st_rdev=555)
            with mock.patch.object(m['os'], 'stat', side_effect=node), \
                    mock.patch.object(m['os'], 'fstat', return_value=types.SimpleNamespace(st_dev=555)), \
                    mock.patch.object(m['os'], 'open', side_effect=AssertionError('device_open_forbidden')):
                result = m['metadata_nodes'](10, mapping, '/dev/disk100s1', 11)
                self.assertEqual(set(result), set(mapping))

    def test_wrong_type_symlink_rdev_or_owner_refuse(self):
        for m, _ in self.modules:
            for field, wrong in (('st_mode', stat.S_IFREG | 0o640),
                                 ('st_mode', stat.S_IFLNK | 0o777),
                                 ('st_rdev', 999), ('st_uid', 501), ('st_nlink', 2)):
                value = dict(st_mode=stat.S_IFBLK | 0o640, st_uid=0, st_gid=5,
                             st_nlink=1, st_dev=222, st_ino=333, st_rdev=555)
                value[field] = wrong
                with mock.patch.object(m['os'], 'stat', return_value=types.SimpleNamespace(**value)), \
                        mock.patch.object(m['os'], 'fstat', return_value=types.SimpleNamespace(st_dev=555)):
                    with self.assertRaises(m['FixtureFailure']):
                        m['metadata_nodes'](10, self.mapping(m), '/dev/disk100s1', 11)

    def test_map_traversal_extra_mount_and_wrong_guid_refuse(self):
        for m, _ in self.modules:
            for change in ('traversal', 'mount', 'guid'):
                value = self.mapping(m)
                if change == 'traversal':
                    value['/dev/../disk1'] = value.pop('/dev/disk99')
                elif change == 'mount':
                    value['/dev/disk99']['mountpoint'] = '/wrong'
                else:
                    value['/dev/disk99']['hint'] = 'wrong'
                with self.assertRaises(m['FixtureFailure']):
                    m['metadata_map']('owners', value)

    def test_dev_directory_replacement_and_devfs_policy_refuse(self):
        for m, _ in self.modules:
            directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o555, st_uid=0, st_gid=0,
                                              st_dev=99, st_ino=100, st_nlink=1)
            replaced = types.SimpleNamespace(**dict(vars(directory), st_ino=101))
            with mock.patch.object(m['os'], 'fstat', return_value=directory), \
                    mock.patch.object(m['os'], 'stat', return_value=replaced):
                with self.assertRaises(m['FixtureFailure']):
                    m['metadata_devfs'](None, 10)
            value = {'fsid': [99, 19], 'owner': 0, 'flags': 0x1000,
                     'type': 'devfs', 'mountpoint': '/dev', 'source': 'devfs'}
            with mock.patch.object(m['os'], 'fstat', return_value=directory), \
                    mock.patch.object(m['os'], 'stat', return_value=directory), \
                    mock.patch.dict(m, metadata_native_mount=mock.Mock(return_value=value),
                                    partial_v2_acl_absent=mock.Mock()):
                m['metadata_devfs'](None, 10)
                for key, wrong in (('type', 'apfs'), ('source', '/wrong'), ('owner', 501),
                                   ('mountpoint', '/wrong'), ('flags', 0), ('fsid', [0, 0])):
                    m['metadata_native_mount'].return_value = dict(value, **{key: wrong})
                    with self.assertRaises(m['FixtureFailure']):
                        m['metadata_devfs'](None, 10)

    def test_close_error_continues_consumes_once(self):
        for m, _ in self.modules:
            m['owned'][:] = [10, 11, 12]
            with mock.patch.object(m['os'], 'close', side_effect=[OSError(5, 'pure'), None]) as close:
                with self.assertRaises(m['FixtureFailure']):
                    m['metadata_close_selected']((10, 11))
                self.assertEqual([v.args[0] for v in close.call_args_list], [10, 11])
                self.assertEqual(m['owned'], [12])

    def test_receipt_unknown_types_and_duplicate_keys_refuse(self):
        for m, _ in self.modules:
            self.assertFalse(m['metadata_equal']({'flags': 1}, {'flags': True}))
            with self.assertRaises(m['FixtureFailure']):
                m['metadata_json_pairs']([('mountPolicy', {}), ('mountPolicy', {})])

    def test_prior_partial_absence_positive_and_refusals(self):
        m = self.modules[0][0]
        for images, allowed in (([], True),
                                ([{'image-path': m['PRIOR_PARTIAL_IMAGE']}], False),
                                ([{'other': 'unknown'}], False)):
            command = mock.Mock(return_value=plistlib.dumps({'images': images}))
            with mock.patch.dict(m, hold=mock.Mock(return_value=21),
                                 partial_v2_acl_absent=mock.Mock(),
                                 prior_partial_identity=mock.Mock(return_value=(1, 2)),
                                 metadata_close_selected=mock.Mock(), command=command):
                if allowed:
                    result = m['prior_partial_absent'](None, 10, 'owners')
                    self.assertTrue(result['imageAbsent'])
                    m['metadata_close_selected'].assert_called_once_with((21,))
                else:
                    with self.assertRaises(m['FixtureFailure']):
                        m['prior_partial_absent'](None, 10, 'owners')
                command.assert_called_once_with(10, 'owners-prior-partial-absence', ['info', '-plist'])

    def test_prior_partial_image_metadata_only_and_changed_inode_refusal(self):
        m = self.modules[0][0]
        parent = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o711, st_dev=16777234,
                                       st_ino=2395883, st_uid=0, st_gid=0)
        image = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=16777234,
                                      st_ino=2395887, st_uid=0, st_gid=0,
                                      st_nlink=1, st_size=134217728)
        def metadata(path, *, dir_fd=None, follow_symlinks=True):
            self.assertFalse(follow_symlinks)
            if dir_fd is None:
                self.assertEqual(path, m['PRIOR_PARTIAL_ROOT'])
                return parent
            self.assertEqual((path, dir_fd), ('owners.dmg', 21))
            return image
        with mock.patch.object(m['os'], 'fstat', return_value=parent), \
                mock.patch.object(m['os'], 'stat', side_effect=metadata), \
                mock.patch.object(m['os'], 'open', side_effect=AssertionError('image_open_forbidden')):
            m['prior_partial_identity'](21)
            image.st_ino += 1
            with self.assertRaises(m['FixtureFailure']):
                m['prior_partial_identity'](21)

    def test_failed_prior_gate_precedes_any_image_creation(self):
        m = self.modules[0][0]
        with mock.patch.dict(m, partial_v2_native_library=mock.Mock(), mutate=mock.Mock(),
                             hold=mock.Mock(return_value=10),
                             identity=mock.Mock(return_value={'uid': 0, 'mode': 0o711, 'dev': 1}),
                             prior_partial_absent=mock.Mock(side_effect=m['FixtureFailure']('pure', ())),
                             command=mock.Mock()):
            with self.assertRaises(m['FixtureFailure']):
                m['setup']()
            m['command'].assert_not_called()

    def control_probe(self, m, label, uid, kind=stat.S_IFREG, expected=None, parent_uid=None):
        policy = {'type': 'apfs', 'owner': 0, 'flags': 0x1000 |
                  (0x200000 if label == 'noowners' else 0),
                  'mountpoint': m['ROOT'] + '/' + label}
        common = dict(st_dev=123, st_gid=20, st_uid=uid, st_nlink=1, st_flags=0)
        parent = types.SimpleNamespace(**dict(common, st_mode=stat.S_IFDIR | 0o700, st_ino=2,
                                               st_uid=uid if parent_uid is None else parent_uid))
        control = types.SimpleNamespace(**dict(common, st_mode=kind | 0o600, st_ino=3, st_size=0))
        def hold(path, flags, *, dir_fd):
            self.assertEqual((path, dir_fd), ('control', 11))
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR))
            return 21
        with mock.patch.dict(m, hold=hold, metadata_native_mount=mock.Mock(return_value=policy),
                             partial_v2_acl_absent=mock.Mock()), \
                mock.patch.object(m['os'], 'geteuid', return_value=0), \
                mock.patch.object(m['os'], 'getuid', return_value=0), \
                mock.patch.object(m['os'], 'fstat', side_effect=lambda fd: parent if fd == 11 else control), \
                mock.patch.object(m['os'], 'open', side_effect=AssertionError('no_real_open')):
            return m['metadata_control'](None, 11, label, expected)

    def test_root_control_uid_is_mount_context_specific(self):
        for m, _ in self.modules:
            self.assertEqual(self.control_probe(m, 'owners', 501), 21)
            self.assertEqual(self.control_probe(m, 'noowners', 99, parent_uid=0), 21)
            self.assertEqual(self.control_probe(m, 'noowners', 99, parent_uid=0,
                expected={'dev': 123, 'ino': 3, 'uid': 99, 'mode': 0o600, 'nlink': 1}), 21)
            for label, parent_uid, control_uid, stage in (
                    ('owners', 0, 501, 'metadata_mount_directory_policy'),
                    ('owners', 501, 0, 'metadata_control_policy'),
                    ('noowners', 501, 99, 'metadata_mount_directory_policy'),
                    ('noowners', 99, 99, 'metadata_mount_directory_policy'),
                    ('noowners', 0, 0, 'metadata_control_policy'),
                    ('noowners', 0, 501, 'metadata_control_policy')):
                with self.assertRaisesRegex(m['FixtureFailure'], stage):
                    self.control_probe(m, label, control_uid, parent_uid=parent_uid)

    def test_control_fifo_nonblocking_open_then_type_refusal(self):
        for m, _ in self.modules:
            for label, uid in (('owners', 501), ('noowners', 99)):
                with self.assertRaisesRegex(m['FixtureFailure'], 'metadata_control_policy'):
                    self.control_probe(m, label, uid, stat.S_IFIFO,
                                       parent_uid=0 if label == 'noowners' else 501)

    def test_regular_control_replacement_inode_refuses(self):
        for m, _ in self.modules:
            with self.assertRaisesRegex(m['FixtureFailure'], 'metadata_control_identity_changed'):
                self.control_probe(m, 'owners', 501, expected={
                    'dev': 123, 'ino': 999, 'uid': 501, 'mode': 0o600, 'nlink': 1})

    def test_every_control_call_binds_label_and_expected_identity(self):
        counts = []
        for m, raw in self.modules:
            calls = [node for node in ast.walk(ast.parse(raw))
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                     and node.func.id == 'metadata_control']
            counts.append(len(calls))
            for call in calls:
                self.assertEqual(len(call.args), 4)
                self.assertEqual(call.keywords, [])
                self.assertEqual(ast.dump(call.args[2]), ast.dump(ast.Name(id='label', ctx=ast.Load())))
                # Execute this exact call expression with closed substitutes.
                expected = {'dev': 123, 'ino': 3, 'uid': 501, 'mode': 0o600, 'nlink': 1}
                def control(lib, mountedfd, label, actual_expected=None):
                    self.assertEqual((lib, mountedfd, label), ('native', 11, 'owners'))
                    self.assertIs(actual_expected, expected)
                    return 21
                expression = ast.Expression(body=call)
                namespace = {'metadata_control': control, 'lib': 'native', 'mountedfd': 11,
                             'label': 'owners', 'record': {'controlIdentity': expected},
                             'identity': lambda fd: expected, 'controlfd': 20}
                self.assertEqual(eval(compile(expression, '<actual-control-call>', 'eval'), namespace), 21)
            self.assertEqual(self.control_probe(m, 'owners', 501, expected={
                'dev': 123, 'ino': 3, 'uid': 501, 'mode': 0o600, 'nlink': 1}), 21)
        self.assertEqual(counts, [1, 2])


class FailureReportingControls(unittest.TestCase):
    def setUp(self):
        self.modules = [load(name)[0] for name in PINS]


    def test_composed_uid99_refusals_report_exact_native_policy_stage(self):
        for m in self.modules:
            self.assertEqual(MetadataControls.control_probe(self, m, 'noowners', 99, parent_uid=0), 21)
            for label, parent_uid, control_uid, stage in (
                    ('owners', 0, 501, 'metadata_mount_directory_policy'),
                    ('owners', 501, 0, 'metadata_control_policy'),
                    ('noowners', 501, 99, 'metadata_mount_directory_policy'),
                    ('noowners', 99, 99, 'metadata_mount_directory_policy'),
                    ('noowners', 0, 0, 'metadata_control_policy'),
                    ('noowners', 0, 501, 'metadata_control_policy')):
                try:
                    MetadataControls.control_probe(self, m, label, control_uid, parent_uid=parent_uid)
                except m['FixtureFailure'] as error:
                    self.assertEqual(m['safe_causes'](error)['code'], stage)
                else:
                    self.fail('UID policy refusal disappeared in serializer composition')

    def test_nested_original_and_close_causes_numeric_only(self):
        for m in self.modules:
            error = m['FixtureFailure']('fixture_operation_failed', (
                m['FixtureFailure']('metadata_setup_policy_changed', (OSError(13, 'SECRET', '/SECRET'),)),
                m['FixtureFailure']('owned_descriptor_cleanup_failed', (OSError(5, 'SECRET'),))))
            result = m['safe_causes'](error)
            self.assertEqual(result['causes'][0]['causes'][0]['errno'], 13)
            self.assertEqual(result['causes'][1]['causes'][0]['errno'], 5)
            self.assertNotIn('SECRET', m['json'].dumps(result))

    def test_cycle_depth_and_node_limits(self):
        for m in self.modules:
            failure = m['FixtureFailure']('fixture_operation_failed', ())
            failure.causes = (failure,)
            self.assertEqual(m['safe_causes'](failure)['causes'], [{'kind': 'cycle'}])
            for _ in range(8):
                failure = m['FixtureFailure']('fixture_operation_failed', (failure,))
            result = m['safe_causes'](failure)
            for _ in range(5):
                result = result['causes'][0]
            self.assertEqual(result, {'kind': 'depth_limit'})
            result = m['safe_causes'](m['FixtureFailure']('fixture_operation_failed', tuple(OSError(5, 'x') for _ in range(40))))
            self.assertEqual(len(result['causes']), 23)
            self.assertTrue(result['truncated'])

    def test_exact_fixed_messages_and_unknowns(self):
        for m in self.modules:
            for message, code in m['SAFE_MESSAGE_CODES'].items():
                self.assertIn(code, m['SAFE_CODES'])
                for actual in (message, message + '; retain all fixture resources'):
                    self.assertEqual(m['safe_causes'](RuntimeError(actual))['code'], code)
            for actual in ('UNLISTED_SECRET',
                    'metadata_setup_policy_changed; retain all fixture resources; retain all fixture resources',
                    'SECRET metadata_setup_policy_changed'):
                self.assertEqual(m['safe_causes'](RuntimeError(actual))['code'], 'unclassified')

    def test_all_source_literal_failure_messages_have_exact_closed_mapping(self):
        for name in PINS:
            m, raw = load(name)
            for node in ast.walk(ast.parse(raw)):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    index = 1 if node.func.id == 'require' else 0 if node.func.id == 'FixtureFailure' else None
                    if index is not None and len(node.args) > index:
                        value = node.args[index]
                        if isinstance(value, ast.Constant) and type(value.value) is str:
                            self.assertIn(value.value, m['SAFE_MESSAGE_CODES'])

    def test_hostile_attributes_strings_and_non_tuple_causes_never_called(self):
        class Hostile(OSError):
            def __getattribute__(self, name):
                raise AssertionError('attribute forbidden')
            def __str__(self):
                raise AssertionError('str forbidden')
            def __repr__(self):
                raise AssertionError('repr forbidden')
            @property
            def errno(self):
                raise AssertionError('errno override forbidden')
            @property
            def causes(self):
                raise AssertionError('causes property forbidden')
        class HostileIterable:
            def __iter__(self):
                raise AssertionError('iteration forbidden')
        for m in self.modules:
            self.assertEqual(m['safe_causes'](Hostile(1, 'SECRET', '/SECRET')),
                dict(kind='os_error', code='unclassified', errno=1, errnoName='EPERM'))
            error = RuntimeError('UNLISTED_SECRET')
            error.causes = HostileIterable()
            self.assertEqual(m['safe_causes'](error), dict(kind='exception', code='unclassified'))
            for number in ('SECRET', True, 999999):
                result = m['safe_causes'](OSError(number, 'SECRET'))
                self.assertNotIn('errno', result)
                self.assertNotIn('SECRET', m['json'].dumps(result))

    def test_close_all_precedes_report_and_original_chain_exit1(self):
        for m in self.modules:
            primary = m['FixtureFailure']('metadata_setup_policy_changed', ())
            close_error = OSError(5, 'SECRET')
            output = __import__('io').StringIO()
            m['owned'][:] = [101, 102]
            def action():
                raise primary
            original_safe = m['safe_causes']
            def safe(error):
                self.assertEqual(m['owned'], [])
                self.assertIs(error.causes[0], primary)
                self.assertIs(error.causes[1].causes[0], close_error)
                return original_safe(error)
            with mock.patch.dict(m, entrypoint=lambda action: m['finalize'](action),
                    gate=mock.Mock(), safe_causes=safe), \
                    mock.patch.object(m['os'], 'close', side_effect=[close_error, None]) as close, \
                    mock.patch.object(m['sys'], 'stderr', output):
                with self.assertRaises(SystemExit) as caught:
                    m['entrypoint_with_failure_report'](action)
                self.assertEqual(caught.exception.code, 1)
                self.assertIs(caught.exception.__cause__.causes[0], primary)
                self.assertEqual(close.call_args_list, [mock.call(102), mock.call(101)])
            self.assertFalse(m['json'].loads(output.getvalue())['complete'])

    def test_report_write_failure_retains_original_close_and_writer_errors_exit1(self):
        for m in self.modules:
            primary = m['FixtureFailure']('owned_command_failed', ())
            close_error = OSError(5, 'close SECRET')
            write_error = OSError(28, 'write SECRET')
            writer = mock.Mock()
            writer.write.side_effect = write_error
            m['owned'][:] = [101, 102]
            def action():
                raise primary
            with mock.patch.dict(m, entrypoint=lambda action: m['finalize'](action), gate=mock.Mock()), \
                    mock.patch.object(m['os'], 'close', side_effect=[close_error, None]) as close, \
                    mock.patch.object(m['sys'], 'stderr', writer):
                with self.assertRaises(SystemExit) as caught:
                    m['entrypoint_with_failure_report'](action)
                self.assertEqual(caught.exception.code, 1)
                failure = caught.exception.__cause__
                self.assertIs(failure.causes[0].causes[0], primary)
                self.assertIs(failure.causes[0].causes[1].causes[0], close_error)
                self.assertIs(failure.causes[1], write_error)
                self.assertEqual(m['owned'], [])
                self.assertEqual(close.call_args_list, [mock.call(102), mock.call(101)])

    def test_report_flush_failure_retains_original_exit1(self):
        for m in self.modules:
            original = m['FixtureFailure']('fixture_operation_failed', ())
            write_error = OSError(5, 'flush SECRET')
            writer = mock.Mock()
            writer.flush.side_effect = write_error
            with mock.patch.dict(m, entrypoint=mock.Mock(side_effect=original)), \
                    mock.patch.object(m['sys'], 'stderr', writer):
                with self.assertRaises(SystemExit) as caught:
                    m['entrypoint_with_failure_report'](None)
                self.assertEqual(caught.exception.code, 1)
                self.assertIs(caught.exception.__cause__.causes[0], original)
                self.assertIs(caught.exception.__cause__.causes[1], write_error)


if __name__ == '__main__':
    unittest.main()
