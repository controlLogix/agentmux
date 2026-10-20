"""Bind private display context to the exact selection bytes used for startup."""
import dataclasses
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hub import cli
from hub import client_launch_coordinator as coordinator
from hub import client_launch_entrypoint as entry
from hub import client_launch_selection as selection
from hub.profile_context import ProfileContext, RegisteredProfileContext


class RegisteredStartupContext(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / 'selected.json'
        self.document = {'schemaVersion': '1.0.0', 'hostPolicy': str(self.root / 'policy.json'),
                         'workspaces': [str(self.root / 'repository')], 'instanceId': 'instance_' + '1' * 32,
                         'profileId': 'profile_' + 'a' * 32, 'hubId': 'hub_one'}
        self.path.write_text(json.dumps(self.document))
        self.path.chmod(0o600)
        self.context = ProfileContext(environment='Ryan - Local Development', project='Agentmux')
        self.registered = self.binding()

    def binding(self, **changes):
        values = dict(selection_sha256='sha256:' + hashlib.sha256(self.path.read_bytes()).hexdigest(),
                      profile_id='profile_' + 'a' * 32, instance_id='instance_' + '1' * 32, context=self.context)
        values.update(changes)
        return RegisteredProfileContext(**values)

    def test_existing_single_read_matches_digest_and_exact_ids(self):
        original_read = selection.os.read
        with patch.object(selection.os, 'read', wraps=original_read) as read:
            loaded = selection._load_selection(str(self.path), descriptor_admission=Mock(return_value=True),
                                               registered_context=self.registered)
        read.assert_called_once()
        self.assertIs(loaded.profile_context, self.context)
        self.assertFalse(hasattr(loaded, 'selection_sha256'))
        self.assertFalse(hasattr(loaded, 'registered_context'))
        plain = selection._load_selection(str(self.path), descriptor_admission=Mock(return_value=True))
        self.assertIsNone(plain.profile_context)
        self.assertEqual(loaded.invocation, plain.invocation)
        self.assertEqual((loaded.profile_id, loaded.instance_id, loaded.hub_id),
                         (plain.profile_id, plain.instance_id, plain.hub_id))

    def test_changed_bytes_or_identity_refuse_before_runtime_admission(self):
        original = self.path.read_bytes()
        for binding in (self.binding(selection_sha256='sha256:' + 'a' * 64),
                        self.binding(profile_id='profile_' + 'b' * 32), self.binding(instance_id='instance_' + '2' * 32)):
            with patch.object(coordinator, '_admit_runtime') as admit:
                runner = Mock()
                observed = coordinator._startup(str(self.path), managed_worker=False,
                    descriptor_admission=Mock(return_value=True), registered_context=binding, runner=runner)
            self.assertEqual(observed.public['code'], 'selection_invalid')
            self.assertIsNone(observed.selection)
            admit.assert_not_called()
            runner.assert_not_called()
        # Even an otherwise equivalent JSON rewrite must match the registered bytes.
        self.path.write_bytes(original + b'\n')
        with self.assertRaisesRegex(selection.SelectionError, '^selection_invalid$'):
            selection._load_selection(str(self.path), descriptor_admission=Mock(return_value=True),
                                      registered_context=self.registered)

    def test_cli_session_exposes_only_validated_immutable_display_values(self):
        for command in ('startup', 'mcp'):
            owner = SimpleNamespace(closed=True)
            runner = Mock(return_value=coordinator.Capture(failure='runtime_failed', admission=owner))
            def startup(path, *, managed_worker, registered_context):
                return coordinator._startup(path, managed_worker=managed_worker,
                    descriptor_admission=Mock(return_value=True), registered_context=registered_context,
                    runner=runner)
            args = [command, '--selection', str(self.path)]
            with patch.object(entry, 'startup', side_effect=startup) as start, \
                    patch.object(coordinator, '_admit_runtime', return_value=owner), \
                    patch.object(cli.sys, 'stdout', io.StringIO()), \
                    patch.object(cli.sys, 'stderr', io.StringIO()), \
                    patch('hub.fed.mcp.main'):
                session = cli.main(args, registered_context=self.registered)
                session.start()
            self.assertIs(session.profile_context, self.context)
            self.assertIsNone(session._registered_context)
            self.assertNotIn('Ryan', json.dumps(session.result.public))
            start.assert_called_once_with(str(self.path), managed_worker=False,
                                          registered_context=self.registered)
            with self.assertRaises(AttributeError):
                session.profile_context = ProfileContext(project='other')
            with self.assertRaises(dataclasses.FrozenInstanceError):
                session.profile_context.project = 'other'

    def test_interrupted_bound_startup_cannot_retry_without_its_binding(self):
        for failure in (KeyboardInterrupt(), RuntimeError('PRIVATE')):
            session = entry.EnrolledSession(entry.Options(str(self.path), False, 'human'),
                                            registered_context=self.registered)
            with patch.object(entry, 'startup', side_effect=failure) as startup:
                with self.assertRaises(type(failure)):
                    session.start()
                with self.assertRaisesRegex(entry.OptionsError, '^Registered client startup did not complete'):
                    session.start()
            startup.assert_called_once_with(str(self.path), managed_worker=False,
                                            registered_context=self.registered)
            self.assertIsNone(session.profile_context)
            self.assertIsNone(session.result)
            self.assertIs(session._registered_context, self.registered)
            self.assertEqual(session.exit_code(), 1)

    def test_invalid_or_unbound_context_cannot_enter_legacy_routes(self):
        fake = Mock()
        with patch.object(cli, 'call') as call, patch.object(entry, 'startup') as startup:
            for arguments, context in ((['mcp'], self.registered), (['ping'], self.registered),
                    (['startup', '--repository-root', '/approved/repo'], self.registered),
                    (['startup', '--selection', str(self.path)], fake)):
                with self.subTest(arguments=arguments), self.assertRaises(cli.Fail):
                    cli.main(arguments, registered_context=context)
        call.assert_not_called()
        startup.assert_not_called()
        with patch.object(selection, '_open_checked') as opened, self.assertRaises(selection.SelectionError):
            selection._load_selection(str(self.path), descriptor_admission=Mock(), registered_context=fake)
        opened.assert_not_called()
        fake.matches_selection.assert_not_called()
        with self.assertRaises(entry.OptionsError):
            entry.EnrolledSession(entry.Options(None, False, 'human'), registered_context=self.registered)
