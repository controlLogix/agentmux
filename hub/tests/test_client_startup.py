"""Offline checks for exact runtime arguments and managed-worker recursion."""
import os
import unittest
from unittest.mock import patch

from hub.client_startup import RuntimeInvocation, StartupSelectionError


class ClientStartup(unittest.TestCase):
    def test_explicit_selection_preserves_literal_paths_and_ignores_environment(self):
        selection = RuntimeInvocation('/trusted launcher/agentmux-runtime',
                                      '/private/quote\" and \' policy.json',
                                      ('/workspace/$(touch nope)', '/workspace/back\\slash'))
        before = os.getcwd()
        with patch.dict(os.environ, {'AGENTMUX_HOME': '/wrong', 'DOCKER_CONTEXT': 'wrong'}):
            self.assertEqual(selection.arguments(), (
                '/trusted launcher/agentmux-runtime', 'ensure', '--host-policy',
                '/private/quote\" and \' policy.json', '--workspace',
                '/workspace/$(touch nope)', '--workspace', '/workspace/back\\slash'))
        self.assertEqual(os.getcwd(), before)

    def test_managed_worker_cannot_request_recursive_ensure(self):
        selection = RuntimeInvocation('/trusted/runtime', '/private/policy', ('/workspace',))
        self.assertEqual(selection.arguments(managed_worker=True)[1], 'status')
        for ambiguous in ('false', 1, None):
            with self.subTest(ambiguous=ambiguous), self.assertRaises(StartupSelectionError):
                selection.arguments(managed_worker=ambiguous)

    def test_incomplete_or_ambient_selection_is_refused(self):
        for executable, policy, roots in (
            ('runtime', '/private/policy', ('/workspace',)),
            ('/trusted/runtime', 'policy', ('/workspace',)),
            ('/trusted/runtime', '/private/policy', ()),
            ('/trusted/runtime', '/private/policy', ('relative',)),
            ('/trusted/runtime', '/private/policy', ('/workspace/../other',)),
            ('/trusted/runtime', '/private/policy', ('/workspace\x00',)),
            ('/trusted/runtime', '/private/policy', ['/workspace']),
            ('/trusted/runtime', '/private/policy', ('/workspace',) * 17),
        ):
            with self.subTest(executable=executable, policy=policy, roots=roots):
                with self.assertRaises(StartupSelectionError):
                    RuntimeInvocation(executable, policy, roots)

    def test_attestor_selection_is_paired_literal_and_absent_from_worker_status(self):
        path = '/private/attestor with "quotes".json'
        digest = 'sha256:' + 'a' * 64
        invocation = RuntimeInvocation('/trusted/runtime', '/private/policy', ('/workspace',), path, digest)
        self.assertEqual(invocation.arguments()[-4:], ('--application-attestor-selection', path,
                         '--application-attestor-selection-sha256', digest))
        self.assertNotIn('--application-attestor-selection', invocation.arguments(managed_worker=True))
        for selected, pinned in ((path, None), (None, digest), (path, 'a' * 64), ('relative', digest)):
            with self.subTest(selected=selected, pinned=pinned), self.assertRaises(StartupSelectionError):
                RuntimeInvocation('/trusted/runtime', '/private/policy', ('/workspace',), selected, pinned)

    def service_pins(self):
        return dict(application_services_installation='b' * 64,
            application_services_selection='/private/service \'quoted\' $(literal).json',
            application_services_digest='sha256:' + 'c' * 64)

    def invocation(self, **pins):
        return RuntimeInvocation('/trusted/runtime', '/private/policy', ('/workspace',),
                                 '/private/attestor', 'sha256:' + 'a' * 64, **pins)

    def test_service_pins_are_literal_and_ensure_only(self):
        pins = self.service_pins()
        invocation = self.invocation(**pins)
        self.assertEqual(invocation.arguments()[-6:], (
            '--application-services-installation', pins['application_services_installation'],
            '--application-services-selection', pins['application_services_selection'],
            '--application-services-selection-sha256', pins['application_services_digest']))
        with self.assertRaises(TypeError):
            self.invocation(**pins, application_services_host_account='STALE_HOST_FIELD')
        self.assertEqual(invocation.arguments(managed_worker=True), (
            '/trusted/runtime', 'status', '--host-policy', '/private/policy', '--workspace', '/workspace'))
        for missing in pins:
            partial = {key: value for key, value in pins.items() if key != missing}
            with self.subTest(missing=missing), self.assertRaises(StartupSelectionError):
                self.invocation(**partial)
        with self.assertRaises(StartupSelectionError):
            RuntimeInvocation('/trusted/runtime', '/private/policy', ('/workspace',), **pins)

    def test_service_scalar_validation_matches_native(self):
        pins = self.service_pins()
        mutations = {
            'application_services_installation': ['', 'B' * 64, 'b' * 63, True],
            'application_services_selection': ['relative', '/private/../service', '//private/services.json', '/' + 's' * 4096,
                '/private/' + 'é' * 2045, '/private/' + chr(127), '/private/\ud800'],
            'application_services_digest': ['', 'c' * 64, 'sha256:' + 'C' * 64, False],
        }
        mutations['application_services_selection'].extend('/private/' + chr(code) for code in range(32))
        for field, values in mutations.items():
            for value in values:
                with self.subTest(field=field, value=repr(value)), self.assertRaises(StartupSelectionError):
                    self.invocation(**{**pins, field: value})
