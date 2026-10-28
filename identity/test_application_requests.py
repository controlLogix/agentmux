"""application-requests writes owner and setup requests the real admissions accept (AMUX-728)."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest

from agentmux_contracts import ContractError
from identity import application_requests, local_enrollment
from identity.test_local_enrollment import GO, REPOSITORY, SDKROOT, _private_write

FAKE_DOCKER = """#!/bin/sh
case "$*" in
  "context show") echo desktop-linux ;;
  "context inspect desktop-linux --format {{.Endpoints.docker.Host}}") echo unix:///Users/tester/.docker/run/docker.sock ;;
  *" info --format {{json .}}") echo '{"ID":"engine-0001","OSType":"linux","ServerVersion":"29.8.2"}' ;;
  *" version --format {{.Client.Version}}") echo 29.8.2 ;;
  *" compose version --short") echo v5.5.1 ;;
  *) exit 1 ;;
esac
"""


def _sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class ApplicationRequestsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(GO).exists():
            raise unittest.SkipTest('pinned Go toolchain unavailable')
        cache = Path.home() / '.cache'
        cache.mkdir(mode=0o700, exist_ok=True)
        cls.build = Path(tempfile.mkdtemp(prefix='amux-requests-build.', dir=cache)).resolve()
        cls.runtime = cls.build / 'agentmux-runtime'
        env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'CGO_ENABLED': '1'}
        if Path(SDKROOT).exists():
            env['SDKROOT'] = SDKROOT
        subprocess.run([GO, 'build', '-mod=readonly', '-o', str(cls.runtime), './cmd/agentmux-runtime'],
                       cwd=REPOSITORY / 'platform', env=env, check=True, capture_output=True, timeout=600)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.build, ignore_errors=True)

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix='amux-requests.', dir=Path.home() / '.cache')).resolve()
        os.chmod(base, 0o700)
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self.base = base
        # The protected installation: a client pinned to its foundation release.
        self.client, foundation = secrets.token_hex(32), secrets.token_hex(32)
        release = base / 'protected' / 'releases' / foundation
        release.mkdir(parents=True)
        manifest, runtime = b'{"releaseVersion":"0.0.0"}', b'runtime-bytes'
        (release / 'release-manifest.json').write_bytes(manifest)
        (release / 'agentmux-runtime').write_bytes(runtime)
        clients = base / 'protected' / 'clients' / self.client
        clients.mkdir(parents=True)
        (clients / 'client-manifest.json').write_bytes(json.dumps(
            {'foundationInstallationId': foundation, 'frontendDigest': _sha(runtime)}).encode())
        for path in (base / 'protected').rglob('*'):
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        self.release_directory = release
        key = secrets.token_hex(32)
        self.selection = {'schemaVersion': '1.0.0', 'release': {
            'packageDirectory': str(base / 'build' / 'payload'), 'publicKeyHex': key,
            'releaseManifestDigest': _sha(manifest),
            'releaseAuthority': {'id': 'local_development', 'ownerHubId': 'dev_' + key[:32], 'revision': 1},
            'releaseVersion': '0.0.0', 'kernelApiMajor': 1},
            'runtime': {'path': str(base / 'build' / 'payload' / 'agentmux-runtime'), 'digest': _sha(runtime)}}
        self.selection_path = base / 'foundation-selection.json'
        self.selection_digest = _private_write(self.selection_path, json.dumps(self.selection).encode())
        # A checkout whose origin is an SSH remote.
        self.repository = base / 'Agentmux'
        (self.repository / '.git').mkdir(parents=True)
        (self.repository / '.git' / 'config').write_text(
            '[core]\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:ControlLogix/agentmux.git\n')
        # This user's Agentmux folder with a runtime port already kept.
        self.agentmux = base / 'Agentmux-home'
        (self.agentmux / 'application-runtime').mkdir(parents=True, mode=0o700)
        os.chmod(self.agentmux, 0o700)
        _private_write(self.agentmux / 'application-runtime' / 'inputs.json', b'{"port":24000}')
        self.docker = base / 'docker'
        self.docker.write_text(FAKE_DOCKER)
        os.chmod(self.docker, 0o755)

    def write(self, **overrides):
        values = dict(client_installation=self.client, foundation_selection=str(self.selection_path),
                      foundation_sha256=self.selection_digest, repository_root=str(self.repository),
                      principal='tester', local_node='tester_mbp', message_peer='peer', organization='org_test',
                      output=str(self.agentmux / 'requests-new'), protected=self.base / 'protected',
                      agentmux=self.agentmux, docker_candidates=(str(self.docker),))
        values.update(overrides)
        return application_requests.write_requests(**values)

    def test_written_requests_pass_owner_preparation_and_the_ceremony_admission(self):
        result = self.write()
        owner_path, setup_path = Path(result['ownerRequest']['path']), Path(result['setupRequest']['path'])
        self.assertEqual(oct(owner_path.parent.stat().st_mode & 0o777), '0o700')
        for path in (owner_path, setup_path):
            self.assertEqual(oct(path.stat().st_mode & 0o777), '0o600')
            self.assertEqual(result[path.stem.replace('-r', 'R')]['sha256'], _sha(path.read_bytes()))
        checked = subprocess.run([str(self.runtime), 'prepare-owner-profile', '--request', str(owner_path),
                                  '--request-sha256', result['ownerRequest']['sha256']],
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(checked.stdout)['outcome'], 'request_checked', checked.stderr)
        request, owner = local_enrollment.admit_request(str(setup_path), result['setupRequest']['sha256'])
        self.assertEqual(request['repositories'], [{'root': str(self.repository), 'localName': 'agentmux',
                                                    'normalizedRemote': 'github.com/controllogix/agentmux'}])
        self.assertEqual((request['localPeer'], request['localNode'], request['messagePeer']), ('tester', 'tester_mbp', 'peer'))
        self.assertEqual(owner['owner']['profileId'], result['profileId'])
        self.assertEqual(owner['owner']['authenticatedIdentityRef']['ownerHubId'], result['hubId'])
        self.assertEqual(owner['release'], dict(self.selection['release'], packageDirectory=str(self.release_directory)))
        self.assertEqual(owner['runtimeExecutable'], {'path': str(self.release_directory / 'agentmux-runtime'),
                                                      'digest': self.selection['runtime']['digest']})
        self.assertEqual(owner['docker'], {'backend': 'native-unix', 'executable': str(self.docker),
            'context': 'desktop-linux', 'endpoint': 'unix:///Users/tester/.docker/run/docker.sock',
            'engineId': 'engine-0001', 'clientVersion': '29.8.2', 'serverVersion': '29.8.2', 'composeVersion': '5.5.1'})
        self.assertIn(owner['hostPort'], local_enrollment.PRIVATE_PORTS)
        self.assertNotEqual(owner['hostPort'], 24000)
        # A second profile gets fresh identities and its own broker names.
        other = self.write(output=str(self.agentmux / 'requests-other'))
        self.assertNotEqual(other['profileId'], result['profileId'])
        second = json.loads(Path(other['ownerRequest']['path']).read_bytes())
        self.assertNotEqual((second['composeProject'], second['serverName'], second['domain']),
                            (owner['composeProject'], owner['serverName'], owner['domain']))

    def test_kept_ports_are_never_chosen(self):
        import socket
        from unittest import mock
        ports = local_enrollment.PRIVATE_PORTS
        for free in ports:
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', free))
                    break
                except OSError:
                    continue
        # The runtime's kept port comes up first and is skipped for a free one.
        draws = [ports.index(24000), ports.index(free)]
        with mock.patch.object(application_requests.secrets, 'randbelow', side_effect=draws):
            self.assertEqual(application_requests.broker_port(self.agentmux), free)
        self.assertIn(24000, application_requests.retained_ports(self.agentmux))

    def test_refusals_leave_nothing_behind(self):
        output = self.agentmux / 'requests-new'
        cases = [
            ({'foundation_sha256': 'sha256:' + '0' * 64}, 'application_requests_selection_changed'),
            ({'principal': 'peer', 'message_peer': 'peer'}, 'application_requests_arguments_invalid'),
            ({'principal': 'Not Valid'}, 'application_requests_arguments_invalid'),
            ({'output': 'relative'}, 'application_requests_arguments_invalid'),
            ({'client_installation': secrets.token_hex(32)}, 'application_requests_installation_invalid'),
            ({'docker_candidates': (str(self.base / 'missing-docker'),)}, 'application_requests_docker_unavailable'),
            ({'repository_root': str(self.base)}, 'application_requests_repository_invalid'),
        ]
        for overrides, code in cases:
            with self.subTest(code=code, overrides=overrides):
                with self.assertRaisesRegex(ContractError, code):
                    self.write(**overrides)
                self.assertFalse(output.exists())
        # The installed release must be the one the selection names.
        os.chmod(self.release_directory / 'agentmux-runtime', 0o644)
        (self.release_directory / 'agentmux-runtime').write_bytes(b'another runtime')
        with self.assertRaisesRegex(ContractError, 'application_requests_release_mismatch'):
            self.write()
        self.assertFalse(output.exists())

    def test_existing_output_is_never_changed(self):
        first = self.write()
        before = {p.name: p.read_bytes() for p in Path(first['ownerRequest']['path']).parent.iterdir()}
        with self.assertRaisesRegex(ContractError, 'application_requests_output_exists'):
            self.write()
        after = {p.name: p.read_bytes() for p in Path(first['ownerRequest']['path']).parent.iterdir()}
        self.assertEqual(after, before)

    def test_command_reports_only_closed_outcomes(self):
        import contextlib
        import io
        arguments = ['--client-installation', self.client, '--foundation-selection', str(self.selection_path),
                     '--foundation-selection-sha256', self.selection_digest, '--repository-root', str(self.repository),
                     '--principal', 'tester', '--local-node', 'tester_mbp', '--message-peer', 'peer',
                     '--organization', 'org_test', '--output', str(self.agentmux / 'requests-cli')]
        for wrong in ([], arguments[:-2], arguments + ['--apply'], ['--output'] + arguments[1:]):
            with self.subTest(arguments=wrong):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(application_requests.main(wrong), 1)
                self.assertEqual(json.loads(err.getvalue())['code'], 'application_requests_arguments_invalid')
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            # The real protected root has no such client installation.
            self.assertEqual(application_requests.main(arguments), 1)
        self.assertEqual(json.loads(err.getvalue())['code'], 'application_requests_installation_invalid')


if __name__ == '__main__':
    unittest.main()
