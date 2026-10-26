"""Local enrollment ceremony against a real application runtime (AMUX-728).

Each test class builds agentmux-runtime from this checkout and starts one
disposable native nats-server 2.15.0 in a private folder under the user's
cache. Every test uses a fresh profile on that runtime. The tests skip when Go
or the pinned server is unavailable; they never touch a real installation.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity import local_enrollment
from identity.application_enrollment import _read_material

REPOSITORY = Path(__file__).resolve().parents[1]
NATS_SERVER = os.environ.get('AGENTMUX_NATS_SERVER', '/opt/homebrew/Cellar/nats-server/2.15.0/bin/nats-server')
GO = os.environ.get('AGENTMUX_GO', str(Path.home() / 'go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.2.darwin-arm64/bin/go'))
SDKROOT = os.environ.get('AGENTMUX_SDKROOT', '/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk')


def _private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class Runtime:
    """One disposable runtime owned by a test class."""

    def __init__(self):
        if not Path(GO).exists() or not Path(NATS_SERVER).exists():
            raise unittest.SkipTest('pinned Go toolchain or nats-server 2.15.0 unavailable')
        cache = Path.home() / '.cache'
        cache.mkdir(mode=0o700, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='amux-enroll.', dir=cache)).resolve()
        os.chmod(self.root, 0o700)
        self.binary = self.root / 'agentmux-runtime'
        env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'CGO_ENABLED': '1'}
        if Path(SDKROOT).exists():
            env['SDKROOT'] = SDKROOT
        subprocess.run([GO, 'build', '-mod=readonly', '-o', str(self.binary), './cmd/agentmux-runtime'],
                       cwd=REPOSITORY / 'platform', env=env, check=True, capture_output=True, timeout=600)
        self.directory = self.root / 'application-runtime'
        init = self.command('init', '--nats-server', NATS_SERVER)
        self.manifest = init['manifest']
        self.command('start')
        self.release = self.root / 'release'
        self.release.mkdir(mode=0o755)
        self.authorization = {'assemblyDigest': 'sha256:' + 'a' * 64, 'releaseManifestDigest': 'sha256:' + 'b' * 64,
                              'releaseVersion': '0.0.0'}
        path = self.release / 'release-authorization.json'
        path.write_bytes(json.dumps(self.authorization).encode())
        os.chmod(path, 0o644)

    def command(self, operation, *arguments):
        result = subprocess.run([str(self.binary), 'application-runtime', operation, '--directory', str(self.directory),
                                 *arguments], capture_output=True, timeout=60)
        if result.returncode != 0:
            raise AssertionError('runtime %s failed: %s' % (operation, result.stderr[:300]))
        return json.loads(result.stdout)

    def close(self):
        try:
            self.command('stop')
        finally:
            shutil.rmtree(self.root, ignore_errors=True)


class Installation:
    """A fresh profile and its private setup request on the shared runtime."""

    def __init__(self, runtime, **overrides):
        self.runtime = runtime
        self.base = runtime.root / ('install-' + secrets.token_hex(4))
        self.base.mkdir(mode=0o700)
        # A private workspace per installation: owners such as definitions
        # claim retained state inside the approved repository root.
        self.workspace = self.base / 'workspace'
        self.workspace.mkdir(mode=0o700)
        hub = 'hub_' + secrets.token_hex(6)
        profile = 'profile_' + secrets.token_hex(16)
        self.owner = {'schemaVersion': '1.0.0', 'owner': {'schemaVersion': '1.0.0', 'ownerUid': os.getuid(),
            'principalId': 'tester', 'authenticatedIdentityRef': {'id': 'tester', 'ownerHubId': hub, 'revision': 1},
            'scope': {'organizationId': 'org_test', 'projectId': None, 'workspaceId': None},
            'instanceId': 'instance_' + secrets.token_hex(6), 'profileId': profile,
            'releaseFingerprint': runtime.authorization['releaseManifestDigest']},
            'context': {'environment': 'Test'}, 'clientInstallationId': secrets.token_hex(32),
            'approvedWorkspaceRoots': [str(self.workspace)],
            'release': {'packageDirectory': str(runtime.release),
                        'releaseManifestDigest': runtime.authorization['releaseManifestDigest']},
            'hostPort': overrides.pop('hostPort', 4333)}
        setup = self.base / 'setup'
        setup.mkdir(mode=0o700)
        owner_raw = json.dumps(self.owner).encode()
        owner_digest = _private_write(setup / 'owner-request.json', owner_raw)
        self.request = {'schemaVersion': '1.0.0',
            'ownerRequest': {'path': str(setup / 'owner-request.json'), 'sha256': owner_digest},
            'projectId': 'project_test', 'repositories': [{'root': str(self.workspace), 'localName': 'agentmux',
                'normalizedRemote': 'github.com/controllogix/agentmux'}],
            'localPeer': 'tester', 'localNode': 'tester_node', 'messagePeer': 'remote', 'validityDays': 30,
            'applicationRuntime': str(runtime.directory)}
        self.request.update(overrides)
        self.request_path = setup / 'setup-request.json'
        self.request_digest = _private_write(self.request_path, json.dumps(self.request).encode())
        self.profile = profile

    @property
    def home(self):
        return self.base / 'hubs' / self.profile.removeprefix('profile_')[:12]

    @property
    def enrollment(self):
        return self.base / 'application-enrollment' / self.profile

    async def run(self):
        return await local_enrollment.run(str(self.request_path), self.request_digest, root=self.base)

    def snapshot(self):
        return {str(p): p.read_bytes() for p in self.enrollment.rglob('*') if p.is_file()}


class LocalEnrollmentTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Runtime()

    @classmethod
    def tearDownClass(cls):
        cls.runtime.close()

    async def test_full_run_resumes_identically_and_loads_with_product_loaders(self):
        from hub.client_launch_enrollment import load_connection_selection
        from hub.client_launch_selection import load_selection
        install = Installation(self.runtime)
        first = await install.run()
        before = install.snapshot()
        self.assertEqual(await install.run(), first)
        self.assertEqual(install.snapshot(), before)
        core = _read_material(first['coreHub']['selection'], max_bytes=16384)
        self.assertEqual(local_enrollment.digest(canonical_bytes(core)), first['coreHub']['sha256'])
        self.assertEqual({k: len(core[k]) for k in ('identity', 'messages', 'work')}, {'identity': 1, 'messages': 2, 'work': 2})
        for family in ('identity', 'messages', 'work'):
            for pin in core[family]:
                selection = load_selection(pin['selection'])
                self.assertEqual((selection.profile_id, selection.hub_id), (install.profile, install.owner['owner']['authenticatedIdentityRef']['ownerHubId']))
                load_connection_selection(selection.application_connection, workspaces=selection.invocation.workspaces,
                                          deadline=time.monotonic() + 5)
        self.assertEqual(load_selection(core['identity'][0]['selection']).application_repositories, ('agentmux',))
        # The selected core Hub route refuses a socket path the OS cannot bind.
        self.assertEqual(core['home'], str(install.home))
        self.assertLessEqual(len(str(Path(core['home']) / 'hub' / 'hub.sock').encode()), local_enrollment.HUB_SOCKET_BYTES)
        for path in install.enrollment.rglob('*'):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o077, 0, path)

    async def test_interruption_after_materials_resumes_without_new_keys(self):
        install = Installation(self.runtime)
        with mock.patch.object(local_enrollment.Ceremony, 'bootstrap', side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):
                await install.run()
        materials = (install.enrollment / 'materials.json').read_bytes()
        self.assertFalse((install.enrollment / 'bootstrap.json').exists())
        await install.run()
        self.assertEqual((install.enrollment / 'materials.json').read_bytes(), materials)

    async def test_interruption_after_commit_accepts_only_its_own_record(self):
        install = Installation(self.runtime)
        original = local_enrollment._write_material

        def lose_receipt(path, material, **kwargs):
            if Path(path).name == 'bootstrap.json':
                raise RuntimeError('interrupted after commit')
            return original(path, material, **kwargs)
        with mock.patch.object(local_enrollment, '_write_material', side_effect=lose_receipt):
            with self.assertRaises(RuntimeError):
                await install.run()
        result = await install.run()
        receipt = _read_material(install.enrollment / 'bootstrap.json', max_bytes=1048576)
        self.assertEqual(receipt['sequence'], 1)
        self.assertTrue(Path(result['coreHub']['selection']).exists())

    async def test_interruption_during_selections_resumes_with_identical_pins(self):
        install = Installation(self.runtime)
        original = local_enrollment._write_material

        def lose_core(path, material, **kwargs):
            if Path(path).name == 'core-hub.json':
                raise RuntimeError('interrupted before coreHub')
            return original(path, material, **kwargs)
        with mock.patch.object(local_enrollment, '_write_material', side_effect=lose_core):
            with self.assertRaises(RuntimeError):
                await install.run()
        partial = install.snapshot()
        result = await install.run()
        for path, raw in partial.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        self.assertEqual(local_enrollment.digest(Path(result['coreHub']['selection']).read_bytes()), result['coreHub']['sha256'])

    async def test_half_built_materials_are_refused_not_regenerated(self):
        install = Installation(self.runtime)
        install.enrollment.parent.mkdir(mode=0o700)
        install.enrollment.mkdir(mode=0o700)
        (install.enrollment / 'materials').mkdir(mode=0o700)
        with self.assertRaisesRegex(ContractError, 'local_enrollment_materials_incomplete'):
            await install.run()

    async def test_changed_retained_selection_is_refused(self):
        install = Installation(self.runtime)
        await install.run()
        (install.enrollment / 'result.json').unlink()
        target = install.enrollment / 'client-selection-work-operator.json'
        changed = strict_loads(target.read_bytes())
        changed['workspaces'] = ['/changed']
        target.unlink()
        _private_write(target, canonical_bytes(changed))
        with self.assertRaisesRegex(ContractError, 'local_enrollment_selection_conflict'):
            await install.run()

    async def test_foreign_identity_record_is_refused(self):
        install = Installation(self.runtime)
        await install.run()
        for name in ('result.json', 'bootstrap.json'):
            (install.enrollment / name).unlink()
        materials = _read_material(install.enrollment / 'materials.json', max_bytes=1048576)
        materials['state']['grants'] = materials['state']['grants'][:-1]
        (install.enrollment / 'materials.json').unlink()
        _private_write(install.enrollment / 'materials.json', canonical_bytes(materials))
        with self.assertRaisesRegex(ContractError, 'local_enrollment_stream_occupied'):
            await install.run()

    async def test_request_refusals(self):
        cases = [
            ({'localNode': 'Not-Valid'}, 'local_enrollment_request_invalid'),
            ({'localPeer': 'same', 'messagePeer': 'same'}, 'local_enrollment_request_invalid'),
            ({'validityDays': 0}, 'local_enrollment_request_invalid'),
            ({'repositories': [{'root': '/not/approved', 'localName': 'agentmux',
                                'normalizedRemote': 'github.com/x/y'}]}, 'local_enrollment_repository_invalid'),
        ]
        for overrides, code in cases:
            with self.subTest(overrides=overrides):
                install = Installation(self.runtime, **overrides)
                with self.assertRaisesRegex(ContractError, code):
                    await install.run()
        install = Installation(self.runtime)
        with self.assertRaisesRegex(ContractError, 'local_enrollment_request_changed'):
            await local_enrollment.run(str(install.request_path), 'sha256:' + '0' * 64, root=install.base)
        port = int(self.runtime.manifest['endpoint'].rsplit(':', 1)[1])
        install = Installation(self.runtime, hostPort=port)
        with self.assertRaisesRegex(ContractError, 'local_enrollment_infrastructure_endpoint'):
            await install.run()
        self.assertFalse(install.enrollment.exists())
        install = Installation(self.runtime)
        deep = install.base / ('d' * 60)
        deep.mkdir(mode=0o700)
        with self.assertRaisesRegex(ContractError, 'local_enrollment_home_too_long'):
            await local_enrollment.run(str(install.request_path), install.request_digest, root=deep)
        self.assertEqual(sorted(p.name for p in deep.iterdir()), [])

    async def test_live_credentials_are_least_privilege(self):
        import nats
        install = Installation(self.runtime)
        result = await install.run()
        core = _read_material(result['coreHub']['selection'], max_bytes=16384)
        manifest = self.runtime.manifest
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_verify_locations(cadata=manifest['rootsPEM'])
        for pin in core['work']:
            selection = _read_material(pin['selection'], max_bytes=16384)
            connection = _read_material(selection['application']['connection'], max_bytes=32768)
            errors = []

            async def record(error):
                errors.append(str(error))
            client = await nats.connect(servers=[connection['endpoint']], tls=tls, tls_hostname=connection['serverName'],
                tls_handshake_first=True, user_credentials=connection['credentialsFile'], allow_reconnect=False,
                inbox_prefix=connection['replyPrefix'], error_cb=record, connect_timeout=3)
            try:
                identity_subject = '.'.join(('amx', 'v1', 'h', install.owner['owner']['authenticatedIdentityRef']['ownerHubId'],
                    'o', 'org_test', 'identity', 'local_authority', 'command'))
                async def violation():
                    # The broker reports a refused operation asynchronously.
                    for _ in range(30):
                        if any('permissions violation' in e.lower() for e in errors):
                            return True
                        await asyncio.sleep(0.1)
                    return False
                await client.publish(identity_subject, b'{}')
                await client.flush(timeout=2)
                await asyncio.sleep(0.3)
                self.assertEqual(errors, [], 'allowed subject refused')
                await client.publish('amx.v1.h.other.o.org_test.identity.local_authority.command', b'{}')
                await client.flush(timeout=2)
                self.assertTrue(await violation(), 'foreign publish was not refused')
                errors.clear()
                await client.subscribe('amx.>')
                await client.flush(timeout=2)
                self.assertTrue(await violation(), 'broad subscribe was not refused')
            finally:
                await client.close()

    async def test_ceremony_selection_starts_the_services_host_including_storage(self):
        # The installed services process runs this host from the packaged
        # dashboard and taskmgmt roots; mirror that layout from the checkout.
        import sys
        for root in (REPOSITORY / 'dashboard', REPOSITORY / 'taskmgmt'):
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
        from application_service_host import ApplicationServiceHost
        from identity.application_service_selection import ApplicationServiceSelection
        install = Installation(self.runtime)
        await install.run()
        policy = (install.home / 'hub' / 'federation.toml').read_text()
        self.assertIn('[peers.remote]\ntrust = "approve"', policy)
        self.assertNotIn('"deny"', policy)
        raw = _read_material(install.enrollment / 'service-selection.json', max_bytes=1048576, return_bytes=True)
        selection = ApplicationServiceSelection(raw)
        port = selection.local_browser_port()
        self.assertNotIn(port, (None, local_enrollment.LEGACY_BROWSER_PORT, install.owner['hostPort']))
        # Hold the historical shared port, as a running legacy dashboard does.
        import socket
        legacy = socket.socket()
        try:
            legacy.bind(('127.0.0.1', local_enrollment.LEGACY_BROWSER_PORT))
            legacy.listen()
        except OSError:
            legacy.close()
            legacy = None  # already held by another local listener, which is the same condition
        # Construct the host exactly as the installed services process does.
        host = ApplicationServiceHost(selection, browser_port=port)
        try:
            await asyncio.wait_for(host.start(), 60)
            self.assertEqual([type(service).__name__ for service in host._services],
                             ['IdentityService', 'DefinitionCommandService', 'IntegrationService', 'SelectedStorageHost'])
            self.assertEqual(host._browser_server.server_address, ('127.0.0.1', port))
            host.check_health()
        finally:
            await host.close()
            if legacy is not None:
                legacy.close()

    async def test_binding_grants_observation_and_sessions_share_one_scope(self):
        # The identity binding provider refuses discovery unless the bind grant,
        # the attested runtime observation and the client selection scopes match.
        install = Installation(self.runtime)
        await install.run()
        materials = _read_material(install.enrollment / 'materials.json', max_bytes=1048576)
        attestor = _read_material(install.enrollment / 'attestor-selection.json', max_bytes=1048576)
        scope = attestor['application']['scope']
        grants = [g for g in materials['state']['grants'] if g['contractId'] in ('application-bind', 'application-attest')]
        self.assertEqual(sorted(g['contractId'] for g in grants), ['application-attest'] + ['application-bind'] * 5)
        self.assertEqual({canonical_bytes(g['scope']) for g in grants}, {canonical_bytes(scope)})
        keys = sorted((install.enrollment / 'materials').glob('client-*/client-key.json'))
        self.assertEqual(len(keys), 5)
        for key in keys:
            self.assertEqual(_read_material(key, max_bytes=65536)['scope'], scope, key.parent.name)
        observer = attestor['application']['identityRef']
        self.assertIn(canonical_bytes(scope), {canonical_bytes(m['scope']) for m in materials['state']['memberships']
                                               if m['identityRef'] == observer})

    async def test_private_browser_port_is_retained_and_schema_closed(self):
        from identity.application_service_selection import ApplicationServiceSelection
        install = Installation(self.runtime)
        await install.run()
        materials = _read_material(install.enrollment / 'materials.json', max_bytes=1048576)
        port = materials['service']['localBrowser']['port']
        selection = _read_material(install.enrollment / 'service-selection.json', max_bytes=1048576)
        self.assertEqual(selection['localBrowser'], {'port': port})
        await install.run()
        self.assertEqual(_read_material(install.enrollment / 'service-selection.json', max_bytes=1048576)['localBrowser'],
                         {'port': port})
        for changed in ({'port': 1023}, {'port': 65536}, {'port': '9000'}, {'port': port, 'host': '0.0.0.0'}, {}):
            with self.subTest(localBrowser=changed), self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(dict(selection, localBrowser=changed)))
        without = {k: v for k, v in selection.items() if k != 'localBrowser'}
        self.assertIsNone(ApplicationServiceSelection(canonical_bytes(without)).local_browser_port())

    async def test_three_installations_get_distinct_identities(self):
        seen = set()
        for _ in range(3):
            install = Installation(self.runtime)
            await install.run()
            materials = _read_material(install.enrollment / 'materials.json', max_bytes=1048576)
            keys = {t['publicKey'] for t in materials['state']['transports']}
            streams = {materials['service'][role]['ledger']['stream'] for role in ('identity', 'definitions', 'integration')}
            self.assertFalse(keys & seen or streams & seen)
            seen |= keys | streams


if __name__ == '__main__':
    unittest.main()


class LocalEnrollmentEntryTests(unittest.TestCase):
    def test_malformed_arguments_report_only_a_closed_code(self):
        import io
        for arguments in ([], ['--request', 'relative', '--request-sha256', 'sha256:' + 'a' * 64],
                          ['--request', '/private/r.json', '--request-sha256', 'sha256:BAD'],
                          ['--request-sha256', 'sha256:' + 'a' * 64, '--request', '/private/r.json']):
            with self.subTest(arguments=arguments), mock.patch('sys.stderr', new_callable=io.StringIO) as err, \
                    mock.patch('sys.stdout', new_callable=io.StringIO) as out:
                self.assertEqual(local_enrollment.main(arguments), 1)
                self.assertEqual(json.loads(err.getvalue())['code'], 'local_enrollment_arguments_invalid')
                self.assertEqual(out.getvalue(), '')

    def test_ceremony_failure_reports_closed_code_without_private_detail(self):
        import io
        with mock.patch.object(local_enrollment, 'run', side_effect=ContractError('local_enrollment_request_changed')), \
                mock.patch('sys.stderr', new_callable=io.StringIO) as err:
            self.assertEqual(local_enrollment.main(['--request', '/private/r.json', '--request-sha256', 'sha256:' + 'a' * 64]), 1)
        self.assertEqual(json.loads(err.getvalue()), {'schemaVersion': '1.0.0', 'kind': 'local-enrollment-diagnostic',
                                                      'code': 'local_enrollment_request_changed'})
