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
        self.root = Path(tempfile.mkdtemp(prefix='agentmux-enrollment-test.', dir=cache)).resolve()
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
        hub = 'hub_' + secrets.token_hex(6)
        profile = 'profile_' + secrets.token_hex(16)
        self.owner = {'schemaVersion': '1.0.0', 'owner': {'schemaVersion': '1.0.0', 'ownerUid': os.getuid(),
            'principalId': 'tester', 'authenticatedIdentityRef': {'id': 'tester', 'ownerHubId': hub, 'revision': 1},
            'scope': {'organizationId': 'org_test', 'projectId': None, 'workspaceId': None},
            'instanceId': 'instance_' + secrets.token_hex(6), 'profileId': profile,
            'releaseFingerprint': runtime.authorization['releaseManifestDigest']},
            'context': {'environment': 'Test'}, 'clientInstallationId': secrets.token_hex(32),
            'approvedWorkspaceRoots': [str(REPOSITORY)],
            'release': {'packageDirectory': str(runtime.release),
                        'releaseManifestDigest': runtime.authorization['releaseManifestDigest']},
            'hostPort': overrides.pop('hostPort', 4333)}
        setup = self.base / 'setup'
        setup.mkdir(mode=0o700)
        owner_raw = json.dumps(self.owner).encode()
        owner_digest = _private_write(setup / 'owner-request.json', owner_raw)
        self.request = {'schemaVersion': '1.0.0',
            'ownerRequest': {'path': str(setup / 'owner-request.json'), 'sha256': owner_digest},
            'projectId': 'project_test', 'repositories': [{'root': str(REPOSITORY), 'localName': 'agentmux',
                'normalizedRemote': 'github.com/controllogix/agentmux'}],
            'localPeer': 'tester', 'localNode': 'tester_node', 'messagePeer': 'remote', 'validityDays': 30,
            'applicationRuntime': str(runtime.directory)}
        self.request.update(overrides)
        self.request_path = setup / 'setup-request.json'
        self.request_digest = _private_write(self.request_path, json.dumps(self.request).encode())
        self.profile = profile

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
