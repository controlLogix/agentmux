"""Local enrollment ceremony against a real application runtime (AMUX-728).

Each test class builds agentmux-runtime from this checkout and starts one
disposable native nats-server 2.15.0 in a private folder under the user's
cache. Every test uses a fresh profile on that runtime. The tests skip when Go
or the pinned server is unavailable; they never touch a real installation.
"""
import asyncio
import base64
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

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
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


class RuntimeAttestor:
    """Stand in for the installed host's Go attestor using the ceremony's own material.

    Mirrors EnrolledApplicationObservationSigner (platform/launcher/
    application_runtime_signer.go): the same observation and update claims,
    taken only from attestor-selection.json, signed with its key file and sent
    with its own NATS credentials, refreshed before each 4-second expiry.
    """

    def __init__(self, enrollment):
        self.selection = _read_material(enrollment / 'attestor-selection.json', max_bytes=1048576)
        key = _read_material(self.selection['keyPath'], max_bytes=4096)
        self.seed = base64.b64decode(key['seed'])
        self.lifetime = secrets.token_hex(32)
        self.receipts = []
        self.task = None

    def signed(self, claims):
        return canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
                                'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
                                'signature': sign_claims(claims, self.seed)})

    def update(self, reply, number):
        from identity.application_binding import _stamp
        s, kernel = self.selection, self.selection['kernelScope']
        application = s['application']
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=4)
        observation = self.signed({'purpose': 'agentmux-application-runtime-observation-v1',
            'hubId': kernel['hubId'], 'profileId': kernel['profileId'], 'instanceId': kernel['instanceId'],
            'generation': s['initialGeneration'], 'lifetimeId': self.lifetime,
            'releaseDigest': kernel['releaseManifestDigest'], 'policyRef': application['policyRef'],
            'workspaceRef': application['workspaceRef'], 'scope': application['scope'],
            'signingKeyRef': application['issuerRef'], 'issuedAt': _stamp(now), 'expiresAt': _stamp(expires)})
        return self.signed({'purpose': 'agentmux-application-observation-update-v1',
            'requestId': 'attest_%d' % number, 'hubId': kernel['hubId'], 'profileId': kernel['profileId'],
            'authorityId': application['authorityId'], 'action': 'refresh', 'generation': s['initialGeneration'],
            'lifetimeId': self.lifetime, 'transportRef': application['transportRef'],
            'observationBytes': base64.b64encode(observation).decode(), 'replySubject': reply,
            'issuedAt': _stamp(now), 'expiresAt': _stamp(expires)})

    async def start(self):
        import nats
        s = self.selection
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_verify_locations(cadata=s['connection']['rootsPEM'])
        prefix = s['credentials']['replyPrefix']
        self.client = await nats.connect(servers=[s['connection']['endpoint']], tls=tls,
            tls_hostname=s['connection']['serverName'], tls_handshake_first=True,
            user_credentials=s['credentials']['path'], allow_reconnect=False, inbox_prefix=prefix,
            connect_timeout=3)
        subject = '.'.join(('amx', 'v1', 'h', s['kernelScope']['hubId'], 'o',
                            s['application']['scope']['organizationId'], 'identity',
                            s['application']['authorityId'], 'command'))
        replies = asyncio.Queue()
        reply = prefix + '.attestor'
        await self.client.subscribe(reply, cb=replies.put)
        async def refresh():
            number = 0
            while True:
                number += 1
                await self.client.publish(subject, self.update(reply, number), reply=reply)
                self.receipts.append(strict_loads((await asyncio.wait_for(replies.get(), 3)).data))
                await asyncio.sleep(1.5)
        self.task = asyncio.create_task(refresh())
        deadline = time.monotonic() + 10
        while not self.receipts and not self.task.done() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        if self.task.done():
            self.task.result()
        return self.receipts[0] if self.receipts else None

    async def close(self):
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
        await self.client.close()


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
            if 'bootstrap.json' in Path(path).name:
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
            if 'core-hub.json' in Path(path).name:
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

    async def test_interruption_while_creating_keys_resumes_with_unused_keys_replaced(self):
        # Review item 4: keys from a materials stage that never completed were
        # never published, so a rerun replaces them instead of refusing forever.
        install = Installation(self.runtime)
        with mock.patch.object(local_enrollment, 'provision_application_attestor',
                               side_effect=RuntimeError('interrupted while creating keys')):
            with self.assertRaises(RuntimeError):
                await install.run()
        self.assertTrue((install.enrollment / 'materials').is_dir())
        self.assertFalse((install.enrollment / 'materials.json').exists())
        result = await install.run()
        self.assertEqual(local_enrollment.digest(Path(result['coreHub']['selection']).read_bytes()),
                         result['coreHub']['sha256'])
        self.assertEqual(await install.run(), result)

    async def test_interruption_while_writing_a_stage_record_resumes(self):
        # Review item 4: a stage record cut off mid-write never takes its final
        # name, so a rerun is not left reading a truncated materials.json.
        install = Installation(self.runtime)
        original = local_enrollment._write_material

        def cut_off(path, material, **kwargs):
            if 'materials.json' in Path(path).name:
                raw = canonical_bytes(material)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, raw[:len(raw) // 2])
                os.close(fd)
                raise RuntimeError('interrupted while writing materials.json')
            return original(path, material, **kwargs)
        with mock.patch.object(local_enrollment, '_write_material', side_effect=cut_off):
            with self.assertRaises(RuntimeError):
                await install.run()
        result = await install.run()
        self.assertTrue(Path(result['coreHub']['selection']).exists())
        self.assertEqual([p.name for p in install.enrollment.iterdir() if p.name.endswith('.partial')], [])

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

    async def test_ceremony_output_starts_the_enrolled_hub_and_answers_ping(self):
        # Runs the selected Hub's application half end to end: the services the
        # ceremony selected, then the enrolled Hub with its coreHub identity,
        # message and Work sessions, then ping. The native kernel operator
        # (NativeCoreContext) is outside this test; it needs an installed client.
        import signal
        import sys
        for root in (REPOSITORY / 'dashboard', REPOSITORY / 'taskmgmt'):
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
        from application_service_host import ApplicationServiceHost
        from identity.application_service_selection import ApplicationServiceSelection
        install = Installation(self.runtime)
        result = await install.run()
        core = _read_material(result['coreHub']['selection'], max_bytes=16384)
        raw = _read_material(install.enrollment / 'service-selection.json', max_bytes=1048576, return_bytes=True)
        selection = ApplicationServiceSelection(raw)
        host = ApplicationServiceHost(selection, browser_port=selection.local_browser_port())
        env = {**os.environ, 'AGENTMUX_HOME': core['home']}
        arguments = []
        for flag, family in (('--selection', 'identity'), ('--message-selection', 'messages'),
                             ('--work-selection', 'work')):
            for pin in core[family]:
                arguments += [flag, pin['selection']]
        # The startup deadline is the child's own monotonic clock.
        start = ('import sys, time\nfrom hub.enrolled_hub_bootstrap import main\n'
                 "raise SystemExit(main(['--startup-deadline', str(time.monotonic() + 30)] + sys.argv[1:]))")
        hub = attestor = None
        try:
            await asyncio.wait_for(host.start(), 60)
            attestor = RuntimeAttestor(install.enrollment)
            receipt = await attestor.start()
            self.assertIsNotNone(receipt, 'identity service did not answer the runtime observation')
            self.assertNotIn('error', receipt)
            log = open(install.base / 'hub.log', 'wb')
            hub = subprocess.Popen([sys.executable, '-c', start, *arguments], cwd=REPOSITORY, env=env,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            socket = Path(core['home']) / 'hub' / 'hub.sock'
            deadline = time.monotonic() + 45
            while not socket.is_socket() and hub.poll() is None and time.monotonic() < deadline:
                await asyncio.sleep(0.2)
            if hub.poll() is not None:
                self.fail('enrolled Hub exited during startup: %r' % (install.base / 'hub.log').read_bytes()[-2000:])
            self.assertTrue(socket.is_socket(), 'enrolled Hub did not open its socket')
            ping = await asyncio.to_thread(subprocess.run,
                [sys.executable, '-c', "from hub import cli; cli.main(['--json', 'ping'])"],
                cwd=REPOSITORY, env=env, capture_output=True, timeout=30)
            self.assertEqual(ping.returncode, 0, (ping.stderr[-2000:], (install.base / 'hub.log').read_bytes()[-4000:]))
            self.assertIn('pong', strict_loads(ping.stdout))
        finally:
            if hub is not None:
                if hub.poll() is None:
                    hub.send_signal(signal.SIGTERM)
                try:
                    await asyncio.to_thread(hub.wait, 30)
                except subprocess.TimeoutExpired:
                    hub.kill()
                    hub.wait()
                log.close()
            if attestor is not None:
                await attestor.close()
            await host.close()
        self.assertIn(hub.returncode, (0, 130), 'enrolled Hub did not stop cleanly')

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

    async def test_hub_database_holds_every_default_plugin_schema(self):
        install = Installation(self.runtime)
        await install.run()
        self.assertHubDatabaseComplete(install.home / 'hub' / 'hub.db')

    async def test_damaged_hub_database_is_repaired_on_rerun(self):
        # Review item 3: a finished enrollment whose hub.db lost its private mode
        # or a plugin table (or predates the plugin tables) is completed on rerun.
        import sqlite3
        install = Installation(self.runtime)
        first = await install.run()
        path = install.home / 'hub' / 'hub.db'
        database = sqlite3.connect(path)
        database.execute('DROP TABLE p_board_cards')
        database.close()
        path.chmod(0o644)
        self.assertEqual(await install.run(), first)
        self.assertHubDatabaseComplete(path)

    async def test_interrupted_hub_database_is_completed_on_rerun(self):
        # Review item 3: an interruption after SQLite created hub.db but before
        # the plugin tables leaves a file the next run must complete, not keep.
        class Interrupted:
            def __iter__(self):
                raise RuntimeError('interrupted before plugin tables')
        install = Installation(self.runtime)
        with mock.patch.object(local_enrollment, 'DEFAULT_PLUGINS', Interrupted()):
            with self.assertRaises(RuntimeError):
                await install.run()
        self.assertTrue((install.home / 'hub' / 'hub.db').exists())
        await install.run()
        self.assertHubDatabaseComplete(install.home / 'hub' / 'hub.db')

    async def test_profiles_on_one_runtime_never_share_a_reply_prefix(self):
        # Review item 1: every profile on a runtime uses the same account, so a
        # shared reply prefix would deliver one profile's replies to another's.
        def prefixes(value):
            if isinstance(value, dict):
                return {v for k, v in value.items() if k == 'replyPrefix'} | {
                    p for v in value.values() for p in prefixes(v)}
            if isinstance(value, list):
                return {p for v in value for p in prefixes(v)}
            return set()
        seen = set()
        for _ in range(2):
            install = Installation(self.runtime)
            await install.run()
            materials = _read_material(install.enrollment / 'materials.json', max_bytes=1048576)
            found = prefixes(materials)
            # Three owners, two storage receivers, the attestor and five client sessions.
            self.assertEqual(len(found), 11)
            self.assertFalse(found & seen, found & seen)
            seen |= found

    def assertHubDatabaseComplete(self, path):
        # A selected Work Hub opens hub.db only when it is owner-private and each
        # default federation plugin's tables, triggers and indexes already exist.
        import importlib, re, sqlite3
        from hub.fed.config import DEFAULT_PLUGINS
        from hub.store import APP_ID, MIGRATIONS, Store
        self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
        Store.open_existing(str(path), application_id=APP_ID, user_version=len(MIGRATIONS),
                            owner_uid=os.getuid()).db.close()
        database = sqlite3.connect(Path(path).as_uri() + '?mode=ro', uri=True)
        try:
            self.assertEqual(database.execute('PRAGMA application_id').fetchone()[0], APP_ID)
            self.assertEqual(database.execute('PRAGMA user_version').fetchone()[0], len(MIGRATIONS))
            for name in DEFAULT_PLUGINS:
                for statement in importlib.import_module('hub.fed.plugins.' + name).PLUGIN.tables:
                    kind, declared = re.match(r'\s*CREATE\s+(?:VIRTUAL\s+)?(TABLE|TRIGGER|INDEX)\s+'
                        r'(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\b', statement, re.I).groups()
                    self.assertIsNotNone(database.execute('SELECT 1 FROM sqlite_schema WHERE type=? AND name=?',
                                                          (kind.lower(), declared)).fetchone(), (name, declared))
        finally:
            database.close()

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
        # Review item 9: the old dashboard's port 8787 is never a selectable port.
        for changed in ({'port': 1023}, {'port': 65536}, {'port': '9000'}, {'port': port, 'host': '0.0.0.0'}, {},
                        {'port': local_enrollment.LEGACY_BROWSER_PORT}):
            with self.subTest(localBrowser=changed), self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(dict(selection, localBrowser=changed)))
        from application_service_host import ApplicationServiceHost
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_configuration'):
            ApplicationServiceHost(ApplicationServiceSelection(canonical_bytes(selection)),
                                   browser_port=local_enrollment.LEGACY_BROWSER_PORT)
        without = {k: v for k, v in selection.items() if k != 'localBrowser'}
        self.assertIsNone(ApplicationServiceSelection(canonical_bytes(without)).local_browser_port())

    async def test_private_browser_port_avoids_temporary_range_and_retained_ports(self):
        # Review item 8: a retained port from the temporary range can be taken
        # by any outgoing connection while its installation is stopped, and a
        # second profile could pick a stopped profile's retained port.
        first = Installation(self.runtime)
        await first.run()
        kept = _read_material(first.enrollment / 'service-selection.json', max_bytes=1048576)['localBrowser']['port']
        temporary = int(subprocess.run(['sysctl', '-n', 'net.inet.ip.portrange.first'],
                                       capture_output=True, text=True, check=True).stdout)
        self.assertLess(kept, min(temporary, 32768))
        second = Installation(self.runtime, hostPort=4334)
        ceremony = local_enrollment.Ceremony(*local_enrollment.admit_request(str(second.request_path),
                                                                              second.request_digest), root=first.base)
        try:
            picks = {ceremony.local_browser_port() for _ in range(200)}
            self.assertTrue(all(port < min(temporary, 32768) for port in picks), sorted(picks)[-3:])
            # The retained port of the stopped first profile is never offered again.
            offset = local_enrollment.PRIVATE_PORTS.index(kept)
            size = len(local_enrollment.PRIVATE_PORTS)
            with mock.patch.object(local_enrollment.secrets, 'randbelow',
                                   side_effect=[offset] + [(offset + n) % size for n in range(1, 64)]):
                self.assertNotEqual(ceremony.local_browser_port(), kept)
        finally:
            ceremony.account.wipe()

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
