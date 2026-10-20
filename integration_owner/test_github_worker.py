"""Offline signed-owner tests for the managed native GitHub worker.

All process calls and thread handoffs are replaced with bounded synthetic results.
No GitHub account, network connection or native credential is used here.
"""
import asyncio
import copy
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from integration_owner import test_admission, test_commands
from integration_owner.github_worker import (_capture_process, GithubProcessResult,
    github_enrollment_bytes, load_github_enrollment, pin_github_client,
    write_github_enrollment, GithubCredentialResolver)
from integration_owner.receiver import IntegrationOwner
from integration_owner.test_intent import payload
from state_owner.artifacts import OwnerArtifacts
from state_owner.test_artifacts import JS as ArtifactJS, Store as ArtifactStore


class GithubWorkerTests(unittest.IsolatedAsyncioTestCase):
    resign = test_admission.AdmissionTests.resign
    execute = test_admission.AdmissionTests.execute
    command = test_commands.CommandTests.command

    def setUp(self):
        test_admission.AdmissionTests.setUp(self)
        fixture = tempfile.TemporaryDirectory(prefix='agentmux-github-worker-offline-')
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name).resolve()
        self.binary = self.root / 'gh'
        self.binary.write_bytes(b'fixture executable; never run')
        self.binary.chmod(0o700)
        self.config_dir = self.root / 'gh-config'
        self.config_dir.mkdir(mode=0o700)
        self.hosts = self.config_dir / 'hosts.yml'
        self.hosts.write_text('synthetic native store; never read')
        self.hosts.chmod(0o600)
        self.reference = payload()['credentialRef']
        pin = pin_github_client(self.reference, executable=self.binary, config_dir=self.config_dir)
        self.resolver = GithubCredentialResolver(self.reference, executable=self.binary,
            config_dir=self.config_dir, client_pin=pin)
        self.calls = []
        self.results = []
        def run(argv, stdin, environment, cwd):
            self.calls.append((argv, {'input': stdin, 'env': environment, 'cwd': cwd}))
            result = self.results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        process_patch = patch('integration_owner.github_worker._capture_process', new=run)
        process_patch.start()
        self.addCleanup(process_patch.stop)
        async def inline(function, *args, **kwargs):
            return function(*args, **kwargs)
        thread_patch = patch('integration_owner.github_worker.asyncio.to_thread', new=inline)
        thread_patch.start()
        self.addCleanup(thread_patch.stop)

    async def configure(self, proposal, *, artifacts=None):
        self.envelope['payload'] = proposal
        digest = payload_digest(proposal)
        self.envelope['operation']['payloadDigest'] = digest
        self.record['state']['approvals'][0]['payloadDigest'] = digest
        self.resign()
        await self.owner.close()
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='github', credential_ref=self.reference, artifacts=artifacts,
            credentials=self.resolver)
        self.addAsyncCleanup(self.owner.close)

    def repo(self):
        return {**payload(), 'action': 'github-repo-create',
            'target': {'owner': 'Exact-Owner', 'name': 'Exact_Repo.Name', 'visibility': 'private'},
            'contentRef': None}

    async def issue(self):
        raw = canonical_bytes({'title': 'Approved title', 'body': 'Approved body', 'labels': ['bug']})
        store = ArtifactStore()
        artifacts = OwnerArtifacts(store, ArtifactJS(store), bucket='bucket', owner_hub_id='hub-one',
            store_ref={'id': 'store-one', 'ownerHubId': 'hub-one', 'revision': 1}, max_bytes=60000)
        content_ref = await artifacts.upload(raw,
            media_type='application/vnd.agentmux.integration-content+json')
        proposal = {**payload(), 'action': 'github-issue-create',
            'target': {'repository': 'Exact-Owner/Exact_Repo.Name'}, 'contentRef': content_ref}
        return proposal, artifacts

    async def complete(self):
        initial = await self.execute()
        digest = initial.original_payload_digest
        self.command('integration-attempt-start', 'attempt-one', 1, digest)
        original_start = copy.deepcopy(self.envelope)
        self.assertEqual((await self.execute()).status, 'dispatch-claimed')
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        reply = await self.execute()
        return digest, original_start, reply

    async def test_signed_repo_create_uses_pinned_client_and_retains_exact_ack(self):
        await self.configure(self.repo())
        self.results.append(GithubProcessResult(0,
            b'https://github.com/exact-owner/exact_repo.name\n', None))
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic-private',
                                     'GITHUB_TOKEN': 'synthetic-private'}, clear=False):
            _, _, reply = await self.complete()
        self.assertEqual(reply.status, 'applied')
        state = strict_loads(self.js.messages[-1].data)['state']
        self.assertEqual(state['observation']['identity'],
            {'repository': 'Exact-Owner/Exact_Repo.Name'})
        argv, options = self.calls[0]
        self.assertEqual(argv, [str(self.binary.resolve()), 'repo', 'create',
            'github.com/Exact-Owner/Exact_Repo.Name', '--private'])
        self.assertEqual(options['input'], b'')
        self.assertEqual(options['cwd'], str(self.config_dir.resolve()))
        self.assertEqual(options['env']['GH_CONFIG_DIR'], str(self.config_dir.resolve()))
        for name in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
            self.assertNotIn(name, options['env'])

    async def test_signed_issue_create_keeps_body_on_stdin_and_validates_issue_number(self):
        proposal, artifacts = await self.issue()
        await self.configure(proposal, artifacts=artifacts)
        self.results.append(GithubProcessResult(0,
            b'https://github.com/Exact-Owner/Exact_Repo.Name/issues/17\n', None))
        _, _, reply = await self.complete()
        self.assertEqual(reply.status, 'applied')
        state = strict_loads(self.js.messages[-1].data)['state']
        self.assertEqual(state['observation']['identity'],
            {'repository': 'Exact-Owner/Exact_Repo.Name', 'issueNumber': 17})
        argv, options = self.calls[0]
        self.assertEqual(argv[1:3], ['issue', 'create'])
        self.assertNotIn('Approved body', argv)
        self.assertEqual(options['input'], b'Approved body')

    async def test_lost_repo_reply_reconciles_read_only_and_replay_never_writes_again(self):
        await self.configure(self.repo())
        self.results.extend([GithubProcessResult(None, b'', 'timeout'),
            GithubProcessResult(0, json.dumps({
                'nameWithOwner': 'exact-owner/exact_repo.name'}).encode(), None)])
        digest, original_start, reply = await self.complete()
        self.assertEqual(reply.status, 'reconciliation-required')
        uncertain = strict_loads(self.js.messages[-1].data)['state']['observation']
        self.assertEqual(uncertain['kind'], 'uncertain')
        self.assertFalse(uncertain['retryAllowed'])
        self.command('integration-effect-reconcile', 'reconcile-one', 3, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        reconciled = strict_loads(self.js.messages[-1].data)['state']['observation']
        self.assertEqual(reconciled['identity'], {
            'presence': 'present', 'resourceId': 'Exact-Owner/Exact_Repo.Name'})
        self.envelope = original_start
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        writes = [call for call in self.calls if call[0][1:3] == ['repo', 'create']]
        reads = [call for call in self.calls if call[0][1:3] == ['repo', 'view']]
        self.assertEqual((len(writes), len(reads)), (1, 1))

    async def test_lost_issue_reply_has_no_guessed_read_or_automatic_retry(self):
        proposal, artifacts = await self.issue()
        await self.configure(proposal, artifacts=artifacts)
        self.results.append(GithubProcessResult(None, b'', 'timeout'))
        digest, original_start, reply = await self.complete()
        self.assertEqual(reply.status, 'reconciliation-required')
        self.command('integration-effect-reconcile', 'reconcile-one', 3, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        observed = strict_loads(self.js.messages[-1].data)['state']['observation']
        self.assertEqual(observed['identity'], {
            'presence': 'unavailable', 'resourceId': 'Exact-Owner/Exact_Repo.Name'})
        self.envelope = original_start
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.assertEqual(len(self.calls), 1)

    async def test_repo_reconciliation_refuses_a_different_repository(self):
        await self.configure(self.repo())
        self.results.extend([GithubProcessResult(None, b'', 'timeout'),
            GithubProcessResult(0, json.dumps({
                'nameWithOwner': 'exact-owner/other-repo'}).encode(), None)])
        digest, _, reply = await self.complete()
        self.assertEqual(reply.status, 'reconciliation-required')
        self.command('integration-effect-reconcile', 'reconcile-one', 3, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        reconciled = strict_loads(self.js.messages[-1].data)['state']['observation']
        self.assertEqual(reconciled['identity'], {
            'presence': 'unavailable', 'resourceId': 'Exact-Owner/Exact_Repo.Name'})
        writes = [call for call in self.calls if call[0][1:3] == ['repo', 'create']]
        reads = [call for call in self.calls if call[0][1:3] == ['repo', 'view']]
        self.assertEqual((len(writes), len(reads)), (1, 1))

    async def test_changed_native_store_before_process_is_not_dispatched(self):
        await self.configure(self.repo())
        entered, release = asyncio.Event(), asyncio.Event()
        async def queued(function, *args, **kwargs):
            entered.set()
            await release.wait()
            return function(*args, **kwargs)
        with patch('integration_owner.github_worker.asyncio.to_thread', new=queued):
            initial = await self.execute()
            digest = initial.original_payload_digest
            self.command('integration-attempt-start', 'attempt-one', 1, digest)
            claim = await self.execute()
            self.assertEqual(claim.status, 'dispatch-claimed')
            await entered.wait()
            self.hosts.write_text('changed native store metadata')
            release.set()
            self.command('integration-attempt-complete', 'complete-one', 2, digest)
            complete = await self.execute()
        self.assertEqual(complete.status, 'not-dispatched')
        self.assertEqual(self.calls, [])

    async def test_missing_client_at_process_start_is_not_dispatched_once(self):
        await self.configure(self.repo())
        self.results.append(GithubProcessResult(None, b'', 'not-started'))
        _, original_start, reply = await self.complete()
        self.assertEqual(reply.status, 'not-dispatched')
        observed = strict_loads(self.js.messages[-1].data)['state']['observation']
        self.assertEqual(observed['kind'], 'not-dispatched')
        self.envelope = original_start
        self.assertEqual((await self.execute()).status, 'not-dispatched')
        self.assertEqual(len(self.calls), 1)

    async def test_parent_side_process_start_error_remains_uncertain(self):
        await self.configure(self.repo())
        self.results.append(OSError(errno.EIO, 'private parent-side failure'))
        _, original_start, reply = await self.complete()
        self.assertEqual(reply.status, 'reconciliation-required')
        observed = strict_loads(self.js.messages[-1].data)['state']['observation']
        self.assertEqual(observed['kind'], 'uncertain')
        self.envelope = original_start
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.assertEqual(len(self.calls), 1)

    async def test_output_limit_is_uncertain_and_private_output_is_not_retained(self):
        await self.configure(self.repo())
        self.results.append(GithubProcessResult(-9, b'private-output' * 400, 'output-limit'))
        _, _, reply = await self.complete()
        self.assertEqual(reply.status, 'reconciliation-required')
        retained = self.js.messages[-1].data
        self.assertNotIn(b'private-output', retained)
        self.assertEqual(strict_loads(retained)['state']['observation']['kind'], 'uncertain')

    def test_pin_uses_metadata_and_refuses_changed_or_wrong_native_namespace(self):
        client = self.resolver.resolve(self.reference)
        self.assertEqual(repr(client), '<PrivateGithubClient private; native credentials>')
        self.hosts.write_text('changed native store metadata')
        with self.assertRaisesRegex(ContractError, 'integration_credential_changed'):
            self.resolver.resolve(self.reference)
        with self.assertRaises(ContractError):
            self.resolver.resolve({**self.reference, 'revision': 2})

    def test_new_or_changed_config_yml_refuses_the_enrolled_native_namespace(self):
        settings = self.config_dir / 'config.yml'
        settings.write_text('http_unix_socket: /private/unapproved.sock')
        settings.chmod(0o600)
        with self.assertRaisesRegex(ContractError, 'integration_credential_changed'):
            self.resolver.resolve(self.reference)
        pin = pin_github_client(self.reference, executable=self.binary, config_dir=self.config_dir)
        resolver = GithubCredentialResolver(self.reference, executable=self.binary,
            config_dir=self.config_dir, client_pin=pin)
        settings.write_text('http_unix_socket: /private/changed.sock')
        with self.assertRaisesRegex(ContractError, 'integration_credential_changed'):
            resolver.resolve(self.reference)

    def test_private_enrollment_round_trip_never_reads_or_copies_native_credentials(self):
        raw = github_enrollment_bytes(self.resolver._pin)
        self.assertNotIn(self.hosts.read_bytes(), raw)
        restored = load_github_enrollment(raw, credential_ref=self.reference)
        self.assertEqual(restored._pin, self.resolver._pin)
        destination = self.root / 'github-enrollment.json'
        digest = write_github_enrollment(destination, self.resolver._pin)
        self.assertRegex(digest, r'^sha256:[a-f0-9]{64}$')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            write_github_enrollment(destination, self.resolver._pin)

    def test_private_enrollment_refuses_changed_store_or_reference(self):
        raw = github_enrollment_bytes(self.resolver._pin)
        self.hosts.write_text('changed native store metadata')
        with self.assertRaisesRegex(ContractError, 'integration_enrollment_unavailable'):
            load_github_enrollment(raw, credential_ref=self.reference)
        with self.assertRaisesRegex(ContractError, 'integration_enrollment_unavailable'):
            load_github_enrollment(raw, credential_ref={**self.reference, 'revision': 2})

    async def test_cancelled_completion_keeps_original_process_owner_until_joined(self):
        await self.configure(self.repo())
        self.results.append(GithubProcessResult(0,
            b'https://github.com/Exact-Owner/Exact_Repo.Name\n', None))
        entered, release = asyncio.Event(), asyncio.Event()
        async def queued(function, *args, **kwargs):
            entered.set()
            await release.wait()
            return function(*args, **kwargs)
        with patch('integration_owner.github_worker.asyncio.to_thread', new=queued):
            initial = await self.execute()
            digest = initial.original_payload_digest
            self.command('integration-attempt-start', 'attempt-one', 1, digest)
            self.assertEqual((await self.execute()).status, 'dispatch-claimed')
            await entered.wait()
            original = self.owner._worker._tasks['attempt-one']
            self.command('integration-attempt-complete', 'complete-one', 2, digest)
            completion = asyncio.create_task(self.execute())
            await asyncio.sleep(0)
            completion.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await completion
            self.assertIs(self.owner._worker._tasks['attempt-one'], original)
            self.assertFalse(original.done())
            release.set()
            self.assertEqual((await self.execute()).status, 'applied')
        self.assertTrue(original.done())
        self.assertEqual(len(self.calls), 1)


class _Pipe:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.closed = False
        self.written = b''

    def fileno(self):
        return self.descriptor

    def write(self, value):
        self.written += value

    def close(self):
        self.closed = True


class _Process:
    def __init__(self):
        self.pid = 417
        self.stdin, self.stdout = _Pipe(10), _Pipe(11)
        self.returncode = None
        self.waits = []

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class _Selector:
    def __init__(self, ready=True):
        self.keys = {}
        self.ready = ready
        self.closed = False

    def register(self, stream, _event, data):
        self.keys[stream.fileno()] = SimpleNamespace(fileobj=stream, data=data)

    def get_map(self):
        return self.keys

    def select(self, _timeout):
        return [] if not self.ready else [(key, None) for key in list(self.keys.values())]

    def unregister(self, stream):
        del self.keys[stream.fileno()]

    def close(self):
        self.closed = True


class GithubProcessCaptureTests(unittest.TestCase):
    def capture(self, chunks, clocks, *, stdin=b'body', ready=True, write_limit=None):
        process, selector = _Process(), _Selector(ready=ready)
        killed = []
        def read(*_args):
            return chunks.pop(0)
        def write(_descriptor, data):
            count = len(data) if write_limit is None else min(write_limit, len(data))
            process.stdin.written += bytes(data[:count])
            return count
        def killpg(pid, sig):
            killed.append((pid, sig))
            process.returncode = -9
        result = _capture_process(['/fixture/gh'], stdin, {}, '/fixture',
            popen=lambda *_args, **_kwargs: process, selector_factory=lambda: selector,
            clock=lambda: clocks.pop(0), read=read, killpg=killpg,
            set_blocking=lambda *_args: None, write=write)
        return result, process, selector, killed

    def test_noisy_output_is_bounded_and_original_process_is_reaped(self):
        result, process, selector, killed = self.capture([b'x' * 4096, b'y'], [0, 0, 0])
        self.assertEqual((result.failure, len(result.stdout)), ('output-limit', 4097))
        self.assertEqual(killed, [(417, 9)])
        self.assertEqual(process.stdin.written, b'body')
        self.assertTrue(process.stdin.closed and process.stdout.closed and selector.closed)
        self.assertEqual(process.returncode, -9)

    def test_exact_missing_executable_is_known_not_started(self):
        error = FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), '/missing/gh')
        result = _capture_process(['/missing/gh'], b'body', {}, '/fixture',
            popen=Mock(side_effect=error))
        self.assertEqual(result, GithubProcessResult(None, b'', 'not-started'))

    def test_other_constructor_os_error_is_not_classified_as_not_started(self):
        error = OSError(errno.EIO, 'private parent-side failure')
        with self.assertRaises(OSError) as raised:
            _capture_process(['/fixture/gh'], b'body', {}, '/fixture',
                popen=Mock(side_effect=error))
        self.assertIs(raised.exception, error)

    def test_timeout_reaps_original_process_and_closes_reader(self):
        result, process, selector, killed = self.capture([], [0, 0, 46], ready=False)
        self.assertEqual((result.failure, result.stdout), ('timeout', b''))
        self.assertEqual(killed, [(417, 9)])
        self.assertTrue(process.stdin.closed and process.stdout.closed and selector.closed)
        self.assertEqual(process.returncode, -9)

    def test_accepted_32000_byte_stdin_uses_partial_nonblocking_writes(self):
        body = ('\U0001f600' * 8000).encode('utf-8')
        result, process, selector, killed = self.capture([b''], [0] * 12,
            stdin=body, write_limit=4096)
        self.assertEqual(result, GithubProcessResult(0, b'', None, 32000))
        self.assertEqual(process.stdin.written, body)
        self.assertEqual(killed, [])
        self.assertTrue(process.stdin.closed and process.stdout.closed and selector.closed)

    def test_child_that_never_reads_stdin_is_killed_at_same_deadline(self):
        body = ('\U0001f600' * 8000).encode('utf-8')
        result, process, selector, killed = self.capture([], [0, 0, 46],
            stdin=body, ready=False)
        self.assertEqual((result.failure, process.stdin.written), ('timeout', b''))
        self.assertEqual(killed, [(417, 9)])
        self.assertTrue(process.stdin.closed and process.stdout.closed and selector.closed)


@unittest.skipUnless(os.environ.get('AGENTMUX_RUN_NATIVE_GITHUB_WORKER_TEST') == '1',
                     'serialized native GitHub worker slot not selected')
class GithubNativeProcessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix='agentmux-github-process-native-')
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name).resolve()

    def command(self, name, source):
        pid = self.root / (name + '.pid')
        return [sys.executable, '-c', source, str(pid)], pid

    def assert_reaped(self, pid_path):
        pid = int(pid_path.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def blocked_pipe_popen(self, arguments, **options):
        read_descriptor, write_descriptor = os.pipe()
        try:
            os.set_blocking(write_descriptor, False)
            while True:
                try:
                    os.write(write_descriptor, b'x' * 65536)
                except BlockingIOError:
                    break
            process = subprocess.Popen(arguments, stdin=read_descriptor,
                stdout=options['stdout'], stderr=options['stderr'], shell=options['shell'],
                start_new_session=options['start_new_session'], cwd=options['cwd'],
                env=options['env'])
            process.stdin = os.fdopen(write_descriptor, 'wb', buffering=0)
            write_descriptor = None
            return process
        finally:
            os.close(read_descriptor)
            if write_descriptor is not None:
                os.close(write_descriptor)

    def test_accepted_32000_bytes_cannot_block_past_deadline(self):
        arguments, pid = self.command('stdin',
            'import os,sys,time; open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(30)')
        body = ('\U0001f600' * 8000).encode('utf-8')
        with patch('integration_owner.github_worker.PROCESS_TIMEOUT', 0.4):
            result = _capture_process(arguments, body, dict(os.environ), str(self.root),
                popen=self.blocked_pipe_popen)
        self.assertEqual(result.failure, 'timeout')
        self.assertLess(result.stdin_bytes, len(body))
        self.assert_reaped(pid)

    def test_stdout_overflow_kills_and_reaps_original_child(self):
        arguments, pid = self.command('stdout',
            'import os,sys,time; open(sys.argv[1], "w").write(str(os.getpid())); '
            'sys.stdout.buffer.write(b"x" * 8192); sys.stdout.buffer.flush(); time.sleep(30)')
        with patch('integration_owner.github_worker.PROCESS_TIMEOUT', 1.0):
            result = _capture_process(arguments, b'', dict(os.environ), str(self.root))
        self.assertEqual((result.failure, len(result.stdout)), ('output-limit', 4097))
        self.assert_reaped(pid)

    def test_silent_timeout_kills_and_reaps_original_child(self):
        arguments, pid = self.command('timeout',
            'import os,sys,time; open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(30)')
        with patch('integration_owner.github_worker.PROCESS_TIMEOUT', 0.3):
            result = _capture_process(arguments, b'', dict(os.environ), str(self.root))
        self.assertEqual(result.failure, 'timeout')
        self.assert_reaped(pid)

    async def test_cancelled_waiter_keeps_original_owner_until_child_is_reaped(self):
        arguments, pid = self.command('cancel',
            'import os,sys,time; open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(30)')
        with patch('integration_owner.github_worker.PROCESS_TIMEOUT', 0.5):
            original = asyncio.create_task(asyncio.to_thread(
                _capture_process, arguments, b'', dict(os.environ), str(self.root)))
            for _ in range(100):
                if pid.is_file():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(pid.is_file())
            waiter = asyncio.create_task(self.wait_for_original(original))
            await asyncio.sleep(0)
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            self.assertFalse(original.cancelled())
            result = await original
        self.assertEqual(result.failure, 'timeout')
        self.assert_reaped(pid)

    async def wait_for_original(self, original):
        return await asyncio.shield(original)


if __name__ == '__main__':
    unittest.main()
