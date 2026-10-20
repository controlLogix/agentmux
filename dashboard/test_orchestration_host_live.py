"""Native application-process lifecycle using the existing private TLS fixture."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import platform
import secrets
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import nkeys
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from application_service_host import ApplicationServiceHost
from capability_owner.test_live import LiveCapabilityTests
from identity.application_service_selection import (
    ApplicationServiceSelection, write_application_service_selection,
    load_application_service_selection)
from identity.local_browser_session import LocalBrowserContext, _CONTEXT_BRAND
from identity.test_application_service_selection import protected_host
from native_security.nats_credentials import service_policy, validate_service
from state_owner.ledger import OwnerLedger, StreamIdentity, owner_subject
from tests.storage.run import Broker
from test_orchestration_host import OrchestrationHostTests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'platform/launcher/testdata'))
from installed_broker_helpers import user_credential, close_client


class NativeCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_pipe_and_connection_failure_do_not_skip_later_cleanup(self):
        fixture = NativeOrchestrationHostTests()
        pipe = SimpleNamespace(is_closing=lambda: True,
            wait_closed=AsyncMock(side_effect=BrokenPipeError()))
        process = SimpleNamespace(stdin=pipe, wait=AsyncMock(return_value=1))
        errors = asyncio.create_task(asyncio.sleep(0))
        with tempfile.TemporaryFile() as lease:
            fixture.children = [(process, errors, os.dup(lease.fileno()))]
            fixture.connections = [object(), object()]
            fixture.broker = SimpleNamespace(stop=Mock())
            fixture.fixture = SimpleNamespace(temp=SimpleNamespace(_finalizer=Mock()),
                probe=SimpleNamespace(tmp=SimpleNamespace(_finalizer=Mock())))
            with patch(__name__ + '.close_client',
                       new=AsyncMock(side_effect=[OSError('fixture failure'), None])) as close:
                with self.assertRaises(ExceptionGroup):
                    await fixture.cleanup()
                self.assertEqual(close.await_count, 2)
            fixture.broker.stop.assert_called_once()
            self.assertTrue(errors.done())

    async def test_failed_child_creation_closes_original_lease(self):
        fixture = NativeOrchestrationHostTests()
        with tempfile.TemporaryDirectory() as directory:
            fixture.directory = Path(directory)
            original_close = os.close
            closed = []
            def close(fd):
                closed.append(fd)
                original_close(fd)
            with patch('asyncio.create_subprocess_exec', new=AsyncMock(side_effect=OSError())), \
                    patch('os.close', new=close):
                with self.assertRaises(OSError):
                    await fixture.launch(1)
            self.assertEqual(len(closed), 1)
            with self.assertRaises(OSError):
                os.fstat(closed[0])


class NativeOrchestrationHostTests(unittest.IsolatedAsyncioTestCase):
    _configure_tls_and_users = LiveCapabilityTests._configure_tls_and_users
    start_tls_broker = LiveCapabilityTests.start_tls_broker
    connect = LiveCapabilityTests.connect
    read_contract = 'task-inspect'
    boundary_checks = False
    broker_stream_limit = 4
    broker_disk_storage = '80m'

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_TASK_LIVE') != '1':
            raise RuntimeError('A coordinated native live slot is required')
        if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
            raise RuntimeError('Native macOS ARM64 is required')

    async def asyncSetUp(self):
        self.fixture = OrchestrationHostTests()
        self.fixture.setUp()
        self.value = self.fixture.value
        self.directory = self.fixture.root / 'native-broker'
        self.directory.mkdir(mode=0o700)
        self.connections = []
        self.errors, self.permission_events = {}, {}
        self.children = []
        self.broker = Broker(self.directory)
        self.addAsyncCleanup(self.cleanup)
        self.inbox_prefixes = {role: '_INBOX.' + secrets.token_hex(16)
            for role in ('identity', 'storage', 'host', 'other-scope', 'provisioner')}
        self.subjects = {'IDENTITY': owner_subject(self.fixture.selection.binding('identity'))}
        self.identity_subject = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        self.read_subject = 'amx.v1.h.hub-one.o.org-one.p._.w._.task.task-one.command'
        self.other_subject = 'amx.v1.h.hub-one.o.other-org.p._.w._.task.task-one.command'
        self._configure_tls_and_users()
        admin = await self.start_tls_broker()
        self.admin = admin
        # Reuse the fixture account owner only for explicit test enrollment.
        account = None
        for path in (self.directory / 'nsc-keys').rglob('*.nk'):
            candidate = nkeys.from_seed(path.read_bytes().strip())
            if candidate.public_key.decode() == self.account_public_key:
                account = candidate
                break
            candidate.wipe()
        self.assertIsNotNone(account)
        try:
            for role in ('identity', 'definitions', 'orchestration'):
                selected = self.value[role]
                selected['connection'].update(endpoint=self.broker.url,
                    serverName=self.server_name, rootsPEM=self.ca_file.read_text(),
                    leafCertificateSHA256=self.leaf_digest, jetstreamDomain=None)
                inputs = self.fixture.selection.service_policy_inputs(role)
                inputs['jetstream_domain'] = None
                policy = service_policy(**inputs)
                raw = user_credential(account, policy.publish_subjects,
                    policy.subscribe_subjects, response=policy.response_permissions)
                path = Path(selected['credentials']['path'])
                path.write_bytes(raw)
                selected['credentials'].update(accountPublicKey=self.account_public_key,
                    sha256='sha256:' + hashlib.sha256(raw).hexdigest())
                admitted = validate_service(raw, account_public_key=self.account_public_key, **inputs)
                selected['credentials']['userPublicKey'] = admitted.public_key
                retention = self.fixture.selection.retention(role)
                binding = self.fixture.selection.binding(role)
                info = await admin.jetstream().add_stream(retention.stream_config(
                    stream=selected['ledger']['stream'], subject=owner_subject(binding)))
                selected['ledger']['streamIdentity'] = {
                    'created': info.created.isoformat().replace('+00:00', 'Z'),
                    'minimumSequence': 0}
            await admin.jetstream().create_object_store(bucket='bucket', max_bytes=67_108_864)
        finally:
            account.wipe()
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        self.identity_ledger = OwnerLedger(admin.jetstream(), stream='IDENTITY',
            subject=owner_subject(self.selection.binding('identity')),
            binding=self.selection.binding('identity'),
            retention=self.selection.retention('identity'),
            stream_identity=self.selection.stream_identity('identity'))
        await self.identity_ledger.append(self.fixture.record, expected_sequence=0)
        self.receipt = write_application_service_selection(self.fixture.path, self.value)

    async def cleanup(self):
        failures = []
        for process, errors, lease in self.children:
            try:
                if not process.stdin.is_closing():
                    process.stdin.close()
            except Exception as error:
                failures.append(error)
            original_wait = asyncio.create_task(process.wait())
            try:
                await asyncio.wait_for(asyncio.shield(original_wait), 15)
            except TimeoutError:
                # Keep this exact join and all borrowed broker resources alive.
                # A slow drain is never permission to replace or abandon it.
                print('Native host cleanup pending; original child and broker retained.',
                      flush=True)
                await asyncio.shield(original_wait)
            for join in (errors, process.stdin.wait_closed()):
                try:
                    await join
                except (BrokenPipeError, ConnectionResetError):
                    # An already joined refusal may close its input first.
                    pass
                except Exception as error:
                    failures.append(error)
            try:
                os.close(lease)
            except Exception as error:
                failures.append(error)
        for connection in reversed(self.connections):
            try:
                await close_client(connection)
            except Exception as error:
                failures.append(error)
        try:
            self.broker.stop()
        except Exception as error:
            failures.append(error)
        # Keep the private enrollment, keys, histories and broker data for review.
        self.fixture.temp._finalizer.detach()
        self.fixture.probe.tmp._finalizer.detach()
        if failures:
            raise ExceptionGroup('Native fixture cleanup failed', failures)

    async def launch(self, number):
        lease_path = self.directory / f'lease-{number}'
        lease = os.open(lease_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        code = (
            'import os,sys; fd=int(sys.argv[1]); '
            'os.dup2(fd,3); '
            'from application_service_process import main; sys.exit(main())')
        try:
            process = await asyncio.create_subprocess_exec(sys.executable, '-B', '-c',
                code, str(lease), pass_fds=(lease,),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
        except BaseException:
            os.close(lease)
            raise
        errors = asyncio.create_task(process.stderr.read())
        self.children.append((process, errors, lease))
        packet = dict(schemaVersion='1.0.0', kind='application-services-start',
            lifetimeId='service_' + secrets.token_hex(16),
            selection=str(self.fixture.path), selectionSHA256=self.receipt.digest,
            hostPolicy=self.value['hostPolicy'], ownerUid=os.getuid(),
            workspaces=self.value['workspaces'], kernelScope=self.value['kernelScope'],
            protectedHostAccount=protected_host(), leaseFd=3)
        process.stdin.write(canonical_bytes(packet) + b'\n')
        await process.stdin.drain()
        return process, packet, errors

    async def state(self, process, packet, expected):
        raw = await asyncio.wait_for(process.stdout.readline(), 15)
        self.assertTrue(raw, 'Application process ended before its state packet')
        self.assertEqual(strict_loads(raw), dict(schemaVersion='1.0.0',
            kind='application-services-state', lifetimeId=packet['lifetimeId'],
            selectionSHA256=packet['selectionSHA256'],
            kernelScope=packet['kernelScope'], state=expected))

    async def stop(self, process, packet, errors):
        process.stdin.write(canonical_bytes(dict(schemaVersion='1.0.0',
            kind='application-services-stop', lifetimeId=packet['lifetimeId'])) + b'\n')
        await process.stdin.drain()
        await self.state(process, packet, 'drained')
        self.assertEqual(await asyncio.wait_for(process.wait(), 15), 0)
        self.assertEqual(await errors, b'')

    async def test_native_start_restart_and_current_phase_revocation(self):
        for number in (1, 2):
            process, packet, errors = await self.launch(number)
            await self.state(process, packet, 'ready')
            await self.stop(process, packet, errors)
            self.assertTrue(Path(self.value['orchestration']['ledger']['history']['path']).exists())
            self.assertFalse(Path(self.value['orchestration']['ledger']['checkpoint']['path']).exists())
            self.assertEqual((await self.admin.jetstream().stream_info('ORCHESTRATION')).state.messages, 0)
        # Explicit fixture authority transition, retained at the next revision.
        revoked = copy.deepcopy(self.fixture.record)
        revoked.update(entityVersion=2, previousRevision=1)
        revoked['recordId'] = 'native-revoked-phase'
        revoked['operation'].update(operationId='native-revoked-phase', expectedVersion=1)
        revoked['state']['grants'][-1]['status'] = 'revoked'
        await self.identity_ledger.append(revoked, expected_sequence=1)
        process, packet, errors = await self.launch(3)
        self.assertEqual(await asyncio.wait_for(process.stdout.readline(), 15), b'')
        self.assertNotEqual(await asyncio.wait_for(process.wait(), 15), 0)
        self.assertNotIn(b'ready', await errors)
        self.assertEqual((await self.admin.jetstream().stream_info('ORCHESTRATION')).state.messages, 0)
        print('Native host: two joined starts/stops; current phase revocation refused.')
        print('Private retained fixture:', self.fixture.root)

    async def test_browser_service_replays_real_journal_after_host_restart(self):
        authority = copy.deepcopy(self.fixture.record)
        authority.update(entityVersion=2, previousRevision=1, recordId='browser-test-grant')
        authority['operation'].update(operationId='browser-test-grant', expectedVersion=1)
        grant = copy.deepcopy(authority['state']['grants'][0])
        grant.update(ref=dict(grant['ref'], id='browser-command-grant'),
            contractId='orchestration-command', definitionTarget=None,
            resourceId=self.value['orchestration']['resourceRef']['id'])
        authority['state']['grants'].append(grant)
        await self.identity_ledger.append(authority, expected_sequence=1)
        command = {'command': 'release-for', 'resource': 'src/no-claim.py', 'holder': 'unused-worker'}
        operation = 'browser_' + '7' * 32
        original_receipt = records = None
        for attempt in (1, 2):
            selected = load_application_service_selection(self.fixture.path,
                expected_digest=self.receipt.digest, host_policy=self.value['hostPolicy'],
                owner_uid=os.getuid(), workspaces=self.value['workspaces'],
                kernel_scope=self.value['kernelScope'], protected_host_account=protected_host())
            host = ApplicationServiceHost(selected, browser_port=0)
            try:
                await host.start()
                snapshot = await host._identity.reader.current()
                current = strict_loads(snapshot.record)
                # Exercise the receiving service with a fixture-branded context,
                # not a fabricated possession signature or a claimed browser login.
                context = LocalBrowserContext(canonical_bytes(grant['callerRef']),
                    canonical_bytes(grant['scope']),
                    canonical_bytes(dict(id=current['entityId'], ownerHubId=current['ownerHubId'],
                                         revision=current['entityVersion'])),
                    snapshot.sequence, (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
                    _CONTEXT_BRAND)
                receipt = await host._orchestration.handle_local_browser(
                    context, command, operation_id=operation)
                journal = await host._orchestration.owner._journal._ledger.current()
                current_records = [row.record for row in journal.records]
                self.assertEqual(len(current_records), 3)
                if attempt == 1:
                    # The real adapter refuses the different working directory.
                    # This proves retained refusal replay, not successful domain execution.
                    self.assertEqual(receipt['outcome'], 'not-dispatched')
                    original_receipt, records = receipt, current_records
                else:
                    self.assertEqual(receipt, original_receipt)
                    self.assertEqual(current_records, records)
                    revoked = copy.deepcopy(authority)
                    revoked.update(entityVersion=3, previousRevision=2, recordId='browser-test-revoked')
                    revoked['operation'].update(operationId='browser-test-revoked', expectedVersion=2)
                    revoked['state']['grants'][-1]['status'] = 'revoked'
                    await self.identity_ledger.append(revoked, expected_sequence=2)
                    with self.assertRaises(ContractError):
                        await host._orchestration.handle_local_browser(
                            context, command, operation_id=operation)
                    self.assertEqual([row.record for row in (
                        await host._orchestration.owner._journal._ledger.current()).records], records)
            finally:
                await host.close()
        print('Real TLS journal: original refusal replayed after host restart; revocation denied.')
        print('Private retained fixture:', self.fixture.root)
