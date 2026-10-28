"""Closed native-process protocol and lifetime controls without live transports."""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import nkeys
from agentmux_contracts import canonical_bytes, strict_loads, ContractError
import application_service_process as process


class ProcessProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.packet = {'schemaVersion': '1.0.0', 'kind': 'application-services-start',
            'lifetimeId': 'service_'+'a'*32, 'selection': '/private/services.json',
            'selectionSHA256': 'sha256:'+'b'*64, 'hostPolicy': '/private/host.json',
            'ownerUid': os.getuid(), 'workspaces': ['/private/workspace'],
            'kernelScope': {'hubId':'hub-one'}, 'protectedHostAccount': {'kind':'named-password', 'account':'HOST', 'broker':{
                'endpoint':'tls://127.0.0.1:4222', 'serverName':'kernel_server', 'configSha256':'sha256:'+'c'*64}}, 'leaseFd': 3}
        self.reader = asyncio.StreamReader(limit=65537)
        self.lines = []
        self.host = SimpleNamespace(start=AsyncMock(), close=AsyncMock(), fence=Mock(), check_health=Mock())
        self.writer = SimpleNamespace(write=lambda raw:self.lines.append(strict_loads(raw)), drain=AsyncMock())
        self.selected = SimpleNamespace(policy={'kernelScope': self.packet['kernelScope']},
            oidc_browser_configuration=Mock(return_value=None),
            oidc_device_configuration=Mock(return_value=None),
            local_browser_port=Mock(return_value=49321))
        self.patchers = [patch('application_service_process._lease'),
            patch('application_service_process._release_lease'),
            patch('application_service_process.load_application_service_selection', return_value=self.selected),
            patch('application_service_process.ApplicationServiceHost', return_value=self.host)]
        self.mocks = [patcher.start() for patcher in self.patchers]
        for patcher in self.patchers:
            self.addCleanup(patcher.stop)
        # Tests never write to the developer's system log.
        log = patch('application_service_process.syslog')
        self.log = log.start()
        self.addCleanup(log.stop)
        process._reported = False

    def record(self):
        self.log.syslog.assert_called_once()
        return self.log.syslog.call_args.args

    def start_packet(self):
        self.reader.feed_data(canonical_bytes(self.packet)+b'\n')

    async def test_missing_stale_or_injected_host_description_refuses_before_lease(self):
        import copy
        for change in (lambda p: p.pop('protectedHostAccount'),
                       lambda p: p.update(hostAccountPublicKey='A'+'B'*55),
                       lambda p: p.update(protectedHostAccount=None),
                       lambda p: p['protectedHostAccount'].update(users=['runtime-host']),
                       lambda p: p['protectedHostAccount']['broker'].update(configSha256='changed')):
            packet = copy.deepcopy(self.packet)
            change(packet)
            reader = asyncio.StreamReader()
            reader.feed_data(canonical_bytes(packet)+b'\n')
            reader.feed_eof()
            with self.assertRaises(ContractError):
                await process.receive(reader, self.writer)
        self.mocks[0].assert_not_called()
        self.mocks[2].assert_not_called()

    def stop_packet(self, lifetime=None):
        self.reader.feed_data(canonical_bytes({'schemaVersion':'1.0.0','kind':'application-services-stop',
            'lifetimeId': lifetime or self.packet['lifetimeId']})+b'\n')
        self.reader.feed_eof()

    async def test_ready_and_drained_bind_the_native_start_after_actual_close(self):
        self.start_packet()
        async def output():
            if self.lines[-1]['state'] == 'ready':
                self.stop_packet()
            else:
                self.host.close.assert_awaited()
        self.writer.drain.side_effect = output
        self.assertEqual(await process.receive(self.reader, self.writer), 0)
        self.assertEqual([line['state'] for line in self.lines], ['ready','drained'])
        for line in self.lines:
            self.assertEqual(line, {'schemaVersion':'1.0.0','kind':'application-services-state',
                'lifetimeId':self.packet['lifetimeId'], 'selectionSHA256':self.packet['selectionSHA256'],
                'kernelScope':self.packet['kernelScope'], 'state':line['state']})
        self.host.fence.assert_called()
        self.mocks[1].assert_called_once_with(3)
        self.assertEqual(self.mocks[2].call_args.kwargs['expected_digest'], self.packet['selectionSHA256'])

    async def test_selected_private_browser_port_reaches_the_host(self):
        self.start_packet()
        self.writer.drain.side_effect = lambda: self.stop_packet() if len(self.lines) == 1 else None
        self.assertEqual(await process.receive(self.reader, self.writer), 0)
        self.mocks[3].assert_called_once_with(self.selected, browser_port=49321)

    async def test_selection_without_a_private_browser_port_is_refused(self):
        # Review item 9: no selected port never falls back to the old dashboard's 8787.
        self.selected.local_browser_port.return_value = None
        self.start_packet()
        self.reader.feed_eof()
        with self.assertRaisesRegex(ContractError, 'application_services_browser_port_unselected'):
            await process.receive(self.reader, self.writer)
        self.mocks[3].assert_not_called()
        self.assertEqual(self.lines, [])

    async def test_protected_oidc_selection_configures_host_before_start(self):
        oidc = (object(), 'https://identity.example/realms/team/auth',
                'https://identity.example/realms/team/token')
        self.selected.oidc_browser_configuration.return_value = oidc
        self.host.configure_oidc_browser = Mock()
        self.start_packet()
        self.writer.drain.side_effect = lambda:self.stop_packet() if len(self.lines) == 1 else None
        self.assertEqual(await process.receive(self.reader, self.writer), 0)
        self.host.configure_oidc_browser.assert_called_once_with(*oidc)
        self.host.start.assert_awaited_once_with()

    async def test_protected_oidc_device_selection_configures_terminal_before_start(self):
        oidc = (object(), 'https://identity.example/realms/team/device',
                'https://identity.example/realms/team/token')
        self.selected.oidc_device_configuration.return_value = oidc
        self.host.configure_oidc_terminal = Mock()
        self.start_packet()
        self.writer.drain.side_effect = lambda:self.stop_packet() if len(self.lines) == 1 else None
        self.assertEqual(await process.receive(self.reader, self.writer), 0)
        self.host.configure_oidc_terminal.assert_called_once_with(*oidc)
        self.host.start.assert_awaited_once_with()

    async def test_stop_during_startup_is_joined_without_publishing_ready(self):
        self.start_packet()
        entered, release = asyncio.Event(), asyncio.Event()
        async def starting():
            entered.set()
            await release.wait()
        self.host.start.side_effect = starting
        self.host.close.side_effect = release.set
        receiving = asyncio.create_task(process.receive(self.reader, self.writer))
        await asyncio.wait_for(entered.wait(), 2)
        self.stop_packet()
        self.assertEqual(await asyncio.wait_for(receiving, 2), 0)
        self.assertEqual([line['state'] for line in self.lines], ['drained'])
        self.host.fence.assert_called()
        self.host.start.assert_awaited_once()

    async def test_wrong_stop_identity_fences_and_returns_failure(self):
        self.start_packet()
        self.writer.drain.side_effect = lambda:self.stop_packet('service_'+'c'*32) if len(self.lines)==1 else None
        self.assertEqual(await process.receive(self.reader, self.writer), 1)
        self.host.fence.assert_called()
        self.assertEqual([line['state'] for line in self.lines], ['ready','drained'])

    async def test_failed_cleanup_never_emits_drained(self):
        self.start_packet()
        self.writer.drain.side_effect = lambda:self.stop_packet()
        self.host.close.side_effect = OSError('private cleanup failure')
        with self.assertRaises(OSError):
            await process.receive(self.reader, self.writer)
        self.assertEqual([line['state'] for line in self.lines], ['ready'])
        self.mocks[1].assert_called_once_with(3)

    async def test_failed_health_check_records_only_its_stage_and_closed_code(self):
        self.start_packet()
        def failing():
            self.host.health_stage = 'storage'
            try:
                raise ConnectionResetError('tls://user:secret@10.0.0.1 /Users/private')
            except ConnectionResetError as cause:
                raise ContractError('storage_ledger_unavailable') from cause
        self.host.check_health.side_effect = failing
        with self.assertRaises(ContractError):
            await process.receive(self.reader, self.writer)
        level, record = self.record()
        self.assertEqual(level, self.log.LOG_ERR)
        self.assertEqual(record, 'application_services_failed phase=health stage=storage'
            ' type=agentmux_contracts.wire.ContractError code=storage_ledger_unavailable'
            ' cause=builtins.ConnectionResetError cause_code=none')
        self.assertEqual([line['state'] for line in self.lines], ['ready'])

    async def test_clean_stop_is_recorded_as_an_owner_stop(self):
        self.start_packet()
        self.writer.drain.side_effect = lambda: self.stop_packet() if self.lines[-1]['state'] == 'ready' else None
        self.assertEqual(await process.receive(self.reader, self.writer), 0)
        self.assertEqual(self.record(), (self.log.LOG_WARNING, 'application_services_ended reason=stopped'))

    async def test_wrong_stop_is_recorded_as_a_protocol_failure(self):
        self.start_packet()
        self.writer.drain.side_effect = lambda: self.stop_packet('service_'+'f'*32) if self.lines[-1]['state'] == 'ready' else None
        self.assertEqual(await process.receive(self.reader, self.writer), 1)
        self.assertEqual(self.record(), (self.log.LOG_WARNING, 'application_services_ended reason=protocol_failure'))

    async def test_startup_and_close_failures_name_their_phase(self):
        self.start_packet()
        self.host.start.side_effect = ContractError('application_service_start_unconfirmed')
        with self.assertRaises(ContractError):
            await process.receive(self.reader, self.writer)
        self.assertIn('phase=startup stage=none', self.record()[1])
        self.assertIn('code=application_service_start_unconfirmed', self.record()[1])

    async def test_close_failure_names_its_phase(self):
        self.start_packet()
        self.writer.drain.side_effect = lambda: self.stop_packet()
        self.host.close.side_effect = OSError('private cleanup failure')
        with self.assertRaises(OSError):
            await process.receive(self.reader, self.writer)
        self.assertEqual(self.record(), (self.log.LOG_ERR, 'application_services_failed phase=close stage=none'
            ' type=builtins.OSError code=none cause=none cause_code=none'))


    def test_failure_record_never_carries_messages_or_uncoded_text(self):
        from native_security.descriptor_admission import AdmissionError
        record = process._failure_record
        self.assertEqual(record('startup', 'storage', AdmissionError('native_admission_acl')),
            'application_services_failed phase=startup stage=storage'
            ' type=native_security.descriptor_admission.AdmissionError code=native_admission_acl'
            ' cause=none cause_code=none')
        for error in (ContractError('Secret_Value'), ContractError('password'), ContractError('a_' * 30 + 'b'),
                      ContractError('code_with /path'), ContractError(('tuple_code',)),
                      ValueError('value_error_text'), OSError(2, 'no_such_file')):
            text = record('health', 'identity', error)
            for private in ('Secret', 'password', '/path', 'value_error_text', 'no_such_file', 'tuple_code', 'a_a_'):
                self.assertNotIn(private, text)
            self.assertIn(' code=none ', text)
        self.assertIn('phase=unknown stage=none', record('elsewhere', 'not_a_stage', ValueError()))
        Hostile = type('Bad Name', (Exception,), {})
        self.assertIn('type=unnamed', record('health', 'host', Hostile()))

    def test_unavailable_system_log_never_changes_the_outcome(self):
        self.log.syslog.side_effect = OSError('log unavailable')
        process._report_failure('health', 'host', ValueError())

    async def test_extra_start_fields_cannot_choose_an_executable(self):
        self.packet['command'] = ['python','other.py']
        self.start_packet()
        with self.assertRaises(ContractError):
            await process.receive(self.reader, self.writer)
        self.mocks[0].assert_not_called()
        self.mocks[2].assert_not_called()
        self.mocks[3].assert_not_called()
        self.assertEqual(self.lines, [])

    async def test_private_main_rejects_malformed_start_and_joins_its_pipes(self):
        root = Path(__file__).resolve().parents[1]
        dependency_path = Path(nkeys.__file__).resolve().parent.parent
        pythonpath = os.pathsep.join([*(str(root / part)
            for part in ('sdk/python', 'dashboard', 'taskmgmt')), str(dependency_path)])
        result = subprocess.run([sys.executable, '-c',
            'from application_service_process import main; raise SystemExit(main())'],
            input=b'{}\n', stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, cwd=root,
            env={'PATH':'/usr/bin:/bin', 'PYTHONPATH':pythonpath})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application services could not finish startup or cleanup.\n')


class ProcessOutsideTheBody(unittest.TestCase):
    def test_failure_outside_the_body_is_recorded_once_as_cleanup(self):
        async def failing():
            raise OSError('private pipe failure')
        process._reported = False
        with patch('application_service_process._stdio', failing), \
                patch('application_service_process.syslog') as log, patch('sys.stderr'):
            self.assertEqual(process.main(), 1)
        log.syslog.assert_called_once_with(log.LOG_ERR, 'application_services_failed phase=cleanup'
            ' stage=none type=builtins.OSError code=none cause=none cause_code=none')

    def test_failure_already_recorded_in_the_body_is_not_recorded_again(self):
        async def failing():
            process._report_failure('health', 'task', ContractError('task_host_unavailable'))
            raise ContractError('task_host_unavailable')
        process._reported = False
        with patch('application_service_process._stdio', failing), \
                patch('application_service_process.syslog') as log, patch('sys.stderr'):
            self.assertEqual(process.main(), 1)
        log.syslog.assert_called_once()
        self.assertIn('phase=health stage=task', log.syslog.call_args.args[1])
