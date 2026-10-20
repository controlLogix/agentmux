"""Entrypoint checks with injected startup; no client or runtime is launched."""
import io
import json
import os
import pty
import select
import termios
import threading
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from hub import cli
from hub import client_launch_entrypoint as entry
from hub.client_launch_coordinator import result


class ClientLaunchEntrypoint(unittest.TestCase):
    def test_options_reject_ambiguous_or_unknown_input(self):
        for args in (["--selection"], ["--selection", ""], ["--enrolled", "--enrolled"],
                     ["--unknown"], ["--output", "invalid"], ["--managed-worker", "false"]):
            with self.subTest(args=args), self.assertRaises(entry.OptionsError):
                entry.parse_options(args)
        with self.assertRaises(entry.OptionsError):
            entry.parse_options(["--output", "json"], mcp=True)
        self.assertIsNone(entry.parse_options(["--enrolled"]).selection)

    def test_report_channels_and_once_only_start(self):
        for mode in ("human", "json"):
            out, err = io.StringIO(), io.StringIO()
            observed = result("ensure", "observed")
            with patch.object(entry, "startup", return_value=observed) as startup, \
                    patch.object(cli.sys, "stdout", out), patch.object(cli.sys, "stderr", err):
                session = cli.main(["startup", "--selection", "/private/a b.json", "--output", mode])
                self.assertIs(session.start(), observed)
            startup.assert_called_once_with("/private/a b.json", managed_worker=False)
            self.assertEqual(session.exit_code(), 0)
            if mode == "human":
                self.assertEqual(out.getvalue(), "")
                self.assertTrue(err.getvalue())
            else:
                self.assertEqual(json.loads(out.getvalue()), observed.public)
                self.assertEqual(err.getvalue(), "")

    def test_enrolled_mcp_starts_once_and_never_calls_legacy_hub(self):
        messages = [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
                     "params": {"name": name}} for i, name in enumerate(
                         ("agentmux_startup_status", "hub_whoami", "agentmux_startup_status"), 1)]
        out = io.StringIO()
        observed = result("status", "observed")
        with patch.object(entry, "startup", return_value=observed) as startup, \
                patch.object(cli, "call") as call, \
                patch.object(cli.sys, "stdin", io.StringIO("".join(json.dumps(m) + "\n" for m in messages))), \
                patch.object(cli.sys, "stdout", out):
            session = cli.main(["mcp", "--enrolled", "--selection", "/private/a.json", "--managed-worker"])
        startup.assert_called_once_with("/private/a.json", managed_worker=True)
        call.assert_not_called()
        replies = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(len(replies), 3)
        self.assertEqual(replies[0]["result"]["structuredContent"], observed.public)
        self.assertTrue(replies[1]["result"]["isError"])
        self.assertIs(session.result, observed)

    def test_stream_failure_finishes_owned_startup(self):
        for protocol in (False, True):
            session = entry.EnrolledSession(entry.Options(None, True, "human"))
            session.result = result("status", "observed")
            with patch.object(session, "exit_code", return_value=0) as cleanup:
                with self.assertRaises(BrokenPipeError):
                    if protocol:
                        with patch("hub.fed.mcp.main", side_effect=BrokenPipeError):
                            session.serve_mcp(stdin=io.StringIO(), stdout=io.StringIO())
                    else:
                        stream = Mock()
                        stream.write.side_effect = BrokenPipeError
                        session.report(stderr=stream)
            cleanup.assert_called_once_with()

    def test_actual_entrypoint_owns_application_and_reports_only_verified_hub(self):
        observed = result('ensure', 'observed')
        observed.public.update(infrastructureReadiness='ready', instanceId='instance-one')
        observed.selection = SimpleNamespace(application_client='/private/key', application_connection='/private/connection')
        application = Mock()
        application.status.return_value = {'state': 'verified', 'hubId': 'hub-one'}
        application.close.return_value = application.join_final.return_value = True
        output, error = io.StringIO(), io.StringIO()
        with patch.object(entry, 'startup', return_value=observed),                 patch('hub.client_launch_session.ApplicationClientSession', return_value=application) as create,                 patch.object(cli.sys, 'stdout', output), patch.object(cli.sys, 'stderr', error):
            session = cli.main(['startup', '--selection', '/private/selected'])
        create.assert_called_once_with(observed.selection)
        application.start.assert_called_once()
        self.assertIn('Authenticated hub hub-one', error.getvalue())
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(observed.public['applicationAccess'], 'unavailable')
        self.assertEqual(session.exit_code(), 0)
        application.join_final.assert_called_once_with()

    def test_dashboard_opens_clean_loopback_url_and_sends_hidden_code_on_owner(self):
        observed = result('ensure', 'observed')
        observed.public.update(infrastructureReadiness='ready', instanceId='instance-one')
        observed.selection = SimpleNamespace(application_client='/private/key',
                                             application_connection='/private/connection')
        application = Mock()
        application.status.return_value = {'state': 'verified', 'hubId': 'hub-one'}
        application.local_browser_enabled.return_value = True
        application.close.return_value = application.join_final.return_value = True
        with patch.object(entry, 'startup', return_value=observed), \
                patch('hub.client_launch_session.ApplicationClientSession', return_value=application), \
                patch.object(entry.EnrolledSession, '_hidden_pairing_code',
                             return_value='2345-6789-ABCD-EFGH-JKMP') as hidden, \
                patch.object(entry.subprocess, 'run') as launch:
            session = cli.main(['dashboard', '--selection', '/private/selected'])
        launch.assert_called_once()
        self.assertEqual(launch.call_args.args[0], ['/usr/bin/open', 'http://127.0.0.1:8787/'])
        hidden.assert_called_once_with()
        application.local_browser_session_open.assert_called_once()
        args, kwargs = application.local_browser_session_open.call_args
        self.assertEqual(args, ('2345-6789-ABCD-EFGH-JKMP', 'http://127.0.0.1:8787'))
        self.assertGreater(kwargs['deadline'], 0)
        self.assertEqual(session.exit_code(), 0)

    def test_hidden_pairing_code_uses_nonseekable_terminal_and_restores_echo(self):
        master, slave = pty.openpty()
        path = os.ttyname(slave)
        result, failure = [], []

        def read_code():
            try:
                result.append(entry.EnrolledSession._hidden_pairing_code(path))
            except BaseException as error:
                failure.append(error)

        worker = threading.Thread(target=read_code)
        worker.start()
        try:
            ready, _, _ = select.select([master], [], [], 2)
            self.assertEqual(ready, [master])
            self.assertIn(b'Pairing code: ', os.read(master, 64))
            deadline = time.monotonic() + 2
            while termios.tcgetattr(slave)[3] & termios.ECHO and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
            os.write(master, b'2345-6789-ABCD-EFGH-JKMP\n')
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failure, [])
            self.assertEqual(result, ['2345-6789-ABCD-EFGH-JKMP'])
            self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)
        finally:
            if worker.is_alive():
                os.write(master, b'\n')
                worker.join(2)
            os.close(master)
            os.close(slave)

    def test_dashboard_failure_and_interruption_join_original_application_owner(self):
        for failure in (entry.OptionsError('invalid pairing code'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                observed = result('ensure', 'observed')
                observed.public.update(infrastructureReadiness='ready', instanceId='instance-one')
                observed.selection = SimpleNamespace(application_client='/private/key',
                                                     application_connection='/private/connection')
                application = Mock()
                application.status.return_value = {'state': 'verified', 'hubId': 'hub-one'}
                application.local_browser_enabled.return_value = True
                application.close.return_value = application.join_final.return_value = True
                with patch.object(entry, 'startup', return_value=observed), \
                        patch('hub.client_launch_session.ApplicationClientSession',
                              return_value=application), \
                        patch.object(entry.EnrolledSession, '_hidden_pairing_code',
                                     side_effect=failure), \
                        patch.object(entry.subprocess, 'run'):
                    with self.assertRaises(type(failure)):
                        cli.main(['dashboard', '--selection', '/private/selected'])
                application.close.assert_called_once()
                application.join_final.assert_called_once_with()

    def test_mcp_rechecks_binding_status_without_legacy_dispatch(self):
        from hub.fed import mcp
        observed = result('ensure', 'observed')
        application = Mock()
        application.status.return_value = {'state': 'unavailable', 'hubId': None}
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'agentmux_startup_status'}}
        with patch.object(cli, 'call') as call:
            response = mcp.handle(request, {}, startup_result=observed, application_session=application)
        self.assertEqual(response['structuredContent']['applicationBinding']['state'], 'unavailable')
        self.assertEqual(response['structuredContent']['applicationAccess'], 'unavailable')
        call.assert_not_called()

    def test_optional_application_import_failure_keeps_runtime_owner_and_fixed_status(self):
        import sys
        observed = result('ensure', 'observed')
        observed.public.update(infrastructureReadiness='ready', instanceId='instance-one')
        observed.selection = SimpleNamespace(application_client='/private/key', application_connection='/private/connection')
        with patch.object(entry, 'startup', return_value=observed),                 patch.dict(sys.modules, {'hub.client_launch_session': None}):
            session = entry.EnrolledSession(entry.Options('/private/selected', False, 'human'))
            self.assertIs(session.start(), observed)
        self.assertEqual(observed.public['applicationBinding'], {'state': 'unavailable', 'hubId': None})
        self.assertEqual(session.exit_code(), 1)

    def test_bare_mcp_keeps_legacy_route(self):
        with patch("hub.fed.mcp.main") as main, patch.object(entry, "startup") as startup:
            cli.main(["mcp"])
        main.assert_called_once_with()
        startup.assert_not_called()

    def test_invalid_cli_options_never_start(self):
        with patch.object(entry, "startup") as startup:
            for args in (["startup", "--json"], ["mcp", "--enrolled", "--as", "operator"],
                         ["startup", "--selection"]):
                with self.subTest(args=args), self.assertRaises(cli.Fail):
                    cli.main(args)
        startup.assert_not_called()

    def test_missing_selection_reports_setup_required(self):
        out = io.StringIO()
        with patch.object(cli.sys, "stdout", out):
            session = cli.main(["startup", "--output", "json"])
        self.assertEqual(json.loads(out.getvalue())["outcome"], "setup_required")
        self.assertEqual(session.exit_code(), 1)

    def test_exit_wait_retains_original_child_and_never_restarts(self):
        observed = result("status", "failed")
        child = Mock()
        observed.capture = Mock(pending=child)
        session = entry.EnrolledSession(entry.Options(None, True, "human"))
        session.result = observed
        with patch.object(session, "finish_cleanup", side_effect=[False, True]), \
                patch.object(entry, "startup") as startup:
            self.assertEqual(session.exit_code(), 1)
        child.wait.assert_called_once_with()
        startup.assert_not_called()
        self.assertIsNone(observed.capture.pending)
