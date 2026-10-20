"""Offline Claude Code SessionStart checks; no runtime or client is started."""
import io
import json
import os
import select
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from hub import client_launch_claude as claude
from hub.client_launch_coordinator import result
from hub.client_launch_entrypoint import Options
from hub.profile_context import ProfileContext


SELECTION = '/private/enrolled client/selection.json'


SIGNAL_SCRIPT = r'''
import json, os, signal, subprocess, sys
from hub import client_launch_claude as claude
from hub.client_launch_entrypoint import EnrolledSession
from hub.client_launch_coordinator import Capture, result

control = os.fdopen(int(sys.argv[1]))
failure = sys.argv[2:] == ['fail-startup']
original_handlers = {number: signal.getsignal(number)
                     for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
requested = claude._TerminationGuard.requested
def report(value):
    print(json.dumps(value), file=sys.stderr, flush=True)
def acknowledged(self, number, frame=None):
    requested(self, number, frame)
    report({'stage': 'signal', 'number': number})
claude._TerminationGuard.requested = acknowledged
owned = {}
class OfflineStartup(EnrolledSession):
    def start(self):
        self.result = result('ensure', 'observed')
        self.result.public.update(infrastructureReadiness='ready',
            instanceId='instance_' + '1' * 32, profileId='profile_' + 'a' * 32,
            callerIdentityOwnerHubId='hub-selected')
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        owned['child'] = child
        self.result.capture = Capture(pending=child, streams=[child.stdout, child.stderr])
        report({'stage': 'startup', 'pid': child.pid})
        control.readline()
        if failure:
            raise ValueError('PRIVATE_STARTUP_FAILURE')
        return self.result
    def exit_code(self):
        if not owned.get('cleanup_entered'):
            owned['cleanup_entered'] = True
            report({'stage': 'cleanup'})
            control.readline()
        return super().exit_code()

claude.EnrolledSession = OfflineStartup
code = claude.main(['--selection', '/private/offline-selection'])
restored = all(signal.getsignal(number) == previous
               for number, previous in original_handlers.items())
report({'stage': 'done', 'restored': restored,
        'joined': owned['child'].returncode is not None})
raise SystemExit(code)
'''


def event(source='startup', **changes):
    value = {
        'session_id': 'session-one',
        'transcript_path': '/private/transcript.jsonl',
        'cwd': '/Users/example/project',
        'permission_mode': 'default',
        'hook_event_name': 'SessionStart',
        'source': source,
    }
    value.update(changes)
    return io.StringIO(json.dumps(value))


class ClaudeCodeHook(unittest.TestCase):
    def session(self, *, operation='ensure', outcome='observed', cleanup=0):
        started = result(operation, outcome)
        started.public.update(
            infrastructureReadiness='ready',
            instanceId='instance_' + '1' * 32,
            profileId='profile_' + 'a' * 32,
            callerIdentityOwnerHubId='hub-selected',
        )
        session = Mock()
        session.start.return_value = started
        session.profile_context = ProfileContext(environment='Local', project='Agentmux')
        session.exit_code.return_value = cleanup
        return session, started

    def invoke(self, stdin, *, arguments=None, session=None):
        output = io.StringIO()
        replacement = session if session is not None else self.session()[0]
        with patch.object(claude, 'EnrolledSession', return_value=replacement) as create:
            code = claude.main(
                ['--selection', SELECTION] if arguments is None else arguments,
                stdin=stdin,
                stdout=output,
            )
        return code, json.loads(output.getvalue()), replacement, create

    def test_startup_resume_and_fork_ensure_once_and_emit_safe_status(self):
        for source in ('startup', 'resume', 'fork'):
            session, started = self.session()
            with self.subTest(source=source):
                code, response, _, create = self.invoke(event(source), session=session)
                self.assertEqual(code, 0)
                create.assert_called_once_with(Options(SELECTION, False, 'human'), registered_context=None)
                session.start.assert_called_once_with()
                session.exit_code.assert_called_once_with()
                self.assertIn(started.public['instanceId'], response['systemMessage'])
                hook = response['hookSpecificOutput']
                self.assertEqual(hook['hookEventName'], 'SessionStart')
                context = hook['additionalContext']
                self.assertIn('"callerIdentityOwnerHubId":"hub-selected"', context)
                self.assertIn('"profileContext":{"environment":"Local","project":"Agentmux"}', context)
                self.assertNotIn('transcript', context)
                self.assertNotIn(SELECTION, json.dumps(response))

    def test_agent_id_uses_status_only_and_does_not_grant_authority(self):
        session, started = self.session(operation='status')
        code, response, _, create = self.invoke(
            event(agent_id='agent-worker', agent_type='general-purpose'), session=session)
        self.assertEqual(code, 0)
        create.assert_called_once_with(Options(SELECTION, True, 'human'), registered_context=None)
        self.assertEqual(started.public['operation'], 'status')
        self.assertIn('does not grant authority', response['hookSpecificOutput']['additionalContext'])

    def test_installed_owner_marks_managed_top_level_without_agent_id(self):
        output = io.StringIO()
        session, started = self.session(operation='status')
        with patch.object(claude, 'EnrolledSession', return_value=session) as create:
            code = claude.main(['--selection', SELECTION], stdin=event(), stdout=output,
                               managed_worker=True)
        self.assertEqual(code, 0)
        create.assert_called_once_with(Options(SELECTION, True, 'human'), registered_context=None)
        self.assertEqual(started.public['operation'], 'status')
        self.assertNotIn('agent_id', event().getvalue())

    def test_clear_and_compact_do_not_start_again(self):
        for source in ('clear', 'compact'):
            with self.subTest(source=source):
                code, response, session, create = self.invoke(event(source))
                self.assertEqual((code, response), (0, {}))
                create.assert_not_called()
                session.start.assert_not_called()

    def test_invalid_input_and_arguments_fail_closed_without_echo(self):
        cases = (
            (io.StringIO('{"hook_event_name":"SessionStart","source":"startup"}'), None),
            (event(source='unknown'), None),
            (event(source=[]), None),
            (event(source={}), None),
            (event(agent_id=True), None),
            (io.StringIO('{"source":"startup","source":"resume"}'), None),
            (io.StringIO('x' * (claude.MAX_BYTES + 1)), None),
            (event(), ['--selection', 'relative']),
            (event(), ['--repository-root', '/private/project']),
        )
        for stdin, arguments in cases:
            with self.subTest(arguments=arguments):
                code, response, session, create = self.invoke(stdin, arguments=arguments)
                self.assertEqual(code, 0)
                self.assertEqual(response, {'systemMessage': 'Agentmux startup hook input is invalid.'})
                create.assert_not_called()
                session.start.assert_not_called()

    def test_failure_status_is_valid_hook_output(self):
        session, started = self.session(outcome='failed', cleanup=1)
        started.public.update(code='runtime_failed', infrastructureReadiness='unknown')
        code, response, _, _ = self.invoke(event(), session=session)
        self.assertEqual(code, 0)
        self.assertIn('startup failed', response['systemMessage'])
        self.assertIn('"code":"runtime_failed"', response['hookSpecificOutput']['additionalContext'])
        session.exit_code.assert_called_once_with()

    def test_interruption_retries_only_cleanup_and_never_startup(self):
        session, _ = self.session()
        session.start.side_effect = KeyboardInterrupt()
        session.exit_code.side_effect = [KeyboardInterrupt(), 1]
        code, response, _, _ = self.invoke(event(), session=session)
        self.assertEqual(code, 0)
        self.assertEqual(response, {
            'systemMessage': 'Agentmux startup was interrupted. Run the runtime doctor before retrying.'})
        session.start.assert_called_once_with()
        self.assertEqual(session.exit_code.call_count, 2)

    def test_registered_context_is_forwarded_only_from_installed_caller(self):
        registered = Mock()
        output = io.StringIO()
        session, _ = self.session()
        with patch.object(claude, 'EnrolledSession', return_value=session) as create:
            code = claude.main(['--selection', SELECTION], stdin=event(), stdout=output,
                               registered_context=registered)
        self.assertEqual(code, 0)
        create.assert_called_once_with(Options(SELECTION, False, 'human'), registered_context=registered)

    def test_output_failure_happens_after_owned_cleanup(self):
        session, _ = self.session()
        output = Mock()
        output.write.side_effect = BrokenPipeError('private stream')
        with patch.object(claude, 'EnrolledSession', return_value=session):
            code = claude.main(['--selection', SELECTION], stdin=event(), stdout=output)
        self.assertEqual(code, 1)
        session.exit_code.assert_called_once_with()

    def test_status_is_flushed_before_the_final_owned_join(self):
        session, _ = self.session()
        output = io.StringIO()
        def cleanup():
            self.assertTrue(output.getvalue().endswith('\n'))
            self.assertIn('hookSpecificOutput', output.getvalue())
            return 0
        session.exit_code.side_effect = cleanup
        with patch.object(claude, 'EnrolledSession', return_value=session):
            self.assertEqual(claude.main(
                ['--selection', SELECTION], stdin=event(), stdout=output), 0)
        session.start.assert_called_once_with()
        session.exit_code.assert_called_once_with()

    def test_status_format_failure_still_emits_fixed_json_then_cleans_up(self):
        session, _ = self.session()
        output = io.StringIO()
        with patch.object(claude, 'EnrolledSession', return_value=session), \
                patch.object(claude, '_response', side_effect=TypeError('private status')):
            self.assertEqual(claude.main(
                ['--selection', SELECTION], stdin=event(), stdout=output), 0)
        self.assertEqual(json.loads(output.getvalue()), {
            'systemMessage': 'Agentmux startup status is unavailable. Run the runtime doctor before retrying.'})
        session.exit_code.assert_called_once_with()

    def test_term_and_hup_are_retained_through_cleanup_without_replacing_owner(self):
        for selected_signal in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=selected_signal):
                session, _ = self.session()
                output = io.StringIO()
                guard = claude._TerminationGuard()
                def cleanup():
                    guard.requested(selected_signal)
                    guard.requested(signal.SIGINT)
                    self.assertTrue(output.getvalue())
                    return 0
                session.exit_code.side_effect = cleanup
                with patch.object(claude, 'EnrolledSession', return_value=session):
                    code = claude._execute(
                        ['--selection', SELECTION], stdin=event(), stdout=output,
                        registered_context=None, managed_worker=False, guard=guard)
                self.assertEqual(code, 0)
                self.assertEqual(guard.signum, selected_signal)
                session.start.assert_called_once_with()
                session.exit_code.assert_called_once_with()


class ClaudeCodeTermination(unittest.TestCase):
    def line(self, stream):
        ready, _, _ = select.select([stream], [], [], 4)
        self.assertTrue(ready, 'Offline Claude hook stage timed out')
        line = stream.readline()
        self.assertTrue(line, 'Offline Claude hook exited before its expected stage')
        return json.loads(line)

    def test_real_term_hup_and_repeated_signals_join_original_child_after_output(self):
        hook_input = json.dumps({
            'session_id': 'session-signal', 'transcript_path': '/private/transcript.jsonl',
            'cwd': '/private/project', 'permission_mode': 'default',
            'hook_event_name': 'SessionStart', 'source': 'startup',
        })
        for first_signal, during_cleanup, startup_fails in (
                (signal.SIGTERM, False, False), (signal.SIGHUP, True, False),
                (signal.SIGTERM, True, True)):
            with self.subTest(signal=first_signal, during_cleanup=during_cleanup,
                              startup_fails=startup_fails):
                control_read, control_write = os.pipe()
                arguments = [sys.executable, '-c', SIGNAL_SCRIPT, str(control_read)]
                if startup_fails:
                    arguments.append('fail-startup')
                process = subprocess.Popen(arguments, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    pass_fds=(control_read,))
                os.close(control_read)
                child_pid = None
                try:
                    process.stdin.write(hook_input)
                    process.stdin.close()
                    process.stdin = None
                    starting = self.line(process.stderr)
                    self.assertEqual(starting['stage'], 'startup')
                    child_pid = starting['pid']
                    if not during_cleanup:
                        process.send_signal(first_signal)
                        self.assertEqual(self.line(process.stderr),
                                         {'stage': 'signal', 'number': first_signal})
                    os.write(control_write, b'continue\n')
                    self.assertEqual(self.line(process.stderr), {'stage': 'cleanup'})
                    # Bounded hook status must already be a complete single line
                    # while the original child's final join is still held.
                    hook = self.line(process.stdout)
                    self.assertEqual(set(hook), {'systemMessage'} if startup_fails else
                                     {'systemMessage', 'hookSpecificOutput'})
                    if during_cleanup:
                        process.send_signal(first_signal)
                        self.assertEqual(self.line(process.stderr),
                                         {'stage': 'signal', 'number': first_signal})
                    for repeated in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                        process.send_signal(repeated)
                        self.assertEqual(self.line(process.stderr),
                                         {'stage': 'signal', 'number': repeated})
                    os.write(control_write, b'finish cleanup\n')
                    self.assertEqual(self.line(process.stderr),
                                     {'stage': 'done', 'restored': True, 'joined': True})
                    self.assertEqual(process.wait(timeout=4), 128 + first_signal)
                    self.assertEqual(process.stdout.read(), '')
                    self.assertEqual(process.stderr.read(), '')
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                finally:
                    os.close(control_write)
                    if process.poll() is None:
                        if child_pid is not None:
                            try:
                                os.kill(child_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        process.kill()
                        process.wait(timeout=4)
                    for stream in (process.stdout, process.stderr):
                        stream.close()


if __name__ == '__main__':
    unittest.main()
