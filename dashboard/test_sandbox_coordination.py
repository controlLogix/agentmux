#!/usr/bin/env python3
"""TM-068 offline regressions: no live server, socket or operator state."""
import argparse
import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'taskmgmt'))
TEMP = tempfile.TemporaryDirectory(prefix='sandbox-coordination-')
os.environ['AGENTMUX_HOME'] = TEMP.name
import coordination as co
import dispatch
import agentdefs


class SandboxCoordination(unittest.TestCase):
    def test_live_and_empty(self):
        for output, expected in [('alice\nbob\n', {'alice', 'bob'}), ('', set())]:
            with patch.object(co.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
                self.assertEqual(co.live_agents(), expected)
        for detail in ['no sessions', 'no server running on /tmp/tmux-1000/agentmux',
                       'error connecting to /tmp/tmux-1000/identity-test-1234 (No such file or directory)',
                       'error connecting to /tmp/tmux-1000/identity-test-1234 (ENOENT)']:
            with self.subTest(detail=detail), patch.object(co.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', detail)):
                self.assertEqual(co.live_agents(), set())

    def test_unreachable_is_not_empty(self):
        for detail in ['Operation not permitted', 'Permission denied', 'EACCES', 'EPERM', 'Connection refused', 'unexpected error']:
            with self.subTest(detail=detail), patch.object(co.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', detail)):
                with self.assertRaisesRegex(co.TmuxUnavailable, 'tmux unreachable.*' + detail):
                    co.live_agents()
        for error in [PermissionError('denied'), FileNotFoundError('tmux'), subprocess.TimeoutExpired('tmux', 10)]:
            with patch.object(co.subprocess, 'run', side_effect=error):
                with self.assertRaisesRegex(co.TmuxUnavailable, 'liveness is unknown'):
                    co.live_agents()

    def test_mutations_refuse_with_actual_cause(self):
        for args in [['claim', 'file.py', '--holder', 'worker'], ['journal', 'note', 'test'], ['task-evidence', 'TM-068', 'tmp/proof.txt']]:
            err = io.StringIO()
            with patch.dict(os.environ, {'AGENTMUX_AGENT': 'worker', 'AGENTMUX_TRUST_IDENTITY': '0'}), patch.object(co.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'Operation not permitted')), patch.object(co, 'journal') as journal, patch.object(co, 'board_call') as board, contextlib.redirect_stderr(err):
                self.assertEqual(co.main(args), 2)
                self.assertIn('tmux unreachable', err.getvalue())
                self.assertIn('sandbox', err.getvalue())
                self.assertNotIn('not a live agent', err.getvalue())
                journal.assert_not_called()
                board.assert_not_called()

    def test_dispatch_refuses_before_spawn_even_dry_run(self):
        fallback = agentdefs.choose_roster({}, {}, {})[0]
        for posture, brake in [('workspace-write', '0'), ('read-only', '0'), ('unrestricted', '1')]:
            for dry in [False, True]:
                spec = replace(fallback, posture=posture)
                task = {'id': 'TM-068', 'title': 'sandbox test'}
                # The board is entirely mocked here, so the foreign-board guard has
                # nothing real to protect - and it fires FIRST, before the posture
                # refusal this case is about. Saying so explicitly is the point of the
                # guard having an override: this suite means it.
                with patch.dict(os.environ, {'AGENTMUX_NO_BYPASS': brake}), patch.object(dispatch, 'approved_project_lead', return_value=None), patch.object(dispatch, 'foreign_board', return_value=''), patch.object(dispatch, 'dispatch_view', return_value={'tasks': [task]}), patch.object(dispatch, 'entity', return_value=task), patch.object(dispatch, 'live_agents', return_value=set()), patch.object(agentdefs, 'load_all', return_value=({}, [])), patch.object(agentdefs, 'choose_roster', return_value=[spec]), patch.object(dispatch, 'agentmux') as spawn, patch.object(dispatch, 'claim_for') as claim, patch.object(dispatch, 'set_status') as status, patch.object(dispatch, 'log') as log:
                    self.assertIsNone(dispatch.dispatch_one('TM-068', dry_run=dry))
                    spawn.assert_not_called()
                    claim.assert_not_called()
                    status.assert_not_called()
                    self.assertIn('sandbox', log.call_args.args[0])
                    self.assertIn('posture=' + posture, log.call_args_list[0].args[0])

    def test_lead_selection_policy_and_visible_posture(self):
        fallback = agentdefs.choose_roster({}, {}, {})[0]
        self.assertEqual(fallback.posture, 'unrestricted')
        z = replace(fallback, name='z-lead', posture='workspace-write')
        a = replace(fallback, name='a-lead', posture='read-only')
        worker = replace(fallback, name='aaa-worker', role='worker')
        self.assertEqual(agentdefs.choose_roster({}, {s.name: s for s in [z, a, worker]}, {})[0], fallback)
        self.assertEqual(agentdefs.choose_roster({}, {s.name: s for s in [z, a, worker]}, {}, approved_lead=z)[0], z)

    def test_dispatch_uses_only_approved_exact_revision_and_refuses_missing_snapshot(self):
        fallback = agentdefs.choose_roster({}, {}, {})[0]
        spec = replace(fallback, name='project-lead', path='/project/lead.md',
                       checksum='sha256:' + 'a' * 64)
        revision = dict(name=spec.name, scope=spec.scope, path=spec.path, checksum=spec.checksum,
                        projectRoot=str(dispatch.REPO.resolve()),
                        snapshotDigest=dispatch.definition_team.snapshot_digest(spec))
        row = dict(agent_name=spec.name, role='lead', status='approved',
                   definitionRevision=revision, definitionState='current')
        with patch.object(dispatch, 'board', return_value={'members': [row]}):
            self.assertEqual(dispatch.approved_project_lead('TM-001', {spec.name: spec}), spec)
            with self.assertRaisesRegex(ValueError, 'changed'):
                dispatch.approved_project_lead('TM-001', {spec.name: replace(spec, checksum='sha256:' + 'b' * 64)})
            with self.assertRaisesRegex(ValueError, 'changed'):
                dispatch.approved_project_lead('TM-001', {})
        with patch.object(dispatch, 'board', return_value={'members': [row]}):
            with self.assertRaisesRegex(ValueError, 'changed'):
                dispatch.approved_project_lead('TM-001', {spec.name: replace(spec, model='new-default')})
        with patch.object(dispatch, 'board', return_value={'members': [dict(row,
                definitionRevision=dict(revision, projectRoot='/other-project'))]}):
            with self.assertRaisesRegex(ValueError, 'another project'):
                dispatch.approved_project_lead('TM-001', {spec.name: spec})
        with patch.object(dispatch, 'board', return_value={'members': [dict(row, definitionRevision=None)]}):
            with self.assertRaisesRegex(ValueError, 'recruit and approve'):
                dispatch.approved_project_lead('TM-001', {spec.name: spec})
        with patch.object(dispatch, 'board', return_value=None):
            with self.assertRaisesRegex(ValueError, 'cannot read'):
                dispatch.approved_project_lead('TM-001', {spec.name: spec})
        with patch.object(dispatch, 'board', return_value={'members': [dict(row, status='proposed')]}):
            self.assertIsNone(dispatch.approved_project_lead('TM-001', {spec.name: spec}))

    def test_dispatch_preserves_approved_builtin_settings_or_refuses_drift(self):
        spec = agentdefs.choose_roster({}, {}, {'dispatchCli': 'claude'})[0]
        revision = dict(name=spec.name, scope=spec.scope, path=spec.path, checksum=spec.checksum,
                        projectRoot=str(dispatch.REPO.resolve()),
                        snapshotDigest=dispatch.definition_team.snapshot_digest(spec))
        row = dict(agent_name=spec.name, role='lead', status='approved',
                   definitionRevision=revision, definitionState='builtin')
        with patch.object(dispatch, 'board', return_value={'members': [row]}):
            self.assertEqual(dispatch.approved_project_lead('TM-001', {}, {'dispatchCli': 'claude'}), spec)
            with self.assertRaisesRegex(ValueError, 'changed'):
                dispatch.approved_project_lead('TM-001', {}, {'dispatchCli': 'codex'})

    def test_team_spawn_refuses_effective_sandbox(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tmux = root / 'tmux'
            tmux.write_text('#!/bin/sh\nexit 1\n')
            tmux.chmod(0o755)
            shell = root / 'agentmux.sh'
            shell.write_text((REPO / 'agentmux.sh').read_text())
            for posture, brake in [('workspace-write', '0'), ('read-only', '0'), ('unrestricted', '1')]:
                env = dict(os.environ, AGENTMUX_HOME=str(root / 'state'), PATH=str(root) + ':' + os.environ['PATH'], AGENTMUX_NO_BYPASS=brake)
                result = subprocess.run(['bash', str(shell), 'spawn', 'sandbox-test', '--cli', 'codex', '--cwd', folder, '--team', 'TM-068', '--posture', posture], env=env, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('sandbox posture', result.stderr)
                self.assertIn('coordination', result.stderr)
                self.assertEqual(list((root / 'state/run').iterdir()), [])

    def test_notification_reports_unknown_without_undoing_claim(self):
        err = io.StringIO()
        with patch.object(co, 'live_agents', side_effect=co.TmuxUnavailable('tmux unreachable')), patch.object(co, 'post') as post, contextlib.redirect_stderr(err):
            self.assertEqual(co.broadcast('worker', 'claim', 'claimed'), 0)
            self.assertIn('Notification skipped', err.getvalue())
            post.assert_not_called()

    def test_collect_aborts_when_liveness_unknown(self):
        with patch.object(dispatch, 'live_agents', side_effect=co.TmuxUnavailable('tmux unreachable')), patch.object(dispatch, 'set_status') as status, patch.object(dispatch, 'release_all') as release:
            with self.assertRaises(co.TmuxUnavailable):
                dispatch.collect_one('TM-068', {'id': 'TM-068'})
            status.assert_not_called()
            release.assert_not_called()

    def generation_is_free(self, resource, path):
        """Can the generation at `path` still be taken? The lock FILE is expected to
        survive a race - see take_generation - so the question is never whether it is
        there, only whether anybody is still holding it."""
        token, _observed = co.take_generation(resource, path)
        if token is co.GENERATION_LOST:
            return False
        co.drop_generation(token)
        return True

    def test_a_killed_process_does_not_wedge_a_generation_forever(self):
        """The reason the token is an flock and not an exclusive create.

        With the file itself as the lock, a process killed between taking a token and
        dropping it leaves the file behind. Inode numbers are recycled, so that
        leftover name then refuses a future generation of an unrelated claim - for
        good, until somebody spots a `.steal.` file in CLAIMS_DIR and deletes it. And
        the repair is worse than the fault: judging a lock file stale is the same
        check-then-act race the token exists to remove.

        An advisory lock has no staleness question in it. SIGKILL - which no `finally`
        can catch - is the case that proves it.
        """
        resource = 'taskmgmt/killed-holder.py'
        co.CLAIMS_DIR.mkdir(parents=True, exist_ok=True)
        path = co.CLAIMS_DIR / co.flatten(resource)
        path.write_text(json.dumps({
            'resource': resource, 'holder': 'holder-a', 'at': 'earlier', 'ttl': 60,
            'expires_at': time.time() + 60, 'note': '', 'task': None, 'depends_on': [],
        }), encoding='utf-8')

        # A real process, killed without warning while holding the token.
        holder = subprocess.Popen(
            [sys.executable, '-c',
             'import os, sys, time\n'
             'sys.path.insert(0, sys.argv[1])\n'
             'import coordination as co\n'
             'token, _ = co.take_generation(sys.argv[2], co.CLAIMS_DIR / co.flatten(sys.argv[2]))\n'
             'assert token not in (None, co.GENERATION_LOST), token\n'
             'print("held", flush=True)\n'
             'time.sleep(300)\n',
             str(REPO / 'taskmgmt'), resource],
            env=dict(os.environ, AGENTMUX_HOME=TEMP.name),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), 'held',
                         'the child never took the token')
        self.assertFalse(self.generation_is_free(resource, path),
                         'the token was not exclusive while the child held it')

        holder.kill()                     # SIGKILL: no finally, no cleanup, no chance
        holder.wait(timeout=30)
        holder.stdout.close()

        self.assertTrue(self.generation_is_free(resource, path),
                        'a SIGKILLed holder wedged this generation permanently')
        path.unlink(missing_ok=True)

    def test_a_renewal_cannot_be_unlinked_by_a_concurrent_steal(self):
        """The last hole in the claim-steal serialisation, driven deterministically.

        WHETHER A CLAIM HAS EXPIRED IS A QUESTION ABOUT THE CLOCK, so two processes
        reading the same bytes can legitimately disagree: the holder reads a
        microsecond before the lease runs out and goes to renew, a rival reads a
        microsecond after and goes to steal. The steal took a token named for the
        inode it observed and rechecked that inode before unlinking; the renewal took
        nothing at all. So the rival could check the inode, the holder's os.replace
        could land, and the rival would then unlink THE HOLDER'S BRAND NEW CLAIM and
        link its own - leaving one told "renewed", the other told "claimed", and two
        agents holding a mutual exclusion primitive.

        Brute force will not find this: the window is between two adjacent syscalls.
        So the interleave is built rather than waited for - the rival is stopped
        exactly inside it, the renewal is run to completion, and only then is the
        rival let go. Both halves are real cmd_claim() calls on a real file.
        """
        resource = 'taskmgmt/steal-race.py'
        co.CLAIMS_DIR.mkdir(parents=True, exist_ok=True)
        path = co.CLAIMS_DIR / co.flatten(resource)
        path.write_text(json.dumps({
            'resource': resource, 'holder': 'holder-a', 'at': 'earlier',
            'ttl': 60, 'expires_at': time.time() - 1,
            'note': '', 'task': None, 'depends_on': [],
        }), encoding='utf-8')

        def claim_args(holder):
            return argparse.Namespace(resource=resource, holder=holder, ttl=60,
                                      note=None, task=None, depends_on=[])

        at_the_window = threading.Event()
        renewal_finished = threading.Event()
        real_unlink = Path.unlink

        def unlink_at_the_window(target, *args, **kwargs):
            # Only the claim file itself; staging files and tokens pass straight
            # through, or the stealer would deadlock on its own cleanup.
            if os.fspath(target) == os.fspath(path):
                at_the_window.set()
                renewal_finished.wait(30)
            return real_unlink(target, *args, **kwargs)

        def expired_per_thread(_claim):
            return threading.current_thread().name == 'stealer'

        outcome = {}
        quiet = {'journal': lambda *a, **k: 'journal', 'broadcast': lambda *a, **k: 0,
                 'post': lambda *a, **k: None, 'all_claims': lambda *a, **k: [],
                 'expired': expired_per_thread}
        with contextlib.ExitStack() as stack:
            for name, value in quiet.items():
                stack.enter_context(patch.object(co, name, value))
            stack.enter_context(patch.object(Path, 'unlink', unlink_at_the_window))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            thief = threading.Thread(
                target=lambda: outcome.setdefault('steal', co.cmd_claim(claim_args('holder-b'))),
                name='stealer')
            thief.start()
            self.assertTrue(at_the_window.wait(30), 'the stealer never reached the unlink')
            outcome['renew'] = co.cmd_claim(claim_args('holder-a'))
            renewal_finished.set()
            thief.join(30)
            self.assertFalse(thief.is_alive(), 'the stealer never finished')

        # EXACTLY ONE WINNER. Which one is not the point - the rival is entitled to
        # take a lease that had in fact run out - but they cannot both be told yes.
        self.assertEqual(sorted(outcome.values()), [0, 1], outcome)
        survivor = json.loads(path.read_text(encoding='utf-8'))
        winner = 'holder-b' if outcome['steal'] == 0 else 'holder-a'
        self.assertEqual(survivor['holder'], winner,
                         'the surviving claim belongs to neither reported winner')
        self.assertTrue(self.generation_is_free(resource, path),
                        'a generation token was still held after the race that took it')
        path.unlink(missing_ok=True)

    def test_a_forced_release_cannot_unlink_the_claim_that_replaced_it(self):
        """The same window, one function along, and wider because of --force.

        cmd_release re-reads through release_still_ours() and then unlinks, which is
        the two-syscall gap that function's own docstring is about - closed for the
        case it describes and left open underneath it.

        WITHOUT --force the claim has to still be ours and unexpired, so a rival can
        only act in the microseconds between the check and the unlink. WITH it,
        release_still_ours() returns True for a claim that has ALREADY EXPIRED, and an
        expired claim is exactly what a stealer is entitled to take. So the rival is
        not racing a microsecond; it takes the claim legitimately, links its own, and
        our unlink deletes THEIRS. The rival is told "claimed", `agentmux claims`
        shows the resource free, and the next agent along takes it too.
        """
        resource = 'taskmgmt/release-race.py'
        co.CLAIMS_DIR.mkdir(parents=True, exist_ok=True)
        path = co.CLAIMS_DIR / co.flatten(resource)
        path.write_text(json.dumps({
            'resource': resource, 'holder': 'holder-a', 'at': 'earlier',
            'ttl': 60, 'expires_at': time.time() - 1,
            'note': '', 'task': None, 'depends_on': [],
        }), encoding='utf-8')

        at_the_window = threading.Event()
        steal_finished = threading.Event()
        real_unlink = Path.unlink

        def unlink_at_the_window(target, *args, **kwargs):
            # The releasing thread only. The stealer unlinks this same path on its way
            # through, and blocking that too would just deadlock the pair.
            if (os.fspath(target) == os.fspath(path)
                    and threading.current_thread().name == 'releaser'):
                at_the_window.set()
                steal_finished.wait(30)
            return real_unlink(target, *args, **kwargs)

        outcome = {}
        quiet = {'journal': lambda *a, **k: 'journal', 'broadcast': lambda *a, **k: 0,
                 'post': lambda *a, **k: None, 'all_claims': lambda *a, **k: []}
        with contextlib.ExitStack() as stack:
            for name, value in quiet.items():
                stack.enter_context(patch.object(co, name, value))
            stack.enter_context(patch.object(Path, 'unlink', unlink_at_the_window))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            releaser = threading.Thread(
                target=lambda: outcome.setdefault('release', co.cmd_release(
                    argparse.Namespace(resource=resource, holder='holder-a', force=True))),
                name='releaser')
            releaser.start()
            self.assertTrue(at_the_window.wait(30), 'the releaser never reached the unlink')
            outcome['steal'] = co.cmd_claim(argparse.Namespace(
                resource=resource, holder='holder-b', ttl=60,
                note=None, task=None, depends_on=[]))
            steal_finished.set()
            releaser.join(30)
            self.assertFalse(releaser.is_alive(), 'the releaser never finished')

        # WHOEVER WAS TOLD THEY HOLD IT, HOLDS IT. Either outcome is defensible on its
        # own - the release was forced, and the lease had expired - but a rival told
        # "claimed" while the resource sits free is the one that puts two agents on
        # the same file.
        if outcome['steal'] == 0:
            self.assertTrue(path.exists(),
                            'the stealer was told it claimed a resource that is now free')
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['holder'],
                             'holder-b')
        else:
            self.assertFalse(path.exists(),
                             'nobody holds it, yet the claim file is still there')
        self.assertTrue(self.generation_is_free(resource, path),
                        'a generation token was still held after the race that took it')
        path.unlink(missing_ok=True)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SandboxCoordination))
    TEMP.cleanup()
    failed = len(result.failures) + len(result.errors)
    print(f'passed {result.testsRun - failed}, failed {failed}', flush=True)
    sys.exit(bool(failed))
