"""Native termination remains one effect when Hub lifecycle completion retries."""
import os
from pathlib import Path
import platform
import shlex
import shutil
import sys
import unittest
from unittest.mock import patch

from hub import server
from hub.tests import test_hub_offline as native_support
from . import test_hub_work_maintenance as maintenance_support
from .test_work_source import SelectedWorkSourceFixture


@unittest.skipUnless(os.environ.get('AGENTMUX_TEST_NATIVE_TMUX') == '1'
                     and sys.platform == 'darwin' and platform.machine() == 'arm64',
                     'requires explicit native macOS ARM64 tmux qualification')
class NativeHubKillRecoveryTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = maintenance_support.HubWorkMaintenanceTests.configure_channels
    asyncSetUp = maintenance_support.HubWorkMaintenanceTests.asyncSetUp
    request = maintenance_support.HubWorkMaintenanceTests.request
    claim_both = maintenance_support.HubWorkMaintenanceTests.claim_both

    def setUp(self):
        SelectedWorkSourceFixture.setUp(self)
        # Keep the original native fixture's process, socket and cleanup owner.
        self.native = native_support.NativeDeliveryOwnership(
            'test_native_termination_confirms_original_session')
        self.addCleanup(self.close_native)
        self.native.setUp()

    def close_native(self):
        self.assertTrue(self.native.doCleanups(), 'original native fixture cleanup failed')

    def prepare_harness(self, session):
        native = self.native
        source = Path(__file__).resolve().parents[1] / 'agentmux.sh'
        harness = native.root / 'harness.sh'
        script = source.read_text()
        dispatch = '\ncase "${1:-}" in\n'
        self.assertEqual(script.count(dispatch), 1, 'expected one harness dispatch marker')
        harness.write_text(script.replace(dispatch, '\nreturn 0 # stop fixture dispatch\n'))
        home = native.root / 'home'
        (home / 'run').mkdir(parents=True)
        (home / 'run' / (session + '.started')).write_text('original')
        (home / 'run' / (session + '.task')).write_text('SYNTHETIC-1')
        binary = shutil.which('bash')
        self.assertIsNotNone(binary)
        wrapper = native.root / 'agentmux-fixture'
        wrapper.write_text('#!' + binary + '\n'
            + 'source ' + shlex.quote(str(harness)) + ' || exit 2\n'
            + 'SOCKET=' + shlex.quote(native.socket) + '\n'
            + '''tm() {
  if [ "$1" = if-shell ]; then
    printf 'attempt\\n' >> "$ROOT/physical-stop-attempts"
  fi
  command ''' + shlex.quote(native.binary) + ''' -N -L "$SOCKET" "$@"
}
task_cli() { return 0; }
claim_reported() { return 0; }
task_try() { printf '%s\\n' "$1" >> "$ROOT/closeout"; }
claude_credentials_sync() { printf 'synchronized\\n' > "$ROOT/sync"; }
stop_courier_if_idle() { :; }
stop_idle_watchdog_if_no_agents() { :; }
[ "$1" = kill ] || exit 2
[ -n "${AGENTMUX_KILL_EXPECTED_TARGET:-}" ] || exit 2
[ "$AGENTMUX_KILL_EXPECTED_TARGET" = "$(kill_target_snapshot "$2")" ] || exit 2
printf 'checked\\n' >> "$ROOT/expected-target-checked"
cmd_kill "$2"
''')
        wrapper.chmod(0o700)
        self.enterContext(patch.dict(os.environ, AGENTMUX_BIN=str(wrapper),
            AGENTMUX_HOME=str(home), AGENTMUX_NO_COURIER='1', AGENTMUX_IDLE_MINUTES='0',
            AGENTMUX_OWNER_TERMINATION='0'))
        return home

    async def test_real_stop_then_interrupted_state_recovers_without_second_termination(self):
        native = self.native
        self.hub.tp = native.transport
        session, generation = await self.maintenance.register(
            'falcon', 'worker', 'native_kill', 'codex', {},
            handle=native.original[0], pane_pid=native.original[1])
        native.tm('rename-session', '-t', 'target', session)
        self.assertEqual(native.transport.handle(session), native.original)
        agent = await self.hub.db(self.hub.store.agent, session)
        self.assertEqual(agent['generation'], generation)
        self.assertTrue(await self.hub._apply_observed_state(agent, 'ready'))
        agent = await self.hub.db(self.hub.store.agent, session)
        rows = await self.claim_both(agent)
        home = self.prepare_harness(session)
        arguments = {'session': session, 'reason': 'native interrupted kill'}
        apply_kill = self.hub._apply_kill
        interrupted = False

        async def interrupt_after_real_stop(original, reason):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                self.assertIsNone(native.transport.handle(session))
                self.assertEqual(native.transport.handle('sentinel'), native.sentinel)
                raise server.HubError('injected interruption after native termination')
            return await apply_kill(original, reason)

        with patch.object(self.hub, 'harness', wraps=self.hub.harness) as terminate, \
                patch.object(self.hub, '_apply_kill', side_effect=interrupt_after_real_stop):
            with self.assertRaisesRegex(server.HubError, 'injected interruption'):
                await self.request('kill', arguments, 'native-original-kill')
            self.assertEqual((await self.hub.db(self.hub.store.agent, session))['state'], 'ready')
            self.assertEqual(len(await self.hub.db(self.hub.store.q, 'SELECT * FROM claims')), 2)
            result = await self.request('kill', arguments, 'native-original-kill')
            self.assertEqual(result, {'killed': session})
            terminate.assert_called_once_with('kill', session, expected_agent=agent)

        self.assertTrue(interrupted)
        self.assertIsNone(native.transport.handle(session))
        self.assertEqual(native.transport.handle('sentinel'), native.sentinel)
        self.assertEqual((home / 'physical-stop-attempts').read_text(), 'attempt\n')
        self.assertEqual((home / 'expected-target-checked').read_text(), 'checked\n')
        self.assertEqual((home / 'closeout').read_text(), 'done\nreport\n')
        self.assertEqual((home / 'sync').read_text(), 'synchronized\n')
        self.assertFalse((home / 'run' / (session + '.started')).exists())
        current = await self.hub.db(self.hub.store.agent, session)
        self.assertEqual((current['state'], current['generation']), ('dead', generation))
        events = await self.hub.db(self.hub.store.q,
            "SELECT * FROM events WHERE entity_id=? AND event='kill'", (session,))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['actor'], 'operator')
        actual = await self.hub.db(self.hub.store.q,
            'SELECT * FROM work_items WHERE id IN (?,?) ORDER BY repo',
            tuple(row['id'] for row in rows))
        self.assertEqual(len(actual), 2)
        self.assertTrue(all(row['state'] == 'ready' and row['claimed_by'] is None for row in actual))
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT * FROM claims'), [])
