"""Offline shell regression for owner request metadata failure."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class OwnerRequestCleanupTests(unittest.TestCase):
    def test_failed_cleanup_kill_retains_live_session_metadata(self):
        with tempfile.TemporaryDirectory(prefix='orchestration-shell-') as folder:
            root = Path(folder)
            state = root / 'sessions'
            state.mkdir()
            binary = root / 'bin'
            binary.mkdir()
            harness = root / 'agentmux.sh'
            harness.write_text((REPO / 'agentmux.sh').read_text())
            tmux = binary / 'tmux'
            tmux.write_text("""#!/usr/bin/env python3
import os, pathlib, sys
args=sys.argv[3:]
root=pathlib.Path(os.environ['FAKE_STATE'])
command=args[0]
def target():
    return args[args.index('-t')+1].lstrip('=')
if command=='has-session':sys.exit(0 if (root/target()).exists() else 1)
if command=='new-session':
    (root/args[args.index('-s')+1]).write_text('live')
    sys.exit(0)
if command=='list-panes':print('%1');sys.exit(0)
if command=='display-message':print('0');sys.exit(0)
if command=='list-sessions':
    for path in root.iterdir():print(path.name)
    sys.exit(0)
if command=='kill-session':sys.exit(1)
sys.exit(0)
""")
            tmux.chmod(0o755)
            chmod = binary / 'chmod'
            chmod.write_text("""#!/bin/sh
case "${@: -1}" in *.request) exit 1;; esac
exec /bin/chmod "$@"
""")
            chmod.chmod(0o755)
            sleep = binary / 'sleep'
            sleep.write_text('#!/bin/sh\nexit 0\n')
            sleep.chmod(0o755)
            home = root / 'home'
            environment = dict(os.environ, AGENTMUX_HOME=str(home),
                AGENTMUX_NO_COURIER='1', AGENTMUX_OWNER_REQUEST='one',
                FAKE_STATE=str(state), PATH=str(binary) + ':' + os.environ['PATH'])
            result = subprocess.run(['bash', str(harness), 'spawn', 'owner-one',
                '--cli', 'shell', '--cwd', str(root)], env=environment,
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 75, result.stderr)
            self.assertTrue((state / 'owner-one').exists())
            sidecars = list((home / 'run').glob('owner-one.*'))
            self.assertTrue(sidecars)
            self.assertTrue((home / 'run' / 'owner-one.cli').exists())
            self.assertIn('termination unconfirmed', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
