"""Offline checks for the MCP configuration passed to a managed Claude pane."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class ClientLaunchConfig(unittest.TestCase):
    def test_checkout_path_survives_json_and_shell_encoding(self):
        source = Path(__file__).resolve().parents[2] / "agentmux.sh"
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "isolated home"
            home.mkdir()
            for name in ("ordinary checkout", "quote\" and ' apostrophe", "back\\slash", "$(touch SHOULD_NOT_EXIST)"):
                with self.subTest(name=name):
                    checkout = Path(tmp) / name
                    checkout.mkdir()
                    (checkout / "agentmux.sh").touch()
                    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTMUX_")}
                    env.update(HOME=str(home), AGENTMUX_REPO=str(checkout),
                               AGENTMUX_HOME=str(home / "state"))
                    # Source the actual functions without spawning a client or tmux.
                    # Round-trip the same shell quoting used by cmd_spawn.
                    script = '''source "$1" help >/dev/null
config="$(agentmux_mcp_config "${2:-}")" || exit 1
printf -v quoted '%q' "$config"
eval "printf '%s' $quoted"
'''
                    selection = "" if name == "ordinary checkout" else str(home / (name + ".json"))
                    result = subprocess.run(["bash", "-c", script, "test", str(source), selection],
                                            env=env, cwd=home, capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    config = json.loads(result.stdout)
                    arguments = [str(checkout / "hub/cli.py"), "mcp"]
                    if selection:
                        arguments += ["--enrolled", "--selection", selection, "--managed-worker"]
                    self.assertEqual(config, {"mcpServers": {"agentmux": {
                        "command": "python3", "args": arguments}}})
                    self.assertFalse((home / "SHOULD_NOT_EXIST").exists())


if __name__ == "__main__":
    unittest.main()
