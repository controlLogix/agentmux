"""Windows launcher. Python 3 is required; the calling shell still parses syntax."""
import os
import re
import subprocess
import sys
import ntpath


def validate_callback(env, verb=None):
    if "AGENTMUX_WINDOWS_CALLBACK" not in env:
        return False
    if env["AGENTMUX_WINDOWS_CALLBACK"] != "1":
        raise ValueError("AGENTMUX_WINDOWS_CALLBACK must be 1 when set")
    distro = env.get("AGENTMUX_WSL_DISTRO", "")
    binary = env.get("AGENTMUX_WSL_BIN", "")
    home = env.get("AGENTMUX_HOME", "")
    if not distro or distro.startswith("-") or any(c in distro for c in "\r\n\0"):
        raise ValueError("Windows agent callbacks need an explicit WSL distribution")
    if not binary.startswith("/") or any(c in binary for c in "\r\n\0"):
        raise ValueError("Windows agent callbacks need an explicit absolute Linux binary path")
    if not home or not (home.startswith("/") or ntpath.isabs(home)) or any(c in home for c in "\r\n\0"):
        raise ValueError("Windows agent callbacks need an explicit absolute AGENTMUX_HOME")
    match = re.fullmatch(r"tcp://127\.0\.0\.1:([0-9]{1,5})", env.get("AGENTMUX_HUB_URL", ""))
    if not match or not 1 <= int(match[1]) <= 65535:
        raise ValueError("Windows agent callbacks need tcp://127.0.0.1:<port>")
    if not env.get("AGENTMUX_HUB_TOKEN_FILE") or env.get("AGENTMUX_HUB_TOKEN"):
        raise ValueError("Windows agent callbacks need an agent token file and no inline token")
    if verb is not None and verb not in {
        "ping", "status", "whoami", "token", "subscribe", "inbox", "ack",
        "claim", "heartbeat", "done", "fail", "return", "block", "post", "work",
        "release", "work_add", "work_show", "work_list",
    }:
        raise ValueError("This operation is not available through an agent callback")
    return True


def command(args, env):
    distro = env.get("AGENTMUX_WSL_DISTRO", "Ubuntu")
    binary = env.get("AGENTMUX_WSL_BIN", "/home/nick/.local/bin/agentmux")
    if not distro or distro.startswith("-") or any(c in distro for c in "\r\n\0"):
        raise ValueError("AGENTMUX_WSL_DISTRO must name a WSL distribution")
    if not binary.startswith("/") or any(c in binary for c in "\r\n\0"):
        raise ValueError("AGENTMUX_WSL_BIN must be an absolute Linux path")
    if validate_callback(env) and (not args or args[0] != "hub"):
        raise ValueError("Windows agent callbacks support hub commands only")
    result = ["wsl.exe", "--distribution", distro]
    if "AGENTMUX_WSL_CWD" in env:
        cwd = env["AGENTMUX_WSL_CWD"]
        if not cwd.startswith("/") or any(c in cwd for c in "\r\n\0"):
            raise ValueError("AGENTMUX_WSL_CWD must be an absolute Linux path")
        result += ["--cd", cwd]
    return result + ["--exec", binary, *args]


def environment(env):
    result = dict(env)
    if validate_callback(env):
        paths = {"AGENTMUX_HOME", "AGENTMUX_REPO", "AGENTMUX_HUB_TOKEN_FILE", "TMUX_TMPDIR"}
        keys = paths | {"AGENTMUX_WINDOWS_CALLBACK", "AGENTMUX_AGENT", "AGENTMUX_SOCKET",
                        "AGENTMUX_HUB_URL", "AGENTMUX_WSL_DISTRO", "AGENTMUX_WSL_BIN", "AGENTMUX_WSL_CWD"}
        entries = [x for x in env.get("WSLENV", "").split(":") if x and x.split("/", 1)[0] not in keys]
        for key in sorted(keys):
            if key in env:
                entries.append(key + ("/pu" if key in paths else "/u"))
        result["WSLENV"] = ":".join(entries)
    return result


def main():
    try:
        return subprocess.call(command(sys.argv[1:], os.environ), env=environment(os.environ))
    except (ValueError, OSError) as exc:
        print(f"agentmux: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
