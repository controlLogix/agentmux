"""Test and demo harness for cross-user federation (docs/FEDERATION.md).

Circle: a NATS server in operator mode with real JWT users - either
  - local: a throwaway nats-server + nsc circle (no TLS), or
  - kind:  the phase-0 cluster from deploy/nats/up.sh (TLS, 3 replicas)  [AGENTMUX_FED_KIND=1]
Person: one hub on its own AGENTMUX_HOME, with its own creds, its own clone of the
shared repo (under its own local name), and agents registered straight into the store
(no panes), acted for with --as exactly like the TM-218 test.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from hub.fed.policy import normalize_remote  # noqa: E402
from hub.store import Store  # noqa: E402

PY = os.path.join(ROOT, ".venv", "bin", "python")
if not os.path.exists(PY):
    PY = sys.executable
CIRCLE_SH = os.path.join(ROOT, "deploy", "nats", "circle.sh")
NATS = shutil.which("nats-server")
NSC = shutil.which("nsc")
ROLE = {"capabilities": ["python", "code"], "max_active": 2, "lease_s": 900}


def have_deps():
    try:
        r = subprocess.run([PY, "-c", "import nats, nkeys"], capture_output=True)
        return r.returncode == 0 and bool(NSC)
    except OSError:
        return False


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait(pred, timeout=15.0, every=0.2):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = pred()
        except Exception:  # noqa: BLE001 - a probe that fails is just not ready yet
            v = None
        if v:
            return v
        time.sleep(every)
    return pred()


def call(sock, verb, args=None, as_=None, timeout=60):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    s.connect(sock)
    req = {"verb": verb, "args": args or {}}
    if as_:
        req["as"] = as_
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    return json.loads(buf)


def sh(*cmd, cwd=None, env=None, check=True):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr or r.stdout}")
    return r.stdout.strip()


class Circle:
    def __init__(self, peers=("nick", "alice", "mallory"), kind=None):
        self.kind = os.environ.get("AGENTMUX_FED_KIND") == "1" if kind is None else kind
        self.peers = peers
        self.proc = None
        if self.kind:
            gen = os.path.join(ROOT, "deploy", "nats", ".generated")
            self.dir = os.path.join(gen, "circle")
            self.url, self.ca = "tls://127.0.0.1:4222", os.path.join(gen, "tls", "ca.pem")
            self.env = {**os.environ, "AGENTMUX_CIRCLE_DIR": self.dir}
            for p in peers:
                if not os.path.exists(os.path.join(self.dir, f"{p}.creds")):
                    sh(CIRCLE_SH, "add", p, env=self.env)
            self.reset()
        else:
            self.tmp = tempfile.mkdtemp(prefix="fedcircle-", dir="/tmp")
            self.dir = os.path.join(self.tmp, "circle")
            self.env = {**os.environ, "AGENTMUX_CIRCLE_DIR": self.dir}
            sh(CIRCLE_SH, "init", "testcircle", env=self.env)
            for p in peers:
                sh(CIRCLE_SH, "add", p, env=self.env)
            port = free_port()
            conf = os.path.join(self.tmp, "nats.conf")
            sh(CIRCLE_SH, "server-conf", conf, str(port), os.path.join(self.tmp, "js"), env=self.env)
            self.proc = subprocess.Popen([NATS, "-c", conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.url, self.ca = f"nats://127.0.0.1:{port}", ""
            def broker_ready():
                with socket.create_connection(("127.0.0.1", port), 1):
                    return True
            wait(broker_ready, 10)
            self.provision()

    def creds(self, peer):
        return os.path.join(self.dir, f"{peer}.creds")

    def provision(self):
        args = [PY, "-m", "hub.fed.admin", "provision", "--url", self.url, "--creds", self.creds("admin"),
                "--replicas", "3" if self.kind else "1"]
        if self.ca:
            args += ["--ca", self.ca]
        sh(*args, cwd=ROOT)

    def reset(self):
        """kind: wipe streams, consumers and buckets so a run starts clean."""
        code = f"""
import asyncio
from hub.fed import conn
async def main():
    nc = await conn.connect({self.url!r}, {self.creds('admin')!r}, {self.ca!r}, 'reset')
    js = nc.jetstream()
    for s in list(conn.STREAMS) + ['KV_' + b for b in conn.BUCKETS]:
        try:
            await js.delete_stream(s)
        except Exception:
            pass
    await conn.close(nc)
asyncio.run(main())
"""
        sh(PY, "-c", code, cwd=ROOT)
        self.provision()

    def close(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)


class Person:
    """One person's hub. repos: {local_name: clone_path}; agents: [(repo, role, agent)]."""

    def __init__(self, peer, circle, repos, agents, trust=None, node=None, plugins=None, extra=None, home=None,
                 live=False):
        """live=True: the hub can spawn real panes (the agentmux harness on its tmux
        socket), for the demo's real-claude mode. Tests keep it off: no panes."""
        self.peer = peer
        self.home = home or tempfile.mkdtemp(prefix=f"fed-{peer}-", dir="/tmp")
        hub = os.path.join(self.home, "hub")
        os.makedirs(hub)
        node = node or f"{peer}_box"
        with open(os.path.join(hub, "config.toml"), "w") as f:
            f.write(f'node = "{node}"\npoll_s = 0.5\n')
        s = Store(os.path.join(hub, "hub.db"))
        for repo, path in repos.items():
            origin = sh("git", "-C", path, "remote", "get-url", "origin")
            s.repo_add(repo, paths=[path], aliases=[normalize_remote(origin)])
        self.sessions = []
        for repo, role, agent, *caps in agents:
            snap = {**ROLE, "capabilities": ROLE["capabilities"] + (caps[0] if caps else [])}
            sess = s.register(repo, role, agent, "codex", snap)
            s.set_state(sess, "ready")
            self.sessions.append(sess)
        s.db.close()
        lines = ["[federation]", "enabled = true", f'url = "{circle.url}"', f'creds = "{circle.creds(peer)}"',
                 f'ca = "{circle.ca}"', f'peer = "{peer}"', "presence_every_s = 2"]
        if plugins:
            lines.append("plugins = " + json.dumps(plugins))
        for k, v in (extra or {}).items():
            lines.append(f"{k} = {json.dumps(v)}")
        for repo in repos:
            lines += ["", f"[repos.{repo}]", 'peers = ["*"]']
        for p, t in (trust or {}).items():
            lines += ["", f'[peers."{p}"]', f'trust = "{t}"']
        with open(os.path.join(hub, "federation.toml"), "w") as f:
            f.write("\n".join(lines) + "\n")
        env = {**os.environ, "AGENTMUX_HOME": self.home}
        if not live:
            env.update(AGENTMUX_SOCKET=f"fed-{peer}-none", AGENTMUX_BIN="/usr/bin/true")
        self.log = open(os.path.join(hub, "hub.log"), "w")
        self.proc = subprocess.Popen([PY, os.path.join(ROOT, "hub", "server.py")], env=env, cwd=ROOT,
                                     stdout=self.log, stderr=self.log, stdin=subprocess.DEVNULL,
                                     start_new_session=True)
        self.sock = os.path.join(hub, "hub.sock")
        if not wait(lambda: os.path.exists(self.sock), 20):
            raise RuntimeError(f"{peer}'s hub did not start: {open(self.log.name).read()[-2000:]}")
        if not wait(lambda: self("fed_status")["result"]["connected"], 30):
            raise RuntimeError(f"{peer}'s hub did not connect: {self('fed_status')}\n"
                               f"{open(self.log.name).read()[-2000:]}")

    def __call__(self, verb, args=None, as_=None, timeout=60):
        return call(self.sock, verb, args, as_, timeout)

    def ok(self, verb, args=None, as_=None):
        r = self(verb, args, as_)
        if not r.get("ok"):
            raise AssertionError(f"{self.peer} {verb} {args}: {r.get('error')}")
        return r["result"]

    def inbox(self, session):
        return self.ok("inbox", {"session": session})["messages"]

    def close(self):
        try:
            self.log.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            self("shutdown")
        except Exception:  # noqa: BLE001
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            # Keep the original owner until the forced exit is reaped too.
            self.proc.wait(timeout=10)


def shared_repo(tmp, name="falcon"):
    """A bare 'shared remote' with one commit, and a function that clones it."""
    bare = os.path.join(tmp, f"{name}.git")
    sh("git", "init", "-q", "--bare", "-b", "main", bare)
    seed = os.path.join(tmp, "seed")
    sh("git", "clone", "-q", bare, seed)
    with open(os.path.join(seed, "README.md"), "w") as f:
        f.write(f"# {name}\n")
    sh("git", "-C", seed, "add", ".")
    sh("git", "-C", seed, "-c", "user.email=seed@example.invalid", "-c", "user.name=seed", "commit", "-qm", "init")
    sh("git", "-C", seed, "push", "-q", "origin", "main")

    def clone(dest):
        sh("git", "clone", "-q", bare, dest)
        sh("git", "-C", dest, "config", "user.email", f"{os.path.basename(dest)}@example.invalid")
        sh("git", "-C", dest, "config", "user.name", os.path.basename(dest))
        return dest
    return bare, clone


def run(coro):
    return asyncio.run(coro)
