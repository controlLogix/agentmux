"""Review candidate: owned watchdog tests, no PID adoption or process signals.

Default is plan-only. Main must review before either explicit scenario runs.
The generated watchdog body is unchanged. Only sleep and tmux dependencies are
private fixtures; the tmux sentinel must never be reached on a passing run.
"""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time

SOURCE_SHA256 = '310d538866f29478ef01bfd77c782dd62ead2a09eb1a244fe890bf96b1b36867'
MAX_FDS = 1024
CAPTURE_LIMIT = 65536
cancelled = False
owners = []


def require(value, code):
    if not value:
        raise ValueError(code)


def cancel(signum, frame):
    global cancelled
    cancelled = True


def held(path, pin):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 1024 * 1024,
                'fixture_source_metadata')
        raw = os.read(fd, 1024 * 1024 + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == pin and
                all(getattr(before, k) == getattr(after, k) for k in
                    ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                     'st_size', 'st_mtime_ns', 'st_ctime_ns')), 'fixture_source_changed')
        return raw
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(count > 0, 'fixture_short_write')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    write_new(path, (json.dumps(value, sort_keys=True) + '\n').encode())


def capture_bytes(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                before.st_size <= CAPTURE_LIMIT, 'fixture_capture_metadata')
        raw = os.read(fd, CAPTURE_LIMIT + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k)
                for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_size',
                          'st_mtime_ns', 'st_ctime_ns')), 'fixture_capture_changed')
        return raw
    finally:
        os.close(fd)


# Complete SDK26.5 public structures, not Darwin's different native stat layout.
class ProcBSDInfo(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ('flags', 'status', 'xstatus', 'pid', 'ppid',
                'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')] + [
                ('comm', C.c_char * 16), ('name', C.c_char * 32),
                ('nfiles', C.c_uint32), ('pgid', C.c_uint32), ('pjobc', C.c_uint32),
                ('tdev', C.c_uint32), ('tpgid', C.c_uint32), ('nice', C.c_int32),
                ('start_sec', C.c_uint64), ('start_usec', C.c_uint64)]


class ProcFDInfo(C.Structure):
    _fields_ = [('fd', C.c_int32), ('kind', C.c_uint32)]


class ProcFileInfo(C.Structure):
    _fields_ = [('openflags', C.c_uint32), ('status', C.c_uint32),
                ('offset', C.c_int64), ('kind', C.c_int32), ('guardflags', C.c_uint32)]


class VInfoStat(C.Structure):
    _fields_ = [('dev', C.c_uint32), ('mode', C.c_uint16), ('nlink', C.c_uint16),
                ('ino', C.c_uint64), ('uid', C.c_uint32), ('gid', C.c_uint32)] + [
                (n, C.c_int64) for n in ('atime', 'atime_ns', 'mtime', 'mtime_ns',
                'ctime', 'ctime_ns', 'birthtime', 'birthtime_ns', 'size', 'blocks')] + [
                ('blksize', C.c_int32), ('flags', C.c_uint32), ('gen', C.c_uint32),
                ('rdev', C.c_uint32), ('spare', C.c_int64 * 2)]


class VNodeInfo(C.Structure):
    _fields_ = [('metadata', VInfoStat), ('kind', C.c_int32), ('pad', C.c_int32),
                ('fsid', C.c_int32 * 2)]


class VNodeFDInfo(C.Structure):
    _fields_ = [('file', ProcFileInfo), ('vnode', VNodeInfo)]


def native_library():
    require(sys.platform == 'darwin' and os.uname().machine == 'arm64', 'native_target_not_qualified')
    require(tuple(C.sizeof(v) for v in (ProcBSDInfo, ProcFDInfo, ProcFileInfo,
                VInfoStat, VNodeInfo, VNodeFDInfo)) == (136, 8, 24, 136, 152, 176),
            'native_fd_layout_refused')
    lib = C.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    lib.proc_pidinfo.restype = C.c_int
    lib.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
    lib.proc_pidfdinfo.restype = C.c_int
    lib.proc_pidfdinfo.argtypes = [C.c_int, C.c_int, C.c_int, C.c_void_p, C.c_int]
    return lib


def owned_pid(owner):
    require(isinstance(owner, Owned) and owner.child is not None and not owner.joined and
            owner.child.returncode is None, 'inspection_requires_unreaped_creator_owner')
    # Query argument only. There is no public numeric-PID input or signal API.
    return owner.child.pid


def darwin_stamp(lib, owner):
    value = ProcBSDInfo()
    pid = owned_pid(owner)
    require(lib.proc_pidinfo(pid, 3, 0, C.byref(value), C.sizeof(value)) == C.sizeof(value),
            'native_process_observation_failed')
    require(value.pid == pid and value.ppid == os.getpid() and value.uid == os.geteuid() and
            value.status not in (0, 5) and not value.flags & 4 and value.start_sec > 0,
            'owned_process_not_live')
    return value.start_sec, value.start_usec


def darwin_fd_list(lib, owner):
    values = (ProcFDInfo * (MAX_FDS + 1))()
    size = C.sizeof(values)
    count = lib.proc_pidinfo(owned_pid(owner), 1, 0, C.byref(values), size)
    require(0 < count < size and count % C.sizeof(ProcFDInfo) == 0, 'native_fd_list_incomplete')
    result = [(values[i].fd, values[i].kind) for i in range(count // C.sizeof(ProcFDInfo))]
    require(len(result) <= MAX_FDS and len({fd for fd, _ in result}) == len(result) and
            all(fd >= 0 and kind in (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11) for fd, kind in result),
            'native_fd_list_schema')
    return sorted(result)


def darwin_probe(owner, probe, lib=None):
    lib = native_library() if lib is None else lib
    before = darwin_stamp(lib, owner)
    descriptors = darwin_fd_list(lib, owner)
    matches, checked = [], 0
    for fd, kind in descriptors:
        if kind != 1:  # PROX_FDTYPE_VNODE
            continue
        value = VNodeFDInfo()
        require(lib.proc_pidfdinfo(owned_pid(owner), fd, 1, C.byref(value), C.sizeof(value)) == C.sizeof(value),
                'native_vnode_fd_observation_failed')
        checked += 1
        if (value.vnode.metadata.dev, value.vnode.metadata.ino) == (probe[0] & 0xffffffff, probe[1]):
            matches.append(fd)
    require(darwin_fd_list(lib, owner) == descriptors and darwin_stamp(lib, owner) == before,
            'native_fd_observation_changed')
    require(checked > 0, 'native_no_vnode_fd_observation')
    return {'platform': 'darwin', 'matchingFDs': matches, 'vnodeFDsChecked': checked,
            'processStart': list(before), 'completeStableEnumeration': True}


def linux_stamp(owner):
    raw = Path('/proc/' + str(owned_pid(owner)) + '/stat').read_text()
    fields = raw.rsplit(')', 1)[1].split()
    require(fields[0] != 'Z' and int(fields[1]) == os.getpid(), 'owned_process_not_live')
    return fields[19]  # Field 22: starttime, with field 3 at index zero.


def linux_probe(owner, probe):
    before = linux_stamp(owner)
    directory = '/proc/' + str(owned_pid(owner)) + '/fd'
    names = sorted(os.listdir(directory))
    require(0 < len(names) <= MAX_FDS and all(re.fullmatch(r'[0-9]+', n) for n in names),
            'linux_fd_list_incomplete')
    matches = []
    for name in names:
        value = os.stat(directory + '/' + name)
        if (value.st_dev, value.st_ino) == probe:
            matches.append(int(name))
    require(sorted(os.listdir(directory)) == names and linux_stamp(owner) == before,
            'linux_fd_observation_changed')
    return {'platform': 'linux', 'matchingFDs': matches, 'completeStableEnumeration': True}


def inspect_fds(owner, probe):
    if sys.platform == 'darwin':
        return darwin_probe(owner, probe)
    require(sys.platform.startswith('linux'), 'native_fd_backend_missing')
    return linux_probe(owner, probe)


COOPERATIVE = r'''import os,select,sys,time
os.write(1,b"READY\n")
end=time.monotonic()+15
ready=select.select([0],[],[],max(0,end-time.monotonic()))[0]
if not ready:
 os.write(1,b"LIFETIME_EXPIRED\n");raise SystemExit(124)
value=os.read(0,1)
if value==b"T":
 os.write(1,b"TICK\n");raise SystemExit(0)
os.write(1,b"EOF_CLEANUP\n");raise SystemExit(125)
'''
LAUNCH = r'''import os,sys
fd=int(sys.argv[1]);os.dup2(fd,200,inheritable=True)
if fd!=200:os.close(fd)
os.execve(sys.argv[2],sys.argv[2:],dict(os.environ))
'''


class Owned:
    """Retain the original Popen and capture descriptors through its sole wait."""
    def __init__(self, argv, env, directory, label, pass_fds=()):
        self.child, self.joined, self.timeout, self.cleanup_eof = None, False, False, False
        self.output_joined = False
        self.capture_errors, self.stdout_bytes, self.label = [], bytearray(), label
        self.outfd = self.errfd = None
        owners.append(self)  # Register the owner before any process can be created.
        try:
            self.outfd = os.open(str(directory / (label + '.stdout')), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.errfd = os.open(str(directory / (label + '.stderr')), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            require(not cancelled, 'fixture_cancelled_before_creation')
            # All owner/capture construction precedes actual process creation.
            self.child = subprocess.Popen(argv, env=env, cwd=str(directory), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=self.errfd, pass_fds=pass_fds, close_fds=True, shell=False)
        except BaseException:
            if self.child is None:
                self.close_captures()
            raise

    def note(self, code):
        if code not in self.capture_errors:
            self.capture_errors.append(code)

    def close_captures(self):
        for name in ('outfd', 'errfd'):
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is None:
                continue
            try:
                os.fsync(fd)
            except BaseException:
                self.note('capture_fsync_failed')
            try:
                os.close(fd)
            except BaseException:
                self.note('capture_close_failed')

    def capture(self, raw):
        if len(self.stdout_bytes) + len(raw) > CAPTURE_LIMIT:
            self.note('capture_overflow')
        kept = raw[:max(0, CAPTURE_LIMIT - len(self.stdout_bytes))]
        self.stdout_bytes.extend(kept)
        try:
            require(os.write(self.outfd, kept) == len(kept), 'capture_short_write')
        except BaseException:
            self.note('capture_write_failed')

    def ready(self, deadline):
        while not self.stdout_bytes.endswith(b'READY\n'):
            require(not cancelled and time.monotonic() < deadline, 'fixture_readiness_deadline')
            readable = select.select([self.child.stdout], [], [], min(0.1, deadline - time.monotonic()))[0]
            if readable:
                raw = os.read(self.child.stdout.fileno(), 64)
                require(raw, 'fixture_exited_before_ready')
                self.capture(raw)
        require(bytes(self.stdout_bytes) == b'READY\n', 'fixture_readiness_protocol')

    def tick(self):
        require(not cancelled, 'fixture_cancelled_before_tick')
        self.child.stdin.write(b'T')
        self.child.stdin.flush()

    def cleanup_input(self):
        self.cleanup_eof = True  # Cleanup exit can never satisfy a behavioral test.
        try:
            if not self.child.stdin.closed:
                self.child.stdin.close()
        except BaseException:
            self.note('cleanup_input_close_failed')

    def join(self, deadline):
        require(self.child is not None and not self.output_joined, 'sole_wait_owner_required')
        while not self.joined:
            try:
                self.child.wait(timeout=max(0.001, min(5, deadline - time.monotonic())) if not self.timeout else 5)
                self.joined = True
                if time.monotonic() >= deadline:
                    self.timeout = True
                break
            except subprocess.TimeoutExpired:
                if not self.timeout and time.monotonic() < deadline:
                    continue  # Poll only; preserve the owner and original deadline.
                self.timeout = True
                self.cleanup_input()
                try:
                    print('owned_fixture_wait_unconfirmed; retain original owner', flush=True)
                except BaseException:
                    self.note('progress_output_failed')
            except BaseException:
                self.note('owned_wait_unconfirmed')
                self.timeout = True
                self.cleanup_input()
                time.sleep(1)  # No retry of a PID, no signal or new success deadline.
        try:
            if not self.child.stdin.closed:
                self.child.stdin.close()
        except BaseException:
            self.note('input_close_failed')
        # The direct child has joined; retain all captures until pipe EOF too.
        while True:
            try:
                readable = select.select([self.child.stdout], [], [], 1)[0]
            except BaseException:
                self.note('output_observation_unconfirmed')
                time.sleep(1)
                continue
            if not readable:
                self.note('output_eof_unconfirmed')
                continue
            try:
                raw = os.read(self.child.stdout.fileno(), 4096)
            except BaseException:
                self.note('output_read_unconfirmed')
                time.sleep(1)
                continue
            if not raw:
                break
            self.capture(raw)
        try:
            self.child.stdout.close()
        except BaseException:
            self.note('output_close_failed')
        self.close_captures()
        self.output_joined = True
        return self.child.returncode


def heredoc(source):
    source = source.replace(b'\r\n', b'\n')
    begin = b'  cat > "$self" <<WATCHDOG\n'
    require(source.count(begin) == 1, 'watchdog_generator_boundary')
    body, separator, _ = source.split(begin, 1)[1].partition(b'\nWATCHDOG\n')
    require(separator and b'CLOSE EVERY DESCRIPTOR' in body and b'[ -d "$RUNDIR" ] || break' in body,
            'watchdog_body_refused')
    return body.decode() + '\n'


def generate(source, bash, env, directory, run, script):
    # Same unquoted heredoc expansion as production; only Bash builtins execute.
    program = ('script=' + shlex.quote(str(script)) + '\nRUNDIR=' + shlex.quote(str(run)) +
               '\nSOCKET=agentmux\nIFS= read -r -d "" generated <<WATCHDOG\n' + heredoc(source) +
               'WATCHDOG\nprintf "%s" "$generated"\n')
    owner = Owned([bash, '--noprofile', '--norc', '-c', program], env, directory, 'generator')
    # Generator output can exceed one pipe buffer only after a source change;
    # read it with the same owner before waiting, within the fixed capture cap.
    deadline = time.monotonic() + 8
    while True:
        require(time.monotonic() < deadline and not cancelled, 'generator_output_deadline')
        if select.select([owner.child.stdout], [], [], 0.1)[0]:
            raw = os.read(owner.child.stdout.fileno(), 4096)
            if not raw:
                break
            owner.capture(raw)
    require(owner.join(deadline) == 0 and not owner.capture_errors and not owner.timeout,
            'generator_failed')
    generated = bytes(owner.stdout_bytes)
    require(generated.startswith(b'#!/usr/bin/env bash\n'), 'generated_watchdog_missing')
    path = run / '.idle-watchdog.sh'
    write_new(path, generated, 0o700)
    return path, hashlib.sha256(generated).hexdigest()


def successful_behavior(owner, code, stderr):
    return (owner.joined and code == 0 and not owner.timeout and not owner.cleanup_eof and
            not owner.capture_errors and bytes(owner.stdout_bytes) == b'READY\nTICK\n' and
            not stderr and not cancelled)


def successful_home_behavior(owner, code, stderr, sentinel):
    return successful_behavior(owner, code, stderr) and sentinel == b''


def tmux_sentinel_program(sentinel):
    # Exact scenario only: run is removed before tick. On recording failure,
    # success avoids the tmux break; idle's missing-run redirection fails before
    # command execution, then another cooperative sleep cannot qualify success.
    return ('#!/bin/sh\nif printf "TMUX\\n" >> ' + shlex.quote(str(sentinel)) +
            '; then\n  exit 125\nelse\n  exit 0\nfi\n').encode()


def closeout_owners():
    # Covers failures during generation too, before scenario's inner try exists.
    # An interrupted pipe drain resumes without invoking a second process wait.
    for owner in owners:
        if owner.child is not None and not owner.output_joined:
            owner.cleanup_input()
            owner.join(time.monotonic())


def scenario(kind, missing_guard_mutation=False):
    require(kind in ('fd', 'home'), 'fixed_fixture_scenario')
    repo = Path(__file__).resolve().parents[1]
    source = held(repo / 'agentmux.sh', SOURCE_SHA256)
    directory = Path(tempfile.mkdtemp(prefix='agentmux-idle-owned-')).resolve()
    os.chmod(directory, 0o700)
    home, run, binary = directory / 'home', directory / 'home/run', directory / 'bin'
    run.mkdir(parents=True, mode=0o700)
    binary.mkdir(mode=0o700)
    (home / 'logs').mkdir(mode=0o700)
    bash = '/opt/homebrew/bin/bash' if sys.platform == 'darwin' else '/bin/bash'
    python = os.path.realpath(sys.executable)
    env = {'PATH': str(binary) + ':/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home),
           'TMPDIR': str(directory), 'TMUX_TMPDIR': str(directory), 'AGENTMUX_IDLE_TICK': '300'}
    write_new(binary / 'sleep', ('#!/bin/sh\nexec ' + shlex.quote(python) + ' -I -S -c ' +
                                shlex.quote(COOPERATIVE) + '\n').encode(), 0o700)
    sentinel = directory / 'tmux-invocations'
    write_new(sentinel, b'')
    # Independent of the watchdog's /dev/null redirections; retained outside HOME.
    write_new(binary / 'tmux', tmux_sentinel_program(sentinel), 0o700)
    watchdog, generated_sha = generate(source, bash, env, directory, run, repo / 'agentmux.sh')
    if missing_guard_mutation:
        # Mutate only the private retained generated artifact, never production.
        generated = held(watchdog, generated_sha)
        guard = ('  [ -d "' + str(run) + '" ] || break\n').encode()
        require(generated.count(guard) == 1, 'mutation_guard_count')
        mutated = generated.replace(guard, b'  : # private missing-home-guard mutation\n', 1)
        watchdog = run / '.idle-watchdog-mutated.sh'
        write_new(watchdog, mutated, 0o700)
        # Retain the unmodified generated file outside the disappearing home.
        os.rename(run / '.idle-watchdog.sh', directory / 'original-generated-watchdog.sh')
    probe_fd = os.open(str(directory / 'probe.lock'), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    probe_stat = os.fstat(probe_fd)
    result = {'scenario': kind, 'capture': str(directory), 'sourceSHA256': SOURCE_SHA256,
              'generatedSHA256': generated_sha, 'passed': False, 'signalsSent': False,
              'successRequiresZeroExit': True}
    try:
        # Match Bash startup too: a no-sweep Bash execs the cooperative observer.
        # All execs replace this same direct child; no detached launcher is used.
        positive_program = 'exec ' + shlex.quote(python) + ' -I -S -c ' + shlex.quote(COOPERATIVE)
        positive = Owned([python, '-I', '-S', '-c', LAUNCH, str(probe_fd), bash,
                          '--noprofile', '--norc', '-c', positive_program],
                         env, directory, 'positive', (probe_fd,))
        positive.ready(time.monotonic() + 1)
        positive_proof = inspect_fds(positive, (probe_stat.st_dev, probe_stat.st_ino))
        require(200 in positive_proof['matchingFDs'], 'inherited_probe_positive_control_failed')
        positive.tick()
        require(successful_behavior(positive, positive.join(time.monotonic() + 8),
                capture_bytes(directory / 'positive.stderr')), 'positive_control_closeout_failed')
        actual = Owned([python, '-I', '-S', '-c', LAUNCH, str(probe_fd), bash,
                        '--noprofile', '--norc', str(watchdog)], env, directory, 'watchdog', (probe_fd,))
        actual.ready(time.monotonic() + 1)
        negative = inspect_fds(actual, (probe_stat.st_dev, probe_stat.st_ino))
        require(not negative['matchingFDs'], 'probe_survived_watchdog_fd_sweep')
        # Preserve the generated bytes outside the home, then remove only exact
        # fixture-owned paths. No recursive deletion or shared-home cleanup.
        os.rename(watchdog, directory / 'generated-watchdog.sh')
        os.rmdir(run)
        os.rmdir(home / 'logs')
        os.rmdir(home)
        require(not os.path.lexists(run) and not os.path.lexists(home),
                'home_removal_not_proven')
        removed_at = time.monotonic()
        actual.tick()  # Successful sleep, NOT EOF: the real home guard must exit.
        code = actual.join(removed_at + 8)
        sentinel_bytes = capture_bytes(sentinel)
        stderr = capture_bytes(directory / 'watchdog.stderr')
        home_passed = successful_home_behavior(actual, code, stderr, sentinel_bytes)
        if missing_guard_mutation:
            require(successful_behavior(actual, code, stderr) and
                    sentinel_bytes == b'TMUX\n' and not home_passed and
                    all(o.joined and o.output_joined and not o.capture_errors and
                        not o.timeout and not o.cleanup_eof for o in owners),
                    'mutation_not_proven')
            result.update(mutation='missing-home-guard', sentinelInvoked=True,
                          homeOracleRefused=True)
        else:
            require(home_passed, 'home_disappearance_behavior_failed')
        result.update(positiveFDProof=positive_proof, watchdogFDProof=negative,
                      homeExitSeconds=time.monotonic() - removed_at, allOwnersJoined=True, passed=True)
    finally:
        # EOF is failure cleanup only. It never changes result.passed to true.
        closeout_owners()
        os.close(probe_fd)
        result['cancelled'] = cancelled
        if cancelled:
            result['passed'] = False
        save(directory / 'result.json', result)
    require(not cancelled, 'fixture_cancelled')
    print(json.dumps(result, sort_keys=True), flush=True)
    require(not cancelled, 'fixture_cancelled_after_output')


def main():
    require(os.getuid() == os.geteuid() != 0 and sys.flags.isolated and sys.flags.no_site,
            'ordinary_isolated_fixture_required')
    if sys.argv[1:] == []:
        print(json.dumps({'planOnly': True, 'scenarios': ['fd', 'home'],
                          'sourceSHA256': SOURCE_SHA256, 'requiresIndependentReview': True}))
        return 0
    require(len(sys.argv) == 3 and sys.argv[1] in ('fd', 'home') and
            sys.argv[2] == '--execute-reviewed', 'fixed_fixture_arguments')
    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGTERM, cancel)
    try:
        scenario(sys.argv[1])
    finally:
        closeout_owners()
    return 0 if not cancelled and not any(owner.capture_errors or owner.timeout for owner in owners) else 1


if __name__ == '__main__':
    raise SystemExit(main())
