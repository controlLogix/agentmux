"""Offline mutation harness draft; default plan only, no automatic execution."""
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys
import types

PIN = '6fae75d474456a0ec2682e5316ee73589c77d06f7fff787402661bdba23e8f57'


def main():
    if not sys.argv[1:]:
        print('plan-only: private generated missing-home-guard mutation; review required')
        return 0
    if sys.argv[1:] != ['--execute-reviewed']:
        raise ValueError('closed_mutation_arguments')
    if not (os.getuid() == os.geteuid() != 0 and sys.flags.isolated and sys.flags.no_site):
        raise ValueError('ordinary_isolated_mutation_required')
    path = Path(__file__).with_name('idle_watchdog_fixture.py')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                before.st_nlink == 1 and not before.st_mode & 0o022 and before.st_size <= 262144):
            raise ValueError('mutation_fixture_metadata')
        raw = os.read(fd, 262145)
        after = os.fstat(fd)
        if not (len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == PIN and
                all(getattr(before, key) == getattr(after, key) for key in
                    ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                     'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise ValueError('mutation_fixture_changed')
    finally:
        os.close(fd)
    module = types.ModuleType('held_mutation_fixture')
    module.__file__ = str(path)
    exec(compile(raw, '<held-mutation-fixture>', 'exec'), module.__dict__)
    signal.signal(signal.SIGINT, module.cancel)
    signal.signal(signal.SIGTERM, module.cancel)
    try:
        module.scenario('home', missing_guard_mutation=True)
    finally:
        module.closeout_owners()
    return 0 if not module.cancelled else 1


if __name__ == '__main__':
    raise SystemExit(main())
