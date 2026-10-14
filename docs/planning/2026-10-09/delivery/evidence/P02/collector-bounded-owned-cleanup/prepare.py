from pathlib import Path
p=Path('/home/ryan/.cache/agentmux-governance/p02-native-collector-cleanup-repair-v3')
s=(p/'original.py').read_text().replace('import argparse\n','import argparse\nimport atexit\n').replace('import time\n','import time\nimport threading\n')
a=s.index('def stop_owned(process):');b=s.index('\ndef admit_preparation_workspace',a)
s=s[:a]+'''# Owners hold only exact Popen/session handles minted by this collector.
_RETAINED_REAPS = set()
_REAP_LOCK = threading.Lock()


class OwnedCleanupError(RuntimeError):
    """Cleanup is incomplete or failed; no exit result has been admitted."""
    def __init__(self, owner, cause=None):
        super().__init__('owned_process_cleanup_incomplete')
        self.owner = owner
        self._cause = cause

    def __repr__(self):
        return 'OwnedCleanupError(owned_process_cleanup_incomplete)'


class _OwnedReap:
    def __init__(self, process):
        self.process = process
        self.gate = threading.Lock()
        self.code = None
        self.failure = None
        self.stop_attempted = False
        self.shutdown_started = False
        with _REAP_LOCK:
            _RETAINED_REAPS.add(self)

    def _stop(self):
        if self.stop_attempted or self.process.returncode is not None:
            return
        self.stop_attempted = True
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            self.failure = exc

    def stop_until(self, deadline, cause=None):
        if not self.gate.acquire(timeout=max(0, deadline - time.monotonic())):
            raise OwnedCleanupError(self, cause) from None
        try:
            if self.code is not None:
                return self.code
            self._stop()
            try:
                # Builtin Popen uses a bounded wait; no background waiter exists.
                self.code = self.process.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException as exc:
                if self.failure is None:
                    self.failure = exc
                raise OwnedCleanupError(self, cause) from None
            with _REAP_LOCK:
                _RETAINED_REAPS.discard(self)
            if self.failure is not None:
                raise OwnedCleanupError(self, cause) from None
            return self.code
        finally:
            self.gate.release()

    def shutdown(self):
        # Interpreter shutdown has no hard wall-time bound. Only this exact owner
        # may wait, after the earlier bounded waiter has returned and released gate.
        with self.gate:
            if self.code is not None or self.shutdown_started:
                return
            self.shutdown_started = True
            self._stop()
            while self.code is None:
                try:
                    self.code = self.process.wait()
                except BaseException as exc:
                    if self.failure is None:
                        self.failure = exc
                    time.sleep(.1)
            with _REAP_LOCK:
                _RETAINED_REAPS.discard(self)


def _shutdown_retained_reaps():
    with _REAP_LOCK:
        owners = tuple(_RETAINED_REAPS)
    for owner in owners:
        owner.shutdown()


atexit.register(_shutdown_retained_reaps)


def stop_owned(process, deadline):
    """Use the original remaining budget; retain incomplete cleanup for shutdown."""
    return _OwnedReap(process).stop_until(deadline)


def wait_owned(process, timeout, *, deadline=None):
    # Real collection passes its original deadline and reserves five seconds.
    # Standalone controls receive a one-second cleanup allowance inside their end.
    end = time.monotonic() + timeout + 1 if deadline is None else deadline
    wait = timeout if deadline is None else min(timeout, max(0, end - time.monotonic() - 5))
    try:
        return process.wait(timeout=wait), False
    except subprocess.TimeoutExpired as exc:
        return _OwnedReap(process).stop_until(end, exc), True
    except BaseException as exc:
        _OwnedReap(process).stop_until(end, exc)
        raise

''' +s[b:]
s=s.replace('wait_owned(preparation, preparation_wait)','wait_owned(preparation, preparation_wait, deadline=collection_deadline)')
s=s.replace('code, timed_out = wait_owned(process, min(360, remaining - 5))','''try:
                    code, timed_out = wait_owned(process, min(360, remaining - 5), deadline=collection_deadline)
                except OwnedCleanupError:
                    report['checks'].append({'name': name, 'command': command, 'status': 'failed',
                        'exitCode': None, 'reason': 'owned_process_cleanup_incomplete',
                        'cleanupJoined': False, 'raw': raw.name, 'stderr': errors.name})
                    raise''')
a=s.index("        report['failureType'] = type(exc).__name__",s.index('def main('))
b=a+len("        report['failureType'] = type(exc).__name__")
s=s[:b]+'''
        if isinstance(exc, OwnedCleanupError):
            report['cleanupJoined'] = False
            report['collectionComplete'] = False
            report['ownedProcessExitCode'] = None
            report['cleanupOwnership'] = 'retained exact process; collector exit waits for owned shutdown cleanup'
            report['limits'].append('Cleanup observation is bounded; physical reaping and collector exit are not hard bounded.')''' +s[b:]
s=s.replace('[mock.call(timeout=1), mock.call()]','[mock.call(timeout=1), mock.call(timeout=mock.ANY)]')
(p/'native_go.py').write_text(s)
(p/'source-design.diff').write_text(''.join(__import__('difflib').unified_diff((p/'original.py').read_text().splitlines(True),s.splitlines(True),fromfile='original/native_go.py',tofile='candidate/native_go.py')))
print(__import__('hashlib').sha256((p/'native_go.py').read_bytes()).hexdigest())
