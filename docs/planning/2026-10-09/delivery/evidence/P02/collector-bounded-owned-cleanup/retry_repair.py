from pathlib import Path
p=Path('/home/ryan/.cache/agentmux-governance/p02-native-collector-cleanup-repair-v3/native_go.py')
s=p.read_text().replace('''        self._cause = cause

    def __repr__''','''        self._cause = cause
        self._cleanup_cause = owner.wait_failure or owner.failure

    def __repr__''').replace('''        self.failure = None
        self.stop_attempted''','''        self.failure = None
        self.wait_failure = None
        self.stop_attempted''')
s=s.replace('''        if not self.gate.acquire(timeout=max(0, deadline - time.monotonic())):
            raise OwnedCleanupError(self, cause) from None''','''        try:
            acquired = self.gate.acquire(timeout=max(0, deadline - time.monotonic()))
        except BaseException as exc:
            self.wait_failure = exc
            raise OwnedCleanupError(self, cause) from None
        if not acquired:
            raise OwnedCleanupError(self, cause) from None''')
s=s.replace('''            if self.code is not None:
                return self.code
            self._stop()''','''            if self.code is not None:
                if self.failure is not None:
                    raise OwnedCleanupError(self, cause) from None
                return self.code
            self._stop()''')
s=s.replace('''            except BaseException as exc:
                if self.failure is None:
                    self.failure = exc
                raise OwnedCleanupError(self, cause) from None
            with _REAP_LOCK:''','''            except BaseException as exc:
                self.wait_failure = exc
                raise OwnedCleanupError(self, cause) from None
            self.wait_failure = None
            with _REAP_LOCK:''')
s=s.replace('''                except BaseException as exc:
                    if self.failure is None:
                        self.failure = exc
                    time.sleep(.1)''','''                except BaseException as exc:
                    self.wait_failure = exc
                    try:
                        time.sleep(.1)
                    except BaseException:
                        pass''')
p.write_text(s)
