from pathlib import Path
p=Path('/home/ryan/.cache/agentmux-governance/p02-native-collector-cleanup-repair-v3/native_go.py')
s=p.read_text().replace('''        except BaseException as exc:
            self.wait_failure = exc
            raise OwnedCleanupError(self, cause) from None
        if not acquired:''','''        except BaseException as exc:
            failure = OwnedCleanupError(self, cause)
            failure._gate_cause = exc
            raise failure from None
        if not acquired:''')
a=s.index('        with self.gate:',s.index('    def shutdown'))
b=s.index('\n\ndef _shutdown_retained_reaps',a)
body=s[a+len('        with self.gate:\n'):b]
s=s[:a]+'''        while True:
            try:
                self.gate.acquire()
                break
            except BaseException:
                pass
        try:
''' +body+'''        finally:
            self.gate.release()
''' +s[b:]
p.write_text(s)
