"""Public macOS process observations for the closed native core caller path.

No process is signalled or adopted. Unreadable and changing observations
refuse classification; transport absence is not a process inventory.
"""
from dataclasses import dataclass
import ctypes as C
import os
import platform
import sys
import time


class CallerEvidenceUnavailable(ValueError):
    def __init__(self):
        super().__init__('native_core_caller_unavailable')


class _BsdInfo(C.Structure):
    # Public struct proc_bsdinfo from the native SDK, checked by a focused test.
    _fields_ = [(name, C.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid',
        'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', C.c_char * 16), ('name', C.c_char * 32)]
    _fields_ += [(name, C.c_uint32) for name in ('nfiles', 'pgid', 'pjobc', 'tdev', 'tpgid')]
    _fields_ += [('nice', C.c_int32), ('start_sec', C.c_uint64), ('start_usec', C.c_uint64)]


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    parent: int
    uid: int
    started: tuple[int, int]
    image: str


@dataclass(frozen=True)
class CallerObservation:
    processes: tuple[ProcessObservation, ...]
    in_pane: bool


def _deadline(deadline):
    if type(deadline) not in (int, float) or not time.monotonic() < deadline < float('inf'):
        raise CallerEvidenceUnavailable()


class NativeCallerProbe:
    def __init__(self):
        if (sys.platform != 'darwin' or platform.machine() != 'arm64'
                or os.getuid() == 0 or os.getuid() != os.geteuid() or C.sizeof(_BsdInfo) != 136):
            raise CallerEvidenceUnavailable()
        self.lib = C.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.lib.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
        self.lib.proc_pidinfo.restype = C.c_int
        self.lib.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
        self.lib.proc_pidpath.restype = C.c_int

    def _info(self, pid, deadline):
        _deadline(deadline)
        value = _BsdInfo()
        result = self.lib.proc_pidinfo(pid, 3, 0, C.byref(value), C.sizeof(value))
        _deadline(deadline)
        if (result != C.sizeof(value) or value.pid != pid or value.start_sec == 0
                or value.start_usec >= 1000000 or value.status in (0, 5)):
            raise CallerEvidenceUnavailable()
        return value.pid, value.ppid, value.uid, value.start_sec, value.start_usec

    def read(self, pid, deadline):
        if type(pid) is not int or pid < 1:
            raise CallerEvidenceUnavailable()
        before = self._info(pid, deadline)
        raw = C.create_string_buffer(4096)
        result = self.lib.proc_pidpath(pid, raw, len(raw))
        _deadline(deadline)
        if not 0 < result < len(raw) or b'\x00' not in raw.raw[:result+1]:
            raise CallerEvidenceUnavailable()
        image = os.fsdecode(raw.value)
        after = self._info(pid, deadline)
        if (before != after or not image.startswith('/') or os.path.normpath(image) != image
                or any(char in image for char in ('\x00', '\n', '\r'))):
            raise CallerEvidenceUnavailable()
        return ProcessObservation(pid, before[1], before[2], (before[3], before[4]), image)

    def observe(self, pid, *, tmux_image, deadline):
        """Classify actual ancestry against the context's selected tmux image."""
        if type(pid) is not int or pid <= 1:
            raise CallerEvidenceUnavailable()
        observations, seen, in_pane = [], set(), False
        while True:
            if pid in seen or len(seen) >= 256:
                raise CallerEvidenceUnavailable()
            seen.add(pid)
            item = self.read(pid, deadline)
            observations.append(item)
            if item.uid != os.getuid() or item.parent < 1:
                raise CallerEvidenceUnavailable()
            if item.image == tmux_image:
                in_pane = True
            # Match the existing complete-ancestry boundary: the kernel reports
            # PID 1 as parent. macOS denies this user inspection of launchd itself.
            if item.parent == 1:
                break
            pid = item.parent
        # Repeat every complete observation; a parent exit, reparent or image
        # change cannot be accepted using a mixture of two process generations.
        for item in observations:
            if self.read(item.pid, deadline) != item:
                raise CallerEvidenceUnavailable()
        return CallerObservation(tuple(observations), in_pane)
