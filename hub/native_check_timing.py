"""Bounded private timing samples for the final native caller check.

A sample records only a closed stage name and the remaining original proof
validity. It never grants authority, changes a check or raises to its caller.
Samples are kept only while a record is installed for the current check.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time

LIMIT = 48
STAGES = frozenset((
    'current-start', 'identify-start', 'caller-return', 'agents-return', 'not-connectable-start',
    'not-connectable-return', 'fresh-caller-return', 'identify-return', 'identify-refused',
    'recheck-start', 'recheck-installed-return', 'recheck-return',
    'probe-start', 'probe-return', 'tmux-run-start', 'tmux-run-return',
))

_record = ContextVar('native_check_timing', default=None)


@contextmanager
def recording(record):
    """Install one record for the enclosed check; nothing is recorded outside it."""
    token = _record.set(record)
    try:
        yield
    finally:
        _record.reset(token)


def sample(stage):
    try:
        record = _record.get()
        if record is None or len(record['samples']) >= LIMIT or stage not in STAGES:
            return
        remaining = record['proof'].expires_monotonic - time.monotonic()
        if math.isfinite(remaining):
            record['samples'].append({'stage': stage, 'proofRemaining': remaining})
    except BaseException:
        pass
