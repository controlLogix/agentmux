"""Bounded private timing samples for the final native caller check.

A sample records only a closed stage name and the remaining original proof
validity. It never grants authority, changes a check or raises to its caller.
Samples are kept only while a record is installed for the current check.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time
import weakref

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


def active():
    """Report whether a record is already installed for the current check."""
    try:
        return _record.get() is not None
    except BaseException:
        return False


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


# Request phases before the final check, so a refusal shows where the original
# proof's validity went. Fixed phase names and remaining validity only.
REQUEST_LIMIT = 16
REQUEST_STAGES = frozenset((
    'admitted', 'dispatch-start', 'status-db-return', 'work-list-return', 'dispatch-return',
))

_request = ContextVar('native_check_request_phases', default=None)
# Keyed by object identity; an entry holds only a float and the samples, and is
# removed when its admitted request is freed, so no request content is kept.
_requests = {}


def start_request(proof):
    """Begin phase samples for one admitted request in the current task."""
    try:
        key = id(proof)
        record = {'expires': float(proof.expires_monotonic), 'samples': []}
        weakref.finalize(proof, _requests.pop, key, None)
        _requests[key] = record
        _request.set(record)
        request_sample('admitted')
    except BaseException:
        pass


def request_sample(stage):
    try:
        record = _request.get()
        if record is None or len(record['samples']) >= REQUEST_LIMIT or stage not in REQUEST_STAGES:
            return
        remaining = record['expires'] - time.monotonic()
        if math.isfinite(remaining):
            record['samples'].append({'stage': stage, 'proofRemaining': remaining})
    except BaseException:
        pass


def request_samples(proof):
    """Copy the phase samples recorded for this admitted request, if any."""
    try:
        record = _requests.get(id(proof))
        return [] if record is None else list(record['samples'])
    except BaseException:
        return []
