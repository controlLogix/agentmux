"""Private sampling of what keeps the Hub's event-loop thread busy.

A daemon thread reads the loop thread's current Python frames ten times a
second. Once a minute, if the loop was busy for at least a fifth of those
samples, one log line names the most frequent code locations (file and
function only). It never reads locals, arguments or any request data, and it
never raises into the Hub.
"""
import os
import sys
import threading
import time

INTERVAL = 0.1
REPORT = 60
BUSY_SHARE = 0.2
TOP = 8
DEPTH = 24
# Leaf frames that mean the loop is waiting, not working.
_IDLE = frozenset((('selectors.py', 'select'), ('base_events.py', '_run_once'),
                   ('base_events.py', 'run_forever')))


def _location(frame):
    code = frame.f_code
    return os.path.basename(code.co_filename), code.co_name


def _sample(frame):
    """Return (leaf, inclusive locations) for one stack, or None when idle."""
    leaf = _location(frame)
    if leaf in _IDLE:
        return None
    seen = []
    depth = 0
    while frame is not None and depth < DEPTH:
        location = _location(frame)
        if location not in seen:
            seen.append(location)
        frame = frame.f_back
        depth += 1
    return leaf, seen


def _top(counts):
    ranked = sorted(counts.items(), key=lambda item: -item[1])[:TOP]
    return [{'at': f'{name}:{function}', 'samples': count} for (name, function), count in ranked]


def summarize(samples, total):
    """Build one report from (leaf, inclusive) samples, or None if the loop was mostly idle."""
    if total <= 0 or len(samples) < BUSY_SHARE * total:
        return None
    leaves, inclusive = {}, {}
    for leaf, seen in samples:
        leaves[leaf] = leaves.get(leaf, 0) + 1
        for location in seen:
            if location[0] not in ('base_events.py', 'events.py', 'tasks.py', 'threading.py'):
                inclusive[location] = inclusive.get(location, 0) + 1
    return {'busy': len(samples), 'samples': total, 'leaf': _top(leaves), 'inclusive': _top(inclusive)}


def start(log, *, thread_id=None, clock=time.monotonic, sleep=time.sleep):
    """Sample the given thread (default: the caller's) until the process exits."""
    target = threading.get_ident() if thread_id is None else thread_id

    def run():
        samples, total, started = [], 0, clock()
        while True:
            try:
                sleep(INTERVAL)
                frame = sys._current_frames().get(target)
                if frame is None:
                    return
                total += 1
                value = _sample(frame)
                del frame
                if value is not None:
                    samples.append(value)
                if clock() - started >= REPORT:
                    report = summarize(samples, total)
                    if report is not None:
                        log(report)
                    samples, total, started = [], 0, clock()
            except Exception:
                samples, total, started = [], 0, clock()

    try:
        thread = threading.Thread(target=run, name='hub-loop-profile', daemon=True)
        thread.start()
        return thread
    except Exception:
        return None
