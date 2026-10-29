"""The loop sampler names only code locations and reports only a busy loop."""
import asyncio
import sys
import threading
import time
import unittest

from hub import loop_profile


class LoopProfile(unittest.TestCase):
    def test_idle_asyncio_loop_is_not_a_sample(self):
        loop = asyncio.new_event_loop()
        ready = threading.Event()
        thread = threading.Thread(target=lambda: (loop.call_soon(ready.set), loop.run_forever()))
        thread.start()
        try:
            ready.wait(2)
            time.sleep(0.05)
            frame = sys._current_frames()[thread.ident]
            self.assertIsNone(loop_profile._sample(frame))
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(2)
            loop.close()

    def test_busy_thread_is_reported_by_location_only(self):
        stop = threading.Event()
        secret = 'private-request-body'

        def hot_path(value):
            while not stop.is_set():
                sum(range(1000))
                len(value)
        thread = threading.Thread(target=hot_path, args=(secret,))
        thread.start()
        try:
            time.sleep(0.05)
            samples = [loop_profile._sample(sys._current_frames()[thread.ident]) for _ in range(5)]
        finally:
            stop.set()
            thread.join(2)
        report = loop_profile.summarize([value for value in samples if value is not None], 5)
        self.assertEqual(set(report), {'busy', 'samples', 'leaf', 'inclusive'})
        names = [item['at'] for item in report['leaf'] + report['inclusive']]
        self.assertIn('test_loop_profile.py:hot_path', names)
        self.assertNotIn(secret, repr(report))
        self.assertTrue(all(set(item) == {'at', 'samples'} for item in report['leaf']))

    def test_mostly_idle_interval_is_not_reported(self):
        sample = (('server.py', 'work'), [('server.py', 'work')])
        self.assertIsNone(loop_profile.summarize([sample], 10))
        self.assertIsNone(loop_profile.summarize([], 0))
        self.assertEqual(loop_profile.summarize([sample] * 3, 10)['busy'], 3)

    def test_sampler_reports_and_never_raises(self):
        reports = []
        clock = iter([0.0] + [float(value) for value in range(0, 200, 30)])
        calls = []

        def sleep(_):
            calls.append(1)
            if len(calls) > 6:
                raise SystemExit
        stop = threading.Event()
        thread = threading.Thread(target=lambda: stop.wait(5))
        thread.start()
        try:
            def broken_log(report):
                reports.append(report)
                raise RuntimeError('log unavailable')
            sampler = loop_profile.start(broken_log, thread_id=thread.ident, clock=lambda: next(clock, 999.0),
                                         sleep=sleep)
            sampler.join(2)
        finally:
            stop.set()
            thread.join(2)
        self.assertFalse(sampler.is_alive())
        self.assertTrue(reports)
        self.assertTrue(all('threading.py:wait' in [item['at'] for item in report['leaf']] for report in reports))


if __name__ == '__main__':
    unittest.main()
