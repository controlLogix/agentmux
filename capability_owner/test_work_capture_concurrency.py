"""Concurrent source replays recover one original signed capture."""
import asyncio
from datetime import timedelta

from agentmux_contracts import payload_digest, strict_loads
from identity.test_service import NOW
from .test_work_capture_hub import WorkCaptureHubTests


class WorkCaptureConcurrencyTests(WorkCaptureHubTests):
    async def test_concurrent_completed_source_replays_keep_one_original_capture(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Concurrent capture')
        self.store.claim(target, work_id=row['id'])
        request = self.work_request('release', {'workId': row['id'], 'outcome': 'done',
            'result': 'One original finding', 'onBehalfOf': {
                'session': target, 'generation': self.store.agent(target)['generation']}},
            operation='concurrent-source-release')
        receipt = await self.work_call(request)
        source = {'kind': 'work-released', 'id': row['id'],
            'digest': payload_digest(receipt['result']), 'resourceRef': receipt['resourceRef'],
            'receiptRef': receipt['receiptRef'], 'operationId': 'concurrent-source-release',
            'payloadDigest': payload_digest(strict_loads(request)['claims']['payload'])}
        client = self.fed._knowledge_commands
        session, enrollment = client._select('federation', 'capture', 'falcon')[0]
        value = {'source': source}
        expires = NOW + timedelta(seconds=5)
        first = await client._capture_original(session, enrollment, value, expires)
        self.assertTrue(first['captured'])
        archive_key = client._capture_key(client._binding(enrollment), value)
        original = client._pending(archive_key)
        self.assertIsNotNone(original)
        self.assertEqual(original['payload']['input'], value)

        # Hold the existing command lock so both replays reach a known wait.
        # Before the repair both wait here after restoring the same original.
        # With the repair one waits here and the other waits at the capture lock.
        session_lock = client._locks[id(session)]
        await session_lock.acquire()
        tasks = [asyncio.create_task(client._capture_original(session, enrollment, value, expires))
            for _ in range(2)]
        try:
            try:
                async with asyncio.timeout(3):
                    while True:
                        capture_lock = getattr(client, '_receipt_capture_locks', {}).get(id(session))
                        locks = [session_lock] + ([capture_lock] if capture_lock is not None else [])
                        waiting = sum(len(getattr(lock, '_waiters', None) or ()) for lock in locks)
                        if waiting == 2:
                            break
                        self.assertFalse(any(task.done() for task in tasks),
                            'A replay ended before the controlled wait')
                        await asyncio.sleep(0)
            finally:
                session_lock.release()
            repeated = await asyncio.gather(*tasks)
        finally:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.assertEqual(repeated, [first, first])
        self.assertEqual(client._pending(archive_key), original)
        self.assertEqual(self.store.q('SELECT id FROM p_knowledge_items'), [{'id': first['id']}])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        captures = [item for item in self.submitted if item['contractId'] == 'federation-knowledge-capture']
        self.assertEqual(len(captures), 1)
        self.assertEqual(captures[0]['operationId'], original['operationId'])
        queries = [item['payload']['input'] for item in self.submitted
            if item['contractId'] == 'federation-knowledge-outcome'
            and item['payload']['input']['operationId'] == original['operationId']]
        self.assertGreaterEqual(len(queries), 2)
        self.assertTrue(all(item['payloadDigest'] == payload_digest(original['payload']) for item in queries))
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
