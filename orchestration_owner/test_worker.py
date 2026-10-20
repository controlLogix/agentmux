import asyncio
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from .commands import OrchestrationPolicyBinding, prepare_command
from .domain_adapter import OrchestrationDomainAdapter, OrchestrationObservation
from .worker import OrchestrationWorker


def ref(name):
    return {'id': name, 'ownerHubId': 'hub-one', 'revision': 1}


class OrchestrationWorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='orchestration-worker-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.binding = OrchestrationPolicyBinding(ref('orchestration-one'), {
            'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None},
            str(self.root), 'orchestrator-project-one')
        self.adapter = OrchestrationDomainAdapter(self.binding)
        self.worker = OrchestrationWorker(self.adapter)

    def effect(self):
        return prepare_command({'resourceRef': ref('orchestration-one'),
            'environmentRef': None, 'input': {'command': 'run-start', 'request': 'one'}},
            self.binding)

    def job(self):
        effect = self.effect()
        return self.worker.prepare('original-one', effect.candidate_digest,
            'attempt-one', effect, actor='human-one', provenance='orchestrator-project-one')

    async def test_same_attempt_owns_one_effect_and_releases_only_after_observation(self):
        observation = OrchestrationObservation('applied', b'{"outcome":"applied"}')
        with patch.object(self.adapter, 'perform', return_value=observation) as perform:
            job = self.job()
            first = self.worker._start(job)
            second = self.worker._start(job)
            self.assertIs(first, second)
            self.assertEqual(await self.worker.wait('attempt-one'), observation)
            self.assertEqual(perform.call_count, 1)
            self.worker._release('attempt-one', observation)
            self.assertEqual(self.worker._tasks, {})

    async def test_cancelled_wait_keeps_original_effect_owned(self):
        started, release = asyncio.Event(), asyncio.Event()
        def blocked(*args, **kwargs):
            loop.call_soon_threadsafe(started.set)
            future = asyncio.run_coroutine_threadsafe(release.wait(), loop)
            future.result(timeout=5)
            return OrchestrationObservation('applied', b'{"outcome":"applied"}')
        loop = asyncio.get_running_loop()
        with patch.object(self.adapter, 'perform', side_effect=blocked):
            self.worker._start(self.job())
            await started.wait()
            waiter = asyncio.create_task(self.worker.wait('attempt-one'))
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            self.assertIn('attempt-one', self.worker._tasks)
            release.set()
            observation = await self.worker.wait('attempt-one')
            self.worker._release('attempt-one', observation)

    async def test_changed_attempt_payload_is_refused_without_second_dispatch(self):
        observation = OrchestrationObservation('applied', b'{"outcome":"applied"}')
        with patch.object(self.adapter, 'perform', return_value=observation) as perform:
            job = self.job()
            self.worker._start(job)
            changed = type(job)(job.original_operation_id, job.original_payload_digest,
                job.attempt_operation_id, 'other-human', job.provenance, job.effect)
            with self.assertRaisesRegex(ContractError, 'orchestration_attempt_conflict'):
                self.worker._start(changed)
            observed = await self.worker.wait('attempt-one')
            self.worker._release('attempt-one', observed)
            self.assertEqual(perform.call_count, 1)

    async def test_worker_does_not_treat_domain_refusal_as_success(self):
        with patch.object(self.adapter, 'perform',
                          side_effect=ContractError('orchestration_environment_mismatch')):
            self.worker._start(self.job())
            observed = await self.worker.wait('attempt-one')
            self.assertEqual(observed.outcome, 'not-dispatched')
            self.worker._release('attempt-one', observed)

    async def test_worker_does_not_redispatch_after_uncertain_process_effect(self):
        with patch.object(self.adapter, 'perform',
                          side_effect=ContractError('orchestration_effect_uncertain')) as perform:
            job = self.job()
            first = self.worker._start(job)
            second = self.worker._start(job)
            self.assertIs(first, second)
            observed = await self.worker.wait('attempt-one')
            self.assertEqual(observed.outcome, 'uncertain')
            self.assertEqual(perform.call_count, 1)
            self.worker._release('attempt-one', observed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
