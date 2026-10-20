"""Known private results survive failed saves and an explicitly joined close."""
import asyncio
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from capability_owner.secret_consumer import SecretConsumerObservation
from capability_owner import test_secret_journal as journal_fixture
from identity import test_service as service_fixture
from native_security.ordinary_secret_custody import OrdinarySecretCustody


class OrdinarySecretCloseTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(journal_fixture.SecretJournalTests.setUpClass.__func__)
    tearDownClass = classmethod(journal_fixture.SecretJournalTests.tearDownClass.__func__)
    setUp = journal_fixture.SecretJournalTests.setUp
    request = journal_fixture.SecretJournalTests.request
    store = journal_fixture.SecretJournalTests.store
    proposal = journal_fixture.SecretJournalTests.proposal
    enrolled = journal_fixture.SecretJournalTests.enrolled
    change_current = journal_fixture.SecretJournalTests.change_current
    revoke = journal_fixture.SecretJournalTests.revoke
    ready = journal_fixture.SecretJournalTests.ready
    open_journal = journal_fixture.SecretJournalTests.open_journal
    phase_signer = journal_fixture.SecretJournalTests.phase_signer
    query_owner = journal_fixture.SecretJournalTests.query_owner
    dispatch = journal_fixture.SecretJournalTests.dispatch

    async def known_result(self):
        await self.ready()
        owner = self.query_owner()
        group = await self.dispatch()
        observed = SecretConsumerObservation('accepted', 'account_matched')
        with patch.object(self.journal, 'save_observation', side_effect=OSError('private failure')):
            with self.assertRaises(OSError):
                await owner._finish(group, observed)
        return owner, group, observed

    def assert_owned(self, owner):
        self.assertTrue(owner._closed)
        self.assertFalse(owner._consumer._closed)
        self.assertIsNotNone(self.custody._store._fd)
        self.assertIsNotNone(self.journal._observations._fd)

    async def replacement(self):
        journal = self.open_journal()
        custody = OrdinarySecretCustody(self.root, self.service.reader)
        from capability_owner.secret_consumer import AtlassianAccountCheckConsumer
        from capability_owner.ordinary_secret import OrdinarySecretOwner
        owner = OrdinarySecretOwner(journal, self.phase_signer(journal), custody,
            AtlassianAccountCheckConsumer(self.service.reader, self.enrollment))
        self.addAsyncCleanup(owner.close)
        return owner

    async def test_close_saves_known_result_before_release_and_restart(self):
        owner, group, observed = await self.known_result()
        await owner.close()
        self.assertIsNone(self.custody._store._fd)
        replacement = await self.replacement()
        self.assertEqual(await replacement._journal.load_observation(group), observed)
        receipt = await replacement.recover(self.outer)
        self.assertEqual(receipt['outcome'], 'accepted')
        self.assertEqual(len(self.journal_js.messages), 3)

    async def test_persistent_failure_retains_resources_and_failed_attempt_is_retryable(self):
        owner, group, observed = await self.known_result()
        with patch.object(self.journal, 'save_observation', side_effect=OSError('private failure')):
            for _ in range(2):
                with self.assertRaisesRegex(ContractError, 'ordinary_secret_owner_cleanup_incomplete'):
                    await owner.close()
                self.assert_owned(owner)
                self.assertTrue(owner._closing.done())
                self.assertEqual(len(self.journal_js.messages), 2)
        await owner.close()
        replacement = await self.replacement()
        self.assertEqual(await replacement._journal.load_observation(group), observed)

    async def test_timeout_and_canceled_close_keep_the_exact_save_task(self):
        owner, group, observed = await self.known_result()
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.journal.save_observation
        calls = []
        async def save(*args):
            calls.append(asyncio.current_task())
            entered.set()
            await release.wait()
            return await original(*args)
        with patch.object(self.journal, 'save_observation', save):
            observer = asyncio.create_task(owner.close())
            await entered.wait()
            attempt = owner._closing
            observer.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await observer
            with self.assertRaisesRegex(ContractError, 'ordinary_secret_owner_cleanup_incomplete'):
                await owner.close(timeout=0.01)
            self.assertIs(owner._closing, attempt)
            self.assertFalse(attempt.done())
            self.assert_owned(owner)
            release.set()
            await owner.close()
            self.assertEqual(calls, [attempt])
        replacement = await self.replacement()
        self.assertEqual(await replacement._journal.load_observation(group), observed)

    async def test_save_does_not_require_current_caller_or_completion_permission(self):
        owner, group, observed = await self.known_result()
        self.revoke(name='ordinary-use-grant')
        self.revoke(name='ordinary-secret-complete')
        await owner.close()
        replacement = await self.replacement()
        self.assertEqual(await replacement._journal.load_observation(group), observed)
        with self.assertRaises(ContractError):
            await replacement.recover(self.outer)
        self.assertEqual(len(self.journal_js.messages), 2)

    async def test_uncertain_save_matches_existing_evidence_on_close(self):
        await self.ready()
        owner = self.query_owner()
        group = await self.dispatch()
        observed = SecretConsumerObservation('rejected', 'http_refused')
        original = self.journal.save_observation
        async def uncertain(*args):
            await original(*args)
            raise OSError('reply lost after write')
        with patch.object(self.journal, 'save_observation', uncertain):
            with self.assertRaises(OSError):
                await owner._finish(group, observed)
        await owner.close()
        replacement = await self.replacement()
        self.assertEqual(await replacement._journal.load_observation(group), observed)
        self.assertEqual((await replacement.recover(self.outer))['outcome'], 'rejected')

    async def test_timeout_keeps_original_descriptor_job_until_joined(self):
        owner, group, observed = await self.known_result()
        entered, release = threading.Event(), threading.Event()
        original = self.journal._observations.access
        def access(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise OSError('test release timed out')
            return original(*args, **kwargs)
        with patch.object(self.journal._observations, 'access', access):
            observer = asyncio.create_task(owner.close(timeout=0.05))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                with self.assertRaisesRegex(ContractError, 'ordinary_secret_owner_cleanup_incomplete'):
                    await observer
                jobs = tuple(self.journal._disk_tasks)
                self.assertEqual(len(jobs), 1)
                self.assertFalse(jobs[0].done())
                self.assert_owned(owner)
            finally:
                release.set()
                await owner.close()
            self.assertTrue(jobs[0].done())
            self.assertFalse(self.journal._disk_tasks)
        replacement = await self.replacement()
        self.assertEqual(await replacement._journal.load_observation(group), observed)

    async def test_absent_physical_evidence_stays_uncertain(self):
        await self.ready()
        await self.dispatch()
        owner = self.query_owner()
        await owner.close()
        replacement = await self.replacement()
        self.assertEqual((await replacement.recover(self.outer))['outcome'], 'uncertain')
        self.assertEqual(len(self.journal_js.messages), 2)

    async def test_completed_consumer_result_survives_save_fault_without_another_use(self):
        await self.ready()
        owner = self.query_owner()
        requests = []
        async def request(entry):
            requests.append(entry.claim_ref)
            return SecretConsumerObservation('accepted', 'account_matched')
        with patch('capability_owner.secret_consumer._now', return_value=service_fixture.NOW), \
                patch.object(owner._consumer, '_request', request), \
                patch.object(self.journal, 'save_observation', side_effect=OSError('private failure')):
            with self.assertRaises(ContractError):
                await owner.use(self.outer)
        self.assertEqual(len(requests), 1)
        group = await self.journal.current()
        await owner.close()
        replacement = await self.replacement()
        self.assertEqual((await replacement.recover(self.outer))['outcome'], 'accepted')
        self.assertEqual(len(requests), 1)
        self.assertEqual(len(self.journal_js.messages), 3)
        self.assertEqual((await replacement._journal.load_observation(group)).status, 'accepted')


if __name__ == '__main__':
    unittest.main()
