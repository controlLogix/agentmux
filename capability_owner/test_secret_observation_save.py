"""A verified observation save cannot be mistaken for a missing load."""
import copy
import os
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from capability_owner import secret_journal
from capability_owner.secret_consumer import SecretConsumerObservation
from capability_owner import test_ordinary_secret_close as close_fixture


class SecretObservationSaveTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(close_fixture.OrdinarySecretCloseTests.setUpClass.__func__)
    tearDownClass = classmethod(close_fixture.OrdinarySecretCloseTests.tearDownClass.__func__)
    setUp = close_fixture.OrdinarySecretCloseTests.setUp
    request = close_fixture.OrdinarySecretCloseTests.request
    store = close_fixture.OrdinarySecretCloseTests.store
    proposal = close_fixture.OrdinarySecretCloseTests.proposal
    enrolled = close_fixture.OrdinarySecretCloseTests.enrolled
    change_current = close_fixture.OrdinarySecretCloseTests.change_current
    revoke = close_fixture.OrdinarySecretCloseTests.revoke
    ready = close_fixture.OrdinarySecretCloseTests.ready
    open_journal = close_fixture.OrdinarySecretCloseTests.open_journal
    phase_signer = close_fixture.OrdinarySecretCloseTests.phase_signer
    query_owner = close_fixture.OrdinarySecretCloseTests.query_owner
    dispatch = close_fixture.OrdinarySecretCloseTests.dispatch
    known_result = close_fixture.OrdinarySecretCloseTests.known_result
    assert_owned = close_fixture.OrdinarySecretCloseTests.assert_owned
    replacement = close_fixture.OrdinarySecretCloseTests.replacement

    async def test_disappeared_save_retains_known_result_until_later_close_and_recovery(self):
        owner, group, observed = await self.known_result()
        reader = secret_journal._read_file
        removed = []

        def disappear(directory, name):
            os.unlink(name, dir_fd=directory)
            removed.append(name)
            return reader(directory, name)

        with patch.object(secret_journal, '_read_file', disappear):
            with self.assertRaisesRegex(ContractError, '^ordinary_secret_owner_cleanup_incomplete$'):
                await owner.close()
        self.assertEqual(len(removed), 1)
        self.assert_owned(owner)
        self.assertEqual(len(owner._pending_observations), 1)
        self.assertTrue(owner._closing.done())
        self.assertFalse(self.journal._disk_tasks)
        self.assertIsNone(await self.journal.load_observation(group))
        self.assertEqual(len(self.journal_js.messages), 2)
        await owner.close()
        self.assertFalse(owner._pending_observations)
        self.assertIsNone(self.custody._store._fd)
        replacement = await self.replacement()
        self.assertEqual(await replacement._journal.load_observation(group), observed)
        receipt = await replacement.recover(self.outer)
        self.assertEqual(receipt['outcome'], 'accepted')
        self.assertEqual(len(self.journal_js.messages), 3)
        self.assertFalse(owner._consumer._entries)
        self.assertFalse(replacement._consumer._entries)

    async def test_missing_load_is_still_absent_without_creating_evidence(self):
        await self.ready()
        group = await self.dispatch()
        self.assertIsNone(await self.journal.load_observation(group))
        self.assertIsNone(await self.journal.load_observation(group))
        self.assertEqual(len(self.journal_js.messages), 2)

    async def test_save_requires_exact_verified_evidence_acknowledgment(self):
        await self.ready()
        group = await self.dispatch()
        observed = SecretConsumerObservation('accepted', 'account_matched')
        for acknowledgment in (None, b'{}'):
            with self.subTest(acknowledgment=acknowledgment), \
                    patch.object(self.journal, '_disk', return_value=acknowledgment), \
                    self.assertRaises(ContractError):
                await self.journal.save_observation(group, observed)
        self.assertIsNone(await self.journal.load_observation(group))
        self.assertEqual(len(self.journal_js.messages), 2)

    async def test_exact_create_or_match_and_original_dispatch_bindings_remain(self):
        await self.ready()
        group = await self.dispatch()
        observed = SecretConsumerObservation('accepted', 'account_matched')
        identifier = await self.journal.save_observation(group, observed)
        self.assertEqual(await self.journal.save_observation(group, observed), identifier)
        self.assertEqual(await self.journal.load_observation(group), observed)
        with self.assertRaises(ContractError):
            await self.journal.save_observation(group,
                SecretConsumerObservation('rejected', 'http_refused'))
        for mutate in (
                lambda g: g['original']['operation'].update(operationId='other-original'),
                lambda g: g['original']['operation'].update(payloadDigest='sha256:' + 'a' * 64),
                lambda g: g['state'].update(originalRequestDigest='sha256:' + 'b' * 64),
                lambda g: g['state']['dispatchRef'].update(revision=9)):
            wrong = copy.deepcopy(group)
            mutate(wrong)
            with self.subTest(change=mutate), self.assertRaises(ContractError):
                await self.journal.load_observation(wrong)
        self.assertEqual(await self.journal.load_observation(group), observed)
        self.assertEqual(len(self.journal_js.messages), 2)


if __name__ == '__main__':
    unittest.main()
