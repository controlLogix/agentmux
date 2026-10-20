"""Exact signed client replay through ingress and the actual definition owner."""
from pathlib import Path
from datetime import timedelta
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'dashboard'))
import test_definition_command_service as support


class DefinitionIngressReplayTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.DefinitionServiceTests.setUp
    asyncSetUp = support.DefinitionServiceTests.asyncSetUp
    new_ledger = support.DefinitionServiceTests.new_ledger
    new_owner = support.DefinitionServiceTests.new_owner
    authority_message = support.DefinitionServiceTests.authority_message
    resign = support.DefinitionServiceTests.resign
    effect_request = support.DefinitionServiceTests.effect_request
    request = support.DefinitionServiceTests.request
    receipt = support.DefinitionServiceTests.receipt

    async def test_exact_request_replays_without_second_commit_or_file_effect(self):
        await self.receiver.start()
        request = self.request()
        first = self.receipt(await self.receiver.handle(request), request)
        before = self.path.read_bytes()
        cursor = self.history.verified_cursor
        self.authority_record['state']['grants'][0]['expiresAt'] = (
            self.now + timedelta(seconds=10)).isoformat().replace('+00:00', 'Z')
        with patch('definition_commands.apply_exact_source', side_effect=AssertionError('replayed file effect')):
            second = self.receipt(await self.receiver.handle(request), request)
        self.assertTrue(second['replayed'])
        self.assertEqual(second['operationId'], first['operationId'])
        self.assertEqual(second['catalogSequence'], first['catalogSequence'])
        self.assertEqual(self.history.verified_cursor, cursor)
        self.assertEqual(self.path.read_bytes(), before)
