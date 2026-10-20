"""Typed authority records reject invalid time intervals, including revoked rows."""
import copy
import unittest

from agentmux_contracts import ContractError, validate
from identity.authority import _indexes
from identity.test_authority import fixture, ref


class SemanticStateTests(unittest.TestCase):
    def state(self):
        state = fixture()[0]['state']
        state['approvals'] = [{
            'ref': ref('approval'), 'grantRef': ref('grant'), 'approverRef': ref('human'),
            'approverGrantRef': ref('grant'), 'payloadDigest': 'sha256:' + 'a' * 64,
            'audience': {'hubId': 'hub-one', 'serviceId': 'task-owner'},
            'operationId': 'operation-one', 'expectedVersion': 1, 'decision': 'approved',
            'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
            'expiresAt': '2026-10-09T12:10:00Z'}]
        return state

    def test_all_timed_collections_reject_invalid_calendar_and_interval(self):
        original = self.state()
        changes = (
            {'issuedAt': '2026-99-09T12:00:00Z'},
            {'expiresAt': '2026-99-09T12:10:00Z'},
            {'expiresAt': '2026-10-09T12:00:00Z'},
            {'expiresAt': '2026-10-09T11:59:59Z'},
        )
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for status in ('active', 'revoked'):
                for change in changes:
                    with self.subTest(collection=collection, status=status, change=change):
                        state = copy.deepcopy(original)
                        state[collection][0].update(status=status, **change)
                        # These values satisfy timestamp shape. The owner must
                        # reject their calendar/interval meaning before commit.
                        validate('identity-authority-state', state)
                        with self.assertRaisesRegex(ContractError, '^authority_time_invalid$'):
                            _indexes(state, 'hub-one')

    def test_valid_revoked_timed_records_remain_readable(self):
        state = self.state()
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            state[collection][0]['status'] = 'revoked'
        validate('identity-authority-state', state)
        index = _indexes(state, 'hub-one')
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            self.assertEqual(len(index[collection]), 1)


if __name__ == '__main__':
    unittest.main()
