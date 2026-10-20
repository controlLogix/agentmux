"""Offline admission arithmetic; no physical disk or replica claim."""
from types import SimpleNamespace
import unittest

from agentmux_contracts import ContractError
from state_owner.retention import Retention


class RetentionTests(unittest.TestCase):
    def test_bulk_stops_before_reserved_completion_capacity(self):
        policy = Retention(10 * 131_072, 3 * 131_072)
        info = SimpleNamespace(state=SimpleNamespace(messages=6))
        policy.admit(info, 65_536, 'bulk')
        info.state.messages = 7
        with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
            policy.admit(info, 1, 'bulk')
        self.assertTrue(policy.warning(info))
        policy.admit(info, 65_536, 'completion')
        info.state.messages = 9
        policy.admit(info, 65_536, 'reconciliation')
        info.state.messages = 10
        with self.assertRaisesRegex(ContractError, '^owner_capacity_exhausted$'):
            policy.admit(info, 1, 'completion')


if __name__ == '__main__':
    unittest.main()
