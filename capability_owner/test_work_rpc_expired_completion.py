"""Finished work remains recoverable when only its final response expires."""
from dataclasses import replace
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, strict_loads
from .test_work_rpc import WorkRpcTests


class WorkRpcExpiredCompletionTests(WorkRpcTests):
    async def test_final_response_expiry_seals_finished_obligations_and_requires_fresh_permission(self):
        rpc = self.hub._work_rpc
        original_complete = rpc.complete

        async def expire_after_followons(result):
            state = rpc._state()
            state['admitted'] = replace(state['admitted'], expires_monotonic=0)
            return await original_complete(result)

        with patch.object(rpc, 'complete', side_effect=expire_after_followons):
            expired = await self.packet(operation_id='expired-completion')
        self.assertFalse(expired['ok'], expired)
        self.assertEqual(expired['error'], 'authenticated work request expired')
        self.assertNotIn('result', expired)
        row = self.store.q1('SELECT * FROM work_items')
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.active(), [])
        completed = self.store.q("SELECT v FROM fed_state WHERE k LIKE 'legacy-work-completion:completed:%'")
        self.assertEqual(len(completed), 1)
        self.assertEqual(strict_loads(completed[0]['v'])['result'], row)

        recovered = await self.packet(operation_id='expired-completion')
        self.assertTrue(recovered['ok'], recovered)
        self.assertEqual(recovered['result'], row)
        self.assertEqual(len(self.mutations()), 1)
        state = strict_loads(self.js.messages[-1].data)
        next(grant for grant in state['state']['grants']
            if grant['ref'] == self.work_grants['human']['federation-work-create'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(state)
        refused = await self.packet(operation_id='expired-completion')
        self.assertFalse(refused['ok'], refused)
        self.assertNotIn(row['id'], canonical_bytes(refused).decode())
        self.assertEqual(len(self.mutations()), 1)
