"""Fresh board owner signing uses actual retained enrollment and ingress."""
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, strict_loads
from identity.test_authority import ref
from identity import test_service as service_tests
from . import test_board_journal as journal_tests
from .board_phase_signer import BoardPhaseSigner


class BoardPhaseSignerTests(unittest.IsolatedAsyncioTestCase):
    open=journal_tests.BoardJournalTests.open
    admit=journal_tests.BoardJournalTests.admit
    prepare=journal_tests.BoardJournalTests.prepare
    phase=journal_tests.BoardJournalTests.phase

    def setUp(self):
        journal_tests.BoardJournalTests.setUp(self)
        patch('capability_owner.board_phase_signer.datetime',service_tests._Clock).start()
        self.signer=BoardPhaseSigner(self.journal,self.service.ingress,
            transport_ref=ref('owner-transport'),signing_seed=journal_tests.OWNER_SEED,
            grants={name:ref(name) for name in ('federation-board-dispatch','federation-board-complete')})

    async def test_actual_owner_signer_creates_fresh_authorized_phase_operation(self):
        _,_,claim=await self.prepare()
        prototype=await self.phase('federation-board-dispatch','prototype')
        payload=strict_loads(prototype)['payload']
        first=await self.signer.admit('federation-board-dispatch',expected_sequence=1,
            payload=payload,cancellation_ref=ref('cancel'))
        second=await self.signer.admit('federation-board-dispatch',expected_sequence=1,
            payload=payload,cancellation_ref=ref('cancel'))
        operation=strict_loads(first.envelope)['operation']
        self.assertEqual(operation['caller']['authenticatedIdentityRef'],ref('board-owner'))
        self.assertNotEqual(operation['operationId'],strict_loads(second.envelope)['operation']['operationId'])
        self.assertNotEqual(operation['operationId'],strict_loads(claim.record)['operation']['operationId'])
        stored=await self.journal.advance(first.envelope,expected_sequence=1)
        self.assertEqual(stored.sequence,2)

    async def test_current_owner_grant_withdrawal_prevents_fresh_phase_signing(self):
        await self.prepare()
        prototype=await self.phase('federation-board-dispatch','prototype')
        self.claims.update(operationId='withdraw-dispatch',contractId='identity-revoke',
            grantRef=ref('grant'),expectedVersion=1,
            payload={'authorityId':'authority-one','targetRef':ref('federation-board-dispatch')})
        receipt=strict_loads(await self.service.handle(service_tests.ServiceTests.request(self)))
        self.assertEqual(receipt['claims']['receipt']['decision'],'allowed')
        with self.assertRaisesRegex(ContractError,'board_phase_access_refused'):
            await self.signer.admit('federation-board-dispatch',expected_sequence=1,
                payload=strict_loads(prototype)['payload'],cancellation_ref=ref('cancel'))
        self.assertEqual(len(self.journal_js.messages),1)
