"""Actual board domain, retained journal and owner signing; broker I/O controlled."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import strict_loads
from hub.fed.board_services import SharedBoardStore
from hub.tests import test_work_board_services as board_tests
from identity import test_service as service_tests
from identity.test_authority import ref
from state_owner.ledger import OwnerBinding, StreamIdentity
from state_owner.test_ledger import CREATED
from . import test_board_journal as journal_tests
from .board_target import BoardTargetBinding
from .board_phase_signer import BoardPhaseSigner
from .board_owner import BoardActor, BoardMutationOwner
from .federation_board import FederationBoardResource


class BoardOwnerTests(unittest.IsolatedAsyncioTestCase):
    open=journal_tests.BoardJournalTests.open
    admit=journal_tests.BoardJournalTests.admit

    def setUp(self):
        journal_tests.BoardJournalTests.setUp(self)
        self.install_board()

    def install_board(self):
        for module in ('capability_owner.board_owner','capability_owner.board_phase_signer'):
            patch(module+'.datetime',service_tests._Clock).start()
        self.legacy=board_tests.WorkBoardServices()
        self.legacy.setUp();self.addCleanup(self.legacy.tearDown)
        owner=self.legacy.owner
        rid=owner.policy.rid_of('falcon')
        self.card={'key':'SH-1','rid':rid,'title':'Existing','status':'todo','comments':[],
                   'history':[],'unknownFutureField':{'nested':[None,42]}}
        self.entry=SimpleNamespace(bucket='am_board',key=rid+'.card.SH-1',
                                   value=json.dumps(self.card).encode(),revision=7)
        self.info=SimpleNamespace(config=SimpleNamespace(name='KV_am_board',subjects=['$KV.am_board.>']),
            created=CREATED,state=SimpleNamespace(last_seq=7))
        async def update(key,value,last):
            self.assertEqual((key,last),(self.entry.key,self.entry.revision))
            self.entry=SimpleNamespace(bucket='am_board',key=key,value=value,revision=23)
            self.info.state.last_seq=23
            return 23
        self.kv=SimpleNamespace(get=AsyncMock(side_effect=lambda key:self.entry),update=AsyncMock(side_effect=update))
        owner.kv=AsyncMock(return_value=self.kv)
        owner.js=SimpleNamespace(_prefix='$JS.API',stream_info=AsyncMock(side_effect=lambda stream:self.info),
                                 key_value=AsyncMock(return_value=self.kv))
        binding=OwnerBinding('hub-one','federation-board','task-one','board-card',self.binding.scope)
        self.resource=FederationBoardResource(binding,SharedBoardStore(owner),'falcon',rid,'SH-1',StreamIdentity(CREATED,0))
        self.journal=self.open(target_binding=BoardTargetBinding(rid,'SH-1',StreamIdentity(CREATED,0)))
        self.signer=BoardPhaseSigner(self.journal,self.service.ingress,transport_ref=ref('owner-transport'),
            signing_seed=journal_tests.OWNER_SEED,grants={name:ref(name) for name in
                ('federation-board-dispatch','federation-board-complete')})
        self.owner=BoardMutationOwner(self.resource,self.journal,self.signer,actors=(
            BoardActor(ref('human'),ref('transport'),'peer:nick','operator'),))
        self.addAsyncCleanup(self.owner.close)

    async def test_domain_comment_commits_once_and_original_result_survives_replay(self):
        raw=await self.admit('federation-board-command','board-comment',7,
            {'resourceRef':self.target,'attribution':'operator',
             'input':{'command':'comment','key':'SH-1','text':'one'}})
        result=await self.owner.apply(raw)
        self.assertEqual((result['outcome'],result['resourceRef']['revision']),('applied',23))
        self.assertEqual(result['receiptRef']['revision'],4)
        card=strict_loads(self.entry.value)
        self.assertEqual(card['unknownFutureField'],self.card['unknownFutureField'])
        self.assertEqual([c['text'] for c in card['comments']],['one'])
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),1)
        self.assertEqual(self.legacy.store.q1('SELECT rev FROM p_board_cards')['rev'],23)
        self.assertEqual(await self.owner.apply(raw),result)
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.journal_js.messages),4)
