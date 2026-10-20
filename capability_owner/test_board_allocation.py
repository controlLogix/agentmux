"""Allocation preparation preserves the actual board domain before dispatch."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,patch

from agentmux_contracts import ContractError,strict_loads
from hub.fed.board_services import SharedBoardStore,_BoardOperations
from hub.fed.guard import Refused
from hub.store import HubError
from hub.tests import test_work_board_services as board_tests
from state_owner.ledger import MAX_SEQUENCE,StreamIdentity
from state_owner.test_ledger import CREATED
from . import test_board_journal as journal_tests
from .board_allocation import BoardAllocationTarget,prepare_allocation
from .board_journal import claim_marker


class AllocationPreparationTests(unittest.IsolatedAsyncioTestCase):
    open=journal_tests.BoardJournalTests.open
    admit=journal_tests.BoardJournalTests.admit
    setUp=journal_tests.BoardJournalTests.setUp

    async def prepare(self,*,command=None,counter=b'12',revision=7,observed=20):
        args=command or {'command':'add','title':'New card','body':'Body','labels':['one'],'assign':'peer:alice'}
        raw=await self.admit('federation-board-command','allocate-one',7,
            {'resourceRef':self.target,'attribution':'operator','input':args})
        target=BoardAllocationTarget('r0123456789ab','SH',StreamIdentity(CREATED,0))
        prepared=_BoardOperations().prepare_add_input(args)
        return raw,prepare_allocation(target,strict_loads(raw),prepared,counter_revision=revision,
            counter_value=counter,observed_sequence=observed,context=None,by='peer:nick',
            at='2026-10-09T12:00:01Z')

    async def test_exact_counter_observation_and_original_marker_are_frozen(self):
        raw,plan=await self.prepare(counter=b' 12\n')
        self.assertEqual((plan.counter_revision,plan.counter_value,plan.counter_bytes,plan.key),
                         (7,b' 12\n',b'13','SH-13'))
        self.assertEqual(plan.target.counter_subject,'$KV.am_board.r0123456789ab.seq.SH')
        card=plan.candidate.card
        self.assertEqual(card['_agentmuxOperation'],claim_marker(strict_loads(raw)))
        self.assertEqual((card['title'],card['body'],card['labels'],card['assignee']),
                         ('New card','Body',['one'],'peer:alice'))
        self.assertEqual((card['created_at'],card['updated_at'],card['history'][0]['at']),
                         ('2026-10-09T12:00:01Z',)*3)
        card['labels'].clear()
        self.assertEqual(plan.candidate.card['labels'],['one'])
        self.assertEqual(self.journal_js.messages,[])

    async def test_absent_counter_prepares_one_without_dispatch_or_recreation(self):
        _,plan=await self.prepare(counter=None,revision=0)
        self.assertEqual((plan.number,plan.counter_bytes,plan.key),(1,b'1','SH-1'))
        self.assertEqual(self.journal_js.messages,[])

    async def test_bad_counter_and_observation_refuse_without_progress(self):
        for raw,revision,observed in ((b'bad',7,20),(b'-1',7,20),
                (str(MAX_SEQUENCE).encode(),7,20),(None,7,20),(b'12',0,20),(b'12',7,6)):
            with self.subTest(raw=raw,revision=revision,observed=observed),self.assertRaises(ContractError):
                await self.prepare(counter=raw,revision=revision,observed=observed)
        self.assertEqual(self.journal_js.messages,[])

    async def test_actual_redaction_and_blocking_happen_before_any_claim(self):
        _,plan=await self.prepare(command={'command':'add','title':'ghp_'+'a'*36})
        self.assertNotIn('ghp_',plan.candidate.value.decode())
        self.assertIn('github_token',plan.candidate.kinds)
        with self.assertRaises(Refused):
            await self.prepare(command={'command':'add','title':'-----BEGIN PRIVATE KEY-----'})
        self.assertEqual(self.journal_js.messages,[])


class AddPreparationDomainTests(unittest.TestCase):
    def test_local_source_is_resolved_once_and_frozen_before_candidate_creation(self):
        operations=_BoardOperations()
        source={'title':'Source','description':'Source body'}
        with patch('hub.fed.board_services._local_card',return_value=source) as lookup:
            prepared=operations.prepare_add_input({'from':'TM-1','labels':['linked']})
            source['title']='Changed later'
            first=operations.prepare_add(None,'r0123456789ab','SH-13',prepared,by='peer:nick',at='fixed')
            second=operations.prepare_add(None,'r0123456789ab','SH-13',prepared,by='peer:nick',at='fixed')
            lookup.assert_called_once_with('TM-1')
        self.assertEqual(first.value,second.value)
        self.assertEqual((first.card['title'],first.card['body'],first.card['links']),
                         ('Source','Source body',{'local':'TM-1'}))
        self.assertEqual(first.card['history'][0]['what'],'created from TM-1')

    def test_required_title_and_assignee_rules_are_preserved(self):
        for args in ({},{'title':'Title','assign':'invalid'}):
            with self.subTest(args=args),self.assertRaises(HubError):
                _BoardOperations().prepare_add_input(args)


class LegacyAddCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.domain=board_tests.WorkBoardServices()
        self.domain.setUp()
        self.addCleanup(self.domain.tearDown)

    async def test_legacy_add_keeps_integer_counter_card_audit_and_mirror(self):
        owner=self.domain.owner
        rid=owner.policy.rid_of('falcon')
        kv=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(value=b'12',revision=7)),
            update=AsyncMock(return_value=19),create=AsyncMock(return_value=23))
        owner.kv=AsyncMock(return_value=kv)
        result=await SharedBoardStore(owner).add({'repo':'falcon','title':'New card','labels':['one']},'operator')
        kv.update.assert_awaited_once_with(rid+'.seq.SH',b'13',last=7)
        key,value=kv.create.await_args.args
        self.assertEqual(key,rid+'.card.SH-13')
        card=json.loads(value)
        self.assertEqual((card['key'],card['rid'],card['title'],result['rev']),('SH-13',rid,'New card',23))
        self.assertNotIn('_agentmuxOperation',card)
        self.assertEqual(len(self.domain.store.q('SELECT * FROM fed_audit')),1)
        self.assertEqual(self.domain.store.q1('SELECT rev FROM p_board_cards')['rev'],23)
