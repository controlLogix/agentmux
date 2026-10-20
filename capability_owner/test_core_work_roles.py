"""Selected original-source role interests use current finite route authority."""
import asyncio
from unittest.mock import AsyncMock, patch
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.authority import AuthoritySnapshot
from identity.core_work_transport import INGEST
from .test_code_selection import SelectedCodeFixture
from .test_core_work_owner import CoreWorkOwnerTests
from .test_selected_work import SelectedWorkCompositionTests


class CoreWorkRoleTests(SelectedCodeFixture, unittest.IsolatedAsyncioTestCase):
    setUp = SelectedWorkCompositionTests.setUp
    start_host = SelectedWorkCompositionTests.start_host
    core = CoreWorkOwnerTests.core

    async def test_live_agent_role_is_intersected_with_declared_subjects_and_removed_on_death(self):
        owner, resource, _, _ = await self.core()
        session = await resource._owner.db(resource._store.register,
            'falcon', 'worker', 'role_test', 'codex', {})
        await resource._owner.db(resource._store.repo_add, 'other')
        await resource._owner.db(resource._store.register, 'other', 'worker', 'unselected', 'codex', {})
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(owner, 'set_work_subjects', AsyncMock()) as apply:
            await owner._roles.sync()
            apply.assert_awaited_once_with({'am.work.falcon.worker'})
            await resource._owner.db(resource._store.set_state, session, 'dead')
            await owner._roles.sync()
            self.assertEqual(apply.await_args.args, (set(),))
        self.assertFalse(owner._roles._active)

    async def test_revoked_route_loses_queue_interest_without_mutating_original_work(self):
        owner, resource, _, route = await self.core()
        await resource._owner.db(resource._store.register, 'falcon', 'worker', 'role_test', 'codex', {})
        before = await resource._owner.db(resource._store.q, 'SELECT * FROM work_items')
        record = strict_loads(self.core_snapshot.record)
        next(grant for grant in record['state']['grants']
            if grant['ref'] == route['peer']['grantRefs'][INGEST])['status'] = 'revoked'
        revoked = AuthoritySnapshot(canonical_bytes(record), self.core_snapshot.sequence + 1)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=revoked)), \
                patch.object(owner, 'set_work_subjects', AsyncMock()) as apply:
            await owner._roles.sync()
            apply.assert_awaited_once_with(set())
        self.assertEqual(await resource._owner.db(resource._store.q, 'SELECT * FROM work_items'), before)

    async def test_pause_joins_current_role_iteration_without_waiting_for_loop_parent(self):
        owner, resource, _, _ = await self.core()
        await resource._owner.db(resource._store.register, 'falcon', 'worker', 'role_test', 'codex', {})
        entered, release = asyncio.Event(), asyncio.Event()
        async def apply(subjects):
            entered.set()
            await release.wait()
        async def parent():
            try:
                await owner._roles.sync()
            except ContractError:
                pass
            await asyncio.Future()
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(owner, 'set_work_subjects', side_effect=apply):
            task = asyncio.create_task(parent())
            observer = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                owner.begin_policy_pause()
                observer = asyncio.create_task(owner.join_policy_pause())
                await asyncio.sleep(0)
                self.assertFalse(observer.done())
                release.set()
                # The iteration refuses after pause, but its exact marker joins.
                await asyncio.wait_for(observer, 1)
                self.assertFalse(owner._roles._active)
                self.assertFalse(task.done())
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                if observer is not None:
                    await asyncio.gather(observer, return_exceptions=True)

    async def test_revocation_during_role_read_refuses_new_queue_interest(self):
        owner, resource, _, route = await self.core()
        await resource._owner.db(resource._store.register, 'falcon', 'worker', 'role_test', 'codex', {})
        record = strict_loads(self.core_snapshot.record)
        next(grant for grant in record['state']['grants']
            if grant['ref'] == route['peer']['grantRefs'][INGEST])['status'] = 'revoked'
        revoked = AuthoritySnapshot(canonical_bytes(record), self.core_snapshot.sequence + 1)
        current = self.core_snapshot
        original = owner._roles._interests
        def changed(selected):
            nonlocal current
            interests = original(selected)
            current = revoked
            return interests
        async def authority():
            return current
        with patch.object(self.identity.reader, 'current', side_effect=authority), \
                patch.object(owner._roles, '_interests', side_effect=changed), \
                patch.object(owner, 'set_work_subjects', AsyncMock()) as apply:
            await owner._roles.sync()
            apply.assert_awaited_once_with(set())
