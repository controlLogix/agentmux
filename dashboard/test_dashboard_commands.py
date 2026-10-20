"""Focused authorization and outcome checks for local dashboard commands."""
import asyncio
import copy
from datetime import datetime
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from agentmux_contracts import ContractError, canonical_bytes, payload_digest
from dashboard_commands import (DashboardCommandService, DashboardEffectOwner,
    DashboardEffectReceipt, DashboardOutcomeUnconfirmed, DashboardDomainEffects,
    SQLiteDashboardEffectOwner)
from identity import test_application_binding as support
from identity.local_browser_session import LocalBrowserContext, _CONTEXT_BRAND
from identity.test_authority import NOW, ref


class _Clock:
    @classmethod
    def now(cls, _zone=None):
        return NOW


class Effects(DashboardEffectOwner):
    def __init__(self, test):
        self.test = test
        self.calls = []
        self.after = None
        self.status = 'applied'
        self.retained = {}

    async def execute(self, *, operation_id, payload, action, body, actor):
        self.calls.append((operation_id, payload, action, body, actor))
        digest = payload_digest(payload)
        previous = self.retained.get(operation_id)
        if previous is not None and previous != digest:
            raise ContractError('dashboard_effect_retargeted')
        self.retained[operation_id] = digest
        if self.after is not None:
            self.after()
        result = canonical_bytes({'saved': True}) if self.status == 'applied' else None
        return DashboardEffectReceipt(operation_id, digest, self.status, result)


class DomainEffects(DashboardDomainEffects):
    def __init__(self):
        self.calls = []
        self.fail_external = False

    def apply_transactional(self, db, target, action, body, actor):
        self.calls.append((action, body, actor))
        db.execute("CREATE TABLE IF NOT EXISTS dashboard_test_effect (value TEXT)")
        db.execute("INSERT INTO dashboard_test_effect VALUES (?)", (body['name'],))
        return {'saved': body['name']}

    def apply_external(self, target, action, body, actor):
        self.calls.append((action, body, actor))
        if self.fail_external:
            raise RuntimeError('outcome lost')
        return {'sent': action}


class DashboardCommandTests(unittest.IsolatedAsyncioTestCase):
    make_provider = support.ApplicationBindingTests.make_provider

    def setUp(self):
        support.ApplicationBindingTests.setUp(self)
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None}
        for membership in self.record['state']['memberships']:
            membership['scope'] = copy.deepcopy(self.scope)
        grant = copy.deepcopy(self.record['state']['grants'][1])
        grant.update(ref=ref('dashboard-command-grant'), scope=copy.deepcopy(self.scope),
            contractId='dashboard-command', resourceId='dashboard-one')
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        self.effects = Effects(self)
        self.service = DashboardCommandService(self.service.reader,
            scope=self.scope, resource_ref=ref('dashboard-one'), effects=self.effects)
        self.addAsyncCleanup(self.service.close)

    def context(self):
        authority = {'id': self.record['entityId'], 'ownerHubId': self.record['ownerHubId'],
                     'revision': self.record['entityVersion']}
        return LocalBrowserContext(canonical_bytes(ref('human')), canonical_bytes(self.scope),
            canonical_bytes(authority), self.js.messages[0].seq,
            '2026-10-09T12:10:00Z', _CONTEXT_BRAND)

    async def command(self, body=None, target='/api/board/config'):
        return await self.service.handle_local_browser(self.context(), target,
            {'name': 'orchestratorEnabled', 'value': False} if body is None else body,
            operation_id='dashboard_' + 'a' * 64)

    async def test_exact_body_uses_current_human_and_scoped_grant(self):
        with mock.patch('dashboard_commands.datetime', _Clock):
            result = await self.command()
        self.assertEqual(result, {'ok': True, 'saved': True,
            'operationId': 'dashboard_' + 'a' * 64, 'outcome': 'applied'})
        operation, payload, action, body, actor = self.effects.calls[0]
        self.assertEqual((operation, action, actor),
                         ('dashboard_' + 'a' * 64, 'config', 'user-one'))
        self.assertEqual(payload['requestId'], operation)
        self.assertEqual(payload['bodyDigest'], payload_digest(body))
        self.assertEqual(payload['resourceRef'], ref('dashboard-one'))
        self.assertEqual(payload['target'], '/api/board/config')

    async def test_payload_identity_and_unknown_routes_never_reach_effect(self):
        with mock.patch('dashboard_commands.datetime', _Clock):
            with self.assertRaisesRegex(ContractError, 'dashboard_identity_field_refused'):
                await self.command({'name': 'orchestratorEnabled', 'value': False,
                                    'actor': 'forged'})
            with self.assertRaisesRegex(ContractError, 'dashboard_command_unavailable'):
                await self.command({}, '/api/board/agentdef')
        self.assertEqual(self.effects.calls, [])

    async def test_membership_revocation_and_hard_denial_fail_before_effect(self):
        original = copy.deepcopy(self.record)
        for mutation in ('membership', 'denial'):
            self.record = copy.deepcopy(original)
            if mutation == 'membership':
                self.record['state']['memberships'][0]['status'] = 'revoked'
            else:
                denied = copy.deepcopy(self.record['state']['grants'][-1])
                denied.update(ref=ref('dashboard-denial'), decision='denied')
                self.record['state']['grants'].append(denied)
            self.js.messages[0].data = canonical_bytes(self.record)
            with self.subTest(mutation=mutation), \
                    mock.patch('dashboard_commands.datetime', _Clock), \
                    self.assertRaises(ContractError):
                await self.command()
        self.assertEqual(self.effects.calls, [])

    async def test_revocation_after_effect_withholds_applied_outcome(self):
        def revoke():
            self.record['state']['grants'][-1]['decision'] = 'denied'
            self.js.messages[0].data = canonical_bytes(self.record)
        self.effects.after = revoke
        with mock.patch('dashboard_commands.datetime', _Clock), \
                self.assertRaises(DashboardOutcomeUnconfirmed) as raised:
            await self.command()
        self.assertEqual(raised.exception.operation_id, 'dashboard_' + 'a' * 64)
        self.assertEqual(len(self.effects.calls), 1)

    async def test_run_review_is_bound_to_run_target_and_no_fixed_actor(self):
        with mock.patch('dashboard_commands.datetime', _Clock):
            await self.command({'decision': 'approved', 'note': 'read'},
                               '/api/runs/abcdef/review')
        self.assertEqual(self.effects.calls[0][2:],
                         ('run-review', {'decision': 'approved', 'note': 'read'}, 'user-one'))
        self.assertEqual(self.effects.calls[0][1]['target'], '/api/runs/abcdef/review')
        with mock.patch('dashboard_commands.datetime', _Clock), \
                self.assertRaises(DashboardOutcomeUnconfirmed):
            await self.command({'decision': 'approved', 'note': 'read'},
                               '/api/runs/123456/review')


class SQLiteDashboardEffectTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'cc.db'
        sqlite3.connect(self.path).close()
        info = self.path.stat()
        self.domain = DomainEffects()
        self.owner = SQLiteDashboardEffectOwner(self.path, device=info.st_dev,
            inode=info.st_ino, owner_uid=os.getuid(), effects=self.domain)
        self.addAsyncCleanup(self.owner.close)

    async def execute(self, operation='dashboard_' + 'b' * 64, action='config'):
        payload = {'resourceRef': ref('dashboard-one'), 'requestId': operation,
            'target': '/api/board/' + action, 'action': action,
            'bodyDigest': payload_digest({'name': 'setting'})}
        return await self.owner.execute(operation_id=operation, payload=payload,
            action=action, body={'name': 'setting'}, actor='user-one')

    async def test_transactional_effect_and_intent_commit_once(self):
        first = await self.execute()
        second = await self.execute()
        self.assertEqual((first.status, second.status), ('applied', 'applied'))
        self.assertEqual((first.result_copy(), second.result_copy()),
                         ({'saved': 'setting'}, {'saved': 'setting'}))
        self.assertEqual(self.domain.calls, [('config', {'name': 'setting'}, 'user-one')])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM dashboard_test_effect").fetchone()[0], 1)

    async def test_operation_cannot_retarget_and_unknown_external_does_not_repeat(self):
        await self.execute()
        with self.assertRaisesRegex(ContractError, 'dashboard_effect_retargeted'):
            await self.owner.execute(operation_id='dashboard_' + 'b' * 64,
                payload={'target': '/api/board/config', 'different': True},
                action='config', body={'name': 'setting'},
                actor='user-one')
        self.domain.fail_external = True
        with self.assertRaises(RuntimeError):
            await self.execute('dashboard_' + 'c' * 64, 'chatsend')
        receipt = await self.execute('dashboard_' + 'c' * 64, 'chatsend')
        self.assertEqual(receipt.status, 'uncertain')
        self.assertEqual([call[0] for call in self.domain.calls].count('chatsend'), 1)

    async def test_ephemeral_confirmation_replays_only_in_the_same_owner(self):
        operation = 'dashboard_' + 'e' * 64
        first = await self.execute(operation, 'plcstate')
        second = await self.execute(operation, 'plcstate')
        self.assertEqual((first.result_copy(), second.result_copy()),
                         ({'sent': 'plcstate'}, {'sent': 'plcstate'}))
        await self.owner.close()
        info = self.path.stat()
        replacement = SQLiteDashboardEffectOwner(self.path, device=info.st_dev,
            inode=info.st_ino, owner_uid=os.getuid(), effects=self.domain)
        self.addAsyncCleanup(replacement.close)
        payload = {'resourceRef': ref('dashboard-one'), 'requestId': operation,
            'target': '/api/board/plcstate', 'action': 'plcstate',
            'bodyDigest': payload_digest({'name': 'setting'})}
        recovered = await replacement.execute(operation_id=operation, payload=payload,
            action='plcstate', body={'name': 'setting'}, actor='user-one')
        self.assertEqual(recovered.status, 'uncertain')
        self.assertEqual([call[0] for call in self.domain.calls].count('plcstate'), 1)

    async def test_cancelled_wait_and_close_still_join_original_external_effect(self):
        entered, release = threading.Event(), threading.Event()

        def held(_target, action, body, actor):
            self.domain.calls.append((action, body, actor))
            entered.set()
            release.wait(2)
            return {'sent': action}

        self.domain.apply_external = held
        operation = 'dashboard_' + 'd' * 64
        executing = asyncio.create_task(self.execute(operation, 'chatsend'))
        self.assertTrue(await asyncio.to_thread(entered.wait, 1))
        executing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await executing

        closing = asyncio.create_task(self.owner.close())
        await asyncio.sleep(0)
        self.assertFalse(closing.done())
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        self.assertFalse(self.owner._close_task.done())

        release.set()
        await self.owner.close()
        self.assertTrue(self.owner._close_task.done())
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT status FROM dashboard_command_effects "
                             "WHERE operation_id=?", (operation,)).fetchone()
        self.assertEqual(row, ('applied',))


if __name__ == '__main__':
    unittest.main()
