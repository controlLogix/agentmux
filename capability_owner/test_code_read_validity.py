"""Actual signed code reads retain authority expiry through Hub disclosure.

The existing fixture controls session transport and physical Git. These checks
qualify no broker or production session startup.
"""
import asyncio
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from . import test_legacy_code_client as fixture


class CodeReadValidityTests(fixture.LegacyCodeTests):
    def setUp(self):
        super().setUp()
        for grant in self.record['state']['grants']:
            if grant['ref'] == self.code_grants['human']['federation-code-read']:
                grant['expiresAt'] = (NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[0].data = canonical_bytes(self.record)

    async def original_share(self):
        result = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Original read'})
        self.assertTrue(result['ok'], result)
        return result['result']['id']

    async def delayed_read(self, verb, arguments, *, after=1):
        original = self.sessions[0].code_command
        observed = []
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        import capability_owner.legacy_code_client as client_module
        def delayed(**kwargs):
            result = original(**kwargs)
            if kwargs['contract_id'] == 'federation-code-read':
                self.assertTrue(kwargs.get('include_valid_until'))
                self.assertEqual(result['validUntil'], (NOW + timedelta(seconds=1)).isoformat(timespec='microseconds').replace('+00:00', 'Z'))
                observed.append(copy.deepcopy(result))
                if len(observed) == after:
                    client_module.datetime = Later
            return result
        try:
            with patch.object(self.sessions[0], 'code_command', side_effect=delayed):
                response = await self.request_hub(verb, arguments)
            self.assertEqual(len(observed), after)
            return response
        finally:
            client_module.datetime = _Clock

    async def test_list_refuses_verified_read_after_owner_expiry(self):
        await self.original_share()
        response = await self.delayed_read('fed_code_list', {'repo': 'falcon'})
        self.assertFalse(response['ok'], response)
        self.assertNotIn('result', response)

    async def test_panel_does_not_disclose_expired_rows(self):
        await self.original_share()
        response = await self.delayed_read('fed_panel', {})
        self.assertTrue(response['ok'], response)
        panel = next(item for item in response['result']['panels'] if item['plugin'] == 'code')
        self.assertEqual(panel['error'], 'Code data is unavailable')
        self.assertNotIn('rows', panel)

    async def test_panel_composition_await_cannot_disclose_expired_code_rows(self):
        await self.original_share()
        import hub.fed.runtime as runtime
        import capability_owner.legacy_code_client as client_module
        audit = runtime._v_audit
        observed = []
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        async def delayed_audit(*args, **kwargs):
            result = await audit(*args, **kwargs)
            observed.extend(item for item in self.submitted if item['contractId'] == 'federation-code-read')
            client_module.datetime = Later
            return result
        try:
            with patch.object(runtime, '_v_audit', side_effect=delayed_audit):
                response = await self.request_hub('fed_panel', {})
        finally:
            client_module.datetime = _Clock
        self.assertEqual(len(observed), 1)
        self.assertTrue(response['ok'], response)
        panel = next(item for item in response['result']['panels'] if item['plugin'] == 'code')
        self.assertEqual(panel['error'], 'Code data is unavailable')
        self.assertNotIn('rows', panel)
        self.assertFalse(self.client._panel_reads)

    async def test_initial_get_expiry_refuses_before_physical_fetch(self):
        identifier = await self.original_share()
        response = await self.delayed_read('fed_code_fetch', {'id': identifier})
        self.assertFalse(response['ok'], response)
        self.git['fetch_verified'].assert_not_awaited()
        self.assertIsNone(self.store.q1('SELECT fetched FROM p_code_shares')['fetched'])

    async def test_earlier_read_expiry_survives_later_signed_read(self):
        await self.original_share()
        select = self.client._select
        def two_reads(caller, command, repo=None):
            routes = select(caller, command, repo)
            # Repeat the real enrolled route to exercise the accumulation loop.
            # Both exchanges use actual signatures; this does not claim a
            # second repository enrollment or bypass source checks.
            return routes + routes if command == 'read' else routes
        with patch.object(self.client, '_select', side_effect=two_reads):
            response = await self.delayed_read('fed_code_list', {}, after=2)
        self.assertFalse(response['ok'], response)
        self.assertNotIn('result', response)

    async def test_current_list_panel_and_get_keep_original_values(self):
        identifier = await self.original_share()
        listing = await self.request_hub('fed_code_list', {'repo': 'falcon'})
        self.assertTrue(listing['ok'], listing)
        self.assertEqual(listing['result'][0]['id'], identifier)
        panel = await self.request_hub('fed_panel', {})
        self.assertTrue(panel['ok'], panel)
        code = next(item for item in panel['result']['panels'] if item['plugin'] == 'code')
        self.assertTrue(code['rows'])
        fetched = await self.request_hub('fed_code_fetch', {'id': identifier})
        self.assertTrue(fetched['ok'], fetched)
        self.assertTrue(fetched['result']['verified'])
        self.git['fetch_verified'].assert_awaited_once()

    async def test_revoked_read_after_git_refuses_final_row_disclosure(self):
        identifier = await self.original_share()
        async def fetched(*args):
            self.claims.update(operationId='revoke-read-after-git', contractId='identity-revoke', grantRef=ref('grant'),
                expectedVersion=2, payload={'authorityId': 'authority-one',
                    'targetRef': self.code_grants['human']['federation-code-read']})
            receipt = strict_loads(await self.service.handle(self.request()))
            self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
            return 'a' * 40
        self.git['fetch_verified'].side_effect = fetched
        response = await self.request_hub('fed_code_fetch', {'id': identifier})
        self.assertFalse(response['ok'], response)
        self.git['fetch_verified'].assert_awaited_once()
        reads = [item for item in self.submitted if item['contractId'] == 'federation-code-read']
        self.assertEqual(len(reads), 2)
        self.assertNotIn('result', response)
        pending = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-code-%' ORDER BY k")
        self.assertTrue(any(item['k'].startswith('legacy-code-git:') for item in pending))
        self.assertTrue(any(item['k'].startswith('legacy-code-client:') for item in pending))
        retry = await self.request_hub('fed_code_fetch', {'id': identifier})
        self.assertFalse(retry['ok'], retry)
        self.git['fetch_verified'].assert_awaited_once()
        self.assertEqual(self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-code-%' ORDER BY k"), pending)

    async def test_completed_fetch_requires_current_read_grant_before_replay(self):
        identifier = await self.original_share()
        args = {'id': identifier, 'operation_id': 'stable-fetch-read'}
        first = await self.request_hub('fed_code_fetch', args)
        self.assertTrue(first['ok'], first)
        completed = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-code-completion:%' ORDER BY k")
        self.assertEqual(len(completed), 1)
        self.claims.update(operationId='revoke-completed-read', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=2, payload={'authorityId': 'authority-one',
                'targetRef': self.code_grants['human']['federation-code-read']})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        before_reads = sum(item['contractId'] == 'federation-code-read' for item in self.submitted)
        retry = await self.request_hub('fed_code_fetch', args)
        self.assertFalse(retry['ok'], retry)
        self.assertNotIn('result', retry)
        self.assertEqual(sum(item['contractId'] == 'federation-code-read' for item in self.submitted), before_reads + 1)
        self.git['fetch_verified'].assert_awaited_once()
        self.assertEqual(self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-code-completion:%' ORDER BY k"), completed)

    async def test_post_git_read_expiry_refuses_disclosure_and_keeps_original_effect(self):
        identifier = await self.original_share()
        response = await self.delayed_read('fed_code_fetch', {'id': identifier}, after=2)
        self.assertFalse(response['ok'], response)
        self.assertNotIn('result', response)
        self.git['fetch_verified'].assert_awaited_once()
        pending = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-code-git:%'")
        self.assertEqual(len(pending), 1)
        self.assertEqual(strict_loads(pending[0]['v'])['state'], 'succeeded')

    async def test_final_group_await_cannot_disclose_after_verified_read_expiry(self):
        identifier = await self.original_share()
        finish = self.client._finish_effect
        completed = []
        import capability_owner.legacy_code_client as client_module
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        async def delayed_finish(*args, **kwargs):
            result = await finish(*args, **kwargs)
            completed.append(result)
            client_module.datetime = Later
            return result
        try:
            with patch.object(self.client, '_finish_effect', side_effect=delayed_finish):
                response = await self.request_hub('fed_code_fetch',
                    {'id': identifier, 'operation_id': 'final-group-expiry'})
        finally:
            client_module.datetime = _Clock
        self.assertFalse(response['ok'], response)
        self.assertNotIn('result', response)
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]['state'], 'completed')
        self.git['fetch_verified'].assert_awaited_once()
        retained = self.store.q("SELECT v FROM fed_state WHERE k LIKE 'legacy-code-completion:completed:%'")
        self.assertEqual([strict_loads(item['v']) for item in retained], completed)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-code-git:%'"), [])

    async def test_read_metadata_is_signed_and_ordinary_shape_unchanged(self):
        await self.original_share()
        await self.request_hub('fed_code_list', {'repo': 'falcon'})
        claims = next(item for item in reversed(self.submitted) if item['contractId'] == 'federation-code-read')
        key = self.code_key('human')
        subject = key.selection['codeCommands']['subject']
        raw = key.sign_command(claims, subject=subject, now=NOW)
        reply = await self.endpoint.handle(raw, received_reply_subject=claims['replySubject'])
        ordinary = key.verify_command_response(reply, raw, subject=subject, now=NOW)
        checked = key.verify_command_response(reply, raw, subject=subject, now=NOW, include_valid_until=True)
        self.assertEqual(checked, {'result': ordinary, 'validUntil': strict_loads(reply)['claims']['validUntil']})
        forged = strict_loads(reply)
        forged['claims']['validUntil'] = (NOW + timedelta(seconds=2)).isoformat().replace('+00:00', 'Z')
        with self.assertRaises(ContractError):
            key.verify_command_response(canonical_bytes(forged), raw, subject=subject, now=NOW, include_valid_until=True)
        publish = next(item for item in self.submitted if item['contractId'] == 'federation-code-publish')
        original = key.sign_command(publish, subject=subject, now=NOW)
        response = await self.endpoint.handle(original, received_reply_subject=publish['replySubject'])
        with self.assertRaises(ContractError):
            key.verify_command_response(response, original, subject=subject, now=NOW, include_valid_until=True)


def load_tests(loader, tests, pattern):
    # Reuse the fixture without rerunning its inherited, separately owned suite.
    return unittest.TestSuite(CodeReadValidityTests(name) for name in sorted(CodeReadValidityTests.__dict__)
        if name.startswith('test_'))
