"""AMUX-635: preserve original approvals and create a new kill after resume."""
import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import envelope, ledger
from hub.client_launch_session import ApplicationSessionFailure
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from .peer_control_client import PeerControlCommandClient
from .test_peer_control_command import PeerControlCommandTests


class PeerControlRetryTests(PeerControlCommandTests):
    async def revoke(self, hub, adapter, item, *, reason, approvals=(), query_approvals=(), query_operation=None):
        args = {'revoke': True, 'reason': reason}
        if approvals:
            args['approvalRefs'] = list(approvals)
        if query_approvals:
            args['outcomeApprovalRefs'] = list(query_approvals)
        if query_operation is not None:
            args['outcomeOperationId'] = query_operation
        proof = await hub.authenticate_caller({'token': 'operator-secret', 'verb': 'fed_kill', 'args': args},
            SimpleNamespace(), True)
        context = hub._authenticated_caller_context.set(proof)
        try:
            return await adapter.revoke('operator', item)
        finally:
            hub._authenticated_caller_context.reset(context)

    async def test_changed_reason_requires_confirmed_kill_and_committed_resume(self):
        session, _, _, wire = self.open_session()
        hub, adapter = self.hub_client(session)
        first = envelope.make('revoke', 'nick', 'mac', data={'reason': 'first'})
        second = envelope.make('revoke', 'nick', 'mac', data={'reason': 'second'})
        async def sent(item):
            return {'eventId': item['id'], 'eventDigest': payload_digest(item)}
        with patch.object(self.publisher, 'publish_revoke', side_effect=sent) as publish:
            first_result = await self.revoke(hub, adapter, first, reason='first')
            with self.assertRaises(ContractError):
                await self.revoke(hub, adapter, second, reason='second')
            killed = {'at': 'original', 'reason': 'first'}
            await hub.db(ledger.state_set, hub.store, 'killed', killed)
            await adapter.confirm_killed(killed)
            with self.assertRaises(ContractError):
                await self.revoke(hub, adapter, second, reason='second')
            await hub.db(ledger.state_set, hub.store, 'killed', None)
            new_result = await self.revoke(hub, adapter, second, reason='second')
            self.assertEqual(first_result[0]['eventId'], first['id'])
            self.assertEqual(new_result[0]['eventId'], second['id'])
            self.assertNotEqual(new_result[0]['operationId'], first_result[0]['operationId'])
            self.assertEqual(publish.call_count, 2)
            self.assertEqual(len(wire.requests), 2)

    async def test_approved_lost_reply_recovery_separates_query_approval(self):
        first_session, _, _, wire = self.open_session(lose_reply=True)
        hub, adapter = self.hub_client(first_session)
        item = envelope.make('revoke', 'nick', 'mac', data={'reason': 'approved kill'})
        record = strict_loads(self.snapshot.record)
        grant = next(g for g in record['state']['grants'] if g['ref'] == self.grants['federation-peer-revoke'])
        grant['decision'] = 'review-required'
        approval_grant = copy.deepcopy(grant)
        approval_grant.update(ref=ref('retry-approve-grant'), contractId='identity-approve',
            resourceId=grant['ref']['id'], decision='allowed')
        record['state']['grants'].append(approval_grant)
        original_call = self.endpoint.handle
        approved_operations = []
        async def admitted(raw, *, received_reply_subject):
            claims = strict_loads(raw)['claims']
            if claims['contractId'] == 'federation-peer-revoke':
                # The existing approval owner may approve the already retained
                # original intent before this first dispatch is admitted.
                record['state']['approvals'] = [{'ref': ref('retry-original-approval'), 'grantRef': grant['ref'],
                    'approverRef': ref('human'), 'approverGrantRef': approval_grant['ref'],
                    'payloadDigest': payload_digest(claims['payload']),
                    'audience': {'hubId': 'hub-one', 'serviceId': 'storage-owner'},
                    'operationId': claims['operationId'], 'expectedVersion': 1,
                    'decision': 'approved', 'status': 'active',
                    'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end}]
                approved_operations.append(claims['operationId'])
            snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)
            with patch.object(self.identity.reader, 'current', AsyncMock(return_value=snapshot)):
                return await original_call(raw, received_reply_subject=received_reply_subject)
        with patch.object(self.endpoint, 'handle', side_effect=admitted), \
                patch.object(self.publisher, 'publish_revoke', AsyncMock(return_value={
                    'eventId': item['id'], 'eventDigest': payload_digest(item)})) as publish:
            with self.assertRaises(ApplicationSessionFailure):
                await self.revoke(hub, adapter, item, reason='approved kill', approvals=(ref('retry-original-approval'),))
            await adapter.close(timeout=2)
            replacement, _, _, fresh = self.open_session()
            recovered = PeerControlCommandClient(hub, (replacement,)).bind(adapter._federation)
            self.addAsyncCleanup(recovered.close, timeout=None)
            result = await self.revoke(hub, recovered,
                envelope.make('revoke', 'nick', 'mac', data={'reason': 'approved kill'}),
                reason='approved kill', approvals=(ref('retry-original-approval'),))
            self.assertEqual(result[0]['eventId'], item['id'])
            self.assertEqual(result[0]['operationId'], approved_operations[0])
            self.assertEqual(result[0], strict_loads(wire.responses[0])['claims']['result'])
            self.assertEqual(strict_loads(fresh.requests[0])['claims']['approvalRefs'], [])
            self.assertEqual(publish.call_count, 1)
            query_grant = next(g for g in record['state']['grants'] if
                g['ref'] == self.grants['federation-peer-revoke-outcome'])
            query_grant['decision'] = 'review-required'
            query_approver = copy.deepcopy(approval_grant)
            query_approver.update(ref=ref('retry-query-approve-grant'), resourceId=query_grant['ref']['id'])
            record['state']['grants'].append(query_approver)
            query = strict_loads(fresh.requests[0])['claims']['payload']
            query_approval = {**record['state']['approvals'][0], 'ref': ref('retry-query-approval'),
                'grantRef': query_grant['ref'], 'approverGrantRef': query_approver['ref'],
                'operationId': 'preapproved-outcome-query', 'payloadDigest': payload_digest(query)}
            record['state']['approvals'].append(query_approval)

            async def recovery(*, refs=(), expect_refusal=False):
                replacement, _, _, requests = self.open_session()
                client = PeerControlCommandClient(hub, (replacement,)).bind(adapter._federation)
                self.addAsyncCleanup(client.close, timeout=None)
                call = self.revoke(hub, client,
                    envelope.make('revoke', 'nick', 'mac', data={'reason': 'approved kill'}),
                    reason='approved kill', approvals=(ref('retry-original-approval'),),
                    query_operation='preapproved-outcome-query', query_approvals=refs)
                if expect_refusal:
                    with self.assertRaises(ApplicationSessionFailure):
                        await call
                    return None
                answer = await call
                self.assertEqual(strict_loads(requests.requests[0])['claims']['operationId'],
                    'preapproved-outcome-query')
                self.assertEqual(strict_loads(requests.requests[0])['claims']['approvalRefs'], list(refs))
                return answer

            # The query requires its own exact preapproved operation/payload.
            # Adding that metadata cannot change the retained effect identity.
            await recovery(expect_refusal=True)
            await recovery(refs=(ref('retry-original-approval'),), expect_refusal=True)
            approved = await recovery(refs=(ref('retry-query-approval'),))
            self.assertEqual(approved, result)
            query_approval['status'] = 'revoked'
            await recovery(refs=(ref('retry-query-approval'),), expect_refusal=True)
            query_approval['status'] = 'active'
            # Original authority remains required even with a valid query approval.
            original_approval = record['state']['approvals'][0]
            record['state']['approvals'].remove(original_approval)
            await recovery(refs=(ref('retry-query-approval'),), expect_refusal=True)
            record['state']['approvals'].insert(0, original_approval)
            original_approval['status'] = 'revoked'
            await recovery(refs=(ref('retry-query-approval'),), expect_refusal=True)
            original_approval['status'] = 'active'
            grant['decision'] = 'denied'
            await recovery(refs=(ref('retry-query-approval'),), expect_refusal=True)
            grant['decision'], grant['status'] = 'review-required', 'revoked'
            await recovery(refs=(ref('retry-query-approval'),), expect_refusal=True)
            self.assertEqual(publish.call_count, 1)
