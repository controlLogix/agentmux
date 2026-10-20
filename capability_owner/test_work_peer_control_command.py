"""A Work-only command borrows its selected source and retained publication."""
import copy
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import envelope
from hub.fed.peer_control import PeerControlPublisher
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from identity.test_work_peer_control import WorkPeerControlFixture

from . import test_peer_control_command as command_support
from .peer_control_command import PeerControlCommandOwner
from .peer_control_service import PeerControlCommandService


class WorkPeerControlCommandFixture(command_support.PeerControlCommandFixture, WorkPeerControlFixture):
    def setUp(self):
        super().setUp()
        current = strict_loads(self.snapshot.record)
        for grant in current['state']['grants']:
            if grant['ref'] in (*self.grants.values(), ref('control-local-publisher-grant')):
                grant['resourceId'] = 'work-one'
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence + 1)

    async def asyncSetUp(self):
        await WorkPeerControlFixture.asyncSetUp(self)
        self.publisher = PeerControlPublisher(self.selection, self.identity, route_id='work-alice')
        self.addAsyncCleanup(self.publisher.close, timeout=None)
        self.owner = PeerControlCommandOwner(self.selection, self.identity, self.source, (self.publisher,))
        self.addAsyncCleanup(self.owner.close, timeout=None)
        self.endpoint = PeerControlCommandService(self.identity.ingress, self.owner,
            service_identity_ref=self.signer['identityRef'], service_instance_id=self.signer['instanceId'],
            signing_key_ref=self.signer['ref'], signing_seed=self.identity.ingress._seed)
        self.addAsyncCleanup(self.endpoint.close, timeout=None)
        self.current = patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot))
        self.current.start()
        self.addCleanup(self.current.stop)


class WorkPeerControlCommandTests(WorkPeerControlCommandFixture, command_support.PeerControlCommandTests):
    """Run the existing signed command/recovery cases against a Work-only owner."""

    async def test_exact_work_source_and_original_publisher_are_required(self):
        self.assertNotIn('knowledge', self.selection.policy['storage'])
        self.assertEqual(self.owner._routes['work-alice']['resourceRef'], ref('work-one'))
        self.assertIs(self.owner._source, self.source)
        self.assertIs(self.owner._store, self.source._store)
        self.assertIs(self.owner._executor, self.source._executor)
        self.owner.check()
        for field, value in (('_peer', 'foreign'),
                ('_pins', {**self.source._pins, 'database': {'path': '/foreign'}}),
                ('_repository', {**self.source._repository, 'localName': 'foreign'})):
            with self.subTest(field=field), patch.object(self.source, field, value), self.assertRaises(ContractError):
                PeerControlCommandOwner(self.selection, self.identity, self.source, (self.publisher,))
        replacement = PeerControlPublisher(self.selection, self.identity, route_id='work-alice')
        self.addAsyncCleanup(replacement.close, timeout=None)
        with patch.dict(self.owner._publishers, {'work-alice': replacement}), self.assertRaises(ContractError):
            self.owner.check()
        with patch.object(self.source, 'db', AsyncMock()), self.assertRaises(ContractError):
            self.owner.check()
        with patch.object(self.publisher, '_identity', object()), self.assertRaises(ContractError):
            self.owner.check()
        self.owner.check()

    async def test_changed_selected_route_generation_refuses_before_publication(self):
        item = envelope.make('revoke', 'nick', 'mac')
        original = self.request(item)
        changed = copy.deepcopy(self.owner._routes['work-alice'])
        changed['resourceRef']['revision'] += 1
        with patch('capability_owner.peer_control_command.selected_route', return_value=changed), \
                patch.object(self.publisher, 'publish_revoke', AsyncMock()) as publish, \
                self.assertRaises(ContractError):
            await self.call(original)
        publish.assert_not_awaited()
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'peer-control-command:%'"), [])

    async def test_revoked_publisher_cannot_disclose_a_completed_work_command(self):
        item = envelope.make('revoke', 'nick', 'mac')
        original = self.request(item)
        with patch.object(self.publisher, 'publish_revoke', AsyncMock(return_value={
                'eventId': item['id'], 'eventDigest': payload_digest(item)})) as publish:
            first = await self.call(original)
            current = strict_loads(self.snapshot.record)
            next(grant for grant in current['state']['grants']
                if grant['ref'] == ref('control-local-publisher-grant'))['status'] = 'revoked'
            denied = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence + 1)
            query = {'routeId': self.commands['routeId'], 'operationId': first['operationId'],
                'payloadDigest': first['payloadDigest']}
            with patch.object(self.identity.reader, 'current', AsyncMock(return_value=denied)), \
                    self.assertRaises(ContractError):
                await self.call(self.request(None, operation='publisher-denied-outcome', query=query))
            self.assertEqual(publish.call_count, 1)
        retained = await self.source.db(self.source._store.q,
            "SELECT v FROM fed_state WHERE k LIKE 'peer-control-command:%'")
        self.assertEqual(len(retained), 1)
        self.assertEqual(strict_loads(retained[0]['v'])['result'], first)


if __name__ == '__main__':
    unittest.main()
