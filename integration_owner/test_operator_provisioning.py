"""Offline composition checks for the owner-authorized provisioning caller."""
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import copy
import os
import unittest
from unittest.mock import AsyncMock, patch

import nkeys

from agentmux_contracts import ContractError, canonical_bytes
from identity.authority import AuthoritySnapshot, LedgerAuthorityReader
from hub.nats_transport import PairedTCPTransport
from identity import test_application_account as account_tests
from identity import test_application_service_selection as selection_tests
from native_security.secret_custody import (PrivateSecret, ScopedSecretCustody,
                                             _resolved_binding)
from native_security.test_secret_custody import NOW
from state_owner.ledger import OwnerBinding

from .live_broker import user_credential
from .intent import effect_id
from .operator_provisioning import (_administrator_subjects,
    _close_client, IntegrationProvisioningResult, provision_integration_effect)
from .test_provisioning import FakeAdmin


class FakeClient:
    def __init__(self, admin):
        self.admin = admin
        self.is_connected = False
        self.closed = False
        self.options = None

    async def connect(self, **options):
        self.options = options
        if not options['user_jwt_cb']() or not options['signature_cb']('nonce'):
            raise AssertionError('credential callbacks did not return material')
        self.is_connected = True

    def jetstream(self, **options):
        self.domain = options.get('domain')
        return self.admin

    async def close(self):
        self.closed = True
        self.is_connected = False


class FailingAdmin(FakeAdmin):
    async def stream_info(self, name):
        raise RuntimeError('synthetic broker failure')


class DelayedCloseClient(FakeClient):
    def __init__(self, admin):
        super().__init__(admin)
        self.close_started = asyncio.Event()
        self.close_released = asyncio.Event()

    async def close(self):
        self.close_started.set()
        await self.close_released.wait()
        await super().close()


class ReportingClient(FakeClient):
    async def connect(self, **options):
        await super().connect(**options)
        await options['error_cb'](RuntimeError('private synthetic broker text'))


class NeverClosingClient:
    def __init__(self):
        self.joined = False

    async def close(self):
        try:
            await asyncio.Event().wait()
        finally:
            self.joined = True


class ShieldedTransportClient:
    def __init__(self, transport):
        self._transport = transport

    async def close(self):
        await self._transport.wait_closed()


class OperatorProvisioningTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.account_seed = nkeys.encode_seed(bytes(range(32)), nkeys.PREFIX_BYTE_ACCOUNT)
        account_key = nkeys.from_seed(self.account_seed)
        try:
            self.account_public = account_key.public_key.decode()
        finally:
            account_key.wipe()
        selected = selection_tests.ServiceSelectionTests(
            methodName='test_selection_builds_explicit_integration_effect_provisioner')
        selected.setUp()
        self.selection_case = selected
        self.addCleanup(selected.temp.cleanup)
        selected.add_integration()
        roots = {}
        for name in ('resources', 'inventory', 'credentials', 'keys'):
            path = selected.root / ('operator-' + name)
            path.mkdir(mode=0o700)
            roots[name] = path
        key = roots['keys'] / 'key-backup-key.key'
        key.write_bytes(os.urandom(32)); key.chmod(0o600)
        selected.value['integration']['routing'] = {
            'resourceDirectory': str(roots['resources']),
            'inventoryDirectory': str(roots['inventory']),
            'credentialDirectory': str(roots['credentials']),
            'backupKeyDirectory': str(roots['keys']),
            'backupKeyId': 'backup-key',
            'backupDestinationId': 'integration-backup'}
        selected.value['integration']['credentials']['accountPublicKey'] = self.account_public
        self.selection = selected.load()
        self.roots = roots

        account = account_tests.ApplicationAccountTests(
            methodName='test_returns_only_exact_public_references_with_signed_deadline')
        account.setUp()
        account.record['state']['applicationAccounts'][0][
            'accountPublicKey'] = self.account_public
        account.payload['accountPublicKey'] = self.account_public
        account.request['payload'] = account.payload
        from agentmux_contracts import payload_digest
        account.request['operation']['payloadDigest'] = payload_digest(account.payload)
        account.resign()
        self.account_record = account.record
        self.snapshot = AuthoritySnapshot(canonical_bytes(account.record), 23)
        self.request = canonical_bytes(account.request)
        self.reader = object.__new__(LedgerAuthorityReader)
        self.reader._hub = 'hub-one'
        self.reader.current = AsyncMock(return_value=self.snapshot)
        custody_root = selected.root / 'operator-custody'
        custody_root.mkdir(mode=0o700)
        self.custody = ScopedSecretCustody(custody_root, self.reader)
        self.admin_inbox = '_INBOX.integration_admin_0001'
        self.created = datetime(2026, 10, 17, tzinfo=timezone.utc)
        self.admin = FakeAdmin(self.created)
        self.clients = []

    def credential(self, publish=None):
        account = nkeys.from_seed(self.account_seed)
        try:
            with patch('integration_owner.live_broker.time.time',
                       return_value=NOW.timestamp() - 60):
                return user_credential(account,
                    _administrator_subjects('enrolled-domain') if publish is None else publish,
                    [self.admin_inbox + '.>'])
        finally:
            account.wipe()

    def enroll_secrets(self, *, administrator=None, issuer=None):
        administrator = self.credential() if administrator is None else administrator
        issuer = self.account_seed if issuer is None else issuer
        for kind, secret in (
                ('nats-administrator-credential', administrator),
                ('nats-account-issuer', issuer)):
            binding = _resolved_binding(self.snapshot, self.request, kind, NOW)
            self.custody._store.provision(binding, secret)

    def factory(self, **options):
        self.factory_options = options
        client = FakeClient(self.admin)
        self.clients.append(client)
        return client

    async def call(self):
        with patch('native_security.nats_credentials.time.time', return_value=NOW.timestamp()):
            return await provision_integration_effect(self.selection,
                authority=self.reader, custody=self.custody,
                resolution_request=self.request,
                original_operation_id='operation-one', now=NOW,
                _client_factory=self.factory)

    async def test_current_custody_provisions_exact_route_and_closes_owners(self):
        self.enroll_secrets()
        result = await self.call()
        self.assertIs(type(result), IntegrationProvisioningResult)
        self.assertEqual(result.route_generation, 1)
        self.assertEqual(result.route_streams, (result.stream,))
        self.assertTrue(result.router_credential_digest.startswith('sha256:'))
        self.assertNotIn('credential', repr(result).lower())
        self.assertEqual(set(self.admin.streams), {result.stream})
        self.assertEqual(self.clients[0].domain, 'enrolled-domain')
        self.assertTrue(self.clients[0].closed)
        self.assertEqual(self.factory_options['leaf_certificate_sha256'], 'sha256:' + 'a' * 64)
        self.assertEqual(self.clients[0].options['inbox_prefix'], self.admin_inbox)
        # The command has released SQLite ownership before returning.
        inventory = self.selection.integration_effect_inventory()
        scope = self.selection.service('integration')['ledger']['scope']
        binding = OwnerBinding('hub-one', 'integrations',
            effect_id(scope, 'operation-one'), 'effect', canonical_bytes(scope))
        with patch('native_security.nats_credentials.time.time',
                   return_value=NOW.timestamp()):
            reopened = inventory.open_effect(binding, 'operation-one',
                route=inventory.current_route())
        reopened.history.close()

    async def test_close_timeout_cancels_and_joins_the_original_task(self):
        client = NeverClosingClient()
        with self.assertRaisesRegex(ContractError,
                '^integration_operator_cleanup_pending$'):
            await _close_client(client, _timeout=.01)
        self.assertTrue(client.joined)
        self.assertFalse(any(task.get_name() == 'integration-operator-client-cleanup'
                             and not task.done() for task in asyncio.all_tasks()))

    async def test_close_timeout_joins_the_paired_transport_child(self):
        joined = False

        async def child():
            nonlocal joined
            try:
                await asyncio.Event().wait()
            finally:
                joined = True

        transport = object.__new__(PairedTCPTransport)
        transport.prior_close_task = None
        transport.current_close_task = asyncio.create_task(child(),
            name='synthetic-paired-transport-close')
        client = ShieldedTransportClient(transport)
        with self.assertRaisesRegex(ContractError,
                '^integration_operator_cleanup_pending$'):
            await _close_client(client, _timeout=.01)
        self.assertTrue(joined)
        self.assertTrue(transport.current_close_task.done())

    async def test_broad_administrator_credential_is_refused_before_connect(self):
        self.enroll_secrets(administrator=self.credential(['>']))
        with self.assertRaisesRegex(ContractError,
                '^integration_operator_administrator_credential_invalid$'):
            await self.call()
        self.assertEqual(self.clients, [])
        self.assertEqual(self.admin.streams, {})

    async def test_substitute_account_issuer_is_refused_before_connect(self):
        other = nkeys.encode_seed(bytes(reversed(range(32))), nkeys.PREFIX_BYTE_ACCOUNT)
        self.enroll_secrets(issuer=other)
        with self.assertRaisesRegex(ContractError,
                '^integration_operator_account_issuer_invalid$'):
            await self.call()
        self.assertEqual(self.clients, [])

    async def test_corrupt_account_issuer_checksum_is_refused_before_connect(self):
        replacement = b'A' if self.account_seed[-1:] != b'A' else b'B'
        corrupt = self.account_seed[:-1] + replacement
        self.enroll_secrets(issuer=corrupt)
        with self.assertRaisesRegex(ContractError,
                '^integration_operator_account_issuer_invalid$'):
            await self.call()
        self.assertEqual(self.clients, [])

    async def test_broker_failure_closes_the_connected_client(self):
        self.enroll_secrets()
        self.admin = FailingAdmin(self.created)
        with self.assertRaisesRegex(ContractError,
                '^integration_provisioning_stream_unavailable$'):
            await self.call()
        self.assertEqual(len(self.clients), 1)
        self.assertTrue(self.clients[0].closed)

    async def test_async_broker_error_returns_only_fixed_diagnostic(self):
        self.enroll_secrets()

        def factory(**options):
            self.factory_options = options
            client = ReportingClient(self.admin)
            self.clients.append(client)
            return client

        with patch('native_security.nats_credentials.time.time',
                   return_value=NOW.timestamp()):
            with self.assertRaisesRegex(ContractError,
                    '^integration_operator_broker_error$'):
                await provision_integration_effect(self.selection,
                    authority=self.reader, custody=self.custody,
                    resolution_request=self.request,
                    original_operation_id='operation-one', now=NOW,
                    _client_factory=factory)
        self.assertTrue(self.clients[0].closed)

    async def test_cancellation_joins_the_original_client_close(self):
        self.enroll_secrets()

        def factory(**options):
            self.factory_options = options
            client = DelayedCloseClient(self.admin)
            self.clients.append(client)
            return client

        with patch('native_security.nats_credentials.time.time',
                   return_value=NOW.timestamp()):
            operation = asyncio.create_task(provision_integration_effect(
                self.selection, authority=self.reader, custody=self.custody,
                resolution_request=self.request,
                original_operation_id='operation-one', now=NOW,
                _client_factory=factory))
            while not self.clients:
                await asyncio.sleep(0)
            await self.clients[0].close_started.wait()
            operation.cancel()
            await asyncio.sleep(0)
            self.assertFalse(operation.done())
            self.clients[0].close_released.set()
            with self.assertRaises(asyncio.CancelledError):
                await operation
            self.assertTrue(self.clients[0].closed)
            inventory = self.selection.integration_effect_inventory()
            route = inventory.current_route()
            self.assertEqual(route.generation, 1)

    async def test_revocation_before_credential_issue_leaves_no_route(self):
        self.enroll_secrets()
        revoked = copy.deepcopy(self.account_record)
        revoked['state']['applicationAccounts'][0]['status'] = 'revoked'
        changed = AuthoritySnapshot(canonical_bytes(revoked), 24)
        self.reader.current = AsyncMock(
            side_effect=[self.snapshot] * 6 + [changed])
        with self.assertRaisesRegex(ContractError,
                '^integration_provisioning_credential_invalid$'):
            await self.call()
        self.assertEqual(len(self.clients), 1)
        self.assertTrue(self.clients[0].closed)
        self.assertEqual(len(list(self.roots['inventory'].glob('effect-*.json'))), 1)
        self.assertEqual(list(self.roots['inventory'].glob('route-*.json')), [])

    async def test_selection_account_mismatch_refuses_private_resolution(self):
        self.enroll_secrets()
        value = self.selection.policy
        value['integration']['credentials']['accountPublicKey'] = (
            nkeys.from_seed(nkeys.encode_seed(bytes([9]) * 32,
                nkeys.PREFIX_BYTE_ACCOUNT)).public_key.decode())
        mismatched = type(self.selection)(canonical_bytes(value))
        with patch.object(self.custody, 'resolve',
                          side_effect=AssertionError('private secret read')):
            with self.assertRaisesRegex(ContractError,
                    '^integration_operator_account_selection_mismatch$'):
                with patch('native_security.nats_credentials.time.time',
                           return_value=NOW.timestamp()):
                    await provision_integration_effect(mismatched,
                        authority=self.reader, custody=self.custody,
                        resolution_request=self.request,
                        original_operation_id='operation-one', now=NOW,
                        _client_factory=self.factory)

    async def test_production_calls_preserve_owner_post_read_clock_sampling(self):
        self.enroll_secrets()
        from identity.application_account import ApplicationAccountAuthority
        admitted = await ApplicationAccountAuthority(self.reader).resolve(
            self.request, now=NOW)
        admitted = replace(admitted,
            valid_until=datetime.now(timezone.utc) + timedelta(minutes=5))
        account_owner = AsyncMock()
        account_owner.resolve = AsyncMock(return_value=admitted)
        private = [PrivateSecret(self.credential()), PrivateSecret(self.account_seed),
                   PrivateSecret(self.account_seed)]
        current = datetime.now(timezone.utc).timestamp()
        with (patch('integration_owner.operator_provisioning.ApplicationAccountAuthority',
                    return_value=account_owner),
              patch.object(self.custody, 'resolve', AsyncMock(side_effect=private)) as resolve,
              patch('native_security.nats_credentials.time.time',
                    side_effect=[NOW.timestamp(), NOW.timestamp(),
                        current, current, current, current, current, current])):
            await provision_integration_effect(self.selection,
                authority=self.reader, custody=self.custody,
                resolution_request=self.request,
                original_operation_id='operation-one',
                _client_factory=self.factory)
        self.assertTrue(all(call.kwargs['now'] is None
                            for call in account_owner.resolve.await_args_list))
        self.assertTrue(all(call.kwargs['now'] is None
                            for call in resolve.await_args_list))


if __name__ == '__main__':
    unittest.main()
