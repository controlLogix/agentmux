"""Offline checks for the explicit integration resource owner."""
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes
from nats.js.api import StreamState
from nats.js.errors import NotFoundError
from native_security.test_nats_credentials import credential
from native_security.test_nats_service_credentials import signed_service
from state_owner.backup_host import BackupHost
from state_owner.ledger import OwnerBinding, StreamIdentity
from state_owner.retention import Retention
from identity.test_authority import ref
from .intent import effect_id
from .provisioning import IntegrationEffectProvisioner


class FakeAdmin:
    def __init__(self, created):
        self.created = created
        self.streams = {}

    async def add_stream(self, config):
        if config.name in self.streams:
            raise AssertionError('duplicate stream creation')
        self.streams[config.name] = config
        return await self.stream_info(config.name)

    async def stream_info(self, name):
        if name not in self.streams:
            raise NotFoundError()
        return SimpleNamespace(config=self.streams[name], created=self.created,
            state=StreamState(messages=0, bytes=0, first_seq=0, last_seq=0,
                              num_deleted=0, consumer_count=0))


class ProvisioningTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='amx-integration-provision-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None}
        self.retention = Retention(2_097_152, 262_144)
        self.created = datetime(2026, 10, 17, tzinfo=timezone.utc)
        self.admin = FakeAdmin(self.created)
        self.issued = []
        # The backup key is enrolled by its existing custody owner, not here.
        keys = self.directory('keys')
        (keys / 'key-backup-key.key').write_bytes(os.urandom(32))
        (keys / 'key-backup-key.key').chmod(0o600)
        _, self.account, _ = credential()

    def directory(self, name):
        path = self.root / name
        path.mkdir(mode=0o700)
        return path

    async def issuer(self, inputs):
        self.issued.append(inputs)
        return signed_service(inputs)[0]

    def provisioner(self, issuer=None):
        roots = {}
        for name in ('resources', 'inventory', 'credentials'):
            path = self.root / name
            if not path.exists():
                path.mkdir(mode=0o700)
            roots[name] = path
        return IntegrationEffectProvisioner(self.admin, hub_id='hub-one',
            scope=self.scope, base_stream='INTEGRATION',
            artifact_bucket='INTEGRATION_ARTIFACTS',
            reply_prefix='_INBOX.integration_router_0001',
            jetstream_domain='LOCAL', account_public_key=self.account,
            retention=self.retention, resource_directory=roots['resources'],
            max_history_records=321, max_history_bytes=8_388_608,
            inventory_directory=roots['inventory'],
            credential_directory=roots['credentials'],
            backup_key_directory=self.root / 'keys', backup_key_id='backup-key',
            backup_destination_id='integration-backup',
            commit_ref=ref('integration-checkpoint'),
            credential_issuer=issuer or self.issuer)

    async def test_two_operations_get_exact_resources_and_complete_route_generations(self):
        owner = self.provisioner()
        first = await owner.provision('operation-one')
        first_id = effect_id(self.scope, 'operation-one')
        self.assertEqual(first.effect_id, first_id)
        self.assertEqual(first.binding, OwnerBinding('hub-one', 'integrations', first_id,
            'effect', canonical_bytes(self.scope)))
        self.assertEqual(first.stream_identity, StreamIdentity(self.created, 0))
        self.assertEqual(first.history.max_records, 321)
        self.assertEqual(first.history.max_bytes, 8_388_608)
        self.assertEqual(first.checkpoint._max_records, 321)
        self.assertEqual(first.checkpoint._max_bytes, 8_388_608)
        self.assertEqual(first.additional_streams, (first.stream,))
        first.history.close()

        second = await owner.provision('operation-two')
        self.assertEqual(set(second.additional_streams), set(self.admin.streams))
        self.assertEqual(len(self.issued), 2)
        self.assertEqual(self.issued[0]['additional_streams'], (first.stream,))
        self.assertEqual(self.issued[1]['additional_streams'],
                         tuple(sorted(self.admin.streams)))
        self.assertNotIn('grant', repr(self.issued))
        self.assertTrue(Path(second.router_credential_path).is_file())
        second.history.close()

        # Reopening an old effect uses the latest complete route and does not
        # mint another credential or recreate its stream.
        reopened = await owner.provision('operation-one')
        self.assertEqual(reopened.additional_streams,
                         tuple(sorted(self.admin.streams)))
        self.assertEqual(len(self.issued), 2)
        reopened.backup.load_key('backup-key')
        reopened.history.close()

    async def test_credential_failure_leaves_resumable_exact_enrollment(self):
        calls = 0
        async def fail_once(inputs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return b'not a credential'
            return signed_service(inputs)[0]

        owner = self.provisioner(fail_once)
        with self.assertRaisesRegex(ContractError,
                                    '^integration_provisioning_credential_invalid$'):
            await owner.provision('operation-one')
        self.assertEqual(len(self.admin.streams), 1)
        self.assertEqual(len(list((self.root / 'inventory').glob('effect-*.json'))), 1)
        self.assertEqual(list((self.root / 'inventory').glob('route-*.json')), [])

        resumed = await owner.provision('operation-one')
        self.assertEqual(len(self.admin.streams), 1)
        self.assertEqual(len(list((self.root / 'inventory').glob('route-*.json'))), 1)
        resumed.history.close()

    async def test_missing_pre_enrolled_backup_key_fails_before_effect_inventory(self):
        os.unlink(self.root / 'keys' / 'key-backup-key.key')
        owner = self.provisioner()
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            await owner.provision('operation-one')
        self.assertEqual(list((self.root / 'inventory').glob('effect-*.json')), [])
        self.assertEqual(self.issued, [])

    async def test_route_publication_failure_reuses_private_credential_on_retry(self):
        from integration_owner import provisioning
        owner = self.provisioner()
        publish = provisioning._publish_private
        failed = False
        def fail_route_once(path, value, **kwargs):
            nonlocal failed
            if Path(path).name.startswith('route-') and not failed:
                failed = True
                raise ContractError('synthetic_route_publication_uncertain')
            return publish(path, value, **kwargs)
        with patch.object(provisioning, '_publish_private', side_effect=fail_route_once):
            with self.assertRaisesRegex(ContractError,
                                        '^synthetic_route_publication_uncertain$'):
                await owner.provision('operation-one')
        self.assertEqual(len(self.issued), 1)
        result = await owner.provision('operation-one')
        self.assertEqual(len(self.issued), 1)
        result.history.close()

    async def test_route_generation_can_admit_multiple_recovered_effects(self):
        failed = False
        async def issuer(inputs):
            nonlocal failed
            if len(inputs['additional_streams']) == 2 and not failed:
                failed = True
                return b'invalid credential'
            return signed_service(inputs)[0]
        owner = self.provisioner(issuer)
        first = await owner.provision('operation-one')
        first.history.close()
        with self.assertRaisesRegex(ContractError,
                                    '^integration_provisioning_credential_invalid$'):
            await owner.provision('operation-two')
        third = await owner.provision('operation-three')
        self.assertEqual(len(third.additional_streams), 3)
        third.history.close()
        reopened = await owner.provision('operation-one')
        self.assertEqual(len(reopened.additional_streams), 3)
        reopened.history.close()

    async def test_expired_latest_route_rotates_without_rejecting_history(self):
        owner = self.provisioner()
        first = await owner.provision('operation-one')
        first.history.close()
        self.assertEqual(len(self.issued), 1)
        with patch('native_security.nats_credentials.time.time',
                   return_value=time.time() + 7200):
            rotated = await owner.provision('operation-one')
        self.assertEqual(len(self.issued), 2)
        self.assertEqual(rotated.additional_streams, (rotated.stream,))
        self.assertEqual(len(list((self.root / 'inventory').glob('route-*.json'))), 2)
        rotated.history.close()

