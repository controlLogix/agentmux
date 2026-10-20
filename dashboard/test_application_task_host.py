"""Optional task activation and retained cleanup through the actual host."""
import asyncio
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from identity.test_authority import ref
from identity.transitions import transition
from native_security.nats_credentials import service_policy
from native_security.test_nats_service_credentials import signed_service
from state_owner.backup_host import BackupHost
from state_owner.ledger import owner_subject
from state_owner.test_ledger import record
import test_application_service_host as support


class TaskComposition(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = support.HostComposition.asyncSetUp

    def setUp(self):
        support.HostComposition.setUp(self)
        directory = self.root / 'task'
        directory.mkdir(mode=0o700)
        selected = copy.deepcopy(self.value['identity'])
        payload, receipt = provision_application_service_issuer(directory / 'issuer.key',
            service_id='task-owner', profile_id='profile-one', authority_id='authority-one',
            instance_id='task-instance', identity={'ref': ref('task-service'), 'kind': 'service',
                'status': 'active', 'principalId': 'task-service', 'externalIdentity': None},
            issuer_ref=ref('task-issuer'), issued_at=self.issuer_start, expires_at=self.issuer_end)
        selected['issuer'] = {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
            'issuerRef': ref('task-issuer'), 'publicKey': payload['issuers'][0]['record']['publicKey']}
        selected['ledger'].update(entityId='task-one', stream='TASK')
        selected['ledger']['history']['path'] = str(directory / 'history.sqlite')
        selected['ledger']['checkpoint'] = {'path': str(directory / 'checkpoint'), 'commitRef': ref('task-checkpoint')}
        selected['backup']['destinationId'] = 'task-backup'
        for name in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'):
            path = directory / name
            path.mkdir(mode=0o700)
            selected['backup'][name] = str(path)
        selected.update(serviceIdentityRef=ref('task-service'), serviceInstanceId='task-instance',
            requesterReplyPrefix='_INBOX.task_requester_000001')
        selected['credentials']['replyPrefix'] = '_INBOX.task_service_00000001'
        self.value['task'] = selected
        options = dict(role='task', hub_id='hub-one', entity_id='task-one',
            scope=selected['ledger']['scope'], stream='TASK', reply_prefix=selected['credentials']['replyPrefix'],
            jetstream_domain=selected['connection']['jetstreamDomain'])
        raw, account, user = signed_service(options)
        path = directory / 'user.creds'
        path.write_bytes(raw)
        path.chmod(0o600)
        selected['credentials'].update(path=str(path), sha256='sha256:' + hashlib.sha256(raw).hexdigest(),
            accountPublicKey=account, userPublicKey=user)
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        backup = selected['backup']
        custody = BackupHost(*(backup[name] for name in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self.selection.binding('task'),
            stream_identity=self.selection.stream_identity('task'))
        custody.enroll_key(backup['keyId'])
        js = support.JetStream(self.selection.retention('task'))
        subject = owner_subject(self.selection.binding('task'))
        js.config = self.selection.retention('task').stream_config(stream='TASK', subject=subject)
        task = record('imported-task')
        task['operation']['scope'] = selected['ledger']['scope']
        task.update(effects=[], state={'taskId': 'task-one', 'status': 'ready', 'assignmentEpoch': 0,
            'reservation': None, 'originHubId': 'hub-one', 'taskInputRef': ref('task-input'), 'flags': {}})
        js.messages = [SimpleNamespace(subject=subject, seq=1, data=canonical_bytes(task))]
        client = support.Client(js)
        client.max_payload = 1024 * 1024
        self.clients.append(client)
        authority = strict_loads(self.clients[0].js.messages[0].data)
        authority['state'] = transition(authority['state'], 'identity-enroll', payload, hub_id='hub-one')
        self.clients[0].js.messages[0].data = canonical_bytes(authority)

    async def start_host(self):
        with patch('application_service_host.new_client', side_effect=self.clients):
            await self.host.start()

    async def test_selected_task_uses_shared_identity_and_selected_custody(self):
        await self.start_host()
        task = self.host._task
        self.assertIn(task, self.host._services)
        self.assertIs(task.owner._authority, self.host._identity.reader)
        self.assertIs(task.service.ingress, self.host._identity.ingress)
        self.assertEqual(task.subject, service_policy(**self.selection.service_policy_inputs('task')).command_subject)
        self.assertEqual(self.clients[2].js.selected_domain, 'enrolled-domain')
        self.assertEqual(self.clients[2].options['inbox_prefix'], self.value['task']['credentials']['replyPrefix'])
        self.assertEqual(task._backup._host.latest().receipt.cursor, 1)
        self.host.check_health()
        task._closed = True
        with self.assertRaisesRegex(ContractError, '^task_host_unavailable$'):
            self.host.check_health()
        await self.host.close()
        self.assertTrue(task.done.is_set() and task.service.done.is_set())
        self.assertTrue(all(history._closed for history in self.host._histories))
        self.assertTrue(all(not client.is_connected for client in self.clients))

    async def test_aggregate_close_joins_original_task_close_before_borrowed_resources(self):
        await self.start_host()
        task = self.host._task
        entered, release = asyncio.Event(), asyncio.Event()
        original = task.service.close
        async def close(*, timeout=3):
            entered.set()
            await release.wait()
            await original(timeout=timeout)
        with patch.object(task.service, 'close', side_effect=close):
            with self.assertRaisesRegex(ContractError, '^task_host_cleanup_incomplete$'):
                await task.close(timeout=.01)
            await entered.wait()
            retained = task._closing
            aggregate = asyncio.create_task(self.host.close())
            try:
                await asyncio.sleep(.01)
                self.assertFalse(aggregate.done())
                self.assertIs(task._closing, retained)
                self.assertTrue(all(client.is_connected for client in self.clients))
                self.assertTrue(all(not history._closed for history in self.host._histories))
            finally:
                release.set()
                await aggregate
        self.assertTrue(retained.done() and task.done.is_set())

    async def test_startup_cancellation_keeps_original_task_subscription(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.clients[2].subscribe
        async def subscribe(subject, **options):
            subscription = await original(subject, **options)
            entered.set()
            await release.wait()
            return subscription
        self.clients[2].subscribe = subscribe
        with patch('application_service_host.new_client', side_effect=self.clients):
            startup = asyncio.create_task(self.host.start())
            await asyncio.wait_for(entered.wait(), 3)
            task = self.host._task
            allocation = task.service._subscribe_task
            closing = asyncio.create_task(self.host.close())
            try:
                await asyncio.sleep(.01)
                self.assertFalse(closing.done() or allocation.done())
                self.assertTrue(all(not history._closed for history in self.host._histories))
            finally:
                release.set()
                results = await asyncio.gather(startup, closing, return_exceptions=True)
        self.assertIsInstance(results[0], support.ApplicationServiceFailure)
        self.assertIsNone(results[1])
        self.assertIs(task.service._subscribe_task, allocation)
        self.assertFalse(allocation.cancelled())
        self.assertTrue(task.done.is_set())

    async def test_missing_task_backup_key_prevents_ready(self):
        backup = self.value['task']['backup']
        (Path(backup['keyDirectory']) / ('key-' + backup['keyId'] + '.key')).unlink()
        with self.assertRaises(support.ApplicationServiceFailure):
            await self.start_host()
        self.assertFalse(self.host._ready)
        self.assertIsNone(self.host._task)
        self.assertFalse(self.clients[2].is_connected)
        await self.host.close()

    async def test_failed_task_close_retains_identity_until_same_owner_retry(self):
        await self.start_host()
        task = self.host._task
        original = task.service.close
        attempts = 0
        async def close(*, timeout=3):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ContractError('task_service_cleanup_incomplete')
            await original(timeout=timeout)
        with patch.object(task.service, 'close', side_effect=close), patch.object(
                self.host._identity, 'close', wraps=self.host._identity.close) as identity_close:
            with self.assertRaises(support.ApplicationServiceFailure):
                await self.host.close()
            identity_close.assert_not_called()
            self.assertFalse(task.done.is_set())
            self.assertTrue(all(client.is_connected for client in self.clients))
            self.assertTrue(all(not history._closed for history in self.host._histories))
            await self.host.close()
            identity_close.assert_awaited_once()
        self.assertIs(task, self.host._task)
        self.assertTrue(task.done.is_set())
