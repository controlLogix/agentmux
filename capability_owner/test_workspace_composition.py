"""Selected startup uses actual identity/task owners and an existing checkout."""
import copy
import hashlib
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims
from dashboard import test_application_service_host as host_support
from application_service_host import ApplicationServiceHost, ApplicationServiceFailure
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref
from identity.test_task_selection import TaskSelectionTests
from identity.test_workspace_selection import add_workspace
from state_owner.backup_host import BackupHost
from state_owner.ledger import owner_subject
from state_owner.test_ledger import record
from hub.store import APP_ID, MIGRATIONS, Store


class WorkspaceCompositionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        TaskSelectionTests.setUp(self)
        payload = add_workspace(self)
        self.payloads.append(payload)
        task = self.value['task']
        issuer = {'ref':task['issuer']['issuerRef'], 'identityRef':ref('task-service'),
            'status':'active', 'instanceId':'task-instance', 'publicKey':task['issuer']['publicKey'],
            'issuedAt':self.issuer_start, 'expiresAt':self.issuer_end}
        proof = {'purpose':'agentmux-enrollment-possession-v1', 'profileId':'profile-one',
            'authorityId':'authority-one', 'credential':issuer}
        selected = ApplicationServiceSelection(canonical_bytes(self.value))
        self.payloads.append({'authorityId':'authority-one', 'identity':{
            'ref':ref('task-service'), 'kind':'service', 'status':'active',
            'principalId':'task-service', 'externalIdentity':None},
            'issuers':[{'record':issuer,'proof':sign_claims(proof,selected.load_signing_seed('task'))}],
            'transports':[]})
        host_support.HostComposition.prepare_services(self)
        pin = self.value['workspace']
        self.checkout = Path(pin['checkoutPath'])
        for args in (('init','-q'),('remote','add','origin','https://example.invalid/workspace.git')):
            subprocess.run(['/usr/bin/git','-C',str(self.checkout),*args],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        (self.checkout/'file').write_bytes(b'workspace from selected startup')
        database = Path(pin['source']['database']['path'])
        store = Store(str(database))
        store.repo_add('falcon', paths=[str(self.checkout)])
        store.db.close()
        database.chmod(0o600)
        raw = b'[federation]\npeer="nick"\n[repos.falcon]\nremote="example.invalid/workspace"\n'
        policy = Path(pin['source']['policy']['path'])
        policy.write_bytes(raw)
        policy.chmod(0o600)
        pin['source']['database'].update(applicationId=APP_ID,userVersion=len(MIGRATIONS))
        pin['source']['policy']['sha256']='sha256:'+hashlib.sha256(raw).hexdigest()
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        selected = self.value['task']
        backup = selected['backup']
        host = BackupHost(*(backup[key] for key in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'],binding=self.selection.binding('task'),
            stream_identity=self.selection.stream_identity('task'))
        host.enroll_key(backup['keyId'])
        original = record('workspace-task')
        original.update(effects=[],artifacts=[],state={'taskId':'task-one','status':'ready',
            'assignmentEpoch':0,'reservation':None},repository={'repositoryId':pin['repository']['repositoryId'],
                'revision':'preserved-revision','treeDigest':'sha256:'+'1'*64})
        original['operation']['scope']=copy.deepcopy(selected['ledger']['scope'])
        self.original = canonical_bytes(original)
        self.clients[2].js.messages=[SimpleNamespace(subject=owner_subject(self.selection.binding('task')),
            seq=1,data=self.original)]
        self.clients[2].max_payload=1_048_576
        workspace_connection=host_support.Client(self.clients[2].js)
        workspace_connection.max_payload=98304
        self.clients.append(workspace_connection)

    async def asyncSetUp(self):
        self.host=ApplicationServiceHost(self.selection,browser_port=0)
        self.addAsyncCleanup(self.host.close)

    async def test_selected_startup_borrows_original_task_and_joins_before_release(self):
        with patch('application_service_host.new_client',side_effect=self.clients) as create:
            try:
                await self.host.start()
            except ApplicationServiceFailure:
                raise self.host._startup.exception()
        self.assertEqual(create.call_count,4)
        self.host.check_health()
        workspace=self.host._workspace
        self.assertIs(workspace._task,self.host._task)
        resource=next(iter(workspace._service._receiver._resources.values()))
        self.assertIs(resource.ledger,self.host._task.ledger)
        await resource.workspace.check_current()
        self.assertEqual(resource.workspace.read('file',repository_id=self.value['workspace']['repository']['repositoryId']),
            b'workspace from selected startup')
        self.assertEqual(self.clients[2].js.messages[0].data,self.original)
        self.assertEqual(len(self.clients[2].js.messages),1)
        self.assertEqual(self.clients[3].options['inbox_prefix'],
            self.value['workspace']['receiver']['credentials']['replyPrefix'])
        await self.host.close()
        self.assertIsNone(workspace._checkout.root._fd)
        self.assertTrue(workspace._closing.done())
        self.assertTrue(self.host._task._closed)

    async def test_selected_missing_checkout_refuses_and_closes_provisional_owners(self):
        self.checkout.rename(self.checkout.with_name('unavailable-checkout'))
        with patch('application_service_host.new_client',side_effect=self.clients), self.assertRaises(ApplicationServiceFailure):
            await self.host.start()
        await self.host.close()
        self.assertTrue(self.host._task._closed)
        self.assertFalse(any(client.is_connected for client in self.clients))
