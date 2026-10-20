"""Selected task artifact custody in the actual application host composition."""
import base64
import copy
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from agentmux_contracts import canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref
from native_security.test_nats_service_credentials import signed_service
from state_owner.backup import restore_backup
import test_application_task_host as support


class TaskArtifactComposition(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = support.TaskComposition.asyncSetUp
    start_host = support.TaskComposition.start_host

    def setUp(self):
        support.TaskComposition.setUp(self)
        selected = self.value['task']
        selected['artifacts'] = {'bucket':'TASK_EVIDENCE','storeRef':ref('task-artifacts'),'maxBytes':1024,
            'reader':{'transportRef':ref('artifact-reader'),'grantRef':ref('artifact-grant'),'approvalsByOperation':{}}}
        options = ApplicationServiceSelection(canonical_bytes(self.value)).service_policy_inputs('task')
        raw, account, user = signed_service(options)
        from pathlib import Path
        Path(selected['credentials']['path']).write_bytes(raw)
        selected['credentials'].update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),
            accountPublicKey=account,userPublicKey=user)
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))
        self.data = b'Exact selected task artifact'
        self.reference = {'artifactId':'fixture-artifact','version':'fixture-version','ownerHubId':'hub-one',
            'storeRef':ref('task-artifacts'),'digest':'sha256:'+hashlib.sha256(self.data).hexdigest(),
            'bytes':len(self.data),'mediaType':'text/plain'}
        client = self.clients[2]
        js = client.js
        original_get = js.get_msg
        async def get_msg(stream, **arguments):
            if stream == 'OBJ_TASK_EVIDENCE':
                assert arguments == {'seq':1,'subject':'$O.TASK_EVIDENCE.C.ABC123','next':True,'direct':False}
                return SimpleNamespace(data=self.data,seq=1,subject=arguments['subject'])
            return await original_get(stream,**arguments)
        js.get_msg = get_msg
        info = SimpleNamespace(name='fixture-artifact.fixture-version',bucket='TASK_EVIDENCE',deleted=False,
            is_link=lambda:False,size=len(self.data),chunks=1,nuid='ABC123',
            digest='SHA-256='+base64.urlsafe_b64encode(hashlib.sha256(self.data).digest()).decode())
        self.store = SimpleNamespace(_name='TASK_EVIDENCE',_js=js,get_info=AsyncMock(return_value=info))
        async def object_store(bucket):
            assert bucket == 'TASK_EVIDENCE'
            return self.store
        js.object_store = object_store
        def jetstream(**options):
            js._nc = client
            js.selected_domain = options.get('domain')
            js._prefix = '$JS.API' if js.selected_domain is None else '$JS.'+js.selected_domain+'.API'
            return js
        client.jetstream = jetstream
        task = strict_loads(js.messages[0].data)
        task['artifacts'] = [self.reference]
        js.messages[0].data = canonical_bytes(task)
        authority = strict_loads(self.clients[0].js.messages[0].data)
        state = authority['state']
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('artifact-reader'),identityRef=ref('task-service'),
            issuerRef=self.value['identity']['issuer']['issuerRef'],publicKey=selected['issuer']['publicKey'],
            issuedAt=self.issuer_start,expiresAt=self.issuer_end)
        state['transports'].append(transport)
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('artifact-member'),identityRef=ref('task-service'),scope=selected['ledger']['scope'])
        state['memberships'].append(member)
        self.grant = copy.deepcopy(state['grants'][0])
        self.grant.update(ref=ref('artifact-grant'),callerRef=ref('task-service'),actorRef=ref('task-service'),
            scope=selected['ledger']['scope'],contractId='task-artifact-backup-read',resourceId='task-one',
            delegationRef=None,definitionTarget=None,decision='allowed',issuedAt=self.issuer_start,expiresAt=self.issuer_end)
        state['grants'].append(self.grant)
        self.authority = authority
        self.clients[0].js.messages[0].data = canonical_bytes(authority)

    async def test_selected_artifacts_use_shared_identity_and_actual_backup_restore(self):
        await self.start_host()
        task = self.host._task
        self.assertIs(task._artifact_custody._service.ingress,self.host._identity.ingress)
        self.assertIs(task.owner._authority,self.host._identity.reader)
        self.assertIs(task._artifact_custody._artifacts._store,self.store)
        self.assertEqual(task._artifact_custody._artifacts._js._prefix,'$JS.enrolled-domain.API')
        backup = task._backup._host
        entry = backup.latest()
        with restore_backup(backup.backup_directory,entry.receipt.manifest_name,expected_digest=entry.receipt.digest,
                key=backup.load_key(entry.key_id),binding=self.selection.binding('task'),
                stream_identity=self.selection.stream_identity('task'),history_path=self.root/'restored-task.sqlite') as restored:
            self.assertTrue(restored.reconciliation_required)
            self.assertEqual(restored.retrieve(self.reference),self.data)
        self.host.check_health()
        await self.host.close()
        self.assertTrue(task.done.is_set())
        self.assertTrue(all(history._closed for history in self.host._histories))

    async def test_missing_current_maintenance_grant_never_reads_object_or_reports_ready(self):
        self.grant['status'] = 'revoked'
        self.clients[0].js.messages[0].data = canonical_bytes(self.authority)
        from application_service_host import ApplicationServiceFailure
        with self.assertRaises(ApplicationServiceFailure):
            await self.start_host()
        self.assertFalse(self.host._ready)
        self.store.get_info.assert_not_called()
        self.assertIsNone(self.host._task._backup._host.latest())
        await self.host.close()
        self.assertTrue(self.host._task.done.is_set())
