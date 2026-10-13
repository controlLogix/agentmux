"""Real single-node JetStream qualification using isolated Python/TypeScript clients."""
import asyncio
import copy
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import time

import nats
from nats.js.api import StreamConfig, StorageType

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CACHE = Path.home() / '.cache/agentmux-governance'
SERVER = Path(os.environ.get('AGENTMUX_STORAGE_SERVER', str(CACHE / 'tools/nats-server')))
TS = Path(os.environ.get('AGENTMUX_STORAGE_TS_CLIENT', str(CACHE / 'typescript-storage/dist/client.js')))
NODE = os.environ.get('AGENTMUX_STORAGE_NODE', 'node')
REPORT = Path(os.environ.get('AGENTMUX_EVIDENCE_DIR', str(ROOT / 'docs/planning/2026-10-09/delivery/evidence/P01'))) / 'storage-result.json'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fixture_atomic_capability(resources):
    """Bounded provider-claim admission fixture, not a production plugin registry."""
    return (bool(resources) and all(set(r) == {'kind', 'stream'} and r['kind'] == 'stream-record'
                                    and isinstance(r['stream'], str) and bool(r['stream']) for r in resources)
            and len({r['stream'] for r in resources}) == 1)


def hashes():
    files = [p for p in HERE.rglob('*') if p.is_file() and p.suffix in ('.py', '.ts', '.json', '.md') and 'node_modules' not in p.parts and '__pycache__' not in p.parts]
    files += [ROOT / 'hub/requirements.lock', ROOT / 'tests/contracts/fake_execution.py']
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def record(operation, version, previous=0):
    ref = {'id': 'fixture-ref', 'ownerHubId': 'hub-fixture', 'revision': 1}
    digest = 'sha256:' + hashlib.sha256(json.dumps({'operation': operation}, separators=(',', ':')).encode()).hexdigest()
    return {'schemaVersion': '1.0.0', 'recordId': 'record-' + operation, 'entityId': 'task-one',
            'entityKind': 'task', 'ownerHubId': 'hub-fixture', 'ownerDomain': 'task',
            'entityVersion': version, 'previousRevision': previous,
            'operation': {'schemaVersion': '1.0.0', 'operationId': operation, 'payloadDigest': digest,
                          'expectedVersion': version - 1,
                          'caller': {'principalId': 'user-fixture', 'kind': 'human', 'authenticatedIdentityRef': ref},
                          'effectiveActorRef': ref, 'scope': {'organizationId': 'org-fixture', 'projectId': 'project-fixture', 'workspaceId': None},
                          'taskId': 'task-one', 'runId': None, 'attemptId': None, 'delegationRef': None,
                          'grantRef': ref, 'approvalRefs': [], 'traceId': 'trace-' + operation,
                          'causationId': 'cause-' + operation, 'deadline': '2026-10-10T00:00:00Z', 'cancellationRef': ref},
            'recordedAt': '2026-10-09T12:00:00Z', 'outcome': 'committed',
            'state': {'status': 'reserved', 'executorHubId': 'hub-executor', 'reservationId': 'reservation-one'},
            'effects': [{'effectId': 'effect-' + operation, 'contractId': 'execute-fixture', 'payloadDigest': digest,
                         'grantRef': ref, 'recovery': 'idempotent-retry', 'payload': {'operation': operation}}],
            'artifacts': [], 'repository': None}


class Broker:
    def __init__(self, directory):
        self.directory = Path(directory)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.token = secrets.token_hex(32)
        self.url = f'nats://127.0.0.1:{self.port}'
        self.config = self.directory / 'server.conf'
        self.config.write_text(f'host: "127.0.0.1"\nport: {self.port}\nauthorization {{ token: "{self.token}" }}\njetstream {{ store_dir: "{self.directory / "store"}" }}\n')
        self.config.chmod(0o600)
        self.process = None
        self.log = None

    async def start(self):
        self.log = (self.directory / 'server.log').open('ab')
        self.process = subprocess.Popen([str(SERVER), '-c', str(self.config)], stdout=self.log, stderr=self.log)
        for _ in range(100):
            require(self.process.poll() is None, 'owned broker stopped before readiness')
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
                info = await asyncio.wait_for(reader.readline(), 1)
                writer.close()
                await writer.wait_closed()
                if info.startswith(b'INFO '):
                    return
            except (OSError, TimeoutError):
                pass
            await asyncio.sleep(.03)
        raise RuntimeError('owned broker readiness timeout')

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()

    async def connect(self):
        return await nats.connect(self.url, token=self.token, allow_reconnect=False, connect_timeout=2)

    async def client(self, language, request):
        command = [sys.executable, str(HERE / 'python_client.py')] if language == 'python' else [NODE, str(TS)]
        env = dict(os.environ, AMX_STORAGE_URL=self.url, AMX_STORAGE_TOKEN=self.token)
        child = await asyncio.create_subprocess_exec(*command, env=env, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(child.communicate(json.dumps(request).encode() + b'\n'), 12)
        except TimeoutError:
            child.kill()
            await child.wait()
            raise RuntimeError('storage client timeout') from None
        require(child.returncode == 0 and not stderr, 'storage client exited or wrote unexpected diagnostics')
        return json.loads(stdout)


async def main():
    initial_hashes = hashes()
    require(SERVER.is_file() and TS.is_file(), 'required broker or compiled TypeScript client missing; skips forbidden')
    build_root = TS.parent.parent
    source_root = HERE / 'typescript'
    build_names = ['package.json', 'package-lock.json', 'tsconfig.json']
    build_names += [p.relative_to(source_root).as_posix() for p in sorted((source_root / 'src').rglob('*.ts'))]
    build_sources = {}
    for name in build_names:
        cached = build_root / name
        require(cached.is_file() and cached.read_bytes() == (source_root / name).read_bytes(),
                'TypeScript cached build input does not match repository: ' + name)
        build_sources[name] = hashlib.sha256(cached.read_bytes()).hexdigest()
    initial_build = hashlib.sha256(TS.read_bytes()).hexdigest()
    server_version = subprocess.check_output([str(SERVER), '--version'], text=True).strip()
    require(server_version.endswith('2.15.0'), 'broker version is not pinned 2.15.0')
    require(importlib.metadata.version('nats-py') == '2.16.0', 'Python NATS version mismatch')
    cases = []
    started = time.monotonic()
    async def case(name, **details):
        cases.append({'id': name, 'passed': True, **details})

    with tempfile.TemporaryDirectory(prefix='agentmux-storage-') as temp:
        broker = Broker(temp)
        nc = None
        try:
            await broker.start()
            nc = await broker.connect()
            js = nc.jetstream(timeout=3)
            await js.add_stream(StreamConfig(name='LEDGER', subjects=['fixture.ledger.>'], storage=StorageType.FILE,
                                             num_replicas=1, duplicate_window=.2, allow_atomic=True))
            await js.add_stream(StreamConfig(name='OTHER', subjects=['fixture.other.>'], storage=StorageType.FILE,
                                             num_replicas=1, allow_atomic=True))
            subject = 'fixture.ledger.task-one'
            first = record('initial', 1)
            published = await broker.client('python', {'op': 'publish', 'subject': subject, 'record': first, 'expectedSequence': 0})
            require(published['ok'], 'initial complete record failed')
            baseline = published['result']['sequence']
            read = await broker.client('typescript', {'op': 'read', 'stream': 'LEDGER', 'subject': subject})
            require(read['ok'] and read['result']['record'] == first, 'cross-language complete record mismatch')
            await case('complete-state-provenance-effect-record', sequence=baseline)

            contenders = [record('python-contender', 2, baseline), record('ts-contender', 2, baseline)]
            outcomes = await asyncio.gather(*(broker.client(lang, {'op': 'publish', 'subject': subject, 'record': item,
                                                                     'expectedSequence': baseline})
                                              for lang, item in zip(('python', 'typescript'), contenders)))
            require(sum(o['ok'] for o in outcomes) == 1, 'conditional race admitted other than one transition')
            winner = contenders[next(i for i, outcome in enumerate(outcomes) if outcome['ok'])]
            winner_seq = next(o['result']['sequence'] for o in outcomes if o['ok'])
            for lang in ('python', 'typescript'):
                fresh = await broker.client(lang, {'op': 'read', 'stream': 'LEDGER', 'subject': subject})
                require(fresh['ok'] and fresh['result']['sequence'] == winner_seq and fresh['result']['record'] == winner,
                        'authoritative read did not expose confirmed winner')
            await case('conditional-two-language-race', winnerSequence=winner_seq,
                       loserApiCodes=[o.get('apiCode') for o in outcomes if not o['ok']])
            await case('authoritative-latest-read-both-clients', sequence=winner_seq)

            # FAIL-06: only the retained reservation can cause fixture execution.
            sys.path.insert(0, str(ROOT / 'tests/contracts'))
            from fake_execution import FakeProvider, FakeWorker, ResponsePlan
            provider = FakeProvider()
            worker = FakeWorker(provider)
            dispatched = {}

            async def dispatch_reserved(candidate):
                authority = await broker.client('python', {'op': 'read', 'stream': 'LEDGER', 'subject': subject})
                require(authority['ok'], 'fixture dispatch could not read owner authority')
                if authority['result']['record'] != candidate or authority['result']['sequence'] != winner_seq:
                    return 'denied'
                identity = candidate['operation']['operationId']
                if identity in dispatched:
                    return 'already_dispatched'
                worker.start(identity, candidate['effects'][0]['effectId'], ResponsePlan(output='one authorized result'))
                dispatched[identity] = candidate['operation']['payloadDigest']
                return 'dispatched'

            loser = next(c for c in contenders if c != winner)
            require(await dispatch_reserved(loser) == 'denied' and not provider.requests,
                    'losing reservation reached provider execution')
            require(await dispatch_reserved(winner) == 'dispatched', 'winning reservation did not dispatch')
            require(await dispatch_reserved(winner) == 'already_dispatched', 'duplicate winning request dispatched again')
            require(await dispatch_reserved(loser) == 'denied', 'loser became executable after winner dispatch')
            provider.advance(0)
            operation = winner['operation']['operationId']
            provider.deliver(operation)
            require(worker.snapshot(operation)['output'] == 'one authorized result'
                    and sum(row['kind'] == 'admitted' for row in provider.history) == 1
                    and sum(row['kind'] == 'completed' for row in provider.history) == 1,
                    'conditional winner did not produce exactly one fixture execution')
            await case('conditional-winner-only-dispatches-once', scenario='FAIL-06',
                       winnerOperation=operation, providerAdmissions=1, providerCompletions=1,
                       boundary='real owner reservation; in-memory dispatch deduplication only')

            lost = record('lost-ack', 3, winner_seq)
            # Send without a reply inbox: the write may commit, but the publisher cannot receive a PubAck.
            await nc.publish(subject, json.dumps(lost).encode(), headers={'Nats-Expected-Last-Subject-Sequence': str(winner_seq), 'Nats-Msg-Id': 'lost-ack'})
            await nc.flush()
            for _ in range(100):
                stored = await js.get_msg('LEDGER', subject=subject)
                if json.loads(stored.data)['operation']['operationId'] == 'lost-ack':
                    break
                await asyncio.sleep(.02)
            else:
                raise AssertionError('unacknowledged write was not committed')
            lost_seq = stored.seq
            later = record('later-operation', 4, lost_seq)
            ack = await js.publish(subject, json.dumps(later).encode(), headers={'Nats-Expected-Last-Subject-Sequence': str(lost_seq)})
            await nc.close()
            nc = None
            broker.stop()
            await asyncio.sleep(.3)  # Exceeds the deliberately short deduplication horizon.
            await broker.start()
            nc = await broker.connect()
            js = nc.jetstream(timeout=3)
            for lang in ('python', 'typescript'):
                replay = await broker.client(lang, {'op': 'reconcile', 'stream': 'LEDGER', 'subject': subject,
                                                     'operationId': 'lost-ack', 'payloadDigest': lost['operation']['payloadDigest']})
                require(replay['ok'] and replay['result']['record'] == lost and replay['result']['sequence'] == lost_seq,
                        'lost acknowledgment did not reconcile retained older operation')
                conflict = await broker.client(lang, {'op': 'reconcile', 'stream': 'LEDGER', 'subject': subject,
                                                       'operationId': 'lost-ack', 'payloadDigest': 'sha256:' + '0' * 64})
                require(not conflict['ok'] and conflict['error'] == 'operation_conflict', 'changed replay input was not rejected')
            require((await js.stream_info('LEDGER')).state.messages == 4, 'reconciliation created additional records')
            await case('lost-puback-reconciles-after-restart-and-dedup-expiry', recoveredSequence=lost_seq, laterSequence=ack.seq)
            await case('changed-digest-replay-rejected-both-clients')

            async def raw(subject, value, headers):
                reply = await nc.request(subject, json.dumps(value).encode(), headers=headers, timeout=3)
                return json.loads(reply.data) if reply.data else {"stagingHeaders": dict(reply.headers or {})}

            # Raw Python batch wire protocol: first-message response is staging, not durable commit.
            batch_subject = 'fixture.ledger.batch-one'
            opened = await raw(batch_subject, {'part': 1}, {'Nats-Batch-Id': 'batch-one', 'Nats-Batch-Sequence': '1', 'Nats-Expected-Last-Subject-Sequence': '0'})
            require('error' not in opened, 'atomic batch opening rejected')
            require((await js.stream_info('LEDGER')).state.messages == 4, 'partial batch leaked into stream')
            final = await raw(batch_subject, {'part': 2}, {'Nats-Batch-Id': 'batch-one', 'Nats-Batch-Sequence': '2', 'Nats-Batch-Commit': '1'})
            require('error' not in final and final.get('count') == 2, 'atomic commit did not confirm whole batch')
            require((await js.stream_info('LEDGER')).state.messages == 6, 'committed batch count mismatch')
            await case('python-atomic-batch-no-partial-before-commit', openingAck=opened, commitAck=final)

            before = (await js.stream_info('LEDGER')).state.messages
            await raw('fixture.ledger.gap', {'part': 1}, {'Nats-Batch-Id': 'gap-batch', 'Nats-Batch-Sequence': '1'})
            gap = await raw('fixture.ledger.gap', {'part': 3}, {'Nats-Batch-Id': 'gap-batch', 'Nats-Batch-Sequence': '3', 'Nats-Batch-Commit': '1'})
            require('error' in gap and (await js.stream_info('LEDGER')).state.messages == before, 'sequence gap partially committed')
            await case('atomic-gap-rejects-without-partial-records', apiCode=gap['error'].get('err_code'))

            # Stage but never commit, then restart: no staged record may become visible.
            await raw('fixture.ledger.abandoned', {'part': 1}, {'Nats-Batch-Id': 'abandoned', 'Nats-Batch-Sequence': '1'})
            await nc.close()
            nc = None
            broker.stop()
            await broker.start()
            nc = await broker.connect()
            js = nc.jetstream(timeout=3)
            require((await js.stream_info('LEDGER')).state.messages == before, 'uncommitted staged batch survived as partial data')
            await case('uncommitted-batch-remains-absent-after-restart')

            tsbatch = await broker.client('typescript', {'op': 'batch', 'subject': 'fixture.ledger.ts-batch',
                                                         'records': [{'part': 1}, {'part': 2}], 'expectedSequence': 0})
            require(tsbatch['ok'], 'native TypeScript atomic batch failed')
            require((await js.stream_info('LEDGER')).state.messages == before + 2, 'TypeScript batch count mismatch')
            await case('typescript-native-atomic-batch', ack=tsbatch['result'])

            # A conditional batch must fail when its initial expectation is already stale.
            stale = await raw(batch_subject, {'part': 3}, {'Nats-Batch-Id': 'stale-batch', 'Nats-Batch-Sequence': '1',
                                                         'Nats-Expected-Last-Subject-Sequence': '0'})
            if 'error' not in stale:
                stale = await raw(batch_subject, {'part': 4}, {'Nats-Batch-Id': 'stale-batch', 'Nats-Batch-Sequence': '2', 'Nats-Batch-Commit': '1'})
            require('error' in stale, 'stale conditional batch unexpectedly committed')
            require((await js.stream_info('LEDGER')).state.messages == before + 2, 'stale batch left partial records')
            await case('atomic-batch-stale-subject-condition-rejected', apiCode=stale['error'].get('err_code'))

            # A competing commit after staging must invalidate the original condition.
            interleaved_subject = 'fixture.ledger.interleaved'
            await raw(interleaved_subject, {'part': 1}, {'Nats-Batch-Id': 'interleaved', 'Nats-Batch-Sequence': '1',
                                                         'Nats-Expected-Last-Subject-Sequence': '0'})
            ordinary = await broker.client('typescript', {'op': 'publish', 'subject': interleaved_subject,
                                                           'record': {'ordinary': True}, 'expectedSequence': 0})
            require(ordinary['ok'], 'ordinary competing commit failed')
            interrupted = await raw(interleaved_subject, {'part': 2}, {'Nats-Batch-Id': 'interleaved', 'Nats-Batch-Sequence': '2', 'Nats-Batch-Commit': '1'})
            require('error' in interrupted and (await js.stream_info('LEDGER')).state.messages == before + 3,
                    'batch did not recheck condition at commit')
            fresh = await broker.client('python', {'op': 'read', 'stream': 'LEDGER', 'subject': interleaved_subject})
            require(fresh['ok'] and fresh['result']['record'] == {'ordinary': True}, 'failed batch overwrote competing state')
            await case('atomic-condition-rechecked-after-interleaved-commit', apiCode=interrupted['error'].get('err_code'))

            ts_gap = await broker.client('typescript', {'op': 'batch', 'messages': [
                {'subject': 'fixture.ledger.ts-gap', 'record': {'part': 1}, 'headers': {'Nats-Batch-Id': 'ts-gap', 'Nats-Batch-Sequence': '1'}},
                {'subject': 'fixture.ledger.ts-gap', 'record': {'part': 3}, 'headers': {'Nats-Batch-Id': 'ts-gap', 'Nats-Batch-Sequence': '3', 'Nats-Batch-Commit': '1'}}]})
            require(not ts_gap['ok'] and ts_gap.get('apiCode') == 10176 and
                    (await js.stream_info('LEDGER')).state.messages == before + 3, 'TypeScript gap did not reject atomically')
            await case('typescript-raw-batch-gap-rejected', apiCode=ts_gap['apiCode'])

            # The same batch identity across two streams cannot commit the first stream's staging.
            total_before = (await js.stream_info('LEDGER')).state.messages
            await raw('fixture.ledger.cross', {'part': 1}, {'Nats-Batch-Id': 'cross-batch', 'Nats-Batch-Sequence': '1'})
            cross = await raw('fixture.other.cross', {'part': 2}, {'Nats-Batch-Id': 'cross-batch', 'Nats-Batch-Sequence': '2', 'Nats-Batch-Commit': '1'})
            require('error' in cross and (await js.stream_info('LEDGER')).state.messages == total_before and
                    (await js.stream_info('OTHER')).state.messages == 0, 'cross-stream batch was not rejected')
            await case('cross-stream-atomic-transaction-rejected', apiCode=cross['error'].get('err_code'))

            # FAIL-42: commit without a reply inbox, then recover the complete set from retained authority.
            lost_subject = 'fixture.ledger.lost-final-batch'
            lost_records = [record('batch-lost-first', 1), record('batch-lost-final', 2)]
            batch_before = (await js.stream_info('LEDGER')).state.messages
            await raw(lost_subject, lost_records[0], {'Nats-Batch-Id': 'lost-final', 'Nats-Batch-Sequence': '1',
                                                     'Nats-Expected-Last-Subject-Sequence': '0'})
            require((await js.stream_info('LEDGER')).state.messages == batch_before, 'lost-ack batch leaked staging')
            await nc.publish(lost_subject, json.dumps(lost_records[1]).encode(),
                             headers={'Nats-Batch-Id': 'lost-final', 'Nats-Batch-Sequence': '2', 'Nats-Batch-Commit': '1'})
            await nc.flush()
            for _ in range(100):
                if (await js.stream_info('LEDGER')).state.messages == batch_before + 2:
                    break
                await asyncio.sleep(.02)
            else:
                raise AssertionError('lost final batch acknowledgment did not leave a complete commit')
            await nc.close(); nc = None
            broker.stop()
            await asyncio.sleep(.3)
            await broker.start()
            nc = await broker.connect(); js = nc.jetstream(timeout=3)
            for language in ('python', 'typescript'):
                recovered = []
                for expected in lost_records:
                    answer = await broker.client(language, {'op': 'reconcile', 'stream': 'LEDGER', 'subject': lost_subject,
                        'operationId': expected['operation']['operationId'], 'payloadDigest': expected['operation']['payloadDigest']})
                    require(answer['ok'] and answer['result']['record'] == expected, 'atomic unknown outcome was not reconciled')
                    recovered.append(answer['result']['sequence'])
                require(recovered[1] == recovered[0] + 1, 'reconciled batch records were not contiguous')
            retry = await raw(lost_subject, lost_records[0], {'Nats-Batch-Id': 'lost-final-retry', 'Nats-Batch-Sequence': '1',
                                                            'Nats-Expected-Last-Subject-Sequence': '0'})
            if 'error' not in retry:
                retry = await raw(lost_subject, lost_records[1], {'Nats-Batch-Id': 'lost-final-retry', 'Nats-Batch-Sequence': '2', 'Nats-Batch-Commit': '1'})
            require('error' in retry and (await js.stream_info('LEDGER')).state.messages == batch_before + 2,
                    'retry after unknown batch outcome created another transition')
            await case('lost-final-batch-ack-reconciles-after-restart-and-dedup-expiry', scenario='FAIL-42', records=2,
                       duplicateWindowSeconds=.2, waitSeconds=.3, retryApiCode=retry['error'].get('err_code'))

            # FAIL-43: KV exposes its source revision but never supplies owner authority.
            projection_subject = 'fixture.ledger.projection-owner'
            allowed = {'state': 'ready', 'policyRevision': 1}
            owner_ack = await js.publish(projection_subject, json.dumps(allowed).encode(),
                                        headers={'Nats-Expected-Last-Subject-Sequence': '0'})
            kv = await js.create_key_value(bucket='FIXTURE_VIEW')
            await kv.put('task', json.dumps({'sourceSequence': owner_ack.seq, 'owner': allowed}).encode())
            def admits(current, current_policy):
                return current['state'] == 'ready' and current['policyRevision'] == current_policy['revision'] and current_policy['allow']
            require(admits(allowed, {'revision': 1, 'allow': True}), 'fixture positive policy control failed')
            require(not admits(allowed, {'revision': 1, 'allow': False}), 'fixture policy denial was ignored')
            require(not admits(allowed, {'revision': 2, 'allow': True}), 'fixture stale policy revision was ignored')
            revoked = {'state': 'reserved', 'policyRevision': 2}
            committed = await js.publish(projection_subject, json.dumps(revoked).encode(),
                                        headers={'Nats-Expected-Last-Subject-Sequence': str(owner_ack.seq)})
            view = json.loads((await kv.get('task')).value)
            require(view['sourceSequence'] == owner_ack.seq and view['sourceSequence'] < committed.seq,
                    'projection fixture was not observably stale')
            stale_write = await broker.client('typescript', {'op': 'publish', 'subject': projection_subject,
                'record': {'state': 'accepted'}, 'expectedSequence': view['sourceSequence']})
            require(not stale_write['ok'], 'stale projection conditional write was admitted')
            total = (await js.stream_info('LEDGER')).state.messages
            for language in ('python', 'typescript'):
                authoritative = await broker.client(language, {'op': 'read', 'stream': 'LEDGER', 'subject': projection_subject})
                require(authoritative['ok'] and authoritative['result']['sequence'] == committed.seq,
                        'owner revalidation did not use current authoritative revision')
                require(not admits(authoritative['result']['record'], {'revision': 2, 'allow': False}),
                        'fresh revision bypassed revoked fixture policy')
            require((await js.stream_info('LEDGER')).state.messages == total, 'policy rejection wrote another owner transition')
            await case('stale-kv-projection-requires-owner-and-policy-revalidation', scenario='FAIL-43',
                       projectionSequence=view['sourceSequence'], ownerSequence=committed.seq, policyRevision=2)

            # FAIL-47: reject unsupported declarations before any adapter can perform a side effect.
            supported = [{'kind': 'stream-record', 'stream': 'LEDGER'}] * 2
            require(fixture_atomic_capability(supported), 'qualified same-stream claim rejected')
            rejected_kinds = []
            for unsupported in ({'kind': 'stream-record', 'stream': 'OTHER'}, {'kind': 'kv', 'bucket': 'FIXTURE_VIEW'},
                                {'kind': 'object-upload', 'bucket': 'ARTIFACTS'}, {'kind': 'external-tool', 'tool': 'fixture-tool'}):
                require(not fixture_atomic_capability([supported[0], unsupported]), 'unsupported atomicity claim admitted')
                rejected_kinds.append(unsupported['kind'])
            require((await js.stream_info('LEDGER')).state.messages == total, 'rejected capability changed the owner ledger')
            require(json.loads((await kv.get('task')).value) == view, 'rejected capability changed the projection')
            await case('fixture-capability-rejects-cross-stream-kv-object-tool-atomicity', scenario='FAIL-47',
                       rejectedResourceKinds=rejected_kinds, boundary='fixture admission only; no production plugin registry')

            # AMX-BASE-002: construct incoming state, attribution and claim intent
            # before one conditional publish. A construction failure cannot leak
            # unattributed or executable work into the authoritative ledger.
            async def receive_incoming(language, incoming_subject, operation, fail_at=None):
                complete = record(operation, 1)
                lookup = {'op': 'reconcile', 'stream': 'LEDGER', 'subject': incoming_subject,
                          'operationId': operation, 'payloadDigest': complete['operation']['payloadDigest']}
                retained = await broker.client(language, lookup)
                if retained['ok']:
                    return retained['result']
                require(retained.get('error') == 'not_found', 'incoming recovery did not fail closed')
                complete['entityId'] = operation
                complete['operation']['taskId'] = operation
                complete['state'] = {'status': 'blocked', 'taskId': operation}
                if fail_at == 'state':
                    raise RuntimeError('injected state construction failure')
                complete['state']['origin'] = {'hubId': 'hub-origin', 'nodeId': 'node-origin',
                                              'offerId': 'offer-' + operation}
                if fail_at == 'attribution':
                    raise RuntimeError('injected attribution construction failure')
                complete['effects'][0].update(contractId='work-claim',
                                              payload={'offerId': 'offer-' + operation,
                                                       'executorHubId': 'hub-executor'})
                complete['effects'][0]['payloadDigest'] = 'sha256:' + hashlib.sha256(
                    json.dumps(complete['effects'][0]['payload'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                if fail_at == 'claim':
                    raise RuntimeError('injected claim construction failure')
                published = await broker.client(language, {'op': 'publish', 'subject': incoming_subject,
                                                           'record': complete, 'expectedSequence': 0})
                require(published['ok'], 'incoming complete record failed')
                if fail_at == 'after-commit':
                    raise RuntimeError('injected caller crash after incoming commit')
                return {'record': complete, 'sequence': published['result']['sequence']}

            for language in ('python', 'typescript'):
                incoming_subject = 'fixture.ledger.incoming-' + language
                operation = 'incoming-' + language
                before = (await js.stream_info('LEDGER')).state.messages
                for fault in ('state', 'attribution', 'claim'):
                    try:
                        await receive_incoming(language, incoming_subject, operation, fault)
                    except RuntimeError as exc:
                        require(str(exc).startswith('injected '), 'unexpected incoming failure')
                    else:
                        raise AssertionError('incoming construction fault did not fire')
                    absent = await broker.client(language, {'op': 'read', 'stream': 'LEDGER',
                                                           'subject': incoming_subject})
                    require(not absent['ok'] and absent.get('error') == 'not_found',
                            'partial incoming state, attribution or claim became durable')
                    require((await js.stream_info('LEDGER')).state.messages == before,
                            'failed incoming creation changed ledger count')
                try:
                    await receive_incoming(language, incoming_subject, operation, 'after-commit')
                except RuntimeError as exc:
                    require(str(exc).startswith('injected '), 'unexpected post-commit failure')
                else:
                    raise AssertionError('post-commit fault did not fire')
                recovered = await receive_incoming(language, incoming_subject, operation)
                repeated = await receive_incoming(language, incoming_subject, operation)
                independent = await broker.client('typescript' if language == 'python' else 'python',
                                                  {'op': 'read', 'stream': 'LEDGER', 'subject': incoming_subject})
                require(recovered == repeated and independent['ok'] and
                        independent['result']['record'] == recovered['record'],
                        'incoming retry did not retain one exact complete record')
                complete = recovered['record']
                require(complete['entityId'] == complete['operation']['taskId'] == complete['state']['taskId'] == operation
                        and complete['state']['status'] == 'blocked'
                        and complete['state']['origin'] == {'hubId': 'hub-origin', 'nodeId': 'node-origin',
                                                          'offerId': 'offer-' + operation}
                        and len(complete['effects']) == 1 and complete['effects'][0]['contractId'] == 'work-claim'
                        and complete['effects'][0]['payload'] == {'offerId': 'offer-' + operation,
                                                                 'executorHubId': 'hub-executor'}
                        and complete['effects'][0]['payloadDigest'] == 'sha256:' + hashlib.sha256(
                            json.dumps(complete['effects'][0]['payload'], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                        'incoming commit lost exact task, blocked state, origin attribution or claim intent')
                require((await js.stream_info('LEDGER')).state.messages == before + 1,
                        'incoming retry duplicated record or claim intent')
                await case('incoming-creation-atomic-with-attribution-claim-' + language,
                           scenario='FAIL-08', baselineFinding='AMX-BASE-002',
                           injectedBoundaries=['state', 'attribution', 'claim', 'after-commit'],
                           recordsAdded=1, claimIntents=1,
                           boundary='fixture complete-record construction; no production authorization or dispatch')

            # Retention holes must never justify inventing a previously acknowledged operation.
            await js.delete_msg('LEDGER', 1)
            for lang in ('python', 'typescript'):
                missing = await broker.client(lang, {'op': 'reconcile', 'stream': 'LEDGER', 'subject': subject,
                                                      'operationId': 'initial', 'payloadDigest': first['operation']['payloadDigest']})
                require(not missing['ok'] and missing['error'] == 'history_gap', 'history hole was not explicit')
            await case('retention-hole-requires-reconciliation')
            # S03 fixture stays separate from the original twenty retained cases.
            from capacity import qualify_capacity
            capacity_root = Path(temp) / 'capacity'
            capacity_root.mkdir()
            await qualify_capacity(Broker, capacity_root, case)
        finally:
            if nc:
                await nc.close()
            broker.stop()

    require(initial_hashes == hashes(), 'source changed during storage run')
    require(initial_build == hashlib.sha256(TS.read_bytes()).hexdigest(), 'TypeScript build changed during storage run')
    require(all(hashlib.sha256((build_root / name).read_bytes()).hexdigest() == digest
                for name, digest in build_sources.items()), 'TypeScript build inputs changed during storage run')
    result = {'status': 'passed', 'recordedAt': datetime.now(timezone.utc).isoformat(),
              'platform': platform.platform(), 'python': platform.python_version(),
              'natsPy': importlib.metadata.version('nats-py'), 'natsServer': server_version,
              'node': subprocess.check_output([NODE, '--version'], text=True).strip(),
              'seconds': round(time.monotonic() - started, 3), 'cases': cases,
              'sourceSha256': initial_hashes, 'typeScriptBuildSha256': initial_build,
              'typeScriptBuildInputSha256': build_sources, 'typeScriptBuildInputsMatchRepository': True,
              'brokerBinarySha256': hashlib.sha256(SERVER.read_bytes()).hexdigest(),
              'command': 'python tests/storage/run.py',
              'sourceCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'limits': ['One file-backed R1 broker on the recorded host platform; no R3, network partition or power-loss qualification.',
                         'Fixture owners use trusted synthetic provenance; no authentication/permission or production domain owner claim.',
                         'Lost acknowledgment is deliberately omitted by the publisher; restart is graceful SIGTERM, not a power failure.',
                         'Retained-history scans are fixture implementations bounded to 10000 messages, not production indexes.',
                         'Atomic persistence does not make external effects, projections, streams or hubs transactional.'],
              'sources': ['https://docs.nats.io/learn/jetstream/advanced-publishing',
                          'https://raw.githubusercontent.com/nats-io/nats-server/v2.15.0/server/stream.go']}
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'passed', 'cases': len(cases), 'seconds': result['seconds']}))


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except Exception as exc:
        failed = {'status': 'failed', 'errorType': type(exc).__name__, 'sourceSha256': hashes()}
        if isinstance(exc, AssertionError):
            failed['detail'] = str(exc)
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps(failed, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({key: value for key, value in failed.items() if key != 'sourceSha256'}))
        sys.exit(1)
