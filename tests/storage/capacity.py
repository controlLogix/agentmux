"""S03 admission fixture. No production authorization or disk-capacity claim."""
import asyncio
import hashlib
import json

from nats.js.api import DiscardPolicy, StorageType, StreamConfig
from nats.js.errors import APIError, NotFoundError


BODY_BUDGET = 10_000
BULK_LIMIT = 8_500
RESERVE_BODY = 1_500
MAX_RECORD = 16_384
STORAGE_SLOT = 32_768
STORAGE_BUDGET = 6 * STORAGE_SLOT


def require(value, message):
    if not value:
        raise AssertionError(message)


def capacity_invariant(state):
    """The same acceptance oracle applies to guarded and bypassed histories."""
    require(state['bulkBytes'] <= BULK_LIMIT, 'bulk capacity exceeded')
    require(state['reserveUsedBytes'] <= state['allocatedReserveBytes'],
            'completion body reserve exceeded')
    require(state['chargedStorageBytes'] + state['remainingFinalRecords'] * STORAGE_SLOT
            <= STORAGE_BUDGET, 'completion storage reserve consumed')


class CapacityOwner:
    """One retained aggregate; independent instances serialize with subject CAS.

    Every accepted record charges a conservative storage slot, including framing.
    The first bulk acceptance allocates two final records and their body budget.
    A restart or replay cannot refund that allocation or earlier storage charges.
    """

    def __init__(self, js, stream):
        self.js, self.stream = js, stream
        self.subject = 'capacity.' + stream.lower() + '.owner'

    async def provision(self):
        await self.js.add_stream(StreamConfig(
            name=self.stream, subjects=['capacity.' + self.stream.lower() + '.>'],
            storage=StorageType.FILE, discard=DiscardPolicy.NEW,
            max_bytes=STORAGE_BUDGET, max_msg_size=MAX_RECORD,
            max_age=0, duplicate_window=.2))

    async def current(self):
        try:
            message = await self.js.get_msg(self.stream, subject=self.subject)
            return json.loads(message.data), message.seq
        except NotFoundError:
            return {'bulkBytes': 0, 'reserveUsedBytes': 0, 'allocatedReserveBytes': 0,
                    'remainingFinalRecords': 0, 'chargedStorageBytes': 0,
                    'operation': None, 'taskState': 'not_accepted'}, 0

    async def replay(self, operation, digest):
        info = await self.js.stream_info(self.stream)
        if info.state.num_deleted or info.state.first_seq > 1 or info.state.last_seq > 10_000:
            return {'status': 'unavailable', 'reason': 'history_gap'}
        for sequence in range(1, info.state.last_seq + 1):
            message = await self.js.get_msg(self.stream, seq=sequence)
            if message.subject != self.subject:
                continue
            record = json.loads(message.data)
            if record['operation']['id'] == operation:
                if record['operation']['digest'] != digest:
                    return {'status': 'rejected', 'reason': 'operation_conflict'}
                return {'status': 'committed', 'sequence': sequence, 'replayed': True,
                        'state': record}
        return None

    async def apply(self, operation, kind, payload, before_commit=None, bypass=False):
        require(kind in ('bulk', 'final', 'reconcile'), 'unknown capacity operation')
        charge = len(payload.encode('utf-8'))
        digest = hashlib.sha256(json.dumps([operation, kind, payload],
                                         ensure_ascii=False).encode()).hexdigest()
        for attempt in range(8):
            prior = await self.replay(operation, digest)
            if prior:
                return prior
            state, sequence = await self.current()
            proposal = dict(state)
            if kind == 'bulk':
                if not bypass and state['bulkBytes'] + charge > BULK_LIMIT:
                    return {'status': 'rejected', 'reason': 'bulk_threshold'}
                if not bypass and state['bulkBytes'] >= BULK_LIMIT:
                    return {'status': 'rejected', 'reason': 'bulk_threshold'}
                if not state['allocatedReserveBytes']:
                    proposal.update(allocatedReserveBytes=RESERVE_BODY,
                                    remainingFinalRecords=2, taskState='reserved')
                proposal['bulkBytes'] += charge
            else:
                if (not state['allocatedReserveBytes'] or not state['remainingFinalRecords']
                        or state['reserveUsedBytes'] + charge > state['allocatedReserveBytes']):
                    return {'status': 'rejected', 'reason': 'completion_reserve_exhausted'}
                proposal['reserveUsedBytes'] += charge
                proposal['remainingFinalRecords'] -= 1
                proposal['taskState'] = 'completed' if kind == 'final' else 'reconciled'
            proposal['chargedStorageBytes'] += STORAGE_SLOT
            remaining = proposal['remainingFinalRecords'] * STORAGE_SLOT
            if not bypass and proposal['chargedStorageBytes'] + remaining > STORAGE_BUDGET:
                return {'status': 'rejected', 'reason': 'physical_reserve'}
            if not bypass:
                capacity_invariant(proposal)
            proposal['operation'] = {'id': operation, 'digest': digest, 'kind': kind,
                                     'bodyBytes': charge, 'payload': payload}
            encoded = json.dumps(proposal, ensure_ascii=False, separators=(',', ':')).encode()
            require(len(encoded) <= MAX_RECORD, 'record exceeds bounded capacity envelope')
            # The only header and subject are bounded. A slot reserves at least an
            # entire maximum record plus 16 KiB for stored protocol framing.
            require(len(self.subject.encode()) < 64, 'capacity subject exceeds framing bound')
            headers = {'Nats-Expected-Last-Subject-Sequence': str(sequence)}
            require(len(str(sequence)) <= 20, 'capacity revision exceeds framing bound')
            if before_commit and attempt == 0:
                await before_commit()
            before = await self.js.stream_info(self.stream)
            try:
                ack = await self.js.publish(self.subject, encoded, headers=headers)
            except APIError as exc:
                if exc.err_code == 10071:
                    continue
                return {'status': 'unavailable', 'reason': 'broker_capacity', 'apiCode': exc.err_code}
            after = await self.js.stream_info(self.stream)
            # Concurrent losers never write; a slot also exceeds any observed
            # accepted framing delta in these isolated fixture histories.
            require(after.state.bytes - before.state.bytes <= STORAGE_SLOT,
                    'broker storage delta exceeds reserved slot')
            require(after.state.bytes <= proposal['chargedStorageBytes'],
                    'actual broker storage exceeds charged history budget')
            return {'status': 'committed', 'sequence': ack.seq, 'replayed': False,
                    'state': proposal, 'actualStreamBytes': after.state.bytes,
                    'warning': proposal['bulkBytes'] * 100 >= BODY_BUDGET * 70}
        return {'status': 'unavailable', 'reason': 'revision_contention'}


async def qualify_capacity(broker_factory, directory, case):
    broker = broker_factory(directory)
    nc = None
    try:
        await broker.start()
        nc = await broker.connect()
        js = nc.jetstream(timeout=3)
        owner = CapacityOwner(js, 'CAPACITY')
        await owner.provision()
        below = await owner.apply('accept', 'bulk', '\u03bb' * 3499 + 'a')
        require(below['status'] == 'committed' and not below['warning'],
                'warning fired below 70 percent')
        initial = await owner.apply('warn', 'bulk', 'x')
        require(initial['status'] == 'committed' and initial['state']['bulkBytes'] == 7000
                and initial['warning'],
                '70 percent byte warning boundary not reached')
        require(initial['state']['allocatedReserveBytes'] == 1500
                and initial['state']['remainingFinalRecords'] == 2,
                'acceptance failed to allocate completion reserve')
        await case('capacity-warn70-and-allocate-completion-reserve', warning=True,
                   bulkBytes=7000, reservedBodyBytes=1500, reservedStorageBytes=2 * STORAGE_SLOT,
                   maxRecordBytes=MAX_RECORD, streamMaxBytes=STORAGE_BUDGET)
        require((await owner.apply('approach', 'bulk', 'b' * 400))['status'] == 'committed',
                'below-threshold bulk rejected')
        crossing = await owner.apply('crossing', 'bulk', 'x' * 1101)
        require(crossing == {'status': 'rejected', 'reason': 'bulk_threshold'},
                'single item crossing 85 percent was admitted')
        waiting = 0
        ready = asyncio.Event()
        async def barrier():
            nonlocal waiting
            waiting += 1
            if waiting == 2:
                ready.set()
            await asyncio.wait_for(ready.wait(), 3)
        rival = CapacityOwner(js, 'CAPACITY')
        outcomes = await asyncio.gather(owner.apply('race-a', 'bulk', 'a' * 1100, barrier),
                                        rival.apply('race-b', 'bulk', 'b' * 1100, barrier))
        require(sorted(x['status'] for x in outcomes) == ['committed', 'rejected'],
                'concurrent capacity admission exceeded bulk budget')
        snapshot, seq = await owner.current()
        require(snapshot['bulkBytes'] == 8500 and snapshot['reserveUsedBytes'] == 0,
                'race consumed completion reserve')
        capacity_invariant(snapshot)
        denied = await asyncio.gather(owner.apply('over-a', 'bulk', 'x'),
                                      rival.apply('over-b', 'bulk', 'y'))
        require(all(x == {'status': 'rejected', 'reason': 'bulk_threshold'} for x in denied),
                'bulk admission not stopped at 85 percent')
        require((await owner.current())[1] == seq, 'denied bulk wrote owner state')
        await case('capacity-concurrent-bulk85-denial', committedContenders=1,
                   deniedContenders=1, thresholdDenials=2, ownerSequence=seq)
        final = await owner.apply('final', 'final', 'f' * 900)
        reconcile = await owner.apply('reconcile', 'reconcile', 'r' * 600)
        require(final['status'] == reconcile['status'] == 'committed',
                'allocated final/reconcile reserve unavailable')
        exhausted = await owner.apply('extra-final', 'final', 'x')
        require(exhausted == {'status': 'rejected', 'reason': 'completion_reserve_exhausted'},
                'reserve exhaustion was not explicit')
        await case('capacity-separate-final-reconciliation-budget', reserveUsedBytes=1500,
                   exhaustion=exhausted['reason'], actualStreamBytes=reconcile['actualStreamBytes'])
        retained, retained_seq = await owner.current()
        capacity_invariant(retained)
        await nc.close()
        nc = None
        broker.stop()
        await broker.start()
        await asyncio.sleep(.3)
        nc = await broker.connect()
        owner = CapacityOwner(nc.jetstream(timeout=3), 'CAPACITY')
        require(await owner.current() == (retained, retained_seq), 'restart replenished capacity')
        replay = await owner.apply('final', 'final', 'f' * 900)
        conflict = await owner.apply('final', 'final', 'changed')
        require(replay['status'] == 'committed' and replay['replayed']
                and conflict == {'status': 'rejected', 'reason': 'operation_conflict'},
                'reserve replay changed accounting or identity')
        require(await owner.current() == (retained, retained_seq), 'replay charged twice')
        await case('capacity-retained-restart-and-idempotent-reserve', sequence=retained_seq,
                   bulkBytes=8500, reserveUsedBytes=1500, chargedStorageBytes=retained['chargedStorageBytes'])
        js = nc.jetstream(timeout=3)
        physical = CapacityOwner(js, 'PHYSICAL')
        await physical.provision()
        for number in range(4):
            require((await physical.apply('tiny-' + str(number), 'bulk', 'x'))['status'] == 'committed',
                    'physical budget rejected allocated slot')
        pressure = await physical.apply('tiny-over', 'bulk', 'x')
        require(pressure == {'status': 'rejected', 'reason': 'physical_reserve'},
                'logical-only admission consumed reserved storage slots')
        require((await physical.apply('p-final', 'final', 'f' * 900))['status'] == 'committed'
                and (await physical.apply('p-reconcile', 'reconcile', 'r' * 600))['status'] == 'committed',
                'physical headroom failed final/reconcile commit')
        await case('capacity-physical-framing-headroom', streamMaxBytes=STORAGE_BUDGET,
                   maxRecordBytes=MAX_RECORD, conservativeRecordSlot=STORAGE_SLOT,
                   admittedBulkRecords=4, allocatedFinalRecords=2)
        unguarded = CapacityOwner(js, 'BYPASS')
        await unguarded.provision()
        require((await unguarded.apply('seed', 'bulk', 'x' * 8500))['status'] == 'committed',
                'negative fixture seed failed')
        unchecked = await unguarded.apply('unchecked', 'bulk', 'x', bypass=True)
        require(unchecked['status'] == 'committed' and unchecked['state']['bulkBytes'] > BULK_LIMIT,
                'bypassed guard negative control did not violate bulk threshold')
        oracle_failure = None
        try:
            capacity_invariant(unchecked['state'])
        except AssertionError as exc:
            oracle_failure = str(exc)
        require(oracle_failure == 'bulk capacity exceeded',
                'same capacity oracle failed to reject bypassed owner state')
        await case('capacity-bypassed-admission-negative-control', violatedInvariant='bulkBytes <= 8500',
                   observedBulkBytes=unchecked['state']['bulkBytes'], rejectedByOracle=True,
                   observedAssertion=oracle_failure)
        full = CapacityOwner(js, 'FULL')
        await full.provision()
        require((await full.apply('full-accept', 'bulk', 'x'))['status'] == 'committed', 'full seed failed')
        before_full = await full.current()
        for size in (MAX_RECORD, 1000, 100):
            for _ in range(2100):
                try:
                    await js.publish('capacity.full.unguarded', b'x' * size)
                except APIError:
                    break
            else:
                raise AssertionError('bounded full-stream fixture did not reach broker quota')
        unavailable = await full.apply('full-final', 'final', 'f' * 900)
        require(unavailable['status'] == 'unavailable' and unavailable['reason'] == 'broker_capacity',
                'broker quota failure falsely reported committed')
        require(await full.current() == before_full, 'failed final publication changed owner state')
        await case('capacity-real-broker-exhaustion-no-false-commit', apiCode=unavailable['apiCode'],
                   ownerStateUnchanged=True, boundary='unguarded writers deliberately defeat reserved headroom')
    finally:
        if nc:
            await nc.close()
        broker.stop()
