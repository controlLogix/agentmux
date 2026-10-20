"""Concrete private custody and fixed consumer composed behind a retained owner.

There is no plugin receiver here. AMUX-287 supplies that declared receiving path.
The host supplies existing, explicitly enrolled identity, ledger and private roots.
"""
import asyncio

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from native_security.ordinary_secret_custody import OrdinarySecretCustody
from .secret_consumer import AtlassianAccountCheckConsumer, SecretConsumerObservation
from .secret_journal import SecretOperationJournal, SecretPhaseSigner


def _refuse(code='ordinary_secret_owner_refused'):
    raise ContractError(code) from None


class OrdinarySecretOwner:
    def __init__(self, journal, phase_signer, custody, consumer):
        if (type(journal) is not SecretOperationJournal or type(phase_signer) is not SecretPhaseSigner
                or phase_signer._journal is not journal or type(custody) is not OrdinarySecretCustody
                or type(consumer) is not AtlassianAccountCheckConsumer
                or custody._reader is not journal._reader
                or consumer._authority._reader is not journal._reader
                or consumer._enrollment != journal._enrollment):
            _refuse('ordinary_secret_owner_configuration')
        self._journal, self._phases, self._custody, self._consumer = journal, phase_signer, custody, consumer
        self._tasks, self._originals, self._jobs = set(), {}, {}
        self._job_groups, self._pending_observations = {}, {}
        self._closed, self._closing, self._loop = False, None, None
        self._query_lock = asyncio.Lock()

    def __repr__(self):
        return '<OrdinarySecretOwner private>'

    async def use(self, resolve_envelope, *, native_proof=None):
        """Start at most one new effect after both original claim acknowledgements."""
        return await self._owned(resolve_envelope, allow_start=True, native_proof=native_proof)

    async def recover(self, resolve_envelope, *, native_proof=None):
        """Recover only the original outcome; this path never starts HTTP."""
        return await self._owned(resolve_envelope, allow_start=False, native_proof=native_proof)

    async def recover_query(self, query_envelope, *, native_proof=None):
        """Read the original receipt with a separate current signed query.

        A missing original returns None only to this owner-native caller. No query
        prepares an intent, reads credential material, or starts an HTTP request.
        """
        if self._closed:
            _refuse('ordinary_secret_owner_closed')
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        if self._loop is not loop or len(self._tasks) >= 16:
            _refuse('ordinary_secret_owner_unavailable')
        await self._journal.authorize_query(query_envelope, native_proof=native_proof)
        if self._closed:
            _refuse('ordinary_secret_owner_closed')
        task = asyncio.create_task(self._query(query_envelope, native_proof), name='ordinary-secret-current-query')
        self._tasks.add(task)
        def done(original):
            self._tasks.discard(original)
            if not original.cancelled():
                original.exception()
        task.add_done_callback(done)
        await asyncio.wait((task,))
        result = task.result()
        group = await self._journal.current()
        await self._journal.authorize_query(query_envelope, group, native_proof=native_proof)
        if self._closed:
            _refuse('ordinary_secret_owner_closed')
        return result

    async def _query(self, raw, native_proof):
        async with self._query_lock:
            envelope = await self._journal.authorize_query(raw, native_proof=native_proof)
            original_id = envelope['payload']['input']['operationId']
            active = self._originals.get(original_id)
            if active is not None and not active[1].done():
                await asyncio.wait((active[1],))
                await self._journal.authorize_query(raw, native_proof=native_proof)
            group = await self._journal.current()
            await self._journal.authorize_query(raw, group, native_proof=native_proof)
            if group is None:
                return None
            group = await self._recover(group)
            await self._journal.authorize_query(raw, group, native_proof=native_proof)
            return self._receipt(group)

    async def reconcile(self, query_envelope, *, native_proof=None):
        receipt = await self.recover_query(query_envelope, native_proof=native_proof)
        original = strict_loads(query_envelope)['payload']['input']
        result = {'operationId': original['operationId'], 'payloadDigest': original['payloadDigest'],
            'recordRef': None, 'outcome': 'absent'}
        if receipt is not None:
            if receipt['outcome'] == 'uncertain':
                _refuse('ordinary_secret_outcome_uncertain')
            result.update(recordRef=receipt['receiptRef'],
                outcome='committed' if receipt['outcome'] == 'accepted' else 'rejected')
        validate('capability-outcome-query-reply', result)
        return result

    async def _owned(self, raw, *, allow_start, native_proof):
        if self._closed:
            _refuse('ordinary_secret_owner_closed')
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        if self._loop is not loop or len(self._tasks) >= 16:
            _refuse('ordinary_secret_owner_unavailable')
        resolution = await self._journal.authorize(raw, native_proof=native_proof)
        if self._closed:
            _refuse('ordinary_secret_owner_closed')
        operation = strict_loads(resolution.original_operation)
        key = operation['operationId']
        active = self._originals.get(key)
        if active is not None and not active[1].done():
            if active[0] != resolution.original_request_digest:
                _refuse('ordinary_secret_original_conflict')
            task = active[1]
        else:
            task = asyncio.create_task(self._execute(raw, allow_start=allow_start, native_proof=native_proof),
                                       name='ordinary-secret-use-owner')
            self._tasks.add(task)
            self._originals[key] = resolution.original_request_digest, task
            def done(original):
                self._tasks.discard(original)
                if not original.cancelled():
                    original.exception()
            task.add_done_callback(done)
        # Cancellation belongs to this observer, never the exact private worker.
        await asyncio.wait((task,))
        receipt = task.result()
        await self._journal.authorize(raw, native_proof=native_proof)
        if self._closed:
            _refuse('ordinary_secret_owner_closed')
        return receipt

    def _receipt(self, group):
        result = {'receiptRef': self._journal.ref(group['latest']),
            'outcome': group['state']['outcome'] if group['state']['phase'] == 'finished' else 'uncertain'}
        validate('capability-secret-use-reply', result)
        return result

    def _retain_observation(self, group, observed):
        # Retain the exact private result before a save can fail or be interrupted.
        # This includes known refusals with no started consumer task.
        identifier = group['original']['operation']['operationId']
        identity = self._journal.observation_identity(group, observed)
        prior = self._pending_observations.get(identifier)
        if prior is not None and self._journal.observation_identity(*prior) != identity:
            _refuse('ordinary_secret_outcome_uncertain')
        if prior is None:
            retained = strict_loads(canonical_bytes({
                'original': group['original'], 'state': group['state']}))
            self._pending_observations[identifier] = retained, observed
        return identifier

    async def _save_observation(self, group, observed):
        identifier = self._retain_observation(group, observed)
        result = await self._journal.save_observation(group, observed)
        self._pending_observations.pop(identifier, None)
        return result

    async def _finish(self, group, observed):
        observation_id = await self._save_observation(group, observed)
        # A lost completion ACK is reconciled against the original ledger, not
        # against a fabricated success or permission to repeat the HTTP request.
        latest = await self._journal.current()
        if latest['state']['phase'] == 'finished':
            return latest
        phase = await self._phases.admit('ordinary-secret-complete', latest,
                                         observation_id=observation_id)
        await self._journal.advance(phase)
        return await self._journal.current()

    async def _recover(self, group):
        if group['state']['phase'] != 'dispatching':
            return group
        operation_id = group['original']['operation']['operationId']
        handle = self._jobs.get(operation_id)
        observed = None if handle is None else self._consumer.private_observation(handle)
        if observed is None:
            observed = await self._journal.load_observation(group)
        if observed is not None:
            finished = await self._finish(group, observed)
            if handle is not None:
                await self._consumer.release(handle)
                self._jobs.pop(operation_id, None)
            return finished
        return group

    async def _execute(self, raw, *, allow_start, native_proof):
        group = await self._journal.current()
        if group is not None:
            original = strict_loads(raw)['payload']['originalEnvelope']
            if canonical_bytes(original) != canonical_bytes(group['original']):
                _refuse('ordinary_secret_original_conflict')
            group = await self._recover(group)
            return self._receipt(group)
        if not allow_start:
            _refuse('ordinary_secret_original_absent')
        prepared = await self._journal.prepare(raw, native_proof=native_proof)
        group = await self._journal.current()
        if not prepared.acknowledged or prepared.replayed:
            return self._receipt(group)
        use = await self._custody.authorize(raw, native_proof=native_proof)
        material = await self._custody._material(use)
        dispatch = await self._phases.admit('ordinary-secret-dispatch', group)
        dispatched = await self._journal.advance(dispatch)
        group = await self._journal.current()
        if not dispatched.acknowledged or dispatched.replayed:
            return self._receipt(group)
        original = group['original']['operation']
        try:
            handle = await self._consumer.prepare(raw, material,
                operation_id=original['operationId'], payload_digest=original['payloadDigest'],
                claim_ref=group['state']['dispatchRef']['id'], native_proof=native_proof)
        except ContractError:
            # No consumer task was started. Record that known refusal with current
            # service authority; it still cannot authorize a caller's disclosure.
            group = await self._finish(group, SecretConsumerObservation('rejected', 'authority_refused'))
            return self._receipt(group)
        self._jobs[original['operationId']] = handle
        self._job_groups[original['operationId']] = group
        try:
            # The fixed consumer also checks actual authority before private use,
            # after subprocess allocation, and before credential transmission.
            try:
                await self._custody.check(use)
            except ContractError:
                group = await self._finish(group, SecretConsumerObservation('rejected', 'authority_refused'))
                await self._consumer.release(handle)
                self._jobs.pop(original['operationId'], None)
                return self._receipt(group)
            self._consumer.start(handle)
            try:
                await self._consumer.wait(handle)
            except ContractError:
                # Its public observation read can refuse after revocation. The
                # exact joined worker still owns its physical result privately.
                pass
            observed = self._consumer.private_observation(handle)
            if observed is None:
                _refuse('ordinary_secret_outcome_uncertain')
            group = await self._finish(group, observed)
            await self._consumer.release(handle)
            self._jobs.pop(original['operationId'], None)
            return self._receipt(group)
        except asyncio.CancelledError:
            raise
        except ContractError:
            # Keep the original consumer and observation for explicit recovery.
            raise
        except Exception:
            _refuse('ordinary_secret_outcome_uncertain')

    async def _cleanup(self):
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
        for identifier, handle in tuple(self._jobs.items()):
            try:
                # Join the original worker even when its public proof has expired.
                await self._consumer.wait(handle)
            except ContractError:
                pass
            observed = self._consumer.private_observation(handle)
            if observed is not None:
                self._retain_observation(self._job_groups[identifier], observed)
        for group, observed in tuple(self._pending_observations.values()):
            # Private retention requires no new use or public disclosure authority.
            await self._save_observation(group, observed)
        await self._consumer.close()
        await self._custody.close()
        await self._journal.close()
        self._jobs.clear()
        self._job_groups.clear()

    async def close(self, *, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            _refuse('ordinary_secret_owner_cleanup_invalid')
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            _refuse('ordinary_secret_owner_unavailable')
        self._loop = loop
        self._closed = True
        if (self._closing is None or self._closing.done() and (
                self._closing.cancelled() or self._closing.exception() is not None)):
            # Only a joined failed attempt may be replaced. Running cleanup stays
            # owned across observer cancellation and timeout, with all resources.
            self._closing = asyncio.create_task(self._cleanup(), name='ordinary-secret-owner-close')
            self._closing.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        done, _ = await asyncio.wait((self._closing,), timeout=timeout)
        if not done or self._closing.cancelled():
            _refuse('ordinary_secret_owner_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            _refuse('ordinary_secret_owner_cleanup_incomplete')
