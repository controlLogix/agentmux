"""Private ownership of an original code Git effect and its retained result.

This is a trusted Hub helper, not an authority or a plugin capability. The
caller supplies current admission on its original task. No proof or token is
retained. A dispatch without a retained result is never executed again.
"""
import asyncio
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.code_services import Checkout, GitOperations
from hub.fed.policy import normalize_remote


_PREFIX = 'legacy-code-git:'
_LIMIT = 1048576


def public_code_remote(url):
    """Repository display identity without URL credentials or query material.

    The exact checked URL is bound separately by digest. This display value is
    never used to select or authenticate a Git remote.
    """
    public = url.split('#', 1)[0].split('?', 1)[0]
    if '://' in public:
        scheme, rest = public.split('://', 1)
        authority, separator, path = rest.partition('/')
        public = scheme + '://' + authority.rsplit('@', 1)[-1] + separator + path
    return normalize_remote(public)


class CodeGitCoordinator:
    def __init__(self, hub, federation, session):
        from hub.server import Hub
        from hub.store import Store
        from hub.fed.runtime import Federation
        from hub.fed.session import FederationSession
        if (not isinstance(hub, Hub) or type(hub.store) is not Store
                or type(federation) is not Federation or federation.hub is not hub
                or type(session) is not FederationSession or federation.session is not session):
            raise ContractError('code_git_configuration')
        self._hub, self._store, self._federation, self._session = hub, hub.store, federation, session
        self._lock = asyncio.Lock()
        self._active, self._workers = set(), set()
        self._closed, self._closing = False, None

    def __repr__(self):
        return '<CodeGitCoordinator private>'

    def _custody(self):
        if self._hub.store is not self._store or self._federation.hub is not self._hub:
            raise ContractError('code_git_binding')
        if hasattr(self._store, '_selected_custody'):
            self._store.check_existing()

    def _current(self):
        self._custody()
        if (self._closed or self._federation.session is not self._session or self._session.closing
                or getattr(self._hub, 'stop', None) is not None and self._hub.stop.is_set()):
            raise ContractError('code_git_unavailable')

    def _intent(self, *, operation_id, principal, request_digest, binding, checkout,
                destination=None, sha=None, envelope=None, share=None, effect_kind='push'):
        if (effect_kind not in ('push', 'fetch')
                or type(operation_id) is not str or not 1 <= len(operation_id) <= 256
                or type(principal) is not dict or set(principal) != {'authenticatedCaller', 'caller'}
                or any(type(v) is not str or not 1 <= len(v) <= 512 for v in principal.values())
                or type(request_digest) is not str or not re.fullmatch(r'[0-9a-f]{64}', request_digest)
                or type(binding) is not dict or not binding or type(checkout) is not Checkout
                or any(type(getattr(checkout, k)) is not str or not getattr(checkout, k)
                       for k in ('repo', 'rid', 'path', 'remote', 'url'))):
            raise ContractError('code_git_intent_invalid')
        public_url = public_code_remote(checkout.url)
        if effect_kind == 'push':
            if (share is not None or type(sha) is not str or not re.fullmatch(r'[0-9a-f]{40}', sha)
                    or type(destination) is not str or not destination.startswith('refs/agentmux/' + self._federation.me + '/')
                    or type(envelope) is not dict):
                raise ContractError('code_git_intent_invalid')
            from hub.fed.envelope import validate
            try:
                validate(envelope)
            except Exception:
                raise ContractError('code_git_intent_invalid') from None
            if (envelope['type'] != 'code' or envelope['from'] != self._federation.me
                    or envelope['node'] != self._federation.node or envelope['to'] != '*'
                    or envelope['rid'] != checkout.rid or type(envelope.get('data')) is not dict
                    or envelope['data'].get('sha') != sha or envelope['data'].get('ref') != destination
                    or 'remote' in envelope['data'] and envelope['data']['remote'] != public_url):
                raise ContractError('code_git_intent_invalid')
            source = dict(destination=destination, sha=sha, envelope=envelope)
        else:
            if (envelope is not None or destination is not None or sha is not None
                    or type(share) is not dict
                    or not {'id', 'repo', 'rid', 'from_peer', 'ref', 'sha'} <= set(share)
                    or any(type(share[k]) is not str or not share[k]
                           for k in ('id', 'repo', 'rid', 'from_peer', 'ref', 'sha'))
                    or len(share['id']) > 128 or share['repo'] != checkout.repo or share['rid'] != checkout.rid
                    or not re.fullmatch(r'[a-z0-9_]{1,32}', share['from_peer'])
                    or not share['ref'].startswith('refs/agentmux/' + share['from_peer'] + '/')
                    or not re.fullmatch(r'[0-9a-f]{40}', share['sha'])):
                raise ContractError('code_git_intent_invalid')
            # The signed owner read is admitted by the caller. Preserve every
            # returned field, including original framing and fetched metadata.
            source = dict(share=share)
        value = dict(operationId=operation_id, principal=principal, requestDigest=request_digest,
            effectKind=effect_kind, binding=binding,
            checkout={**{k: getattr(checkout, k) for k in ('repo', 'rid', 'path', 'remote')}, 'url': public_url},
            checkoutUrlDigest=hashlib.sha256(checkout.url.encode()).hexdigest(), **source)
        # Only public intent belongs here; the Hub request containing its token
        # must never be passed as a binding or embedded in the retained envelope.
        def public(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if type(key) is not str or key.lower() in ('token', 'password', 'secret', 'seed', 'privatekey'):
                        raise ContractError('code_git_intent_invalid')
                    public(child)
            elif isinstance(item, list):
                for child in item:
                    public(child)
        try:
            public(value)
            if effect_kind == 'fetch':
                value['sourceDigest'] = hashlib.sha256(canonical_bytes(share)).hexdigest()
            raw = canonical_bytes(value)
        except (TypeError, ValueError, RecursionError):
            raise ContractError('code_git_intent_invalid') from None
        if len(raw) > _LIMIT - 256:
            raise ContractError('code_git_capacity')
        return strict_loads(raw)

    @staticmethod
    def _key(intent):
        return _PREFIX + hashlib.sha256(intent['operationId'].encode()).hexdigest()

    def _read(self, intent):
        self._custody()
        row = self._store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(intent),))
        if row is None:
            return None
        if len(row['v'].encode()) > _LIMIT:
            raise ContractError('code_git_retained_invalid')
        value = strict_loads(row['v'])
        if (type(value) is not dict or set(value) != {'formatVersion', 'intent', 'state', 'result'}
                or type(value['formatVersion']) is not int or value['formatVersion'] != 1
                or value['state'] not in ('prepared', 'dispatching', 'succeeded', 'uncertain')
                or value['result'] is not None and value['state'] != 'succeeded'
                or canonical_bytes(value).decode() != row['v']):
            raise ContractError('code_git_retained_invalid')
        if canonical_bytes(value['intent']) != canonical_bytes(intent):
            raise ContractError('code_git_intent_conflict')
        return value

    def _prepare(self, intent):
        self._custody()
        with self._store.tx():
            original = self._read(intent)
            if original is not None:
                return original
            count = self._store.q1('SELECT count(*) n FROM fed_state WHERE k LIKE ?', (_PREFIX + '%',))['n']
            if count >= 32:
                raise ContractError('code_git_capacity')
            # A different operation ID cannot relabel the same retained share.
            for row in self._store.q('SELECT v FROM fed_state WHERE k LIKE ? LIMIT 33', (_PREFIX + '%',)):
                if len(row['v'].encode()) > _LIMIT:
                    raise ContractError('code_git_retained_invalid')
                retained = strict_loads(row['v'])
                try:
                    prior = retained['intent']
                    kind = intent['effectKind']
                    source = 'envelope' if kind == 'push' else 'share'
                    same_share = (prior['effectKind'] == kind
                        and prior[source]['id'] == intent[source]['id']
                        and (kind == 'push' or prior['checkout'] == intent['checkout']))
                except (KeyError, TypeError):
                    raise ContractError('code_git_retained_invalid') from None
                if same_share:
                    raise ContractError('code_git_intent_conflict')
            original = dict(formatVersion=1, intent=intent, state='prepared', result=None)
            self._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                (self._key(intent), canonical_bytes(original).decode()))
            return original

    def _transition(self, intent, old, new, result=None):
        self._custody()
        with self._store.tx():
            original = self._read(intent)
            if original is None or original['state'] != old:
                raise ContractError('code_git_uncertain')
            value = {**original, 'state': new, 'result': result}
            raw = canonical_bytes(value)
            if len(raw) > _LIMIT:
                raise ContractError('code_git_capacity')
            self._store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (raw.decode(), self._key(intent)))
            return value

    @staticmethod
    async def _join(task):
        cancelled = None
        while not task.done():
            try:
                await asyncio.wait({task})
            except asyncio.CancelledError as error:
                cancelled = error
        if cancelled is not None:
            if not task.cancelled():
                task.exception()
            raise cancelled
        return task.result()

    async def _db(self, fn, *args):
        # The executor transaction outlives a cancelled await. Join it before
        # reporting cancellation or allowing borrowed Store cleanup.
        return await self._join(asyncio.create_task(self._hub.db(fn, *args)))

    async def _effect_original(self, intent, preparation=None):
        try:
            checkout = Checkout(**intent['checkout'])
            git = GitOperations(self._federation, preparation)
            if intent['effectKind'] == 'push':
                result = await git.push(checkout, intent['sha'], intent['destination'])
            elif intent['effectKind'] == 'fetch':
                result = await git.fetch_verified(checkout, intent['share'])
            else:
                raise ContractError('code_git_intent_invalid')
            # Persist the exact original return, never derive it from a later
            # remote lookup or a replacement Git invocation.
            return await self._db(self._transition, intent, 'dispatching', 'succeeded', result)
        except BaseException:
            try:
                await self._db(self._transition, intent, 'dispatching', 'uncertain')
            except Exception:
                # A retained dispatching record already forbids replay.
                pass
            raise ContractError('code_git_uncertain') from None

    async def push(self, *, authorize, **fields):
        """Push once using fresh admission on the original caller task."""
        return await self._execute('push', authorize, fields)

    async def fetch(self, *, authorize, **fields):
        """Fetch the exact admitted owner row once and retain its verified SHA."""
        return await self._execute('fetch', authorize, fields)

    async def _execute(self, kind, authorize, fields):
        self._current()
        intent = self._intent(effect_kind=kind, **fields)
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            async with self._lock:
                self._current()
                original = await self._db(self._prepare, intent)
                if original['state'] == 'succeeded':
                    await authorize()
                    self._current()
                    return original['result']
                if original['state'] != 'prepared':
                    raise ContractError('code_git_uncertain')
                await self._db(self._transition, intent, 'prepared', 'dispatching')
                try:
                    preparation = None
                    if getattr(self._federation, '_qualified_code', False):
                        git = GitOperations(self._federation)
                        preparation = await git._prepare_effect(Checkout(**intent['checkout']),
                            fields['share']['from_peer'] if kind == 'fetch' else None)
                        deadline = await authorize()
                        application_session = self._federation._code_commands._check_git_selection(fields['binding'])
                        preparation = git._authorize_preparation(preparation, deadline=deadline,
                            binding=fields['binding'], application_session=application_session,
                            effect=({'kind': 'push', 'sha': intent['sha'], 'destination': intent['destination']}
                                if kind == 'push' else {'kind': 'fetch', 'share': intent['share']}))
                    else:
                        await authorize()
                    self._current()
                except BaseException:
                    await self._db(self._transition, intent, 'dispatching', 'uncertain')
                    raise
                worker = asyncio.create_task(self._effect_original(intent, preparation))
                self._workers.add(worker)
                try:
                    original = await self._join(worker)
                finally:
                    if worker.done():
                        self._workers.discard(worker)
                return original['result']
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def lookup(self, *, authorize, **fields):
        """Read an original push; this path never dispatches Git."""
        return await self._lookup('push', authorize, fields)

    async def lookup_fetch(self, *, authorize, **fields):
        """Read an original fetch; this path never dispatches Git."""
        return await self._lookup('fetch', authorize, fields)

    async def _lookup(self, kind, authorize, fields):
        self._current()
        intent = self._intent(effect_kind=kind, **fields)
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            async with self._lock:
                original = await self._db(self._read, intent)
                await authorize()
                self._current()
                return original
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    def _confirm(self, intent):
        self._custody()
        with self._store.tx():
            original = self._read(intent)
            if original is None or original['state'] != 'succeeded':
                raise ContractError('code_git_uncertain')
            self._store.db.execute('DELETE FROM fed_state WHERE k=?', (self._key(intent),))

    async def confirm(self, **fields):
        """Host-only release after durable publication and handoff confirmation."""
        await self._confirm_effect('push', fields)

    async def confirm_fetch(self, **fields):
        """Host-only release after the owner durably confirms fetched state."""
        await self._confirm_effect('fetch', fields)

    async def _confirm_effect(self, kind, fields):
        # The caller owns the durable domain transaction point. A Git result
        # alone does not establish publication or a fetched owner transition.
        self._current()
        intent = self._intent(effect_kind=kind, **fields)
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            async with self._lock:
                self._current()
                await self._db(self._confirm, intent)
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def _finish(self):
        while self._active or self._workers:
            await asyncio.wait(self._active | self._workers)

    async def close(self):
        """Fence new calls and join originals; never close borrowed resources."""
        self._closed = True
        if self._closing is None:
            self._closing = asyncio.create_task(self._finish())
        await self._join(self._closing)
