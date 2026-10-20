"""Private, signed admission of the Hub's original Work database."""
import asyncio
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import os
import secrets

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.store import Store, _ExistingDatabaseCustody


def _refuse():
    try:
        import json
        import sys
        from hub.server import log
        caller = sys._getframe(1)
        line = caller.f_lineno if caller.f_code.co_filename == __file__ else None
        del caller
        log('work source refusal site', json.dumps({'file': 'work_source.py', 'line': line}))
    except BaseException:
        pass
    raise ContractError('work_source_binding_refused')


class WorkSourcePin:
    """Borrow custody taken before SQLite opened; never open a second source."""
    def __init__(self, store):
        if (type(store) is not Store
                or type(getattr(store, '_selected_custody', None)) is not _ExistingDatabaseCustody):
            _refuse()
        self.store, self.connection = store, store.db
        self.custody = store._selected_custody
        self.identity = self.read()

    def __repr__(self):
        return '<WorkSourcePin private>'

    def check(self):
        if (self.store.db is not self.connection
                or self.store._selected_custody is not self.custody
                or self.connection._selected_custody is not self.custody):
            _refuse()
        try:
            self.connection.in_transaction
            self.custody.check()
        except Exception:
            _refuse()

    def read(self, *, full=False):
        """Run only on the source's original database worker."""
        self.check()
        # Sidecar descriptors are appended by custody.check(). The main file is
        # identified by its exact retained path rather than by descriptor order.
        matches = [row for row in self.custody.rows if row[0] == self.custody.path]
        if len(matches) != 1:
            _refuse()
        path, _, _, held = matches[0]
        databases = self.connection.execute('PRAGMA database_list').fetchall()
        if (len(databases) != 1 or databases[0]['name'] != 'main'
                or databases[0]['file'] != path or self.store.path != path
                or os.path.realpath(path) != path):
            _refuse()
        if not hasattr(self,'identity') or full:
            schema = [list(row) for row in self.connection.execute(
                'SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name,tbl_name')]
            value = {'formatVersion':1,
                'sourceDigest':'sha256:'+hashlib.sha256(canonical_bytes({
                    'path':path,'device':held.st_dev,'inode':held.st_ino,'owner':held.st_uid})).hexdigest(),
                'schemaDigest':'sha256:'+hashlib.sha256(canonical_bytes(schema)).hexdigest()}
        else:
            value=dict(self.identity)
        value.update({
            'applicationId': self.connection.execute('PRAGMA application_id').fetchone()[0],
            'userVersion': self.connection.execute('PRAGMA user_version').fetchone()[0],
            'schemaVersion': self.connection.execute('PRAGMA schema_version').fetchone()[0]})
        self.check()
        if hasattr(self, 'identity') and value != self.identity:
            _refuse()
        return value


def _disclosure_source(resource):
    """Recheck held source custody without using its database off the worker."""
    from .work_host import SelectedWorkDomain
    domain, source = resource._owner, resource._source
    if (type(domain) is not SelectedWorkDomain or domain._closed or source._closed
            or source._policy_paused or source._policy_suspended or source._policy_replacing
            or domain._source is not source or domain._store is not resource._store
            or domain._connection is not resource._connection
            or source._store is not resource._store or source._store.db is not resource._connection
            or source._executor is not resource._source_worker
            or domain._executor is not resource._source_worker
            or domain.db != resource._db or domain.node != resource._node
            or domain.node != domain._node or domain._scope != resource.binding.scope
            or domain._scope != domain._bound_scope
            or domain._selection is None
            or domain._selection is not domain._bound_selection
            or domain._selection.document != domain._selection_document
            or canonical_bytes(source._pins) != domain._source_pins
            or canonical_bytes(source._repository) != domain._repository
            or domain._policy is not source._policy or domain._policy is not domain._source._policy
            or domain.session is not domain._session or domain.me != source._peer
            or domain._identity._closed or domain._identity.reader is not domain._identity_reader
            or domain._identity_pins != (domain._identity_reader._hub,domain._identity_reader._entity,
                domain._identity_reader._profile,domain._identity_reader._organization)):
        _refuse()
    repository = strict_loads(domain._bound_repository)
    channel = strict_loads(domain._channel_ref)
    if channel['id'] != resource.binding.entity_id or channel['ownerHubId'] != resource.binding.hub_id:
        _refuse()
    if (repository is None and resource.repository is not None
            or repository is not None and (repository['localName'] != resource.repository
                or repository.get('repositoryId') != resource.repository_id)):
        _refuse()
    source.check_health()
    pin = getattr(resource, '_work_source_pin', None)
    if pin is None or pin.store is not resource._store or pin.connection is not resource._connection:
        _refuse()
    pin.check()
    if domain._session is not None:
        domain._session.check_open()


def _core_owner(resource, *, disclosure=False):
    """Selection, rather than an optional owner attribute, declares participation."""
    from .core_work import CoreWorkOwner
    from .work_host import SelectedWorkDomain
    domain = resource._owner
    if disclosure:
        _disclosure_source(resource)
    else:
        resource._current()
    if type(domain) is not SelectedWorkDomain or domain._bound_selection is None:
        _refuse()
    selected = domain._bound_selection
    routes = [route for route in selected.policy.get('coreWorkTransport', {}).get('routes', ())
        if route['resourceRef']['id'] == resource.binding.entity_id
        and route['resourceRef']['ownerHubId'] == resource.binding.hub_id]
    owner = getattr(resource, '_core_work_owner', None)
    if not routes:
        if owner is not None:
            _refuse()
        return None
    if type(owner) is not CoreWorkOwner or owner._selection is not selected:
        _refuse()
    for route in routes:
        if (route['scope'] != strict_loads(resource.binding.scope)
                or route['repository']['localName'] != resource.repository
                or route['repository'].get('repositoryId') != resource.repository_id
                or route['localNode'] != resource._node
                or owner._routes.get(route['routeId'], (None,))[0] is not resource):
            _refuse()
    return owner


def owner_core_mode(resource, snapshot):
    owner = _core_owner(resource)
    if owner is None:
        return {'mode': 'local-only'}, None
    return owner.transport_proof(resource, snapshot)


def check_source_disclosure(resource, admitted, *, mode=None):
    core = mode if mode is not None else (None if admitted.source is None
        else strict_loads(admitted.source).get('coreTransport'))
    if core is None:
        original = strict_loads(admitted.original)
        if (original['contractId'] == 'federation-work-inspect'
                and 'coreTransport' in original['payload']['input'].get('sourceBinding', {})):
            _disclosure_source(resource)
            return True
        return False
    owner = _core_owner(resource, disclosure=True)
    if owner is None:
        if core != {'mode':'local-only'}:
            _refuse()
    else:
        owner.check_transport_disclosure(resource, core, admitted.snapshot, admitted.valid_until)
    return True


def owner_source(resource, request, snapshot):
    """Called inside the actual owner's fixed inspect operation on its worker."""
    resource._current()
    pin = getattr(resource, '_work_source_pin', None)
    if pin is None:
        pin = WorkSourcePin(resource._store)
        resource._work_source_pin = pin
    if pin.store is not resource._store or pin.connection is not resource._connection:
        _refuse()
    identity = pin.read(full=True)
    resource._current()
    result = {'purpose': 'agentmux-work-source-binding-v1', 'nonce': request['nonce'],
        'localNode': resource._node, 'repository': resource.repository, **identity}
    if 'coreTransport' in request:
        result['coreTransport'], deadline = owner_core_mode(resource, snapshot)
        if deadline is not None:
            resource._journal._deadline(deadline)
    return result


def check_owner_source(resource, expected, snapshot=None):
    """Validate a signed command's source before its actual owner can apply it."""
    # authorize_legacy has just checked this actor on this exact active worker;
    # there is no await between its current source check and this comparison.
    source=resource._source
    if source is None or not getattr(source._worker,'active',False):
        _refuse()
    pin=getattr(resource,'_work_source_pin',None)
    if pin is None:
        pin=WorkSourcePin(resource._store)
        resource._work_source_pin=pin
    core = expected.get('coreTransport')
    plain = {key: value for key, value in expected.items() if key != 'coreTransport'}
    if (pin.store is not resource._store or pin.connection is not resource._connection
            or pin.custody is not resource._store._selected_custody
            or {**pin.identity, 'localNode':resource._node,
                'repository':resource.repository}!=plain):
        _refuse()
    if core is not None:
        current, deadline = owner_core_mode(resource, snapshot)
        if current != core:
            _refuse()
        if deadline is not None:
            resource._journal._deadline(deadline)
        return deadline


class HubWorkSourceBinding:
    """Own admission tasks; borrow only the Hub's original joined DB worker."""
    def __init__(self, commands):
        self.commands, self.hub = commands, commands._hub
        self.store, self.connection = self.hub.store, self.hub.store.db
        self.worker, self.db = self.hub.dbx, self.hub.db
        self.pin = self.worker.submit(WorkSourcePin, self.store).result()
        self.routes = tuple(commands._routes)
        self.activation, self.closed, self.pending = None, False, set()
        self._proof_slots = asyncio.Semaphore(8)
        self._legacy_mode = self.hub.cfg.get('nats_url') or ''
        self._bridge = self.hub.bridge
        self._core_pins = {}

    def __repr__(self):
        return '<HubWorkSourceBinding private>'

    def check(self, *, physical=True):
        if (self.closed or self.hub.store is not self.store or self.store.db is not self.connection
                or self.hub.dbx is not self.worker or self.hub.db != self.db
                or self.hub._work_source_binding is not self
                or (self.hub.cfg.get('nats_url') or '') != self._legacy_mode
                or self.hub.bridge is not self._bridge
                or self._legacy_mode and (self._bridge is None
                    or self._bridge.url != self._legacy_mode
                    or self._bridge.node != self.hub.cfg['node'])
                or tuple(self.commands._routes) != self.routes):
            _refuse()
        if physical:
            self.pin.check()
        for session, raw in self.routes:
            if canonical_bytes(session.work_enrollment()) != raw:
                _refuse()

    async def _local(self, *, full=False):
        self.check(physical=False)
        # Hub.db already checks the physical source and schema generation on
        # both sides of this worker operation. Hash the full schema only for an
        # actual source proof, rather than a third time for ordinary use.
        value = await self.commands._owned_db(self.pin.read if full else lambda:dict(self.pin.identity),
            **({'full':True} if full else {}))
        self.check()
        return value

    async def expectation(self, session):
        self.check()
        matches = [raw for current, raw in self.routes if current is session]
        if len(matches) != 1:
            _refuse()
        selected = strict_loads(matches[0])['workCommands']
        result = {**await self._local(), 'localNode':selected['localNode'],
            'repository':None if selected['repository'] is None else selected['repository']['localName']}
        if self._legacy_mode and id(session) in self._core_pins:
            result['coreTransport'] = strict_loads(self._core_pins[id(session)])
        return result

    def request(self, nonce):
        return {'purpose': 'agentmux-work-source-binding-v1', 'nonce': nonce,
            **({'coreTransport': {'mode': 'tm218-core-v1'}} if self._legacy_mode else {})}

    def _core_reply(self, session, proof):
        if not self._legacy_mode:
            return
        core = proof.get('coreTransport')
        if (type(core) is not dict or core.get('mode') not in ('local-only', 'tm218-core-v1')
                or set(core) != ({'mode'} if core['mode'] == 'local-only' else {'mode','bindingDigest'})):
            _refuse()
        if core['mode'] == 'tm218-core-v1':
            import re
            if type(core['bindingDigest']) is not str or re.fullmatch(r'sha256:[0-9a-f]{64}', core['bindingDigest']) is None:
                _refuse()
        raw = canonical_bytes(core)
        previous = self._core_pins.setdefault(id(session), raw)
        if previous != raw:
            _refuse()

    async def _prove(self, session, raw, expires):
        async def original():
            async with self._proof_slots:
                return await self._prove_current(session, raw, expires)
        task=asyncio.create_task(original())
        self.pending.add(task)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.wait({task})
                except asyncio.CancelledError:
                    continue
            if not task.cancelled():
                task.exception()
            raise
        finally:
            if task.done():
                self.pending.discard(task)

    async def _prove_current(self, session, raw, expires):
        self.check()
        enrollment = strict_loads(raw)
        selected = enrollment['workCommands']
        if selected['localNode'] != self.hub.cfg['node']:
            _refuse()
        nonce = secrets.token_hex(32)
        local = await self._local(full=True)
        reply = await self.commands._call(session, 'federation-work-inspect',
            'work_source_' + secrets.token_hex(16), {'resourceRef': selected['resourceRef'],
                'input': {'sourceBinding': self.request(nonce)}},
            expires, _source_binding=True)
        expected = {'purpose': 'agentmux-work-source-binding-v1', 'nonce': nonce,
            'localNode': selected['localNode'],
            'repository': None if selected['repository'] is None else selected['repository']['localName'], **local}
        result = reply['result']
        self._core_reply(session, result.get('sourceBinding', {}))
        if self._legacy_mode:
            expected['coreTransport'] = strict_loads(self._core_pins[id(session)])
        if (type(result) is not dict or set(result) != {'resourceRef', 'sourceBinding'}
                or result['sourceBinding'] != expected):
            _refuse()
        self.commands._reference(result['resourceRef'], selected['resourceRef'])
        if await self._local() != local:
            _refuse()
        return datetime.fromisoformat(reply['validUntil'])

    async def activate(self):
        self.check()
        if self.activation is None:
            async def original():
                expires = datetime.now(timezone.utc) + timedelta(seconds=4)
                await self._all_routes(expires)
            self.activation = asyncio.create_task(original())
        try:
            await asyncio.shield(self.activation)
        except asyncio.CancelledError:
            while not self.activation.done():
                try:
                    await asyncio.wait({self.activation})
                except asyncio.CancelledError:
                    continue
            if not self.activation.cancelled():
                self.activation.exception()
            raise
        self.check()

    async def _all_routes(self, expires):
        tasks = [asyncio.create_task(self._prove(session, raw, expires))
            for session, raw in self.routes]
        self.pending.update(tasks)
        # Do not abandon other original route checks when one refuses or the
        # observer is cancelled. Each service session retains its exact exchange.
        cancelled = None
        while any(not task.done() for task in tasks):
            try:
                await asyncio.wait(tasks)
            except asyncio.CancelledError as error:
                cancelled = error
        results = [task.exception() if task.exception() is not None else task.result()
            for task in tasks]
        self.pending.difference_update(tasks)
        if cancelled is not None:
            raise cancelled
        if any(isinstance(result, BaseException) for result in results):
            # The public refusal stays unchanged. Retain closed evidence from
            # the original, already joined route checks before folding it away.
            try:
                import json
                from hub.client_launch_binding import BindingError
                from hub.client_launch_session import ApplicationSessionFailure
                from hub.server import log
                kinds = {ContractError: 'contract-refused',
                         ApplicationSessionFailure: 'application-session-failure',
                         BindingError: 'binding-refused', TimeoutError: 'timeout'}
                for result in results:
                    if isinstance(result, BaseException):
                        log('work source route refusal', json.dumps(
                            {'category': kinds.get(type(result), 'other')}))
                        if type(result) is ApplicationSessionFailure:
                            diagnostic = getattr(result, '_command_diagnostic', None)
                            if diagnostic is not None:
                                # This is the same sanitized command diagnostic
                                # used by Hub.handle_conn, from the original wait.
                                log('application command diagnostic', json.dumps(diagnostic))
            except BaseException:
                pass
            _refuse()
        if self._legacy_mode and (len(self._core_pins) != len(self.routes)
                or not any(strict_loads(raw)['mode'] == 'tm218-core-v1' for raw in self._core_pins.values())):
            _refuse()
        self.check()
        if datetime.now(timezone.utc) >= min(results):
            _refuse()

    async def verify(self):
        await self.activate()
        maintenance = getattr(self.hub, '_work_maintenance', None)
        # Startup activation precedes maintenance. Later reads wait before
        # creating their proof batch; submitted proofs retain their deadlines.
        async with (maintenance.source_read_turn() if maintenance is not None else nullcontext()):
            await self._all_routes(datetime.now(timezone.utc) + timedelta(seconds=4))

    async def before_call(self, session, expires):
        await self.activate()
        matches = [raw for current, raw in self.routes if current is session]
        if len(matches) != 1:
            _refuse()
        self.check()
        return expires

    async def check_reply(self, session, request, reply):
        matches=[raw for current,raw in self.routes if current is session]
        if len(matches)!=1:
            _refuse()
        selected=strict_loads(matches[0])['workCommands']
        expected={'purpose':'agentmux-work-source-binding-v1','nonce':request['nonce'],
            'localNode':selected['localNode'],
            'repository':None if selected['repository'] is None else selected['repository']['localName'],
            **await self._local(full=True)}
        result=reply['result']
        self._core_reply(session, result.get('sourceBinding', {}))
        if self._legacy_mode:
            expected['coreTransport'] = strict_loads(self._core_pins[id(session)])
        if (type(result) is not dict or set(result)!={'resourceRef','sourceBinding'}
                or result['sourceBinding']!=expected):
            _refuse()
        self.commands._reference(result['resourceRef'],selected['resourceRef'])
        return {**reply,'result':{'resourceRef':result['resourceRef']}}

    async def close(self):
        self.closed = True
        while self.pending:
            await asyncio.wait(tuple(self.pending))
            for task in tuple(self.pending):
                if task.done():
                    self.pending.discard(task)
                    if not task.cancelled():
                        task.exception()
        if self.activation is not None:
            await asyncio.wait({self.activation})
            if not self.activation.cancelled():
                self.activation.exception()
