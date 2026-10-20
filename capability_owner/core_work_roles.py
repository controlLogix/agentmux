"""Derive legacy role interest inside the selected Work source owner."""
import asyncio
from datetime import datetime, timezone

from agentmux_contracts import ContractError
from hub import names
from identity.core_work_transport import INGEST, check_authority, selected_route


class CoreWorkRoles:
    def __init__(self, owner):
        from .core_work import CoreWorkOwner
        if type(owner) is not CoreWorkOwner:
            raise ContractError('core_work_transport_refused')
        self._owner = owner
        self._active = set()
        self._last_error = None
        self._completed_sync = None
        self._lock = asyncio.Lock()

    def __repr__(self):
        return '<CoreWorkRoles private>'

    def _interests(self, resource):
        self._owner.check()
        resource._current()
        wanted = set()
        for agent in resource._store.agents(True):
            for target in resource._store.eligible_targets(agent['session']):
                if target.startswith('role:'):
                    wanted.add(names.nats_subject(names.parse_address(target), resource._node))
        return wanted

    async def sync(self):
        owner = self._owner
        owner.check()
        finished = asyncio.get_running_loop().create_future()
        self._active.add(finished)
        try:
            # Serialize the read and installation together: an older periodic
            # read must not overwrite a completed lifecycle projection.
            async with self._lock:
                await self._sync()
        finally:
            finished.set_result(None)
            self._active.discard(finished)

    async def _sync(self):
        owner = self._owner
        owner.check()
        allowed, deadlines, admitted = {}, [], []
        for route_id, (resource, _) in owner._routes.items():
            route = selected_route(owner._selection, route_id)
            if not route['workSubjects']:
                continue
            try:
                _, deadline = await check_authority(owner._selection, owner._identity,
                    route_id=route_id, contract=INGEST)
            except ContractError:
                # A revoked peer must not retain this owner's queue interest.
                continue
            deadlines.append(deadline)
            admitted.append(route_id)
            allowed.setdefault(resource, set()).update(route['workSubjects'])
        wanted = set()
        for resource, declared in allowed.items():
            interests = await owner._dispatcher._db(resource, self._interests, resource)
            wanted.update(interests & declared)
        # Role reads await the original DB worker. Recheck the routes against
        # one current authority snapshot before installing queue interests.
        snapshot = await owner._authority.current()
        current_subjects = set()
        for route_id in admitted:
            try:
                _, deadline = await check_authority(owner._selection, owner._identity,
                    route_id=route_id, contract=INGEST, snapshot=snapshot)
            except ContractError:
                continue
            deadlines.append(deadline)
            current_subjects.update(selected_route(owner._selection, route_id)['workSubjects'])
        wanted &= current_subjects
        owner.check()
        if deadlines and datetime.now(timezone.utc) >= min(deadlines):
            raise ContractError('core_work_transport_refused')
        await owner.set_work_subjects(wanted)
        owner.check()
        if deadlines and datetime.now(timezone.utc) >= min(deadlines):
            raise ContractError('core_work_transport_refused')
        self._last_error = None
        self._completed_sync = snapshot.sequence

    async def run(self):
        while not self._owner._closed:
            if not self._owner._policy_paused:
                try:
                    await self.sync()
                except ContractError as error:
                    self._last_error = error.code
                except (OSError, TimeoutError):
                    self._last_error = 'core_work_role_sync_unconfirmed'
            await asyncio.sleep(.5)

    async def join(self):
        if self._active:
            await asyncio.wait(set(self._active))
