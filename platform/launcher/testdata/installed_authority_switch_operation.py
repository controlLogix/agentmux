"""Exercise the installed signed-recovery route against one guarded Store."""
import asyncio
import hashlib
import sys
import time

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.authority_switch_recovery_client import EnrolledAuthoritySwitchRecovery
from hub.client_launch_selection import load_selection
from hub.client_launch_session import ApplicationClientSession
from hub.store import HubError, Store
from identity.application_enrollment import _read_material
from identity.application_service_selection import ApplicationServiceSelection
from state_owner.authority_switch_service import VerifiedEnrolledRecovery


def _closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ContractError('installed_authority_switch_operation_invalid')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _pinned(pin, limit):
    _closed(pin, ('path', 'sha256'))
    raw = _read_material(pin['path'], max_bytes=limit, return_bytes=True)
    if _digest(raw) != pin['sha256']:
        raise ContractError('installed_authority_switch_material_changed')
    return raw


class RecoveryCheck:
    def __init__(self, request):
        _closed(request, ('recoveryMaterial',))
        material = strict_loads(_pinned(request['recoveryMaterial'], 16384))
        _closed(material, ('schemaVersion', 'clientSelection', 'serviceSelection',
                          'database', 'switchId', 'source'))
        _closed(material['database'], ('path',))
        if material['schemaVersion'] != '1.0.0':
            raise ContractError('installed_authority_switch_operation_invalid')
        _pinned(material['clientSelection'], 16384)
        service = ApplicationServiceSelection(_pinned(
            material['serviceSelection'], 65536))
        configured = service.authority_switch_configuration()
        if configured is None:
            raise ContractError('installed_authority_switch_operation_invalid')
        public, closed_guard = configured
        if (public['switchId'] != material['switchId']
                or public['source'] != material['source']):
            raise ContractError('installed_authority_switch_operation_invalid')
        self.material, self.public = material, public
        self.guard = closed_guard
        self.session = self.store = None

    async def run(self):
        selected = load_selection(self.material['clientSelection']['path'],
                                  deadline=time.monotonic() + 3)
        self.session = ApplicationClientSession(selected)
        self.session.start(deadline=time.monotonic() + 5)
        caller = EnrolledAuthoritySwitchRecovery.from_sessions(
            [self.session], public=self.public)
        self.guard = self.guard.with_enrolled_recovery(caller)
        self.store = Store(self.material['database']['path'],
                           migration_recovery=self.guard)
        fence = self.store.migration_fence_status()
        refused_write = refused_mismatch = False
        try:
            try:
                self.store.event('fixture', 'before', 'must-refuse')
            except HubError:
                refused_write = True
            try:
                await self.guard.authorize(self.store, fence,
                    'f' + '0' * 32)
            except HubError:
                refused_mismatch = True
            first = await caller.authorize(fence=fence,
                                           fence_id=fence['fenceId'])
            second = await caller.authorize(fence=fence,
                                            fence_id=fence['fenceId'])
            if (type(first) is not VerifiedEnrolledRecovery
                    or type(second) is not VerifiedEnrolledRecovery):
                raise ContractError('installed_authority_switch_operation_invalid')
            token = await self.guard.authorize(self.store, fence,
                                               fence['fenceId'])
            opened = self.store.recover_legacy_writer(fence['fenceId'], token)
            self.store.event('fixture', 'after', 'allowed')
            if (not refused_write or not refused_mismatch
                    or opened['state'] != 'open'
                    or self.store.migration_authority_closed()):
                raise ContractError('installed_authority_switch_operation_invalid')
            return {'schemaVersion': '1.0.0',
                'result': 'signed-recovery-confirmed',
                'closedWriteRefused': True, 'mismatchedFenceRefused': True,
                'exactBrokerRetryConfirmed': True, 'guardedStoreOpened': True}
        finally:
            if self.store is not None:
                self.store.db.close()

    def close(self):
        if self.session is None:
            return True
        complete = self.session.close(deadline=time.monotonic() + 2)
        return self.session.join_final() and complete


async def main():
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ContractError('installed_authority_switch_operation_invalid')
    owner = RecoveryCheck(strict_loads(raw))
    try:
        result = await owner.run()
    finally:
        if not owner.close():
            raise ContractError('installed_authority_switch_cleanup_incomplete')
    sys.stdout.buffer.write(canonical_bytes(result) + b'\n')
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except BaseException:
        print('installed authority-switch operation refused', file=sys.stderr)
        raise SystemExit(1) from None
