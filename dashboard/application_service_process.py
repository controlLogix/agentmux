"""Private bootstrap receiver for AMUX-61's owned application-service process.

Only the admitted installed bootstrap dispatches main. Stdin carries the native
host's closed selection pins and stop packet; inherited descriptor 3 retains its
already acquired OS lease. Neither a request label nor that descriptor supplies
business authority. Every service still admits current enrolled authority.
"""
import asyncio
import os
import re
import signal
import stat
import sys
import time

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import load_application_service_selection, validate_protected_host_account
from native_security.descriptor_admission import check_descriptor, DescriptorPurpose
from application_service_host import ApplicationServiceHost
from definition_commands import _joined

_START = {'schemaVersion', 'kind', 'lifetimeId', 'selection', 'selectionSHA256', 'hostPolicy',
          'ownerUid', 'workspaces', 'kernelScope', 'protectedHostAccount', 'leaseFd'}


def _start(raw):
    value = strict_loads(raw)
    if (type(value) is not dict or set(value) != _START
            or value['schemaVersion'] != '1.0.0' or value['kind'] != 'application-services-start'
            or type(value['lifetimeId']) is not str or not re.fullmatch(r'service_[a-f0-9]{32}', value['lifetimeId'])
            or type(value['selectionSHA256']) is not str
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', value['selectionSHA256'])
            or type(value['ownerUid']) is not int or value['ownerUid'] != os.getuid()
            or type(value['leaseFd']) is not int or value['leaseFd'] != 3
            or type(value['workspaces']) is not list or not 1 <= len(value['workspaces']) <= 16
            or type(value['kernelScope']) is not dict):
        raise ContractError('application_service_start_invalid')
    validate_protected_host_account(value['protectedHostAccount'])
    return value


def _lease(fd, owner_uid):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise ContractError('application_service_lease_invalid')
    check_descriptor(fd, purpose=DescriptorPurpose.PRIVATE_FILE, deadline=time.monotonic() + 1)


def _release_lease(fd):
    os.close(fd)


async def receive(reader, writer):
    """Consume the fixed private protocol on owned asyncio pipe streams."""
    host = watcher = None
    stop = asyncio.Event()
    installed_signals = []
    request = selected = None
    protocol_failure = False
    lease_admitted = False
    starting = None
    try:
        raw = await asyncio.wait_for(reader.readline(), 3)
        if not raw or len(raw) > 65536 or not raw.endswith(b'\n'):
            raise ContractError('application_service_start_invalid')
        request = _start(raw)
        _lease(3, request['ownerUid'])
        lease_admitted = True
        loop = asyncio.get_running_loop()
        def end_lifetime():
            if host is not None:
                host.fence()
            stop.set()

        for name in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(name, end_lifetime)
            installed_signals.append(name)

        async def lifetime():
            nonlocal protocol_failure
            try:
                raw = await reader.readline()
                if raw:
                    value = strict_loads(raw)
                    if (len(raw) > 65536 or type(value) is not dict
                            or value != {'schemaVersion': '1.0.0', 'kind': 'application-services-stop',
                                         'lifetimeId': request['lifetimeId']}):
                        protocol_failure = True
            except Exception:
                protocol_failure = True
            finally:
                end_lifetime()

        watcher = asyncio.create_task(lifetime())
        selected = await _joined(lambda: load_application_service_selection(request['selection'],
            expected_digest=request['selectionSHA256'], host_policy=request['hostPolicy'],
            owner_uid=request['ownerUid'], workspaces=request['workspaces'], kernel_scope=request['kernelScope'],
            protected_host_account=request['protectedHostAccount']))
        # The services host listens only on the installation's selected private
        # port, never the old dashboard's shared default.
        port = selected.local_browser_port()
        if port is None:
            raise ContractError('application_services_browser_port_unselected')
        host = ApplicationServiceHost(selected, browser_port=port)
        oidc = selected.oidc_browser_configuration()
        if oidc is not None:
            host.configure_oidc_browser(*oidc)
        oidc_device = selected.oidc_device_configuration()
        if oidc_device is not None:
            host.configure_oidc_terminal(*oidc_device)

        async def emit(state):
            writer.write(canonical_bytes({'schemaVersion': '1.0.0', 'kind': 'application-services-state',
                'lifetimeId': request['lifetimeId'], 'selectionSHA256': request['selectionSHA256'],
                'kernelScope': selected.policy['kernelScope'], 'state': state}) + b'\n')
            await asyncio.wait_for(writer.drain(), 3)

        if not stop.is_set():
            starting = asyncio.create_task(host.start())
            stopping = asyncio.create_task(stop.wait())
            try:
                await asyncio.wait({starting, stopping}, return_when=asyncio.FIRST_COMPLETED)
                if starting.done() and not stop.is_set():
                    starting.result()
                if not stop.is_set():
                    await emit('ready')
                while not stop.is_set():
                    host.check_health()
                    try:
                        await asyncio.wait_for(asyncio.shield(stopping), 1)
                    except asyncio.TimeoutError:
                        pass
            finally:
                if not stopping.done():
                    stopping.cancel()
                await asyncio.gather(stopping, return_exceptions=True)
        await host.close()
        await emit('drained')
        return 1 if protocol_failure else 0
    finally:
        # No drained packet is emitted on an uncertain join. The native owner
        # keeps its process, lease and package handle for that failed outcome.
        try:
            if host is not None:
                await host.close()
        finally:
            if starting is not None:
                await asyncio.gather(starting, return_exceptions=True)
            if watcher is not None:
                if not watcher.done():
                    watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
            for name in installed_signals:
                asyncio.get_running_loop().remove_signal_handler(name)
            if lease_admitted:
                _release_lease(3)


async def _stdio():
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=65537)
    input_protocol = asyncio.StreamReaderProtocol(reader)
    input_transport, _ = await loop.connect_read_pipe(lambda: input_protocol, sys.stdin.buffer)
    output_transport = writer = None
    try:
        output_reader = asyncio.StreamReader()
        output_protocol = asyncio.StreamReaderProtocol(output_reader)
        output_transport, _ = await loop.connect_write_pipe(lambda: output_protocol, sys.stdout.buffer)
        writer = asyncio.StreamWriter(output_transport, output_protocol, None, loop)
        return await receive(reader, writer)
    finally:
        input_transport.close()
        await input_protocol._closed
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        elif output_transport is not None:
            output_transport.close()


def main():
    """Called with no arguments by the admitted private installed bootstrap."""
    try:
        return asyncio.run(_stdio())
    except BaseException:
        # Never print credentials, selected paths or private child/transport errors.
        sys.stderr.write('Application services could not finish startup or cleanup.\n')
        return 1
