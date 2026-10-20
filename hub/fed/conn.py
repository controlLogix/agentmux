"""Connecting to the federation cluster (docs/FEDERATION.md sections 3-5).

The one place that knows the stream and bucket layout, so the admin provisioner, the
runtime and the tests cannot disagree about it. nats-py is imported lazily: the core
hub stays stdlib-only and only federation needs the dependency (assumption A4).
"""
from __future__ import annotations

import asyncio
import os
import ssl
import sys
from urllib.parse import urlsplit

from hub.nats_transport import PairedTCPTransport as _PairedTCPTransport, _new_client as _shared_new_client

# name -> (subjects, retention, max_age_s). Section 5.
STREAMS = {
    "AM_MSG": (["am.msg.>"], "limits", 14 * 86400),
    "AM_WORK": (["am.work.>"], "workqueue", 30 * 86400),
    "AM_SHARE": (["am.know.>", "am.code.>"], "limits", 365 * 86400),
}
# name -> (history, ttl_s)
BUCKETS = {
    "am_board": (16, 0),
    "am_presence": (1, 90),
}
DUPE_WINDOW_S = 120


class MissingDependency(RuntimeError):
    pass


def nats_mod():
    try:
        import nats  # noqa: F401
        import nats.js.api  # noqa: F401
        return nats
    except ImportError as e:
        raise MissingDependency(
            "federation needs nats-py: run `agentmux hub fed setup` (creates .venv with hub/requirements.txt)") from e


def tls_context(ca: str | None):
    if not ca:
        return None
    ctx = ssl.create_default_context(cafile=os.path.expanduser(ca))
    return ctx


INITIAL_CONNECT_TIMEOUT = 5
FAILED_CONNECT_CLOSE_TIMEOUT = 5


class InitialConnectTimeout(TimeoutError):
    def __init__(self):
        super().__init__(
            "federation initial connection timed out; check the endpoint, trusted CA and current credentials")


class ConnectionCleanupFailure(RuntimeError):
    """Retain the exact failed client, cleanup attempt and private causes."""

    def __init__(self, client, operation_error):
        super().__init__(
            "failed connection cleanup is incomplete; finish owned cleanup before connecting again")
        self.client = client
        self.operation_error = operation_error
        self.close_task = asyncio.create_task(client.close())
        self.cleanup_errors = []

    async def _wait(self):
        try:
            await asyncio.wait_for(asyncio.shield(self.close_task), FAILED_CONNECT_CLOSE_TIMEOUT)
        except BaseException as error:
            self.cleanup_errors.append(error)
            causes = ([self.operation_error] if self.operation_error is not None else []) + self.cleanup_errors
            raise self from BaseExceptionGroup("failed connection cleanup causes", causes)

    async def retry_close(self):
        """Rejoin the owned close; a consumed failed close is not retry proof."""
        if self.close_task.done() and (self.close_task.cancelled() or self.close_task.exception() is not None):
            # nats-py marks the client closed before closing its transport. A
            # second no-op close cannot prove the first attempt finished.
            raise self
        await self._wait()


def _connection_cleanup(client, operation_error):
    owned = getattr(client, "_agentmux_close_owner", None)
    if owned is None:
        owned = ConnectionCleanupFailure(client, operation_error)
        client._agentmux_close_owner = owned
    return owned


async def _close_failed_connection(client, operation_error):
    await _connection_cleanup(client, operation_error)._wait()


async def _quiet_error(error):
    # nats-py's default callback logs raw endpoint and authentication failures.
    # Callers receive the failure directly; supplied callbacks stay unchanged.
    pass


def _new_client(nats, require_tls):
    # Preserve the federation factory seam while sharing the exact transport.
    return _shared_new_client(nats, require_tls)


async def connect(url: str, creds: str | None, ca: str | None, name: str, reconnect=False, **cb):
    """Bound initial connection separately from an established reconnect lifetime.

    The pinned client's zero retry count permits an unbounded inner selector
    loop, even with allow_reconnect=False. A positive one-shot attempt cap plus
    the total deadline bounds that path. Keep the client before connecting so a
    failed or canceled handshake cannot lose its partially opened transport.
    """
    deadline = asyncio.get_running_loop().time() + INITIAL_CONNECT_TIMEOUT
    nats = nats_mod()
    if cb.get("error_cb") is None:
        cb["error_cb"] = _quiet_error
    opts = dict(servers=[url], name=name, max_reconnect_attempts=-1 if reconnect else 1, reconnect_time_wait=2,
                connect_timeout=INITIAL_CONNECT_TIMEOUT, allow_reconnect=reconnect, **cb)
    if creds:
        opts["user_credentials"] = os.path.expanduser(creds)
    ctx = tls_context(ca)
    if ctx is not None:
        opts["tls"] = ctx
        opts["tls_hostname"] = "localhost" if urlsplit(url).hostname in {"127.0.0.1", "localhost"} else None
        if opts["tls_hostname"] is None:
            del opts["tls_hostname"]
    if asyncio.get_running_loop().time() >= deadline:
        raise InitialConnectTimeout()
    client = _new_client(nats, urlsplit(url).scheme == "tls" or ctx is not None)
    try:
        async with asyncio.timeout_at(deadline):
            await client.connect(**opts)
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError()
    except TimeoutError as error:
        failure = InitialConnectTimeout()
        await _close_failed_connection(client, failure)
        raise failure from error
    except BaseException as error:
        await _close_failed_connection(client, error)
        raise
    return client


async def close(nc):
    """Retain owned paired-client cleanup; keep the legacy close compatibility."""
    if isinstance(getattr(nc, "_transport", None), _PairedTCPTransport):
        await _connection_cleanup(nc, sys.exception())._wait()
        return
    try:
        await nc.close()
    except Exception:  # noqa: BLE001 - preserve the legacy TLS close_notify compatibility
        pass
