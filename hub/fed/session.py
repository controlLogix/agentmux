"""Own local consumers and watchers for one legacy federation connection.

This is resource ownership for trusted Python plugins, not a restricted plugin
context or an identity/grant authority. Durable consumers and KV data remain
owned by the existing federation services.
"""
from __future__ import annotations

import asyncio

from hub.store import HubError


SESSION_CLOSE_TIMEOUT = 5


class SessionCleanupFailure(HubError):
    """Keep the original cleanup attempt and its private cause reachable."""

    def __init__(self, session, cause):
        super().__init__("federation session cleanup is incomplete; reconnect is blocked")
        self.session = session
        self.cause = cause


def _subscription_tasks(resource):
    """The pinned NATS client cancels these tasks but does not join them.

    KeyWatcher wraps PushSubscription, which wraps Subscription. Pull consumers
    have one wrapper. Keep their exact task handles before public unsubscribe
    removes the subscription; never discover or cancel unrelated loop tasks.
    """
    tasks, seen = set(), set()
    while resource is not None and id(resource) not in seen:
        seen.add(id(resource))
        task = getattr(resource, "_wait_for_msgs_task", None)
        if isinstance(task, asyncio.Task):
            tasks.add(task)
        state = getattr(resource, "_jsi", None)
        for name in ("_hbtask", "_fctask"):
            task = getattr(state, name, None)
            if isinstance(task, asyncio.Task):
                tasks.add(task)
        pending = getattr(resource, "_pending_next_msgs_calls", None)
        if isinstance(pending, dict):
            tasks.update(task for task in pending.values() if isinstance(task, asyncio.Task))
        resource = getattr(resource, "_sub", None)
    return tasks


def _subscription_closed(resource):
    seen = set()
    while resource is not None and id(resource) not in seen:
        seen.add(id(resource))
        if getattr(resource, "_closed", False) is True:
            return True
        resource = getattr(resource, "_sub", None)
    return False


class FederationSession:
    def __init__(self):
        self.closing = False
        self.work_subscriptions = {}
        self._tasks = {}
        self._resources = {}
        self._acquisitions = set()
        self._client_tasks = set()
        self.close_task = None
        self.failure = None

    def check_open(self):
        if self.closing:
            raise HubError("federation session is closing")

    def start_task(self, name, coroutine):
        if self.closing or name in self._tasks:
            coroutine.close()
            raise HubError("federation session task is already owned or closing")
        task = asyncio.create_task(coroutine, name=f"federation:{name}")
        self._tasks[name] = task
        return task

    def tasks(self):
        return tuple(self._tasks.values())

    def jetstream(self, client):
        from hub.fed.owned_nats import OwnedJetStream
        client._agentmux_session = self
        return OwnedJetStream(client, self)

    async def acquire(self, coroutine, own):
        """Retain acquisition through cancellation, including its returned handle."""
        if self.closing:
            coroutine.close()
            raise HubError("federation session is closing")

        async def run():
            return own(await coroutine)

        task = asyncio.create_task(run(), name="federation:resource-acquisition")
        self._acquisitions.add(task)
        # A cancelled caller may never read the outcome. Keep unfinished setup
        # for the session's join, but do not retain completed retry failures and
        # their tracebacks for the lifetime of a healthy connection. Successful
        # setup has already registered its resource before this callback runs.
        def completed(done):
            if not done.cancelled():
                done.exception()
            self._acquisitions.discard(done)

        task.add_done_callback(completed)
        # wait leaves the owned task running on caller cancellation without
        # shield's Python 3.14 exception-reporting callback.
        await asyncio.wait({task})
        return task.result()

    def start_client_task(self, coroutine, name="consumer-recreation"):
        if self.closing:
            coroutine.close()
            return None
        task = asyncio.create_task(coroutine, name=f"federation:{name}")
        self._client_tasks.add(task)

        def completed(done):
            if not done.cancelled():
                done.exception()
            self._client_tasks.discard(done)

        task.add_done_callback(completed)
        return task

    def own_subscription(self, subscription):
        return self._own(subscription, subscription.unsubscribe)

    def own_watcher(self, watcher):
        return self._own(watcher, watcher.stop)

    def _own(self, resource, close):
        # An acquisition already in flight may finish while shutdown starts.
        # Retain that returned resource before the owning task can yield again.
        base, depth, seen = resource, 0, set()
        while getattr(base, "_sub", None) is not None and id(base) not in seen:
            seen.add(id(base))
            base, depth = base._sub, depth + 1
        previous = self._resources.get(id(base))
        # Prefer KeyWatcher.stop over its nested PushSubscription.unsubscribe;
        # the early raw Subscription record protects partial setup failures.
        if previous is None or depth >= previous[0]:
            self._resources[id(base)] = (depth, base, resource, close)
        return resource

    async def close(self):
        if self.close_task is None:
            self.closing = True
            self.close_task = asyncio.create_task(self._close(), name="federation:session-cleanup")
            self.close_task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            _, pending = await asyncio.wait({self.close_task}, timeout=SESSION_CLOSE_TIMEOUT)
            if pending:
                raise TimeoutError()
            self.close_task.result()
        except asyncio.CancelledError:
            # The caller may leave; this session still owns the same cleanup.
            raise
        except BaseException as error:
            if self.failure is None:
                self.failure = SessionCleanupFailure(self, error)
            raise self.failure from error

    async def _close(self):
        tasks = self.tasks()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Setup keeps running after its caller is cancelled so that the returned
        # handle can be registered. New acquisitions are refused once closing.
        if self._acquisitions:
            await asyncio.gather(*self._acquisitions, return_exceptions=True)

        # Joining creators first makes the owned resource list final. Capture
        # client tasks before unsubscribe can remove their handles.
        client_tasks = set(self._client_tasks)
        for _, _, resource, _ in self._resources.values():
            client_tasks.update(_subscription_tasks(resource))
        for task in client_tasks:
            if not task.done():
                task.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)

        failures = []
        for _, _, resource, close in self._resources.values():
            try:
                await close()
            except BaseException as error:
                # A closed connection has no usable local inbox. Its exact
                # transport is still closed and checked by Federation/conn.
                from nats.errors import BadSubscriptionError, ConnectionClosedError
                already_closed = isinstance(error, BadSubscriptionError) and _subscription_closed(resource)
                if not isinstance(error, ConnectionClosedError) and not already_closed:
                    failures.append(error)
        if failures:
            raise BaseExceptionGroup("private federation session cleanup causes", failures)
        self.work_subscriptions.clear()
