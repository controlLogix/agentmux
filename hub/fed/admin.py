"""Circle administration that needs a NATS connection (deploy/nats/circle.sh calls this).

  python -m hub.fed.admin provision --url U --creds admin.creds [--ca ca.pem] [--replicas N]
  python -m hub.fed.admin push --url U --creds sys.creds [--ca ca.pem] --jwt account.jwt

provision is idempotent: it creates missing resources and refuses policy differences.
Existing data and policies require a separate, explicit migration.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from hub.fed import conn


class ProvisionFailure(RuntimeError):
    """A bounded failure with a safe next action for the administrator."""


PROVISION_CLOSE_TIMEOUT = 5


class ProvisionCleanupFailure(ProvisionFailure):
    """Keep exact cleanup ownership and causes for an explicit bounded retry."""

    def __init__(self, client, close_task, operation_error, operation="provision"):
        super().__init__(
            f"{operation} connection cleanup incomplete; finish owned connection cleanup before retrying")
        self.client = client
        self.close_task = close_task
        self.operation_error = operation_error
        self.cleanup_errors = []

    async def _wait(self):
        try:
            # A deadline must not abandon or cancel the one owned close attempt.
            await asyncio.wait_for(asyncio.shield(self.close_task), PROVISION_CLOSE_TIMEOUT)
        except BaseException as error:
            self.cleanup_errors.append(error)
            causes = ([self.operation_error] if self.operation_error is not None else []) + self.cleanup_errors
            raise self from BaseExceptionGroup("provision cleanup causes", causes)

    async def retry_close(self):
        # A pinned client's first close may consume its transport before failing.
        # Calling close again can return without completing that cleanup.
        # Await the same owned task; a completed failure remains a failure.
        await self._wait()


async def _close_provision(client, operation_error, operation="provision"):
    cleanup = ProvisionCleanupFailure(client, asyncio.create_task(client.close()), operation_error, operation)
    await cleanup._wait()


async def _ignore_broker_error(error):
    # nats-py otherwise writes raw connection errors to stderr. The caller
    # receives the failure below without exposing endpoints or credentials.
    pass


class LayoutMismatch(RuntimeError):
    """An existing resource needs a deliberate migration, not an automatic update."""


def _check_policy(actual, expected, fields):
    differences = []
    for field in fields:
        old, new = getattr(actual, field), getattr(expected, field)
        if field == "subjects":
            old, new = sorted(old or []), sorted(new or [])
        if field in ("max_age", "duplicate_window"):
            old, new = old or 0, new or 0
        if old != new:
            differences.append(field)
    if differences:
        # Only declared names and field names enter diagnostics, never broker values.
        raise LayoutMismatch(
            f"storage policy differs for {expected.name}: {', '.join(differences)}; "
            "keep existing data and use a reviewed migration before provisioning")


async def provision(url, creds, ca, replicas=1):
    conn.nats_mod()
    from nats.js.api import RetentionPolicy, StorageType, StreamConfig, DiscardPolicy, KeyValueConfig
    from nats.js.errors import NotFoundError

    if type(replicas) is not int or not 1 <= replicas <= 5:
        raise ValueError("replicas must be an integer from 1 to 5")
    nc = None
    stage = "connecting"
    try:
        async with asyncio.timeout(30):
            nc = await conn.connect(url, creds, ca, "agentmux-admin", error_cb=_ignore_broker_error)
            stage = "reading storage policies"
            js = nc.jetstream(timeout=5)
            missing = []
            made = []
            policies = []
            # Inspect the whole layout before creating anything. A known mismatch
            # must not leave unrelated additions behind.
            for name, (subjects, retention, max_age) in conn.STREAMS.items():
                cfg = StreamConfig(name=name, subjects=subjects,
                                   retention=RetentionPolicy.WORK_QUEUE if retention == "workqueue" else RetentionPolicy.LIMITS,
                                   storage=StorageType.FILE, max_age=max_age, num_replicas=replicas,
                                   duplicate_window=conn.DUPE_WINDOW_S, discard=DiscardPolicy.OLD)
                fields = ("subjects", "retention", "storage", "max_age", "num_replicas", "duplicate_window", "discard")
                policies.append((cfg, fields))
                try:
                    info = await js.stream_info(name)
                except NotFoundError:
                    missing.append(("stream", name, cfg))
                    continue
                _check_policy(info.config, cfg, fields)
                made.append(f"stream {name} (exists)")
            for bucket, (history, ttl) in conn.BUCKETS.items():
                cfg = KeyValueConfig(bucket=bucket, history=history, ttl=ttl or None,
                                     replicas=replicas, storage=StorageType.FILE)
                # A KV bucket is a stream. Read its policy directly so an invalid
                # bucket or authorization error is never mistaken for absence.
                expected = StreamConfig(name="KV_" + bucket, subjects=["$KV." + bucket + ".>"],
                                        retention=RetentionPolicy.LIMITS, storage=StorageType.FILE,
                                        max_age=ttl, num_replicas=replicas,
                                        max_msgs_per_subject=history, discard=DiscardPolicy.NEW)
                fields = ("subjects", "retention", "storage", "max_age", "num_replicas", "max_msgs_per_subject", "discard")
                policies.append((expected, fields))
                try:
                    info = await js.stream_info(expected.name)
                except NotFoundError:
                    missing.append(("kv", bucket, cfg))
                    continue
                _check_policy(info.config, expected, fields)
                made.append(f"kv {bucket} (exists)")
            stage = "creating missing storage"
            for kind, name, cfg in missing:
                if kind == "stream":
                    await js.add_stream(cfg)
                else:
                    await js.create_key_value(cfg)
                made.append(f"{kind} {name} (created)")
            stage = "verifying provisioned storage policies"
            # Creation replies and earlier reads cannot establish the final
            # policy. Recheck every resource before reporting success.
            for expected, fields in policies:
                info = await js.stream_info(expected.name)
                _check_policy(info.config, expected, fields)
            return made
    except (LayoutMismatch, conn.ConnectionCleanupFailure):
        raise
    except Exception as error:
        if stage == "connecting":
            action = "check the endpoint, trusted CA and current account credentials"
        else:
            action = "check broker availability and storage permissions, then rerun; existing data is kept"
        raise ProvisionFailure(f"provision failed while {stage}; {action}") from error
    finally:
        if nc is not None:
            # Even interrupted provisioning owns its connection. No reset or
            # rollback deletes data; rerunning fills only the missing resources.
            await _close_provision(nc, sys.exception())


async def push(url, creds, ca, jwt_path):
    """Send an account JWT through the authenticated system account, with owned cleanup."""
    nc = None
    try:
        async with asyncio.timeout(30):
            with open(jwt_path, encoding="ascii") as source:
                jwt = source.read(1024 * 1024 + 1).strip()
            if not jwt or len(jwt) > 1024 * 1024:
                raise ValueError("account JWT is empty or too large")
            nc = await conn.connect(url, creds, ca, "agentmux-admin-push", error_cb=_ignore_broker_error)
            reply = await nc.request("$SYS.REQ.CLAIMS.UPDATE", jwt.encode("ascii"), timeout=5)
            if len(reply.data) > 64 * 1024:
                raise ValueError("account update reply exceeds its bound")
            data = json.loads(reply.data or b"{}")
            if not isinstance(data, dict) or data.get("error") or not isinstance(data.get("data"), dict):
                raise ValueError("account update was not accepted")
            outcome = data["data"]
            if outcome.get("error") or outcome.get("code") != 200:
                raise ValueError("account update was not accepted")
            return data
    except (conn.MissingDependency, conn.ConnectionCleanupFailure):
        raise
    except Exception as error:
        raise ProvisionFailure(
            "account update failed; check the endpoint, trusted CA, system credentials, writable account resolver and signed account JWT") from error
    finally:
        if nc is not None:
            await _close_provision(nc, sys.exception(), "account update")


def main(argv):
    ap = argparse.ArgumentParser(prog="hub.fed.admin")
    ap.add_argument("verb", choices=["provision", "push"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--creds", required=True)
    ap.add_argument("--ca")
    ap.add_argument("--replicas", type=int, default=1)
    ap.add_argument("--jwt")
    a = ap.parse_args(argv)
    try:
        if a.verb == "provision":
            for line in asyncio.run(provision(a.url, a.creds, a.ca, a.replicas)):
                print(line)
        else:
            asyncio.run(push(a.url, a.creds, a.ca, a.jwt))
            # Broker reply text is not a safe output contract. In particular, a
            # refused or malicious response must never echo the supplied JWT.
            print(json.dumps({"updated": True}))
    except (conn.MissingDependency, conn.ConnectionCleanupFailure, LayoutMismatch, ProvisionFailure, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
