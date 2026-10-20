"""Small broker helpers shared by installed test preparations."""
import asyncio
import base64
import hashlib
import secrets
import time

import nkeys

from agentmux_contracts import canonical_bytes


def _encoded(value):
    import json
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=")


def user_credential(account, publish, subscribe, *, response=None):
    """Issue one disposable fixture user under the supplied account owner."""
    key = nkeys.from_seed(nkeys.encode_seed(
        secrets.token_bytes(32), nkeys.PREFIX_BYTE_USER))
    try:
        now = int(time.time())
        claims = {"iat": now, "exp": now + 300,
            "iss": account.public_key.decode(), "sub": key.public_key.decode(),
            "name": "disposable-integration-test"}
        claims["jti"] = base64.b32encode(hashlib.new(
            "sha512_256", canonical_bytes(claims)).digest()).decode().rstrip("=")
        permissions = {"type": "user", "version": 2,
            "pub": {"allow": list(publish)}, "sub": {"allow": list(subscribe)},
            "subs": -1, "data": -1, "payload": -1}
        if response is not None:
            permissions["resp"] = response
        claims["nats"] = permissions
        message = _encoded({"typ": "JWT", "alg": "ed25519-nkey"}) + b"." + _encoded(claims)
        token = message + b"." + base64.urlsafe_b64encode(account.sign(message)).rstrip(b"=")
        return (b"-----BEGIN NATS USER JWT-----\n" + token
            + b"\n------END NATS USER JWT------\n\n"
            + b"-----BEGIN USER NKEY SEED-----\n" + key.seed
            + b"\n------END USER NKEY SEED------\n")
    finally:
        key.wipe()


async def close_client(client):
    """Close and join the original nats-py background tasks."""
    tasks = tuple(task for name in ("_reading_task", "_ping_interval_task",
        "_flusher_task", "_reconnection_task")
        if isinstance((task := getattr(client, name, None)), asyncio.Task))
    try:
        await client.close()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
