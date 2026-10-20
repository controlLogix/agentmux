"""Owner-authorized entry point for one routed integration effect.

The caller supplies a signed application-account resolution request and the
already admitted identity authority and secret custody owners.  This module
resolves current private material, opens one short-lived administrator
connection, provisions one exact effect route, and closes every resource it
opens.  It creates no identity grant, approval, account, or backup key.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import secrets

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.nats_transport import PairedTCPTransport, new_client
from identity.application_account import ApplicationAccountAuthority
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import LedgerAuthorityReader
from native_security.nats_credentials import (_JWT, _base32, _decode64, _validate,
                                               service_policy)
from native_security.secret_custody import ScopedSecretCustody


def _fail(code="integration_operator_provisioning_invalid"):
    raise ContractError(code) from None


@dataclass(frozen=True, slots=True, repr=False)
class IntegrationProvisioningResult:
    """Non-secret result from one completed operator provisioning call."""
    effect_id: str
    stream: str
    route_generation: int
    route_streams: tuple[str, ...]
    router_credential_digest: str

    def __repr__(self):
        return "<IntegrationProvisioningResult non-secret>"


@dataclass(frozen=True, slots=True, repr=False)
class _AdministratorPolicy:
    publish_subjects: tuple[str, ...]
    subscribe_subjects: tuple[str, ...]

    def __repr__(self):
        return "<_AdministratorPolicy private>"


def _administrator_subjects(domain):
    prefixes = (("$JS.API.",) if domain is None
                else ("$JS.API.", "$JS." + domain + ".API."))
    return tuple(sorted(prefix + operation
        for prefix in prefixes
        for operation in ("STREAM.CREATE.*", "STREAM.INFO.*")))


def _administrator_credential(raw, *, account_public_key, domain):
    """Admit only the two stream operations and one credential-owned inbox."""
    try:
        tokens = _JWT.findall(raw)
        if len(tokens) != 1:
            raise ValueError
        claims = strict_loads(_decode64(tokens[0].split(b".")[1]))
        allowed = claims["nats"]["sub"]["allow"]
        if (type(allowed) is not list or len(allowed) != 1
                or type(allowed[0]) is not str
                or re.fullmatch(r"_INBOX\.[A-Za-z0-9_-]{16,64}\.>",
                                allowed[0]) is None):
            raise ValueError
        expires = claims.get("exp")
        if type(expires) is not int or expires <= 0:
            raise ValueError
        policy = _AdministratorPolicy(_administrator_subjects(domain), (allowed[0],))
        credential = _validate(raw, account_public_key=account_public_key,
            publish_subjects=(), subscribe_subjects=(), publisher=policy)
        return credential, allowed[0][:-2]
    except Exception:
        _fail("integration_operator_administrator_credential_invalid")


def _account_seed(private, account_public_key):
    key = None
    try:
        seed = private.private_copy()
        _base32(seed, 36)
        prefix, raw = nkeys.decode_seed(seed)
        if prefix != nkeys.PREFIX_BYTE_ACCOUNT or len(raw) != 32:
            raise ValueError
        key = nkeys.from_seed(seed)
        if key.public_key.decode("ascii") != account_public_key:
            raise ValueError
        return seed
    except Exception:
        _fail("integration_operator_account_issuer_invalid")
    finally:
        if key is not None:
            key.wipe()


def _encoded(value):
    return base64.urlsafe_b64encode(canonical_bytes(value)).rstrip(b"=")


def _issue_service_credential(account_seed, inputs, *, valid_until, now):
    account = user = None
    try:
        account = nkeys.from_seed(account_seed)
        user = nkeys.from_seed(nkeys.encode_seed(
            secrets.token_bytes(32), nkeys.PREFIX_BYTE_USER))
        policy = service_policy(**inputs)
        issued = int(now.timestamp())
        expires = int(valid_until.timestamp())
        if expires <= issued:
            _fail("integration_operator_account_authority_expired")
        claims = {"iat": issued, "exp": expires,
            "iss": account.public_key.decode("ascii"),
            "sub": user.public_key.decode("ascii"),
            "name": "agentmux-integration-router"}
        claims["jti"] = base64.b32encode(
            hashlib.new("sha512_256", canonical_bytes(claims)).digest()
        ).decode("ascii").rstrip("=")
        claims["nats"] = {"type": "user", "version": 2,
            "pub": {"allow": list(policy.publish_subjects)},
            "sub": {"allow": list(policy.subscribe_subjects)},
            "resp": policy.response_permissions,
            "subs": -1, "data": -1, "payload": -1}
        message = _encoded({"typ": "JWT", "alg": "ed25519-nkey"}) + b"." + _encoded(claims)
        token = message + b"." + base64.urlsafe_b64encode(account.sign(message)).rstrip(b"=")
        return (b"-----BEGIN NATS USER JWT-----\n" + token
            + b"\n------END NATS USER JWT------\n\n"
            + b"-----BEGIN USER NKEY SEED-----\n" + user.seed
            + b"\n------END USER NKEY SEED------\n")
    except ContractError:
        raise
    except Exception:
        _fail("integration_operator_credential_issue_failed")
    finally:
        if user is not None:
            user.wipe()
        if account is not None:
            account.wipe()


def _same_resolution(first, second):
    fields = ("account_ref", "account_public_key", "profile_id", "scope",
        "administrator_identity_ref", "administrator_transport_ref",
        "administrator_credential_ref", "account_issuer_ref")
    return all(getattr(first, field) == getattr(second, field) for field in fields)


def _check_selection(selection, resolution):
    value, selected = selection.policy, selection.service("integration")
    if (selected.get("routing") is None
            or resolution.profile_id != value["kernelScope"]["profileId"]
            or resolution.scope != selected["ledger"]["scope"]
            or resolution.account_public_key
               != selected["credentials"]["accountPublicKey"]):
        _fail("integration_operator_account_selection_mismatch")


async def _close_client(client, *, _timeout=5):
    paired_transport = getattr(client, "_transport", None)
    task = asyncio.create_task(client.close(),
        name="integration-operator-client-cleanup")
    task.add_done_callback(
        lambda done: None if done.cancelled() else done.exception())
    cancelled = False
    deadline = asyncio.get_running_loop().time() + _timeout
    timed_out = False
    while not task.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            timed_out = True
            task.cancel()
            break
        try:
            await asyncio.wait({task}, timeout=remaining)
        except asyncio.CancelledError:
            # Finish the one original close before propagating cancellation.
            cancelled = True
    if timed_out:
        # nats-py close is cancellation-responsive. Join that exact task before
        # returning the fixed cleanup failure; never leave a detached owner.
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
            except BaseException:
                break
        try:
            task.result()
        except BaseException:
            pass
        if isinstance(paired_transport, PairedTCPTransport):
            owned = tuple(dict.fromkeys(child for child in
                (paired_transport.prior_close_task,
                 paired_transport.current_close_task)
                if isinstance(child, asyncio.Task)))
            for child in owned:
                if not child.done():
                    child.cancel()
            while any(not child.done() for child in owned):
                try:
                    await asyncio.wait(owned)
                except asyncio.CancelledError:
                    cancelled = True
            for child in owned:
                try:
                    child.result()
                except BaseException:
                    pass
        _fail("integration_operator_cleanup_pending")
    try:
        task.result()
    except BaseException:
        _fail("integration_operator_cleanup_pending")
    if cancelled:
        raise asyncio.CancelledError


async def provision_integration_effect(selection, *, authority, custody,
        resolution_request, original_operation_id, now=None, _client_factory=new_client):
    """Provision one exact effect through current owner-authorized custody.

    ``resolution_request`` is the signed identity-owner request.  The operation
    ID selects one deterministic effect aggregate; it is not authority and is
    never used to select account or secret material.
    """
    if (not isinstance(selection, ApplicationServiceSelection)
            or type(authority) is not LedgerAuthorityReader
            or type(custody) is not ScopedSecretCustody
            or custody._authority is not authority
            or type(resolution_request) is not bytes
            or type(original_operation_id) is not str
            or not original_operation_id
            or not callable(_client_factory)):
        _fail()
    if (now is not None and (not isinstance(now, datetime) or now.tzinfo is None
            or now.utcoffset() != timezone.utc.utcoffset(now))):
        _fail()
    def current_time():
        return datetime.now(timezone.utc) if now is None else now
    account_authority = ApplicationAccountAuthority(authority)
    # Preserve the authority owners' post-read clock sampling in production.
    # A fixed clock is accepted only for deterministic offline verification.
    first = await account_authority.resolve(resolution_request, now=now)
    _check_selection(selection, first)
    admin_private = await custody.resolve(resolution_request,
        kind="nats-administrator-credential", now=now)
    issuer_private = await custody.resolve(resolution_request,
        kind="nats-account-issuer", now=now)
    second = await account_authority.resolve(resolution_request, now=now)
    if not _same_resolution(first, second):
        _fail("integration_operator_account_changed")
    _check_selection(selection, second)
    selected = selection.service("integration")
    domain = selected["connection"]["jetstreamDomain"]
    administrator, inbox = _administrator_credential(admin_private.private_copy(),
        account_public_key=second.account_public_key, domain=domain)
    checked_issuer_seed = _account_seed(issuer_private, second.account_public_key)
    del checked_issuer_seed
    del admin_private, issuer_private

    client = resources = None
    broker_errors = []
    try:
        client = _client_factory(require_tls=True,
            leaf_certificate_sha256=selected["connection"]["leafCertificateSHA256"])

        def signature(nonce):
            if type(nonce) is not str or not 0 < len(nonce) <= 4096:
                _fail("integration_operator_broker_nonce_invalid")
            key = nkeys.from_seed(administrator.seed)
            try:
                return base64.b64encode(key.sign(nonce.encode("ascii")))
            finally:
                key.wipe()

        async def broker_error(_error):
            # The NATS default callback prints raw broker errors. Retain only a
            # fixed local signal so private server text never reaches stderr.
            broker_errors.append(True)

        options = selection.tls_options("integration")
        options.update(name="agentmux-integration-provisioner", allow_reconnect=False,
            max_reconnect_attempts=0, connect_timeout=3, dont_randomize=True,
            no_echo=True, inbox_prefix=inbox,
            user_jwt_cb=lambda: administrator.jwt.encode("ascii"),
            signature_cb=signature, error_cb=broker_error)
        async with asyncio.timeout(5):
            await client.connect(**options)
        if client.is_connected is not True:
            _fail("integration_operator_connection_unavailable")
        jetstream = client.jetstream() if domain is None else client.jetstream(domain=domain)

        async def issue(inputs):
            current = await account_authority.resolve(
                resolution_request, now=now)
            if not _same_resolution(second, current):
                _fail("integration_operator_account_changed")
            private = await custody.resolve(resolution_request,
                kind="nats-account-issuer", now=now)
            seed = _account_seed(private, current.account_public_key)
            del private
            try:
                return _issue_service_credential(seed, inputs,
                    valid_until=current.valid_until, now=current_time())
            finally:
                del seed

        routing = selected["routing"]
        provisioner = selection.integration_effect_provisioner(jetstream,
            resource_directory=routing["resourceDirectory"],
            inventory_directory=routing["inventoryDirectory"],
            credential_directory=routing["credentialDirectory"],
            backup_key_directory=routing["backupKeyDirectory"],
            backup_key_id=routing["backupKeyId"],
            backup_destination_id=routing["backupDestinationId"],
            commit_ref=selected["ledger"]["checkpoint"]["commitRef"],
            credential_issuer=issue)
        resources = await provisioner.provision(original_operation_id)
        route = provisioner.current_route()
        if broker_errors:
            _fail("integration_operator_broker_error")
        return IntegrationProvisioningResult(resources.effect_id, resources.stream,
            route.generation, route.streams, route.credential_digest)
    finally:
        cleanup = None
        if resources is not None:
            try:
                resources.history.close()
            except BaseException as error:
                cleanup = error
        if client is not None:
            try:
                await _close_client(client)
            except asyncio.CancelledError:
                raise
            except BaseException as error:
                cleanup = error if cleanup is None else cleanup
        if cleanup is not None:
            _fail("integration_operator_cleanup_pending")
