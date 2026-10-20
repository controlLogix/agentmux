"""Short-lived installed owner command for one integration effect route.

The native owner supplies the already admitted application-service selection,
one protected custody directory, and one signed account-resolution request over
stdin.  This process opens only the selected identity ledger for current reads,
performs the provisioning action, emits a non-secret receipt, and exits.
"""
from __future__ import annotations

import asyncio
import base64
import os
from pathlib import Path
import re
import stat
import sys
import time

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.nats_transport import new_client
from identity.application_service_selection import (load_application_service_selection,
    validate_protected_host_account)
from identity.authority import LedgerAuthorityReader
from native_security.descriptor_admission import check_descriptor, DescriptorPurpose
from native_security.nats_credentials import validate_service
from native_security.secret_custody import ScopedSecretCustody
from state_owner.ledger import OwnerLedger, owner_subject

from .operator_provisioning import _close_client, provision_integration_effect


_FIELDS = {"schemaVersion", "kind", "selection", "selectionSHA256",
    "hostPolicy", "ownerUid", "workspaces", "kernelScope",
    "protectedHostAccount", "custodyRoot", "originalOperationId",
    "resolutionRequestBase64", "leaseFd"}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


async def _joined(function, *args):
    """Do not abandon a protected blocking operation on cancellation."""
    worker = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        await asyncio.wait({worker})
        return worker.result()
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.wait({worker})
            except asyncio.CancelledError:
                continue
        if not worker.cancelled():
            worker.exception()
        raise


def _fail(code="integration_operator_command_invalid"):
    raise ContractError(code) from None


def _outside(path, workspaces):
    value = Path(path)
    if (not value.is_absolute() or str(value) != os.path.normpath(str(value))
            or "\x00" in str(value) or "\r" in str(value) or "\n" in str(value)):
        _fail()
    resolved = Path(os.path.realpath(value))
    if any(resolved.is_relative_to(os.path.realpath(root)) for root in workspaces):
        _fail()
    return value


def _request(raw):
    try:
        value = strict_loads(raw)
        if (type(value) is not dict or set(value) != _FIELDS
                or value["schemaVersion"] != "1.0.0"
                or value["kind"] != "integration-effect-provision"
                or type(value["ownerUid"]) is not int
                or value["ownerUid"] != os.getuid()
                or type(value["leaseFd"]) is not int or value["leaseFd"] != 3
                or type(value["selectionSHA256"]) is not str
                or _DIGEST.fullmatch(value["selectionSHA256"]) is None
                or type(value["workspaces"]) is not list
                or not 1 <= len(value["workspaces"]) <= 16
                or any(type(path) is not str for path in value["workspaces"])
                or type(value["kernelScope"]) is not dict):
            raise ValueError
        validate_protected_host_account(value["protectedHostAccount"])
        _outside(value["custodyRoot"], value["workspaces"])
        encoded = value["resolutionRequestBase64"]
        if type(encoded) is not str or not 0 < len(encoded) <= 87384:
            raise ValueError
        request = base64.b64decode(encoded, validate=True)
        if not request or len(request) > 65536:
            raise ValueError
        strict_loads(request)
        operation_id = value["originalOperationId"]
        if (type(operation_id) is not str
                or re.fullmatch(r"[a-z][a-z0-9_-]{0,95}", operation_id) is None):
            raise ValueError
        return value, request, operation_id
    except ContractError:
        raise
    except Exception:
        _fail()


def _lease(fd, owner_uid):
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError
        check_descriptor(fd, purpose=DescriptorPurpose.PRIVATE_FILE,
                         deadline=time.monotonic() + 1)
    except Exception:
        _fail("integration_operator_lease_invalid")


async def _identity_reader(selection):
    selected = selection.service("identity")
    raw = await _joined(selection.read_credential_bytes, "identity")
    admitted = validate_service(raw,
        account_public_key=selected["credentials"]["accountPublicKey"],
        **selection.service_policy_inputs("identity"))
    if admitted.public_key != selected["credentials"]["userPublicKey"]:
        _fail("integration_operator_identity_binding_invalid")
    client = new_client(require_tls=True,
        leaf_certificate_sha256=selected["connection"]["leafCertificateSHA256"])

    def signature(nonce):
        key = nkeys.from_seed(admitted.seed)
        try:
            return base64.b64encode(key.sign(nonce.encode()))
        finally:
            key.wipe()

    failed = False
    async def quiet(_error=None):
        nonlocal failed
        failed = True

    options = selection.tls_options("identity")
    options.update(name="agentmux-integration-operator-authority", allow_reconnect=False,
        max_reconnect_attempts=1, reconnect_time_wait=0, connect_timeout=3,
        dont_randomize=True, no_echo=True,
        inbox_prefix=selected["credentials"]["replyPrefix"],
        user_jwt_cb=lambda: admitted.jwt.encode(), signature_cb=signature,
        disconnected_cb=quiet, reconnected_cb=quiet, closed_cb=quiet, error_cb=quiet)
    try:
        async with asyncio.timeout(5):
            await client.connect(**options)
        if client.is_connected is not True or failed:
            _fail("integration_operator_identity_unavailable")
        binding = selection.binding("identity")
        ledger = OwnerLedger(client.jetstream(
            domain=selected["connection"]["jetstreamDomain"]),
            stream=selected["ledger"]["stream"], subject=owner_subject(binding),
            binding=binding, retention=selection.retention("identity"),
            stream_identity=selection.stream_identity("identity"),
            max_history_records=selected["ledger"]["history"]["maxRecords"],
            max_history_bytes=selected["ledger"]["history"]["maxBytes"])
        policy = selection.policy
        reader = LedgerAuthorityReader(ledger,
            hub_id=policy["kernelScope"]["hubId"], entity_id=policy["authorityId"],
            profile_id=policy["kernelScope"]["profileId"],
            organization_id=policy["organizationId"])
        return client, reader
    except BaseException:
        await _close_client(client)
        raise


async def execute(raw):
    """Execute one closed stdin command and return its non-secret receipt."""
    value, resolution_request, operation_id = _request(raw)
    _lease(3, value["ownerUid"])
    selection = await _joined(lambda: load_application_service_selection(
        value["selection"], expected_digest=value["selectionSHA256"],
        host_policy=value["hostPolicy"], owner_uid=value["ownerUid"],
        workspaces=value["workspaces"], kernel_scope=value["kernelScope"],
        protected_host_account=value["protectedHostAccount"]))
    client = None
    try:
        client, authority = await _identity_reader(selection)
        custody = await _joined(ScopedSecretCustody,
            value["custodyRoot"], authority)
        result = await provision_integration_effect(selection, authority=authority,
            custody=custody, resolution_request=resolution_request,
            original_operation_id=operation_id)
        return canonical_bytes({"schemaVersion": "1.0.0",
            "kind": "integration-effect-provisioned", "effectId": result.effect_id,
            "stream": result.stream, "routeGeneration": result.route_generation,
            "routeStreams": list(result.route_streams),
            "routerCredentialDigest": result.router_credential_digest})
    finally:
        if client is not None:
            await _close_client(client)


def main():
    """Run only as the protected installed child, with no command arguments."""
    try:
        raw = sys.stdin.buffer.read(131073)
        if not raw or len(raw) > 131072:
            _fail()
        result = asyncio.run(execute(raw))
        sys.stdout.buffer.write(result + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        sys.stderr.write("Integration provisioning could not be completed.\n")
        return 1

