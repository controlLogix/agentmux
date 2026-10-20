"""Bounded real-TLS check for the owner-authorized provisioning caller.

This module is launched only by the existing disposable Go NATS fixture. The
fixture account seed arrives on stdin and is never placed in arguments or
output.
"""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import ssl
import sys
import traceback

import nats
import nkeys

from agentmux_contracts import canonical_bytes, payload_digest
from hub.nats_transport import new_client
from identity.application_account import ApplicationAccountAuthority
from identity.authority import AuthoritySnapshot, LedgerAuthorityReader
from identity.test_application_account import ApplicationAccountTests
from identity.test_application_service_selection import ServiceSelectionTests
from integration_owner.live_broker import close_client, user_credential
from integration_owner.operator_provisioning import (_administrator_subjects,
                                                       provision_integration_effect)
from native_security.nats_credentials import service_policy, validate_service
from native_security.secret_custody import ScopedSecretCustody, _resolved_binding
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention


STAGE = "input"


def stage(value):
    global STAGE
    STAGE = value
    print("integration operator live stage: " + value, file=sys.stderr, flush=True)


def require(value):
    if not value:
        raise AssertionError("integration_operator_live_check_failed")


def current_interval():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"), (
        now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")


def prepare_account(account_public):
    case = ApplicationAccountTests(
        methodName="test_returns_only_exact_public_references_with_signed_deadline")
    case.setUp()
    issued, expires = current_interval()
    for collection in ("transports", "issuers", "memberships", "grants",
                       "applicationAccounts", "secretReferences"):
        for item in case.record["state"].get(collection, []):
            if "issuedAt" in item:
                item["issuedAt"] = issued
            if "expiresAt" in item:
                item["expiresAt"] = expires
    account = case.record["state"]["applicationAccounts"][0]
    account["accountPublicKey"] = account_public
    case.payload["accountPublicKey"] = account_public
    case.request["payload"] = case.payload
    case.request["operation"]["payloadDigest"] = payload_digest(case.payload)
    case.request["operation"]["deadline"] = expires
    claims = case.request["ingressAttestation"]["claims"]
    claims["issuedAt"], claims["expiresAt"] = issued, expires
    case.resign()
    case.record.update(entityVersion=1, previousRevision=0, effects=[],
                       artifacts=[], repository=None)
    case.record["operation"]["expectedVersion"] = 0
    case.record["operation"]["scope"] = {
        "organizationId": "org-one", "projectId": None, "workspaceId": None}
    return case.record, canonical_bytes(case.request)


def prepare_selection(plan, account_public):
    case = ServiceSelectionTests(
        methodName="test_selection_builds_explicit_integration_effect_provisioner")
    case.setUp()
    case.add_integration()
    selected = case.value["integration"]
    selected["credentials"]["accountPublicKey"] = account_public
    selected["connection"].update(endpoint=plan["endpoint"], rootsPEM=plan["rootsPEM"],
        serverName=plan["serverName"], leafCertificateSHA256=plan["leafPin"],
        jetstreamDomain=plan["domain"])
    roots = {}
    for name in ("resources", "inventory", "credentials", "keys"):
        path = case.root / ("live-operator-" + name)
        path.mkdir(mode=0o700)
        roots[name] = path
    key = roots["keys"] / "key-backup-key.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    selected["routing"] = {"resourceDirectory": str(roots["resources"]),
        "inventoryDirectory": str(roots["inventory"]),
        "credentialDirectory": str(roots["credentials"]),
        "backupKeyDirectory": str(roots["keys"]), "backupKeyId": "backup-key",
        "backupDestinationId": "integration-backup"}
    return case, case.load()


async def run(plan):
    directory = Path(plan["directory"]).resolve()
    require(directory.is_dir())
    account = nkeys.from_seed(plan["accountSeed"].encode("ascii"))
    account_seed = plan["accountSeed"].encode("ascii")
    account_public = account.public_key.decode("ascii")
    selection_case = None
    clients = []
    denied = asyncio.Queue()
    errors = []

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=plan["rootsPEM"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    async def broker_error(error):
        if "permissions violation" in str(error).lower():
            denied.put_nowait(True)
        else:
            errors.append("broker_error")

    async def connect(raw, prefix):
        lines = raw.splitlines()
        token, seed = lines[1], lines[-2]

        def signature(nonce):
            signer = nkeys.from_seed(seed)
            try:
                return base64.b64encode(signer.sign(nonce.encode("ascii")))
            finally:
                signer.wipe()

        client = new_client(require_tls=True, leaf_certificate_sha256=plan["leafPin"])
        clients.append(client)
        await client.connect(servers=[plan["endpoint"]], tls=context,
            tls_hostname=plan["serverName"], tls_handshake_first=True,
            user_jwt_cb=lambda: token,
            signature_cb=signature, inbox_prefix=prefix, allow_reconnect=False,
            max_reconnect_attempts=0, connect_timeout=3, dont_randomize=True,
            no_echo=True, error_cb=broker_error)
        return client

    try:
        stage("fixture-authority")
        setup = await connect(user_credential(account, [">"], [">"]),
                              "_INBOX.integration_setup_0001")
        js = setup.jetstream(domain=plan["domain"], timeout=2)
        authority_scope = {"organizationId": "org-one", "projectId": None,
                           "workspaceId": None}
        authority_binding = OwnerBinding("hub-one", "identity", "authority-one",
            "identity-authority", canonical_bytes(authority_scope))
        retention = Retention(2_097_152, 262144)
        authority_info = await js.add_stream(retention.stream_config(
            stream="AUTHORITY", subject=owner_subject(authority_binding)))
        record, request = prepare_account(account_public)
        await js.publish(owner_subject(authority_binding), canonical_bytes(record),
            headers={"Nats-Expected-Last-Subject-Sequence": "0",
                     "Nats-Expected-Stream": "AUTHORITY"})
        identity_options = {"role": "identity", "hub_id": "hub-one",
            "entity_id": "authority-one", "scope": authority_scope,
            "stream": "AUTHORITY", "reply_prefix": "_INBOX.integration_identity_0001",
            "jetstream_domain": plan["domain"]}
        identity_policy = service_policy(**identity_options)
        identity_raw = user_credential(account, identity_policy.publish_subjects,
            identity_policy.subscribe_subjects,
            response=identity_policy.response_permissions)
        validate_service(identity_raw, account_public_key=account_public,
                         **identity_options)
        identity = await connect(identity_raw, identity_options["reply_prefix"])
        identity_js = identity.jetstream(domain=plan["domain"], timeout=2)
        await close_client(setup)
        clients.remove(setup)

        stage("selection-and-custody")
        selection_case, selection = prepare_selection(plan, account_public)
        authority_ledger = OwnerLedger(identity_js, stream="AUTHORITY",
            subject=owner_subject(authority_binding), binding=authority_binding,
            retention=retention, stream_identity=StreamIdentity(authority_info.created, 1))
        reader = LedgerAuthorityReader(authority_ledger, hub_id="hub-one",
            entity_id="authority-one", profile_id="profile-one",
            organization_id="org-one")
        await ApplicationAccountAuthority(reader).resolve(request)
        custody_root = selection_case.root / "live-operator-custody"
        custody_root.mkdir(mode=0o700)
        custody = ScopedSecretCustody(custody_root, reader)
        inbox = "_INBOX.integration_admin_0001"
        administrator = user_credential(account,
            _administrator_subjects(plan["domain"]), [inbox + ".>"])
        snapshot = AuthoritySnapshot(canonical_bytes(record), 1)
        now = datetime.now(timezone.utc)
        for kind, secret in (("nats-administrator-credential", administrator),
                             ("nats-account-issuer", account_seed)):
            binding = _resolved_binding(snapshot, request, kind, now)
            custody._store.provision(binding, secret)

        stage("operator-provision")
        result = await provision_integration_effect(selection, authority=reader,
            custody=custody, resolution_request=request,
            original_operation_id="live-operation")
        require(result.route_generation == 1 and result.route_streams == (result.stream,))
        require(result.effect_id.startswith("effect-") and result.stream.startswith(
            "AMX_INTEGRATION_"))

        stage("routed-credential")
        route = selection.integration_effect_inventory().current_route()
        route_client = await connect(Path(route.credential_path).read_bytes(),
            selection.service("integration")["credentials"]["replyPrefix"])
        routed = route_client.jetstream(domain=plan["domain"], timeout=.5)
        info = await routed.stream_info(result.stream)
        require(info.config.name == result.stream and info.state.messages == 0)
        try:
            await routed.stream_info("AUTHORITY")
        except nats.errors.TimeoutError:
            pass
        else:
            raise AssertionError("unrelated_authority_stream_accessible")
        await asyncio.wait_for(denied.get(), 1)
        require(not errors)
    except BaseException as error:
        trace = traceback.extract_tb(error.__traceback__)
        if trace:
            last = trace[-1]
            print("integration operator live failure location: "
                  + Path(last.filename).name + ":" + str(last.lineno),
                  file=sys.stderr, flush=True)
        raise
    finally:
        stage("cleanup")
        for client in reversed(clients):
            await close_client(client)
        account.wipe()
        del account_seed
        if selection_case is not None:
            selection_case.doCleanups()
    await asyncio.sleep(0)
    current = asyncio.current_task()
    require(not [task for task in asyncio.all_tasks()
                 if task is not current and not task.done()])
    stage("cleanup-done")
    print("integration operator broker checks passed; route and clients joined")


if __name__ == "__main__":
    try:
        plan = json.load(sys.stdin)
        asyncio.run(run(plan))
    except BaseException:
        print("integration operator broker checks failed at " + STAGE,
              file=sys.stderr)
        raise SystemExit(1) from None
