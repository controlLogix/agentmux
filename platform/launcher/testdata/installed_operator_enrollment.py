"""Prepare one disposable installed integration-operator request.

The Go deployment fixture owns the broker and process waits. This module adds
only the exact application account, custody, and routed integration selection
needed by the installed operator command.
"""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import stat
import sys

from agentmux_contracts import (ContractError, canonical_bytes, sign_claims,
                                strict_loads, validate)
from identity.application_enrollment import _read_material
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import LedgerAuthorityReader
from identity.ingress import EnrolledIngress
from installed_broker_helpers import close_client, user_credential
from integration_owner.operator_provisioning import _administrator_subjects
from native_security.secret_custody import ScopedSecretCustody, _resolved_binding
from state_owner.ledger import OwnerLedger, owner_subject

from installed_service_enrollment import (Preparation, PreparationFailure,
    admit_plan, authority_switch_custody_directory, digest, keep_owner,
    hold_before_reporting, private_bytes, stamp)


ORIGINAL_OPERATION_ID = "fixture_operator_operation"
PREPARATION_FAILURE_PREFIX = "installed operator preparation failure: "
PREPARATION_HOLD = "installed service preparation held; original owner retained"
_FAILURE_CATEGORIES = frozenset({
    "application_account_binding_mismatch",
    "application_account_not_authorized",
    "application_account_resolution_invalid",
    "application_account_unavailable",
    "attestation_time_invalid",
    "audience_mismatch",
    "authority_organization_mismatch",
    "authority_owner_mismatch",
    "authority_reference_ambiguous",
    "authority_time_invalid",
    "contract_destination_mismatch",
    "contract_kind_mismatch",
    "envelope_binding_mismatch",
    "installed_operator_preparation_broker_failure",
    "installed_operator_resolution_refused",
    "schema_invalid",
    "semantic_invalid",
    "secret_custody_busy",
    "secret_custody_changed",
    "secret_custody_invalid",
    "secret_custody_native_refused",
    "secret_custody_not_authorized",
    "secret_custody_recovery_required",
    "secret_custody_unavailable",
    "secret_custody_write_uncertain",
    "signature_invalid",
})
_FAILURE_STAGES = frozenset({
    "materials", "base_provision", "authority_resolution", "secret_custody",
    "binding_resolution", "custody_write", "result_write",
})


class OperatorPreparation(Preparation):
    """Add one current account grant and its private custody material."""

    def materials(self, now):
        self.stage = "materials"
        super().materials(now)
        # Generate the selection supported by the exact installed package.
        # Older operators receive their separate scoped custody root through
        # the native command contract and have no authority-switch selection.
        if authority_switch_custody_directory is None:
            self.value.pop("authoritySwitch", None)

    def make_permit(self, now):
        routing = {}
        for name, field in (("operator-resources", "resourceDirectory"),
                            ("operator-inventory", "inventoryDirectory"),
                            ("operator-credentials", "credentialDirectory"),
                            ("operator-backup-keys", "backupKeyDirectory")):
            path = self.directory / name
            path.mkdir(mode=0o700)
            routing[field] = str(path)
        backup_key = Path(routing["backupKeyDirectory"]) / "key-fixture_operator_key.key"
        private_bytes(backup_key, os.urandom(32))
        routing.update(backupKeyId="fixture_operator_key",
                       backupDestinationId="fixture_operator_backup")
        self.value["integration"]["routing"] = routing
        self.account_ref = self.ref("application_account")
        self.administrator_credential_ref = self.ref("administrator_credential")
        self.account_issuer_ref = self.ref("account_issuer_secret")
        super().make_permit(now)

    def extend_initial_authority(self, state):
        interval = {**self.interval, "status": "active"}
        state["memberships"].append({"ref": self.ref("operator_membership"),
            "identityRef": self.ref("client"), "scope": self.project_scope,
            "status": "active"})
        state["grants"].append({"ref": self.ref("operator_resolve_grant"),
            "callerRef": self.ref("client"), "actorRef": self.ref("client"),
            "scope": self.project_scope,
            "contractId": "identity-application-account-resolve",
            "resourceId": self.account_ref["id"], "decision": "allowed",
            "delegationRef": None, "definitionTarget": None, **interval})
        state["secretReferences"] = [
            {"ref": self.administrator_credential_ref,
             "kind": "nats-administrator-credential", "scope": self.project_scope,
             "profileId": self.plan["host"]["kernelScope"]["profileId"],
             "ownerIdentityRef": self.ref("client"), **interval},
            {"ref": self.account_issuer_ref, "kind": "nats-account-issuer",
             "scope": self.project_scope,
             "profileId": self.plan["host"]["kernelScope"]["profileId"],
             "ownerIdentityRef": self.ref("client"), **interval},
        ]
        state["applicationAccounts"] = [{"ref": self.account_ref,
            "profileId": self.plan["host"]["kernelScope"]["profileId"],
            "scope": self.project_scope,
            "accountPublicKey": self.account.public_key.decode("ascii"),
            "administratorIdentityRef": self.ref("client"),
            "administratorTransportRef": self.ref("client_transport"),
            "administratorCredentialRef": self.administrator_credential_ref,
            "accountIssuerRef": self.account_issuer_ref, **interval}]

    def _signed_ingress_request(self, now):
        key = strict_loads(_read_material(self.client_key, return_bytes=True))
        seed = base64.b64decode(key["seed"], validate=True)
        claims = {"purpose": "agentmux-client-possession-v1",
            "hubId": self.plan["host"]["kernelScope"]["hubId"],
            "profileId": self.plan["host"]["kernelScope"]["profileId"],
            "transportRef": self.ref("client_transport"),
            "grantRef": self.ref("operator_resolve_grant"),
            "operationId": "fixture_account_resolution",
            "expectedVersion": 0,
            "contractId": "identity-application-account-resolve",
            "payload": {"authorityId": self.authority,
                "accountRef": self.account_ref,
                "profileId": self.plan["host"]["kernelScope"]["profileId"],
                "scope": self.project_scope,
                "accountPublicKey": self.account.public_key.decode("ascii")},
            "approvalRefs": [], "issuedAt": stamp(now - timedelta(seconds=1)),
            "expiresAt": stamp(now + timedelta(seconds=45)),
            "authorityId": self.authority}
        request = {"schemaVersion": "1.0.0", "claims": claims,
                   "signature": sign_claims(claims, seed)}
        validate("identity-ingress-request", request)
        return canonical_bytes(request)

    async def provision(self):
        self.stage = "base_provision"
        result = await super().provision()
        selection = ApplicationServiceSelection(canonical_bytes(self.value))
        identity = selection.service("identity")
        js = self.client.jetstream(domain=self.plan["broker"]["domain"], timeout=3)
        ledger = OwnerLedger(js, stream=identity["ledger"]["stream"],
            subject=owner_subject(selection.binding("identity")),
            binding=selection.binding("identity"), retention=selection.retention("identity"),
            stream_identity=selection.stream_identity("identity"))
        reader = LedgerAuthorityReader(ledger,
            hub_id=self.plan["host"]["kernelScope"]["hubId"],
            entity_id=self.authority,
            profile_id=self.plan["host"]["kernelScope"]["profileId"],
            organization_id=self.organization)
        now = datetime.now(timezone.utc)
        self.stage = "authority_resolution"
        ingress = self._signed_ingress_request(now)
        admitted = await EnrolledIngress(reader,
            issuer_ref=identity["issuer"]["issuerRef"],
            signing_seed=selection.load_signing_seed("identity")).admit(ingress,
                cancellation_ref=self.ref("operator_cancel"))
        if admitted.envelope is None or admitted.decision.outcome != "allowed":
            raise ContractError("installed_operator_resolution_refused")
        self.stage = "secret_custody"
        custody_root = self.directory / "operator-custody"
        custody_root.mkdir(mode=0o700)
        custody = ScopedSecretCustody(custody_root, reader)
        snapshot = await reader.current()
        administrator = user_credential(self.account,
            _administrator_subjects(self.plan["broker"]["domain"]),
            ["_INBOX.installed_operator_admin_0001.>"])
        account_seed = self.plan["broker"]["accountSeed"].encode("ascii")
        for kind, secret in (("nats-administrator-credential", administrator),
                             ("nats-account-issuer", account_seed)):
            self.stage = "binding_resolution"
            binding = _resolved_binding(snapshot, admitted.envelope, kind,
                                        datetime.now(timezone.utc))
            self.stage = "custody_write"
            custody._store.provision(binding, secret)
        self.stage = "result_write"
        request_path = self.directory / "operator-resolution-request.json"
        private_bytes(request_path, admitted.envelope)
        service_path = self.directory / "service-selection.json"
        result.update(serviceSelection=str(service_path),
            serviceSelectionSHA256=digest(canonical_bytes(self.value)),
            custodyRoot=str(custody_root), resolutionRequest=str(request_path),
            resolutionRequestSHA256=digest(admitted.envelope),
            originalOperationId=ORIGINAL_OPERATION_ID)
        return result


async def prepare(plan):
    directory, policy = admit_plan(plan)
    owner = OperatorPreparation(plan, directory, policy)
    try:
        owner.materials(datetime.now(timezone.utc))
        result = await owner.provision()
        await close_client(owner.client)
        if owner.protocol_error:
            raise ContractError("installed_operator_preparation_broker_failure")
        owner.account.wipe()
        return result
    except BaseException as error:
        owner.failures.append(error)
        raise PreparationFailure(owner, error) from None


def failure_category(owner, error):
    stage = getattr(owner, "stage", "materials")
    if stage not in _FAILURE_STAGES:
        stage = "materials"
    if isinstance(error, ContractError) and str(error) in _FAILURE_CATEGORIES:
        return stage + ":" + str(error)
    if isinstance(error, ContractError):
        return stage + ":contract_failure"
    return stage + ":unexpected_failure"


async def release_failed_preparation(failure):
    """Wait for the original parent to authorize cleanup through inherited fd 3."""
    try:
        info = os.fstat(3)
        if not stat.S_ISFIFO(info.st_mode):
            raise OSError("release descriptor is not a pipe")
    except OSError:
        await keep_owner(failure)
        return
    try:
        await asyncio.to_thread(os.read, 3, 1)
    finally:
        os.close(3)
    owner = failure.owner
    try:
        if owner.client is not None:
            await close_client(owner.client)
    finally:
        if owner.account is not None:
            owner.account.wipe()
    raise ContractError("installed_operator_preparation_failed")


async def main():
    raw = sys.stdin.buffer.read(131073)
    if len(raw) > 131072:
        raise ContractError("installed_operator_preparation_input_invalid")
    try:
        result = await prepare(strict_loads(raw))
    except PreparationFailure as failure:
        print(PREPARATION_FAILURE_PREFIX + failure_category(failure.owner, failure.cause),
              file=sys.stderr, flush=True)
        await hold_before_reporting(
            lambda: print(PREPARATION_HOLD, file=sys.stderr, flush=True),
            lambda: release_failed_preparation(failure))
    else:
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseException:
        print("installed operator preparation input refused", file=sys.stderr)
        raise SystemExit(1) from None
