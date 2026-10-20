"""Native private-file checks for immutable secret-reference generations."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from sdk.python.tests.test_contracts import NOW, SEED
from identity.authority import AuthoritySnapshot, LedgerAuthorityReader
from identity import test_application_account as account_tests
from identity.test_authority import fixture, ref
from identity.test_transitions import ACCOUNT
from identity.transitions import transition
from native_security import secret_custody
from native_security.secret_custody import (_ImmutableSecretStore, PrivateSecret,
                                             ScopedSecretCustody, _resolved_binding)


class ImmutableSecretStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentmux-secret-custody-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.store = _ImmutableSecretStore(self.root)
        self.secret = b"SYNTHETIC-ADMIN-CREDENTIAL"
        self.binding = {
            "ref": {"id": "application-admin", "ownerHubId": "hub-one", "revision": 1},
            "kind": "nats-administrator-credential",
            "scope": {"organizationId": "org-one", "projectId": "project-one",
                      "workspaceId": None},
            "profileId": "profile-one",
            "ownerIdentityRef": {"id": "deployment-owner", "ownerHubId": "hub-one",
                                 "revision": 3},
            "accountRef": {"id": "application-account", "ownerHubId": "hub-one",
                           "revision": 1},
            "administratorTransportRef": {"id": "administrator-transport",
                                           "ownerHubId": "hub-one", "revision": 2},
            "accountPublicKey": "A" + "A" * 55,
            "issuedAt": "2026-10-17T12:00:00+00:00",
            "expiresAt": "2027-10-17T12:00:00+00:00",
            "accountIssuedAt": "2026-10-17T12:00:00+00:00",
            "accountExpiresAt": "2027-10-17T12:00:00+00:00",
        }

    def test_create_replay_and_private_result(self):
        self.assertEqual(self.store.provision(self.binding, self.secret), self.binding["ref"])
        self.assertEqual(self.store.provision(self.binding, self.secret), self.binding["ref"])
        self.assertEqual(self.store.recover(self.binding), self.binding["ref"])
        private = self.store.resolve(self.binding)
        self.assertIs(type(private), PrivateSecret)
        self.assertEqual(private.private_copy(), self.secret)
        self.assertNotIn(self.secret.decode(), repr(private))
        with self.assertRaises(TypeError):
            json.dumps(private)
        with self.assertRaises(TypeError):
            pickle.dumps(private)
        path = self.root / "hub-one" / self.binding["ref"]["id"] / "1.secret"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_rotation_is_a_distinct_immutable_generation(self):
        self.store.provision(self.binding, self.secret)
        rotated = {**self.binding, "ref": {**self.binding["ref"], "revision": 2}}
        next_secret = b"SYNTHETIC-ROTATED-CREDENTIAL"
        self.store.provision(rotated, next_secret)
        self.assertEqual(self.store.resolve(self.binding).private_copy(), self.secret)
        self.assertEqual(self.store.resolve(rotated).private_copy(), next_secret)
        files = sorted(p.name for p in (self.root / "hub-one" / "application-admin").iterdir())
        self.assertEqual(files, ["1.secret", "2.secret"])

    def test_same_reference_never_changes_meaning(self):
        self.store.provision(self.binding, self.secret)
        with self.assertRaisesRegex(ContractError, "^secret_custody_recovery_required$") as raised:
            self.store.provision(self.binding, b"SYNTHETIC-SUBSTITUTE")
        self.assertNotIn("SYNTHETIC", str(raised.exception))
        self.assertEqual(self.store.resolve(self.binding).private_copy(), self.secret)

    def test_binding_changes_cannot_select_existing_bytes(self):
        self.store.provision(self.binding, self.secret)
        changes = [
            {"profileId": "profile-two"},
            {"accountPublicKey": "A" + "B" * 55},
            {"kind": "nats-account-issuer"},
            {"scope": {**self.binding["scope"], "projectId": "project-two"}},
            {"ownerIdentityRef": {**self.binding["ownerIdentityRef"], "revision": 4}},
            {"accountRef": {**self.binding["accountRef"], "revision": 2}},
            {"administratorTransportRef": {
                **self.binding["administratorTransportRef"], "revision": 3}},
            {"expiresAt": "2028-10-17T12:00:00+00:00"},
            {"accountExpiresAt": "2028-10-17T12:00:00+00:00"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(
                    ContractError, "^secret_custody_changed$"):
                self.store.resolve({**self.binding, **change})

    def test_partial_or_tampered_generation_requires_explicit_recovery(self):
        owner = self.root / "hub-one"
        owner.mkdir(mode=0o700)
        namespace = owner / self.binding["ref"]["id"]
        namespace.mkdir(mode=0o700)
        path = namespace / "1.secret"
        path.write_bytes(b"partial")
        path.chmod(0o600)
        with self.assertRaisesRegex(ContractError, "^secret_custody_recovery_required$"):
            self.store.provision(self.binding, self.secret)
        with self.assertRaisesRegex(ContractError, "^secret_custody_changed$"):
            self.store.resolve(self.binding)
        self.assertEqual(path.read_bytes(), b"partial")

    def test_unsafe_root_namespace_and_secret_file_are_refused(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ContractError, "^secret_custody_native_refused$"):
            _ImmutableSecretStore(self.root)
        self.root.chmod(0o700)
        self.store.provision(self.binding, self.secret)
        path = self.root / "hub-one" / self.binding["ref"]["id"] / "1.secret"
        path.chmod(0o644)
        with self.assertRaisesRegex(ContractError, "^secret_custody_changed$"):
            self.store.resolve(self.binding)

    def test_missing_wrong_or_oversized_values_are_bounded(self):
        with self.assertRaisesRegex(ContractError, "^secret_custody_unavailable$"):
            self.store.resolve(self.binding)
        for secret in (b"", b"x" * 65_537, "text"):
            with self.subTest(size=len(secret)), self.assertRaisesRegex(
                    ContractError, "^secret_custody_invalid$"):
                self.store.provision(self.binding, secret)

    def test_symlink_namespace_and_file_are_refused(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (self.root / "hub-one").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ContractError, "^secret_custody_unavailable$"):
            self.store.provision(self.binding, self.secret)

    def test_rejected_namespace_admission_closes_its_descriptor(self):
        root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        opened = []
        real_open = os.open
        def capture(path, *args, **kwargs):
            fd = real_open(path, *args, **kwargs)
            if path == "hub-one":
                opened.append(fd)
            return fd
        try:
            with patch.object(secret_custody.os, "open", side_effect=capture), patch.object(
                    secret_custody, "_admit", side_effect=ContractError("synthetic_refusal")):
                with self.assertRaisesRegex(ContractError, "^synthetic_refusal$"):
                    secret_custody._open_namespace(root, "hub-one", create=True)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
        finally:
            os.close(root)


class ScopedSecretCustodyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentmux-scoped-secret-custody-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.reader = object.__new__(LedgerAuthorityReader)
        self.reader._hub = "hub-one"
        self.custody = ScopedSecretCustody(self.root, self.reader)
        self.secret = b"SYNTHETIC-OWNER-ONLY-CREDENTIAL"

    @staticmethod
    def resolution_case():
        case = account_tests.ApplicationAccountTests(
            methodName="test_returns_only_exact_public_references_with_signed_deadline")
        case.setUp()
        snapshot = AuthoritySnapshot(canonical_bytes(case.record), 23)
        request = canonical_bytes(case.request)
        return case, snapshot, request

    @staticmethod
    def proposal_case(*, review_required=False, approved=False):
        record, request = fixture()
        state = record["state"]
        project = {"organizationId": "org-one", "projectId": "project-one", "workspaceId": None}
        organization = {"organizationId": "org-one", "projectId": None, "workspaceId": None}
        interval = {"status": "active", "issuedAt": "2026-10-09T12:00:00Z",
                    "expiresAt": "2026-10-09T12:10:00Z"}
        admin = {"ref": ref("account-admin"), "principalId": "application-account-admin",
                 "kind": "service", "status": "active", "externalIdentity": None}
        state["identities"].append(admin)
        transport = copy.deepcopy(state["transports"][0])
        transport.update(ref=ref("account-admin-transport"), identityRef=admin["ref"])
        state["transports"].append(transport)
        state["memberships"].append({"ref": ref("account-admin-member"),
            "identityRef": admin["ref"], "scope": project, "status": "active"})
        credential = {"ref": ref("account-admin-credential"),
            "kind": "nats-administrator-credential", "scope": project,
            "profileId": "profile-one", "ownerIdentityRef": admin["ref"], **interval}
        issuer = {"ref": ref("account-issuer-secret"), "kind": "nats-account-issuer",
            "scope": project, "profileId": "profile-one", "ownerIdentityRef": admin["ref"], **interval}
        account = {"ref": ref("application-account"), "profileId": "profile-one",
            "scope": project, "accountPublicKey": ACCOUNT,
            "administratorIdentityRef": admin["ref"],
            "administratorTransportRef": transport["ref"],
            "administratorCredentialRef": credential["ref"], "accountIssuerRef": issuer["ref"],
            **interval}
        payload = {"authorityId": "authority-one", "record": account, "previousRef": None,
            "administratorCredential": {"record": credential, "previousRef": None},
            "accountIssuer": {"record": issuer, "previousRef": None}}
        operation = request["operation"]
        operation.update(scope=organization, expectedVersion=record["entityVersion"],
            grantRef=ref("account-set-grant"), approvalRefs=[], payloadDigest=payload_digest(payload))
        operation["caller"]["authenticatedIdentityRef"] = ref("human")
        operation["effectiveActorRef"] = ref("human")
        state["memberships"][0]["scope"] = organization
        state["grants"][0].update(ref=ref("account-set-grant"), scope=organization,
            contractId="identity-application-account-set", resourceId="authority-one",
            decision="review-required" if review_required else "allowed")
        if approved:
            approval_grant = copy.deepcopy(state["grants"][0])
            approval_grant.update(ref=ref("account-approval-grant"),
                contractId="identity-approve", resourceId="account-set-grant", decision="allowed")
            state["grants"].append(approval_grant)
            approval = {"ref": ref("account-approval"), "grantRef": ref("account-set-grant"),
                "approverRef": ref("human"), "approverGrantRef": approval_grant["ref"],
                "payloadDigest": operation["payloadDigest"],
                "audience": {"hubId": "hub-one", "serviceId": "identity-owner"},
                "operationId": operation["operationId"],
                "expectedVersion": operation["expectedVersion"], "decision": "approved",
                "status": "active", "issuedAt": "2026-10-09T12:00:00Z",
                "expiresAt": "2026-10-09T12:10:00Z"}
            state["approvals"].append(approval)
            operation["approvalRefs"] = [approval["ref"]]
        request.update(contractId="identity-application-account-set",
            destinationServiceId="identity-owner", payload=payload)
        claims = request["ingressAttestation"]["claims"]
        claims.update(operation=copy.deepcopy(operation), contractId=request["contractId"])
        claims["audience"]["serviceId"] = "identity-owner"
        request["ingressAttestation"]["signature"] = sign_claims(claims, SEED)
        return record, request

    async def test_resolve_rechecks_current_account_before_returning_bytes(self):
        _case, snapshot, request = self.resolution_case()
        binding = _resolved_binding(snapshot, request, "nats-administrator-credential", NOW)
        self.custody._store.provision(binding, self.secret)
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(side_effect=[snapshot, snapshot])) as current:
            private = await self.custody.resolve(request,
                kind="nats-administrator-credential", now=NOW)
        self.assertEqual(private.private_copy(), self.secret)
        self.assertEqual(current.await_count, 2)

    async def test_revocation_between_read_and_return_refuses_secret(self):
        case, snapshot, request = self.resolution_case()
        binding = _resolved_binding(snapshot, request, "nats-administrator-credential", NOW)
        self.custody._store.provision(binding, self.secret)
        case.record["state"]["secretReferences"][0].update(status="revoked")
        revoked = AuthoritySnapshot(canonical_bytes(case.record), 24)
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(side_effect=[snapshot, revoked])):
            with self.assertRaises(ContractError):
                await self.custody.resolve(request,
                    kind="nats-administrator-credential", now=NOW)

    async def test_offline_authority_never_reads_retained_secret_bytes(self):
        _case, snapshot, request = self.resolution_case()
        binding = _resolved_binding(snapshot, request, "nats-administrator-credential", NOW)
        self.custody._store.provision(binding, self.secret)
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(side_effect=TimeoutError("offline"))), patch.object(
                              self.custody._store, "resolve",
                              side_effect=AssertionError("private read must not run")) as resolve:
            with self.assertRaisesRegex(TimeoutError, "^offline$"):
                await self.custody.resolve(request,
                    kind="nats-administrator-credential", now=NOW)
        resolve.assert_not_called()

    async def test_cross_organization_request_is_refused_before_private_read(self):
        case, snapshot, _request = self.resolution_case()
        cross_scope = {"organizationId": "org-two", "projectId": "project-one",
                       "workspaceId": None}
        case.payload["scope"] = cross_scope
        case.request["payload"] = case.payload
        case.request["operation"]["scope"] = cross_scope
        case.request["operation"]["payloadDigest"] = payload_digest(case.payload)
        case.resign()
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(return_value=snapshot)), patch.object(
                              self.custody._store, "resolve",
                              side_effect=AssertionError("private read must not run")):
            with self.assertRaises(ContractError):
                await self.custody.resolve(canonical_bytes(case.request),
                    kind="nats-administrator-credential", now=NOW)

    async def test_cross_user_request_is_refused_before_private_read(self):
        case, snapshot, _request = self.resolution_case()
        case.request["operation"]["caller"]["authenticatedIdentityRef"] = ref("other-human")
        case.request["operation"]["effectiveActorRef"] = ref("other-human")
        case.resign()
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(return_value=snapshot)), patch.object(
                              self.custody._store, "resolve",
                              side_effect=AssertionError("private read must not run")):
            with self.assertRaises(ContractError):
                await self.custody.resolve(canonical_bytes(case.request),
                    kind="nats-administrator-credential", now=NOW)

    async def test_signed_current_owner_operation_provisions_proposed_generation(self):
        record, request = self.proposal_case()
        snapshot = AuthoritySnapshot(canonical_bytes(record), 17)
        raw = canonical_bytes(request)
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(side_effect=[snapshot, snapshot])) as current:
            reference = await self.custody.provision(raw,
                kind="nats-account-issuer", secret=self.secret, now=NOW)
        self.assertEqual(reference, ref("account-issuer-secret"))
        self.assertEqual(current.await_count, 2)

    async def test_authority_change_after_provision_refuses_success_and_retains_generation(self):
        record, request = self.proposal_case()
        first = AuthoritySnapshot(canonical_bytes(record), 17)
        changed_record = copy.deepcopy(record)
        changed_record["entityVersion"] += 1
        changed = AuthoritySnapshot(canonical_bytes(changed_record), 18)
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(side_effect=[first, changed])):
            with self.assertRaisesRegex(ContractError, "^secret_custody_not_authorized$"):
                await self.custody.provision(canonical_bytes(request),
                    kind="nats-account-issuer", secret=self.secret, now=NOW)
        path = self.root / "hub-one" / "account-issuer-secret" / "1.secret"
        self.assertTrue(path.is_file())

    async def test_review_required_without_exact_approval_never_writes(self):
        record, request = self.proposal_case(review_required=True)
        snapshot = AuthoritySnapshot(canonical_bytes(record), 17)
        with patch.object(LedgerAuthorityReader, "current", new=AsyncMock(return_value=snapshot)):
            with self.assertRaisesRegex(ContractError, "^secret_custody_not_authorized$"):
                await self.custody.provision(canonical_bytes(request),
                    kind="nats-account-issuer", secret=self.secret, now=NOW)
        self.assertEqual(list(self.root.iterdir()), [])

    async def test_review_required_with_exact_current_approval_provisions(self):
        record, request = self.proposal_case(review_required=True, approved=True)
        snapshot = AuthoritySnapshot(canonical_bytes(record), 17)
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(side_effect=[snapshot, snapshot])):
            reference = await self.custody.provision(canonical_bytes(request),
                kind="nats-account-issuer", secret=self.secret, now=NOW)
        self.assertEqual(reference, ref("account-issuer-secret"))

    async def test_stale_set_operation_never_writes(self):
        record, request = self.proposal_case()
        record["entityVersion"] += 1
        snapshot = AuthoritySnapshot(canonical_bytes(record), 18)
        with patch.object(LedgerAuthorityReader, "current", new=AsyncMock(return_value=snapshot)):
            with self.assertRaisesRegex(ContractError, "^secret_custody_not_authorized$"):
                await self.custody.provision(canonical_bytes(request),
                    kind="nats-account-issuer", secret=self.secret, now=NOW)
        self.assertEqual(list(self.root.iterdir()), [])

    async def test_rotated_current_reference_never_resolves_old_bytes(self):
        case, original, old_request = self.resolution_case()
        old_binding = _resolved_binding(original, old_request,
            "nats-administrator-credential", NOW)
        self.custody._store.provision(old_binding, self.secret)
        state = case.record["state"]
        account = copy.deepcopy(state["applicationAccounts"][0])
        credential = copy.deepcopy(state["secretReferences"][0])
        issuer = copy.deepcopy(state["secretReferences"][1])
        previous_account, previous_credential, previous_issuer = (
            copy.deepcopy(account["ref"]), copy.deepcopy(credential["ref"]),
            copy.deepcopy(issuer["ref"]))
        for item in (account, credential, issuer):
            item["ref"]["revision"] += 1
        account["administratorCredentialRef"] = credential["ref"]
        account["accountIssuerRef"] = issuer["ref"]
        case.record["state"] = transition(state, "identity-application-account-set", {
            "authorityId": "authority-one", "record": account,
            "previousRef": previous_account,
            "administratorCredential": {"record": credential,
                                         "previousRef": previous_credential},
            "accountIssuer": {"record": issuer, "previousRef": previous_issuer},
        }, hub_id="hub-one")
        case.record["entityVersion"] += 1
        case.payload.update(accountRef=account["ref"])
        case.request["payload"] = case.payload
        case.request["operation"]["payloadDigest"] = payload_digest(case.payload)
        case.resign()
        rotated = AuthoritySnapshot(canonical_bytes(case.record), 24)
        new_request = canonical_bytes(case.request)
        new_binding = _resolved_binding(rotated, new_request,
            "nats-administrator-credential", NOW)
        next_secret = b"SYNTHETIC-ROTATED-OWNER-CREDENTIAL"
        self.custody._store.provision(new_binding, next_secret)
        with patch.object(LedgerAuthorityReader, "current", new=AsyncMock(return_value=rotated)):
            with self.assertRaises(ContractError):
                await self.custody.resolve(old_request,
                    kind="nats-administrator-credential", now=NOW)
        with patch.object(LedgerAuthorityReader, "current",
                          new=AsyncMock(side_effect=[rotated, rotated])):
            private = await self.custody.resolve(new_request,
                kind="nats-administrator-credential", now=NOW)
        self.assertEqual(private.private_copy(), next_secret)

    async def test_nonledger_authority_cannot_construct_custody(self):
        with self.assertRaisesRegex(ContractError, "^secret_custody_authority_required$"):
            ScopedSecretCustody(self.root, object())


if __name__ == "__main__":
    unittest.main()
