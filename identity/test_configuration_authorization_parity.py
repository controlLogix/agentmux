"""Local and linked self-hosted identities use the same authorization rules."""
from __future__ import annotations

import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import (ContractError, canonical_bytes, payload_digest,
                                sign_claims, strict_loads, validate)
from identity import test_application_account as account_tests
from identity import test_native_subscriptions as subscription_tests
from identity.authority import AuthoritySnapshot, LedgerAuthorityReader, evaluate_snapshot
from identity.test_authority import NOW, SEED, fixture, ref
from native_security.secret_custody import ScopedSecretCustody


EXTERNAL_IDENTITY = {
    "issuer": "https://identity.example/realms/team",
    "subject": "keycloak-user-184",
}


def _configured_authorization(contract, destination, resource_id, payload,
                              external_identity):
    record, envelope = fixture()
    record["state"]["identities"][0]["externalIdentity"] = copy.deepcopy(
        external_identity)
    envelope.update(contractId=contract, destinationServiceId=destination,
                    payload=copy.deepcopy(payload))
    operation = envelope["operation"]
    operation["payloadDigest"] = payload_digest(payload)
    grant = record["state"]["grants"][0]
    grant.update(contractId=contract, resourceId=resource_id)
    claims = envelope["ingressAttestation"]["claims"]
    claims.update(operation=copy.deepcopy(operation), contractId=contract)
    claims["audience"]["serviceId"] = destination
    envelope["ingressAttestation"]["signature"] = sign_claims(claims, SEED)
    validate(contract, payload)
    validate("message-envelope", envelope)
    return record, envelope


class ConfigurationAuthorizationParityTests(unittest.TestCase):
    """Compare the same signed operations under both supported identity modes."""

    cases = (
        ("task-inspect", "task-owner", "task-one", {"taskId": "task-one"}),
        ("capability-workspace-read", "workspace-owner", "task-one", {
            "resourceRef": ref("task-one"), "input": {"relativePath": "src/main.py"},
        }),
        ("capability-artifact-read", "artifact-owner", "task-one", {
            "resourceRef": ref("task-one"),
            "input": {"digest": "sha256:" + "f" * 64},
        }),
    )

    @staticmethod
    def _decision(record, envelope):
        return evaluate_snapshot(AuthoritySnapshot(canonical_bytes(record), 17),
            canonical_bytes(envelope), audience={
                "hubId": "hub-one", "serviceId": envelope["destinationServiceId"]},
            now=NOW)

    @staticmethod
    def _resign(envelope):
        claims = envelope["ingressAttestation"]["claims"]
        claims["operation"] = copy.deepcopy(envelope["operation"])
        envelope["ingressAttestation"]["signature"] = sign_claims(claims, SEED)

    def test_commands_files_and_artifacts_keep_exact_scope(self):
        for mode, external_identity in (
                ("local", None), ("self-hosted", EXTERNAL_IDENTITY)):
            for contract, destination, resource, payload in self.cases:
                with self.subTest(mode=mode, contract=contract):
                    record, envelope = _configured_authorization(
                        contract, destination, resource, payload, external_identity)
                    self.assertEqual(self._decision(record, envelope).outcome, "allowed")
                    for scope in (
                            {"organizationId": "org-one", "projectId": "other-project",
                             "workspaceId": None},
                            {"organizationId": "other-org", "projectId": None,
                             "workspaceId": None}):
                        changed = copy.deepcopy(envelope)
                        changed["operation"]["scope"] = scope
                        self._resign(changed)
                        self.assertEqual(
                            self._decision(record, changed).reason,
                            "membership_unavailable")

    def test_forged_actor_is_never_taken_from_payload_or_principal_text(self):
        with self.assertRaises(ContractError):
            validate("task-inspect", {"taskId": "task-one", "actor": "administrator"})
        for mode, external_identity in (
                ("local", None), ("self-hosted", EXTERNAL_IDENTITY)):
            with self.subTest(mode=mode):
                record, envelope = _configured_authorization(
                    "task-inspect", "task-owner", "task-one",
                    {"taskId": "task-one"}, external_identity)
                envelope["operation"]["caller"]["principalId"] = "administrator"
                self._resign(envelope)
                self.assertEqual(
                    self._decision(record, envelope).reason,
                    "identity_binding_mismatch")


class ConfigurationSecretParityTests(unittest.IsolatedAsyncioTestCase):
    """A linked external identity cannot widen a retained secret reference."""

    async def test_cross_user_project_and_organization_refuse_before_private_read(self):
        for mode, external_identity in (
                ("local", None), ("self-hosted", EXTERNAL_IDENTITY)):
            for boundary in ("user", "project", "organization"):
                with self.subTest(mode=mode, boundary=boundary):
                    case = account_tests.ApplicationAccountTests(
                        "test_returns_only_exact_public_references_with_signed_deadline")
                    case.setUp()
                    case.record["state"]["identities"][0]["externalIdentity"] = (
                        copy.deepcopy(external_identity))
                    if boundary == "user":
                        other_ref = ref("other-human")
                        other_external_identity = None if external_identity is None else {
                            "issuer": external_identity["issuer"],
                            "subject": "keycloak-user-185",
                        }
                        case.record["state"]["identities"].append({
                            "ref": other_ref,
                            "principalId": "user-two",
                            "kind": "human",
                            "status": "active",
                            "externalIdentity": other_external_identity,
                        })
                        case.record["state"]["memberships"].append({
                            "ref": ref("other-member"),
                            "identityRef": other_ref,
                            "scope": copy.deepcopy(case.scope),
                            "status": "active",
                        })
                        other_transport = copy.deepcopy(
                            case.record["state"]["transports"][0])
                        other_transport.update(
                            ref=ref("other-transport"), identityRef=other_ref)
                        case.record["state"]["transports"].append(other_transport)
                        case.request["operation"]["caller"][
                            "authenticatedIdentityRef"] = other_ref
                        case.request["operation"]["caller"]["principalId"] = "user-two"
                        case.request["operation"]["effectiveActorRef"] = other_ref
                        case.request["ingressAttestation"]["claims"][
                            "authenticatedTransportRef"] = other_transport["ref"]
                    else:
                        scope = copy.deepcopy(case.scope)
                        key = "projectId" if boundary == "project" else "organizationId"
                        scope[key] = "other-project" if boundary == "project" else "other-org"
                        case.payload["scope"] = scope
                        case.request["payload"] = case.payload
                        case.request["operation"]["scope"] = scope
                        case.request["operation"]["payloadDigest"] = payload_digest(case.payload)
                    case.resign()
                    snapshot = AuthoritySnapshot(canonical_bytes(case.record), 23)
                    with tempfile.TemporaryDirectory(
                            prefix="agentmux-configuration-secret-parity-") as directory:
                        root = Path(directory).resolve()
                        root.chmod(0o700)
                        reader = object.__new__(LedgerAuthorityReader)
                        reader._hub = "hub-one"
                        custody = ScopedSecretCustody(root, reader)
                        with patch.object(LedgerAuthorityReader, "current",
                                new=AsyncMock(return_value=snapshot)), patch.object(
                                    custody._store, "resolve",
                                    side_effect=AssertionError(
                                        "private bytes must not be read")) as private_read:
                            with self.assertRaises(ContractError):
                                await custody.resolve(canonical_bytes(case.request),
                                    kind="nats-administrator-credential", now=NOW)
                        private_read.assert_not_called()


class ConfigurationSubscriptionParityTests(subscription_tests.NativeSubscriptionTests):
    """Run the actual native subscription route with a linked human identity."""

    test_actual_producer_event_admits_new_revision_with_original_lifetime = None
    test_existing_maximum_schema_reference_fits_signed_native_frames = None
    test_wrong_source_schema_owner_or_stream_refuses_preparation = None
    test_event_wrong_owner_schema_or_old_revision_refuses = None
    test_current_producer_revocation_refuses_original_event = None
    test_current_subscriber_denial_and_owner_revocation_refuse = None
    test_expired_original_subscription_cannot_be_renewed_by_fresh_native_call = None

    async def test_linked_identity_keeps_the_native_subscription_scope(self):
        self.record["state"]["identities"][0]["externalIdentity"] = copy.deepcopy(
            EXTERNAL_IDENTITY)
        self.js.messages[0].data = canonical_bytes(self.record)
        opening = await self.prepare()
        self.inp["eventEnvelopeBytes"] = await self.event()
        admitted = await self.admit()
        payload = strict_loads(base64.b64decode(
            admitted["claims"]["result"]["payloadBytes"]))
        self.assertEqual(payload, self.event_payload)
        self.assertLessEqual(admitted["claims"]["validUntil"],
                             opening["claims"]["validUntil"])


if __name__ == "__main__":
    unittest.main()
