"""Current authority for the dashboard and orchestration owner routes."""
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import AuthoritySnapshot, DASHBOARD_COMMANDS, evaluate_snapshot
from identity.ingress import EnrolledIngress
from identity.test_authority import NOW, SEED, fixture, ref
from identity.test_service import _Clock


DESTINATIONS = {
    "dashboard": "dashboard-owner",
    "orchestration": "orchestration-owner",
}


def dashboard_payload(contract):
    common = {"resourceRef": ref("dashboard-one"), "target": "/api/board/config",
              "action": "config", "bodyDigest": "sha256:" + "a" * 64}
    if contract == "dashboard-command":
        return {**common, "requestId": "operation-one"}
    if contract == "dashboard-outcome-query":
        return {**common, "originalOperationId": "original-operation",
                "originalPayloadDigest": "sha256:" + "b" * 64}
    result = {**common, "journalRef": ref("dashboard-journal"),
              "originalOperationId": "original-operation",
              "originalPayloadDigest": "sha256:" + "b" * 64,
              "claimRef": ref("dashboard-claim")}
    if contract == "dashboard-effect-complete":
        result.update(observationId="dashboard-observation", outcome="applied")
    return result


def orchestration_payload(contract):
    common = {"resourceRef": ref("orchestration-one")}
    if contract == "orchestration-command":
        return {**common, "environmentRef": ref("environment-one"),
                "input": {"command": "run-complete", "runId": "abcdef"}}
    if contract == "orchestration-outcome-query":
        return {**common, "originalOperationId": "original-operation",
                "originalPayloadDigest": "sha256:" + "c" * 64}
    result = {**common, "journalRef": ref("orchestration-journal"),
              "claimRef": ref("orchestration-claim"),
              "originalOperationId": "original-operation",
              "originalPayloadDigest": "sha256:" + "c" * 64,
              "candidateDigest": "sha256:" + "d" * 64}
    if contract == "orchestration-complete":
        result["observationId"] = "orchestration-observation"
    return result


class ScopedDomainAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.record, self.envelope = fixture()
        self.audience = {"hubId": "hub-one", "serviceId": "task-owner"}

    def resign(self):
        claims = self.envelope["ingressAttestation"]["claims"]
        claims.update(operation=copy.deepcopy(self.envelope["operation"]),
                      contractId=self.envelope["contractId"])
        claims["audience"] = copy.deepcopy(self.audience)
        self.envelope["ingressAttestation"]["signature"] = sign_claims(claims, SEED)

    def configure(self, contract, payload, *, service=False, original=False):
        destination = DESTINATIONS[contract.split("-", 1)[0]]
        self.envelope.update(contractId=contract, destinationServiceId=destination,
                             payload=copy.deepcopy(payload))
        operation = self.envelope["operation"]
        version_ref = (payload["journalRef"]
            if contract in ("dashboard-dispatch", "dashboard-effect-complete",
                            "orchestration-dispatch", "orchestration-complete")
            else payload["resourceRef"])
        operation.update(expectedVersion=version_ref["revision"],
                         payloadDigest=payload_digest(payload))
        state = self.record["state"]
        grant = state["grants"][0]
        grant.update(contractId=contract, resourceId=payload["resourceRef"]["id"])
        if service:
            state["transports"][0]["identityRef"] = ref("service")
            operation["caller"] = {"principalId": "ingress", "kind": "service",
                                   "authenticatedIdentityRef": ref("service")}
            operation["effectiveActorRef"] = ref("service")
            grant.update(callerRef=ref("service"), actorRef=ref("service"))
            member = copy.deepcopy(state["memberships"][0])
            member.update(ref=ref("service-member"), identityRef=ref("service"))
            state["memberships"].append(member)
        if original:
            original_grant = copy.deepcopy(grant)
            original_grant.update(ref=ref("original-grant"),
                contractId=contract.split("-", 1)[0] + "-command")
            state["grants"].append(original_grant)
        self.audience["serviceId"] = destination
        self.resign()

    def decision(self):
        return evaluate_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 17),
            canonical_bytes(self.envelope), audience=self.audience, now=NOW)

    def test_exact_commands_and_owner_phases_use_distinct_caller_kinds(self):
        cases = (
            ("dashboard-command", dashboard_payload("dashboard-command"), False, False),
            ("dashboard-dispatch", dashboard_payload("dashboard-dispatch"), True, False),
            ("dashboard-effect-complete", dashboard_payload("dashboard-effect-complete"), True, False),
            ("dashboard-outcome-query", dashboard_payload("dashboard-outcome-query"), False, True),
            ("orchestration-command", orchestration_payload("orchestration-command"), False, False),
            ("orchestration-dispatch", orchestration_payload("orchestration-dispatch"), True, False),
            ("orchestration-complete", orchestration_payload("orchestration-complete"), True, False),
            ("orchestration-outcome-query", orchestration_payload("orchestration-outcome-query"), False, True),
        )
        for contract, payload, service, original in cases:
            with self.subTest(contract=contract):
                self.setUp()
                self.configure(contract, payload, service=service, original=original)
                self.assertEqual(self.decision().outcome, "allowed")

    def test_resource_scope_role_and_lineage_substitutions_refuse(self):
        cases = (
            ("dashboard-command", dashboard_payload("dashboard-command")),
            ("dashboard-dispatch", dashboard_payload("dashboard-dispatch")),
            ("orchestration-command", orchestration_payload("orchestration-command")),
            ("orchestration-dispatch", orchestration_payload("orchestration-dispatch")),
        )
        for contract, payload in cases:
            service = contract.endswith("dispatch")
            with self.subTest(contract=contract, change="revision"):
                self.setUp(); self.configure(contract, payload, service=service)
                self.envelope["operation"]["expectedVersion"] += 1; self.resign()
                self.assertNotEqual(self.decision().outcome, "allowed")
            with self.subTest(contract=contract, change="owner"):
                self.setUp(); self.configure(contract, payload, service=service)
                self.envelope["payload"]["resourceRef"]["ownerHubId"] = "other-hub"
                self.envelope["operation"]["payloadDigest"] = payload_digest(self.envelope["payload"])
                self.resign(); self.assertNotEqual(self.decision().outcome, "allowed")
            with self.subTest(contract=contract, change="scope"):
                self.setUp(); self.configure(contract, payload, service=service)
                self.envelope["operation"]["scope"]["projectId"] = None
                for membership in self.record["state"]["memberships"]:
                    membership["scope"] = copy.deepcopy(self.envelope["operation"]["scope"])
                self.record["state"]["grants"][0]["scope"] = copy.deepcopy(
                    self.envelope["operation"]["scope"])
                self.resign()
                self.assertEqual(self.decision().reason,
                    contract.split("-", 1)[0] + "_scope_or_version_mismatch")

    def test_query_requires_separate_grant_and_current_original_authority(self):
        for domain, payload in (("dashboard", dashboard_payload("dashboard-outcome-query")),
                                ("orchestration", orchestration_payload("orchestration-outcome-query"))):
            contract = domain + "-outcome-query"
            with self.subTest(domain=domain):
                self.setUp()
                self.configure(contract, payload, original=True)
                self.assertEqual(self.decision().outcome, "allowed")
                self.record["state"]["grants"][-1]["decision"] = "denied"
                self.assertEqual(self.decision().reason,
                                 domain + "_original_authority_unavailable")

    def test_dashboard_target_and_action_are_one_signed_binding(self):
        for contract in DASHBOARD_COMMANDS:
            service = contract in ("dashboard-dispatch", "dashboard-effect-complete")
            original = contract == "dashboard-outcome-query"
            for target, action in (("/api/runs/abcdef/review", "config"),
                                   ("/api/board/config", "run-review")):
                with self.subTest(contract=contract, target=target, action=action):
                    self.setUp()
                    payload = dashboard_payload(contract)
                    payload.update(target=target, action=action)
                    self.configure(contract, payload, service=service, original=original)
                    self.assertEqual(self.decision().reason, "dashboard_operation_binding")

    def test_phase_roles_lineage_and_selected_environment_refuse_substitution(self):
        self.configure("dashboard-dispatch", dashboard_payload("dashboard-dispatch"))
        self.assertEqual(self.decision().reason, "dashboard_operation_binding")

        self.setUp()
        self.configure("orchestration-command",
                       orchestration_payload("orchestration-command"), service=True)
        self.assertEqual(self.decision().reason, "orchestration_operation_binding")

        self.setUp()
        payload = orchestration_payload("orchestration-dispatch")
        payload["originalOperationId"] = "operation-one"
        self.configure("orchestration-dispatch", payload, service=True)
        self.assertEqual(self.decision().reason, "orchestration_operation_binding")

        self.setUp()
        payload = orchestration_payload("orchestration-command")
        payload["environmentRef"]["ownerHubId"] = "other-hub"
        self.configure("orchestration-command", payload)
        self.assertEqual(self.decision().reason, "orchestration_operation_binding")

    def test_owner_phases_bind_journal_revision_without_retargeting_resource(self):
        for contract, payload in (
                ("dashboard-dispatch", dashboard_payload("dashboard-dispatch")),
                ("dashboard-effect-complete", dashboard_payload("dashboard-effect-complete")),
                ("orchestration-dispatch", orchestration_payload("orchestration-dispatch")),
                ("orchestration-complete", orchestration_payload("orchestration-complete"))):
            with self.subTest(contract=contract):
                self.setUp()
                payload["journalRef"]["revision"] = 2
                self.configure(contract, payload, service=True)
                self.assertEqual(self.decision().outcome, "allowed")
                self.envelope["operation"]["expectedVersion"] = 1
                self.resign()
                self.assertEqual(self.decision().reason,
                    contract.split("-", 1)[0] + "_scope_or_version_mismatch")


class ScopedDomainIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_routes_use_fixed_owner_destinations(self):
        for contract, payload in (("dashboard-command", dashboard_payload("dashboard-command")),
                                  ("orchestration-command", orchestration_payload("orchestration-command"))):
            with self.subTest(contract=contract):
                record, _ = fixture()
                state = record["state"]
                state["grants"][0].update(contractId=contract,
                    resourceId=payload["resourceRef"]["id"])

                class Reader:
                    async def current(self_inner):
                        return AuthoritySnapshot(canonical_bytes(record), 17)

                claims = {"purpose": "agentmux-client-possession-v1", "hubId": "hub-one",
                    "profileId": "profile-one", "authorityId": "authority-one",
                    "transportRef": ref("transport"), "grantRef": ref("grant"),
                    "operationId": "operation-one", "expectedVersion": 1,
                    "contractId": contract, "payload": payload, "approvalRefs": [],
                    "issuedAt": NOW.isoformat().replace("+00:00", "Z"),
                    "expiresAt": (NOW + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")}
                request = canonical_bytes({"schemaVersion": "1.0.0", "claims": claims,
                    "signature": sign_claims(claims, bytes(reversed(SEED)))})
                ingress = EnrolledIngress(Reader(), issuer_ref=ref("issuer"), signing_seed=SEED)
                with patch("identity.ingress.datetime", _Clock):
                    admitted = await ingress.admit(request, cancellation_ref=ref("cancel"))
                event = strict_loads(admitted.envelope)
                self.assertEqual(event["destinationServiceId"], DESTINATIONS[contract.split("-", 1)[0]])


if __name__ == "__main__":
    unittest.main()
