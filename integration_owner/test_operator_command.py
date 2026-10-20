import base64
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agentmux_contracts import canonical_bytes, strict_loads

from integration_owner import operator_command


class OperatorCommandTests(unittest.IsolatedAsyncioTestCase):
    def request(self, operation_id="provision-one"):
        envelope = {"operation": {"operationId": operation_id}}
        return canonical_bytes({"schemaVersion": "1.0.0",
            "kind": "integration-effect-provision", "selection": "/private/selection.json",
            "selectionSHA256": "sha256:" + "a" * 64,
            "hostPolicy": "/private/host-policy.json", "ownerUid": 501,
            "workspaces": ["/private/workspace"], "kernelScope": {},
            "protectedHostAccount": {"kind": "named-password", "account": "HOST",
                "broker": {"endpoint": "tls://127.0.0.1:4222",
                    "serverName": "fixture", "configSha256": "sha256:" + "b" * 64}},
            "custodyRoot": "/private/custody",
            "originalOperationId": "integration-one",
            "resolutionRequestBase64": base64.b64encode(
                canonical_bytes(envelope)).decode("ascii"), "leaseFd": 3})

    async def test_exact_command_derives_operation_and_emits_only_receipt(self):
        result = SimpleNamespace(effect_id="effect-one", stream="AMX_INTEGRATION_ONE",
            route_generation=2, route_streams=("AMX_INTEGRATION_ONE",),
            router_credential_digest="sha256:" + "c" * 64)
        client, authority, selection = AsyncMock(), object(), object()
        with patch("integration_owner.operator_command.os.getuid", return_value=501), \
                patch("integration_owner.operator_command._outside"), \
                patch("integration_owner.operator_command._lease"), \
                patch("integration_owner.operator_command.load_application_service_selection",
                      return_value=selection), \
                patch("integration_owner.operator_command._identity_reader",
                      AsyncMock(return_value=(client, authority))), \
                patch("integration_owner.operator_command.ScopedSecretCustody",
                      return_value="custody") as custody, \
                patch("integration_owner.operator_command.provision_integration_effect",
                      AsyncMock(return_value=result)) as provision, \
                patch("integration_owner.operator_command._close_client",
                      AsyncMock()) as close:
            receipt = strict_loads(await operator_command.execute(self.request()))
        self.assertEqual(receipt, {"schemaVersion": "1.0.0",
            "kind": "integration-effect-provisioned", "effectId": "effect-one",
            "stream": "AMX_INTEGRATION_ONE", "routeGeneration": 2,
            "routeStreams": ["AMX_INTEGRATION_ONE"],
            "routerCredentialDigest": "sha256:" + "c" * 64})
        custody.assert_called_once_with("/private/custody", authority)
        self.assertEqual(provision.await_args.kwargs["original_operation_id"],
                         "integration-one")
        close.assert_awaited_once_with(client)

    async def test_invalid_arguments_refuse_before_dependencies(self):
        value = strict_loads(self.request())
        value["extra"] = "substitute"
        with patch("integration_owner.operator_command.os.getuid", return_value=501), \
                patch("integration_owner.operator_command._identity_reader",
                      AsyncMock()) as reader:
            with self.assertRaises(Exception):
                await operator_command.execute(canonical_bytes(value))
        reader.assert_not_awaited()

    async def test_dependency_failure_still_closes_identity_connection(self):
        client, authority, selection = AsyncMock(), object(), object()
        with patch("integration_owner.operator_command.os.getuid", return_value=501), \
                patch("integration_owner.operator_command._outside"), \
                patch("integration_owner.operator_command._lease"), \
                patch("integration_owner.operator_command.load_application_service_selection",
                      return_value=selection), \
                patch("integration_owner.operator_command._identity_reader",
                      AsyncMock(return_value=(client, authority))), \
                patch("integration_owner.operator_command.ScopedSecretCustody",
                      side_effect=RuntimeError("private detail")), \
                patch("integration_owner.operator_command._close_client",
                      AsyncMock()) as close:
            with self.assertRaisesRegex(RuntimeError, "private detail"):
                await operator_command.execute(self.request())
        close.assert_awaited_once_with(client)

    async def test_failed_identity_connect_uses_joined_client_cleanup(self):
        selected = {"credentials": {"accountPublicKey": "account",
            "userPublicKey": "user", "replyPrefix": "_INBOX.fixture"},
            "connection": {"leafCertificateSHA256": "sha256:" + "a" * 64}}
        selection = SimpleNamespace(service=lambda role: selected,
            read_credential_bytes=lambda role: b"credential",
            service_policy_inputs=lambda role: {}, tls_options=lambda role: {})
        credential = SimpleNamespace(public_key="user", seed=b"seed", jwt="jwt")
        client = SimpleNamespace(connect=AsyncMock(side_effect=RuntimeError("private")))
        with patch("integration_owner.operator_command.validate_service",
                   return_value=credential), \
                patch("integration_owner.operator_command.new_client",
                      return_value=client), \
                patch("integration_owner.operator_command._close_client",
                      AsyncMock()) as close:
            with self.assertRaisesRegex(RuntimeError, "private"):
                await operator_command._identity_reader(selection)
        close.assert_awaited_once_with(client)


if __name__ == "__main__":
    unittest.main()
