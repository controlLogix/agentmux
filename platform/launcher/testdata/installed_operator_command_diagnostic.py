"""Run one exact installed operator command with a closed test diagnostic."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys


PREFIX = "installed operator command failure: "
CODES = frozenset({
    'application_account_authority_required',
    'application_account_binding_mismatch',
    'application_account_not_authorized',
    'application_account_resolution_invalid',
    'application_account_scope_mismatch',
    'application_account_unavailable',
    'application_service_credentials_unavailable',
    'application_service_selection_invalid',
    'authority_configuration_invalid',
    'authority_external_identity_ambiguous',
    'authority_organization_mismatch',
    'authority_owner_mismatch',
    'authority_principal_ambiguous',
    'authority_profile_mismatch',
    'authority_record_invalid',
    'authority_reference_ambiguous',
    'authority_time_invalid',
    'authority_unavailable',
    'backup_host_configuration',
    'backup_inventory_commit_uncertain',
    'backup_inventory_unavailable',
    'backup_key_enrollment_uncertain',
    'backup_key_unavailable',
    'checkpoint_cadence_invalid',
    'checkpoint_export_uncertain',
    'checkpoint_host_configuration',
    'checkpoint_inventory_commit_uncertain',
    'checkpoint_inventory_restore_failed',
    'checkpoint_inventory_unavailable',
    'checkpoint_restore_failed',
    'contract_destination_mismatch',
    'contract_kind_mismatch',
    'contract_unknown',
    'identity_not_enrolled',
    'integration_operator_account_authority_expired',
    'integration_operator_account_changed',
    'integration_operator_account_issuer_invalid',
    'integration_operator_account_selection_mismatch',
    'integration_operator_administrator_credential_invalid',
    'integration_operator_broker_error',
    'integration_operator_broker_nonce_invalid',
    'integration_operator_cleanup_pending',
    'integration_operator_command_invalid',
    'integration_operator_connection_unavailable',
    'integration_operator_credential_issue_failed',
    'integration_operator_identity_binding_invalid',
    'integration_operator_identity_unavailable',
    'integration_operator_lease_invalid',
    'integration_operator_provisioning_invalid',
    'integration_provisioning_authority_required',
    'integration_provisioning_busy',
    'integration_provisioning_capacity',
    'integration_provisioning_credential_invalid',
    'integration_provisioning_credential_write_uncertain',
    'integration_provisioning_invalid',
    'integration_provisioning_inventory_invalid',
    'integration_provisioning_inventory_unavailable',
    'integration_provisioning_publication_invalid',
    'integration_provisioning_publication_uncertain',
    'integration_provisioning_stream_occupied',
    'integration_provisioning_stream_unavailable',
    'integration_provisioning_stream_uncertain',
    'integration_route_credential_unavailable',
    'integration_route_not_enrolled',
    'invalid_clock',
    'legacy_identity_collision',
    'owner_append_rejected',
    'owner_authorization_deadline_invalid',
    'owner_authorization_expired',
    'owner_binding_mismatch',
    'owner_body_limit',
    'owner_commit_uncertain',
    'owner_completion_budget_required',
    'owner_configuration_invalid',
    'owner_effect_conflict',
    'owner_effect_digest',
    'owner_history_cache_invalid',
    'owner_history_capacity',
    'owner_history_configuration',
    'owner_history_corrupt',
    'owner_history_duplicate',
    'owner_history_gap',
    'owner_history_invalid',
    'owner_history_limit',
    'owner_history_recovery_required',
    'owner_operation_conflict',
    'owner_operation_invalid',
    'owner_record_size',
    'owner_recovery_required',
    'owner_rejected_state_changed',
    'owner_revision_conflict',
    'owner_revision_invalid',
    'owner_stream_identity_invalid',
    'owner_subject_mismatch',
    'owner_target_version_invalid',
    'owner_unavailable',
    'payload_context_mismatch',
    'registry_configuration_error',
    'registry_version_unsupported',
    'schema_configuration_error',
    'schema_invalid',
    'secret_custody_authority_required',
    'secret_custody_busy',
    'secret_custody_changed',
    'secret_custody_invalid',
    'secret_custody_invalid_clock',
    'secret_custody_native_refused',
    'secret_custody_not_authorized',
    'secret_custody_recovery_required',
    'secret_custody_unavailable',
    'secret_custody_write_uncertain',
    'semantic_invalid',
    'unknown_schema',
})


def fail():
    raise SystemExit("installed operator package root refused")


root = Path(os.environ.get("AMX_INSTALLED_OPERATOR_PACKAGE_ROOT", ""))
installation = os.environ.get("AMX_INSTALLED_OPERATOR_PACKAGE_ID", "")
try:
    manifest = (root / "client-manifest.json").read_bytes()
    parsed = json.loads(manifest)
except Exception:
    fail()
if (not root.is_absolute() or str(root) != os.path.normpath(root)
        or hashlib.sha256(manifest).hexdigest() != installation
        or parsed.get("kind") != "ordinary-python-client"):
    fail()
app = root / "app"
paths = [root / "site-packages", app / "sdk/python", app]
if any(not path.is_dir() for path in paths):
    fail()
sys.path[:0] = [str(path) for path in paths]

from agentmux_contracts import ContractError, canonical_bytes
from integration_owner import operator_command
if not Path(operator_command.__file__).resolve().is_relative_to(app):
    fail()


async def main():
    raw = sys.stdin.buffer.read(131073)
    try:
        result = await operator_command.execute(raw)
    except ContractError as error:
        code = str(error)
        if code not in CODES:
            code = "contract_failure"
        print(PREFIX + code, file=sys.stderr, flush=True)
        return 1
    sys.stdout.buffer.write(canonical_bytes(json.loads(result)) + b"\n")
    sys.stdout.buffer.flush()
    return 0


raise SystemExit(asyncio.run(main()))
