"""Identity record capacity reserves remain inside the accepted 64 KiB body."""
import copy
from datetime import datetime, timezone, timedelta
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, validate
from identity.bootstrap import BootstrapPermit
from identity.capacity import MAX_OPERATION_BYTES, MAX_STATE_BYTES, require_operation_capacity
from identity.test_bootstrap import initial_record
from identity.test_authority import ref


class CapacityTests(unittest.TestCase):
    def test_maximum_identity_record_metadata_fits_reserved_framing(self):
        record = initial_record(datetime.now(timezone.utc))
        longest = 'a' * 96
        max_revision = 9007199254740991
        for field in ('recordId', 'entityId', 'ownerHubId'):
            record[field] = longest
        record.update(entityVersion=max_revision, previousRevision=max_revision,
                      recordedAt='9999-12-31T23:59:59.999999Z', outcome='committed')
        record['authorizationDecision'] = {
            'operationId': longest, 'decision': 'review-required', 'reason': longest,
            'actorRef': {'id': longest, 'ownerHubId': longest, 'revision': max_revision},
            'contractId': longest}
        validate('owner-record', record)
        # Subtract just the two independent budgeted JSON values. This retains
        # field names, separators, audit provenance and every other record byte.
        overhead = (len(canonical_bytes(record)) - len(canonical_bytes(record['state']))
                    - len(canonical_bytes(record['operation'])))
        self.assertLessEqual(overhead, 8192)
        self.assertLessEqual(MAX_STATE_BYTES + 10554 + overhead, 65536)

    def test_all_32_long_approval_references_remain_accepted(self):
        operation = initial_record(datetime.now(timezone.utc))['operation']
        longest = 'a' * 96
        maximum_ref = {'id': longest, 'ownerHubId': longest, 'revision': 9007199254740991}
        for field in ('operationId', 'taskId', 'runId', 'attemptId', 'traceId', 'causationId'):
            operation[field] = longest
        operation['caller'] = {'principalId': longest, 'kind': 'service',
                               'authenticatedIdentityRef': copy.deepcopy(maximum_ref)}
        for field in ('effectiveActorRef', 'delegationRef', 'grantRef', 'cancellationRef'):
            operation[field] = copy.deepcopy(maximum_ref)
        operation['scope'] = dict.fromkeys(('organizationId', 'projectId', 'workspaceId'), longest)
        operation['deadline'] = '9999-12-31T23:59:59.999999Z'
        operation['expectedVersion'] = 9007199254740991
        operation['approvalRefs'] = [dict(maximum_ref, id='a' + str(index).zfill(95))
                                     for index in range(32)]
        validate('operation-context', operation)
        size = len(canonical_bytes(operation))
        self.assertGreater(size, 8192)
        self.assertEqual(size, 10554)
        require_operation_capacity(operation)

    def test_older_large_state_can_be_revoked_without_new_enrollment(self):
        from identity.test_commands import command_fixture
        from identity.test_authority import NOW
        from identity.authority import AuthoritySnapshot
        from identity.commands import prepare_change
        from identity.capacity import require_state_capacity
        record, env = command_fixture()
        for index in range(20):
            record['state']['identities'].append({
                'ref': ref('padding-' + str(index)), 'principalId': 'padding-' + str(index),
                'kind': 'human', 'status': 'active',
                'externalIdentity': {'issuer': 'i' * 2048, 'subject': str(index).zfill(512)}})
        with self.assertRaisesRegex(ContractError, 'identity_capacity_exceeded'):
            require_state_capacity(record['state'])
        proposal = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7),
                                  canonical_bytes(env), now=NOW)
        self.assertEqual(proposal.decision, 'allowed')
        self.assertLessEqual(len(proposal.record), 65536)

    def test_bootstrap_refuses_valid_record_that_consumes_revocation_reserve(self):
        now = datetime.now(timezone.utc)
        record = initial_record(now)
        for index in range(20):
            identity = {'ref': ref('padding-' + str(index)), 'principalId': 'padding-user-' + str(index),
                        'kind': 'human', 'status': 'active',
                        'externalIdentity': {'issuer': 'i' * 2048, 'subject': str(index).zfill(512)}}
            record['state']['identities'].append(identity)
        record['operation']['payloadDigest'] = payload_digest(record['state'])
        validate('owner-record', record)
        validate('identity-authority-state', record['state'])
        raw = canonical_bytes(record)
        self.assertLessEqual(len(raw), 65536)
        self.assertGreater(len(canonical_bytes(record['state'])), MAX_STATE_BYTES)
        with self.assertRaisesRegex(ContractError, 'identity_capacity_exceeded'):
            BootstrapPermit(raw, 'hub-one', 'authority-one', 'profile-one', 'org-one',
                            now, now + timedelta(minutes=4))


if __name__ == '__main__':
    unittest.main()
