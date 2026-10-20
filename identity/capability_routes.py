"""Fixed capability routes; these entries do not implement receiving effects."""
CAPABILITY_DESTINATIONS = {
    'capability-storage-read': 'storage-owner',
    'capability-storage-write': 'storage-owner',
    'capability-artifact-read': 'artifact-owner',
    'capability-secret-use': 'secret-owner',
    'capability-workspace-read': 'workspace-owner',
    'capability-process-start': 'process-owner',
    'capability-process-cancel': 'process-owner',
    'capability-policy-evaluate': 'policy-owner',
    'capability-decision-request': 'decision-owner',
    'capability-outcome-query': 'outcome-owner',
}
