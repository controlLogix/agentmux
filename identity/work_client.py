"""Protected enrollment and closed commands for the existing work owner."""
import base64
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, canonical_bytes, validate


WORK_PEER_COMMANDS = frozenset('federation-work-' + name for name in (
    'ingest', 'claim-envelope', 'grant-envelope', 'result-envelope'))
WORK_LIFECYCLE_COMMANDS = frozenset('federation-work-' + name for name in ('register', 'state', 'sweep-global'))
WORK_SERVICE_COMMANDS = WORK_PEER_COMMANDS | WORK_LIFECYCLE_COMMANDS | frozenset('federation-work-' + name for name in (
    'stage-result', 'revoke', 'return-leases', 'sweep-leases', 'ingest-legacy', 'result-legacy'))
WORK_OPERATOR_COMMANDS = frozenset('federation-work-' + name for name in (
    'cancel', 'approve', 'approve-privileged'))
WORK_MUTATIONS = WORK_SERVICE_COMMANDS | WORK_OPERATOR_COMMANDS | frozenset(
    'federation-work-' + name for name in ('create', 'offer', 'claim', 'heartbeat', 'release', 'claim-path'))
WORK_COMMANDS = WORK_MUTATIONS | frozenset('federation-work-' + name for name in ('read', 'inspect', 'outcome'))
# Longest lifetime of one authenticated Work command: the Hub's caller proof for
# WORK_REQUEST_VERBS and each signed exchange's issuedAt-to-expiresAt span, as
# checked here and by the Work services. Every other Hub verb keeps 5 s.
WORK_COMMAND_SECONDS = 10
WORK_REQUEST_VERBS = frozenset(('work_add', 'claim', 'heartbeat', 'release', 'work_cancel', 'claim_path',
    'fed_work_add', 'status', 'events', 'work_show', 'work_list'))


def check_enrollment(material):
    selected = material.get('workCommands')
    if selected is None:
        return
    validate('application-work-commands', selected)
    scope = material['scope']
    subject = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_',
        'capability', 'storage-owner', 'command'))
    references = (selected['transportRef'], selected['replyIssuerRef'], selected['serviceIdentityRef'],
        selected['resourceRef'], *selected['grantRefs'].values())
    occupied = [material['transportRef']]
    for field in ('integrationEffectQuery', 'integrationEffectCommands', 'legacyAliasResolve',
            'authoritySwitchRecovery', 'localBrowserSessionOpen', 'oidcTerminalSession',
            'messageCommands', 'knowledgeCommands', 'codeCommands', 'peerControlCommands', 'federationPolicyCommands'):
        if field in material:
            occupied.append(material[field]['transportRef'])
    grants = set(selected['grantRefs'])
    caller, repository = selected['authenticatedCaller'], selected['repository']
    if (selected['subject'] != subject
            or (repository is None) != (scope['projectId'] is None)
            or selected['localPeer'] is None and repository is not None and repository['repositoryId'] is not None
            or any(r['ownerHubId'] != material['hubId'] or r['revision'] < 1 for r in references)
            or selected['transportRef'] in occupied
            or len({canonical_bytes(r) for r in selected['grantRefs'].values()}) != len(grants)
            or caller == 'federation' and (WORK_MUTATIONS - WORK_SERVICE_COMMANDS) & grants
            or caller != 'federation' and WORK_SERVICE_COMMANDS & grants
            or caller != 'operator' and WORK_OPERATOR_COMMANDS & grants
            or repository is None and WORK_MUTATIONS & grants):
        raise ContractError('application_client_command_enrollment')
    public = base64.urlsafe_b64decode(selected['replyIssuerPublicKey'] + '=')
    if base64.urlsafe_b64encode(public).decode().rstrip('=') != selected['replyIssuerPublicKey']:
        raise ContractError('application_client_command_enrollment')


def check_command(material, claims, subject):
    selected = material.get('workCommands')
    contract, payload = claims.get('contractId'), claims.get('payload')
    if (selected is None or contract not in WORK_COMMANDS
            or contract not in selected['grantRefs'] or subject != selected['subject']):
        raise ContractError('application_client_command_unavailable')
    validate(contract, payload)
    reference = payload['resourceRef']
    if (claims.get('purpose') != 'agentmux-client-possession-v1'
            or any(claims.get(k) != material[k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('transportRef') != selected['transportRef']
            or claims.get('grantRef') != selected['grantRefs'][contract]
            or claims.get('expectedVersion') != reference['revision'] or claims.get('approvalRefs') != []
            or 'replySubject' not in claims
            or any(reference[k] != selected['resourceRef'][k] for k in ('id', 'ownerHubId'))
            or reference['revision'] < selected['resourceRef']['revision']
            or datetime.fromisoformat(claims['expiresAt']) - datetime.fromisoformat(claims['issuedAt'])
                > timedelta(seconds=WORK_COMMAND_SECONDS)):
        raise ContractError('application_client_command_binding')
    if contract in WORK_MUTATIONS and payload['attribution'] != selected['authenticatedCaller']:
        raise ContractError('application_client_command_binding')
    if contract in WORK_MUTATIONS:
        target = payload['input'].get('onBehalfOf')
        if (target is not None and selected['authenticatedCaller'] != 'operator'
                or selected['authenticatedCaller'] == 'operator'
                    and contract in {'federation-work-' + name for name in
                        ('claim', 'heartbeat', 'release', 'claim-path')} and target is None):
            raise ContractError('application_client_command_binding')
    if contract in WORK_PEER_COMMANDS | {'federation-work-approve', 'federation-work-approve-privileged'}:
        from hub.fed import envelope
        value, item, repository = payload['input'], payload['input']['envelope'], selected['repository']
        if (repository is None or repository['repositoryId'] is None
                or item['rid'] != repository['repositoryId'] or value['localNode'] != selected['localNode']):
            raise ContractError('application_client_command_binding')
        envelope.validate_route(value['subject'], item)
        if item['type'] != 'work' and item['to'] != selected['localPeer']:
            raise ContractError('application_client_command_binding')
    return selected
