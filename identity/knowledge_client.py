"""Protected application command bindings for the existing knowledge owner."""
import base64
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, canonical_bytes, validate
from .authority import KNOWLEDGE_COMMANDS


def check_enrollment(material):
    selected = material.get('knowledgeCommands')
    if selected is None:
        return
    validate('application-knowledge-commands', selected)
    scope = material['scope']
    subject = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_', 'capability', 'storage-owner', 'command'))
    references = (selected['transportRef'], selected['replyIssuerRef'], selected['serviceIdentityRef'],
        selected['resourceRef'], *selected['grantRefs'].values())
    occupied = [material['transportRef']]
    for field in ('integrationEffectQuery', 'integrationEffectCommands', 'legacyAliasResolve',
            'authoritySwitchRecovery', 'localBrowserSessionOpen', 'oidcTerminalSession', 'messageCommands'):
        if field in material:
            occupied.append(material[field]['transportRef'])
    grants = set(selected['grantRefs'])
    service_actions = {'federation-knowledge-' + action for action in ('index', 'capture', 'withdraw')}
    if (selected['subject'] != subject or scope['projectId'] is None
            or any(r['ownerHubId'] != material['hubId'] or r['revision'] < 1 for r in references)
            or selected['transportRef'] in occupied
            or len({canonical_bytes(r) for r in selected['grantRefs'].values()}) != len(grants)
            or selected['authenticatedCaller'] == 'federation' and 'federation-knowledge-share' in grants
            or selected['authenticatedCaller'] != 'federation' and service_actions & grants):
        raise ContractError('application_client_command_enrollment')
    if selected['authenticatedCaller'] != 'operator' and 'federation-knowledge-approve' in grants:
        raise ContractError('application_client_command_enrollment')
    public = base64.urlsafe_b64decode(selected['replyIssuerPublicKey'] + '=')
    if base64.urlsafe_b64encode(public).decode().rstrip('=') != selected['replyIssuerPublicKey']:
        raise ContractError('application_client_command_enrollment')


def check_command(material, claims, subject):
    selected = material.get('knowledgeCommands')
    contract, payload = claims.get('contractId'), claims.get('payload')
    if selected is None or contract not in selected['grantRefs'] or subject != selected['subject']:
        raise ContractError('application_client_command_unavailable')
    validate(contract, payload)
    reference = payload['resourceRef']
    if (contract not in KNOWLEDGE_COMMANDS or claims.get('purpose') != 'agentmux-client-possession-v1'
            or any(claims.get(k) != material[k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('transportRef') != selected['transportRef']
            or claims.get('grantRef') != selected['grantRefs'][contract]
            or claims.get('expectedVersion') != reference['revision'] or claims.get('approvalRefs') != []
            or 'replySubject' not in claims
            or any(reference[k] != selected['resourceRef'][k] for k in ('id', 'ownerHubId'))
            or reference['revision'] < selected['resourceRef']['revision']
            or datetime.fromisoformat(claims['expiresAt']) - datetime.fromisoformat(claims['issuedAt'])
                > timedelta(seconds=5)):
        raise ContractError('application_client_command_binding')
    if contract in ('federation-knowledge-share', 'federation-knowledge-index', 'federation-knowledge-approve'):
        value, attribution = payload['input'], payload['attribution']
        env = value['envelope']
        if (env.get('type') != 'knowledge' or env.get('to') != '*'
                or env.get('rid') != selected['repository']['repositoryId']):
            raise ContractError('application_client_command_binding')
        if contract == 'federation-knowledge-share':
            if (env.get('from') != selected['localPeer'] or env.get('node') != selected['localNode']
                    or selected['authenticatedCaller'] != 'operator' and attribution != selected['authenticatedCaller']):
                raise ContractError('application_client_command_binding')
        elif (attribution != ('operator' if contract == 'federation-knowledge-approve' else 'federation')
                or env.get('from') == selected['localPeer']
                or value['localNode'] != selected['localNode']
                or value['subject'] != 'am.know.' + str(env.get('from')) + '.' + selected['repository']['repositoryId']):
            raise ContractError('application_client_command_binding')
    elif contract in ('federation-knowledge-capture', 'federation-knowledge-withdraw'):
        if payload['attribution'] != 'federation':
            raise ContractError('application_client_command_binding')
    return selected
