"""Closed message command enrollment for application possession keys."""
import base64
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, canonical_bytes, validate
from .authority import MESSAGE_COMMANDS


def check_enrollment(material):
    selected = material.get('messageCommands')
    if selected is None:
        return
    validate('application-message-commands', selected)
    scope = material['scope']
    subject = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_', 'capability', 'storage-owner', 'command'))
    refs = (selected['transportRef'], selected['replyIssuerRef'], selected['serviceIdentityRef'],
        selected['resourceRef'], *selected['grantRefs'].values())
    occupied = [material['transportRef']]
    for field in ('integrationEffectQuery', 'integrationEffectCommands', 'legacyAliasResolve',
            'authoritySwitchRecovery', 'localBrowserSessionOpen', 'oidcTerminalSession'):
        if field in material:
            occupied.append(material[field]['transportRef'])
    grants = set(selected['grantRefs'])
    if (selected['subject'] != subject or selected['peer'] == selected['localPeer']
            or any(r['ownerHubId'] != material['hubId'] or r['revision'] < 1 for r in refs)
            or selected['transportRef'] in occupied
            or (selected['repository'] is None) != (scope['projectId'] is None)
            or len({canonical_bytes(r) for r in selected['grantRefs'].values()}) != len(grants)
            or selected['authenticatedCaller'] == 'federation' and grants - {
                'federation-message-deliver', 'federation-message-finding', 'federation-message-inspect', 'federation-message-outcome'}
            or selected['authenticatedCaller'] != 'federation' and grants & {
                'federation-message-deliver', 'federation-message-finding'}
            or selected['authenticatedCaller'] != 'operator' and 'federation-message-approve' in grants):
        raise ContractError('application_client_command_enrollment')
    public = base64.urlsafe_b64decode(selected['replyIssuerPublicKey'] + '=')
    if base64.urlsafe_b64encode(public).decode().rstrip('=') != selected['replyIssuerPublicKey']:
        raise ContractError('application_client_command_enrollment')


def check_command(material, claims, subject):
    selected = material.get('messageCommands')
    contract, payload = claims.get('contractId'), claims.get('payload')
    if selected is None or contract not in selected['grantRefs'] or subject != selected['subject']:
        raise ContractError('application_client_command_unavailable')
    validate(contract, payload)
    resource = payload['resourceRef']
    if (contract not in MESSAGE_COMMANDS or claims.get('purpose') != 'agentmux-client-possession-v1'
            or any(claims.get(k) != material[k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('transportRef') != selected['transportRef']
            or claims.get('grantRef') != selected['grantRefs'][contract]
            or claims.get('expectedVersion') != resource['revision'] or claims.get('approvalRefs') != []
            or 'replySubject' not in claims
            or any(resource[k] != selected['resourceRef'][k] for k in ('id', 'ownerHubId'))
            or resource['revision'] < selected['resourceRef']['revision']
            or datetime.fromisoformat(claims['expiresAt']) - datetime.fromisoformat(claims['issuedAt'])
                > timedelta(seconds=5)):
        raise ContractError('application_client_command_binding')
    if contract in ('federation-message-send', 'federation-message-deliver', 'federation-message-approve'):
        value, attribution = payload['input'], payload['attribution']
        env = value['envelope']
        outbound = contract == 'federation-message-send'
        origin, target = ((selected['localPeer'], selected['peer']) if outbound
            else (selected['peer'], selected['localPeer']))
        repository = selected['repository']
        if (value['localNode'] != selected['localNode'] or value['subject'] != 'am.msg.' + origin + '.' + target
                or env.get('from') != origin or env.get('to') != target
                or env.get('rid') != (None if repository is None else repository['repositoryId'])
                or not outbound and attribution != ('federation' if contract == 'federation-message-deliver' else 'operator')
                or outbound and selected['authenticatedCaller'] != 'operator'
                    and attribution != selected['authenticatedCaller']):
            raise ContractError('application_client_command_binding')
    elif contract == 'federation-message-finding':
        value, env = payload['input'], payload['input']['envelope']
        if (payload['attribution'] != 'federation' or selected['repository'] is None
                or value['localNode'] != selected['localNode'] or env.get('type') != 'knowledge'
                or env.get('from') != selected['peer'] or env.get('to') != '*'
                or env.get('rid') != selected['repository']['repositoryId']):
            raise ContractError('application_client_command_binding')
    return selected
