"""Explicit enrolled operator purpose for peer self-revoke commands."""
import base64
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, canonical_bytes, validate
from hub.fed import envelope


COMMANDS = frozenset(('federation-peer-revoke', 'federation-peer-revoke-outcome'))


def check_enrollment(material):
    selected = material.get('peerControlCommands')
    if selected is None:
        return
    validate('application-peer-control-commands', selected)
    scope = material['scope']
    subject = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_', 'capability', 'storage-owner', 'command'))
    references = (selected['transportRef'], selected['replyIssuerRef'], selected['serviceIdentityRef'],
        selected['resourceRef'], *selected['grantRefs'].values())
    occupied = [material['transportRef']]
    for field in ('integrationEffectQuery', 'integrationEffectCommands', 'legacyAliasResolve',
            'authoritySwitchRecovery', 'localBrowserSessionOpen', 'oidcTerminalSession', 'messageCommands', 'knowledgeCommands'):
        if field in material:
            occupied.append(material[field]['transportRef'])
    public = base64.urlsafe_b64decode(selected['replyIssuerPublicKey'] + '=')
    if (scope['projectId'] is None or selected['subject'] != subject
            or selected['authenticatedCaller'] != 'operator' or selected['transportRef'] in occupied
            or any(r['ownerHubId'] != material['hubId'] or r['revision'] < 1 for r in references)
            or len({canonical_bytes(r) for r in selected['grantRefs'].values()}) != 2
            or base64.urlsafe_b64encode(public).decode().rstrip('=') != selected['replyIssuerPublicKey']):
        raise ContractError('application_client_command_enrollment')


def check_command(material, claims, subject):
    selected = material.get('peerControlCommands')
    contract, payload = claims.get('contractId'), claims.get('payload')
    if selected is None or contract not in COMMANDS or contract not in selected['grantRefs']:
        raise ContractError('application_client_command_unavailable')
    validate(contract, payload)
    reference = payload['resourceRef']
    if (subject != selected['subject'] or claims.get('purpose') != 'agentmux-client-possession-v1'
            or any(claims.get(k) != material[k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('transportRef') != selected['transportRef']
            or claims.get('grantRef') != selected['grantRefs'][contract]
            or claims.get('expectedVersion') != reference['revision'] or reference != selected['resourceRef']
            or payload['input']['routeId'] != selected['routeId']
            or type(claims.get('approvalRefs')) is not list or 'replySubject' not in claims
            or datetime.fromisoformat(claims['expiresAt']) - datetime.fromisoformat(claims['issuedAt']) > timedelta(seconds=5)):
        raise ContractError('application_client_command_binding')
    if contract == 'federation-peer-revoke':
        item = payload['input']['envelope']
        envelope.validate_route('am.ctl.' + selected['localPeer'], item)
        if (item['type'] != 'revoke' or item['from'] != selected['localPeer']
                or item['node'] != selected['localNode'] or item['rid'] is not None or item['to'] != '*'):
            raise ContractError('application_client_command_binding')
    return selected
