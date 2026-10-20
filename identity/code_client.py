"""Protected application bindings for existing code-share commands."""
import base64
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, canonical_bytes, validate


CODE_COMMANDS = frozenset('federation-code-' + action for action in (
    'publish', 'index', 'approve', 'fetched', 'read', 'inspect', 'outcome'))


def check_enrollment(material):
    selected = material.get('codeCommands')
    if selected is None:
        return
    validate('application-code-commands', selected)
    scope = material['scope']
    subject = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_',
        'capability', 'storage-owner', 'command'))
    references = (selected['transportRef'], selected['replyIssuerRef'], selected['serviceIdentityRef'],
        selected['resourceRef'], *selected['grantRefs'].values())
    occupied = [material['transportRef']]
    for field in ('integrationEffectQuery', 'integrationEffectCommands', 'legacyAliasResolve',
            'authoritySwitchRecovery', 'localBrowserSessionOpen', 'oidcTerminalSession',
            'messageCommands', 'knowledgeCommands', 'peerControlCommands', 'federationPolicyCommands'):
        if field in material:
            occupied.append(material[field]['transportRef'])
    grants = set(selected['grantRefs'])
    human_actions = {'federation-code-' + action for action in ('publish', 'fetched', 'approve')}
    if (selected['subject'] != subject or scope['projectId'] is None
            or any(r['ownerHubId'] != material['hubId'] or r['revision'] < 1 for r in references)
            or selected['transportRef'] in occupied
            or len({canonical_bytes(r) for r in selected['grantRefs'].values()}) != len(grants)
            or selected['authenticatedCaller'] == 'federation' and human_actions & grants
            or selected['authenticatedCaller'] != 'federation' and 'federation-code-index' in grants
            or selected['authenticatedCaller'] != 'operator' and 'federation-code-approve' in grants):
        raise ContractError('application_client_command_enrollment')
    public = base64.urlsafe_b64decode(selected['replyIssuerPublicKey'] + '=')
    if base64.urlsafe_b64encode(public).decode().rstrip('=') != selected['replyIssuerPublicKey']:
        raise ContractError('application_client_command_enrollment')


def check_command(material, claims, subject):
    selected = material.get('codeCommands')
    contract, payload = claims.get('contractId'), claims.get('payload')
    if (selected is None or contract not in CODE_COMMANDS
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
                > timedelta(seconds=5)):
        raise ContractError('application_client_command_binding')
    if contract in ('federation-code-publish', 'federation-code-index', 'federation-code-approve'):
        value, attribution = payload['input'], payload['attribution']
        env = value['envelope']
        if (env.get('type') != 'code' or env.get('to') != '*'
                or env.get('rid') != selected['repository']['repositoryId']):
            raise ContractError('application_client_command_binding')
        if contract == 'federation-code-publish':
            if (env.get('from') != selected['localPeer'] or env.get('node') != selected['localNode']
                    or selected['authenticatedCaller'] == 'federation'
                    or selected['authenticatedCaller'] != 'operator' and attribution != selected['authenticatedCaller']):
                raise ContractError('application_client_command_binding')
        elif (attribution != ('operator' if contract == 'federation-code-approve' else 'federation')
                or env.get('from') == selected['localPeer']
                or value['localNode'] != selected['localNode']
                or value['subject'] != 'am.code.' + str(env.get('from')) + '.' + selected['repository']['repositoryId']):
            raise ContractError('application_client_command_binding')
    elif contract == 'federation-code-fetched':
        if (selected['authenticatedCaller'] == 'federation'
                or selected['authenticatedCaller'] != 'operator'
                    and payload['attribution'] != selected['authenticatedCaller']):
            raise ContractError('application_client_command_binding')
    return selected
