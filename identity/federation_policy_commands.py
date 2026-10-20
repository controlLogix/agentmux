"""Exact enrolled human routes to the dedicated federation policy owner."""
import base64
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, canonical_bytes, validate
from state_owner.federation_policy import SCHEMA_REF


COMMANDS = frozenset(('configuration-read', 'configuration-set'))


def check_enrollment(material):
    selected = material.get('federationPolicyCommands')
    if selected is None:
        return
    validate('application-federation-policy-commands', selected)
    scope, hub = material['scope'], material['hubId']
    subject = '.'.join(('amx', 'v1', 'h', hub, 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_',
        'configuration', selected['configurationRef']['id'], 'command'))
    occupied = [material['transportRef']]
    for field in ('integrationEffectQuery', 'integrationEffectCommands', 'legacyAliasResolve',
            'authoritySwitchRecovery', 'localBrowserSessionOpen', 'oidcTerminalSession',
            'messageCommands', 'knowledgeCommands', 'peerControlCommands'):
        if field in material:
            occupied.append(material[field]['transportRef'])
    references = (selected['transportRef'], selected['replyIssuerRef'], selected['serviceIdentityRef'],
        selected['keyRef'], selected['target']['sourceRef'], *selected['grantRefs'].values())
    public = base64.urlsafe_b64decode(selected['replyIssuerPublicKey'] + '=')
    if (scope['projectId'] is None or selected['subject'] != subject
            or selected['transportRef'] in occupied
            or selected['configurationRef']['ownerHubId'] != hub
            or selected['target']['repositoryId'] != selected['repository']['repositoryId']
            or any(ref['ownerHubId'] != hub or ref['revision'] < 1 for ref in references)
            or len({canonical_bytes(ref) for ref in selected['grantRefs'].values()}) != 2
            or base64.urlsafe_b64encode(public).decode().rstrip('=') != selected['replyIssuerPublicKey']):
        raise ContractError('application_client_command_enrollment')


def check_command(material, claims, subject):
    selected = material.get('federationPolicyCommands')
    contract, payload = claims.get('contractId'), claims.get('payload')
    if selected is None or contract not in COMMANDS:
        raise ContractError('application_client_command_unavailable')
    validate(contract, payload)
    reference = payload['configurationRef']
    if (subject != selected['subject'] or claims.get('purpose') != 'agentmux-client-possession-v1'
            or any(claims.get(k) != material[k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('transportRef') != selected['transportRef']
            or claims.get('grantRef') != selected['grantRefs'][contract]
            or any(reference[k] != selected['configurationRef'][k] for k in ('id', 'ownerHubId'))
            or claims.get('expectedVersion') != reference['revision'] or payload['owner'] != selected['owner']
            or type(claims.get('approvalRefs')) is not list or 'replySubject' not in claims
            or datetime.fromisoformat(claims['expiresAt']) - datetime.fromisoformat(claims['issuedAt'])
                > timedelta(seconds=5)):
        raise ContractError('application_client_command_binding')
    if contract == 'configuration-set':
        from agentmux_contracts import strict_loads
        try:
            document = strict_loads(base64.b64decode(payload['configurationBytes'], validate=True))
            if (document['target'] != selected['target'] or document['originDigest'] != selected['originDigest']
                    or document['previousRevision'] != reference['revision']
                    or payload['schemaRef'] != SCHEMA_REF or payload['secretReferences'] != [selected['keyRef']]
                    or document['format'] not in ('amx-federation-policy-preparation-v1', 'amx-federation-policy-v1')):
                raise ValueError()
        except Exception:
            raise ContractError('application_client_command_binding') from None
    return selected
