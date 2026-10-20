"""Admit separate lifecycle/context credentials and configuration route pins."""
import re
from datetime import datetime
from agentmux_contracts import ContractError
from .application_enrollment import _read_material
from .application_host_selection import _check_connection, _nkey
from .application_service_selection import _outside, _digest, _schema_name


def _fail():
    raise ContractError('native_host_selection_invalid')


def check_transports(value, now):
    instances = set(value['destinations'])
    keys = value['keys']
    if any(not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', instance) for instance in instances):
        _fail()
    users = {value['credentials']['userPublicKey']}
    for role, server in (('lifecycle', 'controllerCredentials'), ('contextTransport', 'serverCredentials')):
        selected = value.get(role)
        if selected is None:
            continue
        _check_connection(selected['connection'], now)
        if (not re.fullmatch(r'tls://127\.0\.0\.1:[1-9][0-9]{0,4}', selected['connection']['endpoint'])
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', selected['connection']['leafCertificateSHA256'])):
            _fail()
        if not _nkey(selected['accountPublicKey'], 0):
            _fail()
        _outside(selected['caFile']['path'], value['workspaces'])
        bindings = selected['bindings']
        if len(bindings) != len(instances) or {b['instanceId'] for b in bindings} != instances:
            _fail()
        for credential in [selected[server], *(b['credentials'] for b in bindings)]:
            _outside(credential['path'], value['workspaces'])
            if not _nkey(credential['userPublicKey'], 160) or credential['userPublicKey'] in users:
                _fail()
            users.add(credential['userPublicKey'])
        if role == 'lifecycle':
            _outside(selected['stateDirectory'], value['workspaces'])
            for binding in bindings:
                if binding['workspace'] is not None and binding['workspace'] not in value['workspaces']:
                    _fail()
                declarations = value.get('activationDeclarations')
                if declarations is not None and declarations[binding['instanceId']]['pin'] != binding['pin']:
                    _fail()
    routes = value.get('configurationRoutes')
    if routes is not None:
        if set(routes) != instances:
            _fail()
        for route in routes.values():
            service, scope = route['service'], route['scope']
            references = (route['configurationRef'],route['authorityRef'],service['serviceIdentityRef'],service['signingKeyRef'])
            identifiers = [service['profileId'],service['hubId'],service['serviceInstanceId']]
            identifiers += [r[k] for r in references for k in ('id','ownerHubId')]
            identifiers += [v for v in scope.values() if v is not None]
            if any(not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', item) for item in identifiers):
                _fail()
            if (any(service[k] != keys[k] for k in ('profileId','hubId'))
                    or route['authorityRef']['id'] != keys['authorityId']
                    or any(r['ownerHubId'] != keys['hubId'] for r in (route['configurationRef'],route['authorityRef'],
                        service['serviceIdentityRef'],service['signingKeyRef']))
                    or scope['organizationId'] != keys['organizationId']
                    or scope['workspaceId'] is not None and scope['projectId'] is None):
                _fail()
            resources = route['resources']
            if len({r['ref'] for r in resources}) != len(resources) or any(
                    not _schema_name(r[k]) for r in resources for k in ('ref','file')):
                _fail()
    subscriptions = value.get('subscriptionRoutes', [])
    subscription_keys = set()
    for route in subscriptions:
        source, service, scope = route['source'], route['service'], route['scope']
        reference = source['configurationRef']
        route_key = (route['bindingId'], reference['id'])
        identifiers = [route['bindingId'], reference['id'], reference['ownerHubId']]
        identifiers += [service[k] for k in ('profileId','hubId','serviceInstanceId')]
        identifiers += [service[k][field] for k in ('serviceIdentityRef','signingKeyRef') for field in ('id','ownerHubId')]
        identifiers += [v for v in scope.values() if v is not None]
        if (route_key in subscription_keys
                or any(not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', item) for item in identifiers)
                or any(service[k] != keys[k] for k in ('profileId','hubId'))
                or any(r['ownerHubId'] != keys['hubId'] for r in
                       (reference, service['serviceIdentityRef'], service['signingKeyRef']))
                or scope['organizationId'] != keys['organizationId']
                or scope['workspaceId'] is not None and scope['projectId'] is None
                or not _schema_name(source['schemaRef'], max_length=4096)
                or datetime.fromisoformat(source['streamCreated']) > now):
            _fail()
        subscription_keys.add(route_key)
        matches = sum(source in declaration.get('configurationEventSources', [])
                and scope == declaration['facts']['grant']['scope']
                and any(binding['id'] == route['bindingId']
                    and binding['contractId'] == 'configuration-change-subscribe'
                    and binding['action'] == 'subscribe' and binding['resourceClass'] == 'configuration'
                    and reference['id'] in binding['resourceIds']
                    for binding in declaration['facts']['domainBindings'])
                for declaration in value.get('activationDeclarations', {}).values())
        if matches != 1:
            _fail()


def _selected(value, role):
    if role not in ('lifecycle','contextTransport') or value.get(role) is None:
        _fail()
    return value[role]


def _material(pin, limit):
    raw = _read_material(pin['path'], max_bytes=limit, return_bytes=True)
    if not raw or _digest(raw) != pin['sha256']:
        _fail()
    return raw


def trust_options(value, role):
    selected = _selected(value, role)
    connection = selected['connection']
    if _material(selected['caFile'],16384) != connection['rootsPEM'].encode():
        _fail()
    return dict(connection)


def _credential(selected, pin, publish, subscribe):
    from native_security.nats_credentials import validate, CredentialError
    try:
        credential = validate(_material(pin,65536), account_public_key=selected['accountPublicKey'],
            publish_subjects=publish, subscribe_subjects=subscribe)
        if credential.public_key != pin['userPublicKey']:
            _fail()
    except CredentialError:
        _fail()


def transport_options(value, role):
    selected = _selected(value, role)
    trust_options(value, role)
    publish, subscribe, bindings = [], [], []
    for binding in selected['bindings']:
        instance = binding['instanceId']
        prefix = 'amx.v1.h.' + value['keys']['hubId'] + '.plugins.' + instance + '.'
        if role == 'lifecycle':
            outgoing, incoming = [prefix+'lifecycle.control'], [prefix+'lifecycle.event']
            result = {'instanceId':instance,'pin':binding['pin'],'credentialsFile':binding['credentials']['path']}
            if binding['workspace'] is not None:
                result['workspace'] = binding['workspace']
        else:
            outgoing = [prefix+'context.reply',prefix+'operation.invoke',prefix+'operation.cancel']
            incoming = [prefix+'context.request',prefix+'operation.result']
            result = {'instanceId':instance,'clientCredentialsFile':binding['credentials']['path']}
        _credential(selected,binding['credentials'],incoming,outgoing)
        publish.extend(outgoing)
        subscribe.extend(incoming)
        bindings.append(result)
    server, field = (('controllerCredentials','controllerCredentialsFile') if role == 'lifecycle'
                     else ('serverCredentials','serverCredentialsFile'))
    _credential(selected,selected[server],publish,subscribe)
    result = {'hubId':value['keys']['hubId'],'accountPublicKey':selected['accountPublicKey'],
        'serverURL':selected['connection']['endpoint'],'caFile':selected['caFile']['path'],
        field:selected[server]['path'],'bindings':bindings}
    if role == 'lifecycle':
        result['stateDirectory'] = selected['stateDirectory']
    return result
