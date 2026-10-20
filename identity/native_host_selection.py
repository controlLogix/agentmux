"""Explicit native host pins; provisioning and live authority remain separate."""
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from .application_enrollment import _read_material, _write_material
from .application_host_selection import ApplicationHostSelectionReceipt, _nkey, _path, _check_connection
from .application_service_selection import _outside, _digest, validate_protected_host_account
from .capability_routes import CAPABILITY_DESTINATIONS
from .downstream import CAPABILITY_REPLIES


def _fail():
    raise ContractError('native_host_selection_invalid')


def _authority_subject(value):
    keys = value['keys']
    return f"amx.v1.h.{keys['hubId']}.o.{keys['organizationId']}.identity.{keys['authorityId']}.command"


def _capability_subject(route):
    service, scope = route['service'], route['scope']
    return '.'.join(('amx', 'v1', 'h', service['hubId'], 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_',
        'capability', service['serviceId'], 'command'))


def _configuration_subject(route):
    scope = route['scope']
    return '.'.join(('amx', 'v1', 'h', route['service']['hubId'], 'o', scope['organizationId'],
        'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_',
        'configuration', route['configurationRef']['id'], 'command'))


def _publish_subjects(value):
    keys = value['keys']
    subjects = {_authority_subject(value), *(_capability_subject(r) for r in value['capabilityRoutes'])}
    subjects.update(_configuration_subject(r) for r in value.get('configurationRoutes', {}).values())
    subjects.update(_configuration_subject({**r, 'configurationRef':r['source']['configurationRef']})
                    for r in value.get('subscriptionRoutes', []))
    prefixes = ['$JS.API.']
    if keys['domain']:
        prefixes.append('$JS.' + keys['domain'] + '.API.')
    for prefix in prefixes:
        for operation in ('STREAM.INFO.', 'STREAM.MSG.GET.'):
            subjects.add(prefix + operation + keys['stream'])
    if len(subjects) > 16:
        _fail()
    return tuple(sorted(subjects))


def _check(value):
    import os
    try:
        validate('native-authority-host-selection', value)
        keys, kernel = value['keys'], value['kernelScope']
        if (len(canonical_bytes(value)) > 65536 or value['ownerUid'] != os.getuid()
                or value['requestSigner']['ref'] != keys['hostTransportRef']
                or any(keys[k] != kernel[k] for k in ('profileId', 'hubId'))
                or not 1 <= len(value['workspaces']) <= 16
                or not all(_path(p) for p in [value['hostPolicy'], *value['workspaces']])):
            _fail()
        for path in (value['hostPolicy'], value['credentials']['path'], value['requestSigner']['keyFile']['path']):
            _outside(path, value['workspaces'])
        now = datetime.now(timezone.utc)
        created = datetime.fromisoformat(keys['streamCreated'])
        if created.tzinfo is None or created > now:
            _fail()
        _check_connection(value['connection'], now)
        if (not _nkey(value['credentials']['accountPublicKey'], 0)
                or not _nkey(value['credentials']['userPublicKey'], 160)):
            _fail()
        public = base64.urlsafe_b64decode(value['requestSigner']['publicKey'] + '=')
        if len(public) != 32 or base64.urlsafe_b64encode(public).decode().rstrip('=') != value['requestSigner']['publicKey']:
            _fail()
        refs = [keys[k] for k in ('hostTransportRef', 'hostIdentityRef', 'issuerRef', 'issuerIdentityRef')]
        if len({canonical_bytes(ref) for ref in refs}) != len(refs):
            _fail()
        bindings = set()
        for route in value['capabilityRoutes']:
            service, scope = route['service'], route['scope']
            if (route['bindingId'] in bindings
                    or CAPABILITY_DESTINATIONS.get(route['requestContractId']) != service['serviceId']
                    or CAPABILITY_REPLIES.get(route['requestContractId']) != route['replyContractId']
                    or any(service[k] != keys[k] for k in ('profileId', 'hubId'))
                    or scope['organizationId'] != keys['organizationId']
                    or scope['workspaceId'] is not None and scope['projectId'] is None):
                _fail()
            bindings.add(route['bindingId'])
            refs += [service['serviceIdentityRef'], service['signingKeyRef']]
        if any(ref['ownerHubId'] != keys['hubId'] for ref in refs):
            _fail()
        declarations = value.get('activationDeclarations')
        if declarations is not None:
            if set(declarations) != set(value['destinations']):
                _fail()
            for instance, declaration in declarations.items():
                reference, previous = declaration['recordRef'], declaration['previousRef']
                facts = declaration['facts']
                grant, policy = facts['grant'], facts['policy']
                from .native_records import validate_private_storage_resources
                validate_private_storage_resources(declaration.get('privateStorageResources', []), facts)
                sources = declaration.get('configurationEventSources', [])
                source_keys = [(s['configurationRef']['ownerHubId'], s['configurationRef']['id']) for s in sources]
                if (len(source_keys) != len(set(source_keys)) or any(
                        s['configurationRef']['ownerHubId'] != keys['hubId'] or not any(
                            b['contractId'] == 'configuration-change-subscribe'
                            and b['action'] == 'subscribe' and b['resourceClass'] == 'configuration'
                            and s['configurationRef']['id'] in b['resourceIds']
                            for b in facts['domainBindings']) for s in sources)):
                    _fail()
                if (any(r['ownerHubId'] != keys['hubId'] for r in (reference, declaration['identityRef']))
                        or declaration['identityRef'] == keys['hostIdentityRef']
                        or declaration['manifestDigest'] != declaration['pin']['manifestChecksum']
                        or grant['subjectInstanceId'] != instance or policy['subjectInstanceId'] != instance
                        or grant['issuerHubId'] != keys['hubId'] or grant['scope'] != policy['scope']
                        or grant['scope']['organizationId'] != keys['organizationId']
                        or grant['policyRef'] != policy['reference']
                        or policy['reference']['ownerHubId'] != keys['hubId']
                        or facts['scopeRef']['ownerHubId'] != keys['hubId']):
                    _fail()
                if previous is None:
                    if reference['revision'] != 1:
                        _fail()
                elif (previous['id'] != reference['id'] or previous['ownerHubId'] != reference['ownerHubId']
                      or reference['revision'] != previous['revision'] + 1):
                    _fail()
        from .native_transport_selection import check_transports
        check_transports(value, now)
        _publish_subjects(value)
    except (ValueError, TypeError, KeyError, OSError):
        _fail()


@dataclass(frozen=True, repr=False)
class NativeHostSelection:
    """Immutable enrollment inputs, never an admitted live authority provider."""
    document: bytes

    def __repr__(self):
        return '<NativeHostSelection private>'

    @property
    def policy(self):
        return strict_loads(self.document)

    def key_options(self):
        return self.policy['keys']

    def destinations(self):
        return self.policy['destinations']

    def capability_routes(self):
        return self.policy['capabilityRoutes']

    def activation_declarations(self):
        """Admitted declaration inputs; the manager must supply the actual owner."""
        declarations = self.policy.get('activationDeclarations')
        if declarations is None:
            _fail()
        return declarations

    def driver_options(self):
        from .native_transport_selection import transport_options
        return transport_options(self.policy, 'lifecycle')

    def context_options(self):
        from .native_transport_selection import transport_options
        return transport_options(self.policy, 'contextTransport')

    def lifecycle_trust_options(self):
        from .native_transport_selection import trust_options
        return trust_options(self.policy, 'lifecycle')

    def context_trust_options(self):
        from .native_transport_selection import trust_options
        return trust_options(self.policy, 'contextTransport')

    def configuration_routes(self):
        routes = self.policy.get('configurationRoutes')
        if routes is None:
            _fail()
        return routes

    def configuration_transport_options(self, instance_id):
        route = self.configuration_routes().get(instance_id)
        if route is None:
            _fail()
        result = self.transport_options()
        result['subject'] = _configuration_subject(route)
        return result

    def subscription_routes(self):
        routes = self.policy.get('subscriptionRoutes')
        if not routes:
            _fail()
        return routes

    def subscription_transport_options(self, binding_id, resource_id):
        routes = [r for r in self.subscription_routes() if r['bindingId'] == binding_id
                  and r['source']['configurationRef']['id'] == resource_id]
        if len(routes) != 1:
            _fail()
        route = routes[0]
        result = self.transport_options()
        result['subject'] = _configuration_subject({**route, 'configurationRef':route['source']['configurationRef']})
        return result

    def client_options(self):
        """Public pins for NativeAuthorityClientOptions; Go supplies keys/exchange."""
        value = self.policy
        keys = value['keys']
        return {**{k:keys[k] for k in ('profileId', 'hubId', 'authorityId')},
            'requestSigningRef':value['requestSigner']['ref'], 'responseSigningRef':keys['issuerRef'],
            'replyPrefix':value['credentials']['replyPrefix']}

    def read_signer_material(self):
        """Read the exact raw Ed25519 seed; current enrollment is checked by Go."""
        signer = self.policy['requestSigner']
        pin = signer['keyFile']
        raw = _read_material(pin['path'], max_bytes=32, return_bytes=True)
        if len(raw) != 32 or _digest(raw) != pin['sha256']:
            _fail()
        public = base64.urlsafe_b64encode(bytes(SigningKey(raw).verify_key)).decode().rstrip('=')
        if public != signer['publicKey']:
            _fail()
        return raw

    def authority_subject(self):
        return _authority_subject(self.policy)

    def capability_subject(self, binding_id):
        routes = [r for r in self.capability_routes() if r['bindingId'] == binding_id]
        if len(routes) != 1:
            _fail()
        return _capability_subject(routes[0])

    def publish_subjects(self):
        return _publish_subjects(self.policy)

    def load_credentials(self):
        """Validate current private JWT bytes with only derived exact subjects."""
        from native_security.nats_credentials import validate as validate_credentials, CredentialError
        selected = self.policy['credentials']
        raw = _read_material(selected['path'], max_bytes=65536, return_bytes=True)
        if _digest(raw) != selected['sha256']:
            _fail()
        try:
            result = validate_credentials(raw, account_public_key=selected['accountPublicKey'],
                publish_subjects=self.publish_subjects(),
                subscribe_subjects=[selected['replyPrefix']+'.>'], private_inbox=True)
            if result.public_key != selected['userPublicKey']:
                _fail()
            return result
        except CredentialError:
            _fail()

    def transport_options(self, *, binding_id=None):
        """Map validated pins to NativeAuthorityNATSOptions; host constructs TLS trust.

        Go must re-admit the credential path at connection time. This snapshot
        neither opens a connection nor transfers its ownership to Python.
        """
        self.load_credentials()
        value = self.policy
        return {'serverURL':value['connection']['endpoint'],
            'subject':self.authority_subject() if binding_id is None else self.capability_subject(binding_id),
            'credentialsFile':value['credentials']['path'],
            'accountPublicKey':value['credentials']['accountPublicKey'],
            'replyPrefix':value['credentials']['replyPrefix'],
            'publishSubjects':list(self.publish_subjects()), 'connection':value['connection']}


def write_native_host_selection(path, selection):
    """Create only; never create identities, keys, memberships or grants."""
    _check(selection)
    _outside(str(path), selection['workspaces'])
    raw = canonical_bytes(selection)
    _write_material(path, selection, max_bytes=65536)
    return ApplicationHostSelectionReceipt(str(path), _digest(raw))


def load_native_host_selection(path, *, expected_digest, host_policy, owner_uid,
                               workspaces, kernel_scope, protected_host_account):
    validate_protected_host_account(protected_host_account)
    _outside(str(path), workspaces)
    raw = _read_material(path, max_bytes=65536, return_bytes=True)
    if _digest(raw) != expected_digest:
        _fail()
    value = strict_loads(raw)
    _check(value)
    if any(value[k] != v for k, v in {'hostPolicy':host_policy, 'ownerUid':owner_uid,
            'workspaces':list(workspaces), 'kernelScope':kernel_scope}.items()):
        _fail()
    return NativeHostSelection(canonical_bytes(value))
