"""Explicit client key custody and verification; no connections or ambient trust."""
import base64
import hashlib
from datetime import datetime, timezone, timedelta
import secrets

from nacl.signing import SigningKey
from agentmux_contracts import (ContractError, canonical_bytes, payload_digest, sign_claims,
                                strict_loads, validate)
from .application_binding import verify_response, _interval
from .application_enrollment import _read_material, _write_material

_PINS = ('hubId', 'profileId', 'authorityId', 'instanceId', 'releaseDigest',
         'policyRef', 'workspaceRef', 'transportRef', 'grantRef')
_INTEGRATION_LIFECYCLE_COMMANDS = ('integration-intent', 'integration-attempt-start',
                                   'integration-attempt-complete', 'integration-effect-reconcile')
_DYNAMIC_INTEGRATION_COMMANDS = ('integration-intent', 'integration-effect-query',
                                 'integration-attempt-start', 'integration-attempt-complete',
                                 'integration-effect-reconcile')


class ApplicationClientKey:
    def __init__(self, material):
        validate('application-client-key', material)
        self._material = canonical_bytes(material)
        self._seed = base64.b64decode(material['seed'], validate=True)
        if len(self._seed) != 32 or base64.b64encode(self._seed).decode() != material['seed']:
            raise ContractError('application_client_key_invalid')
        public = base64.urlsafe_b64decode(material['replyIssuerPublicKey'] + '=')
        if base64.urlsafe_b64encode(public).decode().rstrip('=') != material['replyIssuerPublicKey']:
            raise ContractError('application_client_key_invalid')
        if any(material[key]['ownerHubId'] != material['hubId'] for key in
               ('callerRef', 'transportRef', 'grantRef', 'replyIssuerRef', 'policyRef')):
            raise ContractError('application_client_key_invalid')
        if material['workspaceRef'] is not None and material['workspaceRef']['ownerHubId'] != material['hubId']:
            raise ContractError('application_client_key_invalid')
        self._authority_switch_seal = object()
        from .message_client import check_enrollment
        check_enrollment(material)
        if 'knowledgeCommands' in material:
            from .knowledge_client import check_enrollment as check_knowledge_enrollment
            check_knowledge_enrollment(material)
        if 'codeCommands' in material:
            from .code_client import check_enrollment as check_code_enrollment
            check_code_enrollment(material)
        if 'workCommands' in material:
            from .work_client import check_enrollment as check_work_enrollment
            check_work_enrollment(material)
        if 'peerControlCommands' in material:
            from .peer_control_commands import check_enrollment as check_peer_control_enrollment
            check_peer_control_enrollment(material)
        if 'federationPolicyCommands' in material:
            from .federation_policy_commands import check_enrollment as check_policy_enrollment
            check_policy_enrollment(material)

        selected = material.get('integrationEffectQuery')
        if selected is not None:
            from integration_owner.intent import effect_id
            scope = material['scope']
            expected = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
                                  'integrations', effect_id(scope, selected['originalOperationId']), 'command'))
            public = base64.urlsafe_b64decode(selected['replyIssuerPublicKey'] + '=')
            if (scope['projectId'] is None or selected['subject'] != expected
                    or selected['grantRef'] == material['grantRef']
                    or selected['transportRef'] == material['transportRef']
                    or any(selected[k]['ownerHubId'] != material['hubId'] for k in ('grantRef', 'transportRef', 'replyIssuerRef'))
                    or base64.urlsafe_b64encode(public).decode().rstrip('=') != selected['replyIssuerPublicKey']):
                raise ContractError('application_client_command_enrollment')
        commands = material.get('integrationEffectCommands')
        if commands is not None:
            public = base64.urlsafe_b64decode(commands['replyIssuerPublicKey'] + '=')
            refs = (commands['transportRef'], commands['replyIssuerRef'])
            occupied_transports = {canonical_bytes(material['transportRef'])}
            if selected is not None:
                occupied_transports.add(canonical_bytes(selected['transportRef']))
            if (material['scope']['projectId'] is None
                    or any(ref['ownerHubId'] != material['hubId'] for ref in refs)
                    or canonical_bytes(commands['transportRef']) in occupied_transports
                    or base64.urlsafe_b64encode(public).decode().rstrip('=')
                    != commands['replyIssuerPublicKey']):
                raise ContractError('application_client_command_enrollment')
        resolver = material.get('legacyAliasResolve')
        if resolver is not None:
            scope = material['scope']
            expected = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
                                 'identity', material['authorityId'], 'command'))
            public = base64.urlsafe_b64decode(resolver['replyIssuerPublicKey'] + '=')
            if (scope['projectId'] is None or resolver['subject'] != expected
                    or resolver['grantRef'] == material['grantRef']
                    or resolver['transportRef'] == material['transportRef']
                    or resolver['replyIssuerRef'] != material['replyIssuerRef']
                    or resolver['replyIssuerPublicKey'] != material['replyIssuerPublicKey']
                    or any(resolver[k]['ownerHubId'] != material['hubId']
                           for k in ('grantRef', 'transportRef', 'replyIssuerRef'))
                    or base64.urlsafe_b64encode(public).decode().rstrip('=') != resolver['replyIssuerPublicKey']):
                raise ContractError('application_client_command_enrollment')
            if selected is not None and (resolver['grantRef'] == selected['grantRef']
                    or resolver['transportRef'] == selected['transportRef']):
                raise ContractError('application_client_command_enrollment')
            if commands is not None and resolver['transportRef'] == commands['transportRef']:
                raise ContractError('application_client_command_enrollment')
        recovery = material.get('authoritySwitchRecovery')
        if recovery is not None:
            from state_owner.authority_switch import authority_switch_id
            scope = material['scope']
            expected = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o',
                scope['organizationId'], 'authority-switch', recovery['switchId'], 'command'))
            public = base64.urlsafe_b64decode(recovery['replyIssuerPublicKey'] + '=')
            occupied = {canonical_bytes(material['transportRef'])}
            for row in (selected, commands, resolver):
                if row is not None:
                    occupied.add(canonical_bytes(row['transportRef']))
            if (recovery['subject'] != expected
                    or authority_switch_id(recovery['source']) != recovery['switchId']
                    or recovery['grantRef'] == material['grantRef']
                    or recovery['replyIssuerRef'] == material['replyIssuerRef']
                    or recovery['replyIssuerPublicKey'] == material['replyIssuerPublicKey']
                    or canonical_bytes(recovery['transportRef']) in occupied
                    or any(recovery[k]['ownerHubId'] != material['hubId']
                           for k in ('grantRef', 'transportRef', 'replyIssuerRef',
                                     'serviceIdentityRef'))
                    or base64.urlsafe_b64encode(public).decode().rstrip('=')
                        != recovery['replyIssuerPublicKey']):
                raise ContractError('application_client_command_enrollment')
        browser = material.get('localBrowserSessionOpen')
        if browser is not None:
            scope = material['scope']
            expected = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
                                 'identity', material['authorityId'], 'command'))
            public = base64.urlsafe_b64decode(browser['replyIssuerPublicKey'] + '=')
            occupied = {canonical_bytes(material['transportRef'])}
            for row in (selected, commands, resolver, recovery):
                if row is not None:
                    occupied.add(canonical_bytes(row['transportRef']))
            if (scope['projectId'] is None or browser['subject'] != expected
                    or browser['grantRef'] == material['grantRef']
                    or canonical_bytes(browser['transportRef']) in occupied
                    or browser['replyIssuerRef'] != material['replyIssuerRef']
                    or browser['replyIssuerPublicKey'] != material['replyIssuerPublicKey']
                    or any(browser[k]['ownerHubId'] != material['hubId']
                           for k in ('grantRef', 'transportRef', 'replyIssuerRef'))
                    or base64.urlsafe_b64encode(public).decode().rstrip('=')
                    != browser['replyIssuerPublicKey']):
                raise ContractError('application_client_command_enrollment')
        terminal = material.get('oidcTerminalSession')
        if terminal is not None:
            scope = material['scope']
            expected = '.'.join(('amx', 'v1', 'h', material['hubId'], 'o', scope['organizationId'],
                                 'identity', material['authorityId'], 'command'))
            public = base64.urlsafe_b64decode(terminal['replyIssuerPublicKey'] + '=')
            occupied = {canonical_bytes(material['transportRef'])}
            for row in (selected, commands, resolver, recovery, browser):
                if row is not None:
                    occupied.add(canonical_bytes(row['transportRef']))
            if (scope['projectId'] is None or terminal['subject'] != expected
                    or material['grantRef'] in terminal['grantRefs'].values()
                    or len({canonical_bytes(ref) for ref in terminal['grantRefs'].values()}) != 3
                    or canonical_bytes(terminal['transportRef']) in occupied
                    or terminal['replyIssuerRef'] != material['replyIssuerRef']
                    or terminal['replyIssuerPublicKey'] != material['replyIssuerPublicKey']
                    or any(ref['ownerHubId'] != material['hubId']
                           for ref in terminal['grantRefs'].values())
                    or any(terminal[k]['ownerHubId'] != material['hubId']
                           for k in ('transportRef', 'replyIssuerRef'))
                    or base64.urlsafe_b64encode(public).decode().rstrip('=')
                    != terminal['replyIssuerPublicKey']):
                raise ContractError('application_client_command_enrollment')

    def __repr__(self):
        return '<ApplicationClientKey private>'

    @property
    def selection(self):
        material = strict_loads(self._material)
        return {key: value for key, value in material.items() if key not in ('seed', 'purpose')}

    @property
    def public_key(self):
        return base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')

    def _check_claims(self, claims):
        selection = self.selection
        if any(claims.get(key) != selection[key] for key in _PINS):
            raise ContractError('application_client_binding')

    def _sign(self, claims, protocol, now):
        self._check_claims(claims)
        if claims.get('purpose') != 'agentmux-' + protocol + '-request-v1':
            raise ContractError('application_signing_purpose')
        _interval(claims, now or datetime.now(timezone.utc))
        request = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519', 'canonicalization': 'RFC8785-JCS-UTF8',
                   'claims': claims, 'signature': sign_claims(claims, self._seed)}
        validate(protocol + '-request', request)
        return canonical_bytes(request)

    def sign_discovery(self, claims, *, now=None):
        return self._sign(claims, 'application-discovery', now)

    def sign_binding(self, claims, *, now=None):
        return self._sign(claims, 'application-binding', now)

    def command_subject(self, contract_id, original_operation_id=None):
        selection = self.selection
        from .federation_policy_commands import COMMANDS as FEDERATION_POLICY_COMMANDS
        if contract_id in FEDERATION_POLICY_COMMANDS:
            selected = selection.get('federationPolicyCommands')
            if selected is None:
                raise ContractError('application_client_command_unavailable')
            return selected['subject']
        from .peer_control_commands import COMMANDS as PEER_CONTROL_COMMANDS
        if contract_id in PEER_CONTROL_COMMANDS:
            selected = selection.get('peerControlCommands')
            if selected is None or contract_id not in selected['grantRefs']:
                raise ContractError('application_client_command_unavailable')
            return selected['subject']
        from .authority import MESSAGE_COMMANDS
        if contract_id in MESSAGE_COMMANDS:
            selected = selection.get('messageCommands')
            if selected is None or contract_id not in selected['grantRefs']:
                raise ContractError('application_client_command_unavailable')
            return selected['subject']
        from .authority import KNOWLEDGE_COMMANDS
        if contract_id in KNOWLEDGE_COMMANDS:
            selected = selection.get('knowledgeCommands')
            if selected is None or contract_id not in selected['grantRefs']:
                raise ContractError('application_client_command_unavailable')
            return selected['subject']
        from .code_client import CODE_COMMANDS
        if contract_id in CODE_COMMANDS:
            selected = selection.get('codeCommands')
            if selected is None or contract_id not in selected['grantRefs']:
                raise ContractError('application_client_command_unavailable')
            return selected['subject']
        from .work_client import WORK_COMMANDS
        if contract_id in WORK_COMMANDS:
            selected = selection.get('workCommands')
            if selected is None or contract_id not in selected['grantRefs']:
                raise ContractError('application_client_command_unavailable')
            return selected['subject']
        commands = selection.get('integrationEffectCommands')
        if (contract_id in _DYNAMIC_INTEGRATION_COMMANDS and original_operation_id is not None
                and commands is not None and contract_id in commands['contracts']):
            if type(original_operation_id) is not str:
                raise ContractError('application_client_command_unavailable')
            from integration_owner.intent import effect_id
            scope = selection['scope']
            return '.'.join(('amx', 'v1', 'h', selection['hubId'], 'o', scope['organizationId'],
                             'integrations', effect_id(scope, original_operation_id), 'command'))
        field = {'integration-effect-query': 'integrationEffectQuery',
                 'identity-legacy-alias-resolve': 'legacyAliasResolve',
                 'authority-switch': 'authoritySwitchRecovery',
                 'local-browser-session-open': 'localBrowserSessionOpen',
                 'oidc-terminal-session-open': 'oidcTerminalSession',
                 'oidc-terminal-session-status': 'oidcTerminalSession',
                 'oidc-terminal-session-close': 'oidcTerminalSession'}.get(contract_id)
        selected = None if field is None else selection.get(field)
        if selected is None:
            raise ContractError('application_client_command_unavailable')
        return selected['subject']

    def _check_command(self, claims, subject):
        contract = claims.get('contractId')
        from .work_client import WORK_COMMANDS
        if 'workSource' in claims and contract not in WORK_COMMANDS:
            raise ContractError('application_client_command_binding')
        selection = self.selection
        from .federation_policy_commands import COMMANDS as FEDERATION_POLICY_COMMANDS
        if contract in FEDERATION_POLICY_COMMANDS:
            from .federation_policy_commands import check_command
            return check_command(selection, claims, subject)
        from .peer_control_commands import COMMANDS as PEER_CONTROL_COMMANDS
        if contract in PEER_CONTROL_COMMANDS:
            from .peer_control_commands import check_command
            return check_command(selection, claims, subject)
        from .authority import MESSAGE_COMMANDS
        if contract in MESSAGE_COMMANDS:
            from .message_client import check_command
            return check_command(selection, claims, subject)
        from .authority import KNOWLEDGE_COMMANDS
        if contract in KNOWLEDGE_COMMANDS:
            from .knowledge_client import check_command
            return check_command(selection, claims, subject)
        from .code_client import CODE_COMMANDS
        if contract in CODE_COMMANDS:
            from .code_client import check_command
            return check_command(selection, claims, subject)
        from .work_client import WORK_COMMANDS
        if contract in WORK_COMMANDS:
            from .work_client import check_command
            return check_command(selection, claims, subject)
        payload = claims.get('payload')
        commands = selection.get('integrationEffectCommands')
        dynamic = (contract in _DYNAMIC_INTEGRATION_COMMANDS and commands is not None
                   and contract in commands['contracts']
                   and claims.get('transportRef') == commands['transportRef'])
        if dynamic:
            selected = commands
            original = claims.get('operationId') if contract == 'integration-intent' else (
                payload.get('originalOperationId') if type(payload) is dict else None)
            expected_subject = self.command_subject(contract, original)
        else:
            field = {'integration-effect-query': 'integrationEffectQuery',
                     'identity-legacy-alias-resolve': 'legacyAliasResolve',
                     'authority-switch': 'authoritySwitchRecovery',
                     'local-browser-session-open': 'localBrowserSessionOpen',
                     'oidc-terminal-session-open': 'oidcTerminalSession',
                     'oidc-terminal-session-status': 'oidcTerminalSession',
                     'oidc-terminal-session-close': 'oidcTerminalSession'}.get(contract)
            selected = None if field is None else selection.get(field)
            expected_subject = self.command_subject(contract)
        if selected is None:
            raise ContractError('application_client_command_unavailable')
        if subject != expected_subject:
            raise ContractError('application_client_command_binding')
        if (claims.get('purpose') != 'agentmux-client-possession-v1'
                or any(claims.get(k) != selection[k] for k in ('hubId', 'profileId', 'authorityId'))
                or claims.get('transportRef') != selected['transportRef']
                or claims.get('grantRef', {}).get('ownerHubId') != selection['hubId']
                or not dynamic and contract not in ('oidc-terminal-session-open',
                    'oidc-terminal-session-status', 'oidc-terminal-session-close')
                    and claims.get('grantRef') != selected['grantRef']
                or contract in ('oidc-terminal-session-open',
                    'oidc-terminal-session-status', 'oidc-terminal-session-close')
                    and claims.get('grantRef') != selected['grantRefs'][contract]
                or 'replySubject' not in claims):
            raise ContractError('application_client_command_binding')
        if ('oidcTerminalSession' in selection
                and contract not in ('oidc-terminal-session-open',
                                     'oidc-terminal-session-status',
                                     'oidc-terminal-session-close',
                                     'local-browser-session-open')
                and not isinstance(claims.get('terminalSessionId'), str)):
            raise ContractError('application_client_command_binding')
        validate(contract, claims['payload'])
        payload = claims['payload']
        if dynamic:
            effect = payload['effectRef']
            approvals = claims.get('approvalRefs')
            operation = claims.get('operationId')
            if (effect['ownerHubId'] != selection['hubId']
                    or effect['id'] != expected_subject.split('.')[-2]
                    or effect['revision'] != claims.get('expectedVersion')
                    or any(ref['ownerHubId'] != selection['hubId'] for ref in approvals or ())):
                raise ContractError('application_client_command_binding')
            if contract == 'integration-effect-query':
                if operation == payload['originalOperationId']:
                    raise ContractError('application_client_command_binding')
            elif contract == 'integration-intent':
                if claims.get('expectedVersion') != 0 or not approvals:
                    raise ContractError('application_client_command_binding')
            elif (payload['attemptOperationId'] == payload['originalOperationId']
                    or operation == payload['originalOperationId']):
                raise ContractError('application_client_command_binding')
            elif contract == 'integration-attempt-start':
                if (operation != payload['attemptOperationId'] or claims.get('expectedVersion') != 1
                        or not approvals):
                    raise ContractError('application_client_command_binding')
            elif operation == payload['attemptOperationId'] or claims.get('expectedVersion', 0) < 2:
                raise ContractError('application_client_command_binding')
        elif contract == 'integration-effect-query':
            if (payload['effectRef']['ownerHubId'] != selection['hubId']
                    or payload['effectRef']['id'] != subject.split('.')[-2]
                    or payload['effectRef']['revision'] != claims.get('expectedVersion')
                    or payload['originalOperationId'] != selected['originalOperationId']
                    or payload['originalPayloadDigest'] != selected['originalPayloadDigest']
                    or claims.get('operationId') == selected['originalOperationId']
                    or any(r['ownerHubId'] != selection['hubId'] for r in claims.get('approvalRefs', []))):
                raise ContractError('application_client_command_binding')
        elif contract == 'identity-legacy-alias-resolve':
            if (payload['authorityId'] != selection['authorityId']
                    or claims.get('expectedVersion') != 0 or claims.get('approvalRefs') != []):
                raise ContractError('application_client_command_binding')
        elif contract == 'authority-switch':
            if (payload != {'action': 'request-recovery',
                    'switchId': selected['switchId'], 'source': selected['source']}
                    or claims.get('expectedVersion') != 1
                    or claims.get('approvalRefs') != []):
                raise ContractError('application_client_command_binding')
        elif (contract not in ('local-browser-session-open',
                               'oidc-terminal-session-open',
                               'oidc-terminal-session-status',
                               'oidc-terminal-session-close')
                or claims.get('expectedVersion') != 0 or claims.get('approvalRefs') != []):
            raise ContractError('application_client_command_binding')
        elif (contract == 'local-browser-session-open'
                and not 1 <= int(payload['origin'].rsplit(':', 1)[1]) <= 65535):
            raise ContractError('application_client_command_binding')
        return selected

    def sign_command(self, claims, *, subject, now=None):
        """Sign only an explicitly enrolled command route."""
        validate('identity-ingress-request', {'schemaVersion': '1.0.0', 'claims': claims, 'signature': 'A' * 86})
        self._check_command(claims, subject)
        now = now if now is not None else datetime.now(timezone.utc)
        try:
            issued, expiry = (datetime.fromisoformat(claims[k]) for k in ('issuedAt', 'expiresAt'))
            if not issued <= now < expiry or expiry - issued > timedelta(seconds=60):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise ContractError('application_signing_time') from None
        request = {'schemaVersion': '1.0.0', 'claims': claims, 'signature': sign_claims(claims, self._seed)}
        validate('identity-ingress-request', request)
        raw = canonical_bytes(request)
        from .authority import LEGACY_STORAGE_COMMANDS
        if len(raw) > (1048576 if claims['contractId'] in LEGACY_STORAGE_COMMANDS else 65536):
            raise ContractError('owner_body_limit')
        return raw

    def verify_command_response(self, raw, request, *, subject, now=None, include_valid_until=False):
        """Verify the exact enrolled command reply; late replies do not renew authority."""
        from .ingress import verify_possession
        from integration_owner.receipts import verify_receipt
        if type(request) is not bytes or len(request) > 1048576:
            raise ContractError('owner_body_limit')
        parsed, selected = self.verify_command_request(request, subject=subject)
        from .work_client import WORK_COMMANDS
        if (include_valid_until and parsed['claims']['contractId'] not in WORK_COMMANDS
                and parsed['claims']['contractId'] not in (
                'federation-code-outcome', 'federation-code-read', 'federation-message-outcome')):
            raise ContractError('application_client_command_unavailable')
        from .federation_policy_commands import COMMANDS as FEDERATION_POLICY_COMMANDS
        if parsed['claims']['contractId'] in FEDERATION_POLICY_COMMANDS:
            from .federation_policy_client import verify_policy_client_response
            return verify_policy_client_response(raw, request,
                reply_subject=parsed['claims']['replySubject'], public_key=selected['replyIssuerPublicKey'],
                issuer_ref=selected['replyIssuerRef'], target=selected['target'], owner=selected['owner'],
                caller_ref=self.selection['callerRef'], scope=self.selection['scope'],
                now=now or datetime.now(timezone.utc))
        from .peer_control_commands import COMMANDS as PEER_CONTROL_COMMANDS
        if parsed['claims']['contractId'] in PEER_CONTROL_COMMANDS:
            from capability_owner.peer_control_service import verify_peer_control_reply
            return verify_peer_control_reply(raw, request, public_key=selected['replyIssuerPublicKey'],
                service_identity_ref=selected['serviceIdentityRef'], service_instance_id=selected['serviceInstanceId'],
                signing_key_ref=selected['replyIssuerRef'], now=now or datetime.now(timezone.utc))
        from .authority import MESSAGE_COMMANDS
        if parsed['claims']['contractId'] in MESSAGE_COMMANDS:
            from capability_owner.message_bridge_service import verify_message_bridge_reply
            return verify_message_bridge_reply(raw, request, public_key=selected['replyIssuerPublicKey'],
                service_identity_ref=selected['serviceIdentityRef'], service_instance_id=selected['serviceInstanceId'],
                signing_key_ref=selected['replyIssuerRef'], now=now or datetime.now(timezone.utc),
                include_valid_until=include_valid_until)
        from .authority import KNOWLEDGE_COMMANDS
        if parsed['claims']['contractId'] in KNOWLEDGE_COMMANDS:
            from capability_owner.knowledge_bridge_service import verify_knowledge_bridge_reply
            return verify_knowledge_bridge_reply(raw, request, public_key=selected['replyIssuerPublicKey'],
                service_identity_ref=selected['serviceIdentityRef'], service_instance_id=selected['serviceInstanceId'],
                signing_key_ref=selected['replyIssuerRef'], now=now or datetime.now(timezone.utc))
        from .code_client import CODE_COMMANDS
        if parsed['claims']['contractId'] in CODE_COMMANDS:
            from capability_owner.code_bridge_service import verify_code_bridge_reply
            return verify_code_bridge_reply(raw, request, public_key=selected['replyIssuerPublicKey'],
                service_identity_ref=selected['serviceIdentityRef'], service_instance_id=selected['serviceInstanceId'],
                signing_key_ref=selected['replyIssuerRef'], now=now or datetime.now(timezone.utc),
                include_valid_until=include_valid_until)
        if parsed['claims']['contractId'] in WORK_COMMANDS:
            from capability_owner.work_bridge_service import verify_work_bridge_reply
            return verify_work_bridge_reply(raw, request, public_key=selected['replyIssuerPublicKey'],
                service_identity_ref=selected['serviceIdentityRef'], service_instance_id=selected['serviceInstanceId'],
                signing_key_ref=selected['replyIssuerRef'], now=now or datetime.now(timezone.utc),
                include_valid_until=include_valid_until)
        if parsed['claims']['contractId'] in _DYNAMIC_INTEGRATION_COMMANDS:
            return verify_receipt(raw, request, public_key=selected['replyIssuerPublicKey'],
                                  issuer_ref=selected['replyIssuerRef'])
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('owner_body_limit')
        response = strict_loads(raw)
        terminal = {
            'oidc-terminal-session-open': ('oidc-terminal-session-open-response',
                'agentmux-oidc-terminal-session-open-response-v1'),
            'oidc-terminal-session-status': ('oidc-terminal-session-status-response',
                'agentmux-oidc-terminal-session-status-response-v1'),
            'oidc-terminal-session-close': ('oidc-terminal-session-close-response',
                'agentmux-oidc-terminal-session-close-response-v1')}
        contract = parsed['claims']['contractId']
        if contract in terminal:
            schema, purpose = terminal[contract]
            validate(schema, response)
            result = response['claims']
            verify_possession(result, response['signature'], selected['replyIssuerPublicKey'])
            wanted, selection = parsed['claims'], self.selection
            if (result.get('purpose') != purpose
                    or any(result.get(k) != selection[k]
                           for k in ('hubId', 'profileId', 'authorityId'))
                    or result.get('issuerRef') != selected['replyIssuerRef']
                    or result.get('requestDigest') != payload_digest(parsed)
                    or result.get('operationId') != wanted['operationId']):
                raise ContractError('application_client_command_binding')
            if (contract == 'oidc-terminal-session-status'
                    and result.get('attemptId') != wanted['payload']['attemptId']
                    or contract == 'oidc-terminal-session-close'
                    and result.get('sessionId') != wanted['payload']['sessionId']):
                raise ContractError('application_client_command_binding')
            if contract == 'oidc-terminal-session-status':
                approved = result['outcome'] == 'approved'
                if approved != (result['sessionId'] is not None
                                and result['sessionExpiresAt'] is not None):
                    raise ContractError('application_client_command_binding')
            now = datetime.now(timezone.utc) if now is None else now
            try:
                issued = datetime.fromisoformat(result['issuedAt'])
                valid = datetime.fromisoformat(result['validUntil'])
                request_issued = datetime.fromisoformat(wanted['issuedAt'])
                request_expires = datetime.fromisoformat(wanted['expiresAt'])
                if (any(value.utcoffset() != timedelta(0) for value in
                        (issued, valid, request_issued, request_expires, now))
                        or not request_issued <= issued <= now < valid <= request_expires):
                    raise ValueError()
            except (ValueError, TypeError, KeyError, AttributeError):
                raise ContractError('application_client_command_binding') from None
            return strict_loads(canonical_bytes(result))
        if parsed['claims']['contractId'] == 'local-browser-session-open':
            validate('local-browser-session-response', response)
            result = response['claims']
            verify_possession(result, response['signature'], selected['replyIssuerPublicKey'])
            wanted, selection = parsed['claims'], self.selection
            digest = 'sha256:' + hashlib.sha256(
                wanted['payload']['challenge'].encode('ascii')).hexdigest()
            if (result.get('purpose') != 'agentmux-local-browser-session-response-v1'
                    or any(result.get(k) != selection[k] for k in ('hubId', 'profileId', 'authorityId'))
                    or result.get('issuerRef') != selected['replyIssuerRef']
                    or result.get('requestDigest') != payload_digest(parsed)
                    or result.get('operationId') != wanted['operationId']
                    or result.get('challengeDigest') != digest
                    or result.get('callerRef') != selection['callerRef']
                    or result.get('scope') != selection['scope']
                    or result.get('outcome') != 'approved'):
                raise ContractError('application_client_command_binding')
            now = datetime.now(timezone.utc) if now is None else now
            try:
                issued = datetime.fromisoformat(result['issuedAt'])
                valid = datetime.fromisoformat(result['validUntil'])
                request_issued = datetime.fromisoformat(wanted['issuedAt'])
                request_expires = datetime.fromisoformat(wanted['expiresAt'])
                if (any(value.utcoffset() != timedelta(0) for value in
                        (issued, valid, request_issued, request_expires, now))
                        or not request_issued <= issued <= now < valid <= request_expires):
                    raise ValueError()
            except (ValueError, TypeError, KeyError, AttributeError):
                raise ContractError('application_client_command_binding') from None
            return strict_loads(canonical_bytes(result))
        if parsed['claims']['contractId'] == 'authority-switch':
            from state_owner.authority_switch_service import verify_recovery_response
            from state_owner.ledger import StreamIdentity
            selected = self.selection['authoritySwitchRecovery']
            stream = selected['streamIdentity']
            return verify_recovery_response(raw, request,
                public_key=selected['replyIssuerPublicKey'],
                signing_key_ref=selected['replyIssuerRef'],
                service_identity_ref=selected['serviceIdentityRef'],
                service_instance_id=selected['serviceInstanceId'],
                source=selected['source'], switch_id=selected['switchId'],
                expected_scope={'organizationId': self.selection['scope']['organizationId'],
                    'projectId': None, 'workspaceId': None},
                caller_ref=self.selection['callerRef'],
                stream_identity=StreamIdentity(datetime.fromisoformat(stream['created']),
                                               stream['minimumSequence']),
                seal=self._authority_switch_seal,
                now=datetime.now(timezone.utc) if now is None else now)
        validate('identity-legacy-alias-resolution', response)
        result = response['claims']
        verify_possession(result, response['signature'], selected['replyIssuerPublicKey'])
        wanted, selection = parsed['claims'], self.selection
        remote = 'remoteAddress' in wanted['payload']
        expected_selector = ({'remoteAddress': wanted['payload']['remoteAddress']} if remote else
                             {'registrations': wanted['payload']['registrations']})
        if (result.get('purpose') != 'agentmux-legacy-alias-resolution-v1'
                or any(result.get(k) != selection[k] for k in ('hubId', 'profileId', 'authorityId'))
                or result.get('issuerRef') != selected['replyIssuerRef']
                or result.get('requestDigest') != payload_digest(parsed)
                or result.get('operationId') != wanted['operationId']
                or result.get('callerRef') != selection['callerRef']
                or result.get('scope') != selection['scope']
                or any(result.get(key) != value for key, value in expected_selector.items())
                or ('registrations' in result) == remote
                or ('remoteAddress' in result) != remote
                or len(result.get('bindings', ())) !=
                    (1 if remote else len(wanted['payload']['registrations']))):
            raise ContractError('application_client_command_binding')
        now = datetime.now(timezone.utc) if now is None else now
        try:
            issued = datetime.fromisoformat(result['issuedAt'])
            valid = datetime.fromisoformat(result['validUntil'])
            request_issued = datetime.fromisoformat(wanted['issuedAt'])
            request_expires = datetime.fromisoformat(wanted['expiresAt'])
            if (any(value.utcoffset() != timedelta(0) for value in
                    (issued, valid, request_issued, request_expires, now))
                    or not request_issued <= issued <= now < valid <= request_expires):
                raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ContractError('application_client_command_binding') from None
        from .legacy_identity import LegacyIdentityBinding, VerifiedLegacyAliasResolution
        bindings = []
        registrations = wanted['payload'].get('registrations', (None,))
        for registration, binding in zip(registrations, result['bindings']):
            if ((remote and 'agent:' + binding['canonicalSession'] != wanted['payload']['remoteAddress'])
                    or not remote and (binding['canonicalSession'] != registration['canonicalSession']
                    or binding['registrationGeneration'] != registration['registrationGeneration']
                    or binding['sourceHubId'] != selection['hubId'])
                    or binding['scope'] != selection['scope']
                    or binding['authoritySequence'] != result['authoritySequence']
                    or binding['identityRef']['ownerHubId'] != selection['hubId']
                    or binding['aliasRef']['ownerHubId'] != selection['hubId']
                    or binding['instanceOwner'] is not None
                    or not remote and registration['legacyAlias'] is not None
                    and binding['alias'] != registration['legacyAlias']):
                raise ContractError('application_client_command_binding')
            bindings.append(LegacyIdentityBinding(binding['alias'], binding['canonicalSession'],
                binding['sourceHubId'], binding['registrationGeneration'],
                canonical_bytes(binding['identityRef']), canonical_bytes(binding['scope']),
                canonical_bytes(binding['instanceOwner']), canonical_bytes(binding['aliasRef']),
                binding['authoritySequence'], not remote))
        return VerifiedLegacyAliasResolution(tuple(bindings), valid)

    def verify_command_request(self, request, *, subject):
        """Verify one exact signed request before a connection admits its subject."""
        from .ingress import verify_possession
        if type(request) is not bytes or len(request) > 1048576:
            raise ContractError('owner_body_limit')
        parsed = strict_loads(request)
        validate('identity-ingress-request', parsed)
        from .authority import LEGACY_STORAGE_COMMANDS
        if parsed['claims']['contractId'] not in LEGACY_STORAGE_COMMANDS and len(request) > 65536:
            raise ContractError('owner_body_limit')
        if parsed['claims']['contractId'] in LEGACY_STORAGE_COMMANDS and canonical_bytes(parsed) != request:
            raise ContractError('application_client_command_binding')
        selected = self._check_command(parsed['claims'], subject)
        verify_possession(parsed['claims'], parsed['signature'], self.public_key)
        return parsed, selected

    def verify_response(self, raw, request, *, now):
        claims = strict_loads(request)['claims']
        self._check_claims(claims)
        purpose = claims.get('purpose')
        if purpose not in ('agentmux-application-discovery-request-v1', 'agentmux-application-binding-request-v1'):
            raise ContractError('application_signing_purpose')
        selection = self.selection
        result = verify_response(raw, request, public_key=selection['replyIssuerPublicKey'],
            signing_key_ref=selection['replyIssuerRef'], now=now,
            discovery=purpose == 'agentmux-application-discovery-request-v1')
        if result['callerRef'] != selection['callerRef'] or result['scope'] != selection['scope']:
            raise ContractError('application_client_binding')
        return result


def load_application_client(path):
    """Load only an explicitly provisioned native-private client key store."""
    return ApplicationClientKey(_read_material(path))


def provision_application_client(path, *, selection, identity, issued_at, expires_at):
    """Create only; return public enrollment proof, never implicit membership/access."""
    if identity.get('kind') not in ('human', 'device', 'service') or identity.get('status') != 'active':
        raise ContractError('application_client_identity')
    material = {**selection, 'purpose': 'agentmux-application-client-key-v1',
                'seed': base64.b64encode(secrets.token_bytes(32)).decode()}
    signer = ApplicationClientKey(material)
    if material['callerRef'] != identity['ref'] or material['transportRef']['revision'] != 1:
        raise ContractError('application_client_binding')
    start, end = datetime.fromisoformat(issued_at), datetime.fromisoformat(expires_at)
    if start.tzinfo != timezone.utc or end.tzinfo != timezone.utc or start >= end:
        raise ContractError('application_signing_time')
    transport = {'ref': material['transportRef'], 'identityRef': identity['ref'],
        'issuerRef': material['replyIssuerRef'], 'status': 'active', 'method': 'nats-credential-mapping',
        'publicKey': signer.public_key, 'issuedAt': issued_at, 'expiresAt': expires_at}
    proof = {'purpose': 'agentmux-enrollment-possession-v1', 'profileId': material['profileId'],
             'authorityId': material['authorityId'], 'credential': transport}
    payload = {'authorityId': material['authorityId'], 'identity': identity, 'issuers': [],
               'transports': [{'record': transport, 'proof': sign_claims(proof, signer._seed)}]}
    for field in ('integrationEffectQuery', 'integrationEffectCommands', 'legacyAliasResolve',
                  'authoritySwitchRecovery',
                  'localBrowserSessionOpen', 'oidcTerminalSession', 'messageCommands', 'knowledgeCommands', 'codeCommands', 'workCommands',
                  'peerControlCommands', 'federationPolicyCommands'):
        selected = material.get(field)
        if selected is None:
            continue
        if selected['transportRef']['revision'] != 1:
            raise ContractError('application_client_command_enrollment')
        command_transport = {**transport, 'ref': selected['transportRef'],
            'issuerRef': (material['replyIssuerRef'] if field in ('authoritySwitchRecovery', 'messageCommands', 'knowledgeCommands', 'codeCommands', 'workCommands',
                                                              'peerControlCommands', 'federationPolicyCommands')
                          else selected['replyIssuerRef'])}
        command_proof = {**proof, 'credential': command_transport}
        payload['transports'].append({'record': command_transport, 'proof': sign_claims(command_proof, signer._seed)})
    validate('identity-enroll', payload)
    _write_material(path, material)
    return payload
