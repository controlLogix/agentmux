"""Semantic checks for persisted native authority inputs, not grant intersection."""
from datetime import datetime, timezone
from agentmux_contracts import ContractError, canonical_bytes


def validate_private_storage_resources(resources, facts):
    """Check enrolled namespace pins; the provider verifies their opaque digest."""
    identifiers = [r['resourceId'] for r in resources]
    applicable = {('capability-storage-read', 'read', 'storage'),
                  ('capability-storage-write', 'write', 'storage'),
                  ('capability-outcome-query', 'inspect', 'outcome')}
    if (len(identifiers) != len(set(identifiers)) or any(
            resource['scope'] != facts['grant']['scope'] or not any(
                (binding['contractId'], binding['action'], binding['resourceClass']) in applicable
                and resource['resourceId'] in binding['resourceIds']
                for binding in facts['domainBindings']) for resource in resources)):
        raise ContractError('native_private_storage_binding_invalid')


def validate_native_records(state, index, hub):
    from .authority import _key
    seen = set()
    for row in state.get('nativeInstances', []):
        owner, facts = row['owner'], row['facts']
        key = canonical_bytes(owner)
        if key in seen:
            raise ContractError('native_owner_ambiguous')
        seen.add(key)
        # Retain stale references after revocation; readers refuse them at use.
        # Requiring exact live revisions here would make revocation itself fail.
        identities = {_key(item['ref'])[:2]: item for item in state['identities']}
        identity = identities.get(_key(row['identityRef'])[:2])
        host = identities.get(_key(row['hostIdentityRef'])[:2])
        if (identity is None or identity['kind'] != 'plugin'
                or host is None or host['kind'] != 'service'
                or row['manifestDigest'] != owner['pin']['manifestChecksum']):
            raise ContractError('native_identity_binding_invalid')
        grant, policy = facts['grant'], facts['policy']
        validate_private_storage_resources(row.get('privateStorageResources', []), facts)
        sources = row.get('configurationEventSources', [])
        source_keys = [(s['configurationRef']['ownerHubId'], s['configurationRef']['id']) for s in sources]
        if (len(source_keys) != len(set(source_keys))
                or any(s['configurationRef']['ownerHubId'] != hub or not any(
                    b['contractId'] == 'configuration-change-subscribe'
                    and b['action'] == 'subscribe' and b['resourceClass'] == 'configuration'
                    and s['configurationRef']['id'] in b['resourceIds']
                    for b in facts['domainBindings']) for s in sources)):
            raise ContractError('native_configuration_source_invalid')
        if (grant['issuerHubId'] != hub or grant['subjectInstanceId'] != owner['instanceId']
                or policy['subjectInstanceId'] != owner['instanceId']
                or grant['scope'] != policy['scope']
                or grant['scope']['organizationId'] != state['organizationId']
                or grant['policyRef'] != policy['reference']
                or policy['reference']['ownerHubId'] != hub
                or facts['scopeRef']['ownerHubId'] != hub):
            raise ContractError('native_facts_binding_invalid')
        for timed in (grant, policy, facts['parentGrant']):
            if timed is None:
                continue
            try:
                start, end = (datetime.fromisoformat(timed[k]) for k in ('issuedAt', 'expiresAt'))
                if start >= end or start.tzinfo is None or end.tzinfo is None:
                    raise ValueError()
            except (ValueError, TypeError):
                raise ContractError('authority_time_invalid') from None
        if row['relationship'] == 'independent':
            if (row['parentOwner'] is not None or facts['parentGrant'] is not None
                    or facts['parentAccess'] or grant['parentGrantRef'] is not None):
                raise ContractError('native_parent_binding_invalid')
        else:
            if row['parentOwner'] is None or facts['parentGrant'] is None:
                raise ContractError('native_parent_binding_invalid')
            parent = facts['parentGrant']
            if (parent['subjectInstanceId'] != row['parentOwner']['instanceId']
                    or grant['parentGrantRef'] != {'id': parent['grantId'],
                        'ownerHubId': parent['issuerHubId'], 'revision': parent['revision']}):
                raise ContractError('native_parent_binding_invalid')


def validate_native_lineage(state, index, row, now):
    """Validate current retained parent authority from one owner snapshot.

    Return the earliest grant/policy expiry in the chain. Go still checks actual
    package declarations, exact parent lifetime and equal read sequences; these
    retained records do not prove a process is alive.
    """
    from .authority import _active, _key

    def refuse():
        raise ContractError('native_parent_binding_invalid')

    seen = set()
    private_ids, private_digests = set(), set()

    def visit(current):
        owner = canonical_bytes(current['owner'])
        if owner in seen or len(seen) >= 64:
            refuse()
        seen.add(owner)
        plugin = index['identities'].get(_key(current['identityRef']))
        host = index['identities'].get(_key(current['hostIdentityRef']))
        if (current['status'] != 'active' or plugin is None or plugin['kind'] != 'plugin'
                or not _active(plugin, now) or host is None or host['kind'] != 'service'
                or not _active(host, now)):
            refuse()
        facts = current['facts']
        resources = current.get('privateStorageResources', [])
        validate_private_storage_resources(resources, facts)
        # Parent delegation does not make an ancestor's private namespace shared.
        for resource in resources:
            if resource['resourceId'] in private_ids or resource['bindingDigest'] in private_digests:
                refuse()
            private_ids.add(resource['resourceId'])
            private_digests.add(resource['bindingDigest'])
        grant, policy = facts['grant'], facts['policy']
        end = None
        for timed in (grant, policy):
            start, expiry = (datetime.fromisoformat(timed[k]) for k in ('issuedAt', 'expiresAt'))
            if not start <= now < expiry:
                raise ContractError('native_facts_expired')
            end = expiry if end is None else min(end, expiry)
        if current['relationship'] == 'independent':
            if (current['parentOwner'] is not None or facts['parentGrant'] is not None
                    or facts['parentAccess'] or grant['parentGrantRef'] is not None):
                refuse()
            return end
        parents = [r for r in state.get('nativeInstances', []) if r['owner'] == current['parentOwner']]
        if current['relationship'] != 'private' or len(parents) != 1:
            refuse()
        parent = parents[0]
        if (parent['hostIdentityRef'] != current['hostIdentityRef']
                or parent['owner']['instanceId'] == current['owner']['instanceId']):
            refuse()
        parent_end = visit(parent)
        parent_facts, parent_grant = parent['facts'], parent['facts']['grant']
        parent_ref = {'id': parent_grant['grantId'], 'ownerHubId': parent_grant['issuerHubId'],
                      'revision': parent_grant['revision']}
        if (facts['parentGrant'] != parent_grant or grant['parentGrantRef'] != parent_ref
                or grant['grantId'] == parent_grant['grantId']
                or grant['issuerHubId'] != parent_grant['issuerHubId']
                or grant['scope'] != parent_grant['scope']
                or not set(grant['actions']) <= set(parent_grant['actions'])
                or not set(grant['resourceIds']) <= set(parent_grant['resourceIds'])
                or datetime.fromisoformat(grant['issuedAt']) < datetime.fromisoformat(parent_grant['issuedAt'])
                or datetime.fromisoformat(grant['expiresAt']) > datetime.fromisoformat(parent_grant['expiresAt'])):
            refuse()
        # The same host must still be permitted to recheck this exact parent.
        grants = [g for g in state['grants'] if _active(g, now)
            and g['callerRef'] == host['ref'] and g['actorRef'] == host['ref']
            and g['scope'] == parent_grant['scope'] and g['delegationRef'] is None
            and g['contractId'] == 'native-authority-recheck'
            and g['resourceId'] == parent['owner']['instanceId']]
        if (not any(g['decision'] == 'allowed' for g in grants)
                or any(g['decision'] == 'denied' for g in grants)
                or not any(_active(m, now) and m['identityRef'] == host['ref']
                    and m['scope'] == parent_grant['scope'] for m in state['memberships'])):
            refuse()
        def tuples(bindings):
            return {(b['action'], b['resourceClass'], resource)
                    for b in bindings for resource in b['resourceIds']}
        declared = tuples(parent_facts['domainBindings'])
        access = facts['parentAccess']
        delegated = {(a['action'], a['resourceClass'], a['resourceId']) for a in access}
        if len(delegated) != len(access):
            refuse()
        for item in access:
            token = (item['action'], item['resourceClass'], item['resourceId'])
            outcomes = [d['outcome'] for d in parent_facts['policy']['decisions'] if d['access'] == item]
            if (token not in declared or item['action'] not in parent_grant['actions']
                    or item['resourceId'] not in parent_grant['resourceIds']
                    or not outcomes or any(outcome != 'allow' for outcome in outcomes)):
                refuse()
        if not tuples(facts['domainBindings']) <= delegated:
            refuse()
        for source in current.get('configurationEventSources', []):
            if not any(all(source[k] == allowed[k] for k in ('schemaRef', 'sourceDigest', 'streamCreated'))
                    and all(source['configurationRef'][k] == allowed['configurationRef'][k]
                            for k in ('id', 'ownerHubId'))
                    and source['configurationRef']['revision'] >= allowed['configurationRef']['revision']
                    for allowed in parent.get('configurationEventSources', [])):
                refuse()
        return min(end, parent_end, *(datetime.fromisoformat(g['expiresAt']) for g in grants))

    return visit(row)
