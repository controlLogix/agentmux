"""Offline schema resolution. No schema or key URL is fetched from a message."""
from collections import OrderedDict
import hashlib
import os
from datetime import datetime
from pathlib import Path
from threading import RLock

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .wire import ContractError, _check, strict_loads

DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parents[3] / "contracts" / "v1" / "schemas"
_CACHE = OrderedDict()
_CATALOG_CACHE = OrderedDict()
_CACHE_LOCK = RLock()
_CACHE_LIMIT = 8


def _catalog(root):
    def identity(info):
        # ctime changes on a write even if size and mtime are restored. File
        # identity also catches atomic replacement, including equal bytes.
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    sources, versions = [], []
    with os.scandir(root) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            if not entry.name.endswith('.schema.json'):
                continue
            path = Path(entry.path)
            link = identity(entry.stat(follow_symlinks=False))
            if entry.is_symlink():
                path = path.resolve(strict=True)
            sources.append(path)
            versions.append((entry.name, str(path), link, identity(entry.stat())))
    return (str(root), identity(root.stat()), tuple(versions)), sources


def _validators(root):
    root = root.resolve()
    version, sources = _catalog(root)
    with _CACHE_LOCK:
        identity = _CATALOG_CACHE.get(version)
        # Windows ctime is creation time, so retain content reads there.
        if os.name == 'posix' and identity in _CACHE:
            _CATALOG_CACHE.move_to_end(version)
            _CACHE.move_to_end(identity)
            return _CACHE[identity]
    # Reload every file after a catalog change. Keep byte-digest cache identity
    # and full catalog validation; no schema or authority is omitted.
    loaded = [(path, path.read_bytes()) for path in sources]
    after, _ = _catalog(root)
    if after != version:
        raise ValueError('schema catalog changed while loading')
    identity = tuple((str(path), hashlib.sha256(raw).digest()) for path, raw in loaded)
    with _CACHE_LOCK:
        _CATALOG_CACHE[version] = identity
        if len(_CATALOG_CACHE) > _CACHE_LIMIT:
            _CATALOG_CACHE.popitem(last=False)
        if identity in _CACHE:
            _CACHE.move_to_end(identity)
            return _CACHE[identity]
        schemas = {}
        for path, raw in loaded:
            schema = strict_loads(raw)
            Draft202012Validator.check_schema(schema)
            schemas[path.name.removesuffix(".schema.json")] = schema
        registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas.values())
        compiled = {name: Draft202012Validator(schema, registry=registry) for name, schema in schemas.items()}
        _CACHE[identity] = compiled
        if len(_CACHE) > _CACHE_LIMIT:
            _CACHE.popitem(last=False)
        return compiled


def semantic_errors(name, value):
    errors = []
    if name == 'protected-assembly':
        if len(value['plugins']) != 4 or {p['id'] for p in value['plugins']} != {'boot', 'kernel-lifecycle', 'internal-communication', 'exported-status'}:
            errors.append('protected_membership')
    if name == 'plugin-context':
        grant = value['effectiveGrant']
        if value['parent'] and value['parent']['instanceId'] == value['instanceId']:
            errors.append('self_parent')
        if value['parent'] and value['parent']['relationship'] == 'private' and grant['parentGrantRef'] is None:
            errors.append('private_parent_grant_required')
        if grant['subjectInstanceId'] != value['instanceId']:
            errors.append('grant_instance_binding')
        try:
            if datetime.fromisoformat(grant['issuedAt']) >= datetime.fromisoformat(grant['expiresAt']):
                errors.append('grant_interval')
        except ValueError:
            errors.append('calendar_date')
    if name == 'plugin-manifest':
        for collection, key in [('dependencies', 'packageId'), ('children', 'packageId'), ('contributions', 'id')]:
            ids = [item[key] for item in value[collection]]
            if len(ids) != len(set(ids)):
                errors.append('duplicate_' + collection)
        if any(item['packageId'] == value['packageId'] for item in value['children'] + value['dependencies']):
            errors.append('self_dependency')
        for capability in value['requestedCapabilities']:
            if capability['resourceClass'].startswith('kernel') and (capability['resourceClass'], capability['action']) != ('kernel-status', 'subscribe'):
                errors.append('protected_kernel_access')
        for dep in value['dependencies']:
            low = tuple(map(int, dep['minimumVersion'].split('.')))
            high = tuple(map(int, dep['exclusiveMaximumVersion'].split('.')))
            if low >= high:
                errors.append('dependency_interval')
    if name in ('message-envelope', 'owner-record'):
        errors.extend(semantic_errors('operation-context', value['operation']))
    if name == 'ingress-attestation':
        claims = value['claims']
        errors.extend(semantic_errors('operation-context', claims['operation']))
        if claims['signingKeyRef']['ownerHubId'] != claims['issuerHubId'] or claims['authenticatedTransportRef']['ownerHubId'] != claims['issuerHubId']:
            errors.append('attestation_issuer_binding')
        try:
            issued, expires, deadline = (datetime.fromisoformat(t) for t in (claims['issuedAt'], claims['expiresAt'], claims['operation']['deadline']))
            if not issued < expires <= deadline:
                errors.append('attestation_interval')
            datetime.fromisoformat(claims['sentAt'])
        except ValueError:
            errors.append('calendar_date')
    if name == 'message-envelope':
        attestation = value['ingressAttestation']
        claims = attestation['claims']
        errors.extend(semantic_errors('ingress-attestation', attestation))
        if claims['operation'] != value['operation']:
            errors.append('attestation_operation_binding')
        if any(claims[k] != value[k] for k in ('messageId', 'kind', 'contractId', 'contractMajor', 'sourceHubId', 'sourceInstanceId', 'sentAt', 'correlationId')):
            errors.append('attestation_envelope_binding')
        if claims['audience'] != {'hubId': value['destinationHubId'], 'serviceId': value['destinationServiceId']}:
            errors.append('attestation_audience_binding')
    if name == 'owner-record':
        ids = [effect['effectId'] for effect in value['effects']]
        if len(ids) != len(set(ids)):
            errors.append('duplicate_effect_identity')
        if value['outcome'] == 'rejected' and value['effects']:
            errors.append('rejected_operation_has_effects')
    if name == 'operation-context':
        try:
            datetime.fromisoformat(value['deadline'])
        except ValueError:
            errors.append('calendar_date')
    return errors


def validate(schema_name, value, schema_dir=None):
    _check(value)
    root = Path(schema_dir) if schema_dir is not None else DEFAULT_SCHEMA_DIR
    try:
        try:
            validators = _validators(root)
        except Exception:
            raise ContractError("schema_configuration_error") from None
        if schema_name not in validators:
            raise ContractError("unknown_schema")
        validator = validators[schema_name]
        if next(validator.iter_errors(value), None) is not None:
            raise ContractError("schema_invalid")
        if semantic_errors(schema_name, value):
            raise ContractError("semantic_invalid")
    except ContractError:
        raise
    except Exception:
        raise ContractError("schema_configuration_error") from None


def validate_payload(envelope, registry_path=None):
    """Validate a registered payload and correlation; this does not grant authority."""
    validate("message-envelope", envelope)
    path = Path(registry_path) if registry_path is not None else DEFAULT_SCHEMA_DIR.parent / "registry.json"
    try:
        registry = strict_loads(path.read_bytes())
        if registry["schemaVersion"] != "1.0.0":
            raise ContractError("registry_version_unsupported")
        entry = registry["contracts"].get(envelope["contractId"])
        if entry is None or entry["major"] != envelope["contractMajor"]:
            raise ContractError("contract_unknown")
        if entry["kind"] != envelope["kind"]:
            raise ContractError("contract_kind_mismatch")
        if entry["destinationServiceId"] is not None and entry["destinationServiceId"] != envelope["destinationServiceId"]:
            raise ContractError("contract_destination_mismatch")
        validate(entry["payloadSchema"], envelope["payload"], path.parent / "schemas")
        payload, operation = envelope["payload"], envelope["operation"]
        for key in ("taskId", "attemptId"):
            if payload.get(key) is not None and payload[key] != operation[key]:
                raise ContractError("payload_context_mismatch")
        if payload.get("delegationId") is not None and (operation["delegationRef"] is None or payload["delegationId"] != operation["delegationRef"]["id"]):
            raise ContractError("payload_context_mismatch")
        if envelope["contractId"] == "operation-outcome" and payload["operationId"] != envelope["correlationId"]:
            raise ContractError("payload_context_mismatch")
    except ContractError:
        raise
    except Exception:
        raise ContractError("registry_configuration_error") from None
