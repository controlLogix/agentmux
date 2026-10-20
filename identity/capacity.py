"""Reserve space inside the 64 KiB record for revocation and audit growth."""
from agentmux_contracts import ContractError, canonical_bytes, strict_loads

MAX_STATE_BYTES = 49152
MAX_OPERATION_BYTES = 65536
_MAX_REVISION = 9007199254740991


def require_state_capacity(state):
    # Size an upper bound, never rewrite the supplied or retained state. Every
    # reference gets its maximum integer width and every status its longer value.
    # Future revocation of any or all current rows therefore consumes no reserve.
    maximum = strict_loads(canonical_bytes(state))
    def expand(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'revision':
                    value[key] = _MAX_REVISION
                elif key == 'status' and item in ('active', 'revoked'):
                    value[key] = 'revoked'
                else:
                    expand(item)
        elif isinstance(value, list):
            for item in value:
                expand(item)
    expand(maximum)
    if len(canonical_bytes(maximum)) > MAX_STATE_BYTES:
        raise ContractError('identity_capacity_exceeded')


def require_operation_capacity(operation):
    if len(canonical_bytes(operation)) > MAX_OPERATION_BYTES:
        raise ContractError('identity_operation_capacity_exceeded')
