"""Installed worker callback handoff; routing is supplied by its owning caller.

This module grants no authority and never chooses an ambient Hub. The registered
profile integration supplies a retained route; component tests may supply their
owned real route without claiming that integration is qualified.
"""
from typing import Protocol


class NativeCoreCallbackRoute(Protocol):
    def invoke(self, arguments: tuple[str, ...]) -> int: ...


class MissingNativeCoreRoute(ValueError):
    def __init__(self):
        super().__init__('native_core_callback_setup_required')


def run_callback(arguments, *, route: NativeCoreCallbackRoute | None = None):
    if (type(arguments) not in (list, tuple) or not 2 <= len(arguments) <= 129
            or arguments[0] != 'hub'
            or any(type(value) is not str or '\x00' in value or len(value) > 65536 for value in arguments)):
        raise MissingNativeCoreRoute()
    if route is None:
        raise MissingNativeCoreRoute()
    # Original arguments and the current process reach the retained consumer.
    # A route must keep existing kernel caller and domain authorization checks.
    return route.invoke(tuple(arguments[1:]))
