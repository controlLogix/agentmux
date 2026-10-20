"""Compatible dashboard definition entrypoints backed by one scoped service.

These compatibility writers retain legacy audit labels. An injected enrolled
application host routes HTTP edits through the authenticated definition owner.
"""

import os  # Retain the existing atomic-replacement test seam.

from definition_service import DefinitionScope, DefinitionService


def _service():
    return DefinitionService(DefinitionScope.legacy())


def agents(db, params):
    return _service().agents(db, params)


def profiles(db, params):
    if params:
        import ccboard
        raise ccboard.Invalid("profile preview accepts no query parameters")
    return _service().preview_profiles()


def agentdef(db, body):
    return _service().legacy_save(db, body)


def agentdrop(db, body):
    return _service().legacy_drop(db, body)
