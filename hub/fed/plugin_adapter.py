"""Compatibility boundary for administrator-installed Python federation plugins.

The adapter keeps the original instance. Built-ins receive named domain services;
unmigrated administrator extensions retain their declared legacy contract. Neither
path isolates native code or establishes enrolled caller identity.
"""
from __future__ import annotations

from dataclasses import replace

from hub.profile_context import ProfileContext
from hub.store import HubError


HOOKS = ("start", "on_connect", "on_tick", "on_envelope", "on_local_event", "on_revoke")


class TrustedPluginAdapter:
    """Wrap the existing contract without replacing its business implementation."""

    def __init__(self, plugin, context_factory=None, *, profile_context=None):
        if profile_context is not None and type(profile_context) is not ProfileContext:
            raise HubError("invalid profile context")
        self._profile_context = profile_context
        self.original = plugin
        self._context_factory = context_factory
        if (not isinstance(getattr(plugin, "name", None), str)
                or not isinstance(getattr(plugin, "handles", None), (tuple, list))
                or not all(isinstance(value, str) for value in plugin.handles)
                or not isinstance(getattr(plugin, "tables", None), (tuple, list))
                or not all(isinstance(value, str) for value in plugin.tables)
                or not all(callable(getattr(plugin, hook, None)) for hook in (*HOOKS, "verbs", "panel"))):
            raise HubError("unsupported federation plugin contract")
        self.name = plugin.name
        # Registration happens after every configured plugin module has loaded.
        self._verbs = None

    def context(self, federation):
        if self._context_factory is not None:
            context = self._context_factory(federation)
            if self._profile_context is not None:
                context = replace(context, profile_context=self._profile_context)
            return context
        return federation

    async def invoke(self, federation, name, args, caller):
        return await self.verbs()[name].fn(self.context(federation), args, caller)

    @property
    def handles(self):
        return self.original.handles

    @property
    def tables(self):
        # Includes indexes and triggers, not only CREATE TABLE statements.
        return self.original.tables

    def verbs(self):
        if self._verbs is not None:
            return self._verbs
        verbs = self.original.verbs()
        if not isinstance(verbs, dict):
            raise HubError("unsupported federation plugin verb registry")
        for name, verb in verbs.items():
            if (not isinstance(name, str) or not callable(getattr(verb, "fn", None))
                    or not isinstance(getattr(verb, "help", None), str)
                    or not isinstance(getattr(verb, "operator_only", None), bool)
                    or not isinstance(getattr(verb, "params", None), dict)):
                raise HubError("unsupported federation plugin verb contract")
            for key, param in verb.params.items():
                if (not isinstance(key, str) or not isinstance(getattr(param, "type", None), str)
                        or not isinstance(getattr(param, "help", None), str)
                        or not isinstance(getattr(param, "required", None), bool)
                        or not isinstance(getattr(param, "positional", None), bool)):
                    raise HubError("unsupported federation plugin parameter contract")

        # Keep the same bound functions, parameter objects and registration order.
        self._verbs = verbs
        return self._verbs

    @property
    def profile_context(self):
        return self._profile_context

    def contribution(self):
        """Return local declarations and supplied display metadata only."""
        contribution = {
            "schemaVersion": "1.0.0",
            "kind": "legacy-federation-plugin",
            "plugin": self.name,
            "trust": "administrator-installed-python",
            "context": "legacy-federation",
            "hooks": list(HOOKS),
            "envelopeTypes": list(self.handles),
            "tablePrefix": f"p_{self.name}_",
            "tableStatements": list(self.tables),
            "panelId": self.name,
            "commands": [{
                "verb": f"fed_{self.name}_{name}",
                "help": verb.help,
                "operator_only": verb.operator_only,
                "params": {key: {"type": param.type, "required": param.required,
                                  "help": param.help, "positional": param.positional}
                           for key, param in verb.params.items()},
            } for name, verb in self.verbs().items()],
        }

        if self._profile_context is not None:
            contribution["profileContext"] = self._profile_context.as_dict()
        return contribution

    async def start(self, ctx):
        return await self.original.start(self.context(ctx))

    async def on_connect(self, ctx):
        return await self.original.on_connect(self.context(ctx))

    async def on_tick(self, ctx):
        return await self.original.on_tick(self.context(ctx))

    async def on_envelope(self, ctx, env, decision):
        # The runtime owns both normal admission and explicit quarantine approval.
        # Forward its exact decision; the descriptor supplies no authority.
        return await self.original.on_envelope(self.context(ctx), env, decision)

    async def on_local_event(self, ctx, kind, data):
        return await self.original.on_local_event(self.context(ctx), kind, data)

    async def on_revoke(self, ctx, peer):
        return await self.original.on_revoke(self.context(ctx), peer)

    def panel(self, ctx):
        return self.original.panel(self.context(ctx))


def builtin_context_factory(name):
    """Composition selects only the services belonging to this built-in."""
    if name == "messages":
        from hub.fed.message_services import build_message_context
        return build_message_context
    if name == "work":
        from hub.fed.work_services import build_work_context
        return build_work_context
    if name == "board":
        from hub.fed.board_services import build_board_context
        return build_board_context
    if name == "knowledge":
        from hub.fed.knowledge_services import build_knowledge_context
        return build_knowledge_context
    if name == "code":
        from hub.fed.code_services import build_code_context
        return build_code_context
    raise HubError("unsupported built-in federation context")
