"""Resolve the bundled SDK from this admitted package, never from the caller cwd."""
import os
import sys


class BundledSDKError(ImportError):
    def __init__(self):
        super().__init__('Bundled SDK import is unavailable.')


def _origin(path):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise BundledSDKError()
    return os.path.realpath(path)


def _check_loaded(sdk):
    roots = ('agentmux_contracts', 'sdk.python.agentmux_contracts')
    for name, module in tuple(sys.modules.items()):
        namespace = next((root for root in roots if name == root or name.startswith(root + '.')), None)
        if namespace is None:
            continue
        spec = getattr(module, '__spec__', None)
        if spec is None or getattr(spec, 'name', None) != name:
            raise BundledSDKError()
        components = name[len(namespace):].lstrip('.').split('.') if name != namespace else []
        if any(not component.isidentifier() for component in components):
            raise BundledSDKError()
        base = os.path.join(sdk, 'agentmux_contracts', *components)
        package = getattr(spec, 'submodule_search_locations', None) is not None
        expected = os.path.realpath(os.path.join(base, '__init__.py') if package else base + '.py')
        if (_origin(getattr(module, '__file__', None)) != expected
                or _origin(getattr(spec, 'origin', None)) != expected):
            raise BundledSDKError()
        if package:
            paths = list(getattr(module, '__path__', ()))
            spec_paths = list(spec.submodule_search_locations)
            root = os.path.realpath(base)
            if (len(paths) != 1 or len(spec_paths) != 1
                    or _origin(paths[0]) != root or _origin(spec_paths[0]) != root):
                raise BundledSDKError()


def use_bundled_sdk():
    package = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sdk = os.path.join(package, 'sdk', 'python')
    # Reject a prior foreign import without removing or replacing its module.
    # Both import names used by the development and installed paths are checked.
    _check_loaded(sdk)
    resolved = os.path.realpath(sdk)
    remaining = [entry for entry in sys.path
                 if not isinstance(entry, str) or os.path.realpath(entry) != resolved]
    sys.path[:] = [sdk, *remaining]
