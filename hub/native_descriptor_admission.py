"""Compatibility import for the shared native descriptor admission module.

Keep one module object so existing exception classes, purpose values and callers
that patch native boundaries retain their original behavior.
"""
import sys
from native_security import descriptor_admission as _shared

sys.modules[__name__] = _shared
