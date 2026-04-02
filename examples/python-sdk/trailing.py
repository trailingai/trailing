"""Compatibility shim for the packaged Trailing Python SDK."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parents[2] / "sdk" / "python" / "trailing"
SPEC = importlib.util.spec_from_file_location(
    "_trailing_sdk",
    PACKAGE_DIR / "__init__.py",
    submodule_search_locations=[str(PACKAGE_DIR)],
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise ImportError(f"could not load packaged SDK from {PACKAGE_DIR}")

MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

# Expose the packaged SDK path so sibling wrappers can import trailing submodules.
__path__ = [str(PACKAGE_DIR)]
if __spec__ is not None:
    __spec__.submodule_search_locations = [str(PACKAGE_DIR)]

AsyncTrailingClient = MODULE.AsyncTrailingClient
RedactionConfig = MODULE.RedactionConfig
RetryConfig = MODULE.RetryConfig
SdkAction = MODULE.SdkAction
SdkContext = MODULE.SdkContext
SdkEvent = MODULE.SdkEvent
TrailingClient = MODULE.TrailingClient
TrailingError = MODULE.TrailingError

__all__ = [
    "AsyncTrailingClient",
    "RedactionConfig",
    "RetryConfig",
    "SdkAction",
    "SdkContext",
    "SdkEvent",
    "TrailingClient",
    "TrailingError",
]
