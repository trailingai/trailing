"""Compatibility wrapper for the production LangChain callback example."""

from __future__ import annotations

import importlib.util
from pathlib import Path

PRODUCTION_PATH = Path(__file__).resolve().parents[1] / "langchain" / "trailing_callback.py"
SPEC = importlib.util.spec_from_file_location("trailing_langchain_callback", PRODUCTION_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise ImportError(f"could not load production callback from {PRODUCTION_PATH}")

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TrailingCallbackHandler = MODULE.TrailingCallbackHandler

__all__ = ["TrailingCallbackHandler"]
