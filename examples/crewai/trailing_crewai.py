"""Compatibility wrapper for the packaged CrewAI adapter."""

from __future__ import annotations

import sys
from pathlib import Path


SDK_DIR = Path(__file__).resolve().parents[2] / "sdk" / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from trailing.adapters.crewai import TrailingCrewAIListener

__all__ = ["TrailingCrewAIListener"]
