"""Adapter integrations built on top of the Trailing Python SDK."""

from .claude_code import TrailingClaudeAdapter, TrailingClaudeCodeAdapter
from .codex_cli import TrailingCodexAdapter, TrailingCodexCLIAdapter
from .crewai import TrailingCrewAIListener
from .cursor import TrailingCursorAdapter, TrailingCursorComposerAdapter
from .langchain import TrailingCallbackHandler
from .openai_agents import TrailingOpenAITracer

__all__ = [
    "TrailingCallbackHandler",
    "TrailingClaudeAdapter",
    "TrailingClaudeCodeAdapter",
    "TrailingCodexAdapter",
    "TrailingCodexCLIAdapter",
    "TrailingCrewAIListener",
    "TrailingCursorAdapter",
    "TrailingCursorComposerAdapter",
    "TrailingOpenAITracer",
]
