from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Pattern


DEFAULT_REDACT_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
    }
)

DEFAULT_REDACT_PATTERNS = (
    re.compile(r"bearer\s+[a-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"sk-[a-z0-9]+", re.IGNORECASE),
)


def _compile_patterns(patterns: Iterable[str | Pattern[str]]) -> tuple[Pattern[str], ...]:
    compiled: list[Pattern[str]] = []
    for pattern in patterns:
        if isinstance(pattern, str):
            compiled.append(re.compile(pattern, re.IGNORECASE))
        else:
            compiled.append(pattern)
    return tuple(compiled)


@dataclass(slots=True)
class RedactionConfig:
    redact_keys: frozenset[str] = field(default_factory=lambda: DEFAULT_REDACT_KEYS)
    redact_value_patterns: tuple[Pattern[str], ...] = field(
        default_factory=lambda: DEFAULT_REDACT_PATTERNS
    )
    replacement: str = "[REDACTED]"

    def __post_init__(self) -> None:
        self.redact_keys = frozenset(key.lower() for key in self.redact_keys)
        self.redact_value_patterns = _compile_patterns(self.redact_value_patterns)

    def should_redact_key(self, key: str) -> bool:
        return key.lower() in self.redact_keys

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: self.replacement if self.should_redact_key(key) else self.redact(item)
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [self.redact(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)

        if isinstance(value, str):
            return self._redact_string(value)

        return value

    def _redact_string(self, value: str) -> str:
        redacted = value
        for pattern in self.redact_value_patterns:
            redacted = pattern.sub(self.replacement, redacted)
        return redacted
