from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_RETRY_STATUSES = (408, 409, 425, 429, 500, 502, 503, 504)


@dataclass(slots=True)
class RetryConfig:
    max_attempts: int = 3
    initial_delay: float = 0.25
    max_delay: float = 5.0
    backoff_multiplier: float = 2.0
    retry_statuses: tuple[int, ...] = field(default_factory=lambda: DEFAULT_RETRY_STATUSES)

    def next_delay(self, attempt_number: int) -> float:
        if attempt_number <= 0:
            return 0.0
        delay = self.initial_delay * (self.backoff_multiplier ** (attempt_number - 1))
        return min(delay, self.max_delay)

    def should_retry_status(self, status_code: int) -> bool:
        return status_code in self.retry_statuses
