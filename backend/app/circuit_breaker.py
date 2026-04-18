"""Circuit breaker pattern for AI API resilience."""

import asyncio
import threading
import time
from enum import Enum
from typing import Callable, Any, Optional
from datetime import datetime, timedelta


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_seconds: int = 60,
        expected_exceptions: tuple = (Exception,),
    ):
        """Initialize circuit breaker config."""
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.expected_exceptions = expected_exceptions


class CircuitBreaker:
    """Circuit breaker for API resilience with thread-safe state management."""

    def __init__(self, config: CircuitBreakerConfig = None):
        """Initialize circuit breaker."""
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.success_count_in_half_open = 0
        self.success_threshold_in_half_open = 2
        self._lock = threading.Lock()  # FIX #2: Thread-safe state transitions

    def is_circuit_open(self) -> bool:
        """Check if circuit is open (thread-safe)."""
        with self._lock:
            if self.state == CircuitState.CLOSED:
                return False

            if self.state == CircuitState.OPEN:
                # Check if recovery timeout has elapsed
                if self.last_failure_time:
                    elapsed = time.time() - self.last_failure_time
                    if elapsed >= self.config.recovery_timeout_seconds:
                        # Transition to half-open (atomic within lock)
                        self.state = CircuitState.HALF_OPEN
                        self.success_count_in_half_open = 0
                        return False
                return True

            # Half-open state
            return False

    async def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute function with circuit breaker protection."""
        if self.is_circuit_open():
            raise CircuitBreakerOpenError(
                f"Circuit breaker is open. Recovering in {self.config.recovery_timeout_seconds}s"
            )

        try:
            result = (
                await func(*args, **kwargs)
                if asyncio.iscoroutinefunction(func)
                else func(*args, **kwargs)
            )

            # Record success (thread-safe)
            with self._lock:
                if self.state == CircuitState.HALF_OPEN:
                    self.success_count_in_half_open += 1
                    if (
                        self.success_count_in_half_open
                        >= self.success_threshold_in_half_open
                    ):
                        # Transition back to closed
                        self.state = CircuitState.CLOSED
                        self.failure_count = 0
                elif self.state == CircuitState.CLOSED:
                    self.failure_count = 0

            return result

        except self.config.expected_exceptions as e:
            # Record failure (thread-safe)
            with self._lock:
                self.failure_count += 1
                self.last_failure_time = time.time()

                if self.state == CircuitState.HALF_OPEN:
                    # Failed during recovery attempt
                    self.state = CircuitState.OPEN
                    self.last_failure_time = time.time()
                elif self.failure_count >= self.config.failure_threshold:
                    # Too many failures
                    self.state = CircuitState.OPEN

            raise

    def reset(self) -> None:
        """Reset circuit breaker to closed state (thread-safe)."""
        with self._lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None
            self.success_count_in_half_open = 0

    def get_status(self) -> dict:
        """Get circuit breaker status (thread-safe)."""
        with self._lock:
            return {
                "state": self.state.value,
                "failure_count": self.failure_count,
                "failure_threshold": self.config.failure_threshold,
                "last_failure_time": self.last_failure_time,
                "time_until_recovery": (
                    max(
                        0,
                        (
                            self.config.recovery_timeout_seconds
                            - (time.time() - self.last_failure_time)
                            if self.last_failure_time
                            else 0
                        ),
                    )
                    if self.state == CircuitState.OPEN
                    else None
                ),
            }


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open."""

    pass


class RetryConfig:
    """Configuration for retry logic with exponential backoff."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay_seconds: float = 1.0,
        max_delay_seconds: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ):
        """Initialize retry config."""
        self.max_retries = max_retries
        self.base_delay_seconds = base_delay_seconds
        self.max_delay_seconds = max_delay_seconds
        self.exponential_base = exponential_base
        self.jitter = jitter


class RetryableCircuitBreaker:
    """Circuit breaker with retry logic."""

    def __init__(
        self,
        circuit_config: CircuitBreakerConfig = None,
        retry_config: RetryConfig = None,
    ):
        """Initialize retryable circuit breaker."""
        self.circuit_breaker = CircuitBreaker(circuit_config or CircuitBreakerConfig())
        self.retry_config = retry_config or RetryConfig()

    async def call_with_retry(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute function with retry and circuit breaker protection."""
        import random

        last_exception = None

        for attempt in range(self.retry_config.max_retries + 1):
            try:
                return await self.circuit_breaker.call(func, *args, **kwargs)

            except CircuitBreakerOpenError:
                raise

            except Exception as e:
                last_exception = e

                if attempt < self.retry_config.max_retries:
                    # Calculate delay with exponential backoff
                    delay = min(
                        self.retry_config.base_delay_seconds
                        * (self.retry_config.exponential_base**attempt),
                        self.retry_config.max_delay_seconds,
                    )

                    if self.retry_config.jitter:
                        delay = delay * (0.5 + random.random())

                    await asyncio.sleep(delay)

        # All retries failed
        raise last_exception or Exception("All retries failed")

    def get_full_status(self) -> dict:
        """Get combined circuit breaker and retry status."""
        return {
            "circuit_breaker": self.circuit_breaker.get_status(),
            "retry_config": {
                "max_retries": self.retry_config.max_retries,
                "base_delay_seconds": self.retry_config.base_delay_seconds,
                "max_delay_seconds": self.retry_config.max_delay_seconds,
            },
        }


# Global circuit breakers for different AI models
AI_CIRCUIT_BREAKERS = {
    "gemini": RetryableCircuitBreaker(
        circuit_config=CircuitBreakerConfig(
            failure_threshold=5, recovery_timeout_seconds=60
        ),
        retry_config=RetryConfig(max_retries=3),
    ),
    "openrouter": RetryableCircuitBreaker(
        circuit_config=CircuitBreakerConfig(
            failure_threshold=5, recovery_timeout_seconds=60
        ),
        retry_config=RetryConfig(max_retries=3),
    ),
    "default": RetryableCircuitBreaker(
        circuit_config=CircuitBreakerConfig(
            failure_threshold=5, recovery_timeout_seconds=60
        ),
        retry_config=RetryConfig(max_retries=3),
    ),
}


def get_circuit_breaker_for_model(model_provider: str) -> RetryableCircuitBreaker:
    """Get circuit breaker for specific model provider."""
    return AI_CIRCUIT_BREAKERS.get(model_provider, AI_CIRCUIT_BREAKERS["default"])
