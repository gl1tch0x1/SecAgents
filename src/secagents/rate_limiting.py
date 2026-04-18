"""Rate limiting and quota management for API calls.

Implements token bucket algorithm for rate limiting and prevents resource exhaustion.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any


@dataclass
class RateLimit:
    """Rate limit configuration."""
    max_requests: int
    time_window_sec: float
    name: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "max_requests": self.max_requests,
            "time_window_sec": self.time_window_sec,
            "name": self.name
        }


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(default_factory=lambda: 0)
    last_refill: float = field(default_factory=time.time)
    lock: Lock = field(default_factory=Lock)
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + (elapsed * self.refill_rate)
        )
        self.last_refill = now
    
    def allow_request(self, tokens_required: int = 1) -> bool:
        """
        Check if request is allowed and consume tokens if so.
        
        Returns:
            True if request is allowed, False otherwise
        """
        with self.lock:
            self._refill()
            if self.tokens >= tokens_required:
                self.tokens -= tokens_required
                return True
            return False
    
    def get_wait_time(self, tokens_required: int = 1) -> float:
        """Get time to wait before retry (seconds)."""
        with self.lock:
            self._refill()
            if self.tokens >= tokens_required:
                return 0.0
            tokens_needed = tokens_required - self.tokens
            return tokens_needed / self.refill_rate


class RateLimiter:
    """Global rate limiter for API calls."""
    
    # Standard rate limits for different providers
    RATE_LIMITS = {
        "openai": RateLimit(max_requests=3500, time_window_sec=60, name="OpenAI"),
        "anthropic": RateLimit(max_requests=100, time_window_sec=60, name="Anthropic"),
        "groq": RateLimit(max_requests=30, time_window_sec=60, name="Groq"),
        "ollama": RateLimit(max_requests=100, time_window_sec=60, name="Ollama"),
        "qwen": RateLimit(max_requests=80, time_window_sec=60, name="Alibaba Qwen"),
        "deepseek": RateLimit(max_requests=50, time_window_sec=60, name="DeepSeek"),
        "xai": RateLimit(max_requests=60, time_window_sec=60, name="XAI (Grok)"),
    }
    
    def __init__(self):
        """Initialize rate limiter with token buckets for each provider."""
        self.buckets: dict[str, TokenBucket] = {}
        self.lock = Lock()
        self._initialize_buckets()
    
    def _initialize_buckets(self) -> None:
        """Initialize token buckets for all providers."""
        for provider, limit in self.RATE_LIMITS.items():
            # Refill rate = max_requests / time_window_sec
            refill_rate = limit.max_requests / limit.time_window_sec
            self.buckets[provider] = TokenBucket(
                capacity=limit.max_requests,
                refill_rate=refill_rate
            )
    
    def allow_request(self, provider: str, tokens: int = 1) -> bool:
        """
        Check if API call is allowed for provider.
        
        Args:
            provider: LLM provider name
            tokens: Number of tokens (requests) required
        
        Returns:
            True if allowed, False if rate limited
        """
        with self.lock:
            if provider not in self.buckets:
                return True  # Unknown provider, allow
            
            return self.buckets[provider].allow_request(tokens)
    
    def get_wait_time(self, provider: str, tokens: int = 1) -> float:
        """
        Get time to wait before next request is allowed.
        
        Returns:
            Seconds to wait (0 if allowed immediately)
        """
        with self.lock:
            if provider not in self.buckets:
                return 0.0
            
            return self.buckets[provider].get_wait_time(tokens)
    
    def get_status(self) -> dict[str, Any]:
        """Get current rate limit status for all providers."""
        status = {}
        for provider, bucket in self.buckets.items():
            with bucket.lock:
                bucket._refill()
                limit = self.RATE_LIMITS[provider]
                status[provider] = {
                    "available_tokens": int(bucket.tokens),
                    "max_tokens": bucket.capacity,
                    "requests_per_minute": limit.max_requests,
                    "utilization": (bucket.capacity - bucket.tokens) / bucket.capacity
                }
        return status
    
    def reset_provider(self, provider: str) -> None:
        """Reset rate limit for a specific provider."""
        with self.lock:
            if provider in self.buckets:
                limit = self.RATE_LIMITS[provider]
                refill_rate = limit.max_requests / limit.time_window_sec
                self.buckets[provider] = TokenBucket(
                    capacity=limit.max_requests,
                    refill_rate=refill_rate
                )


# Global rate limiter instance
_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def check_rate_limit(provider: str) -> None:
    """
    Check rate limit and wait if necessary.
    
    Raises:
        RuntimeError: If rate limit check fails
    """
    limiter = get_rate_limiter()
    
    while not limiter.allow_request(provider):
        wait_time = limiter.get_wait_time(provider)
        if wait_time > 0:
            time.sleep(min(wait_time, 1.0))  # Wait max 1s before retry
