"""Enhanced error handling and recovery for agent workflows.

Provides retry logic, graceful degradation, and comprehensive error logging
for the multi-agent orchestration system.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeVar

from secagents.cli.ui import ui


class ErrorCategory(StrEnum):
    """Categorize different types of errors for handling."""
    
    rate_limit = "rate_limit"
    timeout = "timeout"
    invalid_response = "invalid_response"
    api_error = "api_error"
    sandbox_error = "sandbox_error"
    parse_error = "parse_error"
    unknown = "unknown"


@dataclass
class ErrorInfo:
    """Detailed error information for recovery decisions."""
    
    category: ErrorCategory
    message: str
    retryable: bool
    retry_after_sec: float | None = None
    attempt: int = 1
    max_attempts: int = 3
    original_error: Exception | None = None


class RetryableError(Exception):
    """Base class for errors that should trigger retry."""
    
    def __init__(self, message: str, retry_after_sec: float | None = None):
        super().__init__(message)
        self.retry_after_sec = retry_after_sec


class RateLimitError(RetryableError):
    """Raised when rate limit is hit."""
    pass


class TimeoutError(RetryableError):
    """Raised when operation times out."""
    pass


def categorize_error(error: Exception) -> ErrorInfo:
    """Classify an exception into a recovery strategy."""
    
    msg = str(error).lower()
    
    # API-specific errors
    if "rate limit" in msg or "429" in msg or "quota" in msg:
        return ErrorInfo(
            category=ErrorCategory.rate_limit,
            message=str(error),
            retryable=True,
            retry_after_sec=30.0
        )
    
    if "timeout" in msg or "timed out" in msg:
        return ErrorInfo(
            category=ErrorCategory.timeout,
            message=str(error),
            retryable=True,
            retry_after_sec=10.0
        )
    
    if "json" in msg or "parsing" in msg or "decode" in msg:
        return ErrorInfo(
            category=ErrorCategory.parse_error,
            message=str(error),
            retryable=True,
            retry_after_sec=2.0
        )
    
    if "api" in msg or "500" in msg or "503" in msg:
        return ErrorInfo(
            category=ErrorCategory.api_error,
            message=str(error),
            retryable=True,
            retry_after_sec=20.0
        )
    
    if "docker" in msg or "sandbox" in msg or "container" in msg:
        return ErrorInfo(
            category=ErrorCategory.sandbox_error,
            message=str(error),
            retryable=False
        )
    
    return ErrorInfo(
        category=ErrorCategory.unknown,
        message=str(error),
        retryable=False
    )


T = TypeVar("T")


def retry_with_backoff(
    fn: Callable[[], T],
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
) -> tuple[T | None, ErrorInfo | None]:
    """
    Execute function with exponential backoff retry logic.
    
    Args:
        fn: Function to execute
        max_attempts: Maximum retry attempts
        initial_delay: Starting delay between retries (seconds)
        max_delay: Maximum delay between retries
    
    Returns:
        (result, error_info) - One will be None if successful
    """
    
    delay = initial_delay
    last_error = None
    
    for attempt in range(1, max_attempts + 1):
        try:
            result = fn()
            if attempt > 1:
                ui.print_success(f"Recovered after {attempt} attempts")
            return result, None
        
        except Exception as e:
            last_error = categorize_error(e)
            last_error.attempt = attempt
            last_error.max_attempts = max_attempts
            last_error.original_error = e
            
            if not last_error.retryable or attempt == max_attempts:
                ui.print_error(f"{last_error.category}: {last_error.message} (attempt {attempt}/{max_attempts})")
                return None, last_error
            
            wait_time = min(delay, max_delay)
            ui.print_warning(f"{last_error.category} - Retrying in {wait_time:.1f}s (attempt {attempt}/{max_attempts})")
            time.sleep(wait_time)
            delay *= 2  # Exponential backoff
    
    return None, last_error


def safe_json_extraction(
    text: str,
    fallback_value: dict[str, Any] | None = None,
    allow_partial: bool = True,
) -> tuple[dict[str, Any], bool]:
    """
    Safely extract JSON with graceful fallbacks.
    
    Args:
        text: Text potentially containing JSON
        fallback_value: Default value if parsing fails
        allow_partial: Try to recover partial JSON
    
    Returns:
        (parsed_dict, was_successful)
    """
    
    if fallback_value is None:
        fallback_value = {"error": "failed_to_parse", "findings": []}
    
    text = text.strip()
    
    # Try direct parsing first
    try:
        return json.loads(text), True
    except json.JSONDecodeError:
        pass
    
    # Try extracting JSON from markdown code blocks
    if "```" in text:
        try:
            start = text.find("```") + 3
            if text[start:start+4].lower() == "json":
                start += 4
            end = text.find("```", start)
            if end > start:
                return json.loads(text[start:end]), True
        except json.JSONDecodeError:
            pass
    
    # Try finding JSON object boundaries
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            json_text = text[start:end+1]
            return json.loads(json_text), True
    except json.JSONDecodeError:
        pass
    
    # Partial recovery: try to fix common issues
    if allow_partial:
        try:
            # Try with quotes fixed
            fixed = text.replace("'", '"')
            # Find likely JSON boundaries
            start = fixed.find("{")
            end = fixed.rfind("}")
            if start >= 0 and end > start:
                return json.loads(fixed[start:end+1]), True
        except json.JSONDecodeError:
            pass
    
    # Give up, return fallback
    return fallback_value, False


@dataclass
class AgentPhaseResult:
    """Encapsulates result of an agent phase with error handling."""
    
    success: bool
    data: dict[str, Any] | None
    error: ErrorInfo | None
    partial_data: dict[str, Any] | None = None  # Data recovered on error
    fallback_used: bool = False
    turn: int = 0
    phase: str = ""


def handle_agent_phase_error(
    error: Exception,
    turn: int,
    phase: str,
    fallback_data: dict[str, Any] | None = None,
) -> AgentPhaseResult:
    """
    Handle an error in agent phase execution.
    
    Determines if phase should be retried, skipped, or escalated.
    """
    
    error_info = categorize_error(error)
    
    result = AgentPhaseResult(
        success=False,
        data=None,
        error=error_info,
        turn=turn,
        phase=phase,
        fallback_used=bool(fallback_data)
    )
    
    if fallback_data:
        result.partial_data = fallback_data
        ui.print_warning(f"{phase} T{turn}: Using fallback data ({len(fallback_data.get('findings', []))} fallback findings)")
    
    ui.print_error(f"{phase} T{turn}: {error_info.category.upper()} - {error_info.message}")
    
    return result


# Degradation strategies for different error scenarios
class DegradationStrategy:
    """Provides fallback behaviors when agents fail."""
    
    @staticmethod
    def skip_phase(phase: str) -> dict[str, Any]:
        """Skip current phase and continue."""
        return {
            "skipped": True,
            "phase": phase,
            "findings": [],
            "reason": f"Phase {phase} skipped due to errors"
        }
    
    @staticmethod
    def reduce_scope(phase: str, reduction_factor: float = 0.5) -> dict[str, Any]:
        """Reduce scope of current phase (fewer files, less context)."""
        return {
            "reduced_scope": True,
            "phase": phase,
            "reduction_factor": reduction_factor,
            "reason": f"Reduced scope to {int(reduction_factor*100)}%"
        }
    
    @staticmethod
    def single_model_fallback() -> dict[str, Any]:
        """Fall back to single fastest model instead of consensus."""
        return {
            "fallback_mode": True,
            "reason": "Switched to single-model mode due to consensus failures",
            "use_multi_ai_consensus": False
        }
    
    @staticmethod
    def minimal_scan(phase: str) -> dict[str, Any]:
        """Run minimal automated scan only."""
        return {
            "minimal_mode": True,
            "phase": phase,
            "reason": f"Phase {phase} running in minimal mode - automated checks only"
        }
