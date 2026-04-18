"""Input validation and output sanitization for security.

Prevents injection attacks and ensures data integrity throughout the application.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any


class InputValidator:
    """Validate and sanitize user inputs."""
    
    # Dangerous patterns for injection attacks
    SHELL_INJECTION_PATTERN = re.compile(r'[;&|`$()\\<>]')
    PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[/\\]')
    COMMAND_INJECTION_PATTERN = re.compile(r'(?:;|&&|\|\||`|\$\(|\\n)')
    
    @staticmethod
    def validate_file_path(path: str, base_dir: Path | None = None) -> Path:
        """
        Validate and resolve a file path.
        
        Args:
            path: The path to validate
            base_dir: Base directory to check against (for traversal prevention)
        
        Returns:
            Resolved Path object
        
        Raises:
            ValueError: If path is invalid or attempts traversal
        """
        try:
            resolved = Path(path).resolve()
            
            # Prevent path traversal
            if base_dir:
                base_resolved = base_dir.resolve()
                try:
                    resolved.relative_to(base_resolved)
                except ValueError:
                    raise ValueError(f"Path traversal detected: {path}")
            
            # Verify path exists
            if not resolved.exists():
                raise ValueError(f"Path does not exist: {path}")
            
            return resolved
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid path: {e}")
    
    @staticmethod
    def validate_command(command: str, allowed_patterns: list[str] | None = None) -> str:
        """
        Validate a shell command for dangerous patterns.
        
        Args:
            command: Command to validate
            allowed_patterns: List of regex patterns for allowed commands
        
        Returns:
            Validated command
        
        Raises:
            ValueError: If command contains dangerous patterns
        """
        if not command or not isinstance(command, str):
            raise ValueError("Invalid command: must be non-empty string")
        
        # Reject commands with shell injection characters
        if InputValidator.COMMAND_INJECTION_PATTERN.search(command):
            raise ValueError("Command contains dangerous characters")
        
        # Check against allowed patterns if provided
        if allowed_patterns:
            if not any(re.match(pattern, command) for pattern in allowed_patterns):
                raise ValueError(f"Command does not match allowed patterns")
        
        return command.strip()
    
    @staticmethod
    def validate_url(url: str) -> str:
        """
        Validate a URL.
        
        Args:
            url: URL to validate
        
        Returns:
            Validated URL
        
        Raises:
            ValueError: If URL is invalid
        """
        url = url.strip()
        
        # Check for dangerous protocols
        if not url.lower().startswith(("http://", "https://", "file://")):
            raise ValueError("URL must start with http://, https://, or file://")
        
        # Basic URL validation
        if len(url) > 2048:
            raise ValueError("URL is too long")
        
        # Reject URLs with certain patterns
        if any(p in url.lower() for p in [
            "javascript:",
            "data:",
            "../",
            "..",
            "\x00"
        ]):
            raise ValueError("URL contains forbidden patterns")
        
        return url
    
    @staticmethod
    def validate_api_key(key: str | None) -> str | None:
        """
        Validate an API key.
        
        Args:
            key: API key to validate
        
        Returns:
            Validated key or None
        
        Raises:
            ValueError: If key format is invalid
        """
        if key is None:
            return None
        
        key = key.strip()
        
        if not key:
            return None
        
        # Reject obviously invalid keys (too short or with spaces)
        if len(key) < 10:
            raise ValueError("API key seems too short")
        
        if " " in key:
            raise ValueError("API key contains spaces")
        
        # Should not contain common password patterns
        if key.lower() in ["password", "secret", "key", "test"]:
            raise ValueError("API key appears to be a placeholder")
        
        return key


class OutputSanitizer:
    """Sanitize and escape output to prevent injection attacks."""
    
    @staticmethod
    def escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return html.escape(text, quote=True)
    
    @staticmethod
    def escape_json(text: str) -> str:
        """Escape text for JSON output."""
        return text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
    
    @staticmethod
    def escape_markdown(text: str) -> str:
        """Escape special markdown characters."""
        special_chars = r'\\`*_{}[]()#+-.!'
        for char in special_chars:
            text = text.replace(char, f'\\{char}')
        return text
    
    @staticmethod
    def escape_shell(text: str) -> str:
        """Escape text for safe shell execution."""
        if not text:
            return '""'
        
        # Use single quotes (safest) if possible
        if "'" not in text:
            return f"'{text}'"
        
        # Otherwise use double quotes with escaping
        return f'"{text.replace('"', '\\"')}"'
    
    @staticmethod
    def sanitize_report_text(text: str) -> str:
        """
        Sanitize text for inclusion in reports.
        
        Removes or escapes potentially dangerous content.
        """
        if not text:
            return ""
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Limit length
        if len(text) > 100000:
            text = text[:100000] + "\n[... truncated for length ...]"
        
        return text
    
    @staticmethod
    def sanitize_finding(finding_dict: dict[str, Any]) -> dict[str, Any]:
        """Sanitize a finding object for safe output."""
        result = {}
        
        for key, value in finding_dict.items():
            if isinstance(value, str):
                result[key] = OutputSanitizer.sanitize_report_text(value)
            elif isinstance(value, (list, tuple)):
                result[key] = [
                    OutputSanitizer.sanitize_report_text(str(v))
                    if isinstance(v, str) else v
                    for v in value
                ]
            elif isinstance(value, dict):
                result[key] = OutputSanitizer.sanitize_finding(value)
            else:
                result[key] = value
        
        return result


def validate_and_sanitize(
    text: str,
    input_type: str = "text"
) -> str:
    """
    Convenience function to validate and sanitize text.
    
    Args:
        text: Text to process
        input_type: Type of input ('url', 'command', 'html', 'json')
    
    Returns:
        Validated and sanitized text
    """
    if input_type == "url":
        return InputValidator.validate_url(text)
    elif input_type == "command":
        return InputValidator.validate_command(text)
    elif input_type == "html":
        return OutputSanitizer.escape_html(text)
    elif input_type == "json":
        return OutputSanitizer.escape_json(text)
    else:
        return OutputSanitizer.sanitize_report_text(text)
