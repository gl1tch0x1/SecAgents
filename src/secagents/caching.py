"""Advanced caching system for LLM responses and scan results.

Implements intelligent caching to reduce API calls and improve performance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Generic, TypeVar, overload

T = TypeVar("T")


@dataclass
class CacheEntry(Generic[T]):
    """A cache entry with metadata."""
    key: str
    value: T
    created_at: datetime
    expires_at: datetime | None = None
    hit_count: int = 0
    size_bytes: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def touch(self) -> None:
        """Update hit count on cache access."""
        self.hit_count += 1


class LLMResponseCache:
    """Cache for LLM API responses to reduce redundant calls."""
    
    def __init__(self, cache_dir: Path | None = None, ttl_hours: int = 24):
        self.cache_dir = cache_dir or Path(".secagents-cache")
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.ttl = timedelta(hours=ttl_hours)
        self.memory_cache: dict[str, CacheEntry] = {}
    
    def _hash_key(self, system: str, user: str, model: str) -> str:
        """Generate a cache key from prompt and model."""
        content = f"{system}:::{user}:::{model}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get(self, system: str, user: str, model: str) -> str | None:
        """Retrieve cached LLM response if available."""
        key = self._hash_key(system, user, model)
        
        # Check memory cache first
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if not entry.is_expired():
                entry.touch()
                return entry.value
            else:
                del self.memory_cache[key]
        
        # Check disk cache
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                    expires_at = None
                    if data.get("expires_at"):
                        expires_at = datetime.fromisoformat(data["expires_at"])
                    
                    entry = CacheEntry(
                        key=key,
                        value=data["value"],
                        created_at=datetime.fromisoformat(data["created_at"]),
                        expires_at=expires_at,
                        hit_count=data.get("hit_count", 0)
                    )
                    
                    if not entry.is_expired():
                        entry.touch()
                        self.memory_cache[key] = entry
                        return entry.value
                    else:
                        cache_file.unlink()
            except (json.JSONDecodeError, KeyError):
                cache_file.unlink()
        
        return None
    
    def set(self, system: str, user: str, model: str, response: str) -> None:
        """Cache an LLM response."""
        key = self._hash_key(system, user, model)
        now = datetime.now()
        expires_at = now + self.ttl
        
        entry = CacheEntry(
            key=key,
            value=response,
            created_at=now,
            expires_at=expires_at,
            size_bytes=len(response.encode("utf-8"))
        )
        
        self.memory_cache[key] = entry
        
        # Persist to disk
        cache_file = self.cache_dir / f"{key}.json"
        with open(cache_file, "w") as f:
            json.dump({
                "key": key,
                "value": response,
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "hit_count": entry.hit_count,
                "size_bytes": entry.size_bytes
            }, f)
    
    def clear_expired(self) -> int:
        """Remove expired cache entries. Returns count removed."""
        count = 0
        
        # Clean memory cache
        expired_keys = [
            k for k, v in self.memory_cache.items()
            if v.is_expired()
        ]
        for k in expired_keys:
            del self.memory_cache[k]
            count += 1
        
        # Clean disk cache
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                    if data.get("expires_at"):
                        expires_at = datetime.fromisoformat(data["expires_at"])
                        if datetime.now() > expires_at:
                            cache_file.unlink()
                            count += 1
            except (json.JSONDecodeError, KeyError):
                cache_file.unlink()
                count += 1
        
        return count
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_hits = sum(e.hit_count for e in self.memory_cache.values())
        total_size = sum(e.size_bytes for e in self.memory_cache.values())
        
        return {
            "entries_in_memory": len(self.memory_cache),
            "total_hits": total_hits,
            "total_size_bytes": total_size,
            "ttl_hours": self.ttl.total_seconds() / 3600
        }


class ScanResultCache:
    """Cache for full scan results to avoid duplicate scans."""
    
    def __init__(self, cache_dir: Path | None = None, ttl_days: int = 7):
        self.cache_dir = cache_dir or Path(".secagents-cache/scans")
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.ttl = timedelta(days=ttl_days)
    
    def _hash_target(self, target_path: str, git_hash: str | None = None) -> str:
        """Generate cache key from target and optional git hash."""
        content = f"{target_path}:::{git_hash or 'unknown'}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get(self, target_path: str, git_hash: str | None = None) -> dict | None:
        """Get cached scan result if available and not expired."""
        key = self._hash_target(target_path, git_hash)
        cache_file = self.cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file) as f:
                data = json.load(f)
                created_at = datetime.fromisoformat(data.get("created_at", ""))
                if datetime.now() - created_at > self.ttl:
                    cache_file.unlink()
                    return None
                return data["result"]
        except (json.JSONDecodeError, KeyError):
            cache_file.unlink()
            return None
    
    def set(self, target_path: str, result: dict, git_hash: str | None = None) -> None:
        """Cache a scan result."""
        key = self._hash_target(target_path, git_hash)
        cache_file = self.cache_dir / f"{key}.json"
        
        with open(cache_file, "w") as f:
            json.dump({
                "created_at": datetime.now().isoformat(),
                "target": target_path,
                "git_hash": git_hash,
                "result": result
            }, f)
    
    def clear_expired(self) -> int:
        """Remove expired scan cache entries."""
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                    created_at = datetime.fromisoformat(data.get("created_at", ""))
                    if datetime.now() - created_at > self.ttl:
                        cache_file.unlink()
                        count += 1
            except (json.JSONDecodeError, KeyError):
                cache_file.unlink()
                count += 1
        
        return count


# Global cache instances
_llm_cache: LLMResponseCache | None = None
_result_cache: ScanResultCache | None = None


def get_llm_cache() -> LLMResponseCache:
    """Get or create the LLM response cache."""
    global _llm_cache
    if _llm_cache is None:
        _llm_cache = LLMResponseCache()
    return _llm_cache


def get_scan_result_cache() -> ScanResultCache:
    """Get or create the scan result cache."""
    global _result_cache
    if _result_cache is None:
        _result_cache = ScanResultCache()
    return _result_cache
