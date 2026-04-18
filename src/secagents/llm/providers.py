from __future__ import annotations

import json
from typing import Any

import httpx

from secagents.config import AppConfig, LLMProvider

# Connection pooling for HTTP clients (reused across calls)
_httpx_pool: dict[str, httpx.Client] = {}


def _get_httpx_client(timeout: float = 120.0) -> httpx.Client:
    """Get or create a persistent httpx client with connection pooling."""
    key = f"pool_{timeout}"
    if key not in _httpx_pool:
        _httpx_pool[key] = httpx.Client(
            timeout=timeout,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _httpx_pool[key]


def cleanup_httpx_clients() -> None:
    """Close all pooled HTTP clients (call on shutdown)."""
    for client in _httpx_pool.values():
        try:
            client.close()
        except Exception:
            pass
    _httpx_pool.clear()


def chat_completion(
    cfg: AppConfig,
    *,
    system: str,
    user: str,
) -> str:
    """Route to LLM provider with caching and rate limiting."""
    # Import here to avoid circular dependencies
    from secagents.caching import get_llm_cache
    from secagents.rate_limiting import check_rate_limit
    
    # Check rate limiting
    if cfg.enable_rate_limiting:
        check_rate_limit(cfg.provider.value)
    
    # Check cache first
    if cfg.enable_caching:
        cache = get_llm_cache()
        cached = cache.get(system, user, cfg.model)
        if cached:
            return cached
    
    # Call appropriate provider
    if cfg.provider == LLMProvider.openai:
        response = _openai_chat(cfg, system=system, user=user)
    elif cfg.provider == LLMProvider.anthropic:
        response = _anthropic_chat(cfg, system=system, user=user)
    elif cfg.provider == LLMProvider.ollama:
        response = _ollama_chat(cfg, system=system, user=user)
    elif cfg.provider == LLMProvider.qwen:
        response = _qwen_chat(cfg, system=system, user=user)
    elif cfg.provider == LLMProvider.deepseek:
        response = _deepseek_chat(cfg, system=system, user=user)
    elif cfg.provider == LLMProvider.groq:
        response = _groq_chat(cfg, system=system, user=user)
    elif cfg.provider == LLMProvider.xai:
        response = _xai_chat(cfg, system=system, user=user)
    else:
        raise ValueError(f"Unsupported provider: {cfg.provider}")
    
    # Cache response
    if cfg.enable_caching:
        cache = get_llm_cache()
        cache.set(system, user, cfg.model, response)
    
    return response
    if cfg.provider == LLMProvider.xai:
        return _xai_chat(cfg, system=system, user=user)
    return _ollama_chat(cfg, system=system, user=user)


def _openai_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    if not cfg.openai_api_key:
        raise ValueError("OPENAI_API_KEY or SECAGENTS_OPENAI_API_KEY is required for OpenAI.")
    from openai import OpenAI

    client = OpenAI(api_key=cfg.openai_api_key)
    resp = client.chat.completions.create(
        model=cfg.model,
        temperature=cfg.temperature,
        top_p=cfg.top_p,
        max_tokens=cfg.max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    choice = resp.choices[0].message.content
    return choice or ""


def _anthropic_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    if not cfg.anthropic_api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY or SECAGENTS_ANTHROPIC_API_KEY is required for Anthropic."
        )
    from anthropic import Anthropic

    client = Anthropic(api_key=cfg.anthropic_api_key)
    msg = client.messages.create(
        model=cfg.model,
        max_tokens=cfg.max_tokens,
        temperature=cfg.temperature,
        top_p=cfg.top_p,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    parts: list[str] = []
    for block in msg.content:
        text_block = getattr(block, "text", None)
        if isinstance(text_block, str):
            parts.append(text_block)
    return "".join(parts)


def _ollama_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    url = f"{cfg.ollama_base_url.rstrip('/')}/api/chat"
    payload: dict[str, Any] = {
        "model": cfg.model,
        "stream": False,
        "options": {
            "temperature": cfg.temperature,
            "top_p": cfg.top_p,
            "num_predict": min(cfg.max_tokens, 4096),  # Reduced from 8192 for faster responses
        },
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    client = _get_httpx_client(timeout=120.0)  # Reduced from 600
    r = client.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    msg = data.get("message") or {}
    return str(msg.get("content") or "")


def _qwen_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    """Alibaba Qwen API integration for advanced reasoning."""
    if not cfg.qwen_api_key:
        raise ValueError("QWEN_API_KEY or SECAGENTS_QWEN_API_KEY is required for Qwen.")
    url = f"{cfg.qwen_base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {cfg.qwen_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": cfg.temperature,
        "top_p": cfg.top_p,
        "max_tokens": cfg.max_tokens,
    }
    client = _get_httpx_client(timeout=120.0)  # Reduced from 600
    r = client.post(url, json=payload, headers=headers)
    r.raise_for_status()
    data = r.json()
    choice = data.get("choices", [{}])[0]
    msg = choice.get("message", {})
    return msg.get("content", "")


def _deepseek_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    """DeepSeek API integration for cost-effective reasoning."""
    if not cfg.deepseek_api_key:
        raise ValueError("DEEPSEEK_API_KEY or SECAGENTS_DEEPSEEK_API_KEY is required for DeepSeek.")
    url = f"{cfg.deepseek_base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {cfg.deepseek_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": cfg.temperature,
        "top_p": cfg.top_p,
        "max_tokens": cfg.max_tokens,
    }
    client = _get_httpx_client(timeout=120.0)  # Reduced from 600
    r = client.post(url, json=payload, headers=headers)
    r.raise_for_status()
    data = r.json()
    choice = data.get("choices", [{}])[0]
    msg = choice.get("message", {})
    return msg.get("content", "")


def _groq_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    """Groq API integration for ultra-fast inference."""
    if not cfg.groq_api_key:
        raise ValueError("GROQ_API_KEY or SECAGENTS_GROQ_API_KEY is required for Groq.")
    try:
        from groq import Groq
    except ImportError:
        raise ImportError("Groq SDK required: pip install groq")
    
    client = Groq(api_key=cfg.groq_api_key)
    msg = client.chat.completions.create(
        model=cfg.model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
    )
    return msg.choices[0].message.content or ""


def _xai_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    """XAI (Grok) integration for real-time intelligence."""
    if not cfg.xai_api_key:
        raise ValueError("XAI_API_KEY or SECAGENTS_XAI_API_KEY is required for XAI.")
    url = "https://api.x.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {cfg.xai_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": cfg.model or "grok-beta",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
    }
    client = _get_httpx_client(timeout=120.0)  # Reduced from 600
    r = client.post(url, json=payload, headers=headers)
    r.raise_for_status()
    data = r.json()
    choice = data.get("choices", [{}])[0]
    msg = choice.get("message", {})
    return msg.get("content", "")


def extract_json_object(text: str) -> dict[str, Any]:
    """Best-effort parse of a JSON object from model output."""
    text = text.strip()
    if "```" in text:
        start = text.find("```")
        rest = text[start + 3 :]
        if rest.lower().startswith("json"):
            rest = rest[4:]
        end = rest.find("```")
        if end != -1:
            text = rest[:end].strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object found in model output.")
    return json.loads(text[start : end + 1])
