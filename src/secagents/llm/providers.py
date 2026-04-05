from __future__ import annotations

import json
from typing import Any

import httpx

from secagents.config import AppConfig, LLMProvider


def chat_completion(
    cfg: AppConfig,
    *,
    system: str,
    user: str,
) -> str:
    if cfg.provider == LLMProvider.openai:
        return _openai_chat(cfg, system=system, user=user)
    if cfg.provider == LLMProvider.anthropic:
        return _anthropic_chat(cfg, system=system, user=user)
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
        if hasattr(block, "text"):
            parts.append(block.text)
    return "".join(parts)


def _ollama_chat(cfg: AppConfig, *, system: str, user: str) -> str:
    url = f"{cfg.ollama_base_url.rstrip('/')}/api/chat"
    payload: dict[str, Any] = {
        "model": cfg.model,
        "stream": False,
        "options": {
            "temperature": cfg.temperature,
            "top_p": cfg.top_p,
            "num_predict": min(cfg.max_tokens, 8192),
        },
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    with httpx.Client(timeout=600.0) as client:
        r = client.post(url, json=payload)
        r.raise_for_status()
        data = r.json()
    msg = data.get("message") or {}
    return str(msg.get("content") or "")


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
