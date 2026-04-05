from __future__ import annotations

from pathlib import Path


def package_dir() -> Path:
    return Path(__file__).resolve().parent


def bundled_docker_dir() -> Path:
    return package_dir() / "data"
