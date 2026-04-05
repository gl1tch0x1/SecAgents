from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

from rich.console import Console

console = Console(stderr=True)


@dataclass
class DockerInfo:
    available: bool
    version: str | None
    error: str | None = None


def _run_raw(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def detect_docker() -> DockerInfo:
    docker_path = shutil.which("docker")
    if not docker_path:
        return DockerInfo(
            available=False,
            version=None,
            error="Docker CLI not found in PATH. Install Docker Desktop (Windows/macOS) or Docker Engine (Linux).",
        )
    cp = _run_raw([docker_path, "version", "--format", "json"], timeout=30.0)
    if cp.returncode != 0:
        return DockerInfo(
            available=False,
            version=None,
            error=(cp.stderr or cp.stdout or "docker version failed").strip(),
        )
    version: str | None = None
    try:
        data: dict[str, Any] = json.loads(cp.stdout or "{}")
        version = str(data.get("Client", {}).get("Version") or data.get("Version") or "")
    except json.JSONDecodeError:
        version = (cp.stdout or "").strip() or None
    cp_info = _run_raw([docker_path, "info"], timeout=30.0)
    if cp_info.returncode != 0:
        return DockerInfo(
            available=False,
            version=version,
            error=(cp_info.stderr or "docker info failed — is the daemon running?").strip(),
        )
    return DockerInfo(available=True, version=version, error=None)


def docker_pull(image: str, console_out: Console | None = None) -> None:
    out = console_out or console
    docker_path = shutil.which("docker")
    if not docker_path:
        raise RuntimeError("Docker CLI not found.")
    out.print(f"[bold cyan]Pulling[/bold cyan] {image} …")
    cp = subprocess.run([docker_path, "pull", image], check=False)
    if cp.returncode != 0:
        raise RuntimeError(f"docker pull failed for {image}")


def ensure_image(image: str, *, pull: bool = True) -> None:
    docker_path = shutil.which("docker")
    if not docker_path:
        raise RuntimeError("Docker CLI not found.")
    inspect = _run_raw([docker_path, "image", "inspect", image], timeout=30.0)
    if inspect.returncode == 0:
        return
    if not pull:
        raise RuntimeError(f"Missing Docker image: {image}")
    docker_pull(image)


def container_running(name: str) -> bool:
    docker_path = shutil.which("docker")
    if not docker_path:
        return False
    cp = _run_raw(
        [docker_path, "inspect", "-f", "{{.State.Running}}", name],
        timeout=15.0,
    )
    return cp.returncode == 0 and (cp.stdout or "").strip().lower() == "true"


def start_ollama_container(
    *,
    name: str,
    image: str,
    host_port: int,
    pull: bool = True,
) -> str:
    """Start (or reuse) an Ollama container; returns base URL."""
    docker_path = shutil.which("docker")
    if not docker_path:
        raise RuntimeError("Docker CLI not found.")
    if pull:
        docker_pull(image)
    if container_running(name):
        return f"http://127.0.0.1:{host_port}"
    # Remove stopped container with same name if present
    subprocess.run([docker_path, "rm", "-f", name], capture_output=True, text=True, check=False)
    cp = subprocess.run(
        [
            docker_path,
            "run",
            "-d",
            "--name",
            name,
            "-p",
            f"{host_port}:11434",
            "-v",
            "secagents-ollama:/root/.ollama",
            image,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"Failed to start Ollama container: {(cp.stderr or cp.stdout).strip() or 'unknown error'}"
        )
    return f"http://127.0.0.1:{host_port}"


def ollama_pull_model(base_url: str, model: str, timeout: float = 600.0) -> None:
    """Pull a model inside the running Ollama HTTP API."""
    import httpx

    url = f"{base_url.rstrip('/')}/api/pull"
    console.print(f"[bold cyan]Pulling model[/bold cyan] {model} via Ollama API …")
    with httpx.Client(timeout=timeout) as client:
        with client.stream("POST", url, json={"name": model}) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                status = data.get("status")
                if status:
                    console.print(f"  [dim]{status}[/dim]")


def try_install_docker_hint() -> str:
    if sys.platform == "win32":
        return "https://docs.docker.com/desktop/install/windows-install/"
    if sys.platform == "darwin":
        return "https://docs.docker.com/desktop/install/mac-install/"
    return "https://docs.docker.com/engine/install/"
