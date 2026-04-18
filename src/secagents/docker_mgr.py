from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

from secagents.cli.ui import ui


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


def docker_pull(image: str, console_out: Any | None = None) -> None:
    out = console_out or ui.console
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


def ollama_pull_model(base_url: str, model: str, timeout: float = 300.0) -> None:
    """Pull a model inside the running Ollama HTTP API (optimized timeout)."""
    import httpx

    url = f"{base_url.rstrip('/')}/api/pull"
    ui.console.print(f"[bold cyan]Pulling model[/bold cyan] {model} via Ollama API …")
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
                    ui.console.print(f"  [dim]{status}[/dim]")


def try_install_docker_hint() -> str:
    if sys.platform == "win32":
        return "https://docs.docker.com/desktop/install/windows-install/"
    if sys.platform == "darwin":
        return "https://docs.docker.com/desktop/install/mac-install/"
    return "https://docs.docker.com/engine/install/"


def build_secagents_image(
    tag: str = "secagents:latest",
    dockerfile_path: str = "Dockerfile",
    build_context: str = ".",
    console_out: Any | None = None,
) -> None:
    """Build the SecAgents Docker image from Dockerfile."""
    out = console_out or ui.console
    docker_path = shutil.which("docker")
    if not docker_path:
        raise RuntimeError("Docker CLI not found.")
    
    out.print(f"[bold cyan]Building[/bold cyan] Docker image {tag} …")
    cp = subprocess.run(
        [docker_path, "build", "-t", tag, "-f", dockerfile_path, build_context],
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"docker build failed for {tag}")
    out.print(f"[green]✓ Image built successfully:[/green] {tag}")


def docker_compose_up(
    compose_file: str = "docker-compose.yml",
    project_dir: str = ".",
    detach: bool = True,
    console_out: Any | None = None,
) -> None:
    """Start services using docker-compose."""
    out = console_out or ui.console
    docker_path = shutil.which("docker")
    docker_compose_path = shutil.which("docker-compose")
    
    if not docker_path and not docker_compose_path:
        raise RuntimeError("Docker CLI or docker-compose not found.")
    
    # Use docker compose (newer) or docker-compose (older)
    compose_cmd = ["docker", "compose"] if docker_path else ["docker-compose"]
    
    args = compose_cmd + ["-f", compose_file, "up"]
    if detach:
        args.append("-d")
    
    out.print(f"[bold cyan]Starting[/bold cyan] services from {compose_file} …")
    cp = subprocess.run(args, cwd=project_dir, check=False)
    if cp.returncode != 0:
        raise RuntimeError("docker-compose up failed")
    out.print("[green]✓ Services started[/green]")


def docker_compose_down(
    compose_file: str = "docker-compose.yml",
    project_dir: str = ".",
    remove_volumes: bool = False,
    console_out: Any | None = None,
) -> None:
    """Stop and remove services from docker-compose."""
    out = console_out or ui.console
    docker_path = shutil.which("docker")
    
    if not docker_path:
        raise RuntimeError("Docker CLI not found.")
    
    compose_cmd = ["docker", "compose"] if docker_path else ["docker-compose"]
    args = compose_cmd + ["-f", compose_file, "down"]
    if remove_volumes:
        args.append("-v")
    
    out.print(f"[bold cyan]Stopping[/bold cyan] services …")
    cp = subprocess.run(args, cwd=project_dir, check=False)
    if cp.returncode != 0:
        out.print("[yellow]⚠ docker-compose down had issues[/yellow]")
        return
    out.print("[green]✓ Services stopped[/green]")


def wait_for_ollama(
    base_url: str = "http://127.0.0.1:11434",
    max_retries: int = 20,
    retry_delay: float = 1.0,
    console_out: Any | None = None,
) -> bool:
    """Wait for Ollama to be ready via health check (optimized)."""
    import time
    import httpx
    
    out = console_out or ui.console
    health_url = f"{base_url.rstrip('/')}/api/tags"
    
    # Use persistent client to reuse connections
    with httpx.Client(timeout=3.0) as client:
        for attempt in range(max_retries):
            try:
                resp = client.get(health_url)
                if resp.status_code == 200:
                    out.print(f"[green]✓ Ollama is ready[/green] at {base_url}")
                    return True
            except Exception:
                pass
            
            if attempt < max_retries - 1:
                out.print(f"[dim]Waiting for Ollama… ({attempt + 1}/{max_retries})[/dim]")
                time.sleep(retry_delay)
    
    out.print(f"[red]✗ Ollama not ready after {max_retries * retry_delay:.0f} seconds[/red]")
    return False


def interactive_env_setup(
    env_file_path: str = ".env",
    console_out: Any | None = None,
) -> dict[str, str]:
    """Interactively guide user through .env configuration."""
    import os
    
    out = console_out or ui.console
    
    out.print("\n[bold cyan]╔════════════════════════════════════════════════════════════╗[/bold cyan]")
    out.print("[bold cyan]║      SecAgents Configuration Setup                          ║[/bold cyan]")
    out.print("[bold cyan]╚════════════════════════════════════════════════════════════╝[/bold cyan]\n")
    
    config: dict[str, str] = {}
    
    # Provider selection
    out.print("[bold]1. Select LLM Provider:[/bold]")
    out.print("  [cyan]a[/cyan] - Ollama (Local, Free, Recommended)")
    out.print("  [cyan]b[/cyan] - OpenAI (Most Accurate)")
    out.print("  [cyan]c[/cyan] - Groq (Fastest, Cheapest)")
    out.print("  [cyan]d[/cyan] - DeepSeek (Good Balance)")
    out.print("  [cyan]e[/cyan] - Anthropic")
    out.print("  [cyan]f[/cyan] - Qwen/Alibaba")
    
    choice = input("\nChoice (a-f) [default: a]: ").strip().lower() or "a"
    
    provider_map = {
        "a": "ollama",
        "b": "openai",
        "c": "groq",
        "d": "deepseek",
        "e": "anthropic",
        "f": "qwen",
    }
    
    provider = provider_map.get(choice, "ollama")
    config["SECAGENTS_PROVIDER"] = provider
    out.print(f"[green]✓ Selected: {provider}[/green]\n")
    
    # API Key if needed
    if provider != "ollama":
        out.print(f"[bold]2. Enter {provider.upper()} API Key:[/bold]")
        api_key = input(f"{provider.upper()}_API_KEY (or just press Enter to skip): ").strip()
        
        if api_key:
            if provider == "openai":
                config["OPENAI_API_KEY"] = api_key
            elif provider == "anthropic":
                config["ANTHROPIC_API_KEY"] = api_key
            elif provider == "groq":
                config["SECAGENTS_GROQ_API_KEY"] = api_key
            elif provider == "deepseek":
                config["SECAGENTS_DEEPSEEK_API_KEY"] = api_key
            elif provider == "qwen":
                config["SECAGENTS_QWEN_API_KEY"] = api_key
            out.print(f"[green]✓ API key set[/green]\n")
        else:
            out.print("[yellow]⚠ Skipping API key[/yellow]\n")
    else:
        # Ollama-specific setup
        out.print("[bold]2. Ollama Configuration:[/bold]")
        out.print(f"  Default Ollama URL: http://127.0.0.1:11434")
        custom_url = input("  Enter custom URL (or press Enter to use default): ").strip()
        if custom_url:
            config["SECAGENTS_OLLAMA_BASE_URL"] = custom_url
        
        # Default model
        out.print(f"\n  Available models: llama3.2, mistral, neural-chat, etc.")
        model = input("  Model to pull (default: llama3.2): ").strip() or "llama3.2"
        config["SECAGENTS_MODEL"] = model
        out.print()
    
    # Advanced options
    out.print("[bold]3. Advanced Options:[/bold]")
    use_consensus = input("Enable multi-AI consensus voting? (y/n) [default: y]: ").strip().lower() or "y"
    config["SECAGENTS_USE_MULTI_AI_CONSENSUS"] = "true" if use_consensus == "y" else "false"
    
    team_mode = input("Use multi-agent team (Recon→Exploit→Validator→Remediator)? (y/n) [default: y]: ").strip().lower() or "y"
    config["SECAGENTS_USE_AGENT_TEAM"] = "true" if team_mode == "y" else "false"
    
    out.print()
    
    # Write .env file
    if os.path.exists(env_file_path):
        overwrite = input(f"[yellow]⚠ {env_file_path} already exists. Overwrite? (y/n) [default: n]:[/yellow] ").strip().lower()
        if overwrite != "y":
            out.print("[dim]Keeping existing .env file[/dim]\n")
            return config
    
    with open(env_file_path, "w") as f:
        f.write("# SecAgents Configuration (Generated by setup)\n")
        f.write("# Edit this file to customize settings\n\n")
        for key, value in sorted(config.items()):
            f.write(f"{key}={value}\n")
    
    out.print(f"[green]✓ Configuration saved to {env_file_path}[/green]\n")
    return config
