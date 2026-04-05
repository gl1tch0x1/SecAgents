from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

from rich.console import Console

from secagents.paths import bundled_docker_dir

console = Console(stderr=True)


def _docker_bin() -> str:
    d = shutil.which("docker")
    if not d:
        raise RuntimeError("Docker CLI not found in PATH.")
    return d


def run_in_sandbox(
    workspace: Path,
    command: str,
    *,
    image: str,
    network: str = "none",
    timeout_sec: int = 120,
    shm_size: str | None = None,
) -> tuple[int, str, str]:
    """
    Run a shell command inside an ephemeral container with the workspace mounted read-only
    at /workspace. Network defaults to 'none' for safety; use 'bridge' only when needed.
    """
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise FileNotFoundError(str(workspace))
    docker = _docker_bin()
    name = f"secagents-{uuid.uuid4().hex[:12]}"
    cmd = [docker, "run", "--rm"]
    if shm_size:
        cmd.extend(["--shm-size", shm_size])
    cmd.extend(
        [
        "--name",
        name,
        "-v",
        f"{workspace}:/workspace:ro",
        "-w",
        "/workspace",
        "--network",
        network,
        image,
        "sh",
        "-lc",
        command,
        ]
    )
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout_sec}s"
    return cp.returncode, cp.stdout or "", cp.stderr or ""


def build_sandbox_image_if_needed(dockerfile_dir: Path | None, tag: str) -> None:
    """Build local sandbox image from Dockerfile.sandbox if missing."""
    docker = _docker_bin()
    inspect = subprocess.run(
        [docker, "image", "inspect", tag],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspect.returncode == 0:
        return
    base = dockerfile_dir or bundled_docker_dir()
    df = base / "Dockerfile.sandbox"
    if not df.is_file():
        console.print(
            "[yellow]No Dockerfile.sandbox found; using plain alpine for sandbox.[/yellow]"
        )
        subprocess.run([docker, "pull", "alpine:3.20"], check=True)
        subprocess.run([docker, "tag", "alpine:3.20", tag], check=True)
        return
    console.print(f"[bold cyan]Building[/bold cyan] sandbox image [bold]{tag}[/bold] …")
    subprocess.run(
        [docker, "build", "-f", str(df), "-t", tag, str(base)],
        check=True,
    )
