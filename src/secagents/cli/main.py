from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from secagents.agents.orchestrator import run_red_team_scan
from secagents.config import AppConfig, LLMProvider, Severity
from secagents.docker_mgr import (
    detect_docker,
    ollama_pull_model,
    start_ollama_container,
    try_install_docker_hint,
)
from secagents.reporting.report import ci_should_fail, max_severity, write_reports
from secagents.targets.acquire import acquire_github_repo, acquire_local, acquire_url_target

app = typer.Typer(
    name="secagents",
    help=(
        "Autonomous multi-agent red team: Recon → Exploit/PoC → Validator → Remediator. "
        "Docker sandbox, PoC-backed findings, auto-fix reports, CI gates."
    ),
    no_args_is_help=True,
)
console = Console(stderr=True)

def _typer_severity(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except ValueError as e:
        raise typer.BadParameter(f"Unknown severity: {s}") from e


@app.command("version")
def version_cmd() -> None:
    """Print the installed SecAgents version."""
    try:
        from importlib.metadata import version

        v = version("secagents")
    except Exception:
        from secagents import __version__

        v = __version__
    console.print(v)


@app.command("doctor")
def doctor() -> None:
    """Check Docker availability and basic connectivity."""
    info = detect_docker()
    table = Table(title="SecAgents doctor")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    if info.available:
        table.add_row("Docker", f"[green]OK[/green] ({info.version or 'unknown'})")
    else:
        table.add_row("Docker", f"[red]Unavailable[/red]: {info.error}")
        console.print(table)
        console.print(f"Install guide: {try_install_docker_hint()}")
        raise typer.Exit(code=1)
    console.print(table)


@app.command("setup-ollama")
def setup_ollama(
    model: Annotated[str, typer.Option(help="Ollama model tag, e.g. llama3.2 or mistral")] = "llama3.2",
    port: Annotated[int, typer.Option(help="Host port mapped to Ollama")] = 11434,
    pull_image: Annotated[bool, typer.Option(help="docker pull ollama/ollama")] = True,
) -> None:
    """Pull the Ollama image, start a container, and pull the requested model weights."""
    info = detect_docker()
    if not info.available:
        console.print(f"[red]{info.error}[/red]")
        console.print(f"Install: {try_install_docker_hint()}")
        raise typer.Exit(code=1)
    cfg = AppConfig()
    base = start_ollama_container(
        name=cfg.ollama_container_name,
        image=cfg.ollama_docker_image,
        host_port=port,
        pull=pull_image,
    )
    cfg = cfg.model_copy(update={"ollama_base_url": base})
    ollama_pull_model(base, model)
    console.print(
        f"[green]Ollama ready[/green] at {base} with model [bold]{model}[/bold]. "
        f"Export SECAGENTS_OLLAMA_BASE_URL={base} or pass --provider ollama."
    )


@app.command("scan")
def scan(
    target: Annotated[str, typer.Argument(help="Path, git URL, or https URL")],
    kind: Annotated[
        str,
        typer.Option("--kind", "-k", help="Target: auto, local, repo, or url"),
    ] = "auto",
    provider: Annotated[
        LLMProvider,
        typer.Option(help="LLM backend"),
    ] = LLMProvider.ollama,
    model: Annotated[str | None, typer.Option(help="Model id for the provider")] = None,
    temperature: Annotated[float, typer.Option(min=0.0, max=2.0)] = 0.15,
    top_p: Annotated[float, typer.Option(min=0.0, max=1.0)] = 0.9,
    max_tokens: Annotated[int, typer.Option(min=256, max=128000)] = 4096,
    max_turns: Annotated[int, typer.Option(min=1, max=200)] = 24,
    ollama_url: Annotated[
        str | None,
        typer.Option(help="Override Ollama base URL (default http://127.0.0.1:11434)"),
    ] = None,
    branch: Annotated[str | None, typer.Option(help="Git branch (repo targets)")] = None,
    out_dir: Annotated[
        Path | None,
        typer.Option(help="Write report.md and report.json here"),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Console output: markdown, json, both"),
    ] = "markdown",
    setup_local_ai: Annotated[
        bool,
        typer.Option(
            help="If provider=ollama: ensure Ollama container + pull model before scan",
        ),
    ] = False,
    allow_network: Annotated[
        bool,
        typer.Option(help="Allow sandbox network when model requests it (URL targets)"),
    ] = False,
    team: Annotated[
        bool,
        typer.Option(
            "--team/--no-team",
            help="Use collaborating agents (Recon, Exploit, Validator, Remediator); "
            "--no-team is a single-orchestrator fast path.",
        ),
    ] = True,
    recon_turns: Annotated[
        int,
        typer.Option(min=0, max=80, help="Recon agent turn budget (team mode)"),
    ] = 3,
    validation_turns: Annotated[
        int,
        typer.Option(min=0, max=80, help="Validator agent turn budget (team mode)"),
    ] = 5,
    remediation: Annotated[
        bool,
        typer.Option(
            "--remediation/--no-remediation",
            help="Final Remediator pass: unified diffs + autofix.md / JSON bundle.",
        ),
    ] = True,
    parallel_specialists: Annotated[
        int,
        typer.Option(
            min=1,
            max=8,
            help="Parallel opening tracks: 1=off, 2=code+OSINT, 3+=add Infra/Config (three-way; 4–8 same trio).",
        ),
    ] = 2,
    sandbox_timeout: Annotated[
        int,
        typer.Option(min=30, max=3600, help="Docker sandbox per-command timeout (seconds)."),
    ] = 300,
    sandbox_shm: Annotated[
        str,
        typer.Option(help="Docker --shm-size (e.g. 1g) for Chromium / heavy tools."),
    ] = "1g",
) -> None:
    """Run autonomous red-team agents against a local folder, Git repo, or live URL."""
    info = detect_docker()
    if not info.available:
        console.print(f"[red]{info.error}[/red]")
        console.print(f"Install: {try_install_docker_hint()}")
        raise typer.Exit(code=1)

    resolved_kind = kind.strip().lower()
    if resolved_kind not in ("auto", "local", "repo", "url"):
        raise typer.BadParameter("kind must be one of: auto, local, repo, url")
    if resolved_kind == "auto":
        t = target.strip()
        if t.startswith("http://") or t.startswith("https://"):
            if "github.com" in t and "/blob/" not in t and " " not in t:
                resolved_kind = "repo"
            else:
                resolved_kind = "url"
        else:
            resolved_kind = "local"

    cleanup: Path | None = None
    try:
        if resolved_kind == "local":
            acq = acquire_local(target)
        elif resolved_kind == "repo":
            acq = acquire_github_repo(target, branch=branch)
        elif resolved_kind == "url":
            acq = acquire_url_target(target)
        else:
            raise typer.BadParameter(f"Unsupported kind: {resolved_kind}")
        cleanup = acq.cleanup

        base_cfg = AppConfig()
        cfg = base_cfg.model_copy(
            update={
                "provider": provider,
                "model": model or base_cfg.model,
                "temperature": temperature,
                "top_p": top_p,
                "max_tokens": max_tokens,
                "max_agent_turns": max_turns,
                "use_agent_team": team,
                "recon_turns": recon_turns,
                "validation_turns": validation_turns,
                "run_remediation_pass": remediation,
                "parallel_specialists": parallel_specialists,
                "sandbox_command_timeout_sec": sandbox_timeout,
                "sandbox_shm_size": sandbox_shm,
            }
        )
        if ollama_url:
            cfg = cfg.model_copy(update={"ollama_base_url": ollama_url})

        if provider == LLMProvider.ollama and setup_local_ai:
            base = start_ollama_container(
                name=cfg.ollama_container_name,
                image=cfg.ollama_docker_image,
                host_port=cfg.ollama_host_port,
                pull=True,
            )
            cfg = cfg.model_copy(update={"ollama_base_url": base})
            ollama_pull_model(base, cfg.model)

        if resolved_kind == "url":
            allow_network = True

        console.print(
            f"[bold]Scanning[/bold] [cyan]{acq.label}[/cyan] "
            f"via [yellow]{provider.value}[/yellow] / [bold]{cfg.model}[/bold]"
        )
        result = run_red_team_scan(
            acq.root,
            cfg,
            allow_network=allow_network,
            use_agent_team=team,
        )

        from secagents.reporting.report import findings_to_json, render_markdown_report

        ofmt = output_format.strip().lower()
        if ofmt not in ("markdown", "json", "both"):
            raise typer.BadParameter("format must be markdown, json, or both")
        if ofmt in ("markdown", "both"):
            console.print(
                render_markdown_report(
                    acq.label, result, provider=provider.value, model=cfg.model
                )
            )
        if ofmt in ("json", "both"):
            console.print(findings_to_json(acq.label, result, provider=provider.value, model=cfg.model))

        if out_dir:
            md_p, js_p = write_reports(
                out_dir, acq.label, result, provider=provider.value, model=cfg.model
            )
            console.print(f"[green]Wrote[/green] {md_p} and {js_p}")
            af = out_dir / "autofix.md"
            if af.is_file():
                console.print(f"[green]Wrote[/green] {af}")
            kg = out_dir / "knowledge_graph.json"
            if kg.is_file():
                console.print(f"[green]Wrote[/green] {kg}")

        worst = max_severity(result)
        if worst:
            console.print(f"[bold]Max severity:[/bold] {worst.value}")
    finally:
        if cleanup and cleanup.exists():
            shutil.rmtree(cleanup, ignore_errors=True)


@app.command("ci")
def ci(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)],
    fail_on: Annotated[
        str,
        typer.Option(help="Exit 1 if any finding is at or above this severity"),
    ] = "high",
    provider: Annotated[LLMProvider, typer.Option()] = LLMProvider.ollama,
    model: Annotated[str | None, typer.Option()] = None,
    temperature: Annotated[float, typer.Option(min=0.0, max=2.0)] = 0.1,
    top_p: Annotated[float, typer.Option(min=0.0, max=1.0)] = 0.9,
    max_tokens: Annotated[int, typer.Option(min=256, max=128000)] = 4096,
    max_turns: Annotated[int, typer.Option(min=1, max=200)] = 16,
    out_dir: Annotated[Path, typer.Option(help="Artifact directory")] = Path("secagents-report"),
    setup_local_ai: Annotated[
        bool,
        typer.Option(help="Ensure Ollama container + model (provider=ollama)"),
    ] = False,
    team: Annotated[bool, typer.Option("--team/--no-team")] = True,
    recon_turns: Annotated[int, typer.Option(min=0, max=80)] = 2,
    validation_turns: Annotated[int, typer.Option(min=0, max=80)] = 3,
    remediation: Annotated[bool, typer.Option("--remediation/--no-remediation")] = True,
    parallel_specialists: Annotated[int, typer.Option(min=1, max=8)] = 2,
    sandbox_timeout: Annotated[int, typer.Option(min=30, max=3600)] = 300,
    sandbox_shm: Annotated[str, typer.Option()] = "1g",
) -> None:
    """CI-oriented scan: writes JSON/Markdown artifacts and fails on severity threshold."""
    threshold = _typer_severity(fail_on)
    info = detect_docker()
    if not info.available:
        console.print(f"[red]{info.error}[/red]")
        raise typer.Exit(code=1)

    base_cfg = AppConfig()
    cfg = base_cfg.model_copy(
        update={
            "provider": provider,
            "model": model or base_cfg.model,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
            "max_agent_turns": max_turns,
            "use_agent_team": team,
            "recon_turns": recon_turns,
            "validation_turns": validation_turns,
            "run_remediation_pass": remediation,
            "parallel_specialists": parallel_specialists,
            "sandbox_command_timeout_sec": sandbox_timeout,
            "sandbox_shm_size": sandbox_shm,
        }
    )
    if provider == LLMProvider.ollama and setup_local_ai:
        base = start_ollama_container(
            name=cfg.ollama_container_name,
            image=cfg.ollama_docker_image,
            host_port=cfg.ollama_host_port,
            pull=True,
        )
        cfg = cfg.model_copy(update={"ollama_base_url": base})
        ollama_pull_model(base, cfg.model)

    acq = acquire_local(path)
    result = run_red_team_scan(acq.root, cfg, allow_network=False, use_agent_team=team)
    write_reports(out_dir, acq.label, result, provider=provider.value, model=cfg.model)

    if ci_should_fail(result, threshold):
        console.print(
            f"[red]CI gate failed:[/red] finding at or above [bold]{threshold.value}[/bold]."
        )
        raise typer.Exit(code=1)
    console.print("[green]CI gate passed[/green] for configured threshold.")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(app())
