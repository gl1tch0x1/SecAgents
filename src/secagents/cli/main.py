from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(
    name="secagents",
    help=(
        "Autonomous multi-agent red team: Recon → Exploit/PoC → Validator → Remediator. "
        "Docker sandbox, PoC-backed findings, auto-fix reports, CI gates."
    ),
    no_args_is_help=True,
)


def _typer_severity(s: str):
    from secagents.config import Severity
    try:
        return Severity(s.lower())
    except ValueError as e:
        raise typer.BadParameter(f"Unknown severity: {s}") from e


@app.command("version")
def version_cmd() -> None:
    """Print the installed SecAgents version."""
    from secagents.cli.ui import ui
    try:
        from importlib.metadata import version
        v = version("secagents")
    except Exception:
        from secagents import __version__
        v = __version__
    ui.console.print(f"[bold cyan]SecAgents[/bold cyan] [dim]v{v}[/dim]")


@app.command("doctor")
def doctor() -> None:
    """Check Docker availability and basic connectivity."""
    from secagents.cli.ui import ui
    from secagents.docker_mgr import detect_docker, try_install_docker_hint

    ui.banner()
    with ui.status("Running tactical diagnostic: [bold cyan]DOCTOR[/bold cyan]...", spinner="point"):
        info = detect_docker()
    
    table = ui.tactical_table("Diagnostic Report", ["Check", "Status"])
    
    if info.available:
        table.add_row("Docker Core", f"[success]OK[/success] [dim]({info.version or 'unknown'})[/dim]")
    else:
        table.add_row("Docker Core", f"[error]UNAVAILABLE[/error] [dim]({info.error})[/dim]")
        ui.console.print(table)
        ui.print_warning(f"Deployment hint: {try_install_docker_hint()}")
        raise typer.Exit(code=1)
        
    ui.console.print(table)
    ui.print_success("Systems operational. Ready for deployment.")


@app.command("setup-ollama")
def setup_ollama(
    model: Annotated[str, typer.Option(help="Ollama model tag, e.g. llama3.2 or mistral")] = "llama3.2",
    port: Annotated[int, typer.Option(help="Host port mapped to Ollama")] = 11434,
    pull_image: Annotated[bool, typer.Option(help="docker pull ollama/ollama")] = True,
) -> None:
    """Deploy Ollama core and synchronize models."""
    from secagents.cli.ui import ui
    from secagents.docker_mgr import detect_docker, start_ollama_container, ollama_pull_model, try_install_docker_hint
    from secagents.config import AppConfig

    ui.banner()
    info = detect_docker()
    if not info.available:
        ui.print_error(f"Core failure: {info.error}")
        ui.print_info(f"Install guide: {try_install_docker_hint()}")
        raise typer.Exit(code=1)
        
    cfg = AppConfig()
    ui.h2("Ollama Tactical Deployment")
    
    base = start_ollama_container(
        name=cfg.ollama_container_name,
        image=cfg.ollama_docker_image,
        host_port=port,
        pull=pull_image,
    )
    
    ollama_pull_model(base, model)
    ui.panel(f"Ollama node synchronized at [bold cyan]{base}[/bold cyan] with model [bold yellow]{model}[/bold yellow]", title="DEPLOYMENT COMPLETE")
    ui.print_info(f"Action: Export [bold green]SECAGENTS_OLLAMA_BASE_URL={base}[/bold green]")


@app.command("install")
def install(
    docker_install: Annotated[bool, typer.Option("--docker-install", help="Full Docker suite setup")] = False,
    setup_ollama_cmd: Annotated[bool, typer.Option("--setup-ollama", help="Deploy Ollama node only")] = False,
    env_file: Annotated[str, typer.Option(help="Configuration path")] = ".env",
    compose_file: Annotated[str, typer.Option(help="Orchestration path")] = "docker-compose.yml",
    image_tag: Annotated[str, typer.Option(help="Operative image tag")] = "secagents:latest",
) -> None:
    """Execute SecAgents deployment sequence."""
    from secagents.cli.ui import ui
    from secagents.docker_mgr import (
        detect_docker,
        interactive_env_setup,
        build_secagents_image,
        docker_compose_up,
        wait_for_ollama,
        ollama_pull_model,
        try_install_docker_hint,
    )
    
    if docker_install or setup_ollama_cmd:
        info = detect_docker()
        if not info.available:
            ui.print_error(f"Incomplete environment: {info.error}")
            ui.print_warning("Docker is required for this installation path.")
            ui.print_info(f"Target guide: {try_install_docker_hint()}")
            raise typer.Exit(code=1)
        ui.print_success(f"Docker Link: Verified [dim]({info.version})[/dim]")
    
    # Step 2: Interactive .env setup
    config = interactive_env_setup(env_file)
    
    if docker_install:
        ui.h2("Full Tactical Suite Deployment")
        
        try:
            build_secagents_image(tag=image_tag, console_out=ui.console)
        except Exception as e:
            ui.print_error(f"Build failed: {e}")
            raise typer.Exit(code=1)
        
        try:
            docker_compose_up(compose_file=compose_file, console_out=ui.console)
        except Exception as e:
            ui.print_error(f"Orchestration failed: {e}")
            raise typer.Exit(code=1)
        
        # Wait for Ollama
        base_url = config.get("SECAGENTS_OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        if wait_for_ollama(base_url=base_url):
            model = config.get("SECAGENTS_MODEL", "llama3.2")
            try:
                ollama_pull_model(base_url, model)
            except Exception as e:
                ui.print_warning(f"Model sync failed: {e}")
        else:
            ui.print_warning("Ollama sync timeout. Manual recovery may be required.")
        
        ui.panel("SecAgents Tactical Suite is now fully deployed and operational.", title="MISSION READY", style="green")
        ui.print_info("Execution: [bold cyan]docker-compose run --rm secagents scan ./target[/bold cyan]")
    
    elif setup_ollama_cmd:
        ui.h2("Ollama Node Initialization")
        from secagents.docker_mgr import start_ollama_container
        from secagents.config import AppConfig
        cfg = AppConfig()
        try:
            base = start_ollama_container(name=cfg.ollama_container_name, image=cfg.ollama_docker_image, host_port=cfg.ollama_host_port)
            if wait_for_ollama(base):
                model = config.get("SECAGENTS_MODEL", "llama3.2")
                ollama_pull_model(base, model)
                ui.print_success(f"Ollama Node operational with model: {model}")
        except Exception as e:
            ui.print_error(f"Initialization failed: {e}")
            raise typer.Exit(code=1)
    
    else:
        ui.h2("Standard Link Synchronized")
        ui.print_success("Configuration matrix updated.")
        ui.print_info("Next phase:")
        ui.print_command("pip install -e .")
        ui.print_command("secagents scan ./target")


@app.command("scan")
def scan(
    target: Annotated[str, typer.Argument(help="Path, Git URL, or HTTPS URL")],
    kind: Annotated[str, typer.Option("--kind", "-k", help="Target kind: auto, local, repo, url")] = "auto",
    provider: Annotated[str, typer.Option(help="LLM Core Provider")] = "ollama",
    model: Annotated[str | None, typer.Option(help="Neural Model core ID")] = None,
    temperature: Annotated[float, typer.Option(min=0.0, max=2.0)] = 0.15,
    top_p: Annotated[float, typer.Option(min=0.0, max=1.0)] = 0.9,
    max_tokens: Annotated[int, typer.Option(min=256, max=128000)] = 4096,
    max_turns: Annotated[int, typer.Option(min=1, max=200)] = 24,
    ollama_url: Annotated[str | None, typer.Option(help="Override Ollama Node URL")] = None,
    branch: Annotated[str | None, typer.Option(help="Git source branch")] = None,
    out_dir: Annotated[Path | None, typer.Option(help="Artifact extraction directory")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output matrix: markdown, json, both")] = "markdown",
    setup_local_ai: Annotated[bool, typer.Option(help="Auto-provision Ollama core before scan")] = False,
    allow_network: Annotated[bool, typer.Option(help="Authorize sandbox network egress")] = False,
    team: Annotated[bool, typer.Option("--team/--no-team", help="Deploy multi-agent strike team")] = True,
    parallel_specialists: Annotated[int, typer.Option(min=1, max=10)] = 2,
    platform: Annotated[str, typer.Option(help="Report alignment: generic, h1, bugcrowd")] = "generic",
    sandbox_timeout: Annotated[int, typer.Option(min=30, max=3600)] = 300,
) -> None:
    """Execute autonomous red-team strike against target perimeter."""
    from secagents.cli.ui import ui
    from secagents.docker_mgr import detect_docker, try_install_docker_hint
    from secagents.config import AppConfig, LLMProvider

    ui.banner()
    info = detect_docker()
    if not info.available:
        ui.print_error(f"Incomplete environment: {info.error}")
        ui.print_info(f"Target guide: {try_install_docker_hint()}")
        raise typer.Exit(code=1)

    resolved_kind = kind.strip().lower()
    if resolved_kind == "auto":
        t = target.strip()
        if t.startswith("http://") or t.startswith("https://"):
            resolved_kind = "repo" if "github.com" in t and "/blob/" not in t else "url"
        else:
            resolved_kind = "local"

    from secagents.targets.acquire import acquire_local, acquire_github_repo, acquire_url_target
    from secagents.agents.orchestrator import run_red_team_scan
    import shutil

    cleanup: Path | None = None
    try:
        with ui.status(f"Acquiring target perimeter: [bold yellow]{target}[/bold yellow]...", spinner="earth"):
            if resolved_kind == "local": acq = acquire_local(target)
            elif resolved_kind == "repo": acq = acquire_github_repo(target, branch=branch)
            elif resolved_kind == "url": acq = acquire_url_target(target)
            else: raise typer.BadParameter(f"Unsupported kind: {resolved_kind}")
        
        cleanup = acq.cleanup
        base_cfg = AppConfig()
        
        # Run preflight checks
        if base_cfg.enable_preflight_checks:
            from secagents.preflight import PreflightValidator
            validator = PreflightValidator(base_cfg)
            all_ok, checks = validator.validate_all()
            validator.print_report()
            if not all_ok:
                critical_errors = [c for c in checks if c.severity == "error" and not c.passed]
                if critical_errors:
                    raise typer.Exit(code=1)
        
        # Resolve provider enum
        try:
            prov_enum = LLMProvider(provider.lower())
        except ValueError:
            prov_enum = LLMProvider.ollama

        cfg = base_cfg.model_copy(update={
            "provider": prov_enum,
            "model": model or base_cfg.model,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
            "max_agent_turns": max_turns,
            "use_agent_team": team,
            "parallel_specialists": parallel_specialists,
            "sandbox_command_timeout_sec": sandbox_timeout,
        })
        
        if ollama_url: cfg = cfg.model_copy(update={"ollama_base_url": ollama_url})

        if prov_enum == LLMProvider.ollama and setup_local_ai:
            from secagents.docker_mgr import start_ollama_container, ollama_pull_model
            base = start_ollama_container(name=cfg.ollama_container_name, image=cfg.ollama_docker_image, host_port=cfg.ollama_host_port)
            cfg = cfg.model_copy(update={"ollama_base_url": base})
            ollama_pull_model(base, cfg.model)

        ui.panel(f"Target: [bold cyan]{acq.label}[/bold cyan]\nCore: [bold yellow]{prov_enum.value}[/bold yellow] | Model: [bold]{cfg.model}[/bold]", title="MISSION ASSIGNMENT")
        
        # Setup logging
        from secagents.logging_system import get_logger
        logger = get_logger()
        scan_start = __import__("time").time()
        logger.log_scan_start(acq.label, metadata={
            "provider": prov_enum.value,
            "model": cfg.model,
            "team_mode": team
        })
        
        with ui.status("Agents deployed. Infiltration sequence active...", spinner="aesthetic") as status:
            result = run_red_team_scan(
                acq.root, 
                cfg, 
                allow_network=allow_network, 
                use_agent_team=team,
                status_cb=status.update
            )
        
        # Log scan completion
        scan_duration = __import__("time").time() - scan_start
        logger.log_scan_complete(acq.label, len(result.findings), scan_duration)
        
        # Log vulnerabilities detected
        for finding in result.findings:
            logger.log_vulnerability_detected(finding.title, finding.severity, finding.category)

        from secagents.reporting.report import findings_to_json, render_markdown_report, max_severity

        ui.h2("Strike Analysis Complete")
        
        ofmt = output_format.strip().lower()
        if ofmt in ("markdown", "both"):
            ui.console.print(render_markdown_report(acq.label, result, provider=prov_enum.value, model=cfg.model, platform=platform))
        
        if out_dir:
            from secagents.reporting.report import write_reports
            from secagents.reporting.sarif import SARIFExporter
            md_p, js_p = write_reports(out_dir, acq.label, result, provider=prov_enum.value, model=cfg.model, platform=platform)
            
            # Export SARIF if enabled
            if cfg.enable_sarif_export:
                sarif_path = Path(out_dir) / f"{acq.label.replace('/', '_')}-scan.sarif"
                SARIFExporter.write_sarif_file(result, str(sarif_path), acq.label)
                ui.print_success(f"SARIF report: {sarif_path}")
            
            ui.print_success(f"Artifacts extracted to {out_dir}")

        worst = max_severity(result)
        if worst:
            ui.console.print(f"\n[bold]Criticality Threshold:[/bold] [bold red]{worst.value}[/bold red]")
            
    finally:
        # Cleanup HTTP connection pools
        from secagents.llm.providers import cleanup_httpx_clients
        cleanup_httpx_clients()
        
        if cleanup and cleanup.exists():
            shutil.rmtree(cleanup, ignore_errors=True)


@app.command("ci")
def ci(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)],
    fail_on: Annotated[str, typer.Option(help="Breach threshold")] = "high",
    provider: Annotated[str, typer.Option()] = "ollama",
    model: Annotated[str | None, typer.Option()] = None,
) -> None:
    """CI Operation: Automated perimeter check with exit code failure on vulnerability match."""
    from secagents.cli.ui import ui
    from secagents.docker_mgr import detect_docker
    from secagents.config import AppConfig, LLMProvider
    from secagents.agents.orchestrator import run_red_team_scan
    from secagents.reporting.report import ci_should_fail
    from secagents.targets.acquire import acquire_local

    try:
        threshold = _typer_severity(fail_on)
        info = detect_docker()
        if not info.available:
            ui.print_error("CI Environment failure: Docker unavailable")
            raise typer.Exit(code=1)

        cfg = AppConfig().model_copy(update={
            "provider": LLMProvider(provider),
            "model": model or AppConfig().model,
        })
        
        acq = acquire_local(path)
        with ui.status("CI Strike Protocol active...", spinner="arc") as status:
            result = run_red_team_scan(
                acq.root, 
                cfg, 
                allow_network=False, 
                use_agent_team=True,
                status_cb=status.update
            )

        if ci_should_fail(result, threshold):
            ui.print_error(f"CI Gate: BREACH DETECTED at or above {threshold.value}")
            raise typer.Exit(code=1)
        ui.print_success("CI Gate: No high-criticality vulnerabilities confirmed.")
    finally:
        # Cleanup HTTP connection pools
        from secagents.llm.providers import cleanup_httpx_clients
        cleanup_httpx_clients()


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(app())
