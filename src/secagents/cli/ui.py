from __future__ import annotations

import time
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    DownloadColumn,
    TransferSpeedColumn,
)
from rich.status import Status
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Tactical Hacker Theme
TACTICAL_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "operative": "bold magenta",
    "mission": "bold cyan",
    "command": "bold white on blue",
    "highlight": "bold green",
    "dim": "grey50",
})

class UI:
    """Core UI manager for tactical CLI output."""
    
    def __init__(self, stderr: bool = True):
        self.console = Console(theme=TACTICAL_THEME, stderr=stderr)

    def banner(self):
        """Display the tactical ASCII banner."""
        banner_text = """
 [bold green] ██████╗███████╗ ██████╗  █████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗[/bold green]
 [bold green]██╔════╝██╔════╝██╔════╝ ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝[/bold green]
 [bold green]╚█████╗ █████╗  ██║      ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗[/bold green]
 [bold green] ╚═══██╗██╔══╝  ██║      ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║[/bold green]
 [bold green]██████╔╝███████╗╚██████╗ ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║[/bold green]
 [bold green]╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝[/bold green]
 [bold cyan]  ⚡ AUTONOMOUS MULTI-AGENT RED-TEAM FRAMEWORK | MISSION CONTROL V0.2.1-TAC[/bold cyan]
        """
        self.console.print(banner_text)

    def mission_brief(self, text: str, delay: float = 0.005):
        """Print text with a tactical 'typing' effect."""
        for char in text:
            self.console.print(f"[success]{char}[/success]", end="", highlight=False)
            time.sleep(delay)
        self.console.print()

    def panel(self, content: Any, title: str | None = None, subtitle: str | None = None, style: str = "cyan"):
        """Wrap content in a tactical panel."""
        self.console.print(
            Panel(
                content,
                title=f"[bold]{title}[/bold]" if title else None,
                subtitle=f"[dim]{subtitle}[/dim]" if subtitle else None,
                border_style=style,
                padding=(1, 2),
            )
        )

    def status(self, message: str, spinner: str = "monkey") -> Status:
        """Get a themed status spinner context."""
        return self.console.status(f"[cyan]{message}[/cyan]", spinner=spinner)

    def progress(self, transient: bool = True) -> Progress:
        """Get a themed progress bar."""
        return Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None, style="grey50", complete_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            transient=transient,
            console=self.console,
        )

    def print_success(self, message: str):
        self.console.print(f"[success]✓[/success] {message}")

    def print_error(self, message: str):
        self.console.print(f"[error]✗[/error] {message}")

    def print_info(self, message: str):
        self.console.print(f"[info]ℹ[/info] {message}")

    def print_warning(self, message: str):
        self.console.print(f"[warning]⚠[/warning] {message}")

    def print_command(self, cmd: str):
        self.console.print(f"  [command] > [/command] [bold cyan]{cmd}[/bold cyan]")

    def h2(self, text: str):
        """Header 2 style."""
        self.console.print(f"\n[bold cyan]─── {text.upper()} ───[/bold cyan]\n")

    def tactical_table(self, title: str, columns: list[str]) -> Table:
        """Create a styled tactical table."""
        table = Table(
            title=f"[bold cyan]{title}[/bold cyan]",
            header_style="bold magenta",
            border_style="cyan",
            box=None,
            row_styles=["", "dim"],
        )
        for col in columns:
            table.add_column(col)
        return table

    def prompt(self, message: str, default: str | None = None, choices: list[str] | None = None) -> str:
        """Tactical interactive prompt."""
        from rich.prompt import Prompt
        result = Prompt.ask(
            f"[bold cyan]>[/bold cyan] [white]{message}[/white]",
            default=default,
            choices=choices,
            console=self.console,
        )
        if result is None:
            raise RuntimeError("Prompt aborted or returned no input")
        return result

    def confirm(self, message: str, default: bool = True) -> bool:
        """Tactical confirmation prompt."""
        from rich.prompt import Confirm
        return Confirm.ask(
            f"[bold yellow]?[/bold yellow] [white]{message}[/white]",
            default=default,
            console=self.console,
        )

# Global singleton
ui = UI()
