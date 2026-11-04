"""Command-line interface for agent-sandbox-evals benchmark suite."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from agent_sandbox_evals.models import AttackCategory, HarnessLayer
from agent_sandbox_evals.reporting.generator import ReportGenerator
from agent_sandbox_evals.runner import BenchmarkRunner
from agent_sandbox_evals.vectors.matrix import get_all_vectors, get_vectors_by_category

app = typer.Typer(
    name="agent-sandbox-evals",
    help="Empirical AI Agent Sandbox Containment Benchmark Suite (Raw Host vs Sanitized MCP vs OCI Container)",
    add_completion=False,
)
console = Console()


@app.command()
def list_vectors(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category (ssrf, filesystem, privilege, resource_dos, secret_leak)"),
):
    """List all concrete adversarial attack vectors in the benchmark matrix."""
    vectors = get_all_vectors()
    if category:
        try:
            cat_enum = AttackCategory(category.lower())
            vectors = get_vectors_by_category(cat_enum)
        except ValueError:
            console.print(f"[red]Invalid category: {category}. Choose from: {[c.value for c in AttackCategory]}[/red]")
            raise typer.Exit(code=1)

    table = Table(title=f"Adversarial Attack Suite Matrix ({len(vectors)} Vectors)", show_lines=True)
    table.add_column("Vector ID", style="cyan bold", width=10)
    table.add_column("Category", style="magenta", width=14)
    table.add_column("Severity", style="yellow bold", width=9)
    table.add_column("Name & Description", style="white")
    table.add_column("Payload Preview", style="dim green", width=35)

    for v in vectors:
        sev_color = "red" if v.severity.value in ("CRITICAL", "HIGH") else "yellow"
        table.add_row(
            v.id,
            v.category.value,
            Text(v.severity.value, style=sev_color),
            f"[bold]{v.name}[/bold]\n{v.description}",
            v.payload_command[:60] + "..." if len(v.payload_command) > 60 else v.payload_command,
        )

    console.print(table)


@app.command()
def check_environment():
    """Verify host environment, Python runtime, and Docker container sandbox readiness."""
    console.print(Panel.fit("[bold blue]Agent Sandbox Evals - Environment Preflight Check[/bold blue]"))
    import sys
    import os
    import shutil

    console.print(f"• Python Version: [green]{sys.version.split()[0]}[/green] ({sys.executable})")
    console.print(f"• Host OS: [green]{os.uname().sysname} {os.uname().machine}[/green]")

    docker_path = shutil.which("docker")
    if docker_path:
        console.print(f"• Docker CLI: [green]Available[/green] ({docker_path})")
    else:
        console.print("• Docker CLI: [red]Not Found in PATH[/red]")

    # Check Docker daemon connectivity
    import subprocess
    try:
        res = subprocess.run(["docker", "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        if res.returncode == 0:
            console.print("• Docker Daemon: [green]Connected & Responsive[/green]")
        else:
            console.print("• Docker Daemon: [yellow]Not responsive (Check Docker Desktop)[/yellow]")
    except Exception as e:
        console.print(f"• Docker Daemon: [yellow]Check failed ({e})[/yellow]")


@app.command()
def run(
    layers: Optional[str] = typer.Option(
        "layer0_host,layer1_sanitized,layer2_container",
        "--layers", "-l",
        help="Comma-separated isolation layers to evaluate (layer0_host,layer1_sanitized,layer2_container)",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category", "-c",
        help="Filter vectors by attack category (ssrf, filesystem, privilege, resource_dos, secret_leak)",
    ),
    output_dir: Path = typer.Option(
        Path("./reports"),
        "--output-dir", "-o",
        help="Directory to save generated Markdown and JSON reports",
    ),
    report_name: str = typer.Option(
        "containment_benchmark",
        "--report-name", "-n",
        help="Base filename for generated reports",
    ),
):
    """Execute empirical benchmark and generate containment evaluation reports."""
    console.print(Panel.fit(
        "[bold cyan]Starting Agent Sandbox Containment Empirical Benchmark[/bold cyan]\n"
        "[dim]Evaluating containment boundaries across Layer 0 (Host), Layer 1 (Sanitized MCP), and Layer 2 (OCI Container)[/dim]"
    ))

    # Parse layers
    layer_enums: List[HarnessLayer] = []
    for l_str in layers.split(","):
        l_str = l_str.strip()
        try:
            layer_enums.append(HarnessLayer(l_str))
        except ValueError:
            console.print(f"[red]Error: Unknown layer '{l_str}'. Valid: {[l.value for l in HarnessLayer]}[/red]")
            raise typer.Exit(code=1)

    # Filter vectors
    vectors = get_all_vectors()
    if category:
        try:
            cat_enum = AttackCategory(category.lower())
            vectors = get_vectors_by_category(cat_enum)
        except ValueError:
            console.print(f"[red]Error: Unknown category '{category}'[/red]")
            raise typer.Exit(code=1)

    console.print(f"Configured: [bold]{len(vectors)}[/bold] vectors across [bold]{len(layer_enums)}[/bold] layers.\n")

    # Progress reporting callback
    def on_progress(result, current, total):
        status_symbol = "[red]BREACH[/red]" if result.breached else "[green]OK[/green]"
        layer_tag = result.layer.short_name
        console.print(
            f"[{current:02d}/{total:02d}] {layer_tag:<14} | {result.vector_id:<9} | {status_symbol:<16} | {result.outcome.value:<14} ({result.duration_ms:5.1f} ms)"
        )

    runner = BenchmarkRunner(
        vectors=vectors,
        layers=layer_enums,
        progress_callback=on_progress,
    )

    report = asyncio.run(runner.run())

    # Generate and save reports
    generator = ReportGenerator(report)
    saved_paths = generator.write_reports(output_dir=output_dir, basename=report_name)

    # Print Summary Table to console
    summary_table = Table(title="Containment Benchmark Results Summary", show_lines=True)
    summary_table.add_column("Isolation Layer", style="cyan bold")
    summary_table.add_column("Vectors", justify="right")
    summary_table.add_column("Blocked", justify="right", style="green")
    summary_table.add_column("Contained", justify="right", style="green")
    summary_table.add_column("Breaches", justify="right", style="red bold")
    summary_table.add_column("CFR (%)", justify="right", style="red bold")
    summary_table.add_column("CSR (%)", justify="right", style="green bold")
    summary_table.add_column("Avg Block (ms)", justify="right")
    summary_table.add_column("Avg Exec (ms)", justify="right")
    summary_table.add_column("Overhead (ms)", justify="right")

    for l_enum in layer_enums:
        if l_enum in report.layers:
            s = report.layers[l_enum]
            summary_table.add_row(
                s.layer_name,
                str(s.total_vectors),
                str(s.blocked_count),
                str(s.contained_count),
                str(s.failure_count),
                f"{s.cfr_pct:.1f}%",
                f"{s.csr_pct:.1f}%",
                f"{s.avg_detection_ms:.2f} ms" if s.avg_detection_ms > 0 else "—",
                f"{s.avg_execution_ms:.1f} ms",
                f"{s.baseline_latency_ms:.1f} ms",
            )

    console.print("\n")
    console.print(summary_table)
    console.print(f"\n[bold green]✓ Benchmark complete![/bold green]")
    console.print(f"• Markdown Report: [link=file://{saved_paths['markdown'].resolve()}]{saved_paths['markdown']}[/link]")
    console.print(f"• JSON Dataset:    [link=file://{saved_paths['json'].resolve()}]{saved_paths['json']}[/link]\n")


def main():
    app()


if __name__ == "__main__":
    main()
