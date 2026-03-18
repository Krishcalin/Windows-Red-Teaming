"""CLI entry point for the Windows Red Teaming tool.

Usage:
    python main.py scan --target 192.168.1.10 --profile quick
    python main.py scan --target localhost --simulate
    python main.py scan --target 192.168.1.10 --tactic discovery
    python main.py scan --target 192.168.1.10 --technique T1082
    python main.py report --input reports/scan_20260316.json --format html
    python main.py list-modules
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from core import __version__
from core.config import build_config
from core.engine import ScanEngine
from core.logger import setup_logging
from core.mitre_mapper import MitreMapper
from core.reporter import Reporter

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="Windows Red Teaming Tool")
def cli() -> None:
    """Windows Red Teaming Tool — MITRE ATT&CK-aligned security scanner."""


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target host (IP, hostname, or 'localhost').",
)
@click.option(
    "--profile", "-p",
    default="full",
    type=click.Choice(["quick", "full", "stealth"], case_sensitive=False),
    help="Scan profile (default: full).",
)
@click.option(
    "--simulate", "-s",
    is_flag=True,
    default=False,
    help="Enable active simulation (requires explicit opt-in).",
)
@click.option(
    "--tactic",
    default=None,
    help="Filter to a specific ATT&CK tactic (e.g. 'discovery').",
)
@click.option(
    "--technique",
    default=None,
    help="Filter to a specific technique ID (e.g. T1082).",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output report filename (without extension).",
)
@click.option(
    "--format", "-f", "output_format",
    multiple=True,
    type=click.Choice(["html", "json", "csv"], case_sensitive=False),
    help="Report format(s). Can be specified multiple times.",
)
@click.option(
    "--severity",
    default="INFO",
    type=click.Choice(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False
    ),
    help="Minimum severity threshold for findings.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
def scan(
    target: str,
    profile: str,
    simulate: bool,
    tactic: str | None,
    technique: str | None,
    output: str | None,
    output_format: tuple[str, ...],
    severity: str,
    verbose: bool,
) -> None:
    """Run a security scan against a target."""
    config = build_config(
        target_host=target,
        profile_name=profile,
        simulate=simulate,
        tactic=tactic,
        technique=technique,
        verbose=verbose,
    )

    setup_logging(
        verbose=config.verbose,
        log_file=config.log_file,
        json_output=config.json_output,
    )

    if not config.targets:
        console.print("[red]Error:[/red] No targets configured.")
        sys.exit(1)

    # Show authorization banner
    if config.require_authorization:
        console.print(ScanEngine.AUTHORIZATION_BANNER, style="bold yellow")
        if not click.confirm("Do you have authorization to scan this target?"):
            console.print("[yellow]Scan aborted by user.[/yellow]")
            sys.exit(0)

    from core.models import Severity as SevEnum

    severity_threshold = SevEnum(severity.upper())

    engine = ScanEngine(
        profile=config.profile,
        simulate=config.simulate,
        tactic_filter=config.tactic_filter,
        technique_filter=config.technique_filter,
        severity_threshold=severity_threshold,
        evidence_dir=config.evidence_dir,
        enabled_techniques=config.enabled_techniques,
        disabled_techniques=config.disabled_techniques,
    )

    # Scan each target
    for scan_target in config.targets:
        console.print(
            f"\n[bold cyan]Scanning {scan_target.host}[/bold cyan] "
            f"(profile={config.profile}, simulate={config.simulate})"
        )

        scan_result = engine.scan(scan_target)

        # Print summary
        reporter = Reporter(
            output_dir=config.report_dir,
        )
        console.print(reporter.print_summary(scan_result))

        # Generate reports
        formats = list(output_format) if output_format else config.output_formats

        for fmt in formats:
            match fmt.lower():
                case "html":
                    path = reporter.generate_html(
                        scan_result,
                        f"{output}.html" if output else None,
                    )
                    console.print(f"  HTML report: [green]{path}[/green]")
                case "json":
                    path = reporter.generate_json(
                        scan_result,
                        f"{output}.json" if output else None,
                    )
                    console.print(f"  JSON report: [green]{path}[/green]")
                case "csv":
                    path = reporter.generate_csv(
                        scan_result,
                        f"{output}.csv" if output else None,
                    )
                    console.print(f"  CSV report:  [green]{path}[/green]")

        # Generate ATT&CK Navigator layer
        if config.attack_layer:
            mapper = MitreMapper(output_dir=config.report_dir)
            layer_path = mapper.generate_layer(scan_result)
            console.print(
                f"  ATT&CK layer: [green]{layer_path}[/green]"
            )

    # Exit code
    has_critical_high = any(
        f.severity.value in ("CRITICAL", "HIGH")
        for f in scan_result.all_findings
    )
    sys.exit(1 if has_critical_high else 0)


@cli.command("list-modules")
def list_modules() -> None:
    """List all discovered technique modules."""
    setup_logging(verbose=False)

    engine = ScanEngine()

    table = Table(
        title="Discovered Technique Modules",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Technique ID", style="bold")
    table.add_column("Name")
    table.add_column("Tactic")
    table.add_column("Severity")
    table.add_column("Admin?")
    table.add_column("OS Support")

    for mod in engine.discovered_modules:
        sev = mod["severity"]
        sev_style = {
            "CRITICAL": "red",
            "HIGH": "dark_orange",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }.get(sev, "white")

        table.add_row(
            mod["technique_id"],
            mod["technique_name"],
            mod["tactic"],
            f"[{sev_style}]{sev}[/{sev_style}]",
            "Yes" if mod["requires_admin"] else "No",
            ", ".join(mod["supported_os"]),
        )

    console.print(table)
    console.print(f"\nTotal modules: {len(engine.discovered_modules)}")


@cli.command()
@click.option(
    "--input", "-i", "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to a JSON scan result file.",
)
@click.option(
    "--format", "-f", "output_format",
    default="html",
    type=click.Choice(["html", "json", "csv", "attack-layer"], case_sensitive=False),
    help="Output format.",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output filename.",
)
def report(input_file: str, output_format: str, output: str | None) -> None:
    """Generate a report from a previous scan's JSON output."""
    import json
    from core.models import (
        Finding,
        ModuleResult,
        ModuleStatus,
        ScanResult,
        Severity,
        Target,
    )

    setup_logging(verbose=False)

    with open(input_file, encoding="utf-8") as f:
        data = json.load(f)

    # Reconstruct ScanResult from JSON
    target = Target(host=data["target"]["host"])
    scan_result = ScanResult(
        target=target,
        profile=data.get("profile", "unknown"),
        simulate=data.get("simulate", False),
        scan_id=data.get("scan_id", ""),
        start_time=data.get("start_time", ""),
        end_time=data.get("end_time", ""),
    )

    for mr_data in data.get("module_results", []):
        mr = ModuleResult(
            technique_id=mr_data["technique_id"],
            technique_name=mr_data["technique_name"],
            tactic=mr_data["tactic"],
            status=ModuleStatus(mr_data.get("status", "success")),
            start_time=mr_data.get("start_time", ""),
            end_time=mr_data.get("end_time", ""),
            target_host=mr_data.get("target_host", ""),
            was_simulated=mr_data.get("was_simulated", False),
        )
        for f_data in mr_data.get("findings", []):
            finding = Finding(
                technique_id=f_data["technique_id"],
                technique_name=f_data["technique_name"],
                tactic=f_data["tactic"],
                severity=Severity(f_data["severity"]),
                description=f_data["description"],
                evidence=f_data.get("evidence", ""),
                recommendation=f_data.get("recommendation", ""),
                cwe=f_data.get("cwe", ""),
                timestamp=f_data.get("timestamp", ""),
                finding_id=f_data.get("finding_id", ""),
            )
            mr.add_finding(finding)
        scan_result.add_module_result(mr)

    reporter = Reporter()

    match output_format.lower():
        case "html":
            path = reporter.generate_html(scan_result, output)
            console.print(f"HTML report: [green]{path}[/green]")
        case "json":
            path = reporter.generate_json(scan_result, output)
            console.print(f"JSON report: [green]{path}[/green]")
        case "csv":
            path = reporter.generate_csv(scan_result, output)
            console.print(f"CSV report:  [green]{path}[/green]")
        case "attack-layer":
            mapper = MitreMapper()
            path = mapper.generate_layer(scan_result, output)
            console.print(f"ATT&CK layer: [green]{path}[/green]")


if __name__ == "__main__":
    cli()
