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
    type=click.Choice(["html", "json", "csv", "compliance"], case_sensitive=False),
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
                case "compliance":
                    path = reporter.generate_compliance(
                        scan_result,
                        f"{output}_compliance.json" if output else None,
                    )
                    console.print(f"  Compliance:  [green]{path}[/green]")

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
@click.option(
    "--source", "-s",
    default="all",
    type=click.Choice(["all", "python", "atomic"], case_sensitive=False),
    help="Filter by module source (python, atomic, or all).",
)
def list_modules(source: str) -> None:
    """List all discovered technique modules and atomic tests."""
    setup_logging(verbose=False)

    engine = ScanEngine()

    # Python modules table
    if source in ("all", "python"):
        py_table = Table(
            title="Python Technique Modules (check + simulate)",
            show_header=True,
            header_style="bold cyan",
        )
        py_table.add_column("Technique ID", style="bold")
        py_table.add_column("Name")
        py_table.add_column("Tactic")
        py_table.add_column("Severity")
        py_table.add_column("Admin?")
        py_table.add_column("OS Support")

        for mod in engine.discovered_modules:
            sev = mod["severity"]
            sev_style = {
                "CRITICAL": "red",
                "HIGH": "dark_orange",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "dim",
            }.get(sev, "white")

            py_table.add_row(
                mod["technique_id"],
                mod["technique_name"],
                mod["tactic"],
                f"[{sev_style}]{sev}[/{sev_style}]",
                "Yes" if mod["requires_admin"] else "No",
                ", ".join(mod["supported_os"]),
            )

        console.print(py_table)
        console.print(f"  Python modules: {len(engine.discovered_modules)}")

    # Atomic YAML tests table
    if source in ("all", "atomic"):
        at_table = Table(
            title="\nAtomic YAML Tests (simulate mode)",
            show_header=True,
            header_style="bold magenta",
        )
        at_table.add_column("Technique ID", style="bold")
        at_table.add_column("Name")
        at_table.add_column("Tactic")
        at_table.add_column("Tests", justify="right")
        at_table.add_column("Admin?")
        at_table.add_column("Has Python?")

        atomics = engine.discovered_atomics
        for at in atomics:
            at_table.add_row(
                at["technique_id"],
                at["display_name"],
                at["tactic"],
                str(at["windows_tests"]),
                "Yes" if at["elevation_required"] else "No",
                "[green]Yes[/green]" if at["technique_id"] in {
                    m["technique_id"] for m in engine.discovered_modules
                } else "[dim]No[/dim]",
            )

        console.print(at_table)
        console.print(f"  Atomic techniques: {len(atomics)}")
        total_tests = sum(at["windows_tests"] for at in atomics)
        console.print(f"  Total atomic tests: {total_tests}")

    # Summary
    if source == "all":
        py_ids = {m["technique_id"] for m in engine.discovered_modules}
        at_ids = {at["technique_id"] for at in engine.discovered_atomics}
        all_ids = py_ids | at_ids
        console.print(
            f"\n[bold]Total unique techniques: {len(all_ids)}[/bold] "
            f"({len(py_ids)} Python + {len(at_ids)} atomic, "
            f"{len(py_ids & at_ids)} overlap)"
        )


@cli.command("run-atomic")
@click.option(
    "--target", "-t",
    required=True,
    help="Target host (IP, hostname, or 'localhost').",
)
@click.option(
    "--technique",
    required=True,
    help="MITRE ATT&CK technique ID (e.g. T1082).",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output report filename.",
)
@click.option(
    "--format", "-f", "output_format",
    multiple=True,
    type=click.Choice(["html", "json", "csv"], case_sensitive=False),
    help="Report format(s).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
def run_atomic(
    target: str,
    technique: str,
    output: str | None,
    output_format: tuple[str, ...],
    verbose: bool,
) -> None:
    """Run atomic YAML tests for a specific technique."""
    from core.atomic_runner import AtomicRunner
    from core.models import ConnectionMethod, Severity, Target as TargetModel

    setup_logging(verbose=verbose)

    # Authorization
    console.print(ScanEngine.AUTHORIZATION_BANNER, style="bold yellow")
    if not click.confirm("Do you have authorization to test this target?"):
        console.print("[yellow]Aborted.[/yellow]")
        sys.exit(0)

    # Setup target
    if target in ("localhost", "127.0.0.1", "::1"):
        tgt = TargetModel(host=target, connection=ConnectionMethod.LOCAL)
    else:
        tgt = TargetModel(host=target, connection=ConnectionMethod.WINRM)

    runner = AtomicRunner()
    tech = runner.get_technique(technique)
    if not tech:
        console.print(f"[red]Technique {technique} not found in atomics/[/red]")
        sys.exit(1)

    tests = tech.windows_tests
    console.print(
        f"\n[bold cyan]Running {len(tests)} atomic test(s) for "
        f"{technique} — {tech.display_name}[/bold cyan]"
    )

    from core.session import create_session

    session = create_session(tgt)
    session.connect()

    try:
        results = runner.run_technique(technique, session)

        # Print results
        for result in results:
            status_style = "green" if result.status.value == "success" else "red"
            console.print(
                f"  [{status_style}]{result.status.value.upper()}[/{status_style}] "
                f"{result.technique_name}"
            )
            for finding in result.findings:
                sev = finding.severity.value
                sev_style = {
                    "CRITICAL": "red", "HIGH": "dark_orange",
                    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
                }.get(sev, "white")
                console.print(
                    f"    [{sev_style}]{sev}[/{sev_style}] {finding.description}"
                )

        total = sum(len(r.findings) for r in results)
        console.print(f"\n  Total findings: {total}")

        # Generate reports
        if output_format:
            from core.models import ScanResult

            scan_result = ScanResult(target=tgt, profile="atomic", simulate=True)
            for r in results:
                scan_result.add_module_result(r)
            scan_result.complete()

            reporter = Reporter()
            for fmt in output_format:
                match fmt.lower():
                    case "json":
                        path = reporter.generate_json(
                            scan_result, f"{output}.json" if output else None
                        )
                        console.print(f"  JSON: [green]{path}[/green]")
                    case "html":
                        path = reporter.generate_html(
                            scan_result, f"{output}.html" if output else None
                        )
                        console.print(f"  HTML: [green]{path}[/green]")
                    case "csv":
                        path = reporter.generate_csv(
                            scan_result, f"{output}.csv" if output else None
                        )
                        console.print(f"  CSV:  [green]{path}[/green]")
    finally:
        session.disconnect()


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
    type=click.Choice(["html", "json", "csv", "attack-layer", "compliance"], case_sensitive=False),
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
        case "compliance":
            from core.compliance_mapper import ComplianceMapper
            cm = ComplianceMapper()
            path = cm.generate_compliance_report(scan_result, output)
            console.print(f"Compliance:   [green]{path}[/green]")


if __name__ == "__main__":
    cli()
