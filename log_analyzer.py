#!/usr/bin/env python3
"""Log Analyzer AI - CLI Entry Point."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import click
import yaml
from dotenv import load_dotenv

try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    import re as _re

    class _Con:
        def print(self, msg="", **kw):
            print(_re.sub(r'\[/?[^\]]*\]', '', str(msg)))

    class Table:
        def __init__(self, **kw):
            self.title = kw.get("title", "")
            self._rows = []
        def add_column(self, *a, **kw): pass
        def add_row(self, *vals): self._rows.append(vals)
        def __str__(self):
            lines = [f"\n{self.title}", "-" * 40]
            for r in self._rows:
                clean = [_re.sub(r'\[/?[^\]]*\]', '', str(v)) for v in r]
                lines.append("  ".join(f"{c:30s}" for c in clean))
            return "\n".join(lines)

    console = _Con()

from src.analyzer import LogAnalyzer
from src.detector import ThreatEvent
from src.reporter import ReportData

load_dotenv()
logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("log-analyzer")


def load_config(path: str = "config.yaml") -> dict:
    for p in [path, "config.example.yaml"]:
        if Path(p).exists():
            if p != path:
                console.print(f"[yellow]config.yaml not found, using {p}[/yellow]")
            with open(p, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            return _resolve(cfg)
    return {}


def _resolve(obj):
    if isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
        return os.environ.get(obj[2:-1], obj)
    if isinstance(obj, dict):
        return {k: _resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(i) for i in obj]
    return obj


def _threat_cb(threat: ThreatEvent) -> None:
    colors = {"CRITICAL": "bold red", "HIGH": "bold yellow", "MEDIUM": "bold cyan", "LOW": "bold green"}
    c = colors.get(threat.severity, "white")
    console.print(f"  [{c}][{threat.severity}][/{c}] {threat.threat_type} | {threat.source_ip} | {threat.description}")


@click.group()
@click.option("--config", "-c", default="config.yaml", help="Config file path")
@click.pass_context
def cli(ctx, config):
    """Log Analyzer AI - Intelligent Log Analysis & Threat Detection."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)


@cli.command()
@click.option("--file", "-f", "filepath", help="Log file to analyze")
@click.option("--directory", "-d", "dirpath", help="Directory of log files")
@click.option("--pattern", "-p", default="*.log", help="File pattern for directory mode")
@click.option("--format", "-F", "log_format", default="nginx", help="Log format (nginx/apache/syslog/windows)")
@click.option("--output", "-o", default="./reports", help="Report output directory")
@click.option("--report-format", "-r", default="both", type=click.Choice(["json", "txt", "both"]))
@click.pass_context
def analyze(ctx, filepath, dirpath, pattern, log_format, output, report_format):
    """Analyze log files for security threats."""
    config = ctx.obj["config"]
    analyzer = LogAnalyzer(config)

    console.print("\n[bold cyan]🛡️  Log Analyzer AI[/bold cyan]")
    console.print("─" * 50 + "\n")

    if filepath:
        console.print(f"[bold]File:[/bold] {filepath}")
        console.print(f"[bold]Format:[/bold] {log_format}")
        wl = config.get("whitelist", {}).get("ips", [])
        if wl:
            console.print(f"[bold]Whitelist:[/bold] {', '.join(str(i) for i in wl)}")
        console.print()
        try:
            report = analyzer.analyze_file(filepath, log_format, on_threat=_threat_cb)
        except FileNotFoundError:
            console.print(f"[red]File not found: {filepath}[/red]")
            sys.exit(1)
    elif dirpath:
        console.print(f"[bold]Directory:[/bold] {dirpath}  [bold]Pattern:[/bold] {pattern}\n")
        report = analyzer.analyze_directory(dirpath, pattern, log_format, on_threat=_threat_cb)
    else:
        console.print("[red]Specify --file or --directory[/red]")
        sys.exit(1)

    # Summary
    console.print(f"\n{'─' * 50}")
    s = report.summary()
    table = Table(title="Analysis Summary", show_header=False, border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Lines Processed", str(s["total_lines_processed"]))
    table.add_row("Threats Detected", f"[bold red]{s['total_threats']}[/bold red]")
    table.add_row("Unique Attacker IPs", str(s["unique_attacker_ips"]))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = s["severity_breakdown"].get(sev, 0)
        if c:
            table.add_row(f"  {sev}", str(c))
    if HAS_RICH:
        console.print(table)
    else:
        print(str(table))

    if report.threats:
        files = analyzer.generate_report(report, output, report_format)
        console.print("\n[green]Reports:[/green]")
        for f in files:
            console.print(f"  📄 {f}")
    console.print()


@cli.command()
@click.option("--file", "-f", "filepath", required=True, help="Log file to watch")
@click.option("--format", "-F", "log_format", default="nginx")
@click.pass_context
def watch(ctx, filepath, log_format):
    """Watch a log file in real-time."""
    analyzer = LogAnalyzer(ctx.obj["config"])
    console.print(f"\n[bold cyan]🛡️  Watching:[/bold cyan] {filepath}\n[dim]Ctrl+C to stop[/dim]\n")
    try:
        analyzer.watch_file(filepath, log_format, on_threat=_threat_cb)
    except FileNotFoundError:
        console.print(f"[red]File not found: {filepath}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")


@cli.command()
@click.option("--port", "-p", default=8080)
@click.option("--host", "-h", "host", default="0.0.0.0")
@click.option("--file", "-f", "filepath", default=None, help="Pre-analyze a log file")
@click.option("--format", "-F", "log_format", default="nginx")
@click.pass_context
def dashboard(ctx, port, host, filepath, log_format):
    """Launch the web dashboard."""
    from dashboard.app import init_dashboard, run_dashboard
    analyzer = LogAnalyzer(ctx.obj["config"])
    report = None
    if filepath:
        console.print(f"[bold]Pre-analyzing:[/bold] {filepath}")
        report = analyzer.analyze_file(filepath, log_format, on_threat=_threat_cb)
    init_dashboard(analyzer, report)
    console.print(f"\n[bold cyan]🛡️  Dashboard: http://{host}:{port}[/bold cyan]\n")
    try:
        run_dashboard(host=host, port=port)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")


@cli.command(name="ai-analyze")
@click.option("--file", "-f", "filepath", required=True, help="Log file to analyze with AI")
@click.option("--format", "-F", "log_format", default="nginx")
@click.option("--lines", "-n", default=20, help="Number of log lines to send to AI")
@click.pass_context
def ai_analyze(ctx, filepath, log_format, lines):
    """Analyze log entries using AI (OpenAI)."""
    from models.classifier import AIClassifier

    config = ctx.obj["config"]
    ai_config = config.get("ai", {})
    classifier = AIClassifier(ai_config)

    if not classifier.is_available:
        console.print("[red]AI not available. Check your API key in .env[/red]")
        console.print("[dim]Set OPENAI_API_KEY in .env file[/dim]")
        sys.exit(1)

    console.print(f"\n[bold cyan]🤖 AI Analysis[/bold cyan]")
    console.print(f"[bold]File:[/bold] {filepath}")
    console.print(f"[bold]Provider:[/bold] {classifier.provider} ({classifier.model_name})\n")

    # Read log lines
    from src.parsers import get_parser
    parser = get_parser(log_format)
    raw_lines = []
    try:
        for entry in parser.parse_file(filepath):
            raw_lines.append(entry.raw)
            if len(raw_lines) >= lines:
                break
    except FileNotFoundError:
        console.print(f"[red]File not found: {filepath}[/red]")
        sys.exit(1)

    if not raw_lines:
        console.print("[yellow]No parseable log lines found[/yellow]")
        sys.exit(1)

    console.print(f"Sending {len(raw_lines)} lines to AI for analysis...")

    # Batch analysis
    result = classifier.classify_batch(raw_lines)
    if result:
        console.print("\n[bold green]AI Assessment:[/bold green]")
        console.print(f"  Risk Level: [bold]{result.get('risk_level', 'N/A')}[/bold]")
        console.print(f"  Threats Found: {result.get('threat_count', 'N/A')}")
        console.print(f"  Summary: {result.get('summary', 'N/A')}")
        recs = result.get("recommendations", [])
        if recs:
            console.print("\n[bold]Recommendations:[/bold]")
            for r in recs:
                console.print(f"  • {r}")
    else:
        console.print("[red]AI analysis failed. Check API key and network.[/red]")

    # Single-line classification demo
    console.print(f"\n[bold]Sample single-line classifications:[/bold]")
    for line in raw_lines[:5]:
        result = classifier.classify(line)
        if result:
            is_threat = result.get("is_threat", False)
            icon = "🔴" if is_threat else "🟢"
            console.print(f"  {icon} {result.get('threat_type', 'N/A')} | {result.get('severity', 'N/A')} | {result.get('reason', '')[:80]}")
    console.print()


@cli.command(name="soc-analyze")
@click.option("--file", "-f", "filepath", required=True, help="Log file to analyze")
@click.option("--format", "-F", "log_format", default="nginx", help="Log format")
@click.option("--lines", "-n", default=100, help="Max log lines to send to AI")
@click.pass_context
def soc_analyze(ctx, filepath, log_format, lines):
    """SOC-style correlated threat analysis using AI.

    Unlike ai-analyze which classifies lines individually, this command
    acts as a senior SOC analyst: correlates events, groups attack campaigns,
    and reduces alert noise. 300 sqlmap lines become 1 incident.
    """
    from models.classifier import AIClassifier

    config = ctx.obj["config"]
    ai_config = config.get("ai", {})
    classifier = AIClassifier(ai_config)

    if not classifier.is_available:
        console.print("[red]AI not available. Check your API key in .env[/red]")
        console.print("[dim]Set OPENAI_API_KEY in .env file[/dim]")
        sys.exit(1)

    console.print(f"\n[bold cyan]🔍 SOC Analyst — Correlated Threat Analysis[/bold cyan]")
    console.print("─" * 55)
    console.print(f"  [bold]File    :[/bold] {filepath}")
    console.print(f"  [bold]Provider:[/bold] {classifier.provider} ({classifier.model_name})")
    console.print(f"  [bold]Max Lines:[/bold] {lines}")
    console.print("─" * 55)

    # Read & parse log lines
    from src.parsers import get_parser
    parser = get_parser(log_format)
    raw_lines = []
    try:
        for entry in parser.parse_file(filepath):
            raw_lines.append(entry.raw)
            if len(raw_lines) >= lines:
                break
    except FileNotFoundError:
        console.print(f"[red]File not found: {filepath}[/red]")
        sys.exit(1)

    if not raw_lines:
        console.print("[yellow]No parseable log lines found[/yellow]")
        sys.exit(1)

    console.print(f"\n  Sending {len(raw_lines)} lines to SOC AI analyst...\n")

    # Run SOC analysis
    result = classifier.soc_analyze(raw_lines, max_lines=lines)

    if not result:
        console.print("[red]SOC analysis failed. Try: python log_analyzer.py test-ai[/red]")
        sys.exit(1)

    # ── Risk Level Header ─────────────────────────────────────────
    risk = result.get("risk_level", "UNKNOWN")
    risk_colors = {"CRITICAL": "bold red", "HIGH": "bold yellow", "MEDIUM": "bold cyan", "LOW": "bold green"}
    rc = risk_colors.get(risk, "white")
    console.print(f"  [{rc}]╔══════════════════════════════════════════╗[/{rc}]")
    console.print(f"  [{rc}]║  RISK LEVEL: {risk:^28s} ║[/{rc}]")
    console.print(f"  [{rc}]╚══════════════════════════════════════════╝[/{rc}]")

    # ── Summary ───────────────────────────────────────────────────
    console.print(f"\n  [bold]Incident Count:[/bold] {result.get('incident_count', 'N/A')}")
    console.print(f"  [bold]Summary:[/bold] {result.get('summary', 'N/A')}")

    # ── Noise Reduction ───────────────────────────────────────────
    noise = result.get("noise_reduction", {})
    if noise:
        console.print(f"\n  [bold]📉 Noise Reduction:[/bold]")
        console.print(f"     Total Log Lines    : {noise.get('total_logs', len(raw_lines))}")
        console.print(f"     Distinct Incidents  : {noise.get('distinct_incidents', result.get('incident_count', '?'))}")
        console.print(f"     Reduction Ratio     : {noise.get('reduction_ratio', 'N/A')}")

    # ── Findings Table ────────────────────────────────────────────
    findings = result.get("findings", [])
    if findings:
        console.print(f"\n  [bold]🎯 Findings ({len(findings)} campaigns):[/bold]\n")
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "?")
            sc = risk_colors.get(sev, "white")
            console.print(f"    [{sc}][{sev}][/{sc}] Campaign #{i}")
            console.print(f"      IP          : {f.get('ip', '?')}")
            console.print(f"      Attack Type : {f.get('attack_type', '?')}")
            console.print(f"      Attempts    : {f.get('attempts', '?')}")
            console.print(f"      Tool        : {f.get('tool', '?')}")
            detail = f.get("detail", "")
            if detail:
                console.print(f"      Detail      : {detail}")
            console.print()

    # ── Recommendations ───────────────────────────────────────────
    recs = result.get("recommendations", [])
    if recs:
        console.print(f"  [bold]🛡️ Recommendations:[/bold]")
        for r in recs:
            console.print(f"    • {r}")

    console.print(f"\n{'─' * 55}\n")


@cli.command(name="test-ai")
@click.pass_context
def test_ai(ctx):
    """Test AI connection and show diagnostics."""
    from models.classifier import AIClassifier

    config = ctx.obj["config"]
    ai_config = config.get("ai", {})
    console.print(f"\n[bold cyan]🤖 AI Connection Test[/bold cyan]\n")

    classifier = AIClassifier(ai_config)
    result = classifier.test_connection()

    console.print(f"  Provider   : {result['provider']}")
    console.print(f"  Model      : {result['model']}")
    console.print(f"  API Key    : {result['api_key_preview']}")

    if result["success"]:
        console.print(f"\n  [bold green]✅ CONNECTION SUCCESSFUL[/bold green]")
        resp = result.get("response", {})
        console.print(f"  Test result: is_threat={resp.get('is_threat')}, type={resp.get('threat_type')}")
    else:
        console.print(f"\n  [bold red]❌ CONNECTION FAILED[/bold red]")
        console.print(f"  Error: {result['error']}")
        console.print(f"\n  [dim]Troubleshooting:[/dim]")
        console.print(f"  1. Check .env file has correct API key")
        console.print(f"  2. Run: pip install openai")
        console.print(f"  3. Verify API key at https://platform.openai.com/api-keys")
    console.print()


@cli.command()
@click.option("--file", "-f", "filepath", required=True, help="Clean traffic log for training")
@click.option("--format", "-F", "log_format", default="nginx")
@click.option("--output", "-o", default="./models/trained_model.pkl")
@click.pass_context
def train(ctx, filepath, log_format, output):
    """Train the anomaly detection model."""
    from src.parsers import get_parser
    from models.anomaly_detector import AnomalyDetector

    console.print(f"\n[bold cyan]🛡️  Training Model[/bold cyan]\n")
    entries = list(get_parser(log_format).parse_file(filepath))
    console.print(f"Loaded {len(entries)} entries")

    det = AnomalyDetector()
    result = det.train(entries)
    if result["status"] == "success":
        os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
        det.save_model(output)
        console.print(f"[green]Model saved: {output}[/green]")
    else:
        console.print(f"[red]Failed: {result['message']}[/red]")


if __name__ == "__main__":
    cli()
