#!/usr/bin/env python3
"""
🛡️ Log Analyzer AI - CLI Entry Point
AI-Powered Log Analysis & Automated Threat Response System

Kullanım:
  python log_analyzer.py analyze --file /var/log/nginx/access.log
  python log_analyzer.py watch   --file /var/log/nginx/access.log --auto-block
  python log_analyzer.py dashboard --port 8080
"""
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Proje kök dizinini Python yoluna ekle
sys.path.insert(0, str(Path(__file__).parent))

from src.analyzer import LogAnalyzer
from src.detector import ThreatEvent, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW
from src.reporter import ReportData

console = Console()

SEVERITY_STYLES = {
    SEVERITY_CRITICAL: "bold red",
    SEVERITY_HIGH:     "bold orange1",
    SEVERITY_MEDIUM:   "bold yellow",
    SEVERITY_LOW:      "bold cyan",
}

SEVERITY_EMOJI = {
    SEVERITY_CRITICAL: "🔴",
    SEVERITY_HIGH:     "🟠",
    SEVERITY_MEDIUM:   "🟡",
    SEVERITY_LOW:      "🔵",
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _load_config(config_path: str) -> dict:
    """YAML konfigürasyon dosyasını yükler."""
    path = Path(config_path)
    if not path.exists():
        console.print(f"[yellow]⚠️  Konfigürasyon dosyası bulunamadı: {config_path}[/yellow]")
        console.print("[dim]Varsayılan ayarlar kullanılıyor.[/dim]")
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _print_banner() -> None:
    """Uygulama banner'ını yazdırır."""
    banner = Text()
    banner.append("  🛡️  LOG ANALYZER AI", style="bold blue")
    banner.append("  |  ", style="dim")
    banner.append("AI-Powered Security Log Analysis", style="dim")
    console.print(Panel(banner, border_style="blue"))


def _format_threat_table(threats: list[ThreatEvent]) -> Table:
    """Tehdit listesinden Rich table oluşturur."""
    table = Table(show_header=True, header_style="bold dim", expand=True)
    table.add_column("Zaman", style="dim", width=19)
    table.add_column("Seviye", width=10)
    table.add_column("Tür", width=16)
    table.add_column("Kaynak IP", style="cyan", width=18)
    table.add_column("Hedef", style="white")
    table.add_column("Açıklama")

    for threat in threats[-50:]:
        sev_style = SEVERITY_STYLES.get(threat.severity, "white")
        emoji = SEVERITY_EMOJI.get(threat.severity, "⚪")
        table.add_row(
            threat.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            f"[{sev_style}]{emoji} {threat.severity}[/{sev_style}]",
            threat.threat_type,
            threat.source_ip,
            (threat.target or "-")[:40],
            threat.description[:60],
        )
    return table


# ─────────────────────────────────────────────────────────────────────────────
# CLI Komutları
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
@click.option("--config", "-c", default="config.yaml", help="Konfigürasyon dosyası", show_default=True)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Ayrıntılı log çıktısı")
@click.pass_context
def cli(ctx: click.Context, config: str, verbose: bool) -> None:
    """🛡️ Log Analyzer AI - AI destekli log analiz ve tehdit müdahale sistemi."""
    ctx.ensure_object(dict)
    _setup_logging(verbose)
    ctx.obj["config"] = _load_config(config)


@cli.command("analyze")
@click.option("--file", "-f", "filepath", default=None, help="Analiz edilecek log dosyası")
@click.option("--dir", "-d", "directory", default=None, help="Analiz edilecek dizin")
@click.option("--pattern", "-p", default="*.log", help="Dosya glob deseni", show_default=True)
@click.option("--format", "log_format", default="nginx", help="Log formatı (nginx/apache/syslog)", show_default=True)
@click.option("--report-only", is_flag=True, default=False, help="Sadece rapor üret, bloklama yapma")
@click.option("--output", "-o", default="both", type=click.Choice(["json", "text", "both"]), help="Rapor formatı")
@click.pass_context
def cmd_analyze(
    ctx: click.Context,
    filepath: Optional[str],
    directory: Optional[str],
    pattern: str,
    log_format: str,
    report_only: bool,
    output: str,
) -> None:
    """Log dosyası veya dizinini analiz eder."""
    _print_banner()
    config = dict(ctx.obj["config"])

    if report_only:
        config.setdefault("response", {})
        config["response"].setdefault("auto_block", {})
        config["response"]["auto_block"]["enabled"] = False

    analyzer = LogAnalyzer(config)
    collected_threats: list[ThreatEvent] = []

    def on_threat(t: ThreatEvent) -> None:
        collected_threats.append(t)
        sev_style = SEVERITY_STYLES.get(t.severity, "white")
        emoji = SEVERITY_EMOJI.get(t.severity, "⚪")
        console.print(
            f"[{sev_style}]{emoji} [{t.severity}][/{sev_style}] "
            f"[cyan]{t.source_ip}[/cyan] → [white]{t.threat_type}[/white] "
            f"[dim]{t.target or ''}[/dim]"
        )

    try:
        if filepath:
            if not Path(filepath).exists():
                console.print(f"[red]❌ Dosya bulunamadı: {filepath}[/red]")
                sys.exit(1)
            console.print(f"📁 Analiz ediliyor: [cyan]{filepath}[/cyan]")
            data = analyzer.analyze_file(filepath, log_format=log_format, on_threat=on_threat)
        elif directory:
            if not Path(directory).exists():
                console.print(f"[red]❌ Dizin bulunamadı: {directory}[/red]")
                sys.exit(1)
            console.print(f"📂 Dizin analiz ediliyor: [cyan]{directory}[/cyan] ({pattern})")
            data = analyzer.analyze_directory(
                directory, pattern=pattern, log_format=log_format, on_threat=on_threat
            )
        else:
            console.print("[red]❌ --file veya --dir belirtilmeli.[/red]")
            sys.exit(1)

        # Sonuç özeti
        summary = data.summary()
        totals = summary.get("totals", {})
        console.print()
        console.print(Panel(
            f"[bold]İşlenen:[/bold] {totals.get('lines_processed', 0):,} satır  |  "
            f"[bold red]Tehdit:[/bold red] {totals.get('threats_detected', 0):,}  |  "
            f"[bold yellow]Bloklu IP:[/bold yellow] {totals.get('ips_blocked', 0):,}",
            title="[bold]📊 Analiz Sonucu[/bold]",
            border_style="blue",
        ))

        if collected_threats:
            console.print(_format_threat_table(collected_threats))

        # Rapor oluştur
        analyzer.generate_report(data, fmt=output)
        console.print(f"\n[green]✅ Rapor kaydedildi: [/green]{analyzer.reporter.output_dir}/")

    except Exception as e:
        console.print(f"[red]❌ Hata: {e}[/red]")
        if ctx.obj.get("verbose"):
            raise
        sys.exit(1)


@cli.command("watch")
@click.option("--file", "-f", "filepath", required=True, help="İzlenecek log dosyası")
@click.option("--format", "log_format", default="nginx", help="Log formatı", show_default=True)
@click.option("--auto-block", is_flag=True, default=False, help="Otomatik IP bloklama (root gerekli)")
@click.option("--interval", default=1.0, type=float, help="Dosya kontrol aralığı (saniye)", show_default=True)
@click.pass_context
def cmd_watch(
    ctx: click.Context,
    filepath: str,
    log_format: str,
    auto_block: bool,
    interval: float,
) -> None:
    """Log dosyasını gerçek zamanlı izler. Ctrl+C ile durdurulur."""
    _print_banner()
    config = dict(ctx.obj["config"])

    if auto_block:
        config.setdefault("response", {})
        config["response"].setdefault("auto_block", {})
        config["response"]["auto_block"]["enabled"] = True
        console.print("[yellow]⚠️  Otomatik IP bloklama AKTİF (root yetkisi gerekli)[/yellow]")

    if not Path(filepath).exists():
        console.print(f"[red]❌ Dosya bulunamadı: {filepath}[/red]")
        sys.exit(1)

    analyzer = LogAnalyzer(config)
    stats = {"threats": 0, "blocked": 0, "lines": 0}
    start_time = datetime.now()

    console.print(f"👁️  İzleniyor: [cyan]{filepath}[/cyan]")
    console.print("[dim]Ctrl+C ile durdurulur...[/dim]\n")

    def on_threat(t: ThreatEvent) -> None:
        stats["threats"] += 1
        sev_style = SEVERITY_STYLES.get(t.severity, "white")
        emoji = SEVERITY_EMOJI.get(t.severity, "⚪")
        ts_str = t.timestamp.strftime("%H:%M:%S")
        console.print(
            f"[dim]{ts_str}[/dim] [{sev_style}]{emoji} {t.severity}[/{sev_style}] "
            f"[bold]{t.threat_type}[/bold]  "
            f"[cyan]{t.source_ip}[/cyan] → [white]{(t.target or '-')[:50]}[/white]\n"
            f"[dim]    {t.description}[/dim]"
        )

    try:
        analyzer.watch_file(
            filepath,
            log_format=log_format,
            on_threat=on_threat,
            poll_interval=interval,
        )
    except FileNotFoundError as e:
        console.print(f"[red]❌ {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]⏹️  İzleme durduruldu.[/yellow]")


@cli.command("dashboard")
@click.option("--port", default=8080, type=int, help="Dinlenecek port", show_default=True)
@click.option("--host", default="0.0.0.0", help="Bind adresi", show_default=True)
@click.option("--file", "-f", "filepath", default=None, help="Arka planda izlenecek log dosyası")
@click.option("--format", "log_format", default="nginx", help="Log formatı", show_default=True)
@click.pass_context
def cmd_dashboard(
    ctx: click.Context,
    port: int,
    host: str,
    filepath: Optional[str],
    log_format: str,
) -> None:
    """Web dashboard'u başlatır."""
    _print_banner()
    config = ctx.obj["config"]

    try:
        from dashboard.app import create_app, push_threat
    except ImportError as e:
        console.print(f"[red]❌ Dashboard bağımlılığı eksik: {e}[/red]")
        console.print("[dim]pip install flask flask-socketio eventlet[/dim]")
        sys.exit(1)

    app = create_app(config)
    analyzer = LogAnalyzer(config)

    def on_threat(t: ThreatEvent) -> None:
        push_threat(app, t.to_dict())

    # Arka planda log izleme
    if filepath and Path(filepath).exists():
        import threading
        watcher = threading.Thread(
            target=analyzer.watch_file,
            kwargs={"filepath": filepath, "log_format": log_format, "on_threat": on_threat},
            daemon=True,
            name="log-watcher",
        )
        watcher.start()
        console.print(f"👁️  Arka planda izleniyor: [cyan]{filepath}[/cyan]")

    console.print(f"🌐 Dashboard başlatılıyor: [cyan]http://{host}:{port}[/cyan]")
    console.print("[dim]Ctrl+C ile durdurulur[/dim]\n")

    try:
        if app.socketio:
            app.socketio.run(app, host=host, port=port)
        else:
            app.run(host=host, port=port)
    except KeyboardInterrupt:
        console.print("\n[yellow]⏹️  Dashboard durduruldu.[/yellow]")


@cli.command("train")
@click.option("--file", "-f", "filepath", required=True, help="Eğitim için log dosyası")
@click.option("--format", "log_format", default="nginx", help="Log formatı", show_default=True)
@click.option("--contamination", default=0.05, type=float, help="Beklenen anomali oranı", show_default=True)
@click.pass_context
def cmd_train(
    ctx: click.Context,
    filepath: str,
    log_format: str,
    contamination: float,
) -> None:
    """Anomali tespit modelini eğitir ve kaydeder."""
    _print_banner()

    try:
        from models.anomaly_detector import AnomalyDetector
        from src.analyzer import LogAnalyzer
    except ImportError as e:
        console.print(f"[red]❌ {e}[/red]")
        sys.exit(1)

    if not Path(filepath).exists():
        console.print(f"[red]❌ Dosya bulunamadı: {filepath}[/red]")
        sys.exit(1)

    config = ctx.obj["config"]
    analyzer_obj = LogAnalyzer(config)
    parser = analyzer_obj._get_parser(log_format)

    console.print(f"📚 Eğitim verisi yükleniyor: [cyan]{filepath}[/cyan]")
    entries = list(parser.parse_file(filepath))

    if not entries:
        console.print("[red]❌ Parse edilebilir entry bulunamadı.[/red]")
        sys.exit(1)

    console.print(f"✅ {len(entries):,} entry yüklendi. Model eğitiliyor...")
    detector = AnomalyDetector(contamination=contamination)
    detector.fit(entries)
    detector.save()
    console.print("[green]✅ Model başarıyla eğitildi ve kaydedildi.[/green]")


if __name__ == "__main__":
    cli(obj={})
