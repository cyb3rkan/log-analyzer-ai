<<<<<<< HEAD
"""Report generation module for JSON and text reports."""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set

from src.detector import ThreatEvent
=======
"""
Reporter - Raporlama Modülü
Günlük/haftalık raporlar ve özet istatistikler üretir.
"""
import json
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .detector import ThreatEvent
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0

logger = logging.getLogger(__name__)


<<<<<<< HEAD
@dataclass
class ReportData:
    """Container for analysis results."""
    total_lines_processed: int = 0
    threats: List[ThreatEvent] = field(default_factory=list)
    blocked_ips: Set[str] = field(default_factory=set)
    source_file: str = ""
    start_time: Optional[datetime] = field(default_factory=datetime.now)

    def add_threat(self, threat: ThreatEvent) -> None:
        self.threats.append(threat)

    def summary(self) -> dict:
        return {
            "total_lines_processed": self.total_lines_processed,
            "total_threats": len(self.threats),
            "blocked_ips_count": len(self.blocked_ips),
            "severity_breakdown": dict(Counter(t.severity for t in self.threats)),
            "threat_type_breakdown": dict(Counter(t.threat_type for t in self.threats)),
            "unique_attacker_ips": len(set(t.source_ip for t in self.threats)),
            "source_file": self.source_file,
        }

    def top_attacker_ips(self, n: int = 10) -> List[tuple]:
        return Counter(t.source_ip for t in self.threats).most_common(n)

    def threats_by_severity(self) -> dict:
        result = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for t in self.threats:
            if t.severity in result:
                result[t.severity].append(t)
        return result


class Reporter:
    """Generates analysis reports in JSON and text formats."""

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}
        self.output_dir = self.config.get("reporting", {}).get("output_dir", "./reports")

    def generate_json_report(self, data: ReportData, filename: str) -> str:
        os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
        report = {
            "meta": {
                "generated_at": datetime.now().isoformat(),
                "source_file": data.source_file,
                "analyzer_version": "1.0.0",
            },
            "summary": data.summary(),
            "top_attacker_ips": [{"ip": ip, "count": c} for ip, c in data.top_attacker_ips()],
            "blocked_ips": list(data.blocked_ips),
            "threats": [t.to_dict() for t in data.threats],
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"JSON report: {filename}")
        return filename

    def generate_text_report(self, data: ReportData, filename: str) -> str:
        os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
        s = data.summary()
        lines = [
            "=" * 70,
            "  LOG ANALYZER AI - SECURITY ANALYSIS REPORT",
            "=" * 70,
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Source: {data.source_file}",
            "=" * 70, "",
            "SUMMARY", "-" * 40,
            f"  Lines Processed  : {s['total_lines_processed']}",
            f"  Threats Detected : {s['total_threats']}",
            f"  Unique Attackers : {s['unique_attacker_ips']}",
            f"  Blocked IPs      : {s['blocked_ips_count']}", "",
            "SEVERITY BREAKDOWN", "-" * 40,
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = s["severity_breakdown"].get(sev, 0)
            lines.append(f"  {sev:10s}: {count:4d} {'#' * min(count, 50)}")
        lines += ["", "THREAT TYPES", "-" * 40]
        for tt, c in sorted(s["threat_type_breakdown"].items()):
            lines.append(f"  {tt:20s}: {c:4d}")
        lines += ["", "TOP ATTACKER IPs", "-" * 40]
        for ip, c in data.top_attacker_ips(10):
            lines.append(f"  {ip:20s}: {c:4d} threats")
        lines += ["", "DETAILED THREATS", "-" * 70]
        for i, t in enumerate(data.threats[:100], 1):  # cap at 100 in text report
            ts = t.timestamp.strftime("%Y-%m-%d %H:%M:%S") if t.timestamp else "N/A"
            lines.append(f"  [{i}] {t.severity} | {t.threat_type} | {t.source_ip} | {ts}")
            lines.append(f"      {t.description}")
            if t.payload:
                lines.append(f"      Payload: {t.payload[:120]}")
            lines.append("")
        if len(data.threats) > 100:
            lines.append(f"  ... and {len(data.threats) - 100} more threats")
        lines += ["=" * 70, "  END OF REPORT", "=" * 70]

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logger.info(f"Text report: {filename}")
        return filename
=======
class ReportData:
    """Rapor için veri toplayan ve özetleyen sınıf."""

    def __init__(self):
        self.threats: list[ThreatEvent] = []
        self.total_lines_processed = 0
        self.total_requests = 0
        self.unique_ips: set[str] = set()
        self.blocked_ips: set[str] = set()
        self.start_time: datetime = datetime.now()
        self.end_time: Optional[datetime] = None

    def add_threat(self, threat: ThreatEvent) -> None:
        self.threats.append(threat)
        self.unique_ips.add(threat.source_ip)

    def add_request(self, ip: str) -> None:
        self.total_requests += 1
        self.unique_ips.add(ip)

    def add_blocked(self, ip: str) -> None:
        self.blocked_ips.add(ip)

    def finalize(self) -> None:
        self.end_time = datetime.now()

    def summary(self) -> dict:
        self.end_time = self.end_time or datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        threat_by_type = Counter(t.threat_type for t in self.threats)
        threat_by_severity = Counter(t.severity for t in self.threats)
        top_ips = Counter(t.source_ip for t in self.threats).most_common(10)

        return {
            "period": {
                "start": self.start_time.isoformat(),
                "end": self.end_time.isoformat(),
                "duration_seconds": duration,
            },
            "totals": {
                "lines_processed": self.total_lines_processed,
                "requests": self.total_requests,
                "unique_ips": len(self.unique_ips),
                "threats_detected": len(self.threats),
                "ips_blocked": len(self.blocked_ips),
            },
            "threats_by_type": dict(threat_by_type),
            "threats_by_severity": dict(threat_by_severity),
            "top_attacker_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        }


class Reporter:
    """
    Tehdit raporları oluşturan ve kaydeden sınıf.
    JSON ve text formatında çıktı üretir.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: config.yaml'dan gelen reporting konfigürasyonu
        """
        self.config = config or {}
        reporting = self.config.get("reporting", {})
        self.output_dir = Path(reporting.get("output_dir", "./reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._daily_enabled = reporting.get("daily", True)
        self._weekly_enabled = reporting.get("weekly", True)

    def generate_json_report(self, data: ReportData, filename: Optional[str] = None) -> Path:
        """
        JSON formatında rapor oluşturur.

        Args:
            data: Rapor verisi
            filename: Çıktı dosya adı (None ise otomatik)

        Returns:
            Oluşturulan dosyanın yolu
        """
        summary = data.summary()

        # Tehdit detaylarını ekle
        summary["threat_details"] = [t.to_dict() for t in data.threats]

        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{ts}.json"

        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)

        logger.info(f"JSON raporu oluşturuldu: {filepath}")
        return filepath

    def generate_text_report(self, data: ReportData, filename: Optional[str] = None) -> Path:
        """
        İnsan okunabilir metin raporu oluşturur.

        Args:
            data: Rapor verisi
            filename: Çıktı dosya adı (None ise otomatik)

        Returns:
            Oluşturulan dosyanın yolu
        """
        summary = data.summary()
        lines = self._build_text_report(summary)

        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{ts}.txt"

        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        logger.info(f"Metin raporu oluşturuldu: {filepath}")
        return filepath

    def _build_text_report(self, summary: dict) -> list[str]:
        """Rapor satırlarını oluşturur."""
        sep = "=" * 70
        thin = "-" * 70
        lines = [
            sep,
            "  🛡️  LOG ANALYZER AI - SECURITY REPORT",
            sep,
        ]

        # Dönem
        period = summary.get("period", {})
        lines += [
            f"  Başlangıç : {period.get('start', 'N/A')}",
            f"  Bitiş     : {period.get('end', 'N/A')}",
            thin,
        ]

        # Genel istatistikler
        totals = summary.get("totals", {})
        lines += [
            "  📊 GENEL İSTATİSTİKLER",
            thin,
            f"  İşlenen satır     : {totals.get('lines_processed', 0):,}",
            f"  Toplam istek      : {totals.get('requests', 0):,}",
            f"  Benzersiz IP      : {totals.get('unique_ips', 0):,}",
            f"  Tespit edilen     : {totals.get('threats_detected', 0):,}",
            f"  Bloklu IP         : {totals.get('ips_blocked', 0):,}",
            thin,
        ]

        # Tehdit türleri
        by_type = summary.get("threats_by_type", {})
        if by_type:
            lines.append("  🔍 TEHDİT TÜRLERİ")
            lines.append(thin)
            for ttype, count in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(f"  {ttype:<30} : {count:,}")
            lines.append(thin)

        # Tehdit seviyeleri
        by_sev = summary.get("threats_by_severity", {})
        if by_sev:
            lines.append("  ⚠️  TEHDİT SEVİYELERİ")
            lines.append(thin)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in by_sev:
                    lines.append(f"  {sev:<30} : {by_sev[sev]:,}")
            lines.append(thin)

        # En çok saldıran IP'ler
        top_ips = summary.get("top_attacker_ips", [])
        if top_ips:
            lines.append("  🏴 EN ÇOK SALDIRAN IP'LER")
            lines.append(thin)
            for i, entry in enumerate(top_ips[:10], 1):
                lines.append(f"  {i:2}. {entry['ip']:<20} : {entry['count']:,} olay")
            lines.append(thin)

        lines += [
            "  Rapor oluşturuldu: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "  Powered by Log Analyzer AI",
            sep,
        ]
        return lines

    def print_live_stats(self, data: ReportData) -> None:
        """Konsola canlı istatistik yazdırır."""
        summary = data.summary()
        totals = summary.get("totals", {})
        print(
            f"\r📊 Satır: {totals.get('lines_processed', 0):,} | "
            f"🚨 Tehdit: {totals.get('threats_detected', 0):,} | "
            f"🔒 Blok: {totals.get('ips_blocked', 0):,}",
            end="",
            flush=True,
        )
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
