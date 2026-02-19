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

logger = logging.getLogger(__name__)


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
