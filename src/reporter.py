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

logger = logging.getLogger(__name__)


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
