"""Main log analysis engine - orchestrates parsing, detection, and reporting."""

from __future__ import annotations

import glob
import logging
import os
import time
from pathlib import Path
from typing import Callable, Optional

from src.detector import ThreatDetector, ThreatEvent
from src.parsers import get_parser
from src.reporter import ReportData, Reporter

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Main log analysis orchestrator."""

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}
        self.detector = ThreatDetector(config)
        self.reporter = Reporter(config)
        self._running = False

    def analyze_file(
        self, filepath: str, log_format: str = "nginx",
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    ) -> ReportData:
        """Analyze a single log file."""
        report = ReportData()
        parser = get_parser(log_format)
        logger.info(f"Analyzing file: {filepath} (format: {log_format})")

        for entry in parser.parse_file(filepath):
            report.total_lines_processed += 1
            for threat in self.detector.analyze(entry):
                report.add_threat(threat)
                if on_threat:
                    on_threat(threat)

        report.source_file = filepath
        logger.info(f"Analysis complete: {report.total_lines_processed} lines, {len(report.threats)} threats")
        return report

    def analyze_directory(
        self, dirpath: str, pattern: str = "*.log",
        log_format: str = "nginx",
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    ) -> ReportData:
        """Analyze all matching log files in a directory."""
        combined = ReportData()
        files = sorted(glob.glob(os.path.join(dirpath, pattern)))
        if not files:
            logger.warning(f"No files matching '{pattern}' in {dirpath}")
            return combined

        logger.info(f"Analyzing {len(files)} files in {dirpath}")
        for fp in files:
            try:
                r = self.analyze_file(fp, log_format, on_threat)
                combined.total_lines_processed += r.total_lines_processed
                combined.threats.extend(r.threats)
            except Exception as e:
                logger.error(f"Error processing {fp}: {e}")
        combined.source_file = dirpath
        return combined

    def watch_file(
        self, filepath: str, log_format: str = "nginx",
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
        poll_interval: float = 1.0,
    ) -> None:
        """Watch a log file in real-time (tail -f style).

        Monitors a log file for new lines appended by other processes
        (e.g. nginx, apache, or a log generator script).

        Args:
            filepath: Path to the log file to watch.
            log_format: Log format (nginx, apache, syslog, windows).
            on_threat: Callback function for each detected threat.
            poll_interval: Seconds between file checks (default: 1.0).
        """
        parser = get_parser(log_format)
        if not Path(filepath).exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        self._running = True
        logger.info(f"Watching: {filepath} (Ctrl+C to stop)")

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            # Jump to end of file — only watch NEW lines
            f.seek(0, 2)

            while self._running:
                # CRITICAL: Clear Python's internal EOF cache.
                # Without this, readline() returns "" forever after hitting EOF,
                # even when another process appends new data to the file.
                f.seek(f.tell())

                line = f.readline()
                if line:
                    line = line.strip()
                    if not line:
                        continue
                    entry = parser.parse_line(line)
                    if entry:
                        for threat in self.detector.analyze(entry):
                            if on_threat:
                                on_threat(threat)
                            else:
                                logger.warning(
                                    f"[{threat.severity}] {threat.threat_type}: {threat.description}"
                                )
                else:
                    time.sleep(poll_interval)

    def stop_watching(self) -> None:
        self._running = False

    def generate_report(self, data: ReportData, output_dir: str = "./reports", fmt: str = "both") -> list[str]:
        """Generate reports. fmt: 'json', 'txt', or 'both'."""
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        files = []
        if fmt in ("json", "both"):
            p = os.path.join(output_dir, f"report_{ts}.json")
            self.reporter.generate_json_report(data, p)
            files.append(p)
        if fmt in ("txt", "both"):
            p = os.path.join(output_dir, f"report_{ts}.txt")
            self.reporter.generate_text_report(data, p)
            files.append(p)
        return files
