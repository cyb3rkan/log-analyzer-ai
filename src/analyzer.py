"""
Analyzer - Ana Analiz Motoru
Log dosyalarını parse eder, tespit eder ve müdahale koordinasyonu yapar.
"""
import logging
import os
import time
from pathlib import Path
from typing import Callable, Iterator, Optional

from .detector import ThreatDetector, ThreatEvent
from .parsers.nginx import LogEntry, NginxParser
from .parsers.apache import ApacheParser
from .parsers.syslog import SyslogParser, SyslogEntry
from .reporter import ReportData, Reporter
from .responder import AutoResponder

logger = logging.getLogger(__name__)


def _iter_log_entries(source: dict) -> Iterator[LogEntry]:
    """
    Konfigürasyondaki bir log kaynağını parse eder.

    Args:
        source: config.yaml'dan bir log_sources elemanı

    Yields:
        LogEntry nesneleri
    """
    path = source.get("path", "")
    fmt = source.get("format", "combined").lower()
    name = source.get("name", "unknown")

    if not os.path.exists(path):
        logger.warning(f"Log dosyası bulunamadı: {path}")
        return

    if name in ("nginx",) or fmt in ("combined", "nginx"):
        parser = NginxParser()
    elif name in ("apache",) or fmt in ("apache",):
        parser = ApacheParser()
    else:
        # Fallback: önce nginx, sonra apache dene
        parser = NginxParser()

    yield from parser.parse_file(path)


class LogAnalyzer:
    """
    Ana log analiz sınıfı.
    Tek dosya analizi, dizin analizi ve gerçek zamanlı izleme destekler.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: config.yaml içeriği (dict olarak yüklenmiş)
        """
        self.config = config or {}
        self.detector = ThreatDetector(self.config)
        self.responder = AutoResponder(self.config)
        self.reporter = Reporter(self.config)
        self._report_data = ReportData()

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def analyze_file(
        self,
        filepath: str,
        *,
        log_format: str = "nginx",
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    ) -> ReportData:
        """
        Tek bir log dosyasını analiz eder.

        Args:
            filepath: Log dosyası yolu
            log_format: "nginx", "apache" veya "syslog"
            on_threat: Her tehdit tespit edildiğinde çağrılacak callback

        Returns:
            Analiz sonuçlarını içeren ReportData
        """
        data = ReportData()
        
        # Dosya kontrolü
        if not os.path.exists(filepath):
            logger.warning(f"Log dosyası bulunamadı: {filepath}")
            data.finalize()
            return data
        
        parser = self._get_parser(log_format)
        entries = parser.parse_file(filepath)

        for entry in entries:
            data.total_lines_processed += 1
            data.add_request(entry.ip)
            threats = self.detector.analyze(entry)
            for threat in threats:
                data.add_threat(threat)
                result = self.responder.respond(threat)
                if result.get("actions_taken"):
                    for ip in [threat.source_ip]:
                        if self.responder.is_blocked(ip):
                            data.add_blocked(ip)
                if on_threat:
                    on_threat(threat)

        data.finalize()
        return data

    def analyze_directory(
        self,
        directory: str,
        *,
        pattern: str = "*.log",
        log_format: str = "nginx",
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    ) -> ReportData:
        """
        Dizindeki tüm log dosyalarını analiz eder.

        Args:
            directory: Log dizini yolu
            pattern: Dosya glob deseni
            log_format: "nginx", "apache" veya "syslog"
            on_threat: Her tehdit tespit edildiğinde çağrılacak callback

        Returns:
            Birleşik analiz sonuçları
        """
        combined = ReportData()
        dir_path = Path(directory)
        files = sorted(dir_path.glob(pattern))

        if not files:
            logger.warning(f"Hiç log dosyası bulunamadı: {directory}/{pattern}")
            return combined

        for filepath in files:
            logger.info(f"Analiz ediliyor: {filepath}")
            file_data = self.analyze_file(str(filepath), log_format=log_format, on_threat=on_threat)
            # Birleştir
            combined.threats.extend(file_data.threats)
            combined.total_lines_processed += file_data.total_lines_processed
            combined.total_requests += file_data.total_requests
            combined.unique_ips.update(file_data.unique_ips)
            combined.blocked_ips.update(file_data.blocked_ips)

        combined.finalize()
        return combined

    def watch_file(
        self,
        filepath: str,
        *,
        log_format: str = "nginx",
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
        poll_interval: float = 1.0,
    ) -> None:
        """
        Bir log dosyasını gerçek zamanlı izler (tail -f benzeri).
        Ctrl+C ile durdurulur.

        Args:
            filepath: İzlenecek log dosyası
            log_format: "nginx", "apache" veya "syslog"
            on_threat: Her tehdit tespit edildiğinde çağrılacak callback
            poll_interval: Dosya kontrol aralığı (saniye)
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")

        parser = self._get_parser(log_format)
        data = ReportData()

        logger.info(f"İzleme başlatıldı: {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            # Mevcut içeriği atla, sadece yeni satırları oku
            fh.seek(0, 2)

            try:
                while True:
                    line = fh.readline()
                    if not line:
                        time.sleep(poll_interval)
                        continue

                    data.total_lines_processed += 1
                    entry = parser.parse_line(line)
                    if entry is None:
                        continue

                    data.add_request(entry.ip)
                    threats = self.detector.analyze(entry)
                    for threat in threats:
                        data.add_threat(threat)
                        self.responder.respond(threat)
                        if self.responder.is_blocked(threat.source_ip):
                            data.add_blocked(threat.source_ip)
                        if on_threat:
                            on_threat(threat)

            except KeyboardInterrupt:
                logger.info("İzleme durduruldu.")

        data.finalize()
        self._report_data = data

    def watch_sources(
        self,
        *,
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
        poll_interval: float = 1.0,
    ) -> None:
        """
        config.yaml'daki tüm izleme kaynaklarını gerçek zamanlı izler.

        Args:
            on_threat: Her tehdit tespit edildiğinde çağrılacak callback
            poll_interval: Dosya kontrol aralığı (saniye)
        """
        sources = [
            s for s in self.config.get("log_sources", [])
            if s.get("watch", False)
        ]
        if not sources:
            logger.warning("İzlenecek kaynak bulunamadı.")
            return

        # Birden fazla kaynak için her birini ayrı thread ile izle
        import threading
        threads = []
        for source in sources:
            path = source.get("path", "")
            fmt = source.get("format", "nginx")
            t = threading.Thread(
                target=self._watch_source,
                args=(path, fmt, on_threat, poll_interval),
                daemon=True,
                name=f"watcher-{source.get('name', 'unknown')}",
            )
            t.start()
            threads.append(t)

        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            logger.info("Tüm izleyiciler durduruldu.")

    def _watch_source(
        self,
        filepath: str,
        log_format: str,
        on_threat: Optional[Callable],
        poll_interval: float,
    ) -> None:
        try:
            self.watch_file(filepath, log_format=log_format, on_threat=on_threat, poll_interval=poll_interval)
        except FileNotFoundError as e:
            logger.error(str(e))

    # ──────────────────────────────────────────────────────────────────────────
    # Yardımcı metodlar
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _get_parser(log_format: str):
        """Format adına göre uygun parser'ı döner."""
        fmt = log_format.lower()
        if fmt in ("nginx", "combined"):
            return NginxParser()
        elif fmt == "apache":
            return ApacheParser()
        elif fmt == "syslog":
            return SyslogParser()
        else:
            logger.warning(f"Bilinmeyen format '{fmt}', nginx parser kullanılıyor.")
            return NginxParser()

    def generate_report(self, data: ReportData, fmt: str = "both") -> None:
        """
        Rapor oluşturur.

        Args:
            data: Rapor verisi
            fmt: "json", "text" veya "both"
        """
        if fmt in ("json", "both"):
            path = self.reporter.generate_json_report(data)
            logger.info(f"JSON raporu: {path}")

        if fmt in ("text", "both"):
            path = self.reporter.generate_text_report(data)
            logger.info(f"Metin raporu: {path}")
