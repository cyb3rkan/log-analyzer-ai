"""
Reporter Testleri
"""
import json
import pytest
from datetime import datetime, timezone

from src.detector import ThreatEvent, SEVERITY_HIGH, SEVERITY_MEDIUM
from src.reporter import ReportData, Reporter


def _make_threat(
    threat_type="SQL_INJECTION",
    severity=SEVERITY_HIGH,
    source_ip="1.2.3.4",
    target="/api/search",
) -> ThreatEvent:
    return ThreatEvent(
        threat_type=threat_type,
        severity=severity,
        source_ip=source_ip,
        timestamp=datetime.now(tz=timezone.utc),
        description="Test threat",
        target=target,
    )


class TestReportData:

    def test_initial_state(self):
        data = ReportData()
        assert data.total_lines_processed == 0
        assert data.total_requests == 0
        assert len(data.unique_ips) == 0
        assert len(data.threats) == 0
        assert len(data.blocked_ips) == 0

    def test_add_threat(self):
        data = ReportData()
        threat = _make_threat(source_ip="10.0.0.1")
        data.add_threat(threat)
        assert len(data.threats) == 1
        assert "10.0.0.1" in data.unique_ips

    def test_add_request(self):
        data = ReportData()
        data.add_request("5.5.5.5")
        assert data.total_requests == 1
        assert "5.5.5.5" in data.unique_ips

    def test_add_blocked(self):
        data = ReportData()
        data.add_blocked("6.6.6.6")
        assert "6.6.6.6" in data.blocked_ips

    def test_summary_structure(self):
        data = ReportData()
        data.add_threat(_make_threat())
        data.add_request("1.1.1.1")
        summary = data.summary()

        assert "period" in summary
        assert "totals" in summary
        assert "threats_by_type" in summary
        assert "threats_by_severity" in summary
        assert "top_attacker_ips" in summary

    def test_summary_counts(self):
        data = ReportData()
        for _ in range(3):
            data.add_threat(_make_threat(source_ip="1.2.3.4"))
        data.add_threat(_make_threat(threat_type="XSS", severity=SEVERITY_MEDIUM, source_ip="5.6.7.8"))
        summary = data.summary()

        assert summary["totals"]["threats_detected"] == 4
        assert summary["threats_by_type"]["SQL_INJECTION"] == 3
        assert summary["threats_by_type"]["XSS"] == 1

    def test_top_attacker_ips(self):
        data = ReportData()
        for _ in range(5):
            data.add_threat(_make_threat(source_ip="attacker.ip"))
        data.add_threat(_make_threat(source_ip="other.ip"))
        summary = data.summary()
        top = summary["top_attacker_ips"]
        assert top[0]["ip"] == "attacker.ip"
        assert top[0]["count"] == 5


class TestReporter:

    def test_generate_json_report(self, tmp_path):
        config = {"reporting": {"output_dir": str(tmp_path), "daily": False, "weekly": False}}
        reporter = Reporter(config)

        data = ReportData()
        data.add_threat(_make_threat())
        data.finalize()

        filepath = reporter.generate_json_report(data, filename="test_report.json")
        assert filepath.exists()

        with open(filepath) as f:
            content = json.load(f)
        assert "totals" in content
        assert "threat_details" in content
        assert content["totals"]["threats_detected"] == 1

    def test_generate_text_report(self, tmp_path):
        config = {"reporting": {"output_dir": str(tmp_path), "daily": False, "weekly": False}}
        reporter = Reporter(config)

        data = ReportData()
        data.add_threat(_make_threat())
        data.finalize()

        filepath = reporter.generate_text_report(data, filename="test_report.txt")
        assert filepath.exists()

        content = filepath.read_text()
        assert "LOG ANALYZER AI" in content
        assert "SQL_INJECTION" in content

    def test_output_dir_created(self, tmp_path):
        output_dir = tmp_path / "subdir" / "reports"
        config = {"reporting": {"output_dir": str(output_dir)}}
        reporter = Reporter(config)
        assert output_dir.exists()

    def test_auto_filename(self, tmp_path):
        config = {"reporting": {"output_dir": str(tmp_path)}}
        reporter = Reporter(config)
        data = ReportData()
        data.finalize()

        json_path = reporter.generate_json_report(data)
        text_path = reporter.generate_text_report(data)

        assert json_path.suffix == ".json"
        assert text_path.suffix == ".txt"
