"""Unit tests for reporter."""
import json, os, tempfile
from datetime import datetime
from src.detector import ThreatEvent
from src.reporter import ReportData, Reporter


def mk_threat(tt="SQL_INJECTION", sev="CRITICAL", ip="10.0.0.1"):
    return ThreatEvent(tt, sev, ip, datetime(2024, 1, 15, 14, 30), f"Test {tt}", confidence=0.95)


class TestReportData:
    def test_add_and_summary(self):
        r = ReportData(total_lines_processed=1000)
        r.add_threat(mk_threat("SQL_INJECTION", "CRITICAL", "10.0.0.1"))
        r.add_threat(mk_threat("XSS", "HIGH", "10.0.0.2"))
        s = r.summary()
        assert s["total_threats"] == 2 and s["severity_breakdown"]["CRITICAL"] == 1

    def test_top_ips(self):
        r = ReportData()
        for _ in range(5): r.add_threat(mk_threat(ip="10.0.0.1"))
        for _ in range(3): r.add_threat(mk_threat(ip="10.0.0.2"))
        top = r.top_attacker_ips(2)
        assert top[0] == ("10.0.0.1", 5)

    def test_empty(self):
        assert ReportData().summary()["total_threats"] == 0


class TestReporter:
    def test_json(self):
        r = ReportData(total_lines_processed=100)
        r.add_threat(mk_threat())
        f = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        try:
            Reporter().generate_json_report(r, f)
            d = json.load(open(f))
            assert d["summary"]["total_threats"] == 1
        finally:
            os.unlink(f)

    def test_text(self):
        r = ReportData(total_lines_processed=100, source_file="t.log")
        r.add_threat(mk_threat())
        f = tempfile.NamedTemporaryFile(suffix=".txt", delete=False).name
        try:
            Reporter().generate_text_report(r, f)
            assert "SQL_INJECTION" in open(f).read()
        finally:
            os.unlink(f)
