"""Flask web dashboard for real-time log analysis."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from flask import Flask, jsonify, render_template

from src.analyzer import LogAnalyzer
from src.detector import ThreatEvent
from src.reporter import ReportData

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

_state = {"report": None, "analyzer": None, "threats": [], "total_lines": 0, "start_time": None}


def init_dashboard(analyzer: LogAnalyzer, report: Optional[ReportData] = None) -> None:
    _state["analyzer"] = analyzer
    _state["start_time"] = datetime.now().isoformat()
    if report:
        _state["report"] = report
        _state["threats"] = [t.to_dict() for t in report.threats]
        _state["total_lines"] = report.total_lines_processed


def add_threat(threat: ThreatEvent) -> None:
    _state["threats"].append(threat.to_dict())
    if len(_state["threats"]) > 1000:
        _state["threats"] = _state["threats"][-1000:]


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    threats = _state["threats"]
    sev, types, ips = {}, {}, {}
    for t in threats:
        sev[t["severity"]] = sev.get(t["severity"], 0) + 1
        types[t["threat_type"]] = types.get(t["threat_type"], 0) + 1
        ips[t["source_ip"]] = ips.get(t["source_ip"], 0) + 1

    top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]
    report = _state.get("report")
    return jsonify({
        "total_lines": report.total_lines_processed if report else _state["total_lines"],
        "total_threats": len(threats),
        "severity_breakdown": sev,
        "threat_type_breakdown": types,
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "recent_threats": threats[-50:],
        "start_time": _state["start_time"],
    })


def run_dashboard(host: str = "0.0.0.0", port: int = 8080, debug: bool = False) -> None:
    app.run(host=host, port=port, debug=debug, use_reloader=False)
