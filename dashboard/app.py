"""
Dashboard - Real-time Web Arayüzü
Flask + SocketIO ile canlı tehdit izleme dashboard'u.
"""
import json
import logging
import os
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

logger = logging.getLogger(__name__)

# flask-socketio opsiyonel
try:
    from flask_socketio import SocketIO, emit
    _SOCKETIO_AVAILABLE = True
except ImportError:
    _SOCKETIO_AVAILABLE = False
    logger.warning("flask-socketio bulunamadı. WebSocket devre dışı.")

# Global state
_threats: list[dict] = []
_stats = {
    "total_requests": 0,
    "total_threats": 0,
    "blocked_ips": 0,
    "unique_ips": set(),
    "started_at": datetime.now().isoformat(),
}


def create_app(config: dict = None) -> Flask:
    """
    Flask uygulamasını oluşturur ve döner.

    Args:
        config: Uygulama konfigürasyonu

    Returns:
        Yapılandırılmış Flask uygulaması
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.secret_key = os.environ.get("FLASK_SECRET", "log-analyzer-ai-secret-key")
    cfg = config or {}

    if _SOCKETIO_AVAILABLE:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
        app.socketio = socketio
    else:
        app.socketio = None

    # ─── Routes ──────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Ana dashboard sayfası."""
        return render_template("dashboard.html")

    @app.route("/api/stats")
    def api_stats():
        """Anlık istatistikleri döner."""
        serializable_stats = {k: v for k, v in _stats.items() if k != "unique_ips"}
        serializable_stats["unique_ips"] = len(_stats["unique_ips"])
        serializable_stats["uptime_seconds"] = (
            datetime.now() - datetime.fromisoformat(_stats["started_at"])
        ).total_seconds()
        return jsonify(serializable_stats)

    @app.route("/api/threats")
    def api_threats():
        """Son tehditleri döner."""
        limit = request.args.get("limit", 50, type=int)
        severity = request.args.get("severity", None)

        result = _threats[-limit:]
        if severity:
            result = [t for t in result if t.get("severity") == severity.upper()]

        return jsonify({"threats": result, "total": len(_threats)})

    @app.route("/api/threats/<threat_type>")
    def api_threats_by_type(threat_type: str):
        """Belirli türdeki tehditleri döner."""
        filtered = [
            t for t in _threats
            if t.get("threat_type", "").upper() == threat_type.upper()
        ]
        return jsonify({"threats": filtered, "total": len(filtered)})

    @app.route("/api/top-ips")
    def api_top_ips():
        """En çok saldıran IP'leri döner."""
        from collections import Counter
        ip_counts = Counter(t.get("source_ip") for t in _threats)
        top = [{"ip": ip, "count": cnt} for ip, cnt in ip_counts.most_common(20)]
        return jsonify({"top_ips": top})

    @app.route("/api/timeline")
    def api_timeline():
        """Tehdit zaman çizelgesini döner (son 24 saat, saatlik)."""
        from collections import defaultdict
        hourly: dict[str, int] = defaultdict(int)
        for threat in _threats:
            ts = threat.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts)
                    hour_key = dt.strftime("%Y-%m-%dT%H:00")
                    hourly[hour_key] += 1
                except ValueError:
                    pass
        timeline = [{"hour": h, "count": c} for h, c in sorted(hourly.items())]
        return jsonify({"timeline": timeline})

    @app.route("/health")
    def health():
        """Health check endpoint."""
        return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

    # ─── Socketio events ─────────────────────────────────────────────────────

    if _SOCKETIO_AVAILABLE and app.socketio:
        @socketio.on("connect")
        def on_connect():
            logger.debug("Dashboard client bağlandı.")
            emit("connected", {"message": "Log Analyzer AI Dashboard'a hoş geldiniz!"})

        @socketio.on("request_stats")
        def on_request_stats():
            serializable = {k: v for k, v in _stats.items() if k != "unique_ips"}
            serializable["unique_ips"] = len(_stats["unique_ips"])
            emit("stats_update", serializable)

    return app


def push_threat(app: Flask, threat_dict: dict) -> None:
    """
    Yeni bir tehdit olayını dashboard'a iletir.
    Bu fonksiyon analyzer tarafından çağrılır.

    Args:
        app: Flask uygulama nesnesi
        threat_dict: ThreatEvent.to_dict() sonucu
    """
    _threats.append(threat_dict)
    _stats["total_threats"] += 1
    _stats["unique_ips"].add(threat_dict.get("source_ip", ""))

    # Bellek limitlemesi: en son 10000 tehdit
    if len(_threats) > 10000:
        _threats.pop(0)

    # WebSocket ile push
    if _SOCKETIO_AVAILABLE and hasattr(app, "socketio") and app.socketio:
        try:
            with app.app_context():
                app.socketio.emit("new_threat", threat_dict)
        except Exception as e:
            logger.debug(f"SocketIO push hatası: {e}")


def update_stats(requests_count: int = 0, blocked: int = 0) -> None:
    """Global istatistikleri günceller."""
    _stats["total_requests"] += requests_count
    _stats["blocked_ips"] += blocked
