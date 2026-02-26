"""Automatic response module - IP blocking and alert notifications."""

from __future__ import annotations

import logging
from typing import Optional

from src.detector import ThreatEvent

logger = logging.getLogger(__name__)


class AutoResponder:
    """Handles automatic responses to detected threats."""

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}
        rc = self.config.get("response", {})
        bc = rc.get("auto_block", {})
        self._block_enabled = bc.get("enabled", False)
        self._block_method = bc.get("method", "iptables")
        self._block_duration = bc.get("duration", 3600)
        ac = rc.get("alerts", {})
        self._slack_enabled = ac.get("slack", {}).get("enabled", False)
        self._slack_webhook = ac.get("slack", {}).get("webhook_url", "")
        self._blocked_ips: set[str] = set()

    def respond(self, threat: ThreatEvent) -> dict:
        actions = {"threat": threat.threat_type, "ip": threat.source_ip, "actions": []}
        if self._block_enabled and threat.severity in ("CRITICAL", "HIGH"):
            if self._block_ip(threat.source_ip):
                actions["actions"].append(f"Blocked {threat.source_ip}")
        if self._slack_enabled:
            if self._send_slack_alert(threat):
                actions["actions"].append("Slack alert sent")
        return actions

    def _block_ip(self, ip: str) -> bool:
        if ip in self._blocked_ips:
            return False
        logger.info(f"[DRY-RUN] Would block {ip} via {self._block_method}")
        self._blocked_ips.add(ip)
        return True

    def _send_slack_alert(self, threat: ThreatEvent) -> bool:
        if not self._slack_webhook or self._slack_webhook.startswith("$"):
            return False
        try:
            import requests
            payload = {
                "text": (
                    f":rotating_light: *{threat.severity} - {threat.threat_type}*\n"
                    f"IP: {threat.source_ip}\n{threat.description}"
                )
            }
            resp = requests.post(self._slack_webhook, json=payload, timeout=10)
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False

    @property
    def blocked_ips(self) -> set[str]:
        return self._blocked_ips.copy()
