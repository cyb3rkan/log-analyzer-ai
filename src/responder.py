"""
Automated Responder - Otomatik Tehdit Müdahale Modülü
IP bloklama (iptables), Slack ve Telegram alert gönderimi.
"""
import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Optional

import requests

from .detector import ThreatEvent, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

logger = logging.getLogger(__name__)


class IPBlocker:
    """
    iptables veya firewalld kullanarak IP adresi bloklar.
    Root yetkisi gerektirir.
    """

    def __init__(self, method: str = "iptables", duration: int = 3600):
        """
        Args:
            method: "iptables" veya "firewalld"
            duration: Blok süresi saniye cinsinden (0 = kalıcı)
        """
        self.method = method
        self.duration = duration
        self._blocked: dict[str, datetime] = {}

    def block(self, ip: str) -> bool:
        """
        IP adresini bloklar.

        Args:
            ip: Bloklanacak IP adresi

        Returns:
            Başarılı ise True
        """
        if ip in self._blocked:
            logger.debug(f"IP zaten bloklu: {ip}")
            return True

        try:
            if self.method == "iptables":
                return self._block_iptables(ip)
            elif self.method == "firewalld":
                return self._block_firewalld(ip)
            else:
                logger.error(f"Bilinmeyen bloklama yöntemi: {self.method}")
                return False
        except Exception as e:
            logger.error(f"IP bloklama hatası [{ip}]: {e}")
            return False

    def unblock(self, ip: str) -> bool:
        """
        IP adresinin bloğunu kaldırır.

        Args:
            ip: Bloklanmış IP adresi

        Returns:
            Başarılı ise True
        """
        try:
            if self.method == "iptables":
                return self._unblock_iptables(ip)
            elif self.method == "firewalld":
                return self._unblock_firewalld(ip)
            return False
        except Exception as e:
            logger.error(f"IP unblock hatası [{ip}]: {e}")
            return False
        finally:
            self._blocked.pop(ip, None)

    def is_blocked(self, ip: str) -> bool:
        """IP'nin bloklu olup olmadığını döner."""
        return ip in self._blocked

    def _block_iptables(self, ip: str) -> bool:
        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            self._blocked[ip] = datetime.now()
            logger.info(f"IP bloklandı (iptables): {ip}")
            return True
        else:
            logger.error(f"iptables hata: {result.stderr}")
            return False

    def _unblock_iptables(self, ip: str) -> bool:
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"IP blok kaldırıldı (iptables): {ip}")
            return True
        else:
            logger.warning(f"iptables unblock hata: {result.stderr}")
            return False

    def _block_firewalld(self, ip: str) -> bool:
        cmd = ["firewall-cmd", "--add-rich-rule", f"rule family=ipv4 source address={ip} reject"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            self._blocked[ip] = datetime.now()
            logger.info(f"IP bloklandı (firewalld): {ip}")
            return True
        else:
            logger.error(f"firewalld hata: {result.stderr}")
            return False

    def _unblock_firewalld(self, ip: str) -> bool:
        cmd = [
            "firewall-cmd", "--remove-rich-rule",
            f"rule family=ipv4 source address={ip} reject"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0


class SlackAlerter:
    """Slack Incoming Webhook ile alert gönderir."""

    SEVERITY_COLORS = {
        SEVERITY_CRITICAL: "#FF0000",
        SEVERITY_HIGH: "#FF6600",
        SEVERITY_MEDIUM: "#FFB300",
        SEVERITY_LOW: "#00BCD4",
    }

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, threat: ThreatEvent) -> bool:
        """
        Tehdit olayını Slack'e gönderir.

        Args:
            threat: Gönderilecek tehdit olayı

        Returns:
            Başarılı ise True
        """
        color = self.SEVERITY_COLORS.get(threat.severity, "#808080")
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"🚨 {threat.severity} - {threat.threat_type}",
                    "fields": [
                        {"title": "Kaynak IP", "value": threat.source_ip, "short": True},
                        {"title": "Hedef", "value": threat.target or "-", "short": True},
                        {"title": "Açıklama", "value": threat.description, "short": False},
                        {"title": "Zaman", "value": threat.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "short": True},
                    ],
                    "footer": "Log Analyzer AI",
                    "ts": int(threat.timestamp.timestamp()),
                }
            ]
        }

        if threat.payload:
            payload["attachments"][0]["fields"].append(
                {"title": "Payload", "value": f"`{threat.payload[:500]}`", "short": False}
            )

        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if response.status_code == 200:
                logger.info(f"Slack alert gönderildi: {threat.threat_type}")
                return True
            else:
                logger.error(f"Slack hata {response.status_code}: {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Slack bağlantı hatası: {e}")
            return False


class TelegramAlerter:
    """Telegram Bot API ile alert gönderir."""

    SEVERITY_EMOJI = {
        SEVERITY_CRITICAL: "🔴",
        SEVERITY_HIGH: "🟠",
        SEVERITY_MEDIUM: "🟡",
        SEVERITY_LOW: "🔵",
    }

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    def send(self, threat: ThreatEvent) -> bool:
        """
        Tehdit olayını Telegram'a gönderir.

        Args:
            threat: Gönderilecek tehdit olayı

        Returns:
            Başarılı ise True
        """
        emoji = self.SEVERITY_EMOJI.get(threat.severity, "⚪")
        text = (
            f"{emoji} *{threat.severity} - {threat.threat_type}*\n\n"
            f"📍 Kaynak IP: `{threat.source_ip}`\n"
            f"🎯 Hedef: `{threat.target or '-'}`\n"
            f"📝 Açıklama: {threat.description}\n"
            f"⏰ Zaman: `{threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}`"
        )

        if threat.payload:
            text += f"\n💉 Payload: `{threat.payload[:300]}`"

        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }

        try:
            response = requests.post(self._api_url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info(f"Telegram alert gönderildi: {threat.threat_type}")
                return True
            else:
                logger.error(f"Telegram hata {response.status_code}: {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Telegram bağlantı hatası: {e}")
            return False


class AutoResponder:
    """
    Tehdit olaylarına otomatik müdahale eden ana sınıf.
    IP bloklama ve alert gönderimini koordine eder.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Tam config.yaml içeriği
        """
        self.config = config or {}
        response_cfg = self.config.get("response", {})

        # IP bloklama
        block_cfg = response_cfg.get("auto_block", {})
        self._auto_block_enabled = block_cfg.get("enabled", False)
        if self._auto_block_enabled:
            self._blocker = IPBlocker(
                method=block_cfg.get("method", "iptables"),
                duration=block_cfg.get("duration", 3600),
            )
        else:
            self._blocker = None

        # Alert göndericiler
        self._alerters = []
        alerts_cfg = response_cfg.get("alerts", {})

        slack_cfg = alerts_cfg.get("slack", {})
        if slack_cfg.get("enabled", False):
            webhook = os.environ.get("SLACK_WEBHOOK", slack_cfg.get("webhook_url", ""))
            if webhook:
                self._alerters.append(SlackAlerter(webhook))

        telegram_cfg = alerts_cfg.get("telegram", {})
        if telegram_cfg.get("enabled", False):
            token = os.environ.get("TELEGRAM_TOKEN", telegram_cfg.get("bot_token", ""))
            chat_id = os.environ.get("TELEGRAM_CHAT_ID", telegram_cfg.get("chat_id", ""))
            if token and chat_id:
                self._alerters.append(TelegramAlerter(token, chat_id))

        # Alert seviyesi eşiği
        self._alert_min_severity = SEVERITY_MEDIUM

        # İstatistikler
        self.stats = {
            "total_threats": 0,
            "blocked_ips": 0,
            "alerts_sent": 0,
        }

    def respond(self, threat: ThreatEvent) -> dict:
        """
        Bir tehdit olayına müdahale eder.

        Args:
            threat: Müdahale edilecek tehdit

        Returns:
            Müdahale sonuçlarını içeren dict
        """
        self.stats["total_threats"] += 1
        actions_taken = []

        # IP bloklama (yalnızca HIGH ve CRITICAL için)
        if self._auto_block_enabled and self._blocker:
            if threat.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL):
                blocked = self._blocker.block(threat.source_ip)
                if blocked:
                    actions_taken.append(f"IP BLOCKED ({self._blocker.method})")
                    self.stats["blocked_ips"] += 1
                else:
                    actions_taken.append("BLOCK FAILED")

        # Alert gönderimi
        severity_order = [SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]
        min_idx = severity_order.index(self._alert_min_severity)
        threat_idx = severity_order.index(threat.severity) if threat.severity in severity_order else 0

        if threat_idx >= min_idx:
            for alerter in self._alerters:
                try:
                    alerter.send(threat)
                    actions_taken.append(f"Alert sent via {alerter.__class__.__name__}")
                    self.stats["alerts_sent"] += 1
                except Exception as e:
                    logger.error(f"Alert gönderme hatası: {e}")

        return {
            "threat": threat.to_dict(),
            "actions_taken": actions_taken,
            "timestamp": datetime.now().isoformat(),
        }

    def is_blocked(self, ip: str) -> bool:
        """IP'nin bloklu olup olmadığını kontrol eder."""
        if self._blocker:
            return self._blocker.is_blocked(ip)
        return False
