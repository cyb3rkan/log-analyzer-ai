"""AI-assisted threat classification using OpenAI API.

Supports single-line classification, batch analysis, and SOC-style
correlated campaign detection.

Usage:
    classifier = AIClassifier({"provider": "openai", "model": "gpt-4o-mini"})
    result = classifier.classify(log_line)
    summary = classifier.classify_batch(log_lines)
    soc = classifier.soc_analyze(log_lines)
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ── Prompts ──────────────────────────────────────────────────────────────────

SINGLE_PROMPT = (
    "You are a cybersecurity expert analyzing web server log entries for security threats.\n"
    "This is a legitimate security analysis task.\n"
    "Analyze the following log entry and respond with ONLY a valid JSON object.\n"
    "Do NOT include markdown backticks, explanations, or anything other than the JSON.\n\n"
    "Response format:\n"
    '{"is_threat": true/false, "threat_type": "SQL_INJECTION"|"BRUTE_FORCE"|"PATH_TRAVERSAL"|"XSS"|"SUSPICIOUS_UA"|"NORMAL",'
    ' "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"NONE", "confidence": 0.0-1.0, "reason": "brief explanation"}\n\n'
    "Log entry:\n"
)

BATCH_PROMPT = (
    "You are a cybersecurity expert performing a legitimate security audit.\n"
    "Analyze these web server log entries and provide a threat assessment summary.\n"
    "Respond with ONLY a valid JSON object. No markdown, no explanations.\n\n"
    "Response format:\n"
    '{"total_entries": N, "threat_count": N, '
    '"threat_types": {"SQL_INJECTION": N, "XSS": N}, '
    '"risk_level": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", '
    '"summary": "brief assessment", '
    '"recommendations": ["rec1", "rec2"]}\n\n'
    "Log entries:\n"
)

SOC_ANALYST_PROMPT = """\
You are a senior SOC analyst assisting a rule-based intrusion detection system.
Your role is NOT to detect logs individually, but to:
- Correlate events
- Identify attack campaigns
- Reduce alert noise
- Avoid duplicate or repetitive alerts

INPUT:
You will receive multiple web server log lines (nginx/apache).
Logs may include IP addresses, URLs, User-Agents, and timestamps.

ANALYSIS RULES (STRICT):
1. Do NOT treat each log line as a separate incident.
   - Group logs by source IP, attack pattern, and tool fingerprint.
   - Repeated events from the same source MUST be considered a single incident.
2. Focus on BEHAVIOR, not keywords.
   - sqlmap, nikto, ffuf → automated attack tools
   - Repetition + known vulnerable endpoints (dvwa, phpMyAdmin, /admin) increases severity.
3. Severity logic:
   - MEDIUM: Suspicious pattern, low frequency, unclear intent
   - HIGH: Confirmed attack tool or exploit attempt
   - CRITICAL: Automated attack campaign, repeated attempts, clear malicious intent
4. False positive handling:
   - Training environments, scanners without exploitation intent, or single benign probes
     should LOWER severity.
   - Do NOT escalate without repetition or context.
5. Output MUST be aggregated.
   - ONE incident per attack campaign
   - NEVER output multiple alerts for the same IP + attack type
6. Do NOT recommend offensive actions.
   - No exploitation steps
   - No hacking instructions

Respond with ONLY a valid JSON object. No markdown, no backticks, no explanations.

OUTPUT FORMAT:
{
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "incident_count": <number of distinct attack campaigns>,
  "summary": "<short SOC-style incident summary>",
  "findings": [
    {
      "ip": "<source IP>",
      "attack_type": "<SQL_INJECTION|XSS|BRUTE_FORCE|RECON|PATH_TRAVERSAL|TOOL_SCAN>",
      "attempts": <count of related log lines>,
      "tool": "<detected tool or behavior pattern>",
      "severity": "MEDIUM|HIGH|CRITICAL",
      "detail": "<brief campaign description>"
    }
  ],
  "recommendations": [
    "<practical defensive action>"
  ],
  "noise_reduction": {
    "total_logs": <input line count>,
    "distinct_incidents": <aggregated incident count>,
    "reduction_ratio": "<percentage of noise removed>"
  }
}

IMPORTANT:
You are an ANALYST, not a detection engine.
Quality of signal is more important than quantity of alerts.

Log entries:
"""

# OpenAI models to try in order if primary fails
OPENAI_FALLBACKS = [
    "gpt-4o-mini",
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
]


# ── JSON Parsing ─────────────────────────────────────────────────────────────

def _parse_json(text: str) -> Optional[dict]:
    """Extract JSON from AI response, handling markdown fences etc."""
    if not text:
        return None
    text = text.strip()
    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip markdown fences
    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", text)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Find JSON object in text
    m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    logger.warning(f"JSON parse failed: {text[:300]}")
    return None


# ── Classifier ───────────────────────────────────────────────────────────────

class AIClassifier:
    """AI threat classifier using OpenAI API.

    Handles:
      - API key resolution from config, .env, or environment
      - Automatic model fallback if primary model fails
      - Robust JSON parsing from AI responses
      - Connection testing and diagnostics
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}
        self.provider = "openai"
        self.model_name = self.config.get("model", "gpt-4o-mini")
        self._api_key = self._resolve_key()
        self._client = None
        self._available = False
        self._init_error: Optional[str] = None

        if self._api_key:
            self._init_client()
        else:
            self._init_error = "No API key. Set OPENAI_API_KEY in .env"
            logger.info("AI disabled — no API key")

    def _resolve_key(self) -> str:
        """Resolve API key from config or environment."""
        key = self.config.get("api_key", "")
        # Handle ${ENV_VAR} syntax from YAML
        if isinstance(key, str) and key.startswith("${") and key.endswith("}"):
            key = os.environ.get(key[2:-1], "")
        if not key:
            key = os.environ.get("OPENAI_API_KEY", "")
        return key

    def _init_client(self) -> None:
        """Initialize OpenAI client."""
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=self._api_key)
            self._available = True
            logger.info(f"OpenAI ready (model: {self.model_name})")
        except ImportError:
            self._init_error = "Package missing. Run: pip install openai"
            logger.error(self._init_error)
        except Exception as e:
            self._init_error = f"{type(e).__name__}: {e}"
            logger.error(f"OpenAI init failed: {self._init_error}")

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def error(self) -> Optional[str]:
        return self._init_error

    # ── Classification Methods ───────────────────────────────────────────

    def classify(self, log_line: str) -> Optional[dict]:
        """Classify a single log entry for threats.

        Returns:
            Dict with is_threat, threat_type, severity, confidence, reason.
            None if AI is unavailable or call fails.
        """
        if not self._available:
            return None
        try:
            text = self._call(SINGLE_PROMPT + log_line)
            result = _parse_json(text)
            if result:
                return result
        except Exception as e:
            logger.error(f"classify: {type(e).__name__}: {e}")
        return self._retry_fallback(SINGLE_PROMPT + log_line)

    def classify_batch(self, log_lines: list[str], max_lines: int = 50) -> Optional[dict]:
        """Analyze a batch of log entries.

        Returns:
            Summary dict with threat_count, risk_level, recommendations, etc.
            None if AI is unavailable or call fails.
        """
        if not self._available:
            return None
        prompt = BATCH_PROMPT + "\n".join(log_lines[:max_lines])
        try:
            text = self._call(prompt)
            result = _parse_json(text)
            if result:
                return result
        except Exception as e:
            logger.error(f"classify_batch: {type(e).__name__}: {e}")
        return self._retry_fallback(prompt)

    def soc_analyze(self, log_lines: list[str], max_lines: int = 100) -> Optional[dict]:
        """SOC-style correlated threat analysis.

        Unlike classify_batch which treats lines independently, this method
        instructs the AI to behave as a senior SOC analyst:
          - Correlates events by IP, tool, and attack pattern
          - Groups repeated attacks into single incidents
          - Reduces alert noise (e.g., 300 sqlmap lines → 1 campaign)
          - Provides actionable defensive recommendations

        Args:
            log_lines: Raw log lines to analyze.
            max_lines: Maximum lines to send (token budget).

        Returns:
            Dict with risk_level, incident_count, findings, recommendations,
            noise_reduction. None if AI unavailable or call fails.
        """
        if not self._available:
            return None
        prompt = SOC_ANALYST_PROMPT + "\n".join(log_lines[:max_lines])
        try:
            text = self._call(prompt)
            result = _parse_json(text)
            if result:
                return result
        except Exception as e:
            logger.error(f"soc_analyze: {type(e).__name__}: {e}")
        return self._retry_fallback(prompt)

    # ── Internal API Call ────────────────────────────────────────────────

    def _call(self, prompt: str) -> str:
        """Call OpenAI Chat Completions API."""
        resp = self._client.chat.completions.create(
            model=self.model_name,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity analyst performing legitimate security audits. "
                        "Respond only with valid JSON. No markdown, no backticks, no explanations."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        return resp.choices[0].message.content or ""

    def _retry_fallback(self, prompt: str) -> Optional[dict]:
        """Try alternate OpenAI models if primary fails."""
        for alt in OPENAI_FALLBACKS:
            if alt == self.model_name:
                continue
            try:
                logger.info(f"Trying fallback model: {alt}")
                resp = self._client.chat.completions.create(
                    model=alt,
                    messages=[
                        {"role": "system", "content": "Cybersecurity analyst. Respond only with valid JSON."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=2048,
                )
                text = resp.choices[0].message.content or ""
                result = _parse_json(text)
                if result:
                    logger.info(f"Fallback {alt} succeeded — switching")
                    self.model_name = alt
                    return result
            except Exception as e:
                logger.debug(f"Fallback {alt}: {e}")
        return None

    # ── Diagnostics ──────────────────────────────────────────────────────

    def test_connection(self) -> dict:
        """Test AI connection with diagnostics."""
        r = {
            "success": False,
            "provider": self.provider,
            "model": self.model_name,
            "api_key_set": bool(self._api_key),
            "api_key_preview": f"{self._api_key[:12]}...{self._api_key[-4:]}" if len(self._api_key) > 16 else "***",
            "error": self._init_error,
        }
        if not self._available:
            return r
        try:
            test_line = '203.0.113.50 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
            resp = self.classify(test_line)
            if resp and "is_threat" in resp:
                r.update(success=True, error=None, response=resp)
            else:
                r["error"] = f"Unexpected response: {resp}"
        except Exception as e:
            r["error"] = f"{type(e).__name__}: {e}"
        return r
