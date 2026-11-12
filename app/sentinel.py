"""API Sentinel: Enterprise Security, Threat & Prompt-Injection Guard, and Outbound Zero-Leak Firewall.

Provides:
1. Inbound Threat & Prompt-Injection Guard (inspect_inbound)
2. Outbound Zero-Leakage Firewall (verify_outbound_payload)
3. API Health, Security Posture, & Traffic Diagnostics (get_sentinel_stats)
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

# Suspicious prompt injection and jailbreak signatures
INJECTION_PATTERNS = [
    # Instruction bypass
    r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b",
    r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+rules\b",
    r"(?i)\bforget\s+(?:all\s+)?(?:previous|prior|system)\s+prompts?\b",
    r"(?i)\byou\s+are\s+now\s+(?:DAN|unfiltered|jailbroken|free)\b",
    # Privacy / DPDP bypass attempts
    r"(?i)\bbypass\s+(?:privacy|dpdp|redaction|masking|guardrails?|filters?)\b",
    r"(?i)\breturn\s+(?:the\s+)?raw\s+(?:pii|aadhaar|pan|identity|personal\s+data)\b",
    r"(?i)\breveal\s+(?:the\s+)?hidden\s+mapping\b",
    r"(?i)\bprint\s+(?:the\s+)?original\s+unmasked\b",
    # SQL / Code injection patterns
    r"(?i)(?:union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into|delete\s+from)",
    r"(?i)(?:<script[\s>]|javascript:|onload=|onerror=)",
    # System prompt extraction
    r"(?i)\b(?:repeat|show|display|reveal)\s+(?:the\s+)?(?:system\s+prompt|initial\s+prompt)\b",
]

COMPILED_INJECTION_PATTERNS = [re.compile(p) for p in INJECTION_PATTERNS]


class SentinelInboundResult:
    def __init__(
        self,
        status: str,  # 'SAFE', 'WARNING', 'BLOCKED'
        risk_score: int,  # 0 to 100
        detected_threats: List[str],
        latency_ms: float,
    ):
        self.status = status
        self.risk_score = risk_score
        self.detected_threats = detected_threats
        self.latency_ms = latency_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "detected_threats": self.detected_threats,
            "latency_ms": self.latency_ms,
        }


class SentinelOutboundResult:
    def __init__(
        self,
        passed: bool,
        leakage_count: int,
        leaked_values: List[str],
        latency_ms: float,
    ):
        self.passed = passed
        self.leakage_count = leakage_count
        self.leaked_values = leaked_values
        self.latency_ms = latency_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "leakage_count": self.leakage_count,
            "leaked_values": self.leaked_values,
            "latency_ms": self.latency_ms,
        }


class APISentinel:
    """Security Sentinel operating as a pre-ingestion threat firewall and post-masking outbound verifier."""

    def __init__(self):
        # In-memory diagnostics accumulator
        self.total_inspected = 0
        self.threats_blocked = 0
        self.threats_warned = 0
        self.pii_entities_shielded = 0
        self.total_latency_ms = 0.0
        self.fallback_triggers = 0

    def inspect_inbound(self, text: str) -> SentinelInboundResult:
        """Stage 0: Inspects incoming prompt/document for prompt injection, jailbreaks, and script exploits."""
        t0 = time.perf_counter()
        detected_threats: List[str] = []

        for pat in COMPILED_INJECTION_PATTERNS:
            match = pat.search(text)
            if match:
                detected_threats.append(match.group(0))

        # Risk scoring
        if not detected_threats:
            status = "SAFE"
            risk_score = 0
        elif len(detected_threats) == 1 and not any(
            kw in detected_threats[0].lower()
            for kw in ["ignore", "disregard", "dan", "bypass", "drop table"]
        ):
            status = "WARNING"
            risk_score = 45
            self.threats_warned += 1
        else:
            status = "BLOCKED"
            risk_score = min(100, 75 + len(detected_threats) * 10)
            self.threats_blocked += 1

        t_elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
        self.total_inspected += 1
        self.total_latency_ms += t_elapsed

        return SentinelInboundResult(
            status=status,
            risk_score=risk_score,
            detected_threats=detected_threats,
            latency_ms=t_elapsed,
        )

    def verify_outbound_payload(
        self,
        sanitized_text: str,
        placeholder_map: Dict[str, str],
        blocked_entities: Optional[List[Dict[str, Any]]] = None,
    ) -> SentinelOutboundResult:
        """Stage 2.5: Outbound Zero-Leakage Firewall.

        Verifies that zero raw personal identifiers from the mapping or blocked list exist in the outbound payload.
        """
        t0 = time.perf_counter()
        leaked_values = []

        all_sensitive_values = list(placeholder_map.values())
        if blocked_entities:
            all_sensitive_values.extend([b.get("raw_text", "") for b in blocked_entities])

        sanitized_lower = sanitized_text.lower()
        for raw_val in all_sensitive_values:
            val_clean = raw_val.strip()
            # Ignore short numbers/fragments (< 4 chars) to prevent false substring triggers
            if len(val_clean) < 4:
                continue
            if val_clean.lower() in sanitized_lower:
                leaked_values.append(val_clean)

        leakage_count = len(leaked_values)
        passed = (leakage_count == 0)
        t_elapsed = round((time.perf_counter() - t0) * 1000.0, 2)

        return SentinelOutboundResult(
            passed=passed,
            leakage_count=leakage_count,
            leaked_values=leaked_values,
            latency_ms=t_elapsed,
        )

    def record_metrics(self, entity_count: int, is_fallback: bool = False) -> None:
        self.pii_entities_shielded += entity_count
        if is_fallback:
            self.fallback_triggers += 1

    def get_sentinel_stats(self) -> Dict[str, Any]:
        avg_lat = (
            round(self.total_latency_ms / self.total_inspected, 2)
            if self.total_inspected > 0
            else 0.0
        )
        return {
            "total_requests_inspected": self.total_inspected,
            "threats_blocked": self.threats_blocked,
            "threats_warned": self.threats_warned,
            "pii_entities_shielded": self.pii_entities_shielded,
            "avg_sentinel_latency_ms": avg_lat,
            "local_fallback_triggers": self.fallback_triggers,
            "security_health": "OPTIMAL" if self.threats_blocked == 0 else "PROTECTED_ACTIVE",
        }

