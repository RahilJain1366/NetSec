"""
mitm/config_rules.py
─────────────────────
MITM-specific validation rules extending the base validator.

These rules focus on configuration-layer MITM preconditions:
  - Cipher suite weaknesses enabling traffic decryption
  - Missing certificate validation (OCSP, CT headers)
  - TLS session attack surfaces
  - DNS-level MITM preconditions

Each rule is tagged with attack_vector = "MITM" for reporting.
"""

from __future__ import annotations
import re
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import Severity, Violation
from validator.rules_base import BaseRule


# ── Pattern library ───────────────────────────────────────────────────────────

# Weak ciphers that enable decryption after traffic capture
_WEAK_CIPHER_RE = re.compile(
    r"ssl_ciphers\s+['\"]?([^;'\"]+)['\"]?\s*;", re.I
)
_BAD_CIPHER_KEYWORDS = re.compile(
    r"\b(RC4|MD5|DES(?!-CBC3)|NULL|EXPORT|aNULL|eNULL|ADH|AECDH|PSK)\b", re.I
)

# OCSP stapling (prevents cert revocation bypass)
_OCSP_ON_RE        = re.compile(r"ssl_stapling\s+on\s*;", re.I)
_OCSP_VERIFY_RE    = re.compile(r"ssl_stapling_verify\s+on\s*;", re.I)

# Certificate Transparency
_CT_HEADER_RE      = re.compile(r"Expect-CT", re.I)

# SSL session tickets off (prevents ticket-based session hijack)
_SESSION_TICKET_RE = re.compile(r"ssl_session_tickets\s+off\s*;", re.I)

# HTTP Strict Transport Security — critical for MITM prevention
_HSTS_PRELOAD_RE   = re.compile(r"Strict-Transport-Security.*preload", re.I)

# Mixed content — HTTP resources loaded on HTTPS page
_PROXY_HTTP_RE     = re.compile(r"proxy_pass\s+http://(?!127\.|localhost|10\.|172\.|192\.168\.)", re.I)

# DANE / TLSA reference (advanced — often not in nginx config)
_DANE_RE           = re.compile(r"tlsa|dane", re.I)

# DNS: DNSSEC signing (not just validation)
_DNSSEC_SIGN_RE    = re.compile(r"(inline-signing\s+yes|dnssec-keymgmt)", re.I)

# DNS: Response Policy Zone (RPZ) — blocks known MITM C2 domains
_RPZ_RE            = re.compile(r"response-policy\s*\{", re.I)


# ── Rules ─────────────────────────────────────────────────────────────────────

class NGX_MITM_001_WeakCiphers(BaseRule):
    rule_id     = "NGX-MITM-001"
    description = "Weak cipher suite enables traffic decryption after capture (MITM)"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        m = _WEAK_CIPHER_RE.search(config)
        if m:
            cipher_str = m.group(1)
            bad = _BAD_CIPHER_KEYWORDS.findall(cipher_str)
            if bad:
                return [self._violation(
                    f"Weak ciphers found: {', '.join(set(bad))} in ssl_ciphers directive"
                )]
        return []


class NGX_MITM_002_NoOCSP(BaseRule):
    rule_id     = "NGX-MITM-002"
    description = "OCSP stapling not enabled — certificate revocation bypass possible (MITM)"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        violations = []
        if re.search(r"ssl_certificate\s+", config, re.I):
            if not _OCSP_ON_RE.search(config):
                violations.append(self._violation(
                    "ssl_stapling on; not found — attacker can use revoked cert"
                ))
            if not _OCSP_VERIFY_RE.search(config):
                violations.append(self._violation(
                    "ssl_stapling_verify on; not found — OCSP responses unverified"
                ))
        return violations


class NGX_MITM_003_NoSessionTicketRotation(BaseRule):
    rule_id     = "NGX-MITM-003"
    description = "SSL session tickets not disabled — session resumption attack surface (MITM)"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if re.search(r"ssl_certificate\s+", config, re.I):
            if not _SESSION_TICKET_RE.search(config):
                return [self._violation(
                    "ssl_session_tickets off; not found — tickets enable forward secrecy bypass"
                )]
        return []


class NGX_MITM_004_NoHSTSPreload(BaseRule):
    rule_id     = "NGX-MITM-004"
    description = "HSTS missing 'preload' directive — first-visit MITM downgrade possible"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if re.search(r"Strict-Transport-Security", config, re.I):
            if not _HSTS_PRELOAD_RE.search(config):
                return [self._violation(
                    "HSTS present but lacks 'preload' — browser not protected on first visit"
                )]
        return []


class NGX_MITM_005_MixedContentProxy(BaseRule):
    rule_id     = "NGX-MITM-005"
    description = "HTTPS frontend proxies to public HTTP backend — MITM on backend leg"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        violations = []
        for m in _PROXY_HTTP_RE.finditer(config):
            violations.append(self._violation(
                f"Backend connection unencrypted: {m.group(0).strip()}"
            ))
        return violations


class NGX_MITM_006_NoExpectCT(BaseRule):
    rule_id     = "NGX-MITM-006"
    description = "Expect-CT header missing — certificate transparency not enforced"
    severity    = Severity.LOW

    def check(self, config: str) -> list[Violation]:
        if re.search(r"ssl_certificate\s+", config, re.I):
            if not _CT_HEADER_RE.search(config):
                return [self._violation(
                    "Expect-CT header not set — misissued certs may go undetected"
                )]
        return []


class DNS_MITM_001_NoDNSSECSigning(BaseRule):
    rule_id     = "DNS-MITM-001"
    description = "DNSSEC signing not configured — zone responses can be forged (DNS MITM)"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if re.search(r"type\s+master", config, re.I):
            if not _DNSSEC_SIGN_RE.search(config):
                return [self._violation(
                    "Authoritative zone found but inline-signing not enabled — DNS spoofing possible"
                )]
        return []


class DNS_MITM_002_NoRPZ(BaseRule):
    rule_id     = "DNS-MITM-002"
    description = "Response Policy Zone (RPZ) not configured — no DNS-layer MITM C2 blocking"
    severity    = Severity.LOW

    def check(self, config: str) -> list[Violation]:
        if not _RPZ_RE.search(config):
            return [self._violation(
                "response-policy zone not configured — DNS-based C2 redirect attacks unblocked"
            )]
        return []


# ── Export ────────────────────────────────────────────────────────────────────

from config import ConfigTarget

MITM_NGINX_RULES: list[BaseRule] = [
    NGX_MITM_001_WeakCiphers(),
    NGX_MITM_002_NoOCSP(),
    NGX_MITM_003_NoSessionTicketRotation(),
    NGX_MITM_004_NoHSTSPreload(),
    NGX_MITM_005_MixedContentProxy(),
    NGX_MITM_006_NoExpectCT(),
]

MITM_DNS_RULES: list[BaseRule] = [
    DNS_MITM_001_NoDNSSECSigning(),
    DNS_MITM_002_NoRPZ(),
]

MITM_RULES_BY_TARGET: dict[ConfigTarget, list[BaseRule]] = {
    ConfigTarget.NGINX: MITM_NGINX_RULES,
    ConfigTarget.DNS:   MITM_DNS_RULES,
}
