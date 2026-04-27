"""
validator/rules_nginx.py
────────────────────────
Security rules for nginx configurations.

Rule catalogue
──────────────
NGX-001  No HTTP→HTTPS redirect present
NGX-002  SSL/TLS not configured
NGX-003  Weak or missing TLS protocol restriction
NGX-004  HSTS header missing
NGX-005  Server tokens not disabled (fingerprinting risk)
NGX-006  Sensitive security headers missing (X-Frame-Options, X-Content-Type-Options)
NGX-007  Proxy passing to a public / routable upstream (not localhost / RFC-1918)
NGX-008  autoindex enabled (directory listing)
NGX-009  Missing client_max_body_size (DoS risk on upload endpoints)
NGX-010  Admin/management location not restricted by allow/deny
"""

from __future__ import annotations
import re
from config import Severity, Violation
from .rules_base import BaseRule


# ---------------------------------------------------------------------------
# Helper patterns
# ---------------------------------------------------------------------------
_SSL_CERT_RE      = re.compile(r"ssl_certificate\s+", re.I)
_SSL_PROTO_RE     = re.compile(r"ssl_protocols\s+(.+?);", re.I)
_WEAK_PROTO_RE    = re.compile(r"\bTLSv1\b(?!\.)", re.I)  # TLSv1.0 or TLSv1.1 bare
_HTTP_LISTEN_RE   = re.compile(r"listen\s+(?!443)(\d+)(?!\s*ssl)", re.I)
_RETURN_301_RE    = re.compile(r"return\s+301\s+https://", re.I)
_HSTS_RE          = re.compile(r"Strict-Transport-Security", re.I)
_SERVER_TOKENS_RE = re.compile(r"server_tokens\s+off\s*;", re.I)
_XFRAME_RE        = re.compile(r"X-Frame-Options", re.I)
_XCTYPE_RE        = re.compile(r"X-Content-Type-Options", re.I)
_AUTOINDEX_RE     = re.compile(r"autoindex\s+on\s*;", re.I)
_PROXY_PASS_RE    = re.compile(r"proxy_pass\s+(https?://(.+?))(?:/|\s|;)", re.I)
# RFC-1918 + loopback
_PRIVATE_HOST_RE  = re.compile(
    r"^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", re.I
)
_ADMIN_LOC_RE     = re.compile(r"location\s+[~*\s]*/(?:admin|manage|status|metrics)", re.I)
_ALLOW_DENY_RE    = re.compile(r"\b(allow|deny)\s+", re.I)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class NGX001_NoHttpsRedirect(BaseRule):
    rule_id     = "NGX-001"
    description = "HTTP server block found without an HTTP→HTTPS redirect"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        violations = []
        # Find server blocks that listen on non-443 ports
        for block in _split_server_blocks(config):
            if _HTTP_LISTEN_RE.search(block) and not _RETURN_301_RE.search(block):
                # Only flag if there's no SSL cert (pure HTTP server, not a combined block)
                if not _SSL_CERT_RE.search(block):
                    evidence = _first_match_line(block, _HTTP_LISTEN_RE)
                    violations.append(self._violation(evidence))
        return violations


class NGX002_NoTLS(BaseRule):
    rule_id     = "NGX-002"
    description = "No SSL/TLS certificate configured — plaintext traffic possible"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if not _SSL_CERT_RE.search(config):
            return [self._violation("ssl_certificate directive not found in config")]
        return []


class NGX003_WeakTLSProtocol(BaseRule):
    rule_id     = "NGX-003"
    description = "Weak TLS protocol (TLSv1.0/1.1) enabled — should use TLSv1.2+"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        violations = []
        for m in _SSL_PROTO_RE.finditer(config):
            proto_line = m.group(1)
            if _WEAK_PROTO_RE.search(proto_line):
                violations.append(self._violation(f"ssl_protocols {proto_line}"))
        return violations


class NGX004_MissingHSTS(BaseRule):
    rule_id     = "NGX-004"
    description = "HSTS (Strict-Transport-Security) header not set"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if _SSL_CERT_RE.search(config) and not _HSTS_RE.search(config):
            return [self._violation("Strict-Transport-Security header not found")]
        return []


class NGX005_ServerTokens(BaseRule):
    rule_id     = "NGX-005"
    description = "server_tokens not disabled — nginx version fingerprinting risk"
    severity    = Severity.LOW

    def check(self, config: str) -> list[Violation]:
        if not _SERVER_TOKENS_RE.search(config):
            return [self._violation("server_tokens off; not present")]
        return []


class NGX006_MissingSecurityHeaders(BaseRule):
    rule_id     = "NGX-006"
    description = "Missing security headers: X-Frame-Options or X-Content-Type-Options"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        violations = []
        if not _XFRAME_RE.search(config):
            violations.append(self._violation("X-Frame-Options header not set"))
        if not _XCTYPE_RE.search(config):
            violations.append(self._violation("X-Content-Type-Options header not set"))
        return violations


class NGX007_PublicUpstreamProxy(BaseRule):
    rule_id     = "NGX-007"
    description = "proxy_pass targets a public/routable upstream (should use localhost/RFC-1918)"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        violations = []
        for m in _PROXY_PASS_RE.finditer(config):
            upstream = m.group(2)
            if not _PRIVATE_HOST_RE.search(upstream):
                violations.append(self._violation(f"proxy_pass {m.group(1)}"))
        return violations


class NGX008_AutoIndex(BaseRule):
    rule_id     = "NGX-008"
    description = "autoindex is enabled — directory listing exposes file system"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if _AUTOINDEX_RE.search(config):
            evidence = _first_match_line(config, _AUTOINDEX_RE)
            return [self._violation(evidence)]
        return []


class NGX010_UnrestrictedAdminLocation(BaseRule):
    rule_id     = "NGX-010"
    description = "Admin/metrics location block found without IP restriction (allow/deny)"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        violations = []
        for m in _ADMIN_LOC_RE.finditer(config):
            # Find the { … } block following this location
            start = m.end()
            block = _extract_block(config, start)
            if not _ALLOW_DENY_RE.search(block):
                violations.append(
                    self._violation(f"Location '{m.group(0).strip()}' has no allow/deny")
                )
        return violations


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _split_server_blocks(config: str) -> list[str]:
    """Naively split on 'server {' boundaries for per-block analysis."""
    blocks: list[str] = []
    depth  = 0
    start  = -1
    i      = 0
    while i < len(config):
        if config[i:i+7].lower() == "server " or config[i:i+7].lower() == "server{":
            if depth == 0:
                start = i
        if config[i] == "{":
            depth += 1
        elif config[i] == "}":
            depth -= 1
            if depth == 0 and start != -1:
                blocks.append(config[start : i + 1])
                start = -1
        i += 1
    return blocks or [config]  # fall back to whole config if no blocks found


def _extract_block(config: str, start: int) -> str:
    """Extract content of the { } block starting at *start*."""
    depth = 0
    i = start
    buf: list[str] = []
    while i < len(config):
        c = config[i]
        if c == "{":
            depth += 1
        elif c == "}":
            if depth == 1:
                break
            depth -= 1
        if depth > 0:
            buf.append(c)
        i += 1
    return "".join(buf)


def _first_match_line(text: str, pattern: re.Pattern) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    line_start = text.rfind("\n", 0, m.start()) + 1
    line_end   = text.find("\n", m.end())
    return text[line_start: line_end if line_end != -1 else None].strip()


# ---------------------------------------------------------------------------
# Export all rules
# ---------------------------------------------------------------------------
NGINX_RULES: list[BaseRule] = [
    NGX001_NoHttpsRedirect(),
    NGX002_NoTLS(),
    NGX003_WeakTLSProtocol(),
    NGX004_MissingHSTS(),
    NGX005_ServerTokens(),
    NGX006_MissingSecurityHeaders(),
    NGX007_PublicUpstreamProxy(),
    NGX008_AutoIndex(),
    NGX010_UnrestrictedAdminLocation(),
]
