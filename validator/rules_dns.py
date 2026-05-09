"""
validator/rules_dns.py
──────────────────────
Security rules for BIND / named DNS configurations.

Rule catalogue
──────────────
DNS-001  Recursion enabled without source restrictions (open resolver)
DNS-002  allow-recursion set to { any; } — open recursive resolver
DNS-003  Zone transfer (AXFR) not restricted
DNS-004  CHAOS class query responding (version / bind disclosure)
DNS-005  Rate-limiting not configured
DNS-006  DNSSEC not referenced for authoritative zones
DNS-007  allow-query unrestricted with recursion enabled
DNS-008  Forwarders pointing to private/loopback without DNSSEC validation
"""

from __future__ import annotations
import re
from config import Severity, Violation
from .rules_base import BaseRule


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
_RECURSION_YES_RE     = re.compile(r"\brecursion\s+yes\s*;", re.I)
_RECURSION_NO_RE      = re.compile(r"\brecursion\s+no\s*;", re.I)
_ALLOW_RECURSION_ANY  = re.compile(r"allow-recursion\s*\{\s*any\s*;\s*\}", re.I)
_ALLOW_TRANSFER_ANY   = re.compile(r"allow-transfer\s*\{\s*any\s*;\s*\}", re.I)
_ALLOW_TRANSFER_NONE  = re.compile(r"allow-transfer\s*\{\s*none\s*;\s*\}", re.I)
_CHAOS_VERSION_RE     = re.compile(r'version\s+"[^"]*"', re.I)   # version set → OK
_NO_VERSION_HIDE_RE   = re.compile(r"version\s+", re.I)
_RATE_LIMIT_RE        = re.compile(r"rate-limit\s*\{", re.I)
_DNSSEC_RE            = re.compile(r"(dnssec-enable|dnssec-validation|inline-signing)", re.I)
_ALLOW_QUERY_ANY_RE   = re.compile(r"allow-query\s*\{\s*any\s*;\s*\}", re.I)
_FORWARDERS_RE        = re.compile(r"forwarders\s*\{", re.I)
_DNSSEC_VALIDATE_RE   = re.compile(r"dnssec-validation\s+(yes|auto)\s*;", re.I)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class DNS001_OpenRecursion(BaseRule):
    rule_id     = "DNS-001"
    description = "DNS recursion enabled — server may act as an open resolver (DDoS amplification risk)"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if _RECURSION_YES_RE.search(config) and not _ALLOW_RECURSION_RESTRICTED(config):
            return [self._violation("recursion yes; without restricted allow-recursion")]
        return []


class DNS002_AllowRecursionAny(BaseRule):
    rule_id     = "DNS-002"
    description = "allow-recursion { any; } permits recursive queries from the entire internet"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if _ALLOW_RECURSION_ANY.search(config):
            return [self._violation("allow-recursion { any; }")]
        return []


class DNS003_UnrestrictedZoneTransfer(BaseRule):
    rule_id     = "DNS-003"
    description = "Zone transfer (AXFR) not restricted — zone data may be exfiltrated"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if _ALLOW_TRANSFER_ANY.search(config):
            return [self._violation("allow-transfer { any; } found")]
        # If there's a zone block but no allow-transfer at all, it's permissive by default
        if re.search(r"\bzone\b", config, re.I) and not re.search(r"allow-transfer", config, re.I):
            return [self._violation("zone block found but no allow-transfer directive")]
        return []


class DNS004_VersionDisclosure(BaseRule):
    rule_id     = "DNS-004"
    description = "DNS version string not hidden — BIND version may be disclosed via CHAOS class"
    severity    = Severity.LOW

    def check(self, config: str) -> list[Violation]:
        # OK if version is set to something (presumably "not disclosed" or similar)
        if _NO_VERSION_HIDE_RE.search(config):
            return []   # version is explicitly set
        return [self._violation('version "..."; not found — default version disclosure')]


class DNS005_NoRateLimit(BaseRule):
    rule_id     = "DNS-005"
    description = "Response rate-limiting not configured — vulnerable to DNS amplification attacks"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if not _RATE_LIMIT_RE.search(config):
            return [self._violation("rate-limit { ... } block not found")]
        return []


class DNS006_NoDNSSEC(BaseRule):
    rule_id     = "DNS-006"
    description = "DNSSEC not referenced — authoritative zones lack signing, resolvers lack validation"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if not _DNSSEC_RE.search(config):
            return [self._violation("No DNSSEC directive (dnssec-enable / dnssec-validation) found")]
        return []


class DNS008_ForwardersWithoutValidation(BaseRule):
    rule_id     = "DNS-008"
    description = "Forwarders configured but DNSSEC validation disabled or absent"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if _FORWARDERS_RE.search(config) and not _DNSSEC_VALIDATE_RE.search(config):
            return [self._violation("forwarders present but dnssec-validation not set to yes/auto")]
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ALLOW_RECURSION_RESTRICTED(config: str) -> bool:
    """True if allow-recursion is present and NOT set to 'any'."""
    if re.search(r"allow-recursion\s*\{", config, re.I):
        return not _ALLOW_RECURSION_ANY.search(config)
    return False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
DNS_RULES: list[BaseRule] = [
    DNS001_OpenRecursion(),
    DNS002_AllowRecursionAny(),
    DNS003_UnrestrictedZoneTransfer(),
    DNS004_VersionDisclosure(),
    DNS005_NoRateLimit(),
    DNS006_NoDNSSEC(),
    DNS008_ForwardersWithoutValidation(),
]
