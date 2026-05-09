"""
validator/rules_iptables.py
───────────────────────────
Security rules for iptables configurations.

Rule catalogue
──────────────
IPT-001  Default INPUT policy is not DROP
IPT-002  Default FORWARD policy is not DROP
IPT-003  SSH (port 22) allowed from 0.0.0.0/0 (world)
IPT-004  No ESTABLISHED/RELATED stateful rule
IPT-005  Unrestricted ACCEPT on all ports from any source (0.0.0.0/0 wildcard)
IPT-006  Telnet (port 23) open — cleartext protocol
IPT-007  RDP (port 3389) exposed to 0.0.0.0/0
IPT-008  Database ports (3306/5432/27017) exposed to 0.0.0.0/0
IPT-009  ICMP completely blocked (breaks path MTU discovery)
IPT-010  Loopback interface not explicitly permitted
"""

from __future__ import annotations
import re
from config import Severity, Violation
from .rules_base import BaseRule


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
_INPUT_POLICY_RE    = re.compile(r":INPUT\s+(ACCEPT|DROP|REJECT)", re.I)
_FORWARD_POLICY_RE  = re.compile(r":FORWARD\s+(ACCEPT|DROP|REJECT)", re.I)
_ESTAB_RE           = re.compile(r"--state\s+(?:ESTABLISHED,RELATED|RELATED,ESTABLISHED)", re.I)
_LOOPBACK_RE        = re.compile(r"-A INPUT -i lo -j ACCEPT", re.I)
_ICMP_DROP_RE       = re.compile(r"-A INPUT -p icmp -j DROP", re.I)

# Matches rules like: -A INPUT -p tcp --dport 22 -j ACCEPT  (no -s restriction)
def _open_port_pattern(port: int) -> re.Pattern:
    return re.compile(
        rf"-A INPUT (?!.*-s\s).*--dport\s+{port}\s+.*-j ACCEPT",
        re.I,
    )

_SSH_OPEN_RE    = _open_port_pattern(22)
_TELNET_RE      = _open_port_pattern(23)
_RDP_RE         = _open_port_pattern(3389)
_MYSQL_RE       = _open_port_pattern(3306)
_POSTGRES_RE    = _open_port_pattern(5432)
_MONGO_RE       = _open_port_pattern(27017)

# Wildcard accept: -A INPUT -j ACCEPT (no conditions)
_WILDCARD_ACCEPT_RE = re.compile(r"-A INPUT\s+-j ACCEPT\s*$", re.I | re.MULTILINE)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class IPT001_DefaultInputNotDrop(BaseRule):
    rule_id     = "IPT-001"
    description = "Default INPUT chain policy is not DROP — allows unrestricted inbound traffic"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        m = _INPUT_POLICY_RE.search(config)
        if not m or m.group(1).upper() != "DROP":
            policy = m.group(1) if m else "not set"
            return [self._violation(f":INPUT policy is {policy}")]
        return []


class IPT002_DefaultForwardNotDrop(BaseRule):
    rule_id     = "IPT-002"
    description = "Default FORWARD chain policy is not DROP — risk of transit traffic abuse"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        m = _FORWARD_POLICY_RE.search(config)
        if not m or m.group(1).upper() != "DROP":
            policy = m.group(1) if m else "not set"
            return [self._violation(f":FORWARD policy is {policy}")]
        return []


class IPT003_SSHOpenToWorld(BaseRule):
    rule_id     = "IPT-003"
    description = "SSH (port 22) is permitted from any source — administrative access is exposed globally"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if _SSH_OPEN_RE.search(config):
            evidence = _first_match(config, _SSH_OPEN_RE)
            return [self._violation(evidence)]
        return []


class IPT004_NoStatefulRule(BaseRule):
    rule_id     = "IPT-004"
    description = "No ESTABLISHED/RELATED stateful connection tracking rule found"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if not _ESTAB_RE.search(config):
            return [self._violation("--state ESTABLISHED,RELATED rule not found")]
        return []


class IPT005_WildcardAccept(BaseRule):
    rule_id     = "IPT-005"
    description = "Unconditional ACCEPT rule found — grants unrestricted access to INPUT chain"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        violations = []
        for m in _WILDCARD_ACCEPT_RE.finditer(config):
            violations.append(self._violation(m.group(0).strip()))
        return violations


class IPT006_TelnetOpen(BaseRule):
    rule_id     = "IPT-006"
    description = "Telnet (port 23) is permitted — cleartext protocol, use SSH instead"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if _TELNET_RE.search(config):
            return [self._violation(_first_match(config, _TELNET_RE))]
        return []


class IPT007_RDPOpenToWorld(BaseRule):
    rule_id     = "IPT-007"
    description = "RDP (port 3389) exposed to 0.0.0.0/0 — brute-force and exploitation risk"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        if _RDP_RE.search(config):
            return [self._violation(_first_match(config, _RDP_RE))]
        return []


class IPT008_DatabasePortsExposed(BaseRule):
    rule_id     = "IPT-008"
    description = "Database port (MySQL/Postgres/MongoDB) exposed to 0.0.0.0/0"
    severity    = Severity.HIGH

    def check(self, config: str) -> list[Violation]:
        violations = []
        for pattern, name in [(_MYSQL_RE, "MySQL/3306"), (_POSTGRES_RE, "Postgres/5432"), (_MONGO_RE, "MongoDB/27017")]:
            if pattern.search(config):
                violations.append(self._violation(f"{name}: {_first_match(config, pattern)}"))
        return violations


class IPT010_NoLoopback(BaseRule):
    rule_id     = "IPT-010"
    description = "Loopback interface (lo) not explicitly permitted — may break local services"
    severity    = Severity.MEDIUM

    def check(self, config: str) -> list[Violation]:
        if not _LOOPBACK_RE.search(config):
            return [self._violation("-A INPUT -i lo -j ACCEPT rule not found")]
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _first_match(text: str, pattern: re.Pattern) -> str:
    m = pattern.search(text)
    return m.group(0).strip() if m else ""


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
IPTABLES_RULES: list[BaseRule] = [
    IPT001_DefaultInputNotDrop(),
    IPT002_DefaultForwardNotDrop(),
    IPT003_SSHOpenToWorld(),
    IPT004_NoStatefulRule(),
    IPT005_WildcardAccept(),
    IPT006_TelnetOpen(),
    IPT007_RDPOpenToWorld(),
    IPT008_DatabasePortsExposed(),
    IPT010_NoLoopback(),
]
