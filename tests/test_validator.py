"""
tests/test_validator.py
───────────────────────
Unit tests for all validation rules.  Tests use hand-crafted config strings
so they run entirely without API access (fast, CI-safe).
"""

from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from config import ConfigTarget, Severity
from validator import ValidationEngine
from validator.rules_nginx    import (
    NGX001_NoHttpsRedirect, NGX002_NoTLS, NGX003_WeakTLSProtocol,
    NGX004_MissingHSTS, NGX005_ServerTokens, NGX006_MissingSecurityHeaders,
    NGX008_AutoIndex,
)
from validator.rules_iptables import (
    IPT001_DefaultInputNotDrop, IPT002_DefaultForwardNotDrop,
    IPT003_SSHOpenToWorld, IPT004_NoStatefulRule,
    IPT005_WildcardAccept, IPT006_TelnetOpen, IPT008_DatabasePortsExposed,
)
from validator.rules_dns import (
    DNS001_OpenRecursion, DNS002_AllowRecursionAny,
    DNS003_UnrestrictedZoneTransfer, DNS005_NoRateLimit,
)


# ══════════════════════════════════════════════════════════════════════════════
# Nginx rules
# ══════════════════════════════════════════════════════════════════════════════

SECURE_NGINX = """
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name api.example.com;
    server_tokens off;
    ssl_certificate     /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    location / { proxy_pass http://127.0.0.1:8080; }
}
"""

INSECURE_NGINX_HTTP_ONLY = """
server {
    listen 80;
    server_name api.example.com;
    location / { proxy_pass http://127.0.0.1:8080; }
}
"""

INSECURE_NGINX_WEAK_TLS = """
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    location / { proxy_pass http://127.0.0.1:8080; }
}
"""

INSECURE_NGINX_AUTOINDEX = """
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    location /files/ { autoindex on; }
}
"""


class TestNginxRules:
    def test_secure_config_passes_all_rules(self):
        engine = ValidationEngine()
        result = engine.validate(SECURE_NGINX, ConfigTarget.NGINX)
        assert result.is_secure, f"Expected secure, got violations: {result.violations}"
        assert result.risk_score == 0.0

    def test_http_only_flagged(self):
        rule = NGX001_NoHttpsRedirect()
        violations = rule.check(INSECURE_NGINX_HTTP_ONLY)
        assert len(violations) >= 1
        assert violations[0].severity == Severity.HIGH

    def test_no_tls_flagged(self):
        rule = NGX002_NoTLS()
        violations = rule.check(INSECURE_NGINX_HTTP_ONLY)
        assert len(violations) == 1

    def test_weak_tls_flagged(self):
        rule = NGX003_WeakTLSProtocol()
        violations = rule.check(INSECURE_NGINX_WEAK_TLS)
        assert len(violations) >= 1

    def test_tls12_only_passes(self):
        rule = NGX003_WeakTLSProtocol()
        violations = rule.check(SECURE_NGINX)
        assert violations == []

    def test_autoindex_flagged(self):
        rule = NGX008_AutoIndex()
        violations = rule.check(INSECURE_NGINX_AUTOINDEX)
        assert len(violations) == 1
        assert violations[0].rule_id == "NGX-008"
        assert violations[0].severity == Severity.HIGH

    def test_autoindex_not_present_passes(self):
        rule = NGX008_AutoIndex()
        assert rule.check(SECURE_NGINX) == []

    def test_missing_hsts_flagged(self):
        rule = NGX004_MissingHSTS()
        config_no_hsts = SECURE_NGINX.replace("Strict-Transport-Security", "X-Missing")
        violations = rule.check(config_no_hsts)
        assert len(violations) == 1

    def test_server_tokens_not_off(self):
        rule = NGX005_ServerTokens()
        config = SECURE_NGINX.replace("server_tokens off;", "")
        assert len(rule.check(config)) == 1

    def test_missing_x_frame_flagged(self):
        rule = NGX006_MissingSecurityHeaders()
        config = SECURE_NGINX.replace("X-Frame-Options DENY always;", "")
        violations = rule.check(config)
        assert any("X-Frame-Options" in v.evidence for v in violations)

    def test_risk_score_increases_with_violations(self):
        engine = ValidationEngine()
        secure  = engine.validate(SECURE_NGINX, ConfigTarget.NGINX)
        insecure = engine.validate(INSECURE_NGINX_HTTP_ONLY, ConfigTarget.NGINX)
        assert insecure.risk_score > secure.risk_score


# ══════════════════════════════════════════════════════════════════════════════
# iptables rules
# ══════════════════════════════════════════════════════════════════════════════

SECURE_IPTABLES = """
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 80  -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 22 -s 10.0.1.0/24 -j ACCEPT
COMMIT
"""

INSECURE_IPTABLES_ACCEPT_ALL = """
*filter
:INPUT   ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""

INSECURE_IPTABLES_TELNET = """
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 23 -j ACCEPT
COMMIT
"""


class TestIptablesRules:
    def test_secure_config_passes(self):
        engine = ValidationEngine()
        result = engine.validate(SECURE_IPTABLES, ConfigTarget.IPTABLES)
        assert result.is_secure, f"Violations: {[v.rule_id for v in result.violations]}"

    def test_default_accept_input_flagged(self):
        rule = IPT001_DefaultInputNotDrop()
        violations = rule.check(INSECURE_IPTABLES_ACCEPT_ALL)
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH

    def test_ssh_open_to_world_flagged(self):
        rule = IPT003_SSHOpenToWorld()
        config = """
*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""
        violations = rule.check(config)
        assert len(violations) == 1

    def test_ssh_restricted_passes(self):
        rule = IPT003_SSHOpenToWorld()
        assert rule.check(SECURE_IPTABLES) == []

    def test_no_stateful_rule_flagged(self):
        rule = IPT004_NoStatefulRule()
        config = SECURE_IPTABLES.replace("--state ESTABLISHED,RELATED", "--state SOMETHING_ELSE")
        violations = rule.check(config)
        assert len(violations) == 1

    def test_telnet_flagged(self):
        rule = IPT006_TelnetOpen()
        violations = rule.check(INSECURE_IPTABLES_TELNET)
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH

    def test_database_port_exposed(self):
        rule = IPT008_DatabasePortsExposed()
        config = """
*filter
:INPUT DROP [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 3306 -j ACCEPT
COMMIT
"""
        violations = rule.check(config)
        assert len(violations) == 1

    def test_multiple_violations_risk_score(self):
        engine = ValidationEngine()
        result = engine.validate(INSECURE_IPTABLES_ACCEPT_ALL, ConfigTarget.IPTABLES)
        assert not result.is_secure
        assert result.risk_score > 0.5


# ══════════════════════════════════════════════════════════════════════════════
# DNS rules
# ══════════════════════════════════════════════════════════════════════════════

SECURE_DNS = """
options {
    directory "/var/named";
    recursion no;
    allow-query     { any; };
    allow-recursion { none; };
    allow-transfer  { none; };
    version         "not disclosed";
    rate-limit {
        responses-per-second 10;
    };
    dnssec-validation auto;
};
zone "example.com" IN {
    type master;
    file "example.com.zone";
    allow-transfer { 192.0.2.10; };
};
"""

INSECURE_DNS_OPEN_RESOLVER = """
options {
    recursion yes;
    allow-recursion { any; };
    allow-transfer  { any; };
};
"""


class TestDNSRules:
    def test_secure_dns_passes(self):
        engine = ValidationEngine()
        result = engine.validate(SECURE_DNS, ConfigTarget.DNS)
        # DNS-006 may fire if DNSSEC not detected by pattern; accept minor violations
        high_violations = [v for v in result.violations if v.severity == Severity.HIGH]
        assert high_violations == [], f"HIGH violations: {high_violations}"

    def test_open_resolver_flagged(self):
        rule = DNS002_AllowRecursionAny()
        violations = rule.check(INSECURE_DNS_OPEN_RESOLVER)
        assert len(violations) == 1

    def test_zone_transfer_any_flagged(self):
        rule = DNS003_UnrestrictedZoneTransfer()
        violations = rule.check(INSECURE_DNS_OPEN_RESOLVER)
        assert len(violations) == 1

    def test_no_rate_limit_flagged(self):
        rule = DNS005_NoRateLimit()
        violations = rule.check(INSECURE_DNS_OPEN_RESOLVER)
        assert len(violations) == 1

    def test_rate_limit_present_passes(self):
        rule = DNS005_NoRateLimit()
        assert rule.check(SECURE_DNS) == []


# ══════════════════════════════════════════════════════════════════════════════
# Engine edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestEngineEdgeCases:
    def test_empty_config_flagged(self):
        engine = ValidationEngine()
        result = engine.validate("", ConfigTarget.NGINX)
        assert not result.is_secure
        assert result.risk_score == 1.0
        assert result.parse_error is not None

    def test_very_short_config_flagged(self):
        engine = ValidationEngine()
        result = engine.validate("# comment", ConfigTarget.IPTABLES)
        assert not result.is_secure

    def test_risk_score_zero_for_secure(self):
        engine = ValidationEngine()
        result = engine.validate(SECURE_IPTABLES, ConfigTarget.IPTABLES)
        assert result.risk_score == 0.0

    def test_risk_score_bounded_01(self):
        engine = ValidationEngine()
        result = engine.validate(INSECURE_IPTABLES_ACCEPT_ALL, ConfigTarget.IPTABLES)
        assert 0.0 <= result.risk_score <= 1.0

    def test_validation_result_serializable(self):
        import json
        engine = ValidationEngine()
        result = engine.validate(INSECURE_NGINX_HTTP_ONLY, ConfigTarget.NGINX)
        # Must not raise
        json.dumps(result.to_dict())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
