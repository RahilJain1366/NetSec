"""
demo.py
───────
Demonstrates the full pipeline using pre-generated configs.
This script shows exactly what the live pipeline produces, without
requiring an API key — useful for CI, code review, and documentation.

Run: python demo.py
"""

from __future__ import annotations
import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))

from config import ConfigTarget, OUTPUT_DIR
from validator import ValidationEngine
from observability import setup_logging

# ── Pre-generated configs (as the LLM would produce) ────────────────────────

EXAMPLES = {

    "secure_nginx": {
        "label": "SECURE nginx — HTTPS-only API server",
        "target": ConfigTarget.NGINX,
        "expected_secure": True,
        "config": """
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;
    server_tokens off;

    ssl_certificate     /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5:!RC4;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /admin {
        allow 10.0.0.0/8;
        deny  all;
        proxy_pass http://127.0.0.1:8080;
    }
}
""".strip(),
    },

    "insecure_nginx": {
        "label": "INSECURE nginx — HTTP-only, directory listing, weak TLS",
        "target": ConfigTarget.NGINX,
        "expected_secure": False,
        "config": """
server {
    listen 80;
    server_name legacy.example.com;

    location /files/ {
        root /var/www;
        autoindex on;
    }

    location / {
        proxy_pass http://203.0.113.10:8080;
    }
}

server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/legacy.crt;
    ssl_certificate_key /etc/ssl/private/legacy.key;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

    location / {
        proxy_pass http://203.0.113.10:8080;
    }
}
""".strip(),
    },

    "secure_iptables": {
        "label": "SECURE iptables — web server, SSH restricted to mgmt subnet",
        "target": ConfigTarget.IPTABLES,
        "expected_secure": True,
        "config": """
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT  ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow established and related connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTP and HTTPS
-A INPUT -p tcp --dport 80  -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow SSH only from management network
-A INPUT -p tcp --dport 22 -s 10.0.1.0/24 -j ACCEPT

# Log and drop everything else
-A INPUT -j LOG --log-prefix "IPT-DROP: "
COMMIT
""".strip(),
    },

    "insecure_iptables": {
        "label": "INSECURE iptables — default ACCEPT, SSH+DB open to world, Telnet",
        "target": ConfigTarget.IPTABLES,
        "expected_secure": False,
        "config": """
*filter
:INPUT   ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT  ACCEPT [0:0]

-A INPUT -p tcp --dport 22   -j ACCEPT
-A INPUT -p tcp --dport 23   -j ACCEPT
-A INPUT -p tcp --dport 3306 -j ACCEPT
-A INPUT -p tcp --dport 5432 -j ACCEPT

COMMIT
""".strip(),
    },

    "secure_dns": {
        "label": "SECURE DNS — authoritative-only, rate-limited, version hidden",
        "target": ConfigTarget.DNS,
        "expected_secure": True,
        "config": """
options {
    directory "/var/named";
    recursion no;
    allow-query     { any; };
    allow-recursion { none; };
    allow-transfer  { none; };
    version         "not disclosed";
    rate-limit {
        responses-per-second 10;
        window 5;
        slip 2;
    };
    dnssec-validation auto;
};

zone "example.com" IN {
    type master;
    file "example.com.zone";
    allow-transfer { 192.0.2.10; };
};
""".strip(),
    },

    "insecure_dns": {
        "label": "INSECURE DNS — open resolver, zone transfer to anyone",
        "target": ConfigTarget.DNS,
        "expected_secure": False,
        "config": """
options {
    recursion yes;
    allow-recursion { any; };
    allow-transfer  { any; };
    allow-query     { any; };
};

zone "example.com" IN {
    type master;
    file "example.com.zone";
};
""".strip(),
    },
}


def run_demo() -> None:
    run_id = setup_logging()
    engine = ValidationEngine()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results = []
    sep = "═" * 70

    print(f"\n{sep}")
    print("  NETWORK CONFIG SECURITY PIPELINE — DEMO")
    print(f"  run_id = {run_id}")
    print(sep)

    for key, ex in EXAMPLES.items():
        target = ex["target"]
        config = ex["config"]
        label  = ex["label"]
        expected = ex["expected_secure"]

        print(f"\n{'─'*70}")
        print(f"  [{key.upper()}]  {label}")
        print(f"{'─'*70}")
        print("\n  Generated Config:")
        for line in config.splitlines():
            print(f"    {line}")

        result = engine.validate(config, target)

        print(f"\n  Validation Result:")
        print(f"    is_secure    : {result.is_secure}")
        print(f"    risk_score   : {result.risk_score:.3f}")
        correct = result.is_secure == expected
        status = "✓ CORRECT" if correct else "✗ INCORRECT"
        print(f"    expected     : {'secure' if expected else 'insecure'}  →  {status}")

        if result.violations:
            print(f"\n  Violations ({len(result.violations)}):")
            for v in sorted(result.violations, key=lambda x: x.severity.value):
                print(f"    [{v.severity.value:6s}] {v.rule_id:<10} {v.description}")
                print(f"             Evidence: {v.evidence}")
        else:
            print("\n  ✓ No violations found")

        results.append({
            "example_id":       key,
            "label":            label,
            "target":           target.value,
            "expected_secure":  expected,
            "predicted_secure": result.is_secure,
            "correct":          correct,
            "risk_score":       result.risk_score,
            "violations":       [v.to_dict() for v in result.violations],
            "config":           config,
        })

    # ── Summary ─────────────────────────────────────────────────────────
    total   = len(results)
    correct = sum(1 for r in results if r["correct"])
    print(f"\n{sep}")
    print(f"  DEMO SUMMARY")
    print(f"  {correct}/{total} predictions correct")
    print(sep + "\n")

    # Save
    out_path = os.path.join(OUTPUT_DIR, f"demo_{run_id}_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Results saved → {out_path}\n")

    return results


if __name__ == "__main__":
    run_demo()
