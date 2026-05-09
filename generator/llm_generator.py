"""
generator/llm_generator.py
──────────────────────────
LLM-backed configuration generator.

Design decisions
────────────────
• Low temperature (0.1) for near-deterministic output.
• Structured system prompt primes the model as a "secure config generator".
• Few-shot examples in the user turn show exactly what secure/insecure configs
  look like so the model has calibration signal.
• Output is extracted from a fenced code block; if absent we fall back to the
  raw response so the validator can still flag it.
• Retries on transient API errors (up to 3 attempts, exponential back-off).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Optional

import groq
from groq import Groq

from config import (
    GROQ_MODEL,
    LLM_MAX_TOKENS,
    LLM_TEMPERATURE,
    ConfigTarget,
    GenerationResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt — role + hard constraints
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """You are a production-grade network security configuration generator.

ROLE
────
Generate syntactically correct, minimal, security-hardened configurations for the
requested target (nginx / iptables / DNS).  Your output is consumed directly by a
deterministic validator; follow the constraints below exactly.

HARD CONSTRAINTS
────────────────
1. Output ONLY the raw configuration — no prose, no explanations, no markdown.
2. Wrap the configuration in a single fenced code block: ```<target>\n...\n```
3. Never expose services unnecessarily. Apply the principle of least privilege.
4. Always enforce TLS for any HTTPS endpoint.  Redirect HTTP → HTTPS.
5. Never use 0.0.0.0/0 for ACCEPT rules unless explicitly required and justified
   with an inline comment.
6. For SSH / admin ports, restrict to specific management CIDRs, never the world.
7. Prefer allowlist (whitelist) firewall posture: default DENY, explicit ALLOW.
8. Do not emit placeholder values like <YOUR_CERT> — use realistic dummy paths.

SECURITY DEFAULTS
─────────────────
• nginx  : TLS 1.2+, HSTS, X-Frame-Options, server_tokens off, HTTP→HTTPS redirect.
• iptables: default DROP on INPUT/FORWARD, stateful RELATED/ESTABLISHED, lo ACCEPT.
• DNS    : recursion disabled by default, rate-limiting, no CHAOS class exposure.
"""

# ---------------------------------------------------------------------------
# Few-shot examples per target
# ---------------------------------------------------------------------------
_FEW_SHOT: dict[ConfigTarget, str] = {

    ConfigTarget.NGINX: """
EXAMPLE — secure nginx config for an HTTPS API:
```nginx
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
    ssl_ciphers         HIGH:!aNULL:!MD5;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

EXAMPLE — INSECURE nginx config (DO NOT produce this):
```nginx
server {
    listen 80;
    server_name api.example.com;
    location / { proxy_pass http://backend; }   # No TLS, no redirect
}
```
""",

    ConfigTarget.IPTABLES: """
EXAMPLE — secure iptables ruleset (web server, SSH from mgmt only):
```iptables
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT  ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow established/related
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTP and HTTPS from anywhere
-A INPUT -p tcp --dport 80  -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow SSH only from management subnet
-A INPUT -p tcp --dport 22 -s 10.0.1.0/24 -j ACCEPT

# Drop all other inbound (default policy)
COMMIT
```

EXAMPLE — INSECURE iptables (DO NOT produce this):
```iptables
*filter
:INPUT   ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT  # SSH open to world
COMMIT
```
""",

    ConfigTarget.DNS: """
EXAMPLE — secure BIND named.conf (authoritative + rate-limit, no recursion):
```dns
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
    };
};

zone "example.com" IN {
    type master;
    file "example.com.zone";
    allow-transfer { 192.0.2.10; };   # secondary NS only
};
```

EXAMPLE — INSECURE DNS (DO NOT produce this):
```dns
options {
    recursion yes;
    allow-recursion { any; };         # open resolver — dangerous
};
```
""",
}


# ---------------------------------------------------------------------------
# Generator class
# ---------------------------------------------------------------------------

class LLMConfigGenerator:
    """
    Wraps Anthropic API calls to produce network configuration artifacts.

    Parameters
    ──────────
    model       : Anthropic model string
    temperature : Sampling temperature (low = more deterministic)
    max_tokens  : Token budget for generated config
    max_retries : Number of retry attempts on transient failures
    """

    def __init__(
        self,
        model: str = GROQ_MODEL,
        temperature: float = LLM_TEMPERATURE,
        max_tokens: int = LLM_MAX_TOKENS,
        max_retries: int = 3,
    ) -> None:
        self.client      = Groq()  # reads ANTHROPIC_API_KEY from env
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.max_retries = max_retries

    # ------------------------------------------------------------------
    def generate(self, prompt: str, target: ConfigTarget) -> GenerationResult:
        """
        Generate a configuration for *target* based on the natural-language *prompt*.
        Returns a GenerationResult with the raw config text (or error details).
        """
        user_message = self._build_user_message(prompt, target)
        logger.info("Generating %s config | prompt=%.80s…", target.value, prompt)

        raw_response: Optional[str] = None
        last_error:   Optional[str] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[ {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user",   "content": user_message},],
                )
                raw_response = response.choices[0].message.content
                logger.debug("LLM raw response (attempt %d):\n%s", attempt, raw_response)
                break

            except groq.RateLimitError as exc:
                wait = 2 ** attempt
                logger.warning("Rate-limit hit; retrying in %ds (%s)", wait, exc)
                time.sleep(wait)
                last_error = str(exc)

            except groq.APIError as exc:
                logger.error("API error on attempt %d: %s", attempt, exc)
                last_error = str(exc)
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)

        if raw_response is None:
            return GenerationResult(
                prompt=prompt,
                target=target,
                raw_config="",
                model=self.model,
                temperature=self.temperature,
                success=False,
                error=last_error or "Unknown error after all retries",
            )

        config_text = self._extract_config(raw_response, target)
        return GenerationResult(
            prompt=prompt,
            target=target,
            raw_config=config_text,
            model=self.model,
            temperature=self.temperature,
            success=True,
        )

    # ------------------------------------------------------------------
    def _build_user_message(self, prompt: str, target: ConfigTarget) -> str:
        few_shot = _FEW_SHOT.get(target, "")
        return (
            f"{few_shot}\n"
            f"NOW GENERATE — Target: {target.value}\n"
            f"Policy / requirements:\n{prompt}\n\n"
            f"Produce ONLY the {target.value} configuration inside a fenced code block."
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_config(response: str, target: ConfigTarget) -> str:
        """
        Extract the configuration text from a fenced code block.

        Tries (in order):
        1. ```<target_name> … ``` block
        2. Any ``` … ``` block
        3. Raw response as fallback (lets the validator catch malformed output)
        """
        # Try target-specific fence first
        pattern_specific = re.compile(
            rf"```{re.escape(target.value)}\s*\n(.*?)```",
            re.DOTALL | re.IGNORECASE,
        )
        m = pattern_specific.search(response)
        if m:
            return m.group(1).strip()

        # Generic fenced block
        pattern_generic = re.compile(r"```[a-z]*\s*\n(.*?)```", re.DOTALL)
        m = pattern_generic.search(response)
        if m:
            logger.warning("Used generic code fence fallback for target=%s", target.value)
            return m.group(1).strip()

        # Last resort: raw text (may trigger validator to flag hallucinated configs)
        logger.warning(
            "No fenced block found for target=%s; using raw response", target.value
        )
        return response.strip()
