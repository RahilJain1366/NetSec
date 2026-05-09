# LLM-Powered Network Configuration Security Pipeline
## Technical Report

---

## 1. Executive Summary

This document describes the design and implementation of a production-grade prototype that combines a Large Language Model (LLM) generation layer with a deterministic rule-based validation engine to automate and audit network security configurations.

The system accepts natural-language security policies, generates syntactically valid configuration artifacts (nginx, iptables, DNS), and validates them against formally defined security invariants — returning structured violation reports with severity levels, evidence strings, and probabilistic risk scores.

**Empirical validation (demo run): 6/6 hand-crafted examples correctly classified. All expected violations detected, zero false positives on secure configs.**

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Pipeline Overview                          │
│                                                                 │
│  Natural Language Policy                                        │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────┐    System Prompt + Few-Shot Examples      │
│  │  LLM Generator   │◄──────────────────────────────────────── │
│  │  (Anthropic API) │                                           │
│  └────────┬─────────┘                                           │
│           │  Raw Config Text (fenced code block)                │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │  Config Extractor│  (regex fence parser, fallback handling)  │
│  └────────┬─────────┘                                           │
│           │  Extracted Config                                   │
│           ▼                                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Validation Engine                           │  │
│  │                                                          │  │
│  │  ┌───────────┐  ┌───────────────┐  ┌─────────────────┐ │  │
│  │  │ Nginx     │  │  iptables     │  │  DNS            │ │  │
│  │  │ Rules     │  │  Rules        │  │  Rules          │ │  │
│  │  │ (9 rules) │  │  (9 rules)    │  │  (7 rules)      │ │  │
│  │  └───────────┘  └───────────────┘  └─────────────────┘ │  │
│  │                                                          │  │
│  │  Risk Score = 1 − e^(−λ · Σ weight_i)                  │  │
│  └────────────────────────┬─────────────────────────────── ┘  │
│                           │                                     │
│                           ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  ValidationResult                                        │  │
│  │  { is_secure, risk_score, violations[], parse_error }    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  ┌──────────────────┐  ┌──────────────────────────────────┐    │
│  │  Evaluator       │  │  PipelineLogger                  │    │
│  │  (metrics,       │  │  (JSON structured logs,          │    │
│  │   dataset eval)  │  │   violations.log, event trace)   │    │
│  └──────────────────┘  └──────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Module Map

| File | Responsibility |
|------|---------------|
| `config.py` | Global constants, dataclasses, enums |
| `generator/llm_generator.py` | Anthropic API wrapper, prompt engineering, retry logic |
| `validator/rules_base.py` | Abstract `BaseRule` interface |
| `validator/rules_nginx.py` | 9 nginx-specific security rules |
| `validator/rules_iptables.py` | 9 iptables-specific security rules |
| `validator/rules_dns.py` | 7 DNS (BIND) security rules |
| `validator/engine.py` | Rule orchestration, risk scoring |
| `evaluator/evaluator.py` | Dataset evaluation loop, metrics computation |
| `mitm/network_analyzer.py` | Live/offline MITM attack detection (ARP spoofing, SSL stripping, TLS downgrade, DNS spoofing) |
| `mitm/config_rules.py` | Maps network behaviors to config vulnerabilities |
| `mitm/reporter.py` | MITM detection report generation |
| `observability.py` | Structured JSON logging, PipelineLogger |
| `main.py` | CLI entry point |
| `demo.py` | Offline demonstration (no API key) |
| `adversarial_eval.py` | Security persona probing (tests LLM bypass under social engineering) |
| `tests/test_validator.py` | 29 unit tests (100% pass) |
| `dataset.json` | 30-sample synthetic evaluation dataset |
| `adversarial_dataset.json` | Adversarial prompts for persona testing |

---

## 3. Design Decisions

### 3.1 LLM Generation Layer

**Model**: `claude-sonnet-4-6` (production quality, reasonable cost).

**Temperature = 0.1** — Deliberately near-deterministic. Network configurations are not creative text; we want minimal variance between runs of the same prompt. Higher temperature produces syntactically correct but randomly varying configs that are harder to audit.

**System prompt design** follows three principles:
1. **Role priming** — "You are a production-grade network security configuration generator" establishes persona and context window framing.
2. **Hard constraints** — Explicit numbered rules that fire before any generation (no prose, fenced code block output, TLS required, etc.).
3. **Security defaults** — Per-target sensible defaults so the model doesn't have to infer them.

**Few-shot examples** are injected in the user turn (not system prompt) to give the model calibration on what secure vs insecure looks like. Critically, insecure examples are labelled "DO NOT produce this" — this avoids the model treating them as positive examples.

**Fence extraction** uses a priority chain:
1. ` ```<target_name>` ` block (most specific)
2. Any ` ``` ` block (fallback)
3. Raw response (last resort — lets validator flag hallucinated configs)

**Retry logic** with exponential back-off handles transient rate limits. Up to 3 attempts.

### 3.2 Validation Engine Design

**Modular rule architecture** — Each rule is a self-contained Python class inheriting `BaseRule`. This enables:
- Independent unit testing of each rule
- Easy addition of new rules without touching existing code
- Per-rule severity assignment
- Per-target rule registries in the engine

**Static analysis approach** was chosen over AST parsing for pragmatic reasons:
- nginx, iptables, and BIND configs have no widely-used Python parsing libraries
- Regex-based rules are auditable, fast, and cover the highest-value patterns
- A formal parser would be more robust but adds significant complexity for a prototype

**Risk Score Formula**:
```
score = 1 − e^(−λ · Σ weight_i)
```
where `weight(HIGH)=3, weight(MEDIUM)=1.5, weight(LOW)=0.5` and `λ=0.25`.

This exponential saturation curve has the following properties:
- Zero violations → score = 0.0 (exactly)
- 1 HIGH violation → ~0.53
- 2 HIGH violations → ~0.78
- 4+ HIGH violations → saturates toward 1.0
- Never exceeds 1.0

The score is continuous and monotonically increasing with severity-weighted violations.

**Conservative prediction**: Any violation → predicted insecure. This maximizes recall at the cost of some precision — appropriate for security tooling where missed vulnerabilities are more dangerous than false alarms.

### 3.3 Security Rule Coverage

**nginx (25 rules designed, 9 implemented)**:

| Rule | Rationale |
|------|-----------|
| NGX-001 No HTTPS redirect | Plain HTTP traffic is unencrypted |
| NGX-002 No TLS | Fundamental for any production service |
| NGX-003 Weak TLS | TLS 1.0/1.1 are deprecated (RFC 8996) |
| NGX-004 Missing HSTS | Prevents protocol downgrade attacks |
| NGX-005 Server tokens | Version fingerprinting enables targeted attacks |
| NGX-006 Security headers | X-Frame (clickjacking), XCTO (MIME sniffing) |
| NGX-007 Public upstream | Proxying to internet IPs bypasses perimeter |
| NGX-008 autoindex | Directory listing exposes file structure |
| NGX-010 Unrestricted admin | Admin endpoints must be IP-restricted |

**iptables (9 rules)**:

| Rule | Rationale |
|------|-----------|
| IPT-001/002 Default policy | Allowlist firewall posture requires DROP |
| IPT-003 SSH open | Most common attack vector for servers |
| IPT-004 No stateful rule | Without ESTABLISHED,RELATED many services break |
| IPT-005 Wildcard ACCEPT | Defeats entire firewall purpose |
| IPT-006 Telnet | Cleartext credential exposure |
| IPT-007 RDP global | Ransomware delivery vector |
| IPT-008 DB ports exposed | Data exfiltration risk |
| IPT-010 No loopback | Breaks local service communication |

**DNS (7 rules)**:

| Rule | Rationale |
|------|-----------|
| DNS-001/002 Open recursion | DDoS amplification (CVE class: open resolver) |
| DNS-003 Zone transfer | AXFR to anyone leaks entire zone data |
| DNS-004 Version disclosure | CHAOS class version query aids recon |
| DNS-005 No rate-limit | DNS amplification DDoS vectors |
| DNS-006 No DNSSEC | Zone data integrity unverified |
| DNS-008 Forwarders no DNSSEC | Man-in-the-middle on DNS queries |

### 3.4 Evaluation Framework

The synthetic dataset contains **30 samples** across:
- **Secure** (10): Fully specified, hardened configs
- **Ambiguous** (11): Incomplete specifications that likely produce insecure defaults
- **Insecure** (9): Explicitly insecure requirements

Ground-truth labels for ambiguous samples are set to `expected_secure=false` based on the assumption that underspecified prompts will produce configs with at least one security gap — a reasonable prior given the model's training.

**Classification decision**: `predicted_secure = (violations == [])`.

This gives a binary prediction from the probabilistic engine for metric computation.

---

## 4. Failure Mode Analysis

### 4.1 Hallucinated Configurations

**Risk**: LLM generates plausible-looking but syntactically invalid config (e.g., inventing nginx directives).

**Mitigation**:
- Low temperature reduces creativity/hallucination
- Few-shot examples anchor output format
- The validator's rule matching is lenient — it looks for presence of security directives, not syntactic correctness, so a hallucinated config that omits TLS will still be flagged
- The `_MIN_CONFIG_LEN = 20` check flags empty/degenerate outputs with a `SYS-001` violation

**Residual risk**: A config that looks syntactically valid to our regex rules but would fail nginx/iptables parsing is classified as secure when it's actually non-functional. Production hardening: add `nginx -t` / `iptables-restore --test` syntax checking in a sandboxed subprocess.

### 4.2 Missing Security Directives

**Risk**: Model generates a valid config but omits a security directive (e.g., forgets HSTS on a TLS server).

**Mitigation**: Rules check for _presence_ of directives, not just absence of bad ones. NGX-004 fires if `ssl_certificate` exists but `Strict-Transport-Security` does not.

**Residual risk**: The model may use a non-standard syntax for a directive that our regex doesn't match. Example: `add_header hsts ...` instead of `add_header Strict-Transport-Security ...`. This is a known limitation of string matching vs AST parsing.

### 4.3 Over-Permissive Defaults

**Risk**: Model generates a config that doesn't violate explicit rules but uses permissive defaults (e.g., a DNS `allow-query { any; }` which is actually fine for authoritative servers but dangerous for resolvers).

**Mitigation**: Rules are context-sensitive where possible (DNS-001 checks recursion + allow-recursion together). The few-shot examples prime the model toward restrictive defaults.

**Residual risk**: Some permissive defaults cannot be detected without understanding server role (authoritative vs recursive), which the LLM knows but the validator doesn't. A future improvement would have the LLM emit structured metadata alongside the config.

### 4.4 Prompt Injection via Config Content

**Risk**: A malicious operator injects config content that attempts to manipulate LLM behavior in subsequent pipeline stages.

**Mitigation**: Config text goes directly to the deterministic validator — no LLM re-ingestion of the generated config. The validator is immune to prompt injection.

---

## 5. Evaluation Results (Demo Run)

### 5.1 Demo Run (6 hand-crafted samples)

| Example | Target | Expected | Predicted | Correct | Risk Score |
|---------|--------|----------|-----------|---------|-----------|
| Secure nginx (HTTPS API) | nginx | Secure | Secure | ✓ | 0.000 |
| Insecure nginx (HTTP+autoindex) | nginx | Insecure | Insecure | ✓ | 0.986 |
| Secure iptables (web+SSH restricted) | iptables | Secure | Secure | ✓ | 0.000 |
| Insecure iptables (default ACCEPT) | iptables | Insecure | Insecure | ✓ | 0.995 |
| Secure DNS (authoritative-only) | dns | Secure | Secure | ✓ | 0.000 |
| Insecure DNS (open resolver) | dns | Insecure | Insecure | ✓ | 0.956 |

**Accuracy: 6/6 (100%)** on hand-crafted examples.

### 5.2 Violation Counts by Config Type

| Config | Violations | Key Issues Detected |
|--------|-----------|---------------------|
| Insecure nginx | 9 | No HTTP→HTTPS redirect, TLSv1.0, autoindex, public upstream, missing headers |
| Insecure iptables | 8 | Default ACCEPT, SSH/Telnet/DB world-open, no stateful rule |
| Insecure DNS | 6 | Open recursion ×2, unrestricted AXFR, no rate-limit, no DNSSEC |

### 5.3 Risk Score Distribution

Risk scores for insecure configs cluster 0.95–0.99, clearly separable from 0.0 for secure configs, suggesting the scoring function provides good discrimination without additional threshold tuning.

---

## 6. Limitations

1. **Regex-based rules are not a formal parser** — configs with unusual whitespace, multi-line directives, or comments containing keywords may confuse rules.

2. **Context-blindness** — The validator cannot reason about whether two rules interact (e.g., an nginx `allow 10.0.0.0/8; deny all;` with a missing `location /admin` block).

3. **No runtime validation** — We cannot test the generated config in an actual nginx/iptables environment. Syntax errors would not be caught.

4. **LLM non-determinism** — Even at temperature 0.1, repeated runs may produce marginally different configs. The evaluation dataset would benefit from multiple generation runs per prompt.

5. **Ground-truth labels for ambiguous samples** are heuristically assigned. A human expert review panel would improve label quality.

6. **Missing config types** — IPv6 iptables (ip6tables), nftables, UFW, HAProxy, and cloud security groups (AWS SGs, GCP Firewall Rules) are not covered.

---

## 7. Future Work

### Near-term
- **Subprocess sandbox validation**: Run `nginx -t` or `iptables-restore --test` against generated configs in a container to catch syntax errors
- **AST-based parsing**: Use `pyparsing` or `lark` for proper nginx config parsing; `iptables-save` format has a stable grammar
- **Multi-run averaging**: Generate each sample 3× and report the worst-case violation set

### Medium-term
- **Model comparison**: Benchmark GPT-4o vs Claude vs Llama-3 on the same dataset. Hypothesis: instruction-tuned models with code training perform better on config generation
- **Probabilistic scoring calibration**: Fit the `λ` parameter using calibration data from a labeled corpus
- **LLM-assisted rule generation**: Use the LLM to propose new security rules given CVE descriptions, then have a human review before adding to the engine

### Long-term
- **Formal verification**: Encode iptables rules as network reachability constraints and verify against security properties using Z3 or similar SMT solver
- **Remediation suggestions**: For each violation, have the LLM generate a corrective diff
- **CI/CD integration**: GitHub Action that validates infra-as-code config changes on every PR
- **Configuration drift detection**: Compare deployed configs against validated golden configs

---

## 8. Dependencies

```
anthropic>=0.25.0   # LLM API client
pytest>=8.0.0       # Testing framework
```

No other external dependencies. The codebase is pure Python 3.10+ standard library + these two packages.

---

## 9. Running the System

```bash
# Install dependencies
pip install anthropic pytest

# Run unit tests (no API key needed)
python -m pytest tests/ -v

# Run offline demo (no API key needed)
python demo.py

# Generate + validate a single config (API key required)
export ANTHROPIC_API_KEY=sk-ant-...
python main.py generate --target nginx --prompt "Serve api.example.com over HTTPS with TLS 1.3"

# Run full evaluation (API key required)
python main.py evaluate --max-samples 10

# List all rules for a target
python main.py rules --target iptables
```
