# NetConfig LLM v3

Hybrid LLM + deterministic network security validation framework with MITM risk analysis.

This project generates network configurations from natural language prompts, validates them with rule-based checks, and supports MITM analysis from simulated traffic, PCAP files, live capture, and dataset-derived flows.

## Features

- LLM-based config generation for `nginx`, `iptables`, and `dns`
- Deterministic validation engine with severity-tagged violations
- Risk scoring for generated configurations
- Auto-remediation loop for insecure outputs
- Model-vs-model comparison on a shared evaluation dataset
- MITM detection pipeline (demo, pcap, live, dataset)
- Adversarial prompt evaluation (security persona probing)
- Flask dashboard for runs, samples, remediation, comparison, and adversarial views

## Project Structure

- `main.py`: CLI entrypoint and command dispatcher
- `config.py`: shared enums/dataclasses/constants
- `generator/`: LLM generation module
- `validator/`: deterministic rule engine and rule sets
- `evaluator/`: evaluation workflow + metrics
- `remediator/`: iterative fix engine
- `comparator/`: multi-model comparison
- `mitm/`: network and dataset MITM analysis + attack path report
- `datasets/`: dataset loader, LLM threat interpretation, integrated report builder
- `dashboard/`: Flask web app
- `tests/`: unit tests for validation logic
- `dataset.json`: standard benchmark samples
- `adversarial_dataset.json`: adversarial/security-persona samples
- `logs/`: runtime logs
- `outputs/`: generated artifacts and reports

## Requirements

- Python 3.10+
- Groq API key for LLM-backed commands

Install dependencies:

```bash
pip install -r requirements.txt
```

## Environment Setup

From the project root:

```bash
cd code/netconfig_llm_v3
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create `.env` with at least:

```env
GROQ_API_KEY=your_groq_api_key_here
```

Optional model override:

```env
GROQ_MODEL=llama-3.1-8b-instant
```

## CLI Commands

All commands below are run from `code/netconfig_llm_v3`.

### 1. Run offline demo (no API key needed)

```bash
python demo.py
```

### 2. List security rules for a target

```bash
python main.py rules --target nginx
python main.py rules --target iptables
python main.py rules --target dns
```

### 3. Generate + validate one configuration

```bash
python main.py generate --target nginx --prompt "Create a secure nginx reverse proxy for api.example.com with HTTPS redirect and HSTS."
python main.py generate --target iptables --prompt "Create secure iptables rules for a web server with SSH only from 10.0.1.0/24."
python main.py generate --target dns --prompt "Create secure BIND config for authoritative DNS with recursion disabled and rate limiting."
```

### 4. Full dataset evaluation

```bash
python main.py evaluate
python main.py evaluate --max-samples 10 --delay 2
```

### 5. Generate + validate + remediate insecure configs

```bash
python main.py remediate --target nginx --prompt "Set up nginx quickly on port 80 without TLS." --max-iter 3 --delay 2
```

### 6. Compare two models on the dataset

```bash
python main.py compare --model-a llama-3.1-8b-instant --model-b mixtral-8x7b-32768
python main.py compare --max-samples 10 --delay 2
```

### 7. MITM-only analysis

Demo mode:

```bash
python main.py mitm --mode demo
```

PCAP mode:

```bash
python main.py mitm --mode pcap --pcap-file path/to/capture.pcap
```

Live capture mode:

```bash
sudo python main.py mitm --mode live --interface en0 --count 500 --timeout 60
```

### 8. Integrated config + MITM analysis

```bash
python main.py analyze --target nginx --prompt "Create secure nginx for api.example.com."
```

### 9. End-to-end evaluate-mitm

Demo traffic mode:

```bash
python main.py evaluate-mitm --mitm-mode demo --max-samples 10
```

Dataset traffic mode:

```bash
python main.py evaluate-mitm --mitm-mode dataset --traffic-dataset datasets/data/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv --max-samples 20 --max-traffic-rows 5000
```

PCAP folder mode:

```bash
python main.py evaluate-mitm --mitm-mode pcap --mitm-pcap-folder path/to/pcaps --max-samples 10
```

Live mode:

```bash
sudo python main.py evaluate-mitm --mitm-mode live --interface en0 --count 300 --timeout 30 --max-samples 5
```

### 10. Adversarial evaluation

```bash
python adversarial_eval.py
python adversarial_eval.py --max-samples 20 --delay 2
```

### 11. Launch dashboard

```bash
python main.py dashboard --port 5001
```

From the repository root, you can also use the launcher shim:

```bash
python main.py dashboard --port 5001
```

Open in browser:

```text
http://localhost:5001
```

### 12. Docker (PostgreSQL + dashboard)

Run from `code/netconfig_llm_v3`:

```bash
docker compose up -d --build
docker compose ps
```

Set secrets in `.env` in the same folder as `docker-compose.yml`:

```env
GROQ_API_KEY=your_groq_api_key_here
NETCONFIG_SECRET_KEY=your_long_random_secret
```

Generate a strong secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

The dashboard is exposed at:

```text
http://localhost:5001
```

### 13. Smoke test

Use the included script to perform a full health check + sample run verification:

```bash
chmod +x smoketest.sh
./smoketest.sh
```

### 14. Production hosting

For deployment, run the Flask app behind Gunicorn from `code/netconfig_llm_v3`:

```bash
gunicorn -w 2 -b 0.0.0.0:5001 wsgi:app
```

Set `NETCONFIG_SECRET_KEY` in production and place the app behind a reverse proxy or PaaS.

### 15. Run tests

```bash
pytest -q
```

Or run only validator tests:

```bash
pytest tests/test_validator.py -q
```

## Expected Outputs

Generated files are written under `outputs/`, for example:

- `run_<id>_details.json`
- `run_<id>_metrics.json`
- `run_<id>_events.json`
- `comparison_<id>_records.json`
- `comparison_<id>_summary.json`
- `remediation_<id>_<target>.json`
- `mitm_<id>_<mode>.json`
- `analyze_<id>_<target>.json`
- `e2e_mitm_<id>.json`
- `adversarial_<id>_records.json`
- `adversarial_<id>_summary.json`

## Logs

- `logs/pipeline.log`: structured pipeline logs
- `logs/violations.log`: security finding-focused logs

## Notes

- The active runtime path is rooted in `main.py` and top-level packages.
- `files/` contains integration/backup-style material and is not the primary runtime entrypoint.
- Cache/generated artifacts (`__pycache__`, `.pytest_cache`, `logs`, `outputs`) can be cleaned as needed.
