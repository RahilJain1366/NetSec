"""
dashboard/app.py
────────────────
Flask web dashboard for the network config security pipeline.

Pages
─────
  /                  — Home: list all runs
  /run/<run_id>      — Evaluation run detail (per-sample table + metrics)
  /sample/<run>/<id> — Single sample detail with config + violations
  /remediate         — Interactive remediation (POST prompt → generate → validate → fix)
  /compare           — Comparison run results
  /api/runs          — JSON list of available runs
  /api/remediate     — JSON endpoint: generate + validate + remediate

Run
───
  cd netconfig_llm
  python dashboard/app.py
  open http://localhost:5001
"""

from __future__ import annotations

import json
import os
import sys
import glob

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, render_template_string, jsonify, request, redirect, url_for
from config import ConfigTarget, OUTPUT_DIR
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("NETCONFIG_SECRET_KEY", "netsec-dashboard")
app.config["JSON_SORT_KEYS"] = False

# ── Template helpers ──────────────────────────────────────────────────────────

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>NetConfig Security Pipeline</title>
  <style>
    :root {
      --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
      --text: #e2e8f0; --muted: #718096; --accent: #6366f1;
      --green: #10b981; --red: #ef4444; --yellow: #f59e0b;
      --blue: #3b82f6; --orange: #f97316;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background:
        radial-gradient(circle at top left, rgba(99,102,241,0.18), transparent 30%),
        radial-gradient(circle at top right, rgba(16,185,129,0.10), transparent 24%),
        var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', sans-serif;
      min-height: 100vh;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }

    nav {
      position: sticky; top: 0; z-index: 10;
      background: rgba(26,29,39,0.92); backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--border);
      padding: 0 2rem; display: flex; align-items: center; gap: 2rem; height: 64px;
    }
    nav .brand { font-weight: 800; font-size: 1.05rem; color: var(--text); letter-spacing: 0.01em; }
    nav a { color: var(--muted); font-size: 0.9rem; }
    nav a:hover { color: var(--text); text-decoration: none; }

    .container { max-width: 1240px; margin: 0 auto; padding: 2rem; }
    h1 { font-size: 1.6rem; margin-bottom: 1.5rem; }
    h2 { font-size: 1.2rem; margin-bottom: 1rem; color: var(--muted); }

    .card {
      background: linear-gradient(180deg, rgba(26,29,39,0.98), rgba(20,23,32,0.98));
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 16px 50px rgba(0,0,0,0.24);
      transition: transform 0.18s ease, border-color 0.18s ease;
    }
    .card:hover { transform: translateY(-1px); border-color: rgba(99,102,241,0.45); }
    .card h3 { font-size: 1rem; margin-bottom: 1rem; }

    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .metric { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
    .metric .val { font-size: 2rem; font-weight: 700; }
    .metric .lbl { font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem; }
    .metric.good .val { color: var(--green); }
    .metric.warn .val { color: var(--yellow); }
    .metric.bad  .val { color: var(--red); }

    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { text-align: left; padding: 0.6rem 0.8rem; border-bottom: 2px solid var(--border); color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }
    td { padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    tr:hover td { background: rgba(255,255,255,0.02); }

    .badge {
      display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
      font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
    }
    .badge.secure   { background: rgba(16,185,129,0.15); color: var(--green); }
    .badge.insecure { background: rgba(239,68,68,0.15);  color: var(--red); }
    .badge.HIGH     { background: rgba(239,68,68,0.15);  color: var(--red); }
    .badge.MEDIUM   { background: rgba(245,158,11,0.15); color: var(--yellow); }
    .badge.LOW      { background: rgba(59,130,246,0.15); color: var(--blue); }
    .badge.correct  { background: rgba(16,185,129,0.15); color: var(--green); }
    .badge.wrong    { background: rgba(239,68,68,0.15);  color: var(--red); }
    .badge.secure_cat   { background: rgba(16,185,129,0.1);  color: var(--green); }
    .badge.insecure_cat { background: rgba(239,68,68,0.1);   color: var(--red); }
    .badge.ambiguous    { background: rgba(245,158,11,0.1);  color: var(--yellow); }

    .risk-bar { display: flex; align-items: center; gap: 0.5rem; }
    .risk-track { flex: 1; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
    .risk-fill  { height: 100%; border-radius: 3px; transition: width 0.3s; }
    .risk-val   { font-size: 0.75rem; color: var(--muted); min-width: 36px; text-align: right; }

    pre { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: 0.78rem; line-height: 1.6; }
    code { font-family: 'Fira Code', 'Cascadia Code', monospace; }

    .diff-line { font-family: monospace; font-size: 0.78rem; line-height: 1.6; padding: 1px 8px; white-space: pre; }
    .diff-line.added   { background: rgba(16,185,129,0.1); color: #6ee7b7; }
    .diff-line.added::before   { content: '+ '; color: var(--green); }
    .diff-line.removed { background: rgba(239,68,68,0.1);  color: #fca5a5; }
    .diff-line.removed::before { content: '- '; color: var(--red); }
    .diff-line.equal   { color: var(--muted); }
    .diff-line.equal::before   { content: '  '; }

    .form-group { margin-bottom: 1rem; }
    label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 0.4rem; }
    select, textarea {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      color: var(--text); border-radius: 8px; padding: 0.7rem 0.9rem; font-size: 0.9rem;
    }
    textarea { min-height: 100px; resize: vertical; font-family: inherit; }
    select:focus, textarea:focus { outline: none; border-color: var(--accent); }
    btn, .btn {
      display: inline-block; padding: 0.6rem 1.4rem; background: var(--accent);
      color: white; border: none; border-radius: 6px; font-size: 0.9rem;
      cursor: pointer; font-weight: 600;
    }
    .btn:hover { opacity: 0.92; transform: translateY(-1px); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-outline { background: transparent; border: 1px solid var(--accent); color: var(--accent); }

    .spinner { display: none; }
    .spinner.active { display: inline-block; width: 16px; height: 16px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; vertical-align: middle; margin-left: 8px; }
    @keyframes spin { to { transform: rotate(360deg); } }

    .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
    .tab { padding: 0.7rem 1.2rem; cursor: pointer; color: var(--muted); font-size: 0.88rem; border-bottom: 2px solid transparent; margin-bottom: -1px; }
    .tab.active { color: var(--text); border-bottom-color: var(--accent); }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    @media(max-width:768px) { .compare-grid { grid-template-columns: 1fr; } }

    .alert { padding: 0.8rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.88rem; }
    .alert.success { background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); color: #6ee7b7; }
    .alert.error   { background: rgba(239,68,68,0.1);  border: 1px solid rgba(239,68,68,0.3);  color: #fca5a5; }
    .alert.info    { background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.3); color: #a5b4fc; }

    .empty { text-align: center; color: var(--muted); padding: 3rem; font-size: 0.9rem; }
    .page-title { margin-bottom: 0.5rem; }
    .page-subtitle { color: var(--muted); margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <nav>
    <span class="brand">🔐 NetConfig Security</span>
    <a href="/">Runs</a>
    <a href="/remediate">Remediate</a>
    <a href="/compare">Compare</a>
    <a href="/adversarial">Adversarial</a>
  </nav>
  <div class="container">
    {% block content %}{% endblock %}
  </div>
  <script>
    // Tab switching
    document.addEventListener('click', e => {
      if (e.target.classList.contains('tab')) {
        const group = e.target.dataset.group;
        document.querySelectorAll(`.tab[data-group="${group}"]`).forEach(t => t.classList.remove('active'));
        document.querySelectorAll(`.tab-content[data-group="${group}"]`).forEach(t => t.classList.remove('active'));
        e.target.classList.add('active');
        document.querySelector(`.tab-content[data-group="${group}"][data-tab="${e.target.dataset.tab}"]`).classList.add('active');
      }
    });
  </script>
  {{ extra_scripts|default('')|safe }}
</body>
</html>
"""

# ── Home page ─────────────────────────────────────────────────────────────────

HOME_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
{% block content %}
<h1>Evaluation Runs</h1>
{% if runs %}
<div class="card">
  <table>
    <thead><tr>
      <th>Run ID</th><th>Samples</th><th>Accuracy</th>
      <th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th></th>
    </tr></thead>
    <tbody>
    {% for r in runs %}
    <tr>
      <td><code>{{ r.run_id }}</code></td>
      <td>{{ r.total }}</td>
      <td><span class="badge {{ 'correct' if r.accuracy >= 0.8 else 'wrong' }}">{{ "%.1f"|format(r.accuracy*100) }}%</span></td>
      <td>{{ "%.1f"|format(r.precision*100) }}%</td>
      <td>{{ "%.1f"|format(r.recall*100) }}%</td>
      <td>{{ "%.1f"|format(r.f1*100) }}%</td>
      <td>{{ "%.1f"|format(r.fpr*100) }}%</td>
      <td><a href="/run/{{ r.run_id }}">View →</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% else %}
<div class="empty">No evaluation runs found. Run <code>python main.py evaluate</code> to generate results.</div>
{% endif %}
{% endblock %}
""")

# ── Run detail page ───────────────────────────────────────────────────────────

RUN_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
{% block content %}
<h1>Run <code>{{ run_id }}</code></h1>

<div class="metrics-grid">
  <div class="metric {{ 'good' if m.accuracy>=0.8 else 'warn' }}">
    <div class="val">{{ "%.1f"|format(m.accuracy*100) }}%</div>
    <div class="lbl">Accuracy</div>
  </div>
  <div class="metric {{ 'good' if m.precision_insecure>=0.8 else 'warn' }}">
    <div class="val">{{ "%.1f"|format(m.precision_insecure*100) }}%</div>
    <div class="lbl">Precision</div>
  </div>
  <div class="metric {{ 'good' if m.recall_insecure>=0.8 else 'warn' }}">
    <div class="val">{{ "%.1f"|format(m.recall_insecure*100) }}%</div>
    <div class="lbl">Recall</div>
  </div>
  <div class="metric">
    <div class="val">{{ "%.1f"|format(m.f1_insecure*100) }}%</div>
    <div class="lbl">F1</div>
  </div>
  <div class="metric {{ 'good' if m.false_positive_rate<=0.1 else 'bad' }}">
    <div class="val">{{ "%.1f"|format(m.false_positive_rate*100) }}%</div>
    <div class="lbl">FPR</div>
  </div>
  <div class="metric">
    <div class="val">{{ m.confusion_matrix.TP }}/{{ m.confusion_matrix.TN }}</div>
    <div class="lbl">TP / TN</div>
  </div>
  <div class="metric bad">
    <div class="val">{{ m.confusion_matrix.FP }}/{{ m.confusion_matrix.FN }}</div>
    <div class="lbl">FP / FN</div>
  </div>
</div>

<div class="card">
  <h3>Risk Score by Category</h3>
  <table>
    <thead><tr><th>Category</th><th>N</th><th>Mean Risk</th><th>Std</th></tr></thead>
    <tbody>
    {% for cat, s in m.risk_score_by_category.items() %}
    <tr>
      <td><span class="badge {{ cat }}">{{ cat }}</span></td>
      <td>{{ s.n }}</td>
      <td>
        <div class="risk-bar">
          <div class="risk-track"><div class="risk-fill" style="width:{{ s.mean*100 }}%;background:{{ '#ef4444' if s.mean>0.5 else '#f59e0b' if s.mean>0.2 else '#10b981' }}"></div></div>
          <span class="risk-val">{{ "%.3f"|format(s.mean) }}</span>
        </div>
      </td>
      <td style="color:var(--muted)">{{ "%.3f"|format(s.std) }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<div class="card">
  <h3>Samples</h3>
  <table>
    <thead><tr>
      <th>ID</th><th>Target</th><th>Category</th><th>Expected</th>
      <th>Predicted</th><th>Risk</th><th>Violations</th><th>Result</th>
    </tr></thead>
    <tbody>
    {% for s in samples %}
    <tr>
      <td><a href="/sample/{{ run_id }}/{{ s.sample_id }}"><code>{{ s.sample_id }}</code></a></td>
      <td>{{ s.target }}</td>
      <td><span class="badge {{ s.category }}">{{ s.category }}</span></td>
      <td><span class="badge {{ 'secure' if s.expected_secure else 'insecure' }}">{{ 'secure' if s.expected_secure else 'insecure' }}</span></td>
      <td><span class="badge {{ 'secure' if s.predicted_secure else 'insecure' }}">{{ 'secure' if s.predicted_secure else 'insecure' }}</span></td>
      <td>
        <div class="risk-bar">
          <div class="risk-track"><div class="risk-fill" style="width:{{ s.risk_score*100 }}%;background:{{ '#ef4444' if s.risk_score>0.5 else '#f59e0b' if s.risk_score>0.2 else '#10b981' }}"></div></div>
          <span class="risk-val">{{ "%.3f"|format(s.risk_score) }}</span>
        </div>
      </td>
      <td>{{ s.violation_count }}</td>
      <td><span class="badge {{ 'correct' if s.correct else 'wrong' }}">{{ '✓' if s.correct else '✗' }}</span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
""")

# ── Sample detail page ────────────────────────────────────────────────────────

SAMPLE_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
{% block content %}
<p style="color:var(--muted);margin-bottom:1rem"><a href="/run/{{ run_id }}">← Back to run</a></p>
<h1>{{ s.sample_id }} <span class="badge {{ s.category }}">{{ s.category }}</span></h1>
<p style="color:var(--muted);margin:0.5rem 0 1.5rem">{{ s.prompt }}</p>

<div class="metrics-grid">
  <div class="metric {{ 'good' if s.predicted_secure else 'bad' }}">
    <div class="val">{{ 'Secure' if s.predicted_secure else 'Insecure' }}</div>
    <div class="lbl">Predicted</div>
  </div>
  <div class="metric {{ 'good' if s.expected_secure else 'bad' }}">
    <div class="val">{{ 'Secure' if s.expected_secure else 'Insecure' }}</div>
    <div class="lbl">Expected</div>
  </div>
  <div class="metric {{ 'good' if s.correct else 'bad' }}">
    <div class="val">{{ '✓ Correct' if s.correct else '✗ Wrong' }}</div>
    <div class="lbl">Outcome</div>
  </div>
  <div class="metric {{ 'good' if s.risk_score < 0.2 else 'warn' if s.risk_score < 0.6 else 'bad' }}">
    <div class="val">{{ "%.3f"|format(s.risk_score) }}</div>
    <div class="lbl">Risk Score</div>
  </div>
</div>

<div class="tabs">
  <div class="tab active" data-group="main" data-tab="config">Generated Config</div>
  <div class="tab" data-group="main" data-tab="violations">Violations ({{ s.violations|length }})</div>
</div>

<div class="tab-content active" data-group="main" data-tab="config">
  <pre><code>{{ s.generated_config }}</code></pre>
</div>

<div class="tab-content" data-group="main" data-tab="violations">
  {% if s.violations %}
  <table>
    <thead><tr><th>Rule</th><th>Severity</th><th>Description</th><th>Evidence</th></tr></thead>
    <tbody>
    {% for v in s.violations %}
    <tr>
      <td><code>{{ v.rule_id }}</code></td>
      <td><span class="badge {{ v.severity }}">{{ v.severity }}</span></td>
      <td>{{ v.description }}</td>
      <td style="color:var(--muted);font-size:0.8rem"><code>{{ v.evidence }}</code></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="alert success">✓ No violations detected</div>
  {% endif %}
</div>
{% endblock %}
""")

# ── Remediate page ────────────────────────────────────────────────────────────

REMEDIATE_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
{% block content %}
<h1 class="page-title">Auto-Remediation</h1>
<p class="page-subtitle">Enter a natural language policy. The system will generate a config, validate it, and automatically fix any violations.</p>

<div class="card">
  <div class="form-group">
    <label>Config Target</label>
    <select id="target">
      <option value="nginx">nginx</option>
      <option value="iptables">iptables</option>
      <option value="dns">dns</option>
    </select>
  </div>
  <div class="form-group">
    <label>Policy / Requirements</label>
    <textarea id="prompt" placeholder="e.g. Configure nginx for legacy.oldsite.com with no SSL, accessible via HTTP on port 80."></textarea>
  </div>
  <button class="btn" onclick="runRemediation()">
    Generate &amp; Remediate <span class="spinner" id="spin"></span>
  </button>
</div>

<div id="result" style="display:none">
  <div class="metrics-grid" id="metrics"></div>

  <div class="tabs">
    <div class="tab active" data-group="rem" data-tab="diff">Diff</div>
    <div class="tab" data-group="rem" data-tab="before">Original Config</div>
    <div class="tab" data-group="rem" data-tab="after">Remediated Config</div>
    <div class="tab" data-group="rem" data-tab="violations">Violations</div>
  </div>

  <div class="tab-content active" data-group="rem" data-tab="diff">
    <div class="card" style="padding:0;overflow:hidden">
      <div id="diff-view"></div>
    </div>
  </div>
  <div class="tab-content" data-group="rem" data-tab="before">
    <pre><code id="before-config"></code></pre>
  </div>
  <div class="tab-content" data-group="rem" data-tab="after">
    <pre><code id="after-config"></code></pre>
  </div>
  <div class="tab-content" data-group="rem" data-tab="violations">
    <div id="violations-view"></div>
  </div>
</div>
{% endblock %}
""")

REMEDIATE_SCRIPT = """
<script>
async function runRemediation() {
  const btn = document.querySelector('.btn');
  const spin = document.getElementById('spin');
  btn.disabled = true; spin.classList.add('active');
  document.getElementById('result').style.display = 'none';

  try {
    const res = await fetch('/api/remediate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        prompt: document.getElementById('prompt').value,
        target: document.getElementById('target').value,
      })
    });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    renderResult(data);
  } finally {
    btn.disabled = false; spin.classList.remove('active');
  }
}

function riskColor(r) {
  return r > 0.5 ? '#ef4444' : r > 0.2 ? '#f59e0b' : '#10b981';
}

function renderResult(d) {
  // Metrics
  document.getElementById('metrics').innerHTML = `
    <div class="metric ${d.fully_remediated ? 'good' : 'warn'}">
      <div class="val">${d.fully_remediated ? '✓ Fixed' : '⚠ Partial'}</div>
      <div class="lbl">Outcome</div>
    </div>
    <div class="metric bad"><div class="val">${d.risk_before.toFixed(3)}</div><div class="lbl">Risk Before</div></div>
    <div class="metric good"><div class="val">${d.risk_after.toFixed(3)}</div><div class="lbl">Risk After</div></div>
    <div class="metric"><div class="val">${d.violations_before}</div><div class="lbl">Violations Before</div></div>
    <div class="metric good"><div class="val">${d.violations_after}</div><div class="lbl">Violations After</div></div>
    <div class="metric"><div class="val">${d.iterations_taken}</div><div class="lbl">Iterations</div></div>
  `;

  // Diff
  const diffEl = document.getElementById('diff-view');
  diffEl.innerHTML = d.inline_diff.map(l =>
    `<div class="diff-line ${l.type}">${escHtml(l.line)}</div>`
  ).join('');

  // Configs
  document.getElementById('before-config').textContent = d.original_config;
  document.getElementById('after-config').textContent  = d.final_config;

  // Violations
  const vEl = document.getElementById('violations-view');
  const renderV = (vs, label) => vs.length ? `
    <h3 style="margin-bottom:0.75rem;color:var(--muted)">${label}</h3>
    <table><thead><tr><th>Rule</th><th>Severity</th><th>Description</th><th>Evidence</th></tr></thead><tbody>
    ${vs.map(v => `<tr>
      <td><code>${v.rule_id}</code></td>
      <td><span class="badge ${v.severity}">${v.severity}</span></td>
      <td>${v.description}</td>
      <td style="color:var(--muted);font-size:0.8rem"><code>${escHtml(v.evidence)}</code></td>
    </tr>`).join('')}
    </tbody></table>
  ` : `<div class="alert success">✓ No violations</div>`;

  vEl.innerHTML = renderV(d.violations_detail_before, 'Before Remediation') +
                  '<hr style="border-color:var(--border);margin:1.5rem 0">' +
                  renderV(d.violations_detail_after, 'After Remediation');

  document.getElementById('result').style.display = 'block';
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
"""

# ── Compare page ──────────────────────────────────────────────────────────────

COMPARE_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
{% block content %}
<h1>Model Comparison</h1>
{% if comparisons %}
{% for c in comparisons %}
<div class="card">
  <h3>{{ c.model_a }} vs {{ c.model_b }} &nbsp;<span style="color:var(--muted);font-size:0.8rem">{{ c.run_id }}</span></h3>

  <div class="compare-grid" style="margin-bottom:1.5rem">
    <div>
      <h2>{{ c.model_a }}</h2>
      <div class="metrics-grid">
        <div class="metric"><div class="val">{{ "%.1f"|format(c.ma.accuracy*100) }}%</div><div class="lbl">Accuracy</div></div>
        <div class="metric"><div class="val">{{ "%.1f"|format(c.ma.precision_insecure*100) }}%</div><div class="lbl">Precision</div></div>
        <div class="metric"><div class="val">{{ "%.1f"|format(c.ma.recall_insecure*100) }}%</div><div class="lbl">Recall</div></div>
        <div class="metric"><div class="val">{{ "%.1f"|format(c.ma.f1_insecure*100) }}%</div><div class="lbl">F1</div></div>
      </div>
    </div>
    <div>
      <h2>{{ c.model_b }}</h2>
      <div class="metrics-grid">
        <div class="metric"><div class="val">{{ "%.1f"|format(c.mb.accuracy*100) }}%</div><div class="lbl">Accuracy</div></div>
        <div class="metric"><div class="val">{{ "%.1f"|format(c.mb.precision_insecure*100) }}%</div><div class="lbl">Precision</div></div>
        <div class="metric"><div class="val">{{ "%.1f"|format(c.mb.recall_insecure*100) }}%</div><div class="lbl">Recall</div></div>
        <div class="metric"><div class="val">{{ "%.1f"|format(c.mb.f1_insecure*100) }}%</div><div class="lbl">F1</div></div>
      </div>
    </div>
  </div>

  <div class="metrics-grid">
    <div class="metric"><div class="val">{{ "%.1f"|format(c.agreement_rate*100) }}%</div><div class="lbl">Agreement</div></div>
    <div class="metric good"><div class="val">{{ c.model_a_wins }}</div><div class="lbl">{{ c.model_a }} wins</div></div>
    <div class="metric good"><div class="val">{{ c.model_b_wins }}</div><div class="lbl">{{ c.model_b }} wins</div></div>
    <div class="metric"><div class="val">{{ c.ties }}</div><div class="lbl">Ties</div></div>
    <div class="metric bad"><div class="val">{{ c.both_wrong }}</div><div class="lbl">Both Wrong</div></div>
    <div class="metric"><div class="val">{{ "%.3f"|format(c.avg_risk_diff) }}</div><div class="lbl">Avg Risk Δ</div></div>
  </div>

  <h3 style="margin:1rem 0 0.75rem">Sample Breakdown</h3>
  <table>
    <thead><tr>
      <th>Sample</th><th>Category</th>
      <th>{{ c.model_a }} pred</th><th>{{ c.model_a }} risk</th>
      <th>{{ c.model_b }} pred</th><th>{{ c.model_b }} risk</th>
      <th>Winner</th>
    </tr></thead>
    <tbody>
    {% for r in c.records %}
    <tr>
      <td><code>{{ r.sample_id }}</code></td>
      <td><span class="badge {{ r.category }}">{{ r.category }}</span></td>
      <td><span class="badge {{ 'correct' if r.model_a_correct else 'wrong' }}">{{ '✓' if r.model_a_correct else '✗' }}</span></td>
      <td>{{ "%.3f"|format(r.model_a_risk) }}</td>
      <td><span class="badge {{ 'correct' if r.model_b_correct else 'wrong' }}">{{ '✓' if r.model_b_correct else '✗' }}</span></td>
      <td>{{ "%.3f"|format(r.model_b_risk) }}</td>
      <td><span class="badge {{ 'correct' if r.winner not in ['both_wrong'] else 'wrong' }}">{{ r.winner }}</span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endfor %}
{% else %}
<div class="empty">No comparison runs found. Run <code>python main.py compare</code> to generate results.</div>
{% endif %}
{% endblock %}
""")


# ── Route helpers ─────────────────────────────────────────────────────────────

def _load_runs():
    runs = []
    for mpath in glob.glob(os.path.join(OUTPUT_DIR, "run_*_metrics.json")):
        run_id = os.path.basename(mpath).replace("run_", "").replace("_metrics.json", "")
        with open(mpath) as f:
            m = json.load(f)
        runs.append({
            "run_id":    run_id,
            "total":     m.get("total", 0),
            "accuracy":  m.get("accuracy", 0),
            "precision": m.get("precision_insecure", 0),
            "recall":    m.get("recall_insecure", 0),
            "f1":        m.get("f1_insecure", 0),
            "fpr":       m.get("false_positive_rate", 0),
        })
    return sorted(runs, key=lambda r: r["run_id"], reverse=True)


def _load_run(run_id):
    mpath = os.path.join(OUTPUT_DIR, f"run_{run_id}_metrics.json")
    dpath = os.path.join(OUTPUT_DIR, f"run_{run_id}_details.json")
    if not os.path.exists(mpath):
        return None, None
    with open(mpath) as f:
        metrics = json.load(f)
    with open(dpath) as f:
        samples = json.load(f)
    return metrics, samples


def _load_comparisons():
    comps = []
    for spath in glob.glob(os.path.join(OUTPUT_DIR, "comparison_*_summary.json")):
        run_id = os.path.basename(spath).replace("comparison_", "").replace("_summary.json", "")
        rpath  = os.path.join(OUTPUT_DIR, f"comparison_{run_id}_records.json")
        with open(spath) as f:
            s = json.load(f)
        with open(rpath) as f:
            records = json.load(f)
        comps.append({
            "run_id":       run_id,
            "model_a":      s["model_a"].split("-")[0] + "…",
            "model_b":      s["model_b"].split("-")[0] + "…",
            "agreement_rate": s["agreement_rate"],
            "model_a_wins": s["model_a_wins"],
            "model_b_wins": s["model_b_wins"],
            "ties":         s["ties"],
            "both_wrong":   s["both_wrong"],
            "avg_risk_diff":s["avg_risk_diff"],
            "ma":           s["model_a_metrics"],
            "mb":           s["model_b_metrics"],
            "records":      records,
        })
    return comps


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template_string(HOME_HTML, runs=_load_runs())


@app.route("/run/<run_id>")
def run_detail(run_id):
    metrics, samples = _load_run(run_id)
    if metrics is None:
        return "Run not found", 404

    class M:
        pass
    m = M()
    m.accuracy             = metrics.get("accuracy", 0)
    m.precision_insecure   = metrics.get("precision_insecure", 0)
    m.recall_insecure      = metrics.get("recall_insecure", 0)
    m.f1_insecure          = metrics.get("f1_insecure", 0)
    m.false_positive_rate  = metrics.get("false_positive_rate", 0)
    m.confusion_matrix     = metrics.get("confusion_matrix", {})
    m.risk_score_by_category = metrics.get("risk_score_by_category", {})

    return render_template_string(RUN_HTML, run_id=run_id, m=m, samples=samples)


@app.route("/sample/<run_id>/<sample_id>")
def sample_detail(run_id, sample_id):
    _, samples = _load_run(run_id)
    if samples is None:
        return "Run not found", 404
    s = next((x for x in samples if x["sample_id"] == sample_id), None)
    if not s:
        return "Sample not found", 404

    class S: pass
    obj = S()
    for k, v in s.items():
        setattr(obj, k, v)
    return render_template_string(SAMPLE_HTML, run_id=run_id, s=obj)


@app.route("/remediate")
def remediate_page():
  return render_template_string(REMEDIATE_HTML, extra_scripts=REMEDIATE_SCRIPT)


@app.route("/api/remediate", methods=["POST"])
def api_remediate():
    from generator import LLMConfigGenerator
    from validator import ValidationEngine
    from remediator import RemediationEngine

    data   = request.get_json()
    prompt = data.get("prompt", "").strip()
    target_str = data.get("target", "nginx")

    if not prompt:
        return jsonify({"error": "Prompt is required"}), 400

    try:
        target = ConfigTarget(target_str)
    except ValueError:
        return jsonify({"error": f"Unknown target: {target_str}"}), 400

    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    rem    = RemediationEngine(gen, engine, max_iterations=3)

    gen_result = gen.generate(prompt, target)
    if not gen_result.success:
        return jsonify({"error": f"Generation failed: {gen_result.error}"}), 500

    val_result = engine.validate(gen_result.raw_config, target)
    rem_result = rem.remediate(
        gen_result.raw_config, target, initial_validation=val_result
    )

    return jsonify(rem_result.to_dict())


@app.route("/compare")
def compare_page():
    return render_template_string(COMPARE_HTML, comparisons=_load_comparisons())


@app.route("/api/runs")
def api_runs():
    return jsonify(_load_runs())


@app.route("/favicon.ico")
def favicon():
  return ("", 204)



# ── Adversarial page ──────────────────────────────────────────────────────────

ADVERSARIAL_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
{% block content %}
<h1>Adversarial Persona Probing</h1>
<p style="color:var(--muted);margin-bottom:1.5rem">
  How effectively do social engineering prompts bypass LLM security defaults?
  Does the deterministic validator catch violations regardless of prompt framing?
</p>

{% if results %}
{% for r in results %}
<div class="card">
  <h3>Run <code>{{ r.run_id }}</code></h3>

  <div class="metrics-grid">
    <div class="metric bad">
      <div class="val">{{ "%.1f"|format(r.overall_bypass_rate*100) }}%</div>
      <div class="lbl">LLM Bypass Rate</div>
    </div>
    <div class="metric good">
      <div class="val">{{ "%.1f"|format(r.overall_catch_rate*100) }}%</div>
      <div class="lbl">Validator Catch Rate</div>
    </div>
    <div class="metric">
      <div class="val">{{ r.total_samples }}</div>
      <div class="lbl">Total Samples</div>
    </div>
    <div class="metric bad">
      <div class="val">{{ r.total_llm_bypassed }}</div>
      <div class="lbl">Bypassed</div>
    </div>
    <div class="metric good">
      <div class="val">{{ r.total_validator_caught }}</div>
      <div class="lbl">Caught</div>
    </div>
  </div>

  <h3 style="margin-bottom:1rem">Persona Bypass Rate Ranking</h3>

  <div style="margin-bottom:1.5rem">
  {% for ps in r.persona_ranking %}
  <div style="display:flex;align-items:center;gap:1rem;margin-bottom:0.75rem">
    <div style="width:220px;font-size:0.85rem;flex-shrink:0">{{ ps.label }}</div>
    <div style="flex:1;height:28px;background:var(--border);border-radius:4px;overflow:hidden;position:relative">
      <div style="height:100%;width:{{ ps.bypass_rate*100 }}%;background:{{ '#ef4444' if ps.bypass_rate>0.7 else '#f59e0b' if ps.bypass_rate>0.4 else '#10b981' }};border-radius:4px;transition:width 0.5s"></div>
      <span style="position:absolute;left:8px;top:50%;transform:translateY(-50%);font-size:0.75rem;font-weight:600;color:white">
        {{ "%.1f"|format(ps.bypass_rate*100) }}% bypass
      </span>
    </div>
    <div style="width:100px;text-align:right;font-size:0.8rem;color:var(--green)">
      {{ "%.1f"|format(ps.catch_rate*100) }}% caught
    </div>
    <div style="width:50px;text-align:right;font-size:0.8rem;color:var(--muted)">n={{ ps.total }}</div>
  </div>
  {% endfor %}
  </div>

  <h3 style="margin-bottom:0.75rem">Sample Breakdown</h3>
  <table>
    <thead><tr>
      <th>Sample</th><th>Persona</th><th>Target</th>
      <th>LLM Output</th><th>Risk</th><th>Violations</th><th>Validator</th>
    </tr></thead>
    <tbody>
    {% for rec in r.records %}
    <tr>
      <td><code style="font-size:0.75rem">{{ rec.sample_id }}</code></td>
      <td style="font-size:0.78rem;color:var(--muted)">{{ rec.category }}</td>
      <td>{{ rec.target }}</td>
      <td><span class="badge {{ 'insecure' if rec.llm_bypassed else 'secure' }}">
        {{ 'bypassed' if rec.llm_bypassed else 'defended' }}
      </span></td>
      <td>
        <div class="risk-bar">
          <div class="risk-track">
            <div class="risk-fill" style="width:{{ rec.risk_score*100 }}%;background:{{ '#ef4444' if rec.risk_score>0.5 else '#f59e0b' if rec.risk_score>0.2 else '#10b981' }}"></div>
          </div>
          <span class="risk-val">{{ "%.3f"|format(rec.risk_score) }}</span>
        </div>
      </td>
      <td>{{ rec.violations|length }}</td>
      <td><span class="badge {{ 'correct' if rec.validator_caught else 'wrong' }}">
        {{ '✓ caught' if rec.validator_caught else '✗ missed' }}
      </span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="alert info" style="margin-top:1.5rem">
    <strong>Key Finding:</strong>
    Even when the LLM was socially engineered into producing insecure configs
    ({{ "%.1f"|format(r.overall_bypass_rate*100) }}% bypass rate), the deterministic validator
    caught {{ "%.1f"|format(r.overall_catch_rate*100) }}% of violations —
    demonstrating hybrid LLM + rule-based pipelines are robust to prompt-level manipulation.
  </div>
</div>
{% endfor %}
{% else %}
<div class="empty">
  No adversarial results found.<br>Run <code>python adversarial_eval.py</code> to generate results.
</div>
{% endif %}
{% endblock %}
""")


def _load_adversarial():
    results = []
    for spath in glob.glob(os.path.join(OUTPUT_DIR, "adversarial_*_summary.json")):
        run_id = os.path.basename(spath).replace("adversarial_", "").replace("_summary.json", "")
        rpath  = os.path.join(OUTPUT_DIR, f"adversarial_{run_id}_records.json")
        with open(spath) as f:
            s = json.load(f)
        with open(rpath) as f:
            records = json.load(f)
        results.append({
            "run_id":                run_id,
            "total_samples":         s.get("total_samples", 0),
            "total_llm_bypassed":    s.get("total_llm_bypassed", 0),
            "total_validator_caught":s.get("total_validator_caught", 0),
            "overall_bypass_rate":   s.get("overall_bypass_rate", 0),
            "overall_catch_rate":    s.get("overall_catch_rate", 0),
            "persona_ranking":       s.get("persona_ranking", []),
            "records":               records,
        })
    return results


@app.route("/adversarial")
def adversarial_page():
    return render_template_string(ADVERSARIAL_HTML, results=_load_adversarial())


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  🔐 NetConfig Security Dashboard")
    print("  Open → http://localhost:5001\n")
    app.run(debug=True, port=5001)
