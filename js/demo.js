/* ============================================================
   demo.js — Vulnerability Scanner Simulation Engine
   Avyrix — Frontend-only, no backend required
   Security note: All output uses textContent / createElement.
                  No innerHTML is ever used with user input.
   ============================================================ */

(function () {
  'use strict';
  function detectContext(code) {
    if (code.includes("Flask")) return "Python (Flask)";
    if (code.includes("express")) return "Node.js (Express)";
    if (code.includes("SELECT")) return "SQL-based backend";
    if (code.includes("innerHTML")) return "Frontend JavaScript";
    return "Generic Code";
  }

  /* ── Vulnerability Rule Database ──────────────────────── */
  const VULN_RULES = [
    {
      id: 'sql-injection',
      name: 'SQL Injection',
      severity: 'critical',
      detect(code) {
        // Detect SELECT combined with string concatenation patterns
        const hasSelect = /\bSELECT\b/i.test(code);
        const hasConcat = /(\+\s*['"`]|['"`]\s*\+|['"`]\s*\.\s*['"`]|f['"`][^'"`]*\{|%[sd].*FROM|format\s*\()/i.test(code);
        const hasFrom = /\bFROM\b/i.test(code);
        const hasWhere = /query\s*=|sql\s*=|execute\s*\(|cursor\s*\./i.test(code);
        return (hasSelect && hasFrom && hasConcat) || (hasWhere && hasConcat && hasSelect);
      },
      explanation: [
        'Your code constructs SQL queries using string concatenation with user-controlled data.',
        'An attacker can break out of the query structure by injecting SQL syntax — for example, a single quote followed by a malicious clause.',
        'This can allow unauthorized data reads, bypassing authentication, updating or deleting records, and in some databases, executing OS commands.',
      ],
      steps: [
        'Replace string concatenation with parameterized queries (prepared statements).',
        'Never trust user input — validate and whitelist expected formats (e.g., integers, UUIDs) before using them.',
        'Use an ORM (SQLAlchemy, Prisma, Hibernate) that handles escaping automatically.',
        'Apply principle of least privilege — your DB user should only have the permissions it needs.',
        'Enable a Web Application Firewall (WAF) as a secondary defense layer.',
      ],
      getFixedCode(code) {
        // Replace concatenation patterns with parameterized placeholders
        let fixed = code
          .replace(/["'`]\s*\+\s*(\w+)\s*\+\s*["'`]/g, '?')
          .replace(/f["'`]([^"'`]*)\{(\w+)\}([^"'`]*)["'`]/g, '"$1?" # Use params=($2,)')
          .replace(/(query|sql)\s*=\s*["'`][^"'`]*["'`]\s*\+/gi, '$1 = "SELECT ... FROM table WHERE id = ?"  # parameterized —')
          .replace(/execute\s*\(\s*(query|sql)\s*\)/gi, 'execute($1, (user_input,))  # pass params separately');
        return '# ✓ SQL Injection Fixed — Use Parameterized Queries\n\n' + fixed;
      },
    },

    {
      id: 'xss',
      name: 'Cross-Site Scripting (XSS)',
      severity: 'critical',
      detect(code) {
        // Detect innerHTML with variable data or user input patterns
        return /\.innerHTML\s*=\s*(?!['"`]<[a-z])/i.test(code) ||
          /\.innerHTML\s*\+=/.test(code) ||
          /document\.write\s*\((?![^)]*['"`][^{)]*\))/i.test(code) ||
          /\$\(\s*['"`][^'"]+['"`]\s*\)\.html\s*\(/i.test(code);
      },
      explanation: [
        'Your code inserts user-controlled data directly into the DOM using innerHTML or document.write.',
        'Attackers can inject script tags, event handlers (<img onerror="...">) or javascript: URIs that execute in the victim\'s browser.',
        'This can lead to session hijacking, credential theft, defacement, keylogging, or silently redirecting users to phishing pages.',
      ],
      steps: [
        'Replace .innerHTML = userInput with element.textContent = userInput for plain text.',
        'If you must insert HTML, use a trusted library like DOMPurify to sanitize first.',
        'Use Content Security Policy (CSP) headers to restrict what scripts can run.',
        'Avoid document.write() entirely — it is dangerous and deprecated.',
        'React, Vue, and Angular escape output by default — use frameworks that protect you.',
      ],
      getFixedCode(code) {
        let fixed = code
          .replace(/\.innerHTML\s*=\s*([^;,\n]+)/g, '.textContent = $1  // ✓ Safe: textContent never executes scripts')
          .replace(/\.innerHTML\s*\+=\s*([^;,\n]+)/g, '.textContent += $1  // ✓ Safe')
          .replace(/document\.write\s*\(([^)]+)\)/g, '// Removed document.write — use DOM APIs:\ndocument.getElementById("target").textContent = $1');
        return '// ✓ XSS Fixed — textContent instead of innerHTML\n\n' + fixed;
      },
    },

    {
      id: 'secret-leak',
      name: 'Hardcoded Secret / Credential Leak',
      severity: 'high',
      detect(code) {
        // Detect API keys, tokens, passwords, secrets hardcoded in source
        return /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|db[_-]?pass|client[_-]?secret|bearer)\s*[:=]\s*['"`][A-Za-z0-9+/=_\-\.]{8,}/i.test(code) ||
          /(['"`])(?:sk-|pk-|ghp_|xoxb-|AKIA|AIza|ya29\.|SG\.)[A-Za-z0-9_\-\.]{10,}\1/i.test(code);
      },
      explanation: [
        'Your code contains what appears to be a hardcoded API key, token, or password directly in the source.',
        'If this code is committed to version control (Git), the secret is permanently exposed — even after deletion in a later commit.',
        'Attackers scan public repositories (GitHub, GitLab, npm) constantly using tools like TruffleHog and GitLeaks.',
        'A compromised key can allow unauthorized API usage, billing fraud, data breaches, or full account takeover.',
      ],
      steps: [
        'Immediately rotate the exposed credential if it has ever been committed to any repository.',
        'Move secrets to environment variables: process.env.API_KEY or os.environ["API_KEY"].',
        'Use a secrets manager: AWS Secrets Manager, HashiCorp Vault, or Doppler.',
        'Add .env to your .gitignore and never commit secret files.',
        'Install a pre-commit hook (e.g., detect-secrets, gitleaks) to prevent future leaks.',
      ],
      getFixedCode(code) {
        let fixed = code
          .replace(/(['"`])((?:sk-|pk-|ghp_|xoxb-|AKIA|AIza|ya29\.)[A-Za-z0-9_\-\.]{10,})\1/gi, 'process.env.SECRET_KEY  // ✓ Moved to env var')
          .replace(/(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)\s*[:=]\s*(['"`])[A-Za-z0-9+/=_\-\.]{8,}\2/gi,
            '$1 = process.env.' + '$1'.toUpperCase().replace(/[^A-Z]/g, '_') + '  // ✓ Use environment variable');
        return '// ✓ Secret Leak Fixed — Use Environment Variables\n// Add to .env file (never commit):\n// API_KEY=your-key-here\n\n' + fixed;
      },
    },
  ];

  /* ── Scan Engine ───────────────────────────────────────── */
  function scanCode(rawCode) {
    const code = sanitizeInput(rawCode);
    if (!code) return { error: 'Please enter some code to scan.' };
    if (code.length < 5) return { error: 'Input too short to analyze.' };

    const findings = VULN_RULES
      .filter(rule => rule.detect(code))
      .map(rule => ({
        ...rule,
        fixedCode: rule.getFixedCode(code),
      }));

    return { code, findings };
  }

  /* ── UI Builder ────────────────────────────────────────── */

  // Build a severity bar element
  function buildSeverityBar(severity) {
    const levels = { critical: 5, high: 4, medium: 3 };
    const level = levels[severity] || 3;
    const wrapper = el('div', 'severity');
    const bar = el('div', 'severity__bar');
    for (let i = 0; i < 5; i++) {
      const seg = el('div', 'severity__seg');
      if (i < level) {
        seg.style.background = severity === 'critical' ? 'var(--accent-red)' : 'var(--accent-amber)';
      }
      bar.appendChild(seg);
    }
    const label = el('span');
    label.textContent = severity.toUpperCase();
    label.style.cssText = 'font-size:11px;font-family:var(--font-mono);color:' +
      (severity === 'critical' ? 'var(--accent-red)' : 'var(--accent-amber)') + ';letter-spacing:0.06em;';
    wrapper.appendChild(bar);
    wrapper.appendChild(label);
    return wrapper;
  }

  // Build the "Vulnerability Found" card (Red)
  function buildVulnCard(finding, code) {
    const card = el('div', 'result-card card card--red');

    // Header
    const header = el('div', 'result-card__header');
    const iconWrap = el('div', 'result-card__icon');
    iconWrap.style.background = 'var(--accent-red-dim)';
    iconWrap.textContent = '🚨';
    const titleWrap = el('div');
    const title = el('div', 'result-card__title');
    title.textContent = finding.name + ' Risk Pattern';
    const subtitle = el('div', 'result-card__subtitle');
    subtitle.textContent = 'Potential security risk based on detected code patterns';
    titleWrap.appendChild(title);
    titleWrap.appendChild(subtitle);
    header.appendChild(iconWrap);
    header.appendChild(titleWrap);

    // Severity bar
    const sevWrap = el('div');
    sevWrap.style.cssText = 'margin-left:auto;flex-shrink:0;';
    sevWrap.appendChild(buildSeverityBar(finding.severity));
    header.appendChild(sevWrap);
    card.appendChild(header);

    // Body: badge + description
    const body = el('div', 'result-card__body');
    const badge = el('span', 'badge badge--red badge--dot');
    badge.textContent = finding.id.toUpperCase().replace(/-/g, ' ');
    badge.style.marginBottom = '14px';
    body.appendChild(badge);

    const desc = el('p');
    desc.style.cssText = 'font-size:14px;color:var(--text-secondary);margin-top:12px;line-height:1.7;';
    const context = detectContext(code);

    desc.textContent =
      `⚠️ We detected a pattern in your code that is commonly associated with ${finding.name} vulnerabilities. ` +
      `In real-world applications, this type of pattern can sometimes introduce security risks if not handled carefully. ` +
      `Let’s break down what this means and how to fix it below.`;
    body.appendChild(desc);
    const note = el('div');
    note.style.cssText = 'margin-top:10px;font-size:12px;color:var(--text-muted);';
    note.textContent =
      'Note: This is a pattern-based detection for learning purposes.';
    body.appendChild(note);
    card.appendChild(body);
    const meta = el('div');
    meta.style.cssText = 'margin-top:10px;font-size:12px;color:var(--text-muted);';

    meta.textContent =
      'Confidence: High • Based on pattern similarity • Context: ' + detectContext(code);

    body.appendChild(meta);

    return card;
  }

  // Build the "Explanation" card (Blue)
  function buildExplanationCard(finding) {
    const card = el('div', 'result-card card card--blue');

    const header = el('div', 'result-card__header');
    const iconWrap = el('div', 'result-card__icon');
    iconWrap.style.background = 'var(--accent-blue-dim)';
    iconWrap.textContent = '🧠';
    const titleWrap = el('div');
    const title = el('div', 'result-card__title');
    title.textContent = 'What This Means';
    const subtitle = el('div', 'result-card__subtitle');
    subtitle.textContent = 'Security impact and attack scenario';
    titleWrap.appendChild(title);
    titleWrap.appendChild(subtitle);
    header.appendChild(iconWrap);
    header.appendChild(titleWrap);
    card.appendChild(header);

    const body = el('div', 'result-card__body');
    const list = el('ul');
    list.style.cssText = 'list-style:none;display:flex;flex-direction:column;gap:10px;';
    finding.explanation.forEach((point, i) => {
      const li = el('li');
      li.style.cssText = 'display:flex;gap:12px;font-size:14px;color:var(--text-secondary);line-height:1.65;';
      const num = el('span');
      num.style.cssText = 'flex-shrink:0;width:20px;height:20px;border-radius:50%;background:var(--accent-blue-dim);border:1px solid rgba(77,158,255,0.3);display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-size:11px;color:var(--accent-blue);margin-top:2px;';
      num.textContent = String(i + 1);
      const text = el('span');
      text.textContent = point; // textContent — safe
      li.appendChild(num);
      li.appendChild(text);
      list.appendChild(li);
    });
    body.appendChild(list);
    card.appendChild(body);

    return card;
  }

  // Build the "Fix Steps" card (Green)
  function buildFixStepsCard(finding) {
    const card = el('div', 'result-card card card--green');

    const header = el('div', 'result-card__header');
    const iconWrap = el('div', 'result-card__icon');
    iconWrap.style.background = 'var(--accent-green-dim)';
    iconWrap.textContent = '🛠️';
    const titleWrap = el('div');
    const title = el('div', 'result-card__title');
    title.textContent = 'How to Fix It';
    const subtitle = el('div', 'result-card__subtitle');
    subtitle.textContent = 'Step-by-step remediation guide';
    titleWrap.appendChild(title);
    titleWrap.appendChild(subtitle);
    header.appendChild(iconWrap);
    header.appendChild(titleWrap);
    card.appendChild(header);

    const body = el('div', 'result-card__body');
    const ol = el('ol', 'steps-list');
    finding.steps.forEach(step => {
      const li = el('li');
      const text = el('span');
      text.textContent = step; // textContent — safe
      li.appendChild(text);
      ol.appendChild(li);
    });
    body.appendChild(ol);
    card.appendChild(body);

    return card;
  }

  // Build the "Fixed Code" block
  function buildFixedCodeCard(finding) {
    const wrapper = el('div', 'card');
    wrapper.style.padding = '0';
    wrapper.style.overflow = 'hidden';

    const block = el('div', 'code-block');
    block.style.border = 'none';
    block.style.borderRadius = '0';
    block.style.margin = '0';

    const blockHeader = el('div', 'code-block__header');
    const dots = el('div', 'code-block__dots');
    ['dot1', 'dot2', 'dot3'].forEach(() => dots.appendChild(el('div', 'code-block__dot')));
    const langLabel = el('span', 'code-block__lang');
    langLabel.textContent = '📋 fixed code';

    const copyBtn = el('button', 'copy-btn');
    copyBtn.textContent = '⎘ Copy';
    copyBtn.addEventListener('click', () => copyToClipboard(finding.fixedCode, copyBtn));

    blockHeader.appendChild(dots);
    blockHeader.appendChild(langLabel);
    blockHeader.appendChild(copyBtn);
    block.appendChild(blockHeader);

    const bodyEl = el('div', 'code-block__body');
    bodyEl.textContent = finding.fixedCode; // textContent — safe
    block.appendChild(bodyEl);
    wrapper.appendChild(block);

    return wrapper;
  }

  // Build "All Clear" state
  function buildAllClear() {
    const card = el('div', 'card');
    card.style.cssText = 'text-align:center;padding:48px 24px;border-color:rgba(0,229,160,0.2);background:rgba(0,229,160,0.04);';
    const icon = el('div');
    icon.style.cssText = 'font-size:40px;margin-bottom:16px;';
    icon.textContent = '✅';
    const title = el('h3');
    title.style.cssText = 'font-family:var(--font-display);font-size:20px;font-weight:700;color:var(--accent-green);margin-bottom:10px;';
    title.textContent = 'No common risk patterns detected';
    const desc = el('p');
    desc.style.cssText = 'font-size:14px;color:var(--text-secondary);max-width:380px;margin:0 auto;line-height:1.7;';
    desc.textContent =
      'No common vulnerability patterns were detected in this snippet. Security issues often depend on full application context — always review critical logic carefully.';
    card.appendChild(icon);
    card.appendChild(title);
    card.appendChild(desc);
    return card;
  }

  /* ── Render results into DOM ───────────────────────────── */
  function renderResults(container, result) {
    // Clear previous results safely
    while (container.firstChild) container.removeChild(container.firstChild);

    if (result.error) {
      const alert = el('div', 'alert alert--error');
      alert.textContent = result.error;
      container.appendChild(alert);
      return;
    }

    if (result.findings.length === 0) {
      container.appendChild(buildAllClear());
      return;
    }

    // Summary badge
    const summary = el('div');
    summary.style.cssText = 'display:flex;align-items:center;gap:12px;margin-bottom:8px;flex-wrap:wrap;';
    const countBadge = el('span', 'badge badge--red badge--dot');
    countBadge.textContent = result.findings.length + ' Vulnerabilit' + (result.findings.length > 1 ? 'ies' : 'y') + ' Found';
    summary.appendChild(countBadge);
    container.appendChild(summary);

    // Render each finding
    result.findings.forEach(finding => {
      const findingWrapper = el('div', 'scan-results');
      findingWrapper.appendChild(buildVulnCard(finding, result.code));
      findingWrapper.appendChild(buildExplanationCard(finding));
      findingWrapper.appendChild(buildFixStepsCard(finding));

      // Fixed code section header
      const codeHeader = el('div');
      codeHeader.style.cssText = 'display:flex;align-items:center;gap:10px;margin-top:4px;';
      const codeIcon = el('span');
      codeIcon.textContent = '📋';
      const codeLabel = el('span');
      codeLabel.style.cssText = 'font-size:14px;font-weight:600;color:var(--text-secondary);font-family:var(--font-display);';
      codeLabel.textContent = 'Fixed Code';
      codeHeader.appendChild(codeIcon);
      codeHeader.appendChild(codeLabel);
      findingWrapper.appendChild(codeHeader);
      findingWrapper.appendChild(buildFixedCodeCard(finding));

      container.appendChild(findingWrapper);

      // Separator between multiple findings
    });
  }

  /* ── Scan button handler ───────────────────────────────── */
  function initScanner() {
    const codeInput = document.getElementById('code-input');
    const scanBtn = document.getElementById('scan-btn');
    const results = document.getElementById('scan-results');
    const charCount = document.getElementById('char-count');

    if (!codeInput || !scanBtn || !results) return;

    // Live character count
    if (charCount) {
      codeInput.addEventListener('input', () => {
        const len = codeInput.value.length;
        charCount.textContent = len.toLocaleString() + ' chars';
        charCount.style.color = len > 40000 ? 'var(--accent-red)' : 'var(--text-muted)';
      });
    }

    // Insert example code snippets
    document.querySelectorAll('[data-example]').forEach(btn => {
      btn.addEventListener('click', () => {
        const exampleKey = btn.dataset.example;
        codeInput.value = CODE_EXAMPLES[exampleKey] || '';
        codeInput.dispatchEvent(new Event('input'));
        codeInput.focus();
        codeInput.scrollTop = 0;
      });
    });

    // Clear button
    const clearBtn = document.getElementById('clear-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        codeInput.value = '';
        codeInput.dispatchEvent(new Event('input'));
        while (results.firstChild) results.removeChild(results.firstChild);
        buildEmptyState(results);
      });
    }

    // Main scan action

    // Debounce : Prevent spam
    let lastScan = 0;
    scanBtn.addEventListener('click', async () => {
      const now = Date.now();
      if (now - lastScan < 1500) return; // prevent spam
      lastScan = now;
      const code = codeInput.value;
      if (!code.trim()) {
        codeInput.style.borderColor = 'var(--accent-red)';
        codeInput.style.boxShadow = '0 0 0 3px var(--accent-red-dim)';
        setTimeout(() => {
          codeInput.style.borderColor = '';
          codeInput.style.boxShadow = '';
        }, 2000);
        return;
      }
      // scan started event for analytics
      gtag('event', 'scan_clicked', {
        event_category: 'engagement',
        event_label: 'scan_button'
      });

      // Show loading state
      scanBtn.disabled = true;
      scanBtn.style.opacity = '0.7';
      const originalHTML = scanBtn.innerHTML;
      scanBtn.innerHTML = '';
      const spinner = el('span', 'spinner');
      const loadText = el('span');
      loadText.textContent = 'Scanning...';
      scanBtn.appendChild(spinner);
      scanBtn.appendChild(loadText);

      // Simulate analysis delay
      await new Promise(r => setTimeout(r, 1200 + Math.random() * 1200));

      try {
        const result = scanCode(code);
        renderResults(results, result);
        // scan completed event for analytics
        gtag('event', 'scan_completed', {
          event_category: 'engagement',
          event_label: 'code_scanned'
        });
      } catch (err) {
        console.error(err);

        const errorBox = el('div', 'alert alert--error');
        errorBox.textContent = 'Something went wrong while analyzing the code. Please try again.';
        results.appendChild(errorBox);
      }

      // Restore button
      scanBtn.innerHTML = originalHTML;
      scanBtn.disabled = false;
      scanBtn.style.opacity = '';

      // Scroll results into view
      results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  // Build initial empty state
  function buildEmptyState(container) {
    const empty = el('div', 'empty-state');
    const icon = el('div', 'empty-state__icon');
    icon.textContent = '🔍';
    const title = el('div', 'empty-state__title');
    title.textContent = 'Paste your code to uncover hidden risks';
    const desc = el('div', 'empty-state__desc');
    desc.textContent =
      'Try pasting a backend query, frontend DOM code, or API config. We will highlight common security risk patterns and show how to fix them.'; empty.appendChild(icon);
    desc.textContent +=
      ' For best results, try the example buttons below.';
    empty.appendChild(title);
    empty.appendChild(desc);
    container.appendChild(empty);
  }

  /* ── Example code snippets ─────────────────────────────── */
  const CODE_EXAMPLES = {
    sqli: `# Python — Flask route with SQL Injection
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/user')
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    return str(user)`,

    xss: `// JavaScript — Dynamic content rendering
function loadUserComment(commentData) {
    const container = document.getElementById('comments');
    
    // VULNERABLE: innerHTML with user data
    container.innerHTML += '<div class="comment">' + commentData.text + '</div>';
    
    // Also vulnerable:
    document.getElementById('username').innerHTML = commentData.author;
    
    // Another issue:
    document.write('<p>' + commentData.date + '</p>');
}

// Called when comment loads from API
fetch('/api/comments').then(r => r.json()).then(data => {
    data.forEach(comment => loadUserComment(comment));
});`,

    secret: `// Node.js — API client with hardcoded secrets
const stripe = require('stripe');
const sendgrid = require('@sendgrid/mail');
const aws = require('aws-sdk');

// VULNERABLE: hardcoded credentials
const stripeClient = stripe('sk-prod_4xT8kLmNpQrSvWyZ1234567890abcdef');

sendgrid.setApiKey('SG.xK8mP2qR_tNvYw.AbCdEfGhIjKlMnOpQrStUvWxYz1234567890-ABCDEF');

const s3 = new aws.S3({
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1'
});

const DB_PASSWORD = 'Sup3rS3cr3tP@ssw0rd!';`,
  };

  /* ── Boot ──────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', () => {
    const results = document.getElementById('scan-results');
    if (results) buildEmptyState(results);
    initScanner();
  });
})();

// Simple feedback from users
      function sendFeedback(type) {
        gtag('event', 'feedback', {
          event_category: 'engagement',
          event_label: type
        });
      }
