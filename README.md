# DevSecOps + AI Assignment — Git setup & repo template (ready-to-use)

Below is a ready-to-use plan and a set of files/instructions you can place in your upstream repository
so the student can fork, work in their fork, and submit via a pull request.

It includes:

* Git workflow (fork → branch → PR)
* Repo structure and README (assignment brief)
* Seeded-vulnerabilities ideas the student must find & document
* An AI-agent integration spec (how the student plugs an LLM into the pipeline)
* A sample GitHub Actions workflow that runs SAST + an AI scan step (placeholder)
* Submission and evaluation checklist / rubric

Copy the Markdown below into your repository as README.md (or into the assignment mail), plus create the sample
.github/workflows/security.yml and an issue template if you want.

---

## AI-Integrated DevSecOps Assignment — Repo Setup & Instructions

### Overview

This repository is the assignment seed.
Your task is to fork this repo, find and document security flaws in the seeded project, implement fixes where
appropriate,
and integrate an AI-assisted security scanner into a CI stage that helps detect and explain issues.

Work in your fork. Create a feature branch for your work and open a Pull Request (PR) from your fork to your fork
(or to upstream if instructed) when you're ready for review.

---

## Quick Git workflow (what the student does)

1. Fork the upstream repo (this repo) to your own GitHub account.
2. Clone your fork:

```bash
git clone git@github.com:<your-username>/<repo>.git
cd <repo>
```

3. Create a branch for the assignment:

```bash
git checkout -b feat/devsecops-ai-<yourname>
```

4. Do your work (fixes, docs, AI scanner, pipeline changes).
5. Commit regularly with clear messages:

```bash
git add .
git commit -m "Fix: sanitize input on /login route; add semgrep rule"
```

6. Push branch and open a PR from your fork to your fork (or to upstream if requested). Share link with the reviewer.

---

## Repo structure (recommended)

```dir
/
├─ app/                      # minimal demo app (Flask/Express) with seeded issues
├─ docs/                     # additional instructions, threat model
├─ scanner/                  # AI-assisted scanner code (Python/Node)
│   ├─ scanner.py
│   └─ requirements.txt
├─ .github/
│   └─ workflows/
│       └─ security.yml      # CI pipeline that runs SAST + AI scan
├─ seeded-vulnerabilities.md # list (hidden to student in real test; here for maintainers)
├─ README.md                 # this assignment brief
└─ AI_DevSecOps_Report.md    # student deliverable template
```

---

## Assignment tasks (what the student must deliver)

1. Explore the app in app/ and locate security vulnerabilities or misconfigurations.
2. Document at least 3 security issues:
    * For each: title, file / line, impact, exploit steps, proposed fix.
    * Put this in docs/security_findings.md (or AI_DevSecOps_Report.md).
3. Implement at least 1 fix in the codebase (commit to your branch).
4. Build an AI-assisted scanner:
    * It should scan code, dependency files, or SAST output and produce human-readable explanations and suggested
      remediations.
    * Must produce sample output included in the repo (scanner/samples/*.md).
5. Integrate scanner into CI:
    * Add to .github/workflows/security.yml as a pipeline stage (the repo includes a sample you can use/extend).
    * The AI step may be implemented as a script that uses an LLM (via API key in secrets) or a local LLM if the
      student prefers.
6. Deliver a short report summarizing tools used, findings, how AI was integrated, limitations, and next steps.

---

## AI-assisted scanner — expected behaviour & example

**Purpose**: show how an LLM can help triage and explain security findings, not to replace deterministic tools.

**Minimum requirements** for the student's scanner:

* Accepts a target (file path or repo root).
* Runs or ingests SAST output (e.g., Semgrep/Bandit JSON) or scans files directly.
* Calls an LLM (API or local) to:
    * Summarize the suspicious snippets.
    * Explain why something is a vulnerability.
    * Suggest remediation in plain language and code changes.
* Writes a human-readable report (scanner/output/<timestamp>_ai_report.md) with examples.

```bash
cd scanner
python scanner.py --target ../app --output ../scanner/samples/report.md
```

**Security note for student: do not commit keys. Use env vars or GitHub Secrets.**

---

## CI Pipeline (sample .github/workflows/security.yml)

Place this file at .github/workflows/security.yml. It runs SAST and calls the AI scanner stage (AI step
uses a secret like LLM_API_KEY).

```yaml
name: Security CI

on:
  push:
    branches:
      - '**'
  pull_request:

jobs:
  sast:
    name: SAST Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install Semgrep & deps
        run: |
          python -m pip install --upgrade pip
          pip install semgrep
      - name: Run Semgrep
        run: |
          semgrep --config p/ci --json --output semgrep-results.json ./app || true
      - name: Upload SAST results
        uses: actions/upload-artifact@v4
        with:
          name: semgrep-results
          path: semgrep-results.json

  ai_scan:
    name: AI-assisted Scan
    runs-on: ubuntu-latest
    needs: sast
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install scanner deps
        run: |
          pip install -r scanner/requirements.txt
      - name: Run AI Scanner
        env:
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: |
          python scanner/scanner.py --target ./app --sast ./semgrep-results.json --output scanner/output/ci_ai_report.md || true
      - name: Upload AI report
        uses: actions/upload-artifact@v4
        with:
          name: ai-report
          path: scanner/output/ci_ai_report.md

```

`The ai_scan job expects scanner/scanner.py to accept a --sast argument. Students may adapt as needed.`

---

## How the AI integration can be implemented (suggestions for student)

* Use a small wrapper script that:
    * Loads semgrep-results.json or reads suspicious file snippets.
    * Sends context + snippet + a prompt to the LLM asking for: vulnerability classification, risk level, remediation
      steps, and a short remediation patch suggestion.

* Prompt design ideas:
    * "Given this code snippet and SAST warning, explain the vulnerability in 2–3 short bullets, show an example fix,
      and list
      why this fix is safe."

* Options for LLM:
    * Hosted APIs (OpenAI, Google Gemini) — must put keys into GitHub Secrets (for CI) or local env for development.
    * Local LLM (Ollama, llama.cpp, etc.) if privacy concerns exist.

**Responsible use**: Student must ensure the scanner is not used to attack external targets. Scanning is restricted to
this repo/workspace only.

---

## Hints for the student

* Start by running Semgrep locally to get quick hits: semgrep --config p/ci ./app
* Keep the AI prompts narrowly scoped: include file name, ~6–12 lines of context.
* Ensure the CI job does not leak secrets or write to external services without permission.
* Automate report generation (Markdown) so reviewers can open one file with results.

---

## Example scanner/README.md (to include in repo)

```bash
# AI-assisted scanner

Requirements:
- Python 3.10
- pip install -r requirements.txt
- Set LLM_API_KEY as env var

Run:
python scanner.py --target ../app --sast ../semgrep-results.json --output ./output/report.md
```