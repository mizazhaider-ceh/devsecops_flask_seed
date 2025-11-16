# Universal AI Security Scanner

## Overview

AI-powered security scanner that analyzes **source code**, **dependency files**, and **SAST reports** using Google Gemini 2.5 Pro. Supports **any programming language** and multiple security tools with **batch processing** for speed and cost efficiency.

**Author:** Muhammad Izaz Haider (@mizazhaider-ceh)  
**Date:** November 16, 2025  
**Version:** 2.0 (Universal Multi-Language)

---

## Key Features

- 🌐 **Multi-Language Support** - Python, JavaScript, Java, C/C++, Go, Ruby, PHP, C#, TypeScript, Rust, Swift, Kotlin, and more
- 📦 **Dependency Analysis** - Scans requirements.txt, package.json, Gemfile, pom.xml, go.mod, Cargo.toml, etc.
- 🔍 **SAST Integration** - Semgrep, Bandit, ESLint, SonarQube, SARIF, Generic JSON/XML
- ⚡ **Batch Processing** - One API call for all vulnerabilities (no rate limits)
- 🎯 **4 Scan Modes** - SAST reports, source code, dependencies, or full scan
- 📊 **Smart Analysis** - Context-aware security assessment with exploit examples
- 📝 **Professional Reports** - Markdown reports with OWASP/CWE mapping
- 🚀 **CI/CD Ready** - GitHub Actions integration included

---

## Quick Start

### Step 1: Navigate to Scanner

```bash
cd devsecops_flask_seed/scanner
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Set Gemini API Key

```bash
export GEMINI_API_KEY="your-api-key-here"
# Get free API key from: https://ai.google.dev/
```

### Step 4: Choose Your Scan Mode

#### Option A: Analyze SAST Results

```bash
semgrep ci --json --output=semgrep-results.json
python scanner.py --mode sast --target ../app --sast semgrep-results.json --output output/sast_report.md
```

#### Option B: Analyze Source Code

```bash
python scanner.py --mode code --target ../app --output output/code_report.md
```

#### Option C: Analyze Dependencies

```bash
python scanner.py --mode dependency --target .. --output output/dep_report.md
```

#### Option D: Full Scan (All Modes)

```bash
semgrep ci --json --output=semgrep-results.json
python scanner.py --mode full --target .. --sast semgrep-results.json --output output/full_report.md
```

### Step 5: View Results

```bash
cat output/*_report.md
```

---

## Supported Languages & Files

### Source Code (30+ Languages)

**Web:** Python, JavaScript, TypeScript, PHP, Ruby, Go  
**Enterprise:** Java, C#, Scala, Kotlin  
**Systems:** C, C++, Rust, Swift  
**Scripting:** Bash, PowerShell, SQL  
**Markup:** HTML, XML

### Dependency Files

**Python:** requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, setup.py, poetry.lock  
**JavaScript:** package.json, package-lock.json, yarn.lock  
**Ruby:** Gemfile, Gemfile.lock  
**Java:** pom.xml, build.gradle  
**Go:** go.mod, go.sum  
**Rust:** Cargo.toml, Cargo.lock  
**PHP:** composer.json, composer.lock

### SAST Tools

**Supported:** Semgrep, Bandit, ESLint, SonarQube, SARIF  
**Formats:** JSON, XML, CSV

---

## Why Batch Processing?

### The Problem with Individual API Calls
- 22 vulnerabilities = 22 separate API calls
- Rate limits: Only 2 requests/minute on free tier
- Total time: ~11 minutes with failures
- Constant 429 RESOURCE_EXHAUSTED errors
- High API costs

### The Solution - Single Batch Call
- 22 vulnerabilities = 1 API request ✅
- No rate limit issues
- Complete in ~15 seconds
- 95% cost reduction
- Better AI context (sees all vulnerabilities together)

---

## Installation

```bash
cd scanner
pip install -r requirements.txt
```

**Dependencies:**
- `google-genai>=0.2.0` - Google Gemini API client
- `semgrep` - SAST tool integration

---

## Command-Line Arguments

| Argument | Required | Description | Default |
|----------|----------|-------------|---------|
| `--target` | Yes | Target directory to scan | - |
| `--sast` | Yes | Path to Semgrep JSON results | - |
| `--output` | Yes | Output path for report | - |
| `--limit` | No | Max vulnerabilities to analyze | All |

**Example:**
```bash
python scanner/scanner.py \
  --target ./app \
  --sast ./semgrep-results.json \
  --output ./output/report.md \
  --limit 10  # Optional: analyze first 10 only
```

---

## Semgrep Scanning Strategy

### Basic Scan (Limited)
```bash
semgrep ./app --json --output=findings.json
# Finds: ~11 code vulnerabilities
```

### Semgrep CI (Recommended)
```bash
semgrep ci --json --output=semgrep-results.json
# Finds: ~22 vulnerabilities including:
# - All code vulnerabilities
# - Supply chain CVEs (Flask, urllib3, requests)
# - Security misconfigurations
```

**Why Semgrep CI?**
- Access to Semgrep Pro rules
- CVE detection in dependencies
- More comprehensive security coverage
- Better CI/CD integration

---

## Output Report Structure

The scanner generates `ai_report.md` with:

### 1. Executive Summary
- Total vulnerabilities found
- Scan coverage statistics
- AI model information

### 2. Vulnerability Summary Table
All findings at a glance with file, line, rule, and severity.

### 3. AI Security Analysis
For each vulnerability:
- **Severity & Impact** - Why it's dangerous
- **Exploit Example** - Real attack payload
- **Fix Recommendation** - Secure code (before/after)
- **OWASP Reference** - Industry standard mapping

### 4. Scan Metadata
Timestamp, model version, API call count.

---

## Sample Output

```markdown
## Vulnerability 3: RCE via eval()
**Location:** `app/admin_tools.py:8`
**Severity:** CRITICAL

### 1. Severity & Impact
Complete server takeover via arbitrary code execution.
Attacker can run system commands, steal data, install malware.

### 2. Exploit Example
curl "http://app/eval?expr=__import__('os').system('whoami')"

### 3. Fix Recommendation
Before: result = eval(expr)  # INSECURE
After:  result = ast.literal_eval(expr)  # SECURE

### 4. OWASP Reference
A03:2021 – Injection
```

---

## CI/CD Integration

Already integrated in `.github/workflows/security.yml`:

```yaml
ai_scan:
  name: AI-assisted Scan
  runs-on: ubuntu-latest
  needs: sast
  steps:
    - name: Download SAST results
      uses: actions/download-artifact@v4
      with:
        name: semgrep-results
    
    - name: Install scanner dependencies
      run: pip install -r scanner/requirements.txt
    
    - name: Run AI Security Scanner
      env:
        GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      run: |
        python scanner/scanner.py \
          --target ./app \
          --sast ./semgrep-results.json \
          --output scanner/output/ci_ai_report.md
    
    - name: Upload AI report
      uses: actions/upload-artifact@v4
      with:
        name: ai-report
        path: scanner/output/ci_ai_report.md
```

**Setup:** Add `GEMINI_API_KEY` secret in GitHub repository settings.

---

## Architecture

```
scanner/
├── scanner.py              # Main scanner with batch processing
├── requirements.txt        # Dependencies
├── README.md              # This file
├── IMPLEMENTATION_SUMMARY.md  # Technical details
└── output/
    └── ai_report.md       # Generated AI analysis
```

### Core Components

**AISecurityScanner Class:**
- `analyze_all_with_ai()` - Batch analysis (single API call)
- `load_sast_results()` - Parse Semgrep JSON
- `extract_vulnerability_info()` - Extract file/line/severity
- `generate_report()` - Create Markdown report

---

## Environment Variables

| Variable | Description | Where Used |
|----------|-------------|------------|
| `GEMINI_API_KEY` | Google Gemini API key | Local & CI/CD |

**Setup:**
```bash
# Local Development
export GEMINI_API_KEY="AIza..."

# CI/CD (GitHub Actions)
# Add as GitHub secret: Settings → Secrets and variables → Actions
# Secret name: GEMINI_API_KEY
# Secret value: Your API key from https://ai.google.dev/
```

---

## Performance Metrics

| Metric | Individual Calls | Batch Processing |
|--------|-----------------|------------------|
| API Calls | 22 | 1 |
| Time | ~11 minutes | ~15 seconds |
| Rate Limit Errors | 18 failures | 0 failures |
| Cost | 22x | 1x |
| Success Rate | 18% | 100% |

---

## Troubleshooting

### Error: "google-genai package not installed"
```bash
pip install google-genai
```

### Error: "API key not found"
```bash
export GEMINI_API_KEY="your-api-key"
# Get your free API key from: https://ai.google.dev/
```

### Error: "SAST file not found"
```bash
semgrep ci --json --output=semgrep-results.json
```

### Warning: "No vulnerabilities found"
Normal if code is secure. Empty report will be generated.

---

## Security Considerations

1. **API Key Protection**
   - Never commit keys to Git
   - Use environment variables
   - `.gitignore` configured for safety

2. **Data Privacy**
   - Source code sent to Google Gemini API
   - Review Google's privacy policy
   - Consider on-premise LLM for sensitive code

3. **API Rate Limits**
   - Free tier: 2 req/min (batch processing avoids this)
   - Monitor usage: https://ai.dev/usage

---

## References

- **Google Gemini API:** https://ai.google.dev/
- **Semgrep CI:** https://semgrep.dev/docs/semgrep-ci/
- **OWASP Top 10:** https://owasp.org/Top10/
- **Implementation Details:** See `IMPLEMENTATION_SUMMARY.md`

---

## Contact

**Muhammad Izaz Haider**  
GitHub: [@mizazhaider-ceh](https://github.com/mizazhaider-ceh)

---

*Last Updated: November 16, 2025*
