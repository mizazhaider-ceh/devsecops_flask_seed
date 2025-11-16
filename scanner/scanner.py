#!/usr/bin/env python3
"""
Universal AI-Assisted Security Scanner
Analyzes code files (any language), dependency files, and SAST outputs
Uses Google Gemini API for intelligent security analysis

Supports:
- Source Code: .py, .js, .java, .c, .cpp, .go, .rb, .php, .cs, .ts, .jsx, .tsx, etc.
- Dependencies: requirements.txt, package.json, Gemfile, pom.xml, go.mod, etc.
- SAST Reports: Semgrep JSON, Bandit JSON, ESLint JSON, SonarQube JSON, etc.

Author: Muhammad Izaz Haider
Date: November 16, 2025
GitHub: @mizazhaider-ceh
"""

import json
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# Check for required packages
try:
    from google import genai
except ImportError:
    print("ERROR: google-genai package not installed")
    print("Please run: pip install google-genai")
    sys.exit(1)


class AISecurityScanner:
    """Universal AI-powered security scanner using Google Gemini"""
    
    # Supported file extensions by category
    CODE_EXTENSIONS = {
        '.py', '.js', '.java', '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
        '.go', '.rb', '.php', '.cs', '.ts', '.tsx', '.jsx', '.rs', '.swift',
        '.kt', '.scala', '.sh', '.bash', '.ps1', '.sql', '.html', '.xml'
    }
    
    DEPENDENCY_FILES = {
        'requirements.txt', 'package.json', 'package-lock.json', 'yarn.lock',
        'Gemfile', 'Gemfile.lock', 'pom.xml', 'build.gradle', 'go.mod', 'go.sum',
        'Cargo.toml', 'Cargo.lock', 'composer.json', 'composer.lock', 'Pipfile',
        'Pipfile.lock', 'poetry.lock', 'pyproject.toml', 'setup.py'
    }
    
    SAST_EXTENSIONS = {
        '.json', '.sarif', '.xml', '.csv'
    }
    
    def __init__(self, api_key: str):
        """Initialize scanner with Gemini API key"""
        if not api_key:
            raise ValueError("API key is required")
        
        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-2.5-pro"
        print(f"✅ Initialized Gemini model: {self.model}")
    
    def detect_file_type(self, filepath: str) -> Tuple[str, str]:
        """Detect file type: 'code', 'dependency', 'sast', or 'unknown'"""
        path = Path(filepath)
        filename = path.name
        extension = path.suffix.lower()
        
        # Check if it's a dependency file
        if filename in self.DEPENDENCY_FILES:
            return 'dependency', filename
        
        # Check if it's a code file
        if extension in self.CODE_EXTENSIONS:
            return 'code', extension
        
        # Check if it's a SAST report
        if extension in self.SAST_EXTENSIONS:
            return 'sast', extension
        
        return 'unknown', extension
    
    def scan_directory(self, target_dir: str) -> Dict[str, List[str]]:
        """Scan target directory for all supported file types"""
        target_path = Path(target_dir)
        if not target_path.exists():
            print(f"WARNING: Target directory not found: {target_dir}")
            return {'code': [], 'dependency': [], 'sast': []}
        
        categorized_files = {'code': [], 'dependency': [], 'sast': []}
        
        for file_path in target_path.rglob("*"):
            if file_path.is_file():
                file_type, _ = self.detect_file_type(str(file_path))
                if file_type in categorized_files:
                    categorized_files[file_type].append(str(file_path))
        
        print(f"📁 Scan results for {target_dir}:")
        print(f"   - Code files: {len(categorized_files['code'])}")
        print(f"   - Dependency files: {len(categorized_files['dependency'])}")
        print(f"   - SAST reports: {len(categorized_files['sast'])}")
        
        return categorized_files
    
    def load_sast_results(self, filepath: str) -> Tuple[List[Dict[str, Any]], str]:
        """Load SAST results from various formats (Semgrep, Bandit, ESLint, etc.)"""
        if not filepath or not os.path.exists(filepath):
            print(f"WARNING: SAST file not found: {filepath}")
            return [], 'unknown'
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Detect SAST tool format
            # Semgrep format
            if 'results' in data and isinstance(data['results'], list):
                results = data['results']
                print(f"📊 Loaded {len(results)} findings from Semgrep")
                return results, 'semgrep'
            
            # Bandit format
            elif 'results' in data and isinstance(data.get('metrics'), dict):
                results = data['results']
                print(f"📊 Loaded {len(results)} findings from Bandit")
                return results, 'bandit'
            
            # ESLint format
            elif isinstance(data, list) and len(data) > 0 and 'messages' in data[0]:
                results = []
                for file_result in data:
                    for msg in file_result.get('messages', []):
                        msg['filePath'] = file_result.get('filePath', 'unknown')
                        results.append(msg)
                print(f"📊 Loaded {len(results)} findings from ESLint")
                return results, 'eslint'
            
            # SonarQube format
            elif 'issues' in data:
                results = data['issues']
                print(f"📊 Loaded {len(results)} findings from SonarQube")
                return results, 'sonarqube'
            
            # Generic array of findings
            elif isinstance(data, list):
                print(f"📊 Loaded {len(data)} findings (generic format)")
                return data, 'generic'
            
            else:
                print(f"WARNING: Unknown SAST format in {filepath}")
                return [], 'unknown'
                
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in {filepath}: {e}")
            return [], 'error'
        except Exception as e:
            print(f"ERROR: Failed to load SAST results: {e}")
            return [], 'error'
    
    def extract_vulnerability_info(self, vuln: Dict[str, Any], sast_type: str) -> Dict[str, str]:
        """Extract key information from various SAST tool formats"""
        try:
            if sast_type == 'semgrep':
                return {
                    'file': vuln.get('path', 'Unknown'),
                    'line': str(vuln.get('start', {}).get('line', 'Unknown')),
                    'rule_id': vuln.get('check_id', 'Unknown'),
                    'message': vuln.get('extra', {}).get('message', 'No description'),
                    'severity': vuln.get('extra', {}).get('severity', 'UNKNOWN').upper(),
                    'code': vuln.get('extra', {}).get('lines', ''),
                }
            
            elif sast_type == 'bandit':
                return {
                    'file': vuln.get('filename', 'Unknown'),
                    'line': str(vuln.get('line_number', 'Unknown')),
                    'rule_id': vuln.get('test_id', 'Unknown'),
                    'message': vuln.get('issue_text', 'No description'),
                    'severity': vuln.get('issue_severity', 'UNKNOWN').upper(),
                    'code': vuln.get('code', ''),
                }
            
            elif sast_type == 'eslint':
                return {
                    'file': vuln.get('filePath', 'Unknown'),
                    'line': str(vuln.get('line', 'Unknown')),
                    'rule_id': vuln.get('ruleId', 'Unknown'),
                    'message': vuln.get('message', 'No description'),
                    'severity': ('ERROR' if vuln.get('severity') == 2 else 'WARNING'),
                    'code': '',
                }
            
            elif sast_type == 'sonarqube':
                return {
                    'file': vuln.get('component', 'Unknown'),
                    'line': str(vuln.get('line', 'Unknown')),
                    'rule_id': vuln.get('rule', 'Unknown'),
                    'message': vuln.get('message', 'No description'),
                    'severity': vuln.get('severity', 'UNKNOWN').upper(),
                    'code': '',
                }
            
            else:  # generic
                return {
                    'file': vuln.get('file', vuln.get('path', 'Unknown')),
                    'line': str(vuln.get('line', 'Unknown')),
                    'rule_id': vuln.get('rule', vuln.get('id', 'Unknown')),
                    'message': vuln.get('message', str(vuln)),
                    'severity': vuln.get('severity', 'UNKNOWN').upper(),
                    'code': vuln.get('code', ''),
                }
        
        except Exception as e:
            print(f"WARNING: Failed to extract vulnerability info: {e}")
            return {
                'file': 'Unknown',
                'line': 'Unknown',
                'rule_id': 'Unknown',
                'message': str(vuln),
                'severity': 'UNKNOWN',
                'code': '',
            }
    
    def analyze_code_files(self, files: List[str]) -> str:
        """Analyze source code files for security issues"""
        print(f"\n🔍 Analyzing {len(files)} code files...")
        
        files_content = ""
        for file_path in files[:20]:  # Limit to 20 files per batch
            try:
                path = Path(file_path)
                if path.exists():
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    file_type, ext = self.detect_file_type(file_path)
                    files_content += f"""
---
### File: `{file_path}` ({ext})
```{ext.lstrip('.')}
{content[:5000]}  # Truncate large files
```
"""
            except Exception as e:
                files_content += f"\n### File: `{file_path}` - Error: {e}\n"
        
        prompt = f"""You are an expert security researcher analyzing source code for vulnerabilities.

# TASK
Analyze the following source code files and identify security vulnerabilities, code quality issues, and potential risks.

# SOURCE CODE FILES
{files_content}

# INSTRUCTIONS
For EACH vulnerability found, provide:

## Vulnerability: [Description]

**File:** `[filename]:[line]`
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
**Type:** [e.g., SQL Injection, XSS, Hardcoded Secret, etc.]

### 1. Issue Description (2-3 sentences)
Explain what's wrong and why it's dangerous.

### 2. Exploit Scenario
Show how an attacker could exploit this.

### 3. Fix Recommendation
Provide secure code example showing the fix.

### 4. OWASP/CWE Reference
Which OWASP Top 10 category and CWE number?

---

Focus on:
- Injection vulnerabilities (SQL, Command, XSS, etc.)
- Authentication/Authorization flaws
- Sensitive data exposure
- Hardcoded secrets/credentials
- Insecure configurations
- Cryptographic issues

Be concise, technical, and actionable."""

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            print(f"✅ Code analysis complete!")
            return response.text
        except Exception as e:
            error_msg = f"Code analysis failed: {str(e)}"
            print(f"⚠️  {error_msg}")
            return f"## Code Analysis Error\n\n{error_msg}"
    
    def analyze_dependency_files(self, files: List[str]) -> str:
        """Analyze dependency files for known vulnerabilities"""
        print(f"\n🔍 Analyzing {len(files)} dependency files...")
        
        deps_content = ""
        for file_path in files:
            try:
                path = Path(file_path)
                if path.exists():
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    deps_content += f"""
---
### Dependency File: `{file_path}`
```
{content}
```
"""
            except Exception as e:
                deps_content += f"\n### File: `{file_path}` - Error: {e}\n"
        
        prompt = f"""You are an expert security analyst specializing in dependency vulnerabilities.

# TASK
Analyze the following dependency files and identify outdated packages, known CVEs, and security risks.

# DEPENDENCY FILES
{deps_content}

# INSTRUCTIONS
For EACH vulnerable dependency, provide:

## Vulnerability: [Package Name] - [CVE or Issue]

**Package:** [name]
**Current Version:** [version]
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
**CVE/Advisory:** [CVE number or advisory link if known]

### 1. Vulnerability Description
What's the security issue?

### 2. Impact
What can an attacker achieve?

### 3. Fix Recommendation
Which version should be used? Provide upgrade command.

### 4. Additional Context
Any breaking changes or migration notes?

---

Focus on:
- Known CVEs in dependencies
- Outdated packages with security patches
- Deprecated packages
- Packages with known vulnerabilities
- Supply chain risks

Provide specific version numbers and upgrade paths."""

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            print(f"✅ Dependency analysis complete!")
            return response.text
        except Exception as e:
            error_msg = f"Dependency analysis failed: {str(e)}"
            print(f"⚠️  {error_msg}")
            return f"## Dependency Analysis Error\n\n{error_msg}"
    
    def analyze_sast_with_ai(self, vulnerabilities: List[Dict[str, str]]) -> str:
        """Analyze SAST findings with AI for enhanced explanations"""
        
        print(f"\n🔍 Preparing batch analysis for {len(vulnerabilities)} SAST findings...")
        
        # Read all unique files
        file_contents = {}
        for vuln_info in vulnerabilities:
            file_path = vuln_info['file']
            if file_path not in file_contents and file_path != 'Unknown':
                try:
                    path = Path(file_path)
                    if path.exists():
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            file_contents[file_path] = f.read()
                        print(f"    ✓ Loaded: {file_path} ({len(file_contents[file_path])} bytes)")
                    else:
                        file_contents[file_path] = vuln_info.get('code', 'File not found')
                except Exception as e:
                    file_contents[file_path] = f"Error reading file: {e}"
        
        # Build comprehensive prompt with all vulnerabilities
        vuln_list = ""
        for i, vuln_info in enumerate(vulnerabilities, 1):
            vuln_list += f"""
---
### Vulnerability {i}
- **File:** `{vuln_info['file']}`
- **Line:** {vuln_info['line']}
- **Rule ID:** {vuln_info['rule_id']}
- **Severity:** {vuln_info['severity']}
- **SAST Message:** {vuln_info['message']}
"""
        
        # Build file contents section
        files_section = ""
        for file_path, content in file_contents.items():
            files_section += f"""
---
#### File: `{file_path}`
```python
{content}
```
"""
        
        prompt = f"""You are an expert security researcher analyzing SAST findings with deep code understanding.

# TASK
Analyze ALL {len(vulnerabilities)} vulnerabilities from SAST scan and provide comprehensive security insights.

# SAST FINDINGS
{vuln_list}

# SOURCE CODE FILES
{files_section}

# INSTRUCTIONS
For EACH vulnerability, provide:

## Vulnerability [Number]: [Rule ID]

**Location:** `[file]:[line]`
**Severity:** [severity]

### 1. Issue Explanation (2-3 sentences)
Why is this dangerous? What can an attacker achieve?

### 2. Exploit Example
Show a realistic attack payload or scenario with actual code.

### 3. Secure Fix
Provide secure code replacement (before/after if possible).

### 4. References
OWASP Top 10 category, CWE number, and security best practices.

---

Prioritize CRITICAL and HIGH severity issues. Be concise, technical, and provide actionable remediation."""

        print(f"\n🤖 Sending batch request to Gemini API...")
        print(f"    Prompt size: {len(prompt)} characters")
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            print(f"✅ SAST analysis complete!")
            return response.text
            
        except Exception as e:
            error_msg = f"AI SAST analysis failed: {str(e)}"
            print(f"⚠️  {error_msg}")
            return f"## SAST Analysis Error\n\n{error_msg}\n\nPlease check your API key and rate limits."
    
    def generate_report(
        self, 
        ai_analysis: str,
        scan_type: str,
        output_path: str,
        target_dir: str = "./",
        file_stats: Optional[Dict[str, int]] = None,
        vulnerabilities: Optional[List[Dict[str, str]]] = None
    ):
        """Generate comprehensive Markdown report with AI analysis"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        report = f"""# Universal AI-Assisted Security Scan Report

**Generated:** {timestamp}  
**AI Model:** Google Gemini 2.5 Pro
**Scan Type:** {scan_type.upper()}
**Target:** {target_dir}

---

## Executive Summary

This report provides AI-enhanced security analysis using Google Gemini 2.5 Pro.

**Scan Coverage:**
"""
        
        if file_stats:
            report += f"""- Code files: {file_stats.get('code', 0)}
- Dependency files: {file_stats.get('dependency', 0)}
- SAST reports: {file_stats.get('sast', 0)}
"""
        
        if vulnerabilities:
            report += f"- Vulnerabilities found: {len(vulnerabilities)}\n"
        
        report += f"""
**Analysis Method:** Batch processing (optimized API usage)

---
"""
        
        # Add vulnerability summary table if applicable
        if vulnerabilities and scan_type == 'sast':
            report += """
## Vulnerability Summary

| # | File | Line | Rule | Severity |
|---|------|------|------|----------|
"""
            for i, vuln_info in enumerate(vulnerabilities, 1):
                rule_id = vuln_info['rule_id'][:40] + '...' if len(vuln_info['rule_id']) > 40 else vuln_info['rule_id']
                report += f"| {i} | `{vuln_info['file']}` | {vuln_info['line']} | {rule_id} | {vuln_info['severity']} |\n"
            
            report += "\n---\n"
        
        report += f"""
## AI Security Analysis

{ai_analysis}

---

## Scan Metadata

| Attribute | Value |
|-----------|-------|
| **Scan Date** | {timestamp} |
| **AI Model** | Gemini 2.5 Pro |
| **Scan Type** | {scan_type.upper()} |
| **Target** | {target_dir} |
"""
        
        if file_stats:
            report += f"""| **Files Analyzed** | Code: {file_stats.get('code', 0)}, Dependencies: {file_stats.get('dependency', 0)}, SAST: {file_stats.get('sast', 0)} |
"""
        
        if vulnerabilities:
            report += f"| **Vulnerabilities** | {len(vulnerabilities)} |\n"
        
        report += """
---

## Scanner Capabilities

This universal AI scanner supports:

### Source Code Analysis
- Python (.py), JavaScript (.js), Java (.java), C/C++ (.c, .cpp)
- Go (.go), Ruby (.rb), PHP (.php), C# (.cs), TypeScript (.ts)
- Rust (.rs), Swift (.swift), Kotlin (.kt), Scala (.scala)
- Shell scripts (.sh, .bash, .ps1), SQL, HTML, XML

### Dependency Analysis
- Python: requirements.txt, Pipfile, pyproject.toml
- JavaScript: package.json, yarn.lock, package-lock.json
- Ruby: Gemfile, Gemfile.lock
- Java: pom.xml, build.gradle
- Go: go.mod, go.sum
- Rust: Cargo.toml, Cargo.lock
- PHP: composer.json, composer.lock

### SAST Report Analysis
- Semgrep JSON
- Bandit JSON
- ESLint JSON
- SonarQube JSON
- SARIF format
- Generic JSON/XML reports

---

*Report generated by Universal AI Security Scanner*  
**Author:** Muhammad Izaz Haider (@mizazhaider-ceh)  
**Version:** 2.0 (Universal Multi-Language Support)
"""

        # Write report
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            
            print(f"\n✅ Report generated: {output_path}")
            return True
            
        except Exception as e:
            print(f"\n❌ Failed to write report: {e}")
            return False


def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description='Universal AI Security Scanner - Analyze code, dependencies, and SAST reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze SAST results
  python scanner.py --mode sast --target ./app --sast semgrep-results.json --output report.md
  
  # Analyze source code
  python scanner.py --mode code --target ./src --output code-analysis.md
  
  # Analyze dependencies
  python scanner.py --mode dependency --target . --output dependency-report.md
  
  # Full scan (code + dependencies + SAST)
  python scanner.py --mode full --target . --sast results.json --output full-report.md

Supported Languages:
  Python, JavaScript, Java, C/C++, Go, Ruby, PHP, C#, TypeScript, Rust, Swift, Kotlin, etc.

SAST Tools:
  Semgrep, Bandit, ESLint, SonarQube, SARIF, Generic JSON/XML
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['sast', 'code', 'dependency', 'full'],
        default='sast',
        help='Scan mode: sast (SAST reports), code (source files), dependency (dep files), full (all)'
    )
    
    parser.add_argument(
        '--target',
        required=True,
        help='Target directory or file to scan'
    )
    
    parser.add_argument(
        '--sast',
        help='Path to SAST report file (JSON/XML) - required for sast/full modes'
    )
    
    parser.add_argument(
        '--output',
        required=True,
        help='Output path for report (e.g., scanner/output/report.md)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Max items to analyze per category (default: all)'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("🤖 UNIVERSAL AI SECURITY SCANNER")
    print("=" * 70)
    print(f"Mode: {args.mode.upper()}")
    print(f"Target: {args.target}")
    if args.sast:
        print(f"SAST Input: {args.sast}")
    print(f"Output: {args.output}")
    print("=" * 70)
    
    # Validate mode-specific requirements
    if args.mode in ['sast', 'full'] and not args.sast:
        print("\n❌ ERROR: --sast argument required for 'sast' and 'full' modes")
        sys.exit(1)
    
    # Get API key from environment
    api_key = os.environ.get('GEMINI_API_KEY')
    
    if not api_key:
        print("\n❌ ERROR: GEMINI_API_KEY not found")
        print("\nPlease set the environment variable:")
        print("  export GEMINI_API_KEY='your-api-key-here'")
        print("\nGet your free API key from: https://ai.google.dev/")
        print("\nFor CI/CD: Add GEMINI_API_KEY secret in GitHub repository settings")
        sys.exit(1)
    
    # Initialize scanner
    try:
        scanner = AISecurityScanner(api_key)
    except Exception as e:
        print(f"\n❌ Failed to initialize scanner: {e}")
        sys.exit(1)
    
    # Scan target directory
    print(f"\n📁 Scanning target: {args.target}")
    categorized_files = scanner.scan_directory(args.target)
    
    file_stats = {
        'code': len(categorized_files.get('code', [])),
        'dependency': len(categorized_files.get('dependency', [])),
        'sast': len(categorized_files.get('sast', []))
    }
    
    ai_analysis = ""
    vuln_infos = []
    scan_type = args.mode
    
    # MODE: SAST Analysis
    if args.mode in ['sast', 'full']:
        print(f"\n📊 Loading SAST results: {args.sast}")
        vulnerabilities, sast_type = scanner.load_sast_results(args.sast)
        
        if vulnerabilities:
            # Limit if specified
            if args.limit and len(vulnerabilities) > args.limit:
                print(f"🔍 Limiting SAST analysis to {args.limit} findings")
                vulnerabilities = vulnerabilities[:args.limit]
            
            # Extract vulnerability info
            print(f"📋 Extracting {len(vulnerabilities)} findings...")
            for vuln in vulnerabilities:
                vuln_info = scanner.extract_vulnerability_info(vuln, sast_type)
                vuln_infos.append(vuln_info)
            
            print(f"\n{'='*70}")
            print(f"🚀 AI ANALYSIS - SAST Findings")
            print(f"{'='*70}")
            ai_analysis += scanner.analyze_sast_with_ai(vuln_infos)
        else:
            ai_analysis += "## SAST Analysis\n\nNo vulnerabilities found in SAST report.\n\n"
    
    # MODE: Code Analysis
    if args.mode in ['code', 'full']:
        code_files = categorized_files.get('code', [])
        if code_files:
            if args.limit:
                code_files = code_files[:args.limit]
            
            print(f"\n{'='*70}")
            print(f"🚀 AI ANALYSIS - Source Code")
            print(f"{'='*70}")
            ai_analysis += "\n\n" + scanner.analyze_code_files(code_files)
        else:
            ai_analysis += "\n\n## Code Analysis\n\nNo source code files found.\n\n"
    
    # MODE: Dependency Analysis
    if args.mode in ['dependency', 'full']:
        dep_files = categorized_files.get('dependency', [])
        if dep_files:
            if args.limit:
                dep_files = dep_files[:args.limit]
            
            print(f"\n{'='*70}")
            print(f"🚀 AI ANALYSIS - Dependencies")
            print(f"{'='*70}")
            ai_analysis += "\n\n" + scanner.analyze_dependency_files(dep_files)
        else:
            ai_analysis += "\n\n## Dependency Analysis\n\nNo dependency files found.\n\n"
    
    # Generate comprehensive report
    print(f"\n📝 Generating report...")
    success = scanner.generate_report(
        ai_analysis=ai_analysis,
        scan_type=scan_type,
        output_path=args.output,
        target_dir=args.target,
        file_stats=file_stats,
        vulnerabilities=vuln_infos if vuln_infos else None
    )
    
    if success:
        print("\n" + "=" * 70)
        print("✅ SCAN COMPLETE!")
        print("=" * 70)
        print(f"📄 Report: {args.output}")
        print(f"📊 Mode: {args.mode.upper()}")
        print(f"📁 Files: Code={file_stats['code']}, Deps={file_stats['dependency']}, SAST={file_stats['sast']}")
        if vuln_infos:
            print(f"🔍 Vulnerabilities: {len(vuln_infos)}")
        print("=" * 70)
    else:
        print("\n❌ Scan completed with errors")
        sys.exit(1)


if __name__ == '__main__':
    main()