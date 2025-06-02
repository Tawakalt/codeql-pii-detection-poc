#!/usr/bin/env python3
"""
Generate combined PII detection report from Semgrep and CodeQL results
"""

import json
import argparse
from datetime import datetime
from pathlib import Path

def load_semgrep_results(file_path):
    """Load Semgrep findings from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def generate_markdown_report(semgrep_findings, codeql_findings=None):
    """Generate markdown report combining both tools"""
    
    report = []
    report.append("# PII Detection Analysis Report")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report.append("")
    
    # Summary section
    semgrep_count = len(semgrep_findings)
    codeql_count = len(codeql_findings) if codeql_findings else 0
    total_findings = semgrep_count + codeql_count
    
    report.append("## 📊 Summary")
    report.append(f"- **Total Issues Found:** {total_findings}")
    report.append(f"- **Semgrep (Pattern Detection):** {semgrep_count}")
    report.append(f"- **CodeQL (Data Flow Analysis):** {codeql_count}")
    report.append("")
    
    # Severity breakdown
    if semgrep_findings:
        critical_count = len([f for f in semgrep_findings if f.get('level') == 'ERROR'])
        warning_count = len([f for f in semgrep_findings if f.get('level') == 'WARNING'])
        
        report.append("## 🚨 Severity Breakdown")
        report.append(f"- **Critical/Error:** {critical_count}")
        report.append(f"- **Warning:** {warning_count}")
        report.append("")
    
    # Semgrep findings
    if semgrep_findings:
        report.append("## 🔍 Semgrep Pattern Detection Results")
        report.append("")
        
        for i, finding in enumerate(semgrep_findings[:10], 1):  # Limit to top 10
            severity = "🔴" if finding.get('level') == 'ERROR' else "🟡"
            file_path = finding.get('path', 'Unknown file')
            line = finding.get('start', {}).get('line', 'Unknown line')
            rule_id = finding.get('check_id', 'Unknown rule')
            message = finding.get('message', 'No message')
            
            report.append(f"### {i}. {severity} {rule_id}")
            report.append(f"**File:** `{file_path}:{line}`")
            report.append(f"**Issue:** {message}")
            
            # Add code snippet if available
            if 'extra' in finding and 'lines' in finding['extra']:
                report.append("**Code:**")
                report.append("```python")
                report.append(finding['extra']['lines'].strip())
                report.append("```")
            
            report.append("")
    
    # CodeQL findings placeholder
    if codeql_count > 0:
        report.append("## 🧬 CodeQL Data Flow Analysis Results")
        report.append("*CodeQL findings are available in the Security tab of your repository.*")
        report.append("")
        report.append("CodeQL detected complex data flows that may not be caught by pattern matching.")
        report.append("Review the Security tab for detailed data flow paths and remediation guidance.")
        report.append("")
    
    # Recommendations
    report.append("## 💡 Recommendations")
    
    if total_findings > 0:
        report.append("### Immediate Actions")
        report.append("1. **Review critical findings** marked with 🔴 immediately")
        report.append("2. **Check Security tab** for CodeQL data flow analysis")
        report.append("3. **Remove or mask PII** from logging statements")
        report.append("4. **Use user IDs** instead of emails/personal data")
        report.append("")
        
        report.append("### Safe Logging Practices")
        report.append("- Use `user_id` instead of `email` in logs")
        report.append("- Hash sensitive data: `sha256(email)[:8]`")
        report.append("- Log events without personal identifiers")
        report.append("- Use correlation IDs for tracking")
        
    else:
        report.append("✅ **No PII issues detected** - Great job following secure logging practices!")
    
    report.append("")
    report.append("---")
    report.append("*This report combines fast pattern detection (Semgrep) with deep data flow analysis (CodeQL)*")
    
    return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description='Generate combined PII detection report')
    parser.add_argument('--semgrep-results', required=True, help='Path to Semgrep results JSON')
    parser.add_argument('--codeql-results', help='Path to CodeQL results JSON')
    parser.add_argument('--output-format', choices=['markdown', 'json'], default='markdown')
    
    args = parser.parse_args()
    
    # Load results
    semgrep_findings = load_semgrep_results(args.semgrep_results)
    codeql_findings = []  # TODO: Parse CodeQL results when available
    
    if args.output_format == 'markdown':
        print(generate_markdown_report(semgrep_findings, codeql_findings))
    else:
        # JSON output
        combined_results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(semgrep_findings) + len(codeql_findings),
                'semgrep_findings': len(semgrep_findings),
                'codeql_findings': len(codeql_findings)
            },
            'semgrep_results': semgrep_findings,
            'codeql_results': codeql_findings
        }
        print(json.dumps(combined_results, indent=2))

if __name__ == '__main__':
    main()