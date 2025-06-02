#!/usr/bin/env python3
"""
Filter duplicate findings between Semgrep and CodeQL results
"""

import json
import argparse

def normalize_finding(finding, tool):
    """Normalize finding format for comparison"""
    if tool == 'semgrep':
        return {
            'file': finding.get('path', ''),
            'line': finding.get('start', {}).get('line', 0),
            'rule_type': 'pattern',
            'message': finding.get('message', ''),
            'tool': 'semgrep'
        }
    elif tool == 'codeql':
        # Adapt based on your CodeQL output format
        return {
            'file': finding.get('file', ''),
            'line': finding.get('line', 0),
            'rule_type': 'dataflow',
            'message': finding.get('message', ''),
            'tool': 'codeql'
        }

def find_duplicates(semgrep_findings, codeql_findings):
    """Identify potential duplicates between tools"""
    
    duplicates = []
    unique_semgrep = []
    unique_codeql = []
    
    # Normalize findings
    norm_semgrep = [normalize_finding(f, 'semgrep') for f in semgrep_findings]
    norm_codeql = [normalize_finding(f, 'codeql') for f in codeql_findings]
    
    # Simple duplicate detection based on file + line
    for sg_finding in norm_semgrep:
        is_duplicate = False
        for cq_finding in norm_codeql:
            if (sg_finding['file'] == cq_finding['file'] and 
                abs(sg_finding['line'] - cq_finding['line']) <= 2):  # Allow 2-line variance
                duplicates.append({
                    'semgrep': sg_finding,
                    'codeql': cq_finding,
                    'confidence': 0.8
                })
                is_duplicate = True
                break
        
        if not is_duplicate:
            unique_semgrep.append(sg_finding)
    
    # Add unique CodeQL findings
    for cq_finding in norm_codeql:
        is_duplicate = any(
            cq_finding['file'] == dup['codeql']['file'] and 
            abs(cq_finding['line'] - dup['codeql']['line']) <= 2
            for dup in duplicates
        )
        if not is_duplicate:
            unique_codeql.append(cq_finding)
    
    return {
        'duplicates': duplicates,
        'unique_semgrep': unique_semgrep,
        'unique_codeql': unique_codeql
    }

def main():
    parser = argparse.ArgumentParser(description='Filter duplicate PII findings')
    parser.add_argument('--semgrep-results', required=True)
    parser.add_argument('--codeql-results', required=True)
    parser.add_argument('--output', help='Output file for filtered results')
    
    args = parser.parse_args()
    
    # Load results
    with open(args.semgrep_results, 'r') as f:
        semgrep_data = json.load(f)
    
    with open(args.codeql_results, 'r') as f:
        codeql_data = json.load(f)
    
    # Filter duplicates
    filtered = find_duplicates(semgrep_data, codeql_data)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(filtered, f, indent=2)
    else:
        print(json.dumps(filtered, indent=2))

if __name__ == '__main__':
    main()