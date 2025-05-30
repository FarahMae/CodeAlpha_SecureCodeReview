#!/usr/bin/env python3
"""
CodeAlpha Task 3: Secure Coding Review
Comprehensive Security Analysis Tool - FIXED VERSION

Author: FarahMae - CodeAlpha Cybersecurity Intern
"""

import os
import sys
import json
import subprocess
import re
import sqlite3
from datetime import datetime
from pathlib import Path

class SecurityScanner:
    def __init__(self, target_dir="../vulnerable_apps"):
        self.target_dir = Path(target_dir)
        self.vulnerabilities = []
        self.report_dir = Path("../reports")
        self.report_dir.mkdir(exist_ok=True)
        
        # Vulnerability patterns for manual analysis
        self.vulnerability_patterns = {
            'sql_injection': [
                r'f".*{.*}.*".*cursor\.execute',  # f-string SQL
                r'".*\+.*".*cursor\.execute',     # String concatenation SQL
                r'query.*=.*f".*SELECT.*{',       # F-string in queries
                r'\.execute\(f".*{.*}.*"\)',      # Direct f-string execution
            ],
            'xss': [
                r'render_template_string.*\+',    # Template string concatenation
                r'innerHTML.*=.*[^(textContent)]', # innerHTML usage
                r'<.*>.*\+.*<.*>',                # HTML concatenation
            ],
            'command_injection': [
                r'eval\(',                        # eval() usage
                r'exec\(',                        # exec() usage
                r'os\.system\(',                  # os.system() calls
                r'subprocess\..*shell=True',      # Shell execution
            ],
            'hardcoded_secrets': [
                r'password.*=.*["\'].*["\']',     # Hardcoded passwords
                r'secret.*=.*["\'].*["\']',       # Hardcoded secrets
                r'api_key.*=.*["\'].*["\']',      # Hardcoded API keys
                r'token.*=.*["\'].*["\']',        # Hardcoded tokens
            ],
            'path_traversal': [
                r'open\(.*filename.*\)',         # Direct file opening
                r'open\(.*request\..*\)',        # User input file opening
                r'\.read\(\).*request',           # Reading user-specified files
            ],
            'debug_mode': [
                r'debug.*=.*True',                # Debug mode enabled
                r'app\.run\(.*debug.*True',       # Flask debug mode
            ]
        }
    
    def scan_file(self, file_path):
        """Scan a single file for security vulnerabilities"""
        vulnerabilities_found = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Check each vulnerability pattern
                for vuln_type, patterns in self.vulnerability_patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            # Find line number
                            line_num = content[:match.start()].count('\n') + 1
                            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                            
                            vulnerability = {
                                'file': str(file_path),
                                'type': vuln_type,
                                'line': line_num,
                                'code': line_content,
                                'pattern': pattern,
                                'severity': self.get_severity(vuln_type),
                                'description': self.get_description(vuln_type),
                                'remediation': self.get_remediation(vuln_type)
                            }
                            vulnerabilities_found.append(vulnerability)
        
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities_found
    
    def get_severity(self, vuln_type):
        """Get severity level for vulnerability type"""
        severity_map = {
            'sql_injection': 'Critical',
            'command_injection': 'Critical',
            'xss': 'High',
            'path_traversal': 'High',
            'hardcoded_secrets': 'High',
            'debug_mode': 'Medium'
        }
        return severity_map.get(vuln_type, 'Low')
    
    def get_description(self, vuln_type):
        """Get description for vulnerability type"""
        descriptions = {
            'sql_injection': 'SQL Injection vulnerability allows attackers to execute arbitrary SQL commands',
            'command_injection': 'Command injection allows attackers to execute system commands',
            'xss': 'Cross-Site Scripting allows attackers to inject malicious scripts',
            'path_traversal': 'Path traversal allows access to files outside intended directory',
            'hardcoded_secrets': 'Hardcoded credentials expose sensitive information',
            'debug_mode': 'Debug mode exposes sensitive application information'
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected')
    
    def get_remediation(self, vuln_type):
        """Get remediation advice for vulnerability type"""
        remediations = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'command_injection': 'Avoid eval/exec, use safe alternatives and input validation',
            'xss': 'Use template engines with auto-escaping, validate and sanitize input',
            'path_traversal': 'Validate file paths, use whitelist of allowed files',
            'hardcoded_secrets': 'Use environment variables or secure configuration management',
            'debug_mode': 'Disable debug mode in production environments'
        }
        return remediations.get(vuln_type, 'Follow secure coding best practices')
    
    def scan_directory(self, directory):
        """Scan all Python files in directory"""
        all_vulnerabilities = []
        
        for file_path in directory.rglob("*.py"):
            print(f"🔍 Scanning: {file_path}")
            file_vulns = self.scan_file(file_path)
            all_vulnerabilities.extend(file_vulns)
        
        return all_vulnerabilities
    
    def run_bandit_scan(self):
        """Run Bandit security scanner"""
        print("🛡️ Running Bandit security analysis...")
        
        bandit_output = self.report_dir / "bandit_results.json"
        
        try:
            cmd = [
                'bandit', '-r', str(self.target_dir),
                '-f', 'json', '-o', str(bandit_output)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if bandit_output.exists():
                with open(bandit_output, 'r') as f:
                    bandit_data = json.load(f)
                return bandit_data
            else:
                print("⚠️ Bandit output file not created")
                return None
                
        except FileNotFoundError:
            print("⚠️ Bandit not installed or not in PATH")
            return None
        except Exception as e:
            print(f"❌ Error running Bandit: {e}")
            return None
    
    def analyze_flask_security(self):
        """Specific Flask security analysis"""
        flask_issues = []
        
        # Check for common Flask security issues
        for file_path in self.target_dir.rglob("*.py"):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                    # Check for specific Flask vulnerabilities
                    flask_patterns = {
                        'hardcoded_secret_key': r'secret_key.*=.*["\'].*["\']',
                        'debug_enabled': r'app\.run\(.*debug.*=.*True',
                        'missing_csrf': r'@app\.route.*methods.*POST',
                        'template_injection': r'render_template_string.*\+',
                    }
                    
                    for issue_type, pattern in flask_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            flask_issues.append({
                                'file': str(file_path),
                                'type': issue_type,
                                'severity': 'High' if 'secret' in issue_type else 'Medium',
                                'description': f'Flask security issue: {issue_type}',
                                'line': 1,  # Default line number
                                'code': 'See file for details',
                                'remediation': 'Follow Flask security best practices'
                            })
            
            except Exception as e:
                print(f"Error analyzing Flask security in {file_path}: {e}")
        
        return flask_issues
    
    def generate_vulnerability_matrix(self, vulnerabilities):
        """Generate vulnerability risk matrix"""
        matrix = {
            'Critical': {'count': 0, 'types': []},
            'High': {'count': 0, 'types': []},
            'Medium': {'count': 0, 'types': []},
            'Low': {'count': 0, 'types': []}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            matrix[severity]['count'] += 1
            if vuln['type'] not in matrix[severity]['types']:
                matrix[severity]['types'].append(vuln['type'])
        
        return matrix
    
    def generate_html_report(self, vulnerabilities, bandit_results=None):
        """Generate comprehensive HTML report"""
        matrix = self.generate_vulnerability_matrix(vulnerabilities)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_template = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>CodeAlpha Security Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .critical {{ color: #e74c3c; font-weight: bold; }}
                .high {{ color: #e67e22; font-weight: bold; }}
                .medium {{ color: #f39c12; font-weight: bold; }}
                .low {{ color: #27ae60; font-weight: bold; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .code {{ background: #f8f9fa; padding: 10px; border-left: 4px solid #007bff; margin: 10px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ CodeAlpha Security Analysis Report</h1>
                <p>Task 3: Secure Coding Review</p>
                <p>Generated: {timestamp}</p>
            </div>
            
            <div class="summary">
                <h2>📊 Executive Summary</h2>
                <p>Total vulnerabilities found: <strong>{len(vulnerabilities)}</strong></p>
                <ul>
                    <li class="critical">Critical: {matrix['Critical']['count']}</li>
                    <li class="high">High: {matrix['High']['count']}</li>
                    <li class="medium">Medium: {matrix['Medium']['count']}</li>
                    <li class="low">Low: {matrix['Low']['count']}</li>
                </ul>
            </div>
            
            <h2>🔍 Detailed Findings</h2>
        '''
        
        # Add individual vulnerabilities
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.get('severity', 'medium').lower()
            html_template += f'''
            <div class="vulnerability">
                <h3 class="{severity_class}">#{i} {vuln.get('type', 'unknown').replace('_', ' ').title()} ({vuln.get('severity', 'Medium')})</h3>
                <p><strong>File:</strong> {vuln.get('file', 'N/A')}</p>
                <p><strong>Line:</strong> {vuln.get('line', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'Security vulnerability detected')}</p>
                <div class="code">
                    <strong>Vulnerable Code:</strong><br>
                    <code>{vuln.get('code', 'See file for details')}</code>
                </div>
                <p><strong>🔧 Remediation:</strong> {vuln.get('remediation', 'Follow secure coding best practices')}</p>
            </div>
            '''
        
        html_template += '''
            <div class="summary">
                <h2>📋 Recommendations</h2>
                <ol>
                    <li>Immediately address all Critical and High severity vulnerabilities</li>
                    <li>Implement input validation and sanitization throughout the application</li>
                    <li>Use parameterized queries to prevent SQL injection</li>
                    <li>Enable security headers and CSRF protection</li>
                    <li>Remove hardcoded credentials and use secure configuration management</li>
                    <li>Disable debug mode in production</li>
                    <li>Implement comprehensive security testing in CI/CD pipeline</li>
                </ol>
            </div>
        </body>
        </html>
        '''
        
        # Save HTML report
        report_file = self.report_dir / "security_analysis_report.html"
        with open(report_file, 'w') as f:
            f.write(html_template)
        
        print(f"📊 HTML report generated: {report_file}")
        return report_file
    
    def run_comprehensive_scan(self):
        """Run complete security analysis"""
        print("🚀 Starting Comprehensive Security Analysis...")
        print("=" * 60)
        
        # Manual pattern-based scan
        print("🔍 Phase 1: Pattern-based vulnerability detection...")
        vulnerabilities = self.scan_directory(self.target_dir)
        
        # Flask-specific analysis
        print("🔍 Phase 2: Flask security analysis...")
        flask_issues = self.analyze_flask_security()
        vulnerabilities.extend(flask_issues)
        
        # Bandit analysis
        print("🔍 Phase 3: Bandit static analysis...")
        bandit_results = self.run_bandit_scan()
        
        # Generate reports
        print("📊 Phase 4: Generating reports...")
        
        # Save raw data
        with open(self.report_dir / "vulnerabilities.json", 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        
        # Generate HTML report
        html_report = self.generate_html_report(vulnerabilities, bandit_results)
        
        # Print summary
        print("\n" + "=" * 60)
        print("📋 SCAN SUMMARY")
        print("=" * 60)
        print(f"Total vulnerabilities found: {len(vulnerabilities)}")
        
        matrix = self.generate_vulnerability_matrix(vulnerabilities)
        for severity, data in matrix.items():
            if data['count'] > 0:
                print(f"{severity}: {data['count']} ({', '.join(data['types'])})")
        
        print(f"\n📊 Detailed report: {html_report}")
        print("🔍 Raw data: reports/vulnerabilities.json")
        
        if bandit_results:
            print("🛡️ Bandit results: reports/bandit_results.json")
        
        return vulnerabilities

def main():
    """Main execution function"""
    print("🛡️ CodeAlpha Task 3: Security Scanner")
    print("Author: FarahMae")
    print("-" * 40)
    
    scanner = SecurityScanner()
    vulnerabilities = scanner.run_comprehensive_scan()
    
    print(f"\n✅ Security analysis complete!")
    print(f"Found {len(vulnerabilities)} security issues")
    print("📝 Check the reports/ directory for detailed findings")

if __name__ == "__main__":
    main()
