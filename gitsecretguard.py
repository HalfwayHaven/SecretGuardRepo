import re
import subprocess
import sys
import json
import os

# Default patterns for common secrets
SECRET_PATTERNS = [
    r'(?i)api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',  # API keys
    r'(?i)password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',  # Passwords
    r'(?i)aws_access_key_id["\']?\s*[:=]\s*["\']AKIA[0-9A-Z]{16}["\']',  # AWS keys
    r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\'][0-9a-zA-Z\/+]{40}["\']',
    r'(?i)bearer["\']?\s*[:=]\s*["\']eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}["\']',  # JWT
]

class GitSecretGuard:
    def __init__(self, config_file='.secretguardignore'):
        self.patterns = SECRET_PATTERNS
        self.ignore_patterns = self.load_ignore(config_file)
    
    def load_ignore(self, config_file):
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return []
    
    def should_ignore(self, file_path):
        for ignore in self.ignore_patterns:
            if re.match(ignore, file_path):
                return True
        return False
    
    def scan_file(self, file_path):
        if self.should_ignore(file_path):
            return []
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                for pattern in self.patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        findings.append({
                            'file': file_path,
                            'line': content[:match.start()].count('\n') + 1,
                            'match': match.group(0)
                        })
        except Exception:
            pass  # Skip binary or unreadable files
        return findings
    
    def get_staged_files(self):
        try:
            result = subprocess.run(['git', 'diff', '--cached', '--name-only'], capture_output=True, text=True)
            return result.stdout.splitlines()
        except Exception:
            return []
    
    def scan_repo(self, full_scan=False):
        if full_scan:
            files = [os.path.join(root, file) for root, _, files in os.walk('.') for file in files if not self.should_ignore(file)]
        else:
            files = self.get_staged_files()
        all_findings = []
        for file in files:
            all_findings.extend(self.scan_file(file))
        return all_findings
    
    def generate_report(self, findings, output_file=None):
        report = {'findings': findings}
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
        return report
    
    def send_alert(self, findings):
        if findings:
            print("ALERT: Secrets found!")
            for f in findings:
                print(f"File: {f['file']}, Line: {f['line']}, Match: {f['match']}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="GitSecretGuard: Scan for secrets in Git repo.")
    parser.add_argument('--full', action='store_true', help="Scan entire repo")
    parser.add_argument('--report', type=str, help="Output JSON report file")
    args = parser.parse_args()
    
    guard = GitSecretGuard()
    findings = guard.scan_repo(full_scan=args.full)
    guard.send_alert(findings)
    if args.report:
        guard.generate_report(findings, args.report)
    
    if findings:
        sys.exit(1)  # For pre-commit hook

if __name__ == "__main__":
    main()

# To install as pre-commit hook:
# Save this as gitsecretguard.py
# In .git/hooks/pre-commit:
# #!/bin/sh
# python gitsecretguard.py
# Make executable: chmod +x .git/hooks/pre-commit