# GitSecretGuard - Secret Scanner Project

## Project Objectives
Detect secrets (API keys, passwords, AWS keys, JWTs) in Git repositories to prevent accidental commits.

## Features
- Scans staged files (pre-commit style) or full repo.
- Regex patterns for common secrets.
- Ignores files via .secretguardignore.
- Alerts on findings, exits with code 1 (blocks commit).
- Generates JSON report.
- Installable as Git pre-commit hook.

## Setup and Run
1. Clone repo: `git clone https://github.com/your-username/SecretGuardRepo.git`
2. Navigate: `cd SecretGuardRepo`
3. Run staged scan: `python gitsecretguard.py`
4. Full scan: `python gitsecretguard.py --full`
5. With report: `python gitsecretguard.py --full --report output.json`
6. Install pre-commit hook:
   - Copy script to `.git/hooks/pre-commit`
   - Edit to run script (see code comments)
   - `chmod +x .git/hooks/pre-commit` (Git Bash)

## Prerequisites
- Python 3
- Git
- No external dependencies (standard library only)

## Code Documentation
Inline comments explain logic. Key files: gitsecretguard.py (main scanner), test.py/test2.py (demo secrets).

No real API keys used.
