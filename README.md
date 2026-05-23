# Security Tools

Python security tools built by Chris Beauvoir.
Tools to help me develop "UERO" AI specialized in Cybersecurity work.

## uero.py — Automated Log Threat Analyzer
Parses Linux auth logs and automatically detects:
- Brute force attacks with attempt counts
- Successful logins following brute force (account compromise)
- Impossible travel (same account, multiple geographic locations)
- Privilege escalation and dangerous command execution
- Reverse shell establishment

Outputs a formatted threat report with severity ratings and IOC extraction.

**Built with:** Python, regex, collections
**Usage:** `python3 uero.py`

## port_scanner.py — TCP Port Scanner
Probes target systems across common security-relevant ports and identifies open services.

**Built with:** Python socket library
**Usage:** `python3 port_scanner.py`

---
*Part of an ongoing cybersecurity learning journey toward a SOC Analyst role.*
